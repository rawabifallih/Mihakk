"""Storing an event stream, resuming it, and knowing when it is incomplete."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from app import db as store
from app.engine_client import consume_stream

from conftest import TOKEN, FakeEngine, event, finding_event


def rebuilt_client(fake_engine: FakeEngine):
    """A second client onto the same fake engine, for a second pass."""
    import httpx
    from app.config import Settings
    from app.engine_client import EngineClient

    settings = Settings(
        database_path=":memory:", engine_base_url="http://engine:8900",
        engine_token=TOKEN, reconnect_delay_seconds=0.0, reconnect_attempts=1,
    )
    return EngineClient(settings, client=httpx.AsyncClient(
        transport=httpx.MockTransport(fake_engine.handler),
        base_url=settings.engine_base_url))


def run(coro):
    """Run one coroutine on its own loop, shutting it down cleanly.

    Without closing the loop and finalising its async generators, httpx's
    streaming generators are collected later and asyncio complains about
    pending tasks, which buries real failures in noise.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()


def consume(client, database: store.Database, session_id: str = "s1",
            attempts: int = 4, force_from: Any = None) -> Any:
    """Drive a stream into storage, exactly as the service does.

    force_from overrides the resume point, so a test can ask the engine to
    re-deliver events already held.
    """

    def on_event(e: dict[str, Any]) -> bool:
        stored = database.append_event(session_id, e)
        if e.get("type") == "finding":
            f = e.get("finding") or {}
            if f.get("case_id"):
                database.append_finding(session_id, f["case_id"], int(e["seq"]), f)
        if e.get("type") == "done":
            done = e.get("done") or {}
            database.update_session(session_id,
                                    total_seq=int(done.get("total_seq", 0)) or None)
        return stored

    def on_gap(e: dict[str, Any]) -> None:
        w = e.get("warning") or {}
        database.append_gap_notice(session_id, e.get("at"),
                                   int(w.get("events_dropped", 0)),
                                   str(w.get("message", "")))

    resume_from = (lambda: force_from) if force_from is not None else (
        lambda: database.last_contiguous_seq(session_id))

    async def go():
        try:
            return await consume_stream(
                client, session_id,
                resume_from=resume_from,
                on_event=on_event, on_gap=on_gap,
                attempts=attempts, delay=0.0,
            )
        finally:
            await client.aclose()

    return run(go())


def complete_run(count: int = 6) -> list[dict[str, Any]]:
    events = [event(1, "started")]
    for seq in range(2, count):
        events.append(finding_event(seq, f"s1-{seq:06d}"))
    events.append(event(count, "done", done={
        "status": "completed", "total_seq": count, "events_dropped": 0,
    }))
    return events


# --- the happy path --------------------------------------------------------


def test_a_clean_stream_is_stored_and_marked_complete(client, db, fake_engine: FakeEngine):
    db.create_session("s1", "2026-01-01T00:00:00Z")
    fake_engine.events = complete_run(6)

    outcome = consume(client, db)

    assert outcome.finished
    assert outcome.events_stored == 6
    assert outcome.duplicates == 0

    completeness = db.refresh_completeness("s1")
    assert completeness.complete, completeness.reason
    assert completeness.events_received == 6
    assert completeness.events_dropped == 0
    assert completeness.last_seq == 6
    assert store.resolve_status("completed", completeness) == store.COMPLETED


def test_events_come_back_in_order(client, db, fake_engine: FakeEngine):
    db.create_session("s1", "t")
    fake_engine.events = complete_run(8)
    consume(client, db)

    stored = db.events("s1")
    assert [e["seq"] for e in stored] == list(range(1, 9))


def test_findings_are_extracted_and_deduplicated(client, db, fake_engine: FakeEngine):
    db.create_session("s1", "t")
    fake_engine.events = complete_run(6)
    consume(client, db)

    findings = db.findings("s1")
    assert len(findings) == 4
    assert all(f["status"] == "indicator_needs_verification" for f in findings)
    # No finding carries a confidence: that is the analysis phase's job.
    for f in findings:
        for indicator in f["indicators"]:
            assert "confidence" not in indicator


# --- idempotency -----------------------------------------------------------


def test_storing_the_same_event_twice_is_harmless(db):
    db.create_session("s1", "t")
    e = event(1, "started")

    assert db.append_event("s1", e) is True
    assert db.append_event("s1", e) is False
    assert db.append_event("s1", e) is False

    assert db.event_seqs("s1") == [1]


def test_a_replayed_stream_stores_nothing_new(client, db, fake_engine: FakeEngine):
    db.create_session("s1", "t")
    fake_engine.events = complete_run(6)

    first = consume(client, db)
    assert first.events_stored == 6

    # Ask for the whole stream again, as an engine that resends from earlier
    # than requested would. Every event is already held, so nothing new may be
    # stored, nothing may be duplicated, and nothing may raise.
    second = consume(rebuilt_client(fake_engine), db, force_from=0)
    assert second.events_stored == 0
    assert second.duplicates == 6, "the replayed events were not recognised as duplicates"
    assert db.event_seqs("s1") == list(range(1, 7))
    assert len(db.findings("s1")) == 4


# --- resuming --------------------------------------------------------------


def test_a_dropped_stream_resumes_from_the_last_contiguous_event(
        client, db, fake_engine: FakeEngine):
    db.create_session("s1", "t")
    fake_engine.events = complete_run(8)
    # Cut the connection after three events, once.
    fake_engine.break_after = 3

    outcome = consume(client, db)

    assert outcome.attempts >= 2, "the stream was not actually interrupted"
    assert outcome.finished, "the resume never reached the done event"
    assert db.event_seqs("s1") == list(range(1, 9))

    completeness = db.refresh_completeness("s1")
    assert completeness.complete, completeness.reason


def test_resume_asks_for_what_is_actually_missing(db):
    db.create_session("s1", "t")
    for seq in (1, 2, 3):
        db.append_event("s1", event(seq, "progress"))
    assert db.last_contiguous_seq("s1") == 3

    # A hole: 4 never arrived, 5 did. Resuming from 5 would write off 4, so
    # the resume point is the last event with nothing missing before it.
    db.append_event("s1", event(5, "progress"))
    assert db.highest_seq("s1") == 5
    assert db.last_contiguous_seq("s1") == 3


def test_events_survive_a_restart_and_resume_from_storage(settings, client,
                                                          fake_engine: FakeEngine):
    """A restarted orchestrator resumes from the database, not from memory."""
    fake_engine.events = complete_run(8)
    fake_engine.break_after = 4

    first_db = store.Database(settings.database_path)
    first_db.create_session("s1", "t")
    consume(client, first_db, attempts=1)  # one attempt: the stream breaks and stops
    partial = first_db.event_seqs("s1")
    first_db.close()

    assert 0 < len(partial) < 8, f"expected a partial stream, got {partial}"

    # A fresh process, a fresh connection to the same file.
    second_db = store.Database(settings.database_path)
    assert second_db.event_seqs("s1") == partial, "stored events did not survive"

    resume_point = second_db.last_contiguous_seq("s1")
    assert resume_point == partial[-1]

    # A restarted process makes a fresh connection to the engine.
    consume(rebuilt_client(fake_engine), second_db)
    assert second_db.event_seqs("s1") == list(range(1, 9))
    assert second_db.refresh_completeness("s1").complete
    second_db.close()


# --- incompleteness --------------------------------------------------------


def test_a_gap_notice_is_recorded_and_blocks_completion(client, db,
                                                        fake_engine: FakeEngine):
    db.create_session("s1", "t")
    fake_engine.events = complete_run(10)
    # The engine can no longer supply events 1-4.
    fake_engine.gap_before_seq = 5
    fake_engine.gap_count = 4

    outcome = consume(client, db)

    assert outcome.gap_notices >= 1, "the gap notice was not delivered"
    notices = db.gap_notices("s1")
    assert notices and notices[0]["events_dropped"] == 4

    completeness = db.refresh_completeness("s1")
    assert not completeness.complete
    assert completeness.events_dropped >= 4
    assert "permanently lost" in (completeness.reason or "")

    # And the status must not read as a complete result set, whatever the
    # engine's done event said.
    assert store.resolve_status("completed", completeness) == store.INCOMPLETE


def test_a_hole_in_the_sequence_is_reported_explicitly(db):
    db.create_session("s1", "t")
    for seq in (1, 2, 4, 5):
        db.append_event("s1", event(seq, "progress"))
    db.update_session("s1", total_seq=5)

    completeness = db.compute_completeness("s1")
    assert not completeness.complete
    assert completeness.missing_seqs == [3]
    assert "gaps at sequence 3" in (completeness.reason or "")
    assert store.resolve_status("completed", completeness) == store.INCOMPLETE


def test_a_stream_that_ends_early_is_incomplete(db):
    db.create_session("s1", "t")
    for seq in range(1, 5):
        db.append_event("s1", event(seq, "progress"))
    db.update_session("s1", total_seq=9)  # the engine produced nine

    completeness = db.compute_completeness("s1")
    assert not completeness.complete
    assert completeness.events_dropped == 5
    assert "ended early" in (completeness.reason or "")


def test_no_total_seq_means_unknown_not_complete(db):
    """Without a done event there is no way to know what is missing."""
    db.create_session("s1", "t")
    for seq in range(1, 5):
        db.append_event("s1", event(seq, "progress"))

    completeness = db.compute_completeness("s1")
    assert not completeness.complete
    assert "unknown" in (completeness.reason or "")
    assert store.resolve_status(None, completeness) == store.INCOMPLETE


def test_a_stream_that_never_finishes_gives_up_and_stays_incomplete(
        client, db, fake_engine: FakeEngine):
    db.create_session("s1", "t")
    # Events but no done event, and the stream closes each time.
    fake_engine.events = [event(seq, "progress") for seq in range(1, 4)]

    outcome = consume(client, db, attempts=3)

    assert not outcome.finished
    assert outcome.attempts == 3, "it did not retry the agreed number of times"
    completeness = db.refresh_completeness("s1")
    assert not completeness.complete


def test_a_stopped_run_keeps_its_status(db):
    db.create_session("s1", "t")
    for seq in range(1, 4):
        db.append_event("s1", event(seq, "progress"))
    db.update_session("s1", total_seq=3)

    completeness = db.compute_completeness("s1")
    assert completeness.complete
    # A stopped run is not a claim of completeness, so it keeps its own status.
    assert store.resolve_status(store.STOPPED, completeness) == store.STOPPED
    assert store.resolve_status(store.FAILED, completeness) == store.FAILED


# --- the token -------------------------------------------------------------


def test_the_engine_is_called_with_the_shared_token(client, db, fake_engine: FakeEngine):
    db.create_session("s1", "t")
    fake_engine.events = complete_run(4)
    consume(client, db)
    assert fake_engine.unauthorised_calls == 0


def test_a_wrong_token_is_rejected_and_stores_nothing(settings, db,
                                                      fake_engine: FakeEngine):
    import httpx
    from app.config import Settings
    from app.engine_client import EngineClient

    bad = Settings(
        database_path=settings.database_path,
        engine_base_url=settings.engine_base_url,
        engine_token="not-the-token",
        reconnect_delay_seconds=0.0,
        reconnect_attempts=1,
    )
    transport = httpx.MockTransport(fake_engine.handler)
    client = EngineClient(bad, client=httpx.AsyncClient(
        transport=transport, base_url=bad.engine_base_url))

    db.create_session("s1", "t")
    fake_engine.events = complete_run(4)

    outcome = consume(client, db, attempts=1)

    assert fake_engine.unauthorised_calls >= 1
    assert not outcome.finished
    assert db.event_seqs("s1") == [], "events were stored despite a rejected token"
