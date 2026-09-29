"""Two things a restart and a lossy engine must not be able to hide."""

from __future__ import annotations

import time
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from app import db as store
from app import main
from app.config import Settings
from app.engine_client import EngineClient

from conftest import TOKEN, FakeEngine, event, finding_event, bearer
from test_api import start_body, wait_for


def wire(settings: Settings, fake_engine: FakeEngine) -> store.Database:
    """Point the service at a database file and a fake engine."""
    database = store.Database(settings.database_path)
    client = EngineClient(settings, client=httpx.AsyncClient(
        transport=httpx.MockTransport(fake_engine.handler),
        base_url=settings.engine_base_url))
    main.configure(settings, database=database, client=client)
    return database


def run_with_status(count: int, status: str) -> list[dict[str, Any]]:
    """A contiguous stream from 1 to count, ending with the given status."""
    events = [event(1, "started")]
    for seq in range(2, count):
        events.append(finding_event(seq, f"s1-{seq:06d}"))
    events.append(event(count, "done", done={
        "status": status, "total_seq": count, "events_dropped": 0,
    }))
    return events


# --- the engine's own losses ----------------------------------------------


def test_an_engine_reported_incomplete_is_not_promoted_to_completed(
        settings: Settings, fake_engine: FakeEngine):
    """A whole stream is not proof of a whole result set.

    Every event arrives, contiguously, from 1 to total_seq. But the engine
    failed to write a case or an audit record and says so in its done event.
    Reading the tidy stream as completeness would turn the engine's own
    admission of loss into a claim that nothing was lost.
    """
    fake_engine.events = run_with_status(6, store.INCOMPLETE)
    database = wire(settings, fake_engine)

    with TestClient(main.app, headers=bearer()) as api:
        api.post("/v1/sessions/s1/start", json=start_body())
        body = wait_for(api, "s1", {store.COMPLETED, store.INCOMPLETE,
                                    store.INTERRUPTED, store.FAILED})

        # The stream itself was perfect -- that is the whole point.
        assert body["completeness"]["complete"] is True
        assert body["completeness"]["events_received"] == 6
        assert body["completeness"]["events_dropped"] == 0

        assert body["status"] == store.INCOMPLETE, (
            f"an engine-reported incomplete run was shown as {body['status']}")
        assert body["engine_status"] == store.INCOMPLETE

    database.close()


def test_the_engines_reason_for_losing_results_is_kept(settings: Settings,
                                                       fake_engine: FakeEngine):
    reason = ("8 observed indicator(s) could not be written to the case store "
              "(first error: no space left on device); the saved results are a "
              "subset of what was found")
    fake_engine.events = [
        event(1, "started"),
        event(2, "warning", warning={"code": "results_not_persisted",
                                     "message": reason, "events_dropped": 8}),
        event(3, "done", done={"status": store.INCOMPLETE, "total_seq": 3,
                               "events_dropped": 0}),
    ]
    database = wire(settings, fake_engine)

    with TestClient(main.app, headers=bearer()) as api:
        api.post("/v1/sessions/s1/start", json=start_body())
        body = wait_for(api, "s1", {store.INCOMPLETE, store.COMPLETED, store.INTERRUPTED})

        assert body["status"] == store.INCOMPLETE
        assert body["engine_incomplete_reason"], "the engine's reason was dropped"
        assert "could not be written" in body["engine_incomplete_reason"]

    database.close()


def test_an_engine_reported_completed_with_a_whole_stream_is_completed(
        settings: Settings, fake_engine: FakeEngine):
    """The positive case, or the checks above prove nothing."""
    fake_engine.events = run_with_status(6, store.COMPLETED)
    database = wire(settings, fake_engine)

    with TestClient(main.app, headers=bearer()) as api:
        api.post("/v1/sessions/s1/start", json=start_body())
        body = wait_for(api, "s1", {store.COMPLETED, store.INCOMPLETE})
        assert body["status"] == store.COMPLETED
        assert body["engine_status"] == store.COMPLETED

    database.close()


@pytest.mark.parametrize("engine_status", [store.STOPPED, store.FAILED])
def test_stopped_and_failed_keep_their_meaning(settings: Settings,
                                               fake_engine: FakeEngine,
                                               engine_status: str):
    """Neither is a claim about completeness, so both survive intact.

    How much data arrived is reported separately, in the completeness block.
    """
    fake_engine.events = run_with_status(5, engine_status)
    database = wire(settings, fake_engine)

    with TestClient(main.app, headers=bearer()) as api:
        api.post("/v1/sessions/s1/start", json=start_body())
        body = wait_for(api, "s1", {engine_status, store.COMPLETED, store.INCOMPLETE})

        assert body["status"] == engine_status
        # And the data completeness is visible on its own terms.
        assert body["completeness"]["complete"] is True
        assert body["completeness"]["events_received"] == 5

    database.close()


def test_resolve_status_covers_the_combinations():
    whole = store.Completeness(complete=True, events_received=5, events_dropped=0,
                               last_seq=5, total_seq=5)
    lossy = store.Completeness(complete=False, events_received=3, events_dropped=2,
                               last_seq=5, total_seq=5, reason="gaps")

    # completed needs both halves.
    assert store.resolve_status(store.COMPLETED, whole) == store.COMPLETED
    assert store.resolve_status(store.COMPLETED, lossy) == store.INCOMPLETE
    assert store.resolve_status(store.INCOMPLETE, whole) == store.INCOMPLETE
    assert store.resolve_status(store.INCOMPLETE, lossy) == store.INCOMPLETE

    # stopped and failed are kept whatever the stream did.
    for status in (store.STOPPED, store.FAILED, store.INTERRUPTED):
        assert store.resolve_status(status, whole) == status
        assert store.resolve_status(status, lossy) == status

    # No statement from the engine is not a basis for claiming completeness.
    assert store.resolve_status(None, whole) == store.INCOMPLETE


# --- restarting the service ------------------------------------------------


def test_the_service_resumes_a_running_session_after_a_restart(
        settings: Settings, fake_engine: FakeEngine):
    """A full restart cycle, not just the consume helper.

    A process that died mid-run leaves exactly this behind: a session marked
    running and the events it had collected so far. The state is built
    directly rather than by racing a real run to a convenient moment -- an
    earlier version of this test started a run and slept, but the run
    finished during the sleep, so the restart had nothing left to do and the
    test passed with the recovery removed.
    """
    fake_engine.events = run_with_status(8, store.COMPLETED)

    crashed = store.Database(settings.database_path)
    crashed.create_session("s1", "t")
    crashed.update_session("s1", status=store.RUNNING, planned_cases=10)
    for stored in fake_engine.events[:3]:
        crashed.append_event("s1", stored)
    assert crashed.event_seqs("s1") == [1, 2, 3]
    assert crashed.last_contiguous_seq("s1") == 3
    crashed.close()

    # The service starts again against the same database.
    resumed_db = wire(settings, fake_engine)
    fake_engine.from_seqs.clear()

    with TestClient(main.app, headers=bearer()) as api:
        body = wait_for(api, "s1", {store.COMPLETED, store.INCOMPLETE,
                                    store.INTERRUPTED}, tries=100)

        assert fake_engine.from_seqs, "the restarted service never asked for events"
        assert fake_engine.from_seqs[0] == 3, (
            f"the resume asked from {fake_engine.from_seqs[0]}, not the last "
            "contiguous sequence number it already had")

        assert resumed_db.event_seqs("s1") == list(range(1, 9)), (
            "the restarted service did not collect the remaining events")
        assert body["status"] == store.COMPLETED, body
        assert body["completeness"]["complete"] is True

    resumed_db.close()


def test_a_restart_does_not_start_a_second_follower(settings: Settings,
                                                    fake_engine: FakeEngine):
    """Two followers would both consume, both write, and race on the status."""
    fake_engine.events = run_with_status(6, store.COMPLETED)
    database = wire(settings, fake_engine)

    database.create_session("s1", "t")
    database.update_session("s1", status=store.RUNNING)

    import asyncio

    async def resume_twice():
        first = await main.resume_running_sessions()
        second = await main.resume_running_sessions()
        return first, second

    loop = asyncio.new_event_loop()
    try:
        first, second = loop.run_until_complete(resume_twice())
        assert first == ["s1"], first
        assert second == [], "a second follower was started for the same session"
        loop.run_until_complete(asyncio.sleep(0.2))
    finally:
        for task in list(main._tasks.values()):
            task.cancel()
        loop.run_until_complete(asyncio.sleep(0))
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()

    database.close()


def test_a_session_the_engine_has_forgotten_becomes_interrupted(
        settings: Settings, fake_engine: FakeEngine):
    """A run the engine no longer knows must not stay `running` for ever.

    This is what a restart of the *engine* looks like from here: the session
    is in the database, the engine has no record of it, and every attempt to
    resume the stream is refused.
    """

    def forgotten(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/events"):
            return httpx.Response(404, json={"error": "not_found"})
        return fake_engine.handler(request)

    database = store.Database(settings.database_path)
    client = EngineClient(settings, client=httpx.AsyncClient(
        transport=httpx.MockTransport(forgotten),
        base_url=settings.engine_base_url))
    main.configure(settings, database=database, client=client)

    database.create_session("s1", "t")
    database.update_session("s1", status=store.RUNNING)

    with TestClient(main.app, headers=bearer()) as api:
        body = wait_for(api, "s1", {store.INTERRUPTED, store.INCOMPLETE,
                                    store.COMPLETED}, tries=100)

        assert body["status"] != store.RUNNING, "the session was left running"
        assert body["status"] == store.INTERRUPTED, body
        assert body["incomplete_reason"], "no reason was recorded"
        assert "attempt" in body["incomplete_reason"]
        assert body["completeness"]["complete"] is False

    database.close()


def test_a_finished_session_is_not_resumed(settings: Settings, fake_engine: FakeEngine):
    """Only sessions that were mid-run are picked up."""
    fake_engine.events = run_with_status(4, store.COMPLETED)
    database = wire(settings, fake_engine)

    database.create_session("done-already", "t")
    database.update_session("done-already", status=store.COMPLETED)
    database.create_session("was-stopped", "t")
    database.update_session("was-stopped", status=store.STOPPED)

    import asyncio

    loop = asyncio.new_event_loop()
    try:
        resumed = loop.run_until_complete(main.resume_running_sessions())
    finally:
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()

    assert resumed == [], f"a finished session was resumed: {resumed}"
    database.close()
