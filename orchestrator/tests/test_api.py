"""The orchestrator's HTTP surface: lifecycle, status, and honesty."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from app import db as store
from app import main
from app.config import Settings
from app.engine_client import EngineClient

from conftest import (DASHBOARD_TOKEN, TOKEN, FakeEngine, bearer, event,
                      finding_event)


@pytest.fixture
def api(settings: Settings, fake_engine: FakeEngine):
    """The service wired to a fake engine and a temporary database."""
    database = store.Database(settings.database_path)
    client = EngineClient(settings, client=httpx.AsyncClient(
        transport=httpx.MockTransport(fake_engine.handler),
        base_url=settings.engine_base_url))
    main.configure(settings, database=database, client=client)
    with TestClient(main.app, headers=bearer()) as test_client:
        yield test_client
    database.close()


def start_body(session_id: str = "s1") -> dict[str, Any]:
    return {
        "session_id": session_id,
        "config": {
            "config_version": "1",
            "scope": {"targets": [{
                "scheme": "http", "host": "testbed", "port": 8000,
                "path_prefixes": ["/api"], "methods": ["GET"],
                "allowed_addresses": ["127.0.0.1/32"],
            }]},
            "authorization": {
                "operator": "tester",
                "statement": "I am authorised to test the targets listed in this scope.",
                "acked_at": "2026-01-01T00:00:00Z",
                "scope_digest": "sha256:" + "a" * 64,
            },
        },
        "corpus": {"corpus_version": "1", "samples": [
            {"id": "items", "method": "GET", "url": "http://testbed:8000/api/items?page=1"}]},
        "seed": "a1b2c3d4",
    }


def complete_run(count: int = 6) -> list[dict[str, Any]]:
    events = [event(1, "started")]
    for seq in range(2, count):
        events.append(finding_event(seq, f"s1-{seq:06d}"))
    events.append(event(count, "done", done={
        "status": "completed", "total_seq": count, "events_dropped": 0,
    }))
    return events


def wait_for(api: TestClient, session_id: str, statuses: set[str], tries: int = 60) -> dict:
    for _ in range(tries):
        body = api.get(f"/v1/sessions/{session_id}").json()
        if body["status"] in statuses:
            return body
        import time
        time.sleep(0.05)
    return api.get(f"/v1/sessions/{session_id}").json()


# --- lifecycle -------------------------------------------------------------


def test_health(api: TestClient):
    response = api.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_create_start_status_and_findings(api: TestClient, fake_engine: FakeEngine):
    fake_engine.events = complete_run(6)

    created = api.post("/v1/sessions", json=start_body())
    assert created.status_code == 201
    assert created.json()["status"] == store.CREATED

    started = api.post("/v1/sessions/s1/start", json=start_body())
    assert started.status_code == 202, started.text
    assert started.json()["planned_cases"] == 10

    body = wait_for(api, "s1", {store.COMPLETED, store.INCOMPLETE, store.FAILED})
    assert body["status"] == store.COMPLETED, body
    assert body["completeness"]["complete"] is True
    assert body["completeness"]["events_received"] == 6
    assert body["completeness"]["events_dropped"] == 0
    assert body["incomplete_reason"] is None
    assert "indicators that need verification" in body["note"]

    findings = api.get("/v1/sessions/s1/findings").json()
    assert findings["count"] == 4
    assert findings["completeness"]["complete"] is True
    assert "not confirmed vulnerabilities" in findings["note"]

    events = api.get("/v1/sessions/s1/events").json()
    assert [e["seq"] for e in events["events"]] == list(range(1, 7))


def test_a_duplicate_session_is_rejected(api: TestClient):
    assert api.post("/v1/sessions", json=start_body()).status_code == 201
    assert api.post("/v1/sessions", json=start_body()).status_code == 409


def test_unknown_session_is_404(api: TestClient):
    assert api.get("/v1/sessions/nope").status_code == 404
    assert api.get("/v1/sessions/nope/findings").status_code == 404
    assert api.post("/v1/sessions/nope/stop").status_code == 404


def test_stop_reaches_the_engine(api: TestClient, fake_engine: FakeEngine):
    fake_engine.events = complete_run(4)
    api.post("/v1/sessions/s1/start", json=start_body())
    wait_for(api, "s1", {store.COMPLETED, store.INCOMPLETE})

    response = api.post("/v1/sessions/s1/stop")
    assert response.status_code == 202
    assert "s1" in fake_engine.stopped, "the stop never reached the engine"


# --- the engine stays the authority ----------------------------------------


def test_an_engine_refusal_is_passed_through(api: TestClient, fake_engine: FakeEngine):
    """The orchestrator must not soften or reinterpret a refusal."""

    def refuse(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/runs":
            return httpx.Response(403, json={
                "error": "authorization_required",
                "detail": "mihakk: authorisation acknowledgement is not valid",
            })
        return fake_engine.handler(request)

    settings = Settings(database_path=":memory:", engine_base_url="http://engine:8900",
                        engine_token=TOKEN, reconnect_delay_seconds=0.0,
                        reconnect_attempts=1,
                        # Without this the dashboard is not served at all, and the
                        # request is refused before it can reach the engine.
                        dashboard_token=DASHBOARD_TOKEN,
                        allowed_hosts=("testserver",))
    main.configure(settings, database=store.Database(":memory:"),
                   client=EngineClient(settings, client=httpx.AsyncClient(
                       transport=httpx.MockTransport(refuse),
                       base_url=settings.engine_base_url)))

    with TestClient(main.app, headers=bearer()) as client:
        response = client.post("/v1/sessions/s1/start", json=start_body())
        assert response.status_code == 403, response.text
        assert "acknowledgement" in response.json()["detail"]

        # And the session is not left looking like it ran.
        body = client.get("/v1/sessions/s1").json()
        assert body["status"] == store.FAILED
        assert body["completeness"]["complete"] is False


def test_the_orchestrator_exposes_no_way_to_send_a_request(api: TestClient):
    """There is no endpoint that forwards a caller-composed request.

    The engine owns scope checking, address pinning, the limits and the kill
    switch. An orchestrator endpoint that took a URL and fetched it would be a
    second, unguarded way out.
    """
    paths = {route.path for route in main.app.routes}
    for path in paths:
        assert "proxy" not in path and "fetch" not in path and "request" not in path, path

    # Every route is either health, or scoped to a session the engine started.
    for path in paths:
        if path.startswith("/v1/"):
            assert path.startswith("/v1/sessions"), path


# --- incompleteness is never hidden ----------------------------------------


def test_a_gap_makes_the_api_report_incomplete(api: TestClient, fake_engine: FakeEngine):
    fake_engine.events = complete_run(10)
    fake_engine.gap_before_seq = 5
    fake_engine.gap_count = 4

    api.post("/v1/sessions/s1/start", json=start_body())
    body = wait_for(api, "s1", {store.COMPLETED, store.INCOMPLETE, store.INTERRUPTED})

    assert body["status"] != store.COMPLETED, "a lossy run was reported as completed"
    assert body["status"] == store.INCOMPLETE
    assert body["completeness"]["complete"] is False
    assert body["completeness"]["events_dropped"] >= 4
    assert "permanently lost" in body["completeness"]["reason"]
    assert "subset" in body["completeness"]["warning"]

    # The findings response must carry the same warning: it is the response a
    # reader is most likely to mistake for the whole picture.
    findings = api.get("/v1/sessions/s1/findings").json()
    assert findings["completeness"]["complete"] is False
    assert "subset" in findings["completeness"]["warning"]


def test_a_stream_that_never_completes_is_interrupted_not_completed(
        api: TestClient, fake_engine: FakeEngine):
    # Events, but the engine never sends `done`.
    fake_engine.events = [event(seq, "progress") for seq in range(1, 4)]

    api.post("/v1/sessions/s1/start", json=start_body())
    body = wait_for(api, "s1", {store.INTERRUPTED, store.INCOMPLETE, store.COMPLETED})

    assert body["status"] != store.COMPLETED
    assert body["completeness"]["complete"] is False
    assert body["incomplete_reason"]


def test_a_session_cannot_keep_claiming_completeness(api: TestClient,
                                                     fake_engine: FakeEngine):
    """Status is re-derived from the stored rows on every read."""
    fake_engine.events = complete_run(6)
    api.post("/v1/sessions/s1/start", json=start_body())
    body = wait_for(api, "s1", {store.COMPLETED, store.INCOMPLETE})
    assert body["status"] == store.COMPLETED

    # A later discovery that the run actually produced more events must flip
    # the answer, even though the stored status still says completed.
    main.database().update_session("s1", total_seq=99)

    body = api.get("/v1/sessions/s1").json()
    assert body["status"] == store.INCOMPLETE
    assert body["completeness"]["complete"] is False


# --- redaction -------------------------------------------------------------


def test_no_secret_reaches_the_database_or_the_api(api: TestClient,
                                                   fake_engine: FakeEngine):
    """The engine redacts; the orchestrator must not reintroduce anything.

    The stream carries an already-redacted record, and it is stored and served
    unchanged, so there is no second path a secret could take.
    """
    redacted = finding_event(2, "s1-000002")
    redacted["finding"]["request_summary"]["headers"] = {
        "Authorization": ["[REDACTED]"], "Accept": ["application/json"],
    }
    redacted["finding"]["request_summary"]["body_preview"] = '{"password":"[REDACTED]"}'

    fake_engine.events = [
        event(1, "started"),
        redacted,
        event(3, "done", done={"status": "completed", "total_seq": 3, "events_dropped": 0}),
    ]

    api.post("/v1/sessions/s1/start", json=start_body())
    wait_for(api, "s1", {store.COMPLETED, store.INCOMPLETE})

    findings = api.get("/v1/sessions/s1/findings").text
    events_body = api.get("/v1/sessions/s1/events").text

    for secret in ("hunter2", "SUPERSECRET", "Bearer ey"):
        assert secret not in findings, f"{secret} reached the findings response"
        assert secret not in events_body, f"{secret} reached the events response"

    # The redaction marker survives, so a reader can see something was removed.
    assert "[REDACTED]" in findings

    # And the raw database rows carry the same redacted payload.
    rows = main.database().findings("s1")
    assert rows and "[REDACTED]" in json.dumps(rows)
    for secret in ("hunter2", "SUPERSECRET"):
        assert secret not in json.dumps(rows)


def test_the_stored_payload_is_exactly_what_arrived(api: TestClient,
                                                    fake_engine: FakeEngine):
    """No rewriting between the wire and the database."""
    fake_engine.events = complete_run(4)
    api.post("/v1/sessions/s1/start", json=start_body())
    wait_for(api, "s1", {store.COMPLETED, store.INCOMPLETE})

    stored = main.database().events("s1")
    assert [e["seq"] for e in stored] == [1, 2, 3, 4]
    for original, kept in zip(fake_engine.events, stored):
        assert original["type"] == kept["type"]
        assert original["seq"] == kept["seq"]


# A session id becomes a directory name in the engine's store, where an id
# carrying a path was shown to read and overwrite files outside the store root.
# The engine enforces this itself and remains the authority; refusing it here too
# means the orchestrator does not forward what the engine will refuse, and the
# caller gets a 422 naming the field instead of a 502 from further in.
UNSAFE_SESSION_IDS = [
    "../../escaped",
    "../escaped",
    "a/../../escaped",
    "..",
    ".",
    "nested/child",
    "/etc/passwd",
    ".hidden",
    "-rf",
    "sess ion",
    "sess\x00ion",
    "sess\nion",
    "a" * 129,
]

SAFE_SESSION_IDS = ["s1", "live-1790430000", "under_score", "dot.separated", "A1"]


@pytest.mark.parametrize("session_id", UNSAFE_SESSION_IDS)
def test_an_unsafe_session_id_is_refused_in_the_body(api: TestClient, session_id: str,
                                                     fake_engine: FakeEngine):
    before = len(fake_engine.started)
    response = api.post("/v1/sessions", json={"session_id": session_id,
                                              "config": {}, "seed": "ab"})
    assert response.status_code == 422, response.text
    # And nothing was forwarded to the engine.
    assert len(fake_engine.started) == before


# Ids that never reach routing as a session id at all, for reasons outside this
# service: httpx refuses to build a URL containing a control character, and a
# path of "." or ".." is normalised away before any route is matched. They are
# still refused, just not by the pattern -- so the path test asserts the property
# that holds regardless: no such session is ever created, and nothing is sent on.
ERASED_BEFORE_ROUTING = {".", "..", "sess\x00ion", "sess\nion"}


@pytest.mark.parametrize("session_id", UNSAFE_SESSION_IDS)
def test_an_unsafe_session_id_is_refused_in_the_path(api: TestClient, session_id: str,
                                                     fake_engine: FakeEngine):
    before = len(fake_engine.started)
    body = start_body(session_id)

    def attempt(method, path):
        """Returns a status, or None when the request could not even be built."""
        try:
            return api.request(method, path).status_code
        except httpx.InvalidURL:
            return None

    statuses = [
        attempt("POST", f"/v1/sessions/{session_id}/start"),
        attempt("GET", f"/v1/sessions/{session_id}"),
        attempt("GET", f"/v1/sessions/{session_id}/findings"),
        attempt("GET", f"/v1/sessions/{session_id}/events"),
    ]

    if session_id not in ERASED_BEFORE_ROUTING:
        for status in statuses:
            assert status is None or status >= 400, (session_id, statuses)

    # The property that holds either way.
    assert len(fake_engine.started) == before, "an unsafe id was forwarded to the engine"
    listed = {s["session_id"] for s in api.get("/v1/sessions").json()["sessions"]}
    assert session_id not in listed, f"a session was created under {session_id!r}"


@pytest.mark.parametrize("session_id", SAFE_SESSION_IDS)
def test_ordinary_session_ids_still_work(api: TestClient, session_id: str):
    response = api.post("/v1/sessions", json={"session_id": session_id,
                                              "config": {}, "seed": "ab"})
    assert response.status_code == 201, response.text
    assert api.get(f"/v1/sessions/{session_id}").status_code == 200
