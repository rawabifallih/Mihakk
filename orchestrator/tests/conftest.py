"""Shared fixtures.

Every test runs against an in-process fake engine. Nothing here contacts a
real target or a real network: the orchestrator's only outbound path is the
engine's control API, and that is exactly what is faked.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Optional

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import db as store          # noqa: E402
from app.config import Settings      # noqa: E402
from app.engine_client import EngineClient  # noqa: E402

TOKEN = "test-control-token"

# The dashboard credential the tests authenticate with. Separate from the control
# API token on purpose, and used for real: there is no test-only bypass of the
# auth layer, so every request in these suites carries a genuine credential.
DASHBOARD_TOKEN = "test-dashboard-token-0123456789abcdef"


def event(seq: int, type_: str, **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "seq": seq, "type": type_, "session_id": "s1",
        "at": "2026-01-01T00:00:00Z",
    }
    payload.update(extra)
    return payload


def finding_event(seq: int, case_id: str, **extra: Any) -> dict[str, Any]:
    return event(seq, "finding", finding={
        "case_id": case_id,
        "session_id": "s1",
        "status": "indicator_needs_verification",
        "indicators": [{"type": "http_5xx", "reason": "the server answered 500"}],
        "request_summary": {"method": "GET", "url": "http://testbed:8000/api/items",
                            "redacted": True},
        **extra,
    })


class FakeEngine:
    """An engine whose stream can be broken, truncated and resumed."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.started: list[dict[str, Any]] = []
        self.stopped: list[str] = []
        # Break the stream after this many events, once, to simulate a drop.
        self.break_after: Optional[int] = None
        self._broken_once = False
        # Events the engine can no longer supply, reported as a gap notice.
        self.gap_before_seq: int = 0
        self.gap_count: int = 0
        self.stream_attempts = 0
        self.from_seqs: list[int] = []
        self.require_token = True
        self.unauthorised_calls = 0
        # The aggregate this engine will serve, and how it behaves when asked.
        self.aggregate_document: Optional[dict[str, Any]] = None
        self.aggregate_status = 200
        self.aggregate_calls = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/healthz":
            return httpx.Response(200, json={"status": "ok"})

        if self.require_token:
            if request.headers.get("Authorization") != f"Bearer {TOKEN}":
                self.unauthorised_calls += 1
                return httpx.Response(401, json={"error": "unauthorized"})

        if request.url.path == "/v1/runs" and request.method == "POST":
            body = json.loads(request.content or b"{}")
            self.started.append(body)
            return httpx.Response(202, json={
                "session_id": body.get("session_id", "s1"),
                "engine_version": "0.5.0-fake",
                "scope_digest": "sha256:" + "a" * 64,
                "corpus_digest": "sha256:" + "b" * 64,
                "config_digest": "sha256:" + "c" * 64,
                "planned_cases": 10,
            })

        if request.url.path.endswith("/aggregate"):
            self.aggregate_calls += 1
            if self.aggregate_status != 200:
                return httpx.Response(self.aggregate_status,
                                      json={"error": "refused", "detail": "no"})
            return httpx.Response(200, json=self.aggregate_document or aggregate_document())

        if request.url.path.endswith("/events"):
            return self._stream(request)

        if request.method == "DELETE":
            self.stopped.append(request.url.path.split("/")[-1])
            return httpx.Response(202, json={"stopping": True})

        return httpx.Response(404, json={"error": "not_found"})

    def _stream(self, request: httpx.Request) -> httpx.Response:
        self.stream_attempts += 1
        from_seq = int(request.url.params.get("from_seq", 0))
        self.from_seqs.append(from_seq)

        lines: list[bytes] = []
        if self.gap_count and from_seq + 1 < self.gap_before_seq:
            lines.append(json.dumps({
                "seq": 0, "type": "warning", "session_id": "s1",
                "at": "2026-01-01T00:00:00Z",
                "warning": {
                    "code": "events_dropped",
                    "events_dropped": self.gap_count,
                    "message": f"{self.gap_count} event(s) were evicted and are lost",
                },
            }).encode() + b"\n")

        sent = 0
        for e in self.events:
            if e["seq"] <= from_seq:
                continue
            if self.gap_count and e["seq"] < self.gap_before_seq:
                continue
            if (self.break_after is not None and not self._broken_once
                    and sent >= self.break_after):
                self._broken_once = True
                break
            lines.append(json.dumps(e).encode() + b"\n")
            sent += 1

        return httpx.Response(200, content=b"".join(lines),
                              headers={"Content-Type": "application/x-ndjson"})


@pytest.fixture
def fake_engine() -> FakeEngine:
    return FakeEngine()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        database_path=str(tmp_path / "mihakk.db"),
        engine_base_url="http://engine:8900",
        engine_token=TOKEN,
        reconnect_delay_seconds=0.0,
        reconnect_attempts=4,
        dashboard_token=DASHBOARD_TOKEN,
        session_absolute_seconds=12 * 60 * 60,
        session_idle_seconds=30 * 60,
        session_rotate_seconds=60 * 60,
        login_max_failures=5,
        login_window_seconds=300,
        login_lockout_seconds=300,
        # TestClient sends Host: testserver, so it has to be answerable here.
        allowed_hosts=("testserver", "127.0.0.1:8100", "localhost:8100"),
    )


@pytest.fixture
def db(settings: Settings) -> store.Database:
    database = store.Database(settings.database_path)
    yield database
    database.close()


@pytest.fixture
def client(settings: Settings, fake_engine: FakeEngine) -> EngineClient:
    transport = httpx.MockTransport(fake_engine.handler)
    http_client = httpx.AsyncClient(transport=transport, base_url=settings.engine_base_url)
    return EngineClient(settings, client=http_client)


def aggregate_document(*, groups: Optional[list[dict[str, Any]]] = None,
                       scope: Optional[dict[str, Any]] = None,
                       completeness: Optional[dict[str, Any]] = None,
                       totals: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """An engine aggregate, shaped like schemas/aggregate.schema.json."""
    if groups is None:
        groups = [aggregate_group()]
    instances = sum(g.get("occurrences", 0) for g in groups)
    cases = len({cid for g in groups for cid in g.get("case_ids", [])})
    return {
        "aggregate_version": "1",
        "session": {
            "session_id": "s1", "engine_version": "0.5.0-fake",
            "started_at": "2026-01-01T00:00:00Z", "status": "completed",
            "operator": "tester",
            "corpus_digest": "sha256:" + "b" * 64,
            "config_digest": "sha256:" + "c" * 64,
            "planned_cases": 10, "executed_cases": 10,
            "saved_cases": cases, "refused_cases": 0,
            # A healthy run: everything attempted and answered, nothing refused.
            "accounting": {"cases_attempted": 10, "cases_answered": 10,
                           "baseline_attempted": 3,
                           "baseline_refused": 0, "baseline_answered": 3,
                           "http_answered": 13, "http_unanswered": 0, "http_refused": 0},
        },
        "scope": scope if scope is not None else {
            "recorded": True, "consistent": True,
            "digest": "sha256:" + "a" * 64,
            "recomputed_digest": "sha256:" + "a" * 64,
            "max_redirects": 2,
            "targets": [{
                "scheme": "http", "host": "testbed", "port": 8000,
                "path_prefixes": ["/api"], "methods": ["GET", "POST"],
            }],
            "targets_summary": ["http://testbed:8000"],
            "withheld": ["allowed_addresses"],
        },
        "completeness": completeness if completeness is not None else {
            "engine_status": "completed",
            "saved_cases_stated": cases, "cases_in_store": cases,
            "unsaved_cases": 0, "audit_failures": 0, "consistent": True,
        },
        "totals": totals if totals is not None else {
            "cases": cases, "indicator_instances": instances, "groups": len(groups),
        },
        "groups": groups,
        "note": "Results are indicators that need verification, "
                "not confirmed vulnerabilities.",
    }


def aggregate_group(*, indicator_type: str = "http_5xx",
                    case_ids: Optional[list[str]] = None,
                    reason: str = "the server answered 500",
                    url: str = "http://testbed:8000/api/items?page=1",
                    body_preview: Optional[str] = None,
                    status_code: Optional[int] = 500,
                    group_id: Optional[str] = None,
                    error: Optional[str] = None) -> dict[str, Any]:
    case_ids = case_ids or ["s1-000001"]
    return {
        "group_id": group_id or ("sha256:" + "d" * 64),
        "signature": {
            "indicator_type": indicator_type, "target": "items.query.page",
            "method": "GET", "path": "/api/items", "status_code": status_code,
        },
        "occurrences": len(case_ids),
        "case_ids": list(case_ids),
        "representative": {
            "case_id": case_ids[0], "case_index": 1, "reason": reason,
            "reproduction": {
                "engine_version": "0.5.0-fake", "master_seed": "ab", "case_index": 1,
                "corpus_digest": "sha256:" + "b" * 64,
                "config_digest": "sha256:" + "c" * 64,
                "target": "items.query.page",
            },
            "request_summary": {
                "method": "GET", "url": url, "redacted": True,
                "body_preview": body_preview,
            },
            "response_summary": {
                "status_code": status_code, "latency_ms": 12.5,
                "body_bytes": 40, "truncated": False, "error": error,
            },
        },
        "first_observed_at": "2026-01-01T00:00:01Z",
        "last_observed_at": "2026-01-01T00:00:02Z",
    }


# --- authenticating in tests -------------------------------------------------


def bearer() -> dict[str, str]:
    """Headers for a non-browser caller.

    The bearer path needs no CSRF token for the same reason CSRF exists: browsers
    attach cookies to cross-site requests by themselves and never attach an
    Authorization header, so this credential is not ambient.
    """
    return {"Authorization": f"Bearer {DASHBOARD_TOKEN}"}


def sign_in(client) -> str:
    """Log a TestClient in the way a browser does, returning the CSRF token.

    Goes through the real login: fetch the form for its pre-login cookie and
    hidden field, post both with the token, then read the session's CSRF token.
    """
    page = client.get("/auth/login")
    assert page.status_code == 200, page.text
    import re
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert match, "the login form carries no csrf field"

    response = client.post("/auth/login",
                           data={"token": DASHBOARD_TOKEN, "csrf_token": match.group(1)},
                           follow_redirects=False)
    assert response.status_code == 303, response.text

    csrf = client.get("/auth/csrf")
    assert csrf.status_code == 200, csrf.text
    return csrf.json()["csrf_token"]
