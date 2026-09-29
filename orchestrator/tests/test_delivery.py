"""What became of a session's requests, on every surface that presents it.

Three words kept apart -- refused (nothing left), attempted (let through, which a
refused connection also is), answered (a response was observed) -- and two
units kept apart: cases, and HTTP requests (one per redirect hop).

The HTML is judged by its structure: the section carries both judgements in
data-delivery and data-responses, and a banner is an element with class
"banner" -- never a phrase search, which has rejected correct pages in this
project and, in 8a, passed a page whose banner had been removed.
"""

from __future__ import annotations

from html.parser import HTMLParser
from typing import Any, Optional

import httpx
import pytest
from fastapi.testclient import TestClient

from app import db as store
from app import delivery as d, main
from app.config import Settings
from app.engine_client import EngineClient

from conftest import FakeEngine, aggregate_document, bearer, event


def counts(ca, cr, cn, ba, br, bn, ha, hu, hr) -> dict[str, Any]:
    return dict(cases_attempted=ca, cases_refused=cr, cases_answered=cn,
                baseline_attempted=ba, baseline_refused=br, baseline_answered=bn,
                http_answered=ha, http_unanswered=hu, http_refused=hr)


# --- the pure judgement --------------------------------------------------------

class TestAssess:
    def test_everything_refused(self):
        r = d.assess(counts(0, 8, 0, 0, 3, 0, 0, 0, 11), source="t")
        assert (r["verdict"], r["responses"]) == (d.NONE_ATTEMPTED, d.NOT_APPLICABLE)
        assert "Nothing was attempted" in r["message"]

    def test_a_refused_connection_is_attempted_and_unanswered_never_sent(self):
        r = d.assess(counts(8, 0, 0, 3, 0, 0, 0, 11, 0), source="t")
        assert (r["verdict"], r["responses"]) == (d.NONE_REFUSED, d.NONE_ANSWERED)
        assert "sent" not in r["message"].replace("never sent", "")
        assert "Nothing establishes that the target received them" in r["message"]

    def test_hops_are_counted_as_requests_not_cases(self):
        r = d.assess(counts(8, 0, 8, 3, 0, 3, 44, 0, 0), source="t")
        assert r["responses"] == d.ALL_ANSWERED
        assert r["http_requests"]["attempted"] == 44
        assert (r["cases"]["attempted"], r["baseline"]["attempted"]) == (8, 3)

    def test_an_answered_hop_followed_by_a_refusal_is_partly_refused_not_unattempted(self):
        # One case ended in a safety refusal on a later redirect, but two earlier
        # hops received responses. The case outcome cannot erase those requests.
        r = d.assess(counts(0, 1, 0, 0, 0, 0, 2, 0, 1), source="t")
        assert (r["verdict"], r["responses"]) == (d.PARTLY_REFUSED, d.ALL_ANSWERED)
        assert r["http_requests"]["attempted"] == 2

    def test_partly_refused_and_partly_answered(self):
        r = d.assess(counts(8, 8, 5, 3, 3, 3, 8, 3, 11), source="t")
        assert (r["verdict"], r["responses"]) == (d.PARTLY_REFUSED, d.PARTLY_ANSWERED)

    @pytest.mark.parametrize("missing", ["baseline_refused", "http_refused"])
    def test_a_missing_attempt_count_is_unknown_not_zero(self, missing):
        c = counts(8, 0, 8, 3, 0, 3, 11, 0, 0)
        c[missing] = None
        r = d.assess(c, source="t")
        assert r["verdict"] == d.UNKNOWN

    @pytest.mark.parametrize("missing", ["http_answered", "http_unanswered"])
    def test_a_missing_response_count_is_unknown_not_zero(self, missing):
        c = counts(8, 0, 8, 3, 0, 3, 11, 0, 0)
        c[missing] = None
        r = d.assess(c, source="t")
        assert (r["verdict"], r["responses"]) == (d.UNKNOWN, d.UNKNOWN)

    def test_a_missing_case_attempt_count_does_not_erase_known_http_attempts(self):
        c = counts(8, 0, 8, 3, 0, 3, 11, 0, 0)
        c["cases_attempted"] = None
        r = d.assess(c, source="t")
        assert (r["verdict"], r["responses"]) == (d.NONE_REFUSED, d.ALL_ANSWERED)
        assert r["cases"]["attempted"] is None

    @pytest.mark.parametrize("bad", ["3", True, -1, 1.5])
    def test_an_unreadable_count_is_unknown(self, bad):
        c = counts(8, 0, 8, 3, 0, 3, 11, 0, 0)
        c["baseline_refused"] = bad
        assert d.assess(c, source="t")["verdict"] == d.UNKNOWN

    def test_a_null_accounting_is_unknown_throughout(self):
        """What the engine now writes for a session it never counted."""
        document = aggregate_document(groups=[], totals={"cases": 0, "indicator_instances": 0,
                                                         "groups": 0})
        document["session"]["accounting"] = None
        r = d.from_aggregate(document)
        assert (r["verdict"], r["responses"]) == (d.UNKNOWN, d.UNKNOWN)
        assert r["baseline"] == {"attempted": None, "refused": None, "answered": None}
        assert r["http_requests"]["answered"] is None

    def test_a_running_session_says_so_far(self):
        r = d.assess(counts(0, 2, 0, 0, 3, 0, 0, 0, 5), source="t", final=False)
        assert r["message"].startswith("So far")


# --- through the API: the session view, the list, SQLite, the reports ------------

@pytest.fixture
def api(settings: Settings, fake_engine: FakeEngine):
    database = store.Database(settings.database_path)
    client = EngineClient(settings, client=httpx.AsyncClient(
        transport=httpx.MockTransport(fake_engine.handler),
        base_url=settings.engine_base_url))
    main.configure(settings, database=database, client=client)
    with TestClient(main.app, headers=bearer()) as test_client:
        yield test_client, database
    database.close()


def progress_event(seq: int, c: dict[str, Any], used: int) -> dict[str, Any]:
    return event(seq, "progress", progress={
        "requests_used": used, "requests_budget": 500, "saved": 0, "planned": 8,
        "executed": c["cases_attempted"], "attempted": c["cases_attempted"],
        "refused": c["cases_refused"],
        "answered": c["cases_answered"],
        **{k: c[k] for k in ("baseline_attempted", "baseline_refused", "baseline_answered",
                             "http_answered", "http_unanswered", "http_refused")},
        "elapsed_ms": 10 * seq})


def finished_session(client, database, events: list[dict[str, Any]]) -> None:
    response = client.post("/v1/sessions", json={"session_id": "s1", "config": {}, "seed": "ab"})
    assert response.status_code == 201, response.text
    seq = 0
    for seq, e in enumerate([event(1, "started")] + events, start=1):
        e["seq"] = seq
        database.append_event("s1", e)
    database.append_event("s1", event(seq + 1, "done", done={
        "status": "completed", "total_seq": seq + 1, "events_dropped": 0}))
    database.update_session("s1", total_seq=seq + 1, engine_status="completed",
                            status=store.COMPLETED, ended_at="2026-01-01T00:00:01Z")
    database.refresh_completeness("s1")


def engine_record(fake_engine, c: Optional[dict[str, Any]]) -> None:
    document = aggregate_document(groups=[], totals={"cases": 0, "indicator_instances": 0,
                                                     "groups": 0})
    session = document["session"]
    if c is None:
        session["accounting"] = None
    else:
        session.update(executed_cases=c["cases_attempted"], refused_cases=c["cases_refused"])
        session["accounting"] = {k: c[k] for k in d.COUNT_KEYS
                                 if k != "cases_refused"}
    session["saved_cases"] = 0
    document["completeness"].update(saved_cases_stated=0, cases_in_store=0)
    fake_engine.aggregate_document = document


class _Page(HTMLParser):
    """#delivery's attributes, the classes inside it, and its table cells."""

    def __init__(self):
        super().__init__()
        self.delivery: dict[str, Optional[str]] = {}
        self.depth = 0
        self.classes: list[str] = []
        self.cells: list[str] = []
        self._cell = False
        self.empty_result: Optional[str] = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if a.get("id") == "delivery":
            self.delivery, self.depth = a, 1
            return
        if self.depth:
            self.depth += 1
            self.classes.extend((a.get("class") or "").split())
            if tag == "td":
                self._cell = True
        elif tag == "p" and "data-delivery" in a:
            self.empty_result = a.get("data-delivery")

    def handle_endtag(self, tag):
        if self.depth:
            self.depth -= 1
        if tag == "td":
            self._cell = False

    def handle_data(self, data):
        if self.depth and self._cell and data.strip():
            self.cells.append(data.strip())


def page(markup: str) -> _Page:
    p = _Page()
    p.feed(markup)
    return p


CASES = [
    # name, counts, budget used, verdict, responses
    ("all_refused", counts(0, 8, 0, 0, 3, 0, 0, 0, 11), 11, d.NONE_ATTEMPTED, d.NOT_APPLICABLE),
    ("connection_refused", counts(8, 0, 0, 3, 0, 0, 0, 11, 0), 11, d.NONE_REFUSED, d.NONE_ANSWERED),
    ("redirected", counts(8, 0, 8, 3, 0, 3, 44, 0, 0), 44, d.NONE_REFUSED, d.ALL_ANSWERED),
    ("partly", counts(8, 8, 5, 3, 3, 3, 8, 3, 11), 22, d.PARTLY_REFUSED, d.PARTLY_ANSWERED),
    ("healthy", counts(8, 0, 8, 3, 0, 3, 11, 0, 0), 11, d.NONE_REFUSED, d.ALL_ANSWERED),
]


@pytest.mark.parametrize("name, c, used, verdict, responses", CASES, ids=[x[0] for x in CASES])
def test_every_surface_agrees(api, fake_engine, name, c, used, verdict, responses):
    client, database = api
    finished_session(client, database, [progress_event(2, c, used)])
    engine_record(fake_engine, c)

    view = client.get("/v1/sessions/s1").json()
    assert view["status"] == "completed", "what became of the requests must not rewrite the status"
    listed = client.get("/v1/sessions").json()["sessions"][0]
    report = client.get("/v1/sessions/s1/report").json()
    for where, got in (("view", view["delivery"]), ("list", listed["delivery"]),
                       ("json", report["delivery"])):
        assert (got["verdict"], got["responses"]) == (verdict, responses), where
        # Two units, reported apart and consistently everywhere.
        assert got["http_requests"]["answered"] == c["http_answered"], where
        assert got["cases"]["attempted"] == c["cases_attempted"], where
        assert got["baseline"]["answered"] == c["baseline_answered"], where

    html = page(client.get("/v1/sessions/s1/report?format=html").text)
    assert (html.delivery.get("data-delivery"), html.delivery.get("data-responses")) == \
        (verdict, responses)
    warned = "banner" in html.classes
    assert warned == (verdict != d.NONE_REFUSED or responses != d.ALL_ANSWERED), html.classes
    # The HTTP table carries the request count, not the case count.
    assert str(c["http_answered"]) in html.cells


def test_the_stored_progress_carries_the_counts(api):
    """SQLite itself: the counts are in the stored row, not only derived."""
    client, database = api
    c = counts(8, 0, 0, 3, 0, 0, 0, 11, 0)
    finished_session(client, database, [progress_event(2, c, 11)])
    stored = database.last_event("s1", "progress")["progress"]
    assert (stored["http_unanswered"], stored["http_answered"], stored["answered"]) == (11, 0, 0)


def test_a_legacy_session_is_unknown_on_every_surface(api, fake_engine):
    """An engine from before these counts: progress without them, accounting null."""
    client, database = api
    finished_session(client, database, [event(2, "progress", progress={
        "requests_used": 11, "executed": 8, "refused": 0, "planned": 8, "saved": 0,
        "elapsed_ms": 20})])
    engine_record(fake_engine, None)

    assert client.get("/v1/sessions/s1").json()["delivery"]["verdict"] == d.UNKNOWN
    report = client.get("/v1/sessions/s1/report").json()
    assert report["session"]["accounting"] is None
    assert (report["delivery"]["verdict"], report["delivery"]["responses"]) == (d.UNKNOWN, d.UNKNOWN)
    assert report["delivery"]["baseline"]["attempted"] is None
    html = page(client.get("/v1/sessions/s1/report?format=html").text)
    assert html.delivery.get("data-delivery") == d.UNKNOWN
    # Uncounted is shown as unknown, and no uncounted cell reads as a zero.
    assert html.cells.count("unknown") == 8, html.cells
    assert html.empty_result == d.UNKNOWN
