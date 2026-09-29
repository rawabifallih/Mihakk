"""The report: what it may claim, and what it must never execute.

The HTML checks parse the document and inspect elements, attributes and link
schemes. They deliberately do NOT search the raw text for strings like
`javascript:` or `onerror=`, because the same tests require the hostile payload to
remain VISIBLE: an escaped payload rendered as text is the correct outcome, and a
raw-text search would reject exactly that. What matters is that no executable
context exists, not that a sequence of characters is absent.
"""

from __future__ import annotations

import json
import pathlib
import sys
from typing import Any, Optional

import httpx
import pytest
from fastapi.testclient import TestClient

from app import classify
from app import db as store
from app import main
from app import report as report_mod
from app.config import Settings
from app.engine_client import EngineClient

from conftest import (TOKEN, FakeEngine, aggregate_document, aggregate_group,
                      bearer, event, finding_event)


@pytest.fixture
def api(settings: Settings, fake_engine: FakeEngine):
    database = store.Database(settings.database_path)
    client = EngineClient(settings, client=httpx.AsyncClient(
        transport=httpx.MockTransport(fake_engine.handler),
        base_url=settings.engine_base_url))
    main.configure(settings, database=database, client=client)
    with TestClient(main.app, headers=bearer()) as test_client:
        yield test_client
    database.close()


def a_session(api: TestClient, session_id: str = "s1") -> None:
    """Create a session row so the report endpoint has something to report on."""
    response = api.post("/v1/sessions", json={"session_id": session_id,
                                              "config": {}, "seed": "ab"})
    assert response.status_code == 201, response.text


# --- the HTML inspector, shared with the live path ---------------------------
#
# The checker is scripts/check_report_html.py, the same module the live integration
# run uses, mounted read-only at /checks. Writing a second parser here would mean
# the page was judged by different code in the two places that judge it, and the
# weaker of the two would set the real standard.


def _load_shared_checker():
    for path in ("/checks", str(pathlib.Path(__file__).resolve().parents[2] / "scripts")):
        if pathlib.Path(path, "check_report_html.py").exists():
            if path not in sys.path:
                sys.path.insert(0, path)
            break
    import check_report_html
    return check_report_html


check_report_html = _load_shared_checker()


def inspect(markup: str):
    """Parse a page and return what a browser would act on."""
    page = check_report_html.Page()
    page.feed(markup)
    page.close()
    return page


def assert_no_executable_context(markup: str):
    """The whole HTML safety requirement, over the parsed document.

    Deliberately not a search of the raw text: the report is required to keep a
    hostile payload VISIBLE as escaped text, so a test banning "javascript:" or
    "onerror=" anywhere would reject the correct answer.
    """
    code, messages = check_report_html.check(markup)
    assert code == 0, "the page has an executable context:\n" + "\n".join(
        m for m in messages if not m.startswith("PASS"))
    return inspect(markup)


# --- the payloads the report must survive ------------------------------------


SUBSET_WARNING_TEXT = report_mod.SUBSET_WARNING

HOSTILE = (
    "<script>alert(1)</script>"
    "\"><img src=x onerror=alert(1)>"
    "</textarea></pre><script>alert(2)</script>"
    "javascript:alert(3)"
    "<a href=\"javascript:alert(4)\">x</a>"
    "{{7*7}} ${7*7}"
    "<style>body{display:none}</style>"
    "<iframe src=\"//evil.invalid\"></iframe>"
    "‮​"
)


def hostile_aggregate() -> dict[str, Any]:
    """An aggregate with the payload in every field the report renders.

    This is not far-fetched: the engine's own indicator reason embeds bytes taken
    from the target's response body, and the request summary carries the mutated
    payload, so target-influenced text reaches the page by design.
    """
    group = aggregate_group(
        reason=HOSTILE,
        url="http://testbed:8000/api/items?q=" + HOSTILE,
        body_preview=HOSTILE,
        error=HOSTILE,
        case_ids=["s1-000001", "s1-0000" + "02"],
    )
    group["signature"]["target"] = HOSTILE
    group["signature"]["path"] = "/api/" + HOSTILE
    group["representative"]["reproduction"]["target"] = HOSTILE

    scope = {
        "recorded": True, "consistent": True,
        "digest": "sha256:" + "a" * 64,
        "recomputed_digest": "sha256:" + "a" * 64,
        "max_redirects": 2,
        "targets": [{
            "scheme": HOSTILE, "host": HOSTILE, "port": 8000,
            "path_prefixes": [HOSTILE], "methods": [HOSTILE],
        }],
        "targets_summary": [HOSTILE],
        "withheld": ["allowed_addresses"],
    }
    doc = aggregate_document(groups=[group], scope=scope)
    doc["session"]["operator"] = HOSTILE
    return doc


class TestHtmlCannotBecomeCode:
    def test_a_hostile_report_has_no_executable_context(self, api: TestClient,
                                                        fake_engine: FakeEngine):
        a_session(api)
        fake_engine.aggregate_document = hostile_aggregate()

        response = api.get("/v1/sessions/s1/report?format=html")
        assert response.status_code == 200, response.text
        assert_no_executable_context(response.text)

    def test_the_payload_is_still_visible_as_text(self, api: TestClient,
                                                  fake_engine: FakeEngine):
        """Escaped, not dropped. A reader must be able to see what arrived."""
        a_session(api)
        fake_engine.aggregate_document = hostile_aggregate()

        page = inspect(api.get("/v1/sessions/s1/report?format=html").text)
        # convert_charrefs turns the escaped entities back into characters in the
        # TEXT, which is exactly the point: it was a text node, not markup.
        assert "<script>alert(1)</script>" in page.text, \
            "the payload was dropped instead of being shown as text"
        assert "javascript:alert(3)" in page.text

    def test_the_hostile_markup_did_not_become_elements(self, api: TestClient,
                                                        fake_engine: FakeEngine):
        a_session(api)
        fake_engine.aggregate_document = hostile_aggregate()
        page = inspect(api.get("/v1/sessions/s1/report?format=html").text)
        for forbidden in ("script", "img", "iframe", "a", "style"):
            if forbidden == "style":
                # A single stylesheet block is expected; the payload must not add
                # another.
                assert page.elements.count("style") <= 1, \
                    "the payload introduced a style element"
                continue
            assert forbidden not in page.elements, \
                f"the payload became a real <{forbidden}> element"

    def test_a_clean_report_is_also_free_of_executable_context(self, api: TestClient):
        a_session(api)
        response = api.get("/v1/sessions/s1/report?format=html")
        assert response.status_code == 200
        page = assert_no_executable_context(response.text)
        assert page.csp, "the saved-to-disk fallback policy is missing"

    def test_the_shared_checker_would_catch_an_unsafe_page(self):
        """The checker must fail on something genuinely unsafe, or it proves nothing.

        Kept here as well as in the checker's own unit tests: this asserts that the
        module these tests actually loaded is the one that refuses.
        """
        for unsafe in (
            "<html><body><script>alert(1)</script></body></html>",
            "<html><body><div onclick=\"x()\">hi</div></body></html>",
            "<html><body><a href=\"javascript:alert(1)\">x</a></body></html>",
            "<html><body><img src=\"https://evil.invalid/x.png\"></body></html>",
            "<html><body><div style=\"x\">hi</div></body></html>",
            "<html><head><meta http-equiv=\"refresh\" content=\"0\"></head></html>",
        ):
            with pytest.raises(AssertionError):
                assert_no_executable_context(unsafe)


class TestResponseHeaders:
    def test_the_served_html_carries_the_policy_headers(self, api: TestClient):
        a_session(api)
        response = api.get("/v1/sessions/s1/report?format=html")
        assert response.status_code == 200

        assert response.headers["content-type"] == "text/html; charset=utf-8"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["referrer-policy"] == "no-referrer"

        csp = response.headers["content-security-policy"]
        for directive in ("default-src 'none'", "form-action 'none'",
                          "base-uri 'none'", "frame-ancestors 'none'", "sandbox"):
            assert directive in csp, f"the policy is missing {directive!r}: {csp}"

    def test_the_meta_policy_matches_the_header(self, api: TestClient):
        a_session(api)
        response = api.get("/v1/sessions/s1/report?format=html")
        page = inspect(response.text)
        assert page.csp == response.headers["content-security-policy"]


class TestScopePresentation:
    def test_a_coherent_scope_is_presented_as_the_scope(self, api: TestClient):
        a_session(api)
        document = api.get("/v1/sessions/s1/report").json()
        scope = document["scope"]
        assert scope["trustworthy"] is True
        assert scope["recorded"] is True and scope["consistent"] is True
        assert "NOT" not in scope["title"]
        assert scope["targets"], "the structural scope should be shown"

    def test_a_scope_that_does_not_match_its_digest_is_not_presented_as_coherent(
            self, api: TestClient, fake_engine: FakeEngine):
        a_session(api)
        fake_engine.aggregate_document = aggregate_document(scope={
            "recorded": True, "consistent": False,
            "inconsistency_reason": "the stored scope hashes to sha256:zzz but the "
                                    "record stores sha256:aaa; the two disagree",
            "digest": "sha256:" + "a" * 64,
            "recomputed_digest": "sha256:" + "9" * 64,
            "targets": [{"scheme": "http", "host": "testbed", "port": 8000,
                         "path_prefixes": ["/api"], "methods": ["GET"]}],
            "targets_summary": ["http://testbed:8000"],
        })

        document = api.get("/v1/sessions/s1/report").json()
        scope = document["scope"]
        assert scope["trustworthy"] is False
        assert scope["consistent"] is False
        assert "NOT" in scope["title"] or "not" in scope["title"]
        assert "disagree" in scope["reason"]

        page = api.get("/v1/sessions/s1/report?format=html")
        text = inspect(page.text).text
        assert "not an established description" in text, \
            "the page must say plainly that the scope is not established"
        assert "disagree" in text, "the reason must be shown"
        assert_no_executable_context(page.text)

    def test_a_session_without_a_recorded_scope_is_only_a_targets_summary(
            self, api: TestClient, fake_engine: FakeEngine):
        a_session(api)
        fake_engine.aggregate_document = aggregate_document(scope={
            "recorded": False, "consistent": False,
            "inconsistency_reason": "the engine that ran this session did not record "
                                    "the scope its client enforced; this is a summary "
                                    "of targets, not the session's full scope",
            "digest": "sha256:" + "a" * 64,
            "targets_summary": ["http://testbed:8000"],
        })

        document = api.get("/v1/sessions/s1/report").json()
        scope = document["scope"]
        assert scope["recorded"] is False
        assert scope["trustworthy"] is False
        assert scope["targets"] == [], "no structural scope may be claimed"
        assert "Targets summary" in scope["title"]

        text = inspect(api.get("/v1/sessions/s1/report?format=html").text).text
        assert "not the session's full scope" in text

    def test_authorised_addresses_never_reach_the_report(self, api: TestClient,
                                                         fake_engine: FakeEngine):
        """Even if a future aggregate started including them, this path filters."""
        a_session(api)
        fake_engine.aggregate_document = aggregate_document(scope={
            "recorded": True, "consistent": True,
            "digest": "sha256:" + "a" * 64,
            "recomputed_digest": "sha256:" + "a" * 64,
            "targets": [{
                "scheme": "http", "host": "testbed", "port": 8000,
                "path_prefixes": ["/api"], "methods": ["GET"],
                # Should not be here, and must not escape through the report.
                "allowed_addresses": ["172.19.0.2/32"],
            }],
            "targets_summary": ["http://testbed:8000"],
            "withheld": ["allowed_addresses"],
        })

        document = api.get("/v1/sessions/s1/report").json()
        raw = json.dumps(document)
        assert "172.19.0.2" not in raw, "an authorised address reached the JSON report"
        for target in document["scope"]["targets"]:
            assert "allowed_addresses" not in target

        page = api.get("/v1/sessions/s1/report?format=html").text
        assert "172.19.0.2" not in page, "an authorised address reached the HTML report"


class TestCompleteness:
    def test_a_whole_run_is_reported_complete(self, api: TestClient,
                                              fake_engine: FakeEngine, db):
        _finish_a_session(api, fake_engine, db)
        document = api.get("/v1/sessions/s1/report").json()
        assert document["completeness"]["complete"] is True
        text = inspect(api.get("/v1/sessions/s1/report?format=html").text).text
        assert "Complete result set" in text

    def test_an_engine_that_lost_cases_makes_the_report_incomplete(
            self, api: TestClient, fake_engine: FakeEngine, db):
        _finish_a_session(api, fake_engine, db)
        doc = aggregate_document()
        doc["completeness"]["unsaved_cases"] = 3
        doc["completeness"]["incomplete_reason"] = "three indicators were not written down"
        fake_engine.aggregate_document = doc

        document = api.get("/v1/sessions/s1/report").json()
        c = document["completeness"]
        assert c["complete"] is False
        assert c["engine_saved_everything"] is False
        assert c["stream_whole"] is True, "the stream was fine; only the engine lost things"
        sides = {r["side"] for r in c["reasons"]}
        assert sides == {"engine"}, f"the reason must be attributed to the engine: {c['reasons']}"
        assert c["warning"]

        text = inspect(api.get("/v1/sessions/s1/report?format=html").text).text
        assert "Incomplete result set" in text
        assert "Absence of a finding here does not mean" in text
        assert "The engine" in text

    def test_a_broken_stream_makes_the_report_incomplete(
            self, api: TestClient, fake_engine: FakeEngine, db):
        """The other source, independently: the engine is content, the stream is not."""
        a_session(api)
        db.append_event("s1", event(1, "started"))
        db.append_event("s1", event(3, "progress"))  # a gap at 2
        db.update_session("s1", total_seq=3, engine_status="completed",
                          status=store.COMPLETED)
        db.refresh_completeness("s1")

        document = api.get("/v1/sessions/s1/report").json()
        c = document["completeness"]
        assert c["complete"] is False
        assert c["stream_whole"] is False
        sides = {r["side"] for r in c["reasons"]}
        assert "orchestrator" in sides

        text = inspect(api.get("/v1/sessions/s1/report?format=html").text).text
        assert "The orchestrator" in text

    def test_no_findings_with_an_incomplete_stream_still_warns(
            self, api: TestClient, fake_engine: FakeEngine, db):
        a_session(api)
        db.append_event("s1", event(1, "started"))
        db.append_event("s1", event(5, "progress"))
        db.update_session("s1", total_seq=5)
        db.refresh_completeness("s1")
        fake_engine.aggregate_document = aggregate_document(
            groups=[], totals={"cases": 0, "indicator_instances": 0, "groups": 0})

        text = inspect(api.get("/v1/sessions/s1/report?format=html").text).text
        assert "No indicator was stored" in text
        assert "Absence of a finding here does not mean" in text


class TestConservation:
    @pytest.mark.parametrize("fmt", ["json", "html"])
    def test_totals_that_disagree_with_the_groups_produce_no_report(
            self, api: TestClient, fake_engine: FakeEngine, fmt: str):
        """A document that contradicts itself must not come back as a result.

        Returning 200 with a warning inside was the wrong shape: the warning is the
        part a reader skips and the numbers are the part they quote. Neither format
        may succeed.
        """
        a_session(api)
        doc = aggregate_document(groups=[aggregate_group(case_ids=["s1-000001"])])
        doc["totals"]["indicator_instances"] = 99  # not what the groups add up to
        fake_engine.aggregate_document = doc

        response = api.get(f"/v1/sessions/s1/report?format={fmt}")
        assert response.status_code == 502, \
            f"{fmt}: a self-contradicting aggregate produced a successful report"
        detail = response.json()["detail"]
        assert "no report was produced" in detail
        assert "99" in detail and "1" in detail, \
            f"the refusal should name both numbers: {detail}"

    @pytest.mark.parametrize("fmt", ["json", "html"])
    def test_a_case_count_that_disagrees_also_produces_no_report(
            self, api: TestClient, fake_engine: FakeEngine, fmt: str):
        a_session(api)
        doc = aggregate_document(groups=[aggregate_group(case_ids=["s1-000001"])])
        doc["totals"]["cases"] = 7  # more cases than the groups cover
        fake_engine.aggregate_document = doc

        response = api.get(f"/v1/sessions/s1/report?format={fmt}")
        assert response.status_code == 502, f"{fmt}: accepted a case-count mismatch"

    @pytest.mark.parametrize("fmt", ["json", "html"])
    def test_a_sound_aggregate_still_produces_a_report(
            self, api: TestClient, fake_engine: FakeEngine, fmt: str):
        """The other half: refusing the broken one must not refuse the good one."""
        a_session(api)
        fake_engine.aggregate_document = aggregate_document(
            groups=[aggregate_group(case_ids=["s1-000001", "s1-000002"])])

        response = api.get(f"/v1/sessions/s1/report?format={fmt}")
        assert response.status_code == 200, f"{fmt}: a sound aggregate was refused"
        if fmt == "json":
            assert response.json()["conservation"]["consistent"] is True
        else:
            assert_no_executable_context(response.text)

    def test_a_consistent_aggregate_reports_conservation_holding(self, api: TestClient):
        a_session(api)
        document = api.get("/v1/sessions/s1/report").json()
        assert document["conservation"]["consistent"] is True

    def test_every_case_id_is_kept_in_the_json_even_when_the_page_truncates(
            self, api: TestClient, fake_engine: FakeEngine):
        many = [f"s1-{i:06d}" for i in range(1, 41)]
        a_session(api)
        fake_engine.aggregate_document = aggregate_document(
            groups=[aggregate_group(case_ids=many)])

        document = api.get("/v1/sessions/s1/report").json()
        assert document["groups"][0]["case_ids"] == many, \
            "the JSON report must keep every case id"

        text = inspect(api.get("/v1/sessions/s1/report?format=html").text).text
        assert "40" in text
        assert "further case id(s) are not listed here" in text, \
            "a page that shows fewer ids must say how many it left out"


class TestNoVerdicts:
    def test_every_mention_of_a_vulnerability_is_a_denial(self, api: TestClient,
                                                         fake_engine: FakeEngine):
        """Forbidding the word outright is the wrong test: the required disclaimer
        contains it ("not a confirmed vulnerability"). What must hold is that the
        word never appears as a claim -- so every occurrence is checked for a
        negation immediately before it.
        """
        a_session(api)
        fake_engine.aggregate_document = hostile_aggregate()

        as_json = json.dumps(api.get("/v1/sessions/s1/report").json()).lower()
        as_html = api.get("/v1/sessions/s1/report?format=html").text.lower()

        for label, text in (("JSON", as_json), ("HTML", as_html)):
            occurrences = 0
            start = 0
            while True:
                at = text.find("vulnerabilit", start)
                if at < 0:
                    break
                occurrences += 1
                window = text[max(0, at - 40):at]
                assert "not" in window, (
                    f"the {label} report mentions a vulnerability without denying "
                    f"it: ...{text[max(0, at - 60):at + 40]}...")
                start = at + 1
            assert occurrences > 0, f"the {label} report carries no disclaimer at all"

    def test_no_output_asserts_exploitability(self, api: TestClient,
                                             fake_engine: FakeEngine):
        a_session(api)
        fake_engine.aggregate_document = hostile_aggregate()
        as_json = json.dumps(api.get("/v1/sessions/s1/report").json()).lower()
        as_html = api.get("/v1/sessions/s1/report?format=html").text.lower()
        for forbidden in ("exploitable", "proof of exploit", "successfully exploited"):
            assert forbidden not in as_json, f"the JSON report says {forbidden!r}"
            assert forbidden not in as_html, f"the HTML report says {forbidden!r}"

    def test_no_group_carries_a_verdict_shaped_field(self, api: TestClient):
        """Structural, so a future field cannot smuggle a judgement past the prose."""
        a_session(api)
        document = api.get("/v1/sessions/s1/report").json()
        for group in document["groups"]:
            for key in group:
                assert key not in ("verdict", "vulnerability", "cve", "exploit",
                                   "severity"), f"a group carries a {key!r} field"

    def test_every_group_explains_its_rating(self, api: TestClient):
        a_session(api)
        document = api.get("/v1/sessions/s1/report").json()
        for group in document["groups"]:
            classification = group["classification"]
            assert classification["confidence"] in ("low", "medium", "high")
            assert classification["rationale"], "a rating with no reasoning"
            assert classification["note"]


class TestReportPlumbing:
    def test_an_unknown_session_is_404(self, api: TestClient):
        assert api.get("/v1/sessions/nope/report").status_code == 404

    def test_an_unsupported_format_is_refused(self, api: TestClient):
        a_session(api)
        assert api.get("/v1/sessions/s1/report?format=pdf").status_code == 400

    def test_an_engine_that_cannot_be_read_produces_no_report(
            self, api: TestClient, fake_engine: FakeEngine):
        """Half the sources is not a report."""
        a_session(api)
        fake_engine.aggregate_status = 500
        response = api.get("/v1/sessions/s1/report")
        assert response.status_code == 502
        assert "no report can be produced" in response.json()["detail"]

    def test_the_report_is_derived_on_every_read(self, api: TestClient,
                                                 fake_engine: FakeEngine):
        a_session(api)
        first = api.get("/v1/sessions/s1/report").json()
        assert first["completeness"]["complete"] in (True, False)
        calls = fake_engine.aggregate_calls

        # A later-discovered gap must change the answer, which it cannot do if the
        # report was cached.
        api.get("/v1/sessions/s1/report")
        assert fake_engine.aggregate_calls == calls + 1, \
            "the report was served without re-reading the engine"

    def test_an_unsafe_session_id_is_refused(self, api: TestClient):
        for session_id in ("../../escaped", ".hidden", "-rf"):
            response = api.get(f"/v1/sessions/{session_id}/report")
            assert response.status_code >= 400


def _finish_a_session(api: TestClient, fake_engine: FakeEngine, db) -> None:
    """A session whose stream arrived whole."""
    a_session(api)
    db.append_event("s1", event(1, "started"))
    db.append_event("s1", finding_event(2, "s1-000001"))
    db.append_event("s1", event(3, "done", done={"status": "completed", "total_seq": 3}))
    db.update_session("s1", total_seq=3, engine_status="completed",
                      status=store.COMPLETED)
    db.refresh_completeness("s1")


# --- the shared golden document ---------------------------------------------


def _golden_path() -> pathlib.Path:
    """Where the shared golden document is, in a container or in a checkout.

    The test runner mounts schemas/ read-only at /schemas; running pytest from a
    checkout finds it relative to the repository instead. One file either way --
    a copy inside the test tree would be free to drift from what Go produces,
    which is the whole thing the golden document exists to prevent.
    """
    candidates = [
        pathlib.Path("/schemas/examples/aggregate.golden.json"),
        pathlib.Path(__file__).resolve().parents[2] / "schemas" / "examples" / "aggregate.golden.json",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


GOLDEN = _golden_path()


def load_golden() -> dict[str, Any]:
    with GOLDEN.open(encoding="utf-8") as handle:
        return json.load(handle)


class TestTheGoldenAggregateIsUnderstood:
    """The other half of the cross-language contract.

    A Go test asserts the engine still produces this exact document; these assert
    Python still understands it. A field renamed on either side fails one of the
    two at once, instead of surviving until a live run.
    """

    def test_the_golden_file_is_committed(self):
        assert GOLDEN.exists(), (
            f"{GOLDEN} is missing; regenerate it with "
            f"scripts/go.sh test ./internal/aggregate/ -run TestGolden -update")

    def test_every_field_the_report_depends_on_is_present(self):
        doc = load_golden()
        assert doc["aggregate_version"] == "1"
        for key in ("session", "scope", "completeness", "totals", "groups", "note"):
            assert key in doc, f"the golden document has no {key!r}"
        for key in ("recorded", "consistent", "digest", "targets_summary"):
            assert key in doc["scope"], f"scope has no {key!r}"
        for key in ("engine_status", "saved_cases_stated", "cases_in_store", "consistent"):
            assert key in doc["completeness"], f"completeness has no {key!r}"
        for key in ("cases", "indicator_instances", "groups"):
            assert key in doc["totals"], f"totals has no {key!r}"
        for group in doc["groups"]:
            for key in ("group_id", "signature", "occurrences", "case_ids",
                        "representative"):
                assert key in group, f"a group has no {key!r}"
            for key in ("indicator_type", "target", "method", "path"):
                assert key in group["signature"], f"a signature has no {key!r}"
            for key in ("case_id", "case_index", "reason"):
                assert key in group["representative"], f"a representative has no {key!r}"

    def test_the_conservation_identities_hold_on_it(self):
        doc = load_golden()
        summed = sum(g["occurrences"] for g in doc["groups"])
        assert summed == doc["totals"]["indicator_instances"]
        covered = {cid for g in doc["groups"] for cid in g["case_ids"]}
        assert len(covered) == doc["totals"]["cases"]
        assert len(doc["groups"]) == doc["totals"]["groups"]

    def test_it_classifies_and_renders(self):
        doc = load_golden()
        groups = classify.classify_document(doc)
        assert len(groups) == len(doc["groups"])
        for entry in groups:
            assert entry["classification"]["confidence"] in ("low", "medium", "high")
            assert entry["classification"]["rationale"]

        view = {"status": "completed",
                "completeness": {"complete": True, "events_received": 10,
                                 "events_dropped": 0, "last_seq": 10, "total_seq": 10}}
        document = report_mod.build_report("golden", view, doc, groups)
        assert document["conservation"]["consistent"] is True
        assert document["completeness"]["complete"] is True
        assert document["scope"]["trustworthy"] is True

        page = report_mod.render_html(document)
        assert_no_executable_context(page)
        text = inspect(page).text
        assert "golden" in text

    def test_it_carries_no_judgement_from_the_engine(self):
        """The split: the engine groups, the orchestrator rates."""
        raw = GOLDEN.read_text(encoding="utf-8")
        for forbidden in ("confidence", "priority", "severity"):
            assert forbidden not in raw, \
                f"the engine's aggregate carries {forbidden!r}; rating is the " \
                f"orchestrator's job"

    def test_it_withholds_the_authorised_addresses(self):
        raw = GOLDEN.read_text(encoding="utf-8")
        assert "172.19.0.2" not in raw
        doc = load_golden()
        assert doc["scope"]["withheld"] == ["allowed_addresses"]
        for target in doc["scope"]["targets"]:
            assert "allowed_addresses" not in target


class TestTheEnginesOwnVerdictIsDecisive:
    """The engine saying "incomplete" settles it, whatever the counters say.

    The counters were the only thing consulted before, so a run the engine had
    explicitly declared incomplete came back as a complete result set whenever the
    stream was whole and the counters happened to be zero or absent -- which is the
    exact overclaim the completeness rule exists to prevent.
    """

    def _engine_says(self, status: str, **extra) -> dict[str, Any]:
        completeness = {
            "engine_status": status,
            "saved_cases_stated": 1, "cases_in_store": 1,
            "unsaved_cases": 0, "audit_failures": 0, "consistent": True,
        }
        completeness.update(extra)
        return aggregate_document(completeness=completeness)

    @pytest.mark.parametrize("status", ["incomplete", "failed"])
    def test_a_declared_incompleteness_is_decisive_with_no_counters(
            self, api: TestClient, fake_engine: FakeEngine, db, status: str):
        """Every counter zero, no reason field, the stream whole -- still not complete."""
        _finish_a_session(api, fake_engine, db)
        fake_engine.aggregate_document = self._engine_says(status)

        document = api.get("/v1/sessions/s1/report").json()
        completeness = document["completeness"]

        assert completeness["stream_whole"] is True, \
            "precondition: the stream must be whole, or this proves nothing"
        assert completeness["engine_saved_everything"] is False
        assert completeness["complete"] is False, \
            f"the engine declared {status!r} and the report called the results complete"

        sides = {r["side"] for r in completeness["reasons"]}
        assert sides == {"engine"}
        assert completeness["warning"]

    @pytest.mark.parametrize("status", ["incomplete", "failed"])
    def test_neither_format_describes_it_as_complete(
            self, api: TestClient, fake_engine: FakeEngine, db, status: str):
        _finish_a_session(api, fake_engine, db)
        fake_engine.aggregate_document = self._engine_says(status)

        as_json = api.get("/v1/sessions/s1/report").json()
        assert as_json["completeness"]["complete"] is False

        page = api.get("/v1/sessions/s1/report?format=html")
        text = inspect(page.text).text
        assert "Incomplete result set" in text
        assert "Complete result set" not in text, \
            "the page describes a declared-incomplete run as a complete result set"
        assert SUBSET_WARNING_TEXT in text
        assert_no_executable_context(page.text)

    def test_the_reason_is_shown_even_though_the_engine_gave_none(
            self, api: TestClient, fake_engine: FakeEngine, db):
        """A bare status with no incomplete_reason must still explain itself."""
        _finish_a_session(api, fake_engine, db)
        fake_engine.aggregate_document = self._engine_says("incomplete")

        reasons = api.get("/v1/sessions/s1/report").json()["completeness"]["reasons"]
        assert reasons, "a declared incompleteness with no reason produced no reason"
        assert any("could not record" in r["reason"] for r in reasons), reasons

        text = inspect(api.get("/v1/sessions/s1/report?format=html").text).text
        assert "could not record" in text

    def test_a_completed_engine_status_is_still_complete(
            self, api: TestClient, fake_engine: FakeEngine, db):
        """The guard must not make everything incomplete."""
        _finish_a_session(api, fake_engine, db)
        fake_engine.aggregate_document = self._engine_says("completed")
        assert api.get("/v1/sessions/s1/report").json()["completeness"]["complete"] is True

    def test_a_stopped_run_is_not_called_incomplete_but_says_it_stopped(
            self, api: TestClient, fake_engine: FakeEngine, db):
        """A stopped run holds everything it produced; it just did not cover the plan."""
        _finish_a_session(api, fake_engine, db)
        fake_engine.aggregate_document = self._engine_says("stopped")

        completeness = api.get("/v1/sessions/s1/report").json()["completeness"]
        assert completeness["complete"] is True
        assert completeness["stopped_early"] is True

        text = inspect(api.get("/v1/sessions/s1/report?format=html").text).text
        assert "stopped early" in text
        assert "not the same as everything the plan would have covered" in text
