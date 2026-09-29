"""Tests for the run-report reader.

The reader's whole reason for existing is that its input arrives over HTTP, so
the tests that matter most are the hostile ones: a value carrying shell
metacharacters must be treated as text, and a value that is missing must produce
UNVERIFIED rather than a pass.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
READER = HERE / "read_run_report.py"

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_UNVERIFIED = 2


def finding(case_id: str = "s-000001", confidence: str | None = None) -> dict:
    indicator: dict = {"type": "http_5xx", "reason": "the server answered 500"}
    if confidence is not None:
        indicator["confidence"] = confidence
    return {
        "case_id": case_id,
        "session_id": "s",
        "reproduction": {
            "engine_version": "0.5.0",
            "master_seed": "6d69",
            "case_index": 1,
            "corpus_digest": "sha256:" + "a" * 64,
            "config_digest": "sha256:" + "b" * 64,
        },
        "request_summary": {"method": "GET", "url": "http://testbed:8000/api/items",
                           "redacted": True},
        "indicators": [indicator],
    }


def healthy(case_ids: tuple[str, ...] = ("s-000001", "s-000002"),
            padding: int = 1) -> tuple[dict, dict, dict]:
    """A run where everything agrees: events, findings and completeness.

    The finding events carry the same case ids as the stored findings, because
    that agreement is one of the things under test.
    """
    events: list[dict] = [{"seq": 1, "type": "started"}]
    for case_id in case_ids:
        events.append({"seq": len(events) + 1, "type": "finding",
                       "finding": finding(case_id)})
    for _ in range(padding):
        events.append({"seq": len(events) + 1, "type": "progress"})
    total = len(events) + 1
    events.append({"seq": total, "type": "done",
                   "done": {"status": "completed", "total_seq": total}})

    view = {
        "session_id": "s",
        "status": "completed",
        "engine_status": "completed",
        "completeness": {
            "complete": True,
            "events_received": len(events),
            "events_dropped": 0,
            "last_seq": total,
            "total_seq": total,
            "reason": None,
        },
    }
    findings_body = {"findings": [finding(c) for c in case_ids], "count": len(case_ids)}
    return view, findings_body, {"events": events}


class ReaderCase(unittest.TestCase):
    def run_reader(self, view, findings, events) -> tuple[int, list[tuple[str, str]], str]:
        with tempfile.TemporaryDirectory() as tmp:
            paths = []
            for name, body in (("view", view), ("findings", findings), ("events", events)):
                p = pathlib.Path(tmp) / f"{name}.json"
                p.write_text(body if isinstance(body, str) else json.dumps(body))
                paths.append(str(p))
            out = subprocess.run([sys.executable, str(READER), *paths],
                                 capture_output=True, text=True, timeout=60)
        parsed = []
        for line in out.stdout.splitlines():
            if "\t" in line:
                verdict, message = line.split("\t", 1)
                parsed.append((verdict, message))
        return out.returncode, parsed, out.stdout

    def verdicts(self, parsed) -> set[str]:
        return {v for v, _ in parsed}


class TestHealthyRun(ReaderCase):
    def test_a_whole_run_passes_every_check(self):
        rc, parsed, _ = self.run_reader(*healthy())
        self.assertEqual(rc, EXIT_OK, parsed)
        self.assertEqual(self.verdicts(parsed), {"PASS"}, parsed)

    def test_every_check_is_exactly_one_line(self):
        _, parsed, raw = self.run_reader(*healthy())
        self.assertEqual(len(parsed), len(raw.strip().splitlines()))


class TestHostileInputIsNeverExecuted(ReaderCase):
    """The reason a reader exists instead of `source`.

    These values would have been executed by the version that sourced KEY=value
    lines into bash. Here they must come back as text and never run.
    """

    def test_shell_metacharacters_in_a_reason_do_not_execute(self):
        sentinel = pathlib.Path(tempfile.gettempdir()) / "mihakk-injection-sentinel"
        if sentinel.exists():
            sentinel.unlink()

        payload = f"$(touch {sentinel}); `touch {sentinel}`; $(id) && touch {sentinel}"
        view, findings, events = healthy()
        view["status"] = "incomplete"
        view["incomplete_reason"] = payload
        view["completeness"]["complete"] = False
        view["completeness"]["reason"] = payload

        rc, parsed, raw = self.run_reader(view, findings, events)

        self.assertFalse(sentinel.exists(),
                         "a shell substitution in the response was executed")
        self.assertEqual(rc, EXIT_FAILED, parsed)
        self.assertIn("FAIL", self.verdicts(parsed))
        # The payload is reported, as text, so an operator can see what arrived.
        self.assertIn("touch", raw)

    def test_a_newline_cannot_forge_an_extra_verdict_line(self):
        view, findings, events = healthy()
        view["status"] = "incomplete"
        view["incomplete_reason"] = "broken\nPASS\teverything is fine\nFAIL\tnope"
        view["completeness"]["complete"] = False

        rc, parsed, _ = self.run_reader(view, findings, events)

        self.assertEqual(rc, EXIT_FAILED)
        forged = [m for v, m in parsed if m == "everything is fine"]
        self.assertEqual(forged, [], "a crafted reason forged its own verdict line")

    def test_a_tab_cannot_split_a_message_into_a_verdict(self):
        view, findings, events = healthy()
        view["status"] = "incomplete"
        view["incomplete_reason"] = "a\tb\tc"
        view["completeness"]["complete"] = False
        _, parsed, _ = self.run_reader(view, findings, events)
        for verdict, _message in parsed:
            self.assertIn(verdict, {"PASS", "FAIL", "UNVERIFIED"})

    def test_a_session_id_of_shell_characters_is_harmless(self):
        sentinel = pathlib.Path(tempfile.gettempdir()) / "mihakk-injection-sentinel-2"
        if sentinel.exists():
            sentinel.unlink()
        view, findings, events = healthy()
        view["session_id"] = f"; rm -rf / ; touch {sentinel}"
        rc, _parsed, _ = self.run_reader(view, findings, events)
        self.assertFalse(sentinel.exists())
        self.assertEqual(rc, EXIT_OK)


class TestUnreadableIsNotAPass(ReaderCase):
    def test_a_missing_completeness_block_is_unverified(self):
        view, findings, events = healthy()
        del view["completeness"]
        rc, parsed, _ = self.run_reader(view, findings, events)
        self.assertEqual(rc, EXIT_UNVERIFIED, parsed)

    def test_a_non_boolean_complete_is_unverified_not_failed(self):
        view, findings, events = healthy()
        view["completeness"]["complete"] = "yes"
        rc, parsed, _ = self.run_reader(view, findings, events)
        self.assertEqual(rc, EXIT_UNVERIFIED, parsed)

    def test_malformed_json_is_unverified(self):
        _view, findings, events = healthy()
        rc, parsed, _ = self.run_reader("{not json", findings, events)
        self.assertEqual(rc, EXIT_UNVERIFIED, parsed)

    def test_an_empty_response_is_unverified(self):
        _view, findings, events = healthy()
        rc, parsed, _ = self.run_reader("", findings, events)
        self.assertEqual(rc, EXIT_UNVERIFIED, parsed)

    def test_a_partial_event_page_is_unverified_not_failed(self):
        """Fewer events fetched than stored says nothing about contiguity."""
        view, findings, events = healthy()
        events["events"] = events["events"][:2]
        rc, parsed, _ = self.run_reader(view, findings, events)
        self.assertEqual(rc, EXIT_UNVERIFIED, parsed)

    def test_a_missing_engine_status_is_unverified(self):
        view, findings, events = healthy()
        del view["engine_status"]
        rc, parsed, _ = self.run_reader(view, findings, events)
        self.assertEqual(rc, EXIT_UNVERIFIED, parsed)


class TestRealFailuresAreFailures(ReaderCase):
    def test_a_gap_in_the_sequence_fails(self):
        view, findings, events = healthy(case_ids=("s-000001",))
        events["events"] = [{"seq": 1, "type": "started"},
                            {"seq": 3, "type": "finding", "finding": finding("s-000001")},
                            {"seq": 4, "type": "done"}]
        view["completeness"]["last_seq"] = 4
        view["completeness"]["total_seq"] = 4
        view["completeness"]["events_received"] = 3
        rc, parsed, _ = self.run_reader(view, findings, events)
        self.assertEqual(rc, EXIT_FAILED, parsed)

    def test_no_findings_fails(self):
        view, findings, events = healthy()
        findings["findings"] = []
        rc, parsed, _ = self.run_reader(view, findings, events)
        self.assertEqual(rc, EXIT_FAILED, parsed)

    def test_an_engine_assigned_confidence_fails(self):
        view, findings, events = healthy()
        findings["findings"] = [finding(confidence="high")]
        rc, parsed, _ = self.run_reader(view, findings, events)
        self.assertEqual(rc, EXIT_FAILED, parsed)

    def test_a_lost_recipe_fails(self):
        view, findings, events = healthy()
        broken = finding()
        del broken["reproduction"]["master_seed"]
        findings["findings"] = [broken]
        rc, parsed, _ = self.run_reader(view, findings, events)
        self.assertEqual(rc, EXIT_FAILED, parsed)


class TestStoredFindingsMustMatchTheStream(ReaderCase):
    """The acceptance criterion: the stored findings ARE what the engine announced.

    Each of these keeps the event sequence whole and contiguous, so every other
    check still passes. Only the comparison of case ids can catch them, which is
    the point: a complete stream says nothing about whether each finding inside it
    was written down.
    """

    def test_a_dropped_stored_finding_fails(self):
        view, findings, events = healthy(case_ids=("s-000001", "s-000002"))
        findings["findings"] = [f for f in findings["findings"]
                               if f["case_id"] != "s-000002"]
        findings["count"] = 1
        rc, parsed, raw = self.run_reader(view, findings, events)
        self.assertEqual(rc, EXIT_FAILED, parsed)
        self.assertIn("s-000002", raw)
        self.assertIn("announced but not stored", raw)

    def test_a_renamed_stored_finding_fails_both_ways(self):
        view, findings, events = healthy(case_ids=("s-000001", "s-000002"))
        findings["findings"][1]["case_id"] = "s-999999"
        rc, parsed, raw = self.run_reader(view, findings, events)
        self.assertEqual(rc, EXIT_FAILED, parsed)
        self.assertIn("announced but not stored", raw)
        self.assertIn("stored but never announced", raw)

    def test_a_finding_stored_that_was_never_announced_fails(self):
        view, findings, events = healthy(case_ids=("s-000001",))
        findings["findings"].append(finding("s-000042"))
        rc, parsed, raw = self.run_reader(view, findings, events)
        self.assertEqual(rc, EXIT_FAILED, parsed)
        self.assertIn("s-000042", raw)

    def test_a_duplicate_stored_finding_fails(self):
        view, findings, events = healthy(case_ids=("s-000001",))
        findings["findings"].append(finding("s-000001"))
        rc, parsed, raw = self.run_reader(view, findings, events)
        self.assertEqual(rc, EXIT_FAILED, parsed)
        self.assertIn("more than once", raw)

    def test_a_resent_finding_event_is_not_read_as_loss(self):
        """The findings table is keyed on (session, case), so a resend collapses."""
        view, findings, events = healthy(case_ids=("s-000001",))
        resent = {"seq": len(events["events"]) + 1, "type": "finding",
                  "finding": finding("s-000001")}
        events["events"].insert(-1, resent)
        # Renumber so the sequence stays contiguous and the done event stays last.
        for index, event in enumerate(events["events"], start=1):
            event["seq"] = index
        total = len(events["events"])
        events["events"][-1]["done"] = {"status": "completed", "total_seq": total}
        view["completeness"].update(events_received=total, last_seq=total, total_seq=total)

        rc, parsed, raw = self.run_reader(view, findings, events)
        self.assertEqual(rc, EXIT_OK, parsed)
        self.assertIn("duplicates collapse on store", raw)

    def test_a_finding_event_without_a_case_id_is_unverified(self):
        view, findings, events = healthy(case_ids=("s-000001",))
        for event in events["events"]:
            if event.get("type") == "finding":
                del event["finding"]["case_id"]
        rc, parsed, _ = self.run_reader(view, findings, events)
        self.assertEqual(rc, EXIT_UNVERIFIED, parsed)

    def test_findings_with_no_finding_event_at_all_is_unverified(self):
        """Nothing to compare against is not the same as agreement."""
        view, findings, events = healthy(case_ids=("s-000001",))
        events["events"] = [e for e in events["events"] if e.get("type") != "finding"]
        for index, event in enumerate(events["events"], start=1):
            event["seq"] = index
        total = len(events["events"])
        view["completeness"].update(events_received=total, last_seq=total, total_seq=total)
        rc, parsed, _ = self.run_reader(view, findings, events)
        self.assertEqual(rc, EXIT_UNVERIFIED, parsed)


class TestClaimName(unittest.TestCase):
    """The guard that decides whether a test may create a named resource.

    It must fail closed. An inventory that errored, or answered about something
    other than the name asked about, means the name's state is unknown -- and
    unknown must never be treated as free, because the caller goes on to delete
    what it believes it created.
    """

    def claim(self, name: str, rc: int, output: str = ""):
        script = HERE / "claim_name.py"
        out = subprocess.run([sys.executable, str(script), name, str(rc), output],
                             capture_output=True, text=True, timeout=60)
        return out.returncode, out.stdout + out.stderr

    def test_an_empty_inventory_means_the_name_is_free(self):
        rc, _ = self.claim("mihakk-decoy-1_engine-data", 0, "")
        self.assertEqual(rc, 0)

    def test_an_exact_match_means_the_name_is_taken(self):
        rc, message = self.claim("mihakk-decoy-1_engine-data", 0,
                                 "mihakk-decoy-1_engine-data\n")
        self.assertEqual(rc, 1)
        self.assertIn("already exists", message)

    def test_a_failed_inventory_is_unknown_not_free(self):
        for bad_rc in (1, 2, 125, 127):
            rc, message = self.claim("mihakk-decoy-1_engine-data", bad_rc, "")
            self.assertEqual(rc, 2, f"a failed inventory (rc={bad_rc}) was read as free")
            self.assertIn("unknown", message)

    def test_an_inventory_answering_about_something_else_is_unknown(self):
        rc, message = self.claim("mihakk-decoy-1_engine-data", 0,
                                 "some-other-volume\nyet-another\n")
        self.assertEqual(rc, 2)
        self.assertIn("not an exact match", message)

    def test_a_partial_name_match_is_unknown(self):
        rc, _ = self.claim("mihakk-decoy-1_engine-data", 0, "mihakk-decoy-1_engine\n")
        self.assertEqual(rc, 2)

    def test_a_name_with_whitespace_is_refused(self):
        for name in ("", " ", "has space", "trailing "):
            rc, _ = self.claim(name, 0, "")
            self.assertEqual(rc, 2, f"accepted an untrustworthy name {name!r}")

    def test_a_non_integer_inventory_code_is_refused(self):
        script = HERE / "claim_name.py"
        out = subprocess.run([sys.executable, str(script), "a-name", "not-a-number", ""],
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 2)


class TestIsolatedCompose(unittest.TestCase):
    """The derived project must not keep any globally pinned name."""

    def derive(self, config, *extra):
        script = HERE / "isolated_compose.py"
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp) / "resolved.json"
            p.write_text(config if isinstance(config, str) else json.dumps(config))
            out = subprocess.run([sys.executable, str(script), str(p), *extra],
                                 capture_output=True, text=True, timeout=60)
        return out.returncode, out.stdout, out.stderr

    def real_shape(self):
        return {
            "name": "mihakk",
            "services": {
                "testbed": {"container_name": "mihakk-testbed",
                            "networks": {"mihakk-internal": None}},
                "orchestrator": {"container_name": "mihakk-orchestrator",
                                 "ports": [{"mode": "ingress", "target": 8100,
                                            "published": "8100", "protocol": "tcp"}]},
            },
            "networks": {"mihakk-internal": {"name": "mihakk-internal", "internal": True}},
            "volumes": {"engine-data": {"name": "mihakk_engine-data"}},
        }

    def test_every_pinned_name_is_removed(self):
        rc, stdout, err = self.derive(self.real_shape())
        self.assertEqual(rc, 0, err)
        derived = json.loads(stdout)
        self.assertNotIn("name", derived)
        for name, service in derived["services"].items():
            self.assertNotIn("container_name", service, name)
        self.assertNotIn("name", derived["networks"]["mihakk-internal"])
        self.assertNotIn("name", derived["volumes"]["engine-data"])

    def test_what_is_under_test_is_preserved(self):
        rc, stdout, _ = self.derive(self.real_shape())
        self.assertEqual(rc, 0)
        derived = json.loads(stdout)
        self.assertTrue(derived["networks"]["mihakk-internal"]["internal"])
        self.assertIn("mihakk-internal", derived["services"]["testbed"]["networks"])

    def test_the_published_port_can_be_moved(self):
        rc, stdout, err = self.derive(self.real_shape(), "orchestrator", "127.0.0.1", "18100")
        self.assertEqual(rc, 0, err)
        derived = json.loads(stdout)
        port = derived["services"]["orchestrator"]["ports"][0]
        self.assertEqual(port["published"], "18100")
        self.assertEqual(port["host_ip"], "127.0.0.1")
        self.assertEqual(port["target"], 8100)

    def test_an_unreadable_config_is_refused(self):
        for bad in ("{not json", "", "null", json.dumps({"services": {}}),
                    json.dumps({"services": "nope"})):
            rc, _out, _err = self.derive(bad)
            self.assertEqual(rc, 2, f"accepted an unreadable config: {bad!r}")

    def test_overriding_an_absent_service_is_refused(self):
        rc, _out, _err = self.derive(self.real_shape(), "nosuch", "127.0.0.1", "18100")
        self.assertEqual(rc, 2)

    def test_the_host_allowlist_follows_the_moved_port(self):
        """Moving the published port must move the host allowlist with it.

        The orchestrator answers only to the names it is configured for, which is
        what blunts DNS rebinding. A derived project on a random port whose
        allowlist still named the real one refused every request to itself.
        """
        config = self.real_shape()
        config["services"]["orchestrator"]["environment"] = {
            "MIHAKK_ALLOWED_HOSTS": "127.0.0.1:8100,localhost:8100",
            "MIHAKK_DB": "/data/mihakk.db",
        }
        rc, stdout, err = self.derive(config, "orchestrator", "127.0.0.1", "54321")
        self.assertEqual(rc, 0, err)
        derived = json.loads(stdout)
        hosts = derived["services"]["orchestrator"]["environment"]["MIHAKK_ALLOWED_HOSTS"]
        self.assertIn("127.0.0.1:54321", hosts)
        self.assertNotIn("8100", hosts)
        # Other variables are untouched.
        self.assertEqual(
            derived["services"]["orchestrator"]["environment"]["MIHAKK_DB"],
            "/data/mihakk.db")

    def test_a_list_shaped_environment_is_handled_too(self):
        config = self.real_shape()
        config["services"]["orchestrator"]["environment"] = [
            "MIHAKK_ALLOWED_HOSTS=127.0.0.1:8100", "MIHAKK_DB=/data/mihakk.db",
        ]
        rc, stdout, err = self.derive(config, "orchestrator", "127.0.0.1", "54321")
        self.assertEqual(rc, 0, err)
        env = json.loads(stdout)["services"]["orchestrator"]["environment"]
        joined = " ".join(env)
        self.assertIn("MIHAKK_ALLOWED_HOSTS=127.0.0.1:54321", joined)
        self.assertIn("MIHAKK_DB=/data/mihakk.db", joined)
        self.assertNotIn("8100", joined)


class TestReportHtmlChecker(unittest.TestCase):
    """The HTML checker used on the live path.

    It must refuse anything a browser could act on, and must NOT refuse a page that
    correctly shows a hostile payload as escaped text -- the report is required to
    keep the payload readable, so a checker that banned the characters would reject
    the right answer.
    """

    def check(self, markup: str):
        import check_report_html
        return check_report_html.check(markup)

    SAFE_PAGE = (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        'style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">'
        '<title>r</title><style>body{margin:0}</style></head>'
        '<body><h1>Report</h1><pre>PAYLOAD</pre></body></html>'
    )

    def test_a_clean_page_passes(self):
        code, messages = self.check(self.SAFE_PAGE.replace("PAYLOAD", "all well"))
        self.assertEqual(code, 0, messages)

    def test_an_escaped_payload_shown_as_text_still_passes(self):
        payload = ("&lt;script&gt;alert(1)&lt;/script&gt; "
                   "javascript:alert(2) onerror=alert(3) "
                   "&quot;&gt;&lt;img src=x onerror=alert(4)&gt;")
        code, messages = self.check(self.SAFE_PAGE.replace("PAYLOAD", payload))
        self.assertEqual(code, 0,
                         f"a correctly escaped payload was rejected: {messages}")

    def test_each_kind_of_unsafe_page_is_refused(self):
        cases = {
            "script element": "<script>alert(1)</script>",
            "event handler": '<div onclick="x()">x</div>',
            "javascript url": '<a href="javascript:alert(1)">x</a>',
            "data url": '<a href="data:text/html,<script>1</script>">x</a>',
            "external image": '<img src="https://evil.invalid/x.png">',
            "inline style attribute": '<div style="color:red">x</div>',
            "iframe": '<iframe src="/x"></iframe>',
            "form": '<form action="/x"><input name="a"></form>',
            "meta refresh": '<meta http-equiv="refresh" content="0;url=/x">',
        }
        for name, snippet in cases.items():
            page = self.SAFE_PAGE.replace("<pre>PAYLOAD</pre>", snippet)
            code, messages = self.check(page)
            self.assertEqual(code, 1, f"{name} was accepted: {messages}")

    def test_a_missing_policy_is_refused(self):
        page = self.SAFE_PAGE.replace(
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
            'style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">', "")
        code, messages = self.check(page.replace("PAYLOAD", "x"))
        self.assertEqual(code, 1, messages)

    def test_something_that_is_not_html_is_unverified_not_safe(self):
        for junk in ("", "   ", "not markup at all", "{\"json\": true}"):
            code, _ = self.check(junk)
            self.assertEqual(code, 2, f"{junk!r} should be UNVERIFIED, not a pass")


class TestDashboardJsGuard(unittest.TestCase):
    """The guard that keeps the dashboard from turning data into markup.

    The dashboard is the first component that needs JavaScript, so the report's
    "no script at all" defence does not carry over. This guard is what replaces
    it, and it runs in a second without a browser -- which is why it, and not the
    browser test, is the one that fires on every commit.
    """

    def scan(self, source: str):
        import check_dashboard_js
        return check_dashboard_js.scan_text(source)

    def test_clean_source_passes(self):
        source = (
            "const node = document.createElement('p');\n"
            "node.textContent = untrusted;\n"
            "node.setAttribute('data-origin', 'target');\n"
            "parent.appendChild(node);\n"
        )
        self.assertEqual(self.scan(source), [])

    def test_each_forbidden_construct_is_caught(self):
        cases = {
            "innerHTML": "node.innerHTML = untrusted;",
            "outerHTML": "node.outerHTML = untrusted;",
            "insertAdjacentHTML": "node.insertAdjacentHTML('beforeend', untrusted);",
            "document.write": "document.write(untrusted);",
            "document.writeln": "document.writeln(untrusted);",
            "eval": "eval(untrusted);",
            "new Function": "const f = new Function('return 1');",
            "setTimeout string": "setTimeout('doThing()', 10);",
            "setInterval string": "setInterval(\"doThing()\", 10);",
            "srcdoc": "frame.srcdoc = untrusted;",
            "javascript url": "link.href = 'javascript:alert(1)';",
            "document.domain": "document.domain = 'example.test';",
        }
        for label, line in cases.items():
            hits = self.scan(line + "\n")
            self.assertTrue(hits, f"{label} was not caught: {line}")

    def test_prose_explaining_a_construct_is_not_a_violation(self):
        """A comment is not code.

        A guard that refused the word anywhere could not document itself -- the
        same mistake as banning a phrase from a report whose required disclaimer
        contains it.
        """
        source = (
            "// There is no innerHTML here, and no insertAdjacentHTML either:\n"
            "// assigning a string as markup is the failure this avoids.\n"
            "/* eval and new Function are likewise absent. */\n"
            " * document.write would parse a string as markup.\n"
            "node.textContent = value;\n"
        )
        self.assertEqual(self.scan(source), [])

    def test_the_real_dashboard_source_is_clean(self):
        import pathlib
        import check_dashboard_js
        for candidate in (pathlib.Path("/dashboard"),
                          pathlib.Path(__file__).resolve().parents[1] / "dashboard"):
            if (candidate / "assets" / "app.js").is_file():
                hits = check_dashboard_js.scan_file(candidate / "assets" / "app.js")
                self.assertEqual(hits, [], f"the dashboard source is not clean: {hits}")
                return
        self.skipTest("the dashboard source is not mounted here")


if __name__ == "__main__":
    unittest.main(verbosity=2)
