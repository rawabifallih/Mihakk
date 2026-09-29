"""Tests for the strict readers of external-command output.

Covers all three: the container port tables, the resolved compose config, and
the in-container probe's report.

The behaviour under test is refusal. Each of these inputs was once absorbed
into something that looked clean -- an empty mapping read as "no host
bindings", an empty problems list read as "nothing wrong", a partial report
read as a completed run -- so the isolation check passed on evidence it never
had. Each must now be an error the caller is obliged to notice.
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_container_ports import (  # noqa: E402
    EXIT_OK,
    EXIT_UNVERIFIABLE,
    Unreadable,
    describe,
    parse_port_table,
)

SCRIPT = Path(__file__).resolve().parent / "check_container_ports.py"


class TestRefusesUnreadableInput(unittest.TestCase):
    """None of these may be read as "no bindings"."""

    UNREADABLE = {
        "docker inspect failed (no output)": "",
        "whitespace only": "   \n  ",
        "bare null": "null",
        "null with whitespace": "  null\n",
        "malformed json": "{not json",
        "truncated json": '{"8000/tcp":',
        "a list, not an object": '["8000/tcp"]',
        "a string": '"8000/tcp"',
        "a number": "42",
        "a bool": "true",
        "bindings are a string": '{"8000/tcp": "0.0.0.0:8000"}',
        "bindings are a number": '{"8000/tcp": 8000}',
        "binding entry is not an object": '{"8000/tcp": ["0.0.0.0:8000"]}',
        "binding entry lacks HostPort": '{"8000/tcp": [{"HostIp": "0.0.0.0"}]}',
    }

    def test_each_unreadable_input_raises(self):
        for name, raw in self.UNREADABLE.items():
            with self.subTest(name=name):
                with self.assertRaises(Unreadable, msg=f"{name!r} was accepted"):
                    parse_port_table(raw, "test")

    def test_none_input_raises(self):
        with self.assertRaises(Unreadable):
            parse_port_table(None, "test")

    def test_cli_exits_two_for_each_unreadable_input(self):
        for name, raw in self.UNREADABLE.items():
            with self.subTest(name=name):
                result = subprocess.run(
                    [sys.executable, str(SCRIPT), raw, "{}"],
                    capture_output=True, text=True, timeout=30,
                )
                self.assertEqual(
                    result.returncode, EXIT_UNVERIFIABLE,
                    f"{name!r} exited {result.returncode}, expected {EXIT_UNVERIFIABLE}",
                )
                payload = json.loads(result.stdout)
                self.assertIn("error", payload, f"{name!r} produced no error message")
                self.assertNotIn("bound", payload, f"{name!r} produced a bindings report anyway")

    def test_a_bad_second_table_is_also_refused(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "{}", "null"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, EXIT_UNVERIFIABLE)
        self.assertIn("HostConfig.PortBindings", json.loads(result.stdout)["error"])


class TestAcceptsRealInput(unittest.TestCase):
    """The shapes Docker actually produces must still be read."""

    def test_empty_table(self):
        self.assertEqual(parse_port_table("{}", "test"), {})

    def test_exposed_but_unpublished(self):
        table = parse_port_table('{"8000/tcp": null}', "test")
        self.assertEqual(table, {"8000/tcp": None})

    def test_published_binding(self):
        raw = '{"8000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "18000"}]}'
        table = parse_port_table(raw, "test")
        report = describe(table, {})
        self.assertEqual(len(report["bound"]), 1)
        self.assertIn("18000", report["bound"][0])

    def test_requested_but_not_live(self):
        """Docker ignores `ports:` on an internal network, so the request
        shows up only in HostConfig.PortBindings."""
        live = parse_port_table('{"8000/tcp": null}', "live")
        requested = parse_port_table('{"8000/tcp": [{"HostIp": "", "HostPort": "19999"}]}', "req")
        report = describe(live, requested)
        self.assertEqual(len(report["bound"]), 1)
        self.assertIn("19999", report["bound"][0])
        self.assertIn("requested", report["bound"][0])

    def test_clean_case_exits_zero_with_no_bindings(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), '{"8000/tcp": null}', "{}"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, EXIT_OK)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["bound"], [])
        self.assertEqual(payload["exposed"], ["8000/tcp"])


ALL_THREE = {
    "no_default_route": {"status": "pass", "detail": "no default route"},
    "external_connect_refused": {"status": "pass", "detail": "ENETUNREACH"},
    "testbed_reachable_by_service_name": {"status": "pass", "detail": "reachable"},
}


def probe_report(checks, exit_code):
    """Run the probe-report reader over a synthetic report."""
    return subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parent / "check_probe_report.py"), str(exit_code)],
        input=json.dumps({"checks": checks}), capture_output=True, text=True, timeout=30,
    )


class TestProbeReportReader(unittest.TestCase):
    """A partial report, or one that contradicts the exit code, is untrusted."""

    def test_a_complete_consistent_report_is_accepted(self):
        result = probe_report(ALL_THREE, 0)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("end|", result.stdout)
        self.assertEqual(result.stdout.count("pass|"), 3)

    def test_a_report_with_only_one_passing_check_is_refused(self):
        """The case that used to read as a clean run.

        Any non-empty checks mapping was accepted, so a report carrying one
        passing check looked identical to one where all three had run.
        """
        result = probe_report({"no_default_route": ALL_THREE["no_default_route"]}, 0)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("invalid|", result.stdout)
        self.assertIn("external_connect_refused", result.stdout)
        self.assertIn("testbed_reachable_by_service_name", result.stdout)
        self.assertNotIn("pass|", result.stdout, "a refused report must not emit passing checks")

    def test_each_missing_check_is_named(self):
        for omitted in ALL_THREE:
            with self.subTest(omitted=omitted):
                partial = {k: v for k, v in ALL_THREE.items() if k != omitted}
                result = probe_report(partial, 0)
                self.assertEqual(result.returncode, 2)
                self.assertIn(omitted, result.stdout)

    def test_an_all_pass_report_with_a_non_zero_exit_is_refused(self):
        """The probe exits 0 only when everything passed, so this is a
        contradiction, and the optimistic half must not be believed."""
        for code in (1, 2, 3, 137):
            with self.subTest(exit_code=code):
                result = probe_report(ALL_THREE, code)
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertIn("disagree", result.stdout)
                self.assertNotIn("pass|", result.stdout)

    def test_a_failing_report_with_a_zero_exit_is_refused(self):
        checks = dict(ALL_THREE)
        checks["no_default_route"] = {"status": "fail", "detail": "default route present"}
        result = probe_report(checks, 0)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("disagree", result.stdout)

    def test_a_failing_report_with_exit_one_is_accepted(self):
        """A genuine failure is readable; it is the disagreement that is not."""
        checks = dict(ALL_THREE)
        checks["no_default_route"] = {"status": "fail", "detail": "default route present"}
        result = probe_report(checks, 1)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("fail|no_default_route", result.stdout)

    def test_unreadable_reports_are_refused(self):
        script = Path(__file__).resolve().parent / "check_probe_report.py"
        for name, raw in {
            "empty": "",
            "malformed": "{not json",
            "a list": "[1,2]",
            "no checks key": '{"all_passed": true}',
            "empty checks": '{"checks": {}}',
            "check is not an object": '{"checks": {"no_default_route": "pass"}}',
            "unknown status": '{"checks": {"no_default_route": {"status": "maybe"}}}',
        }.items():
            with self.subTest(name=name):
                result = subprocess.run(
                    [sys.executable, str(script), "0"],
                    input=raw, capture_output=True, text=True, timeout=30,
                )
                self.assertEqual(result.returncode, 2, f"{name}: {result.stdout}")
                self.assertIn("invalid|", result.stdout)

    def test_a_missing_exit_code_is_refused(self):
        script = Path(__file__).resolve().parent / "check_probe_report.py"
        result = subprocess.run(
            [sys.executable, str(script)],
            input=json.dumps({"checks": ALL_THREE}), capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid|", result.stdout)


class TestComposeCheckerRefusesUnreadableConfig(unittest.TestCase):
    """The same rule for the resolved compose config."""

    CHECKER = Path(__file__).resolve().parent / "check_testbed_isolation.py"

    UNREADABLE = {
        "empty (command failed)": "",
        "whitespace": "  \n ",
        "malformed json": "{not json",
        "bare null": "null",
        "a list": "[1, 2]",
        "no services key": '{"networks": {}}',
        "services is a string": '{"services": "x"}',
        "services is a list": '{"services": []}',
        "networks is a list": '{"services": {"testbed": {}}, "networks": []}',
        "the service is a string": '{"services": {"testbed": "x"}, "networks": {}}',
    }

    def test_unreadable_config_exits_two(self):
        for name, raw in self.UNREADABLE.items():
            with self.subTest(name=name):
                result = subprocess.run(
                    [sys.executable, str(self.CHECKER)],
                    input=raw, capture_output=True, text=True, timeout=30,
                )
                self.assertEqual(
                    result.returncode, 2,
                    f"{name!r} exited {result.returncode}, expected 2 (unverifiable)",
                )
                payload = json.loads(result.stdout)
                self.assertIn("error", payload)
                self.assertNotIn(
                    "problems", payload,
                    f"{name!r} produced a problems list, which a caller could read as clean",
                )

    def test_readable_configs_use_zero_and_one(self):
        clean = json.dumps({
            "services": {"testbed": {"networks": {"net": None}}},
            "networks": {"net": {"internal": True}},
        })
        result = subprocess.run(
            [sys.executable, str(self.CHECKER)],
            input=clean, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["problems"], [])

        broken = json.dumps({
            "services": {"testbed": {"ports": ["8000:8000"], "networks": {"net": None}}},
            "networks": {"net": {"internal": True}},
        })
        result = subprocess.run(
            [sys.executable, str(self.CHECKER)],
            input=broken, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 1, "a config with problems should exit 1, not 2")
        self.assertTrue(json.loads(result.stdout)["problems"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
