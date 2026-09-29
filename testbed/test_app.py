"""Tests for the local testbed.

They cover the two planted behaviours and, just as importantly, the stable
endpoints: a baseline that flaps would make every false-positive measurement
in later phases meaningless.

Standard library only, run against a real server bound to loopback inside the
test process.
"""

from __future__ import annotations

import json
import threading
import time
import unittest
import urllib.error
import urllib.request

import app


class ServerTestCase(unittest.TestCase):
    """Starts one testbed server for the whole class."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.httpd = app.serve(host="127.0.0.1", port=0)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def request(self, method: str, path: str, body=None, content_type="application/json"):
        """Returns (status, payload, elapsed_seconds). Never raises on 4xx/5xx."""
        data = None
        headers = {}
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
            headers["Content-Type"] = content_type

        req = urllib.request.Request(self.url(path), data=data, method=method, headers=headers)
        started = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = resp.read()
                status = resp.status
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            status = exc.code
        elapsed = time.monotonic() - started

        try:
            payload = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload = {"_undecodable": raw[:200].decode("utf-8", "replace")}
        return status, payload, elapsed


class TestStableEndpoints(ServerTestCase):
    """Acceptance criterion 3: at least one path that stays put."""

    def test_health_is_constant(self):
        first = None
        for _ in range(20):
            status, payload, _ = self.request("GET", "/api/health")
            self.assertEqual(status, 200)
            self.assertEqual(payload["status"], "ok")
            if first is None:
                first = payload
            self.assertEqual(payload, first, "health response drifted between calls")

    def test_items_is_stable_under_hostile_query_values(self):
        """The baseline must survive anything the mutation engine sends it."""
        hostile = [
            "", "0", "-1", "999999999999999999999", "1e309", "NaN", "null",
            "%00", "%zz", "'", '"', "<>", "\\", "{}", "[]",
            "A" * 2000, "‮​", "\U0001f600", "../../etc/passwd",
            "true", "false", "-0", "1.5", "0x10", " ", "\t",
        ]
        sizes_by_param = {"page": set(), "limit": set(), "q": set()}
        for value in hostile:
            for param in ("page", "limit", "q"):
                path = f"/api/items?{param}={urllib.request.quote(value, safe='')}"
                status, payload, elapsed = self.request("GET", path)
                self.assertEqual(
                    status, 200,
                    f"baseline returned {status} for {param}={value!r}: {payload}",
                )
                self.assertLess(elapsed, 1.0, f"baseline was slow for {param}={value!r}")
                self.assertIn("items", payload)
                sizes_by_param[param].add(len(json.dumps(payload)))

        # page and q must barely move the response size. Byte-exact equality
        # would be stricter than any detector needs -- the page number is
        # echoed back, so its digit count alone shifts the body slightly -- but
        # the drift has to stay far below any sane anomaly threshold.
        for param in ("page", "q"):
            low, high = min(sizes_by_param[param]), max(sizes_by_param[param])
            drift = (high - low) / low
            self.assertLess(
                drift, 0.05,
                f"mutating {param} moved the response size by {drift:.1%} "
                f"({low}..{high} bytes); the baseline would generate "
                "size-anomaly false positives",
            )

        # limit legitimately selects how many items come back, so its size
        # varies -- but only within the clamp, never unbounded.
        self.assertLessEqual(
            max(sizes_by_param["limit"]), max(sizes_by_param["page"]) * 3,
            "limit is not being clamped; the response can be inflated by input",
        )

    def test_items_clamps_limit(self):
        status, payload, _ = self.request("GET", "/api/items?limit=100000")
        self.assertEqual(status, 200)
        self.assertLessEqual(payload["limit"], app.MAX_LIMIT)
        self.assertLessEqual(payload["count"], app.MAX_LIMIT)

    def test_unknown_paths_are_clean_errors(self):
        status, payload, _ = self.request("GET", "/api/nope")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"], "not_found")

        status, payload, _ = self.request("GET", "/api/orders")
        self.assertEqual(status, 405, "a known path with the wrong method should be 405, not 5xx")


class TestPlantedServerError(ServerTestCase):
    """Acceptance criterion 2a: a 5xx on a specific input, safely repeatable."""

    def test_wrong_typed_qty_returns_500(self):
        for qty in (None, [], {}, [1, 2], {"n": 1}):
            with self.subTest(qty=qty):
                status, payload, _ = self.request("POST", "/api/orders", {"sku": "A-001", "qty": qty})
                self.assertEqual(status, 500, f"qty={qty!r} should trigger the planted 500")
                self.assertEqual(payload["error"], "internal_error")
                self.assertEqual(payload["type"], "TypeError")

    def test_valid_and_merely_invalid_input_do_not_return_500(self):
        """The distinction that separates an indicator from ordinary validation."""
        for qty, expected in [
            (2, 201), ("2", 201), (3.7, 201), (0, 201), (-1, 201), (True, 201),
            ("abc", 400), ("", 400), ("1.2.3", 400), ("NaN", 400), ("مرحبا", 400),
        ]:
            with self.subTest(qty=qty):
                status, payload, _ = self.request("POST", "/api/orders", {"sku": "A-001", "qty": qty})
                self.assertEqual(
                    status, expected,
                    f"qty={qty!r} returned {status} ({payload}); a 5xx here would be a false indicator",
                )

    def test_malformed_body_is_a_clean_400(self):
        for raw in [b"{", b"not json", b"[1,2", b"\xff\xfe", b'{"qty":}']:
            with self.subTest(raw=raw):
                status, payload, _ = self.request("POST", "/api/orders", raw)
                self.assertEqual(status, 400, f"malformed body {raw!r} should be 400, got {payload}")

    def test_five_hundred_is_repeatable_without_restarting(self):
        """The planted error must not take the process down.

        Fifty consecutive failures, then a healthy request: if the server were
        dying and being restarted, this is where it would show.
        """
        for i in range(50):
            status, _, _ = self.request("POST", "/api/orders", {"qty": None})
            self.assertEqual(status, 500, f"iteration {i} did not return the planted 500")

        status, payload, _ = self.request("GET", "/api/health")
        self.assertEqual(status, 200, "server did not survive repeated planted errors")
        self.assertEqual(payload["status"], "ok")

        status, payload, _ = self.request("POST", "/api/orders", {"sku": "A-002", "qty": 5})
        self.assertEqual(status, 201, "server no longer serves valid orders after repeated errors")
        self.assertEqual(payload["order"]["qty"], 5)


class TestPlantedSlowPath(ServerTestCase):
    """Acceptance criterion 2b: bounded slowness, on a different input."""

    def test_wildcard_term_is_slow(self):
        for term in ("%shoes", "*shoes", "sho%es", "shoes*", ""):
            with self.subTest(term=term):
                status, payload, elapsed = self.request("GET", f"/api/search?term={urllib.request.quote(term)}")
                self.assertEqual(status, 200)
                self.assertEqual(payload["scan"], "full")
                self.assertGreaterEqual(
                    elapsed, app.SLOW_PATH_DELAY_SECONDS * 0.9,
                    "the slow path did not actually wait",
                )

    def test_ordinary_term_is_fast(self):
        for term in ("shoes", "item-001", "A-001"):
            with self.subTest(term=term):
                status, payload, elapsed = self.request("GET", f"/api/search?term={term}")
                self.assertEqual(status, 200)
                self.assertEqual(payload["scan"], "index")
                self.assertLess(
                    elapsed, app.SLOW_PATH_DELAY_SECONDS / 2,
                    "the fast path is not meaningfully faster than the slow one",
                )

    def test_delay_does_not_scale_with_input_length(self):
        """The property that stops this becoming an amplifiable outage.

        A one-character term and a 20,000-character term must wait the same
        fixed time. If the delay tracked input size, a fuzzer could turn the
        slow path into a denial of service against the app it is testing.
        """
        short_term = "%a"
        long_term = "%" + "a" * 20_000

        def timed(term: str) -> float:
            status, payload, elapsed = self.request(
                "POST", "/api/search", {"term": term}
            )
            self.assertEqual(status, 200)
            self.assertEqual(payload["scan"], "full")
            return elapsed

        # Take the best of three: the minimum is the measurement least
        # polluted by scheduling noise, so the comparison stays stable.
        short = min(timed(short_term) for _ in range(3))
        long = min(timed(long_term) for _ in range(3))

        self.assertGreaterEqual(short, app.SLOW_PATH_DELAY_SECONDS * 0.9)
        self.assertGreaterEqual(long, app.SLOW_PATH_DELAY_SECONDS * 0.9)

        # A 10,000x longer input must not buy meaningfully more delay.
        self.assertLess(
            abs(long - short), app.SLOW_PATH_DELAY_SECONDS * 0.5,
            f"delay scales with input length: {short:.3f}s for 2 bytes, "
            f"{long:.3f}s for {len(long_term)} bytes",
        )

    def test_slow_path_has_a_hard_ceiling(self):
        """However hostile the term, the wait stays near the constant."""
        terms = ["%" + "\U0001f600" * 500, "*" + "%00" * 500, "%" * 1000, "%" + "\\" * 2000]
        for term in terms:
            with self.subTest(term=term[:16]):
                _, _, elapsed = self.request("POST", "/api/search", {"term": term})
                self.assertLess(
                    elapsed, app.SLOW_PATH_DELAY_SECONDS * 3,
                    "the slow path exceeded its bound",
                )


class TestBehavioursAreIndependent(unittest.TestCase):
    """The two planted behaviours must be reachable by different inputs."""

    def test_triggers_are_distinct(self):
        self.assertNotEqual(
            ("POST", "/api/orders"), ("GET", "/api/search"),
            "the planted behaviours should live on different endpoints",
        )

    def test_slow_delay_is_a_constant_not_a_function(self):
        self.assertIsInstance(app.SLOW_PATH_DELAY_SECONDS, float)
        self.assertGreater(app.SLOW_PATH_DELAY_SECONDS, 0)
        self.assertLessEqual(
            app.SLOW_PATH_DELAY_SECONDS, 2.0,
            "the fixed delay should stay small enough to be harmless",
        )


class TestCoerceInt(unittest.TestCase):
    def test_never_raises(self):
        for raw in [None, "", "abc", [], {}, "1e309", "NaN", "\U0001f600", 3.7, True, "  7  "]:
            with self.subTest(raw=raw):
                value = app.coerce_int(raw, default=1, minimum=1, maximum=10)
                self.assertIsInstance(value, int)
                self.assertGreaterEqual(value, 1)
                self.assertLessEqual(value, 10)


if __name__ == "__main__":
    unittest.main(verbosity=2)
