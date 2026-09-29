"""Tests for check_networks.py: is the network Docker really has internal?

The half that matters is the refusals. Every way the inspect output can fail to
answer the question -- a failed command, output that is not what inspect prints,
a missing or duplicated network, a field of the wrong type -- has to be exit 2,
never a pass and never quietly "not internal" either.
"""

from __future__ import annotations

import json
import unittest

from check_networks import EXIT_INTERNAL, EXIT_NOT_INTERNAL, EXIT_UNVERIFIED, judge


def net(name, internal=True, driver="bridge", scope="local"):
    return {"Name": name, "Internal": internal, "Driver": driver, "Scope": scope,
            "Id": "f" * 64}


def inspect(*entries):
    return json.dumps(list(entries))


class TestVerdicts(unittest.TestCase):
    def test_an_internal_bridge_network_passes(self):
        code, lines = judge(["owner-shared"], 0, inspect(net("owner-shared")))
        self.assertEqual(code, EXIT_INTERNAL, lines)

    def test_every_named_network_must_be_internal(self):
        code, lines = judge(["a", "b"], 0, inspect(net("a"), net("b", internal=False)))
        self.assertEqual(code, EXIT_NOT_INTERNAL, lines)
        self.assertTrue(any("'b'" in line and "NOT internal" in line for line in lines), lines)

    def test_a_non_internal_network_is_refused(self):
        code, _ = judge(["x"], 0, inspect(net("x", internal=False)))
        self.assertEqual(code, EXIT_NOT_INTERNAL)

    def test_only_the_local_bridge_driver_is_supported(self):
        for driver, scope in (("overlay", "swarm"), ("macvlan", "local"), ("host", "local")):
            code, _ = judge(["x"], 0, inspect(net("x", driver=driver, scope=scope)))
            self.assertEqual(code, EXIT_NOT_INTERNAL, driver)


class TestUnreadableIsUnverified(unittest.TestCase):
    def test_a_failed_inspect(self):
        self.assertEqual(judge(["x"], 1, "")[0], EXIT_UNVERIFIED)
        # Even a failed command that printed something plausible.
        self.assertEqual(judge(["x"], 1, inspect(net("x")))[0], EXIT_UNVERIFIED)

    def test_output_that_is_not_what_inspect_prints(self):
        for raw in ("", "[]", "{}", "null", "not json", json.dumps([["x"]]),
                    json.dumps([{"Internal": True}])):
            self.assertEqual(judge(["x"], 0, raw)[0], EXIT_UNVERIFIED, raw)

    def test_a_network_missing_from_the_output(self):
        self.assertEqual(judge(["x", "y"], 0, inspect(net("x")))[0], EXIT_UNVERIFIED)

    def test_a_network_that_appears_twice(self):
        self.assertEqual(judge(["x"], 0, inspect(net("x"), net("x")))[0], EXIT_UNVERIFIED)

    def test_fields_of_the_wrong_type(self):
        for entry in (net("x", internal="true"), net("x", internal=None),
                      net("x", internal=1), dict(net("x"), Driver=None)):
            self.assertEqual(judge(["x"], 0, inspect(entry))[0], EXIT_UNVERIFIED, entry)

    def test_names_docker_would_not_create(self):
        for name in ("", "-x", "x y", "x;rm -rf /", "$(id)", "a" * 129):
            self.assertEqual(judge([name], 0, inspect(net(name)))[0], EXIT_UNVERIFIED, name)

    def test_no_names_at_all(self):
        self.assertEqual(judge([], 0, "[]")[0], EXIT_UNVERIFIED)


if __name__ == "__main__":
    unittest.main(verbosity=2)
