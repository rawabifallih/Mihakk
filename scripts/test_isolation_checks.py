"""Tests for the static testbed-isolation checks.

Two things have to hold, and they pull in opposite directions:

  - the check must REJECT anything that would give the testbed a way out, or a
    way in from the host;
  - the check must ACCEPT the services that legitimately need a published port
    or a non-internal network, because a check that blocks ordinary work gets
    switched off, and a switched-off check protects nothing.

These run against synthetic configurations, so they are fast and need no
Docker. The end-to-end behaviour is exercised by verify-testbed-isolation.sh.
"""

from __future__ import annotations

import unittest

from check_testbed_isolation import check


def config(testbed: dict | None = None, networks: dict | None = None, extra_services: dict | None = None) -> dict:
    """Build a resolved-compose-shaped config with a testbed service."""
    services = {}
    if testbed is not None:
        services["testbed"] = testbed
    services.update(extra_services or {})
    return {"services": services, "networks": networks or {}}


ISOLATED_TESTBED = {"image": "mihakk-testbed:dev", "networks": {"mihakk-internal": None}}
INTERNAL_NETWORKS = {"mihakk-internal": {"name": "mihakk-internal", "internal": True}}


class TestAcceptsIsolatedTestbed(unittest.TestCase):
    def test_current_shape_is_accepted(self):
        problems, notes = check(config(ISOLATED_TESTBED, INTERNAL_NETWORKS))
        self.assertEqual(problems, [], f"the isolated configuration was rejected: {problems}")
        self.assertTrue(any("internal=true" in n for n in notes))

    def test_multiple_internal_networks_are_accepted(self):
        cfg = config(
            {"networks": {"mihakk-internal": None, "mihakk-testbed-2": None}},
            {
                "mihakk-internal": {"internal": True},
                "mihakk-testbed-2": {"internal": True},
            },
        )
        problems, _ = check(cfg)
        self.assertEqual(problems, [], f"two internal networks should be fine: {problems}")

    def test_networks_as_a_list_are_understood(self):
        cfg = config({"networks": ["mihakk-internal"]}, INTERNAL_NETWORKS)
        problems, _ = check(cfg)
        self.assertEqual(problems, [], f"list-form networks should be handled: {problems}")


class TestRejectsPublishedPorts(unittest.TestCase):
    def test_published_port_is_rejected(self):
        cfg = config(
            dict(ISOLATED_TESTBED, ports=[{"mode": "ingress", "target": 8000,
                                           "published": "8000", "protocol": "tcp"}]),
            INTERNAL_NETWORKS,
        )
        problems, _ = check(cfg)
        self.assertTrue(problems, "a published port on the testbed must be rejected")
        self.assertTrue(
            any("publishes ports" in p for p in problems),
            f"the reason should name the published port: {problems}",
        )

    def test_short_form_published_port_is_rejected(self):
        cfg = config(dict(ISOLATED_TESTBED, ports=["8000:8000"]), INTERNAL_NETWORKS)
        problems, _ = check(cfg)
        self.assertTrue(any("publishes ports" in p for p in problems), problems)

    def test_expose_without_publishing_is_accepted(self):
        """`expose` documents a port; it does not reach the host."""
        cfg = config(dict(ISOLATED_TESTBED, expose=["8000"]), INTERNAL_NETWORKS)
        problems, _ = check(cfg)
        self.assertEqual(problems, [], f"expose should not be treated as publishing: {problems}")


class TestRejectsNonInternalNetworks(unittest.TestCase):
    def test_single_non_internal_network_is_rejected(self):
        cfg = config(
            {"networks": {"mihakk-app": None}},
            {"mihakk-app": {"internal": False}},
        )
        problems, _ = check(cfg)
        self.assertTrue(any("not internal" in p for p in problems), problems)

    def test_network_without_an_internal_key_is_rejected(self):
        """Omitting `internal` means false; it must not be read as internal."""
        cfg = config({"networks": {"mihakk-app": None}}, {"mihakk-app": {}})
        problems, _ = check(cfg)
        self.assertTrue(any("not internal" in p for p in problems), problems)

    def test_mixed_internal_and_non_internal_is_rejected(self):
        """The case that matters most.

        From phase 4 the engine joins the testbed's internal network. If the
        testbed were also attached to a non-internal network, it would have a
        route out through that second interface. A check that only asked
        whether *some* attached network is internal would pass this.
        """
        cfg = config(
            {"networks": {"mihakk-internal": None, "mihakk-app": None}},
            {
                "mihakk-internal": {"internal": True},
                "mihakk-app": {"internal": False},
            },
        )
        problems, _ = check(cfg)
        self.assertTrue(
            problems,
            "a testbed on both an internal and a non-internal network must be rejected",
        )
        self.assertTrue(
            any("mihakk-app" in p and "not internal" in p for p in problems),
            f"the reason should name the non-internal network: {problems}",
        )

    def test_no_networks_at_all_is_rejected(self):
        cfg = config({"image": "x"}, INTERNAL_NETWORKS)
        problems, _ = check(cfg)
        self.assertTrue(any("default network" in p for p in problems), problems)

    def test_undeclared_network_is_rejected(self):
        cfg = config({"networks": {"somewhere-else": None}}, INTERNAL_NETWORKS)
        problems, _ = check(cfg)
        self.assertTrue(any("not declared" in p for p in problems), problems)

    def test_network_mode_host_is_rejected(self):
        cfg = config(dict(ISOLATED_TESTBED, network_mode="host"), INTERNAL_NETWORKS)
        problems, _ = check(cfg)
        self.assertTrue(any("network_mode" in p for p in problems), problems)


class TestOtherServicesAreNotConstrained(unittest.TestCase):
    """The checks are about the testbed, and only the testbed."""

    def test_dashboard_may_publish_a_port(self):
        cfg = config(
            ISOLATED_TESTBED,
            dict(INTERNAL_NETWORKS, **{"mihakk-app": {"internal": False}}),
            extra_services={
                "dashboard": {
                    "ports": ["8080:8080"],
                    "networks": {"mihakk-app": None},
                },
            },
        )
        problems, _ = check(cfg)
        self.assertEqual(
            problems, [],
            f"a published port on another service must not be rejected: {problems}",
        )

    def test_api_may_use_a_non_internal_network(self):
        cfg = config(
            ISOLATED_TESTBED,
            dict(INTERNAL_NETWORKS, **{"mihakk-app": {"internal": False}}),
            extra_services={"api": {"networks": {"mihakk-app": None}}},
        )
        problems, _ = check(cfg)
        self.assertEqual(problems, [], f"another service on a public network is fine: {problems}")

    def test_engine_may_bridge_internal_and_non_internal(self):
        """The shape phase 4 will actually have.

        The engine sits on the testbed's internal network to reach it, and on
        a non-internal network to talk to the orchestrator. That is fine: the
        testbed still has no route out, because Docker does not forward
        between networks on the engine's behalf.
        """
        cfg = config(
            ISOLATED_TESTBED,
            dict(INTERNAL_NETWORKS, **{"mihakk-app": {"internal": False}}),
            extra_services={
                "engine": {"networks": {"mihakk-internal": None, "mihakk-app": None}},
                "orchestrator": {"ports": ["8000:8000"], "networks": {"mihakk-app": None}},
                "dashboard": {"ports": ["8080:80"], "networks": {"mihakk-app": None}},
            },
        )
        problems, notes = check(cfg)
        self.assertEqual(problems, [], f"the phase 4 layout must be accepted: {problems}")
        self.assertTrue(
            any("not checked" in n for n in notes),
            "the report should say which services were left unchecked",
        )

    def test_a_broken_other_service_does_not_mask_a_broken_testbed(self):
        cfg = config(
            dict(ISOLATED_TESTBED, ports=["8000:8000"]),
            dict(INTERNAL_NETWORKS, **{"mihakk-app": {"internal": False}}),
            extra_services={"dashboard": {"ports": ["8080:80"], "networks": {"mihakk-app": None}}},
        )
        problems, _ = check(cfg)
        self.assertTrue(any("testbed" in p for p in problems), problems)
        self.assertFalse(any("dashboard" in p for p in problems), problems)


class TestMissingService(unittest.TestCase):
    def test_absent_testbed_is_reported(self):
        problems, _ = check(config(None, INTERNAL_NETWORKS))
        self.assertTrue(problems)
        self.assertIn("not defined", problems[0])


class TestRealComposeFile(unittest.TestCase):
    """The committed compose file must pass its own check."""

    def test_repository_compose_file_is_isolated(self):
        import json
        import os
        import pathlib
        import subprocess

        compose = pathlib.Path(__file__).resolve().parent.parent / "deploy" / "docker-compose.yml"
        if not compose.exists():
            self.skipTest("compose file not present")

        # The engine service declares ${MIHAKK_CONTROL_TOKEN:?...}, and compose
        # interpolates the whole file before doing anything with it. Unset, the
        # resolve failed and this test skipped itself -- so the guard on the
        # committed compose file was off by default. Nothing is started here, so
        # the placeholder authenticates nothing.
        env = dict(os.environ)
        env.setdefault("MIHAKK_CONTROL_TOKEN", "isolation-check-placeholder")
        # The dashboard token is required for interpolation too, for the same
        # reason and with the same consequence if it is missing: the resolve fails
        # and this test would skip itself.
        env.setdefault("MIHAKK_DASHBOARD_TOKEN", "isolation-check-placeholder")

        try:
            out = subprocess.run(
                ["docker", "compose", "-f", str(compose), "config", "--format", "json"],
                capture_output=True, text=True, timeout=60, env=env,
            )
        except (OSError, subprocess.SubprocessError):
            self.skipTest("docker is not available in this environment")
        if out.returncode != 0:
            self.skipTest(f"docker compose config failed: {out.stderr[:200]}")

        problems, _ = check(json.loads(out.stdout))
        self.assertEqual(problems, [], f"the committed compose file is not isolated: {problems}")


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestEngineControlAPIIsAlsoIsolated(unittest.TestCase):
    """The control API can start a run, so it gets the testbed's treatment.

    A shared token guards it, but a port that is never published is the part
    that does not depend on the token being right.
    """

    def test_a_published_engine_port_is_rejected(self):
        from check_testbed_isolation import check_all

        cfg = {
            "services": {
                "testbed": ISOLATED_TESTBED,
                "engine": {"ports": ["8900:8900"], "networks": {"mihakk-internal": None}},
            },
            "networks": INTERNAL_NETWORKS,
        }
        problems, _ = check_all(cfg)
        self.assertTrue(any("engine" in p and "publishes ports" in p for p in problems),
                        f"a published control API port was accepted: {problems}")

    def test_an_engine_on_a_non_internal_network_is_rejected(self):
        from check_testbed_isolation import check_all

        cfg = {
            "services": {
                "testbed": ISOLATED_TESTBED,
                "engine": {"networks": {"mihakk-public": None}},
            },
            "networks": dict(INTERNAL_NETWORKS, **{"mihakk-public": {"internal": False}}),
        }
        problems, _ = check_all(cfg)
        self.assertTrue(any("engine" in p and "not internal" in p for p in problems), problems)

    def test_both_isolated_together_are_accepted(self):
        from check_testbed_isolation import check_all

        cfg = {
            "services": {
                "testbed": ISOLATED_TESTBED,
                "engine": {"networks": {"mihakk-internal": None}},
                # Other services stay unconstrained.
                "orchestrator": {"ports": ["8100:8100"],
                                 "networks": {"mihakk-internal": None, "mihakk-public": None}},
            },
            "networks": dict(INTERNAL_NETWORKS, **{"mihakk-public": {"internal": False}}),
        }
        problems, _ = check_all(cfg)
        self.assertEqual(problems, [], f"the phase 5 layout was rejected: {problems}")

    def test_a_missing_service_is_skipped_not_failed(self):
        from check_testbed_isolation import check_all

        cfg = {"services": {"testbed": ISOLATED_TESTBED}, "networks": INTERNAL_NETWORKS}
        problems, notes = check_all(cfg)
        self.assertEqual(problems, [], problems)
        self.assertTrue(any("engine" in n and "skipped" in n for n in notes), notes)

    def test_a_config_with_none_of_them_is_reported(self):
        from check_testbed_isolation import check_all

        cfg = {"services": {"dashboard": {"ports": ["80:80"]}}, "networks": {}}
        problems, _ = check_all(cfg)
        self.assertTrue(problems, "a config with nothing isolated was accepted")


class TestExternalTargetNetwork(unittest.TestCase):
    """Phase 8a: the engine may join ONE operator-owned network.

    external: true says who owns a network, not that it is isolated, so the
    config alone can never make it acceptable: only a caller that inspected the
    real network may vouch for it, by name. And the testbed never joins one.
    """

    TARGET = {"name": "owner-shared", "external": True}

    def _cfg(self, engine_networks, testbed=None):
        return {
            "services": {
                "testbed": testbed or ISOLATED_TESTBED,
                "engine": {"networks": engine_networks},
            },
            "networks": dict(INTERNAL_NETWORKS, **{"mihakk-target": self.TARGET}),
        }

    def test_an_unverified_external_network_is_a_problem(self):
        from check_testbed_isolation import check_all

        problems, _ = check_all(self._cfg({"mihakk-internal": None, "mihakk-target": None}))
        self.assertTrue(any("owner-shared" in p and "inspected" in p for p in problems),
                        problems)

    def test_a_verified_external_network_is_accepted_for_the_engine(self):
        from check_testbed_isolation import check_all

        problems, notes = check_all(
            self._cfg({"mihakk-internal": None, "mihakk-target": None}),
            verified_internal=frozenset({"owner-shared"}))
        self.assertEqual(problems, [], problems)
        self.assertTrue(any("owner-shared" in n and "inspected" in n for n in notes), notes)

    def test_verification_is_by_the_real_name_not_the_compose_key(self):
        """Vouching for the key would vouch for whatever network it names."""
        from check_testbed_isolation import check_all

        problems, _ = check_all(
            self._cfg({"mihakk-internal": None, "mihakk-target": None}),
            verified_internal=frozenset({"mihakk-target"}))
        self.assertTrue(problems, "the compose key was accepted in place of the network name")

    def test_the_testbed_may_not_join_an_external_network_even_verified(self):
        from check_testbed_isolation import check_all

        testbed = {"image": "mihakk-testbed:dev",
                   "networks": {"mihakk-internal": None, "mihakk-target": None}}
        problems, _ = check_all(
            self._cfg({"mihakk-internal": None}, testbed=testbed),
            verified_internal=frozenset({"owner-shared"}))
        self.assertTrue(any("testbed" in p and "external" in p for p in problems), problems)

    def test_the_command_line_takes_verified_names(self):
        import json
        import pathlib
        import subprocess
        import sys

        script = pathlib.Path(__file__).resolve().parent / "check_testbed_isolation.py"
        cfg = json.dumps(self._cfg({"mihakk-internal": None, "mihakk-target": None}))
        unverified = subprocess.run([sys.executable, str(script)], input=cfg,
                                    capture_output=True, text=True)
        verified = subprocess.run(
            [sys.executable, str(script), "--verified-internal", "owner-shared"],
            input=cfg, capture_output=True, text=True)
        dangling = subprocess.run([sys.executable, str(script), "--verified-internal"],
                                  input=cfg, capture_output=True, text=True)
        self.assertEqual(unverified.returncode, 1, unverified.stdout)
        self.assertEqual(verified.returncode, 0, verified.stdout)
        self.assertEqual(dangling.returncode, 2, dangling.stdout)
