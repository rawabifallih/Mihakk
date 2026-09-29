"""Static isolation checks for the testbed service in a resolved compose config.

Reads `docker compose config --format json` on stdin and reports whether the
testbed is declared in an isolated way. Kept separate from the shell script so
it can be unit-tested against synthetic configurations without Docker.

Scope: these checks apply to ONE service, the testbed. Other services are
deliberately left alone. The dashboard and the orchestrator API will need a
published port and a non-internal network in later phases, and a check that
forbade those everywhere would either block that work or be switched off --
and a check that gets switched off protects nothing. The property worth
enforcing is narrower and permanent: *the testbed* is unreachable from the
host and has no route off the Docker network.

Every network the testbed attaches to must be internal, not merely one of
them. From phase 4 the engine joins the testbed's internal network, which is
fine; but if the testbed itself were also attached to a non-internal network,
it would have egress through that second interface and the isolation would be
gone. "At least one internal network" would pass that case, so the check
requires all of them.

External networks (phase 8a). The engine may join ONE network the operator
created and owns (deploy/compose.target.yml), declared `external: true`. The
config cannot say whether such a network is internal -- the operator chose that
when they created it -- so an external network counts as internal only when the
caller has read the real network with check_networks.py and names it here as
verified. Unverified, it is a problem, never a pass. And the testbed may not join
an external network at all, verified or not: its neighbours are the engine and
nothing the operator brings.
"""

from __future__ import annotations

import json
import sys

TESTBED_SERVICE = "testbed"

# Services that must never be reachable from the host and must never have a
# route off the Docker network.
#
# The engine's control API joined this list in phase 5. It can start a run, so
# anything that reaches its port can make the engine send traffic on someone
# else's behalf; a shared token guards it, but a port that is never published
# is the part that does not depend on the token being right.
ISOLATED_SERVICES = ("testbed", "engine")

# Exit codes. The caller must be able to tell "I checked, and it is wrong"
# from "I could not check", because the second must never be reported as a
# pass: a verdict reached without evidence is not a verdict.
EXIT_CLEAN = 0
EXIT_PROBLEMS = 1
EXIT_UNVERIFIABLE = 2


class Unreadable(Exception):
    """The compose config cannot be interpreted."""


def validate_shape(config) -> dict:
    """Refuse a config that cannot be interpreted, and return its services.

    Shared by check and check_all. When only check performed these guards, a
    config that was null, a list, or missing its services key reached
    check_all and produced "no problems found" -- the fail-open shape this
    file exists to prevent.
    """
    if not isinstance(config, dict):
        raise Unreadable(f"compose config is {type(config).__name__}, not an object")

    services = config.get("services")
    if services is None:
        raise Unreadable("compose config has no 'services' key; it may not be a resolved config")
    if not isinstance(services, dict):
        raise Unreadable(f"'services' is {type(services).__name__}, not an object")

    declared_networks = config.get("networks")
    if declared_networks is not None and not isinstance(declared_networks, dict):
        raise Unreadable(f"'networks' is {type(declared_networks).__name__}, not an object")

    return services


def _attached_network_names(service: dict) -> list[str]:
    """Network names a service attaches to, in the resolved config.

    Compose resolves `networks:` to a mapping, but a hand-written or
    partially-resolved config may still carry a list.
    """
    networks = service.get("networks")
    if isinstance(networks, dict):
        return sorted(networks.keys())
    if isinstance(networks, list):
        return sorted(str(n) for n in networks)
    return []


def check(config: dict, service_name: str = TESTBED_SERVICE,
          verified_internal: frozenset = frozenset()) -> tuple[list[str], list[str]]:
    """Return (problems, notes) for the named service.

    An empty problems list means the service is declared in an isolated way.
    verified_internal holds the real names of external networks that the caller
    inspected and found internal; no other external network is accepted.
    """
    problems: list[str] = []
    notes: list[str] = []

    services = validate_shape(config)

    service = services.get(service_name)
    if service is None:
        return [f"service {service_name!r} is not defined in the compose config"], notes
    if not isinstance(service, dict):
        raise Unreadable(f"service {service_name!r} is {type(service).__name__}, not an object")

    # 1. Nothing published to the host.
    ports = service.get("ports") or []
    if ports:
        problems.append(f"service {service_name} publishes ports to the host: {ports}")
    else:
        notes.append(f"service {service_name}: no published ports")

    # network_mode bypasses the networks list entirely, so `host` or `bridge`
    # would make the internal-network checks below meaningless.
    mode = service.get("network_mode")
    if mode:
        problems.append(
            f"service {service_name} sets network_mode={mode!r}, which bypasses "
            "the internal network"
        )

    # 2. Every attached network must be internal.
    declared = config.get("networks") or {}
    attached = _attached_network_names(service)

    if not attached:
        problems.append(
            f"service {service_name} declares no networks, so it joins the implicit "
            "default network, which is not internal"
        )
    for name in attached:
        network = declared.get(name)
        if network is None:
            problems.append(
                f"service {service_name} attaches to network {name!r}, which is not "
                "declared in this config, so its isolation cannot be verified"
            )
        elif not isinstance(network, dict):
            raise Unreadable(f"network {name!r} is {type(network).__name__}, not an object")
        elif network.get("external") is True:
            real = network.get("name") or name
            if service_name == TESTBED_SERVICE:
                problems.append(
                    f"service {service_name} attaches to the external network {real!r}; "
                    "the testbed may not share a network with anything the operator "
                    "brings, internal or not"
                )
            elif real in verified_internal:
                notes.append(f"network {name} ({real}): external, inspected: internal=true")
            else:
                problems.append(
                    f"service {service_name} attaches to the external network {real!r}, "
                    "whose isolation the config cannot show; it must be inspected and "
                    "found internal first"
                )
        elif network.get("internal") is True:
            notes.append(f"network {name}: internal=true")
        else:
            problems.append(
                f"service {service_name} attaches to network {name!r}, which is not "
                f"internal (internal={network.get('internal')!r}); the testbed would "
                "have a route off the Docker network through it"
            )

    other = sorted(set(services) - set(ISOLATED_SERVICES))
    if other:
        notes.append(
            "not checked (isolation is only required of " +
            ", ".join(ISOLATED_SERVICES) + "): " + ", ".join(other)
        )
    return problems, notes


def check_all(config: dict, service_names=ISOLATED_SERVICES,
              verified_internal: frozenset = frozenset()) -> tuple[list[str], list[str]]:
    """Check every service that must be isolated.

    A service absent from the config is skipped rather than reported: the
    compose file grows over the phases, and a check that failed on a service
    that does not exist yet would be noise.
    """
    problems: list[str] = []
    notes: list[str] = []
    services = validate_shape(config)

    checked = []
    for name in service_names:
        if name not in services:
            notes.append(f"service {name}: not present in this config, skipped")
            continue
        checked.append(name)
        service_problems, service_notes = check(config, name, verified_internal)
        problems.extend(service_problems)
        notes.extend(service_notes)

    if not checked:
        problems.append(
            "none of the services that must be isolated "
            f"({', '.join(service_names)}) are present in this config"
        )
    return problems, notes


def main() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        print(json.dumps({"error": "no compose config on stdin (the command likely failed)"}))
        return EXIT_UNVERIFIABLE

    try:
        config = json.loads(raw)
    except (ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": f"compose config is not valid JSON: {exc}"}))
        return EXIT_UNVERIFIABLE

    # --verified-internal NAME, repeatable: external networks the caller has
    # inspected (check_networks.py) and found internal. Everything else on the
    # command line is the optional single service to check.
    args = sys.argv[1:]
    verified: set = set()
    positional: list = []
    while args:
        arg = args.pop(0)
        if arg == "--verified-internal":
            if not args:
                print(json.dumps({"error": "--verified-internal needs a network name"}))
                return EXIT_UNVERIFIABLE
            verified.add(args.pop(0))
        else:
            positional.append(arg)

    try:
        if positional:
            problems, notes = check(config, positional[0], frozenset(verified))
        else:
            problems, notes = check_all(config, verified_internal=frozenset(verified))
    except Unreadable as exc:
        print(json.dumps({"error": str(exc)}))
        return EXIT_UNVERIFIABLE

    print(json.dumps({"problems": problems, "notes": notes}))
    return EXIT_PROBLEMS if problems else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
