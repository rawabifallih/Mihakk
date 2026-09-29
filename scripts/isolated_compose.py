"""Derive a throwaway compose project from the real one.

A test that brings services up must not do it inside the project a person's own
stack lives in. `docker compose -p <name>` is not enough on its own: the real
compose file pins `container_name:` on every service and `name:` on every
network and volume, and a pinned name is global. Two projects would fight over
the same containers, and a `down -v` in either would take the other's volumes
with it -- including the engine's stored sessions and the orchestrator's SQLite.

So this strips exactly the keys that pin a resource to a global name, leaving
everything that is under test untouched:

    top-level  name            -> removed, so -p decides the project
    services   container_name  -> removed, so containers are <project>-<service>
    networks   name            -> removed, so networks are <project>_<network>
    volumes    name            -> removed, so volumes are <project>_<volume>

Nothing else is rewritten, apart from an optional published-port override for
one service, because a fixed host port collides with whatever already holds it.

The input is `docker compose config --format json`, which is the real file after
interpolation -- so the derived project still tests the committed definitions,
not a hand-written copy of them that could drift away from it.

    exit 0  the derived project was written
    exit 2  the input could not be read; the caller must not fall back to the
            shared project
"""

from __future__ import annotations

import json
import sys

EXIT_OK = 0
EXIT_UNREADABLE = 2


class Unreadable(Exception):
    """The resolved compose config cannot be interpreted."""


def strip_pinned_names(config: dict, port_override: tuple[str, str, str] | None = None) -> dict:
    """Return the config with every globally pinned name removed."""
    if not isinstance(config, dict):
        raise Unreadable(f"expected an object at the top level, got {type(config).__name__}")

    services = config.get("services")
    if not isinstance(services, dict) or not services:
        raise Unreadable("the resolved config declares no services")

    out = dict(config)
    out.pop("name", None)

    new_services = {}
    for name, service in services.items():
        if not isinstance(service, dict):
            raise Unreadable(f"service {name!r} is {type(service).__name__}, not an object")
        copy = dict(service)
        copy.pop("container_name", None)
        new_services[name] = copy
    out["services"] = new_services

    for section in ("networks", "volumes"):
        block = config.get(section)
        if block is None:
            continue
        if not isinstance(block, dict):
            raise Unreadable(f"{section} is {type(block).__name__}, not an object")
        rebuilt = {}
        for name, body in block.items():
            if body is None:
                rebuilt[name] = None
                continue
            if not isinstance(body, dict):
                raise Unreadable(f"{section}.{name} is {type(body).__name__}, not an object")
            entry = dict(body)
            entry.pop("name", None)
            rebuilt[name] = entry
        out[section] = rebuilt

    if port_override is not None:
        service_name, host_ip, host_port = port_override
        target = out["services"].get(service_name)
        if target is None:
            raise Unreadable(f"cannot override the port of absent service {service_name!r}")
        published = target.get("ports")
        if not isinstance(published, list) or not published:
            raise Unreadable(f"service {service_name!r} publishes no port to override")
        first = published[0]
        if not isinstance(first, dict) or "target" not in first:
            raise Unreadable(f"service {service_name!r} has an unreadable ports entry")
        target["ports"] = [{
            "mode": first.get("mode", "ingress"),
            "target": first["target"],
            "published": str(host_port),
            "protocol": first.get("protocol", "tcp"),
            "host_ip": host_ip,
        }]

        # Moving the port has to move the host allowlist with it. The orchestrator
        # answers only to the names it is told, which is what blunts DNS rebinding;
        # leaving the allowlist on the real port meant a derived project refused
        # every request to itself with "does not answer to that host name".
        environment = target.get("environment")
        if isinstance(environment, dict):
            environment["MIHAKK_ALLOWED_HOSTS"] = (
                f"{host_ip}:{host_port},localhost:{host_port}")
        elif isinstance(environment, list):
            kept = [entry for entry in environment
                    if not str(entry).startswith("MIHAKK_ALLOWED_HOSTS=")]
            kept.append(f"MIHAKK_ALLOWED_HOSTS={host_ip}:{host_port},"
                        f"localhost:{host_port}")
            target["environment"] = kept

    return out


def main() -> int:
    if len(sys.argv) not in (2, 5):
        print("usage: isolated_compose.py <resolved-json> "
              "[<service> <host-ip> <host-port>]", file=sys.stderr)
        return EXIT_UNREADABLE

    raw = sys.argv[1]
    try:
        with open(raw, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        print(f"could not read {raw}: {exc}", file=sys.stderr)
        return EXIT_UNREADABLE

    if not text.strip():
        print(f"{raw} is empty; docker compose config likely failed", file=sys.stderr)
        return EXIT_UNREADABLE

    try:
        config = json.loads(text)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"{raw} is not valid JSON ({exc})", file=sys.stderr)
        return EXIT_UNREADABLE

    override = None
    if len(sys.argv) == 5:
        override = (sys.argv[2], sys.argv[3], sys.argv[4])

    try:
        derived = strip_pinned_names(config, override)
    except Unreadable as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_UNREADABLE

    # JSON is valid YAML, and compose's parser accepts it, so no YAML library
    # is needed on the host.
    json.dump(derived, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
