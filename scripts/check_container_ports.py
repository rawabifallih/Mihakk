"""Strict reader for a container's host port bindings.

Takes the raw output of

    docker inspect -f '{{json .NetworkSettings.Ports}}'   (live bindings)
    docker inspect -f '{{json .HostConfig.PortBindings}}' (requested bindings)

and reports which host ports the container binds.

The point of this file is what it refuses to do. An earlier version turned
anything it could not read -- a failed docker inspect, malformed JSON, a bare
`null` -- into an empty mapping, which then read as "no bindings" and passed
the isolation check. A check that passes because its own input was unreadable
is worse than no check: it reports safety it never established.

So every unreadable input is an error here, never an empty result:

    exit 0  the bindings were read; the report says what they are
    exit 2  the bindings could NOT be read; the caller must treat the port
            state as unverified, not as clean

Both tables are objects mapping "port/proto" to either null (exposed but not
published) or a list of {HostIp, HostPort} objects. A stopped container
returns {} for both, so {} is legitimate and `null` is not.
"""

from __future__ import annotations

import json
import sys

EXIT_OK = 0
EXIT_UNVERIFIABLE = 2


class Unreadable(Exception):
    """The input cannot be interpreted as a port table."""


def parse_port_table(raw: str, source: str) -> dict:
    """Parse one port table, refusing anything unexpected."""
    if raw is None:
        raise Unreadable(f"{source}: no output captured")

    text = raw.strip()
    if text == "":
        raise Unreadable(f"{source}: docker produced no output (the command likely failed)")
    if text == "null":
        raise Unreadable(
            f"{source}: docker returned null rather than a port table, so the "
            "container's port state is unknown"
        )

    try:
        table = json.loads(text)
    except (ValueError, json.JSONDecodeError) as exc:
        raise Unreadable(f"{source}: output is not valid JSON ({exc})") from exc

    if table is None:
        raise Unreadable(f"{source}: parsed to null rather than a port table")
    if not isinstance(table, dict):
        raise Unreadable(
            f"{source}: expected an object mapping ports to bindings, got {type(table).__name__}"
        )

    for container_port, bindings in table.items():
        if not isinstance(container_port, str):
            raise Unreadable(f"{source}: port key {container_port!r} is not a string")
        if bindings is None:
            continue
        if not isinstance(bindings, list):
            raise Unreadable(
                f"{source}: bindings for {container_port} should be a list or null, "
                f"got {type(bindings).__name__}"
            )
        for binding in bindings:
            if not isinstance(binding, dict):
                raise Unreadable(
                    f"{source}: a binding for {container_port} is "
                    f"{type(binding).__name__}, not an object"
                )
            if "HostPort" not in binding:
                raise Unreadable(
                    f"{source}: a binding for {container_port} has no HostPort field"
                )
    return table


def describe(live: dict, requested: dict) -> dict:
    """Summarise which host ports are bound, from both tables."""
    bound = []
    for source, table in (("live", live), ("requested", requested)):
        for container_port, bindings in sorted(table.items()):
            for binding in bindings or []:
                host_ip = binding.get("HostIp") or ""
                host_port = binding.get("HostPort") or ""
                bound.append(f"{container_port} -> {host_ip}:{host_port} ({source})")

    exposed = sorted(live.keys()) or ["none"]
    return {"bound": bound, "exposed": exposed}


def main() -> int:
    if len(sys.argv) != 3:
        print(json.dumps({"error": "usage: check_container_ports.py <live-json> <requested-json>"}))
        return EXIT_UNVERIFIABLE

    try:
        live = parse_port_table(sys.argv[1], "NetworkSettings.Ports")
        requested = parse_port_table(sys.argv[2], "HostConfig.PortBindings")
    except Unreadable as exc:
        print(json.dumps({"error": str(exc)}))
        return EXIT_UNVERIFIABLE

    print(json.dumps(describe(live, requested)))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
