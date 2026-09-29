"""Decide, from `docker network inspect`, whether networks are internal.

`external: true` in a compose file says who owns a network. It says nothing about
whether the network is isolated: the operator created it, with whatever options
they chose. So before the engine joins an operator's network, and after it has
joined, the network Docker actually has is read -- not the compose file's idea of
it -- and anything short of a clear "internal" is refused.

The caller runs, for example

    docker network inspect NAME [NAME...]; rc=$?

and passes the exit status, the raw output and the names it asked about. Docker
is not run from here, which makes this a pure function of its input and testable
without Docker -- the same shape as claim_name.py and check_container_ports.py.

    exit 0  every named network exists exactly once, is a local bridge network,
            and Docker reports Internal=true
    exit 1  at least one of them is readable and NOT internal (or not a local
            bridge); stdout says which
    exit 2  the answer could not be read: the inspect failed, the output is not
            what inspect prints, a name is missing or ambiguous. UNVERIFIED --
            the caller must refuse, never proceed

Only the bridge driver is accepted. Internal means something specific for it
(no gateway off the host, Docker's isolation rules on the bridge); for overlay,
macvlan or a plugin driver the same flag has different guarantees, and none of
them has been tested here.
"""

from __future__ import annotations

import json
import re
import sys

EXIT_INTERNAL = 0
EXIT_NOT_INTERNAL = 1
EXIT_UNVERIFIED = 2

# Docker's own rule for network names, anchored. Anything else was not produced
# by `docker network create`, so the question being asked is already wrong.
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class Unverified(Exception):
    """The inspect output does not answer the question that was asked."""


def judge(names: list[str], inspect_rc: int, inspect_output: str) -> tuple[int, list[str]]:
    """Return (exit code, one line per network or one line explaining why not)."""
    if not names:
        return EXIT_UNVERIFIED, ["no network names were given, so nothing was checked"]
    for name in names:
        if not NAME_RE.match(name):
            return EXIT_UNVERIFIED, [f"{name!r} is not a valid Docker network name"]

    if inspect_rc != 0:
        return EXIT_UNVERIFIED, [
            f"docker network inspect exited {inspect_rc}; whether the network(s) "
            "exist or are internal is unknown"]

    try:
        data = json.loads(inspect_output)
    except (ValueError, json.JSONDecodeError) as exc:
        return EXIT_UNVERIFIED, [f"the inspect output is not JSON ({exc})"]
    if not isinstance(data, list):
        return EXIT_UNVERIFIED, [f"the inspect output is {type(data).__name__}, not a list"]

    by_name: dict[str, list[dict]] = {}
    for entry in data:
        if not isinstance(entry, dict) or not isinstance(entry.get("Name"), str):
            return EXIT_UNVERIFIED, ["the inspect output has an entry without a Name"]
        by_name.setdefault(entry["Name"], []).append(entry)

    lines: list[str] = []
    worst = EXIT_INTERNAL
    for name in names:
        found = by_name.get(name, [])
        if len(found) != 1:
            return EXIT_UNVERIFIED, [
                f"network {name!r} appears {len(found)} time(s) in the inspect output; "
                "exactly one was expected"]
        entry = found[0]
        internal = entry.get("Internal")
        driver = entry.get("Driver")
        scope = entry.get("Scope")
        if not isinstance(internal, bool) or not isinstance(driver, str) \
                or not isinstance(scope, str):
            return EXIT_UNVERIFIED, [
                f"network {name!r}: Internal/Driver/Scope are missing or not the "
                "types inspect prints"]
        if driver != "bridge" or scope != "local":
            worst = EXIT_NOT_INTERNAL
            lines.append(f"network {name!r} uses driver {driver!r} (scope {scope!r}); "
                         "only a local bridge network is supported")
        elif not internal:
            worst = EXIT_NOT_INTERNAL
            lines.append(f"network {name!r} is NOT internal: containers on it have a "
                         "route off the Docker host")
        else:
            lines.append(f"network {name!r} is an internal local bridge network")
    return worst, lines


def main() -> int:
    if len(sys.argv) < 4:
        print("usage: check_networks.py <inspect-exit-code> <inspect-output> NAME [NAME...]",
              file=sys.stderr)
        return EXIT_UNVERIFIED
    try:
        rc = int(sys.argv[1])
    except ValueError:
        print(f"the inspect exit code {sys.argv[1]!r} is not an integer")
        return EXIT_UNVERIFIED
    code, lines = judge(sys.argv[3:], rc, sys.argv[2])
    for line in lines:
        print(line)
    return code


if __name__ == "__main__":
    sys.exit(main())
