"""Runtime proof that the testbed network is isolated.

Run inside a container attached to the testbed's Docker network:

    docker compose run --rm testbed python3 /app/isolation_probe.py

Checks, in order:

  1. no default route  -- a network declared `internal: true` gets no gateway,
     so nothing can be routed off the Docker network. This is read straight
     from the kernel routing table and sends no packets at all.

  2. external connect fails -- a TCP connect that must not succeed. The target
     is 192.0.2.1, from TEST-NET-1 (RFC 5737), a block reserved for
     documentation that is never routed on the public internet. No real
     service is contacted, here or anywhere else in this project.

  3. the testbed is reachable by service name -- the positive control. An
     isolated network that also does not work would pass the first two checks
     for the wrong reason.

Prints one JSON object and exits non-zero if any check fails.
"""

from __future__ import annotations

import errno
import json
import socket
import sys
import urllib.error
import urllib.request

# RFC 5737 TEST-NET-1: reserved for documentation, never globally routed.
EXTERNAL_PROBE_HOST = "192.0.2.1"
EXTERNAL_PROBE_PORT = 80
EXTERNAL_PROBE_TIMEOUT = 3.0

TESTBED_URL = "http://testbed:8000/api/health"


def check_no_default_route() -> tuple[str, str]:
    """A default route would mean traffic can leave the Docker network."""
    try:
        with open("/proc/net/route", "r", encoding="ascii") as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        # Not a failure: nothing was established either way.
        return "unverified", f"could not read /proc/net/route: {exc}"

    defaults = []
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 3:
            continue
        iface, destination = fields[0], fields[1]
        # Destination 00000000 is 0.0.0.0, i.e. the default route.
        if destination == "00000000":
            defaults.append(f"{iface} via gateway {fields[2]}")

    if not lines:
        return "unverified", "/proc/net/route was empty; routing state unknown"
    if defaults:
        return "fail", "default route present: " + "; ".join(defaults)
    return "pass", "no default route: traffic cannot leave the Docker network"


def check_external_connect_fails() -> tuple[str, str]:
    """Connecting outwards must fail *because there is no route*.

    The distinction matters. Any failure is not good enough: 192.0.2.1 is
    unroutable on the public internet, so a container with full egress also
    fails to reach it -- by timing out after the packet has left the host.
    Accepting "it failed" would let a non-isolated network pass this check,
    which is exactly what happened before this was tightened.

    Isolation shows up as ENETUNREACH (or EHOSTUNREACH) raised immediately by
    the local kernel, with no packet sent. A timeout means the opposite: the
    traffic was routed out and simply got no answer.
    """
    target = f"{EXTERNAL_PROBE_HOST}:{EXTERNAL_PROBE_PORT}"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(EXTERNAL_PROBE_TIMEOUT)
    try:
        sock.connect((EXTERNAL_PROBE_HOST, EXTERNAL_PROBE_PORT))
    except socket.timeout:
        return "fail", (
            f"connect to {target} timed out rather than being refused by the "
            "local kernel; the packet was routed off the host, so there is egress"
        )
    except OSError as exc:
        if exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
            return "pass", (
                f"connect to {target} refused locally with "
                f"{errno.errorcode.get(exc.errno, exc.errno)}: no route exists, no packet sent"
            )
        # An unexpected errno proves nothing either way: it is neither the
        # local refusal that shows isolation, nor evidence of a route out.
        return "unverified", (
            f"connect to {target} failed with an unexpected error "
            f"({exc.__class__.__name__}: {exc}); expected ENETUNREACH"
        )
    else:
        return "fail", f"connect to {target} SUCCEEDED; the network is not isolated"
    finally:
        sock.close()


def check_testbed_reachable() -> tuple[str, str]:
    """Positive control: the testbed answers on the internal network."""
    try:
        with urllib.request.urlopen(TESTBED_URL, timeout=5) as resp:
            if resp.status != 200:
                return "fail", f"{TESTBED_URL} returned {resp.status}"
            payload = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return "fail", f"{TESTBED_URL} unreachable: {exc}"

    if not isinstance(payload, dict) or payload.get("status") != "ok":
        return "fail", f"unexpected health payload: {payload}"
    return "pass", f"{TESTBED_URL} reachable by service name"


CHECKS = [
    ("no_default_route", check_no_default_route),
    ("external_connect_refused", check_external_connect_fails),
    ("testbed_reachable_by_service_name", check_testbed_reachable),
]


def main() -> int:
    results = {}
    ok = True
    for name, fn in CHECKS:
        try:
            status, detail = fn()
        except Exception as exc:  # noqa: BLE001
            status, detail = "unverified", f"check raised {type(exc).__name__}: {exc}"
        results[name] = {"status": status, "passed": status == "pass", "detail": detail}
        ok = ok and status == "pass"

    print(json.dumps({"all_passed": ok, "checks": results}, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
