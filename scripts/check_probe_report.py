"""Strict reader for the in-container isolation probe's report.

Takes the probe's stdout on stdin and its exit code as argv[1], and emits one
line per check for the shell to render.

Two things this refuses that the previous inline reader accepted:

  - A report containing *some* checks. Any non-empty `checks` mapping was
    enough, so a report carrying only one passing check read as a clean run
    while the default-route and egress checks had silently not happened. The
    three checks are now required by name: a missing one is unverified, not
    an absent problem.

  - A report that disagrees with the exit code. The probe exits 0 only when
    every check passed, so an all-pass report arriving with a non-zero exit
    means one of the two is lying and neither can be trusted. Reading the
    report and ignoring the code would take the optimistic half of a
    contradiction.

Output on success: one `status|name: detail` line per check, then `end|`.
Output on refusal: a single `invalid|reason` line.

    exit 0  the report was read and is self-consistent
    exit 2  the report cannot be trusted; the caller must record unverified
"""

from __future__ import annotations

import json
import sys

# Every check the probe is expected to perform. Naming them here rather than
# accepting whatever turns up is the whole point: a check that did not run
# must be visible as a gap, not read as silence.
REQUIRED_CHECKS = (
    "no_default_route",
    "external_connect_refused",
    "testbed_reachable_by_service_name",
)

VALID_STATUSES = ("pass", "fail", "unverified")

EXIT_OK = 0
EXIT_UNTRUSTWORTHY = 2


def refuse(reason: str) -> int:
    print("invalid|" + reason)
    return EXIT_UNTRUSTWORTHY


def read(raw: str, exit_code: int) -> tuple[int, list[str]]:
    """Return (exit status, lines to print)."""
    if not raw.strip():
        return EXIT_UNTRUSTWORTHY, ["invalid|the probe produced no output"]

    try:
        data = json.loads(raw)
    except (ValueError, json.JSONDecodeError) as exc:
        return EXIT_UNTRUSTWORTHY, [f"invalid|the probe's output is not valid JSON ({exc})"]

    if not isinstance(data, dict):
        return EXIT_UNTRUSTWORTHY, [
            f"invalid|the probe's report is {type(data).__name__}, not an object"
        ]

    checks = data.get("checks")
    if not isinstance(checks, dict) or not checks:
        return EXIT_UNTRUSTWORTHY, ["invalid|the probe's report contains no checks"]

    missing = [name for name in REQUIRED_CHECKS if name not in checks]
    if missing:
        return EXIT_UNTRUSTWORTHY, [
            "invalid|the probe did not report these required checks: " + ", ".join(missing)
        ]

    for name in sorted(checks):
        result = checks[name]
        if not isinstance(result, dict):
            return EXIT_UNTRUSTWORTHY, [
                f"invalid|check {name} is {type(result).__name__}, not an object"
            ]
        if result.get("status") not in VALID_STATUSES:
            return EXIT_UNTRUSTWORTHY, [
                f"invalid|check {name} has status {result.get('status')!r}, "
                f"expected one of {'/'.join(VALID_STATUSES)}"
            ]

    all_passed = all(checks[name]["status"] == "pass" for name in checks)
    expected_code = 0 if all_passed else 1
    if exit_code != expected_code:
        summary = "every check passed" if all_passed else "at least one check did not pass"
        return EXIT_UNTRUSTWORTHY, [
            f"invalid|the probe exited {exit_code} but its report says {summary}; "
            f"the exit code and the report disagree, so neither can be trusted"
        ]

    lines = [
        f"{checks[name]['status']}|{name}: {checks[name].get('detail', '')}"
        for name in sorted(checks)
    ]
    lines.append("end|")
    return EXIT_OK, lines


def main() -> int:
    if len(sys.argv) != 2:
        return refuse("the probe's exit code was not passed to the reader")
    try:
        exit_code = int(sys.argv[1])
    except ValueError:
        return refuse(f"the probe's exit code {sys.argv[1]!r} is not a number")

    status, lines = read(sys.stdin.read(), exit_code)
    for line in lines:
        print(line)
    return status


if __name__ == "__main__":
    sys.exit(main())
