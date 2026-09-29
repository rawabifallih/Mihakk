"""Decide whether a test may create a Docker resource under a given name.

A test that creates a volume, container or network, and later removes it because
it believes it created it, is one wrong inventory away from deleting someone's
data. The belief is the dangerous part: it rests on an inventory command that can
fail, be truncated, or answer about something else entirely.

So the decision is made here, from the inventory's exit status and output
together, and it fails CLOSED -- an inventory that cannot be trusted refuses the
name rather than assuming it is free:

    exit 0  the name is free; the caller may create it and may remove what it
            created
    exit 1  a resource with that exact name already exists; the caller must not
            create over it and must not remove it
    exit 2  the inventory could not be read, so whether the name is free is
            UNKNOWN; the caller must refuse to proceed

Docker is not run from here. The caller runs, for example

    docker volume ls -q --filter "name=^${NAME}$"; rc=$?

and passes the exit status and the raw output in, which is what makes this a pure
function of its input and testable without Docker -- the same shape as
check_container_ports.py.
"""

from __future__ import annotations

import sys

EXIT_FREE = 0
EXIT_TAKEN = 1
EXIT_UNKNOWN = 2


def decide(name: str, inventory_rc: int, inventory_output: str) -> tuple[int, str]:
    """Return (exit code, explanation) for one name."""
    if not name or name.strip() != name or any(c.isspace() for c in name):
        return EXIT_UNKNOWN, (
            f"the requested name {name!r} is empty or carries whitespace, so an "
            "exact-match inventory cannot be trusted"
        )

    if inventory_rc != 0:
        return EXIT_UNKNOWN, (
            f"the inventory for {name!r} exited {inventory_rc}, so whether the name "
            "is free is unknown; refusing rather than assuming it is free"
        )

    lines = [line.strip() for line in inventory_output.splitlines() if line.strip()]

    if not lines:
        return EXIT_FREE, f"no existing resource is named {name!r}"

    if lines == [name]:
        return EXIT_TAKEN, (
            f"a resource named {name!r} already exists; it was not created by this "
            "run, so it must be neither written over nor removed"
        )

    # The filter was an exact anchored match, so anything else means the output is
    # not the answer to the question that was asked.
    return EXIT_UNKNOWN, (
        f"the inventory for {name!r} returned {lines!r}, which is not an exact "
        "match for the requested name; the answer cannot be interpreted"
    )


def main() -> int:
    if len(sys.argv) not in (3, 4):
        print("usage: claim_name.py <name> <inventory-exit-code> [<inventory-output>]",
              file=sys.stderr)
        return EXIT_UNKNOWN

    name = sys.argv[1]
    try:
        inventory_rc = int(sys.argv[2])
    except ValueError:
        print(f"the inventory exit code {sys.argv[2]!r} is not an integer", file=sys.stderr)
        return EXIT_UNKNOWN

    output = sys.argv[3] if len(sys.argv) == 4 else ""

    code, explanation = decide(name, inventory_rc, output)
    print(explanation)
    return code


if __name__ == "__main__":
    sys.exit(main())
