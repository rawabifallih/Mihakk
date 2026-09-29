"""Copy a compose config into a namespace of its own, keeping its shape.

isolated_compose.py strips pinned names so `-p` decides them. Some tests need the
opposite: a stack that keeps every pinned name -- so scripts/stack.sh, which reads
the project name from the file, can drive it unchanged -- but under names no real
stack uses. This rewrites every name the project OWNS into the namespace:

    top-level  name            -> NS
    services   container_name  -> NS-<service>
    networks   name            -> NS-<network>   (unless external)
    volumes    name            -> NS_<volume>    (unless external)

An external network or volume is not the project's, so its name is kept: it is
the thing the operator owns, and renaming it would point the stack at something
else. The input is `docker compose config --no-interpolate --format json`, so the
${...} references survive and are interpolated when the copy is used -- which is
what makes the copy exercise the real secrets and port handling.

    exit 0  written to stdout
    exit 2  the input could not be read
"""

from __future__ import annotations

import json
import re
import sys

NS_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{2,62}$")


class Unreadable(Exception):
    pass


def namespace(config: dict, ns: str) -> dict:
    if not NS_RE.match(ns):
        raise Unreadable(f"namespace {ns!r} is not a valid compose project name")
    if not isinstance(config, dict) or not isinstance(config.get("services"), dict):
        raise Unreadable("the config has no services mapping")
    out = json.loads(json.dumps(config))
    out["name"] = ns
    for service, body in out["services"].items():
        if not isinstance(body, dict):
            raise Unreadable(f"service {service!r} is not an object")
        body["container_name"] = f"{ns}-{service}"
    for section, sep in (("networks", "-"), ("volumes", "_")):
        block = out.get(section) or {}
        if not isinstance(block, dict):
            raise Unreadable(f"{section} is not an object")
        for key, body in block.items():
            if body is None:
                body = block[key] = {}
            if not isinstance(body, dict):
                raise Unreadable(f"{section}.{key} is not an object")
            if body.get("external"):
                continue
            body["name"] = f"{ns}{sep}{key}"
    return out


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: namespaced_compose.py <resolved-json> <namespace>", file=sys.stderr)
        return 2
    try:
        with open(sys.argv[1], encoding="utf-8") as handle:
            config = json.load(handle)
        derived = namespace(config, sys.argv[2])
    except (OSError, ValueError, Unreadable) as exc:
        print(f"cannot namespace the config: {exc}", file=sys.stderr)
        return 2
    json.dump(derived, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
