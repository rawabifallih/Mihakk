"""Find the run's tokens anywhere they should not be, without printing them.

test-all.sh gives every suite one pair of tokens for the whole run, then asks
this script whether either value turned up in a log it kept or in a file git
tracks. The tokens are read from the environment (MIHAKK_CONTROL_TOKEN,
MIHAKK_DASHBOARD_TOKEN), never from argv, which other users can read from the
process list. A hit is reported by file, line and WHICH token -- never by value.

    scan FILE...        exit 0 no hit, 1 a hit (listed), 2 no tokens to look for
    scan-tracked REPO   the same, over every file `git ls-files` lists in REPO
    redact FILE...      replace each value with [REDACTED:<name>] in place, so a
                        log kept for evidence does not keep the secret with it

A token shorter than 16 characters is refused as a search term: it would match
by accident, and a match that means nothing is worse than no check.
"""

from __future__ import annotations

import os
import subprocess
import sys

NAMES = ("MIHAKK_CONTROL_TOKEN", "MIHAKK_DASHBOARD_TOKEN")
MIN_LENGTH = 16

EXIT_CLEAN = 0
EXIT_FOUND = 1
EXIT_UNVERIFIED = 2


def tokens_from_env(environ=os.environ) -> dict:
    """{name: value} for every token set and long enough to search for."""
    found = {}
    for name in NAMES:
        value = environ.get(name, "")
        if len(value) >= MIN_LENGTH:
            found[name] = value
    return found


def scan_bytes(label: str, data: bytes, tokens: dict) -> list:
    """Lines 'label:line: NAME' for every token occurrence, in file order."""
    hits = []
    for number, line in enumerate(data.split(b"\n"), start=1):
        for name, value in tokens.items():
            if value.encode() in line:
                hits.append(f"{label}:{number}: {name}")
    return hits


def scan_files(paths: list, tokens: dict) -> tuple:
    hits, unreadable = [], []
    for path in paths:
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError as exc:
            unreadable.append(f"{path}: {exc.strerror}")
            continue
        hits.extend(scan_bytes(path, data, tokens))
    return hits, unreadable


def redact(path: str, tokens: dict) -> int:
    with open(path, "rb") as handle:
        data = handle.read()
    count = 0
    for name, value in tokens.items():
        count += data.count(value.encode())
        data = data.replace(value.encode(), f"[REDACTED:{name}]".encode())
    if count:
        with open(path, "wb") as handle:
            handle.write(data)
    return count


def tracked_files(repo: str) -> list:
    out = subprocess.run(["git", "-C", repo, "ls-files", "-z"], capture_output=True,
                         check=True)
    return [os.path.join(repo, name) for name in out.stdout.decode().split("\0") if name]


def main(argv: list) -> int:
    if not argv or argv[0] not in ("scan", "scan-tracked", "redact"):
        print("usage: scan_secrets.py scan FILE... | scan-tracked REPO | redact FILE...",
              file=sys.stderr)
        return EXIT_UNVERIFIED
    tokens = tokens_from_env()
    if not tokens:
        print("no token of at least 16 characters is set, so there is nothing to look for")
        return EXIT_UNVERIFIED

    command, args = argv[0], argv[1:]
    if command == "redact":
        for path in args:
            count = redact(path, tokens)
            if count:
                print(f"{path}: {count} occurrence(s) redacted")
        return EXIT_CLEAN

    if command == "scan-tracked":
        if len(args) != 1:
            return EXIT_UNVERIFIED
        try:
            paths = tracked_files(args[0])
        except (OSError, subprocess.CalledProcessError) as exc:
            print(f"could not list the tracked files: {exc}")
            return EXIT_UNVERIFIED
        # A tracked file deleted in the working tree is not there to leak.
        paths = [p for p in paths if os.path.isfile(p)]
    else:
        paths = args

    hits, unreadable = scan_files(paths, tokens)
    for hit in hits:
        print(hit)
    for problem in unreadable:
        print(f"unreadable: {problem}")
    if hits:
        return EXIT_FOUND
    if unreadable:
        return EXIT_UNVERIFIED
    print(f"no token in {len(paths)} file(s)")
    return EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
