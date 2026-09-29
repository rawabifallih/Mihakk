"""Fail if git tracks a file shaped like a secrets file.

.gitignore stops `git add .` from picking one up, but not `git add -f`, and not a
file that was tracked before the pattern existed. This asks git what it actually
tracks, which is the question that matters.

    exit 0  nothing tracked looks like a secrets file
    exit 1  something does; the names are listed
    exit 2  git could not answer, so nothing is claimed
"""

from __future__ import annotations

import fnmatch
import os
import subprocess
import sys

# The patterns .gitignore carries, matched against each tracked file's basename.
PATTERNS = (".env", ".env.*", "*.env")


def offending(names: list) -> list:
    return sorted(n for n in names
                  if any(fnmatch.fnmatchcase(os.path.basename(n), p) for p in PATTERNS))


def main(argv: list) -> int:
    repo = argv[0] if argv else "."
    try:
        out = subprocess.run(["git", "-C", repo, "ls-files", "-z"],
                             capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"git could not list the tracked files: {exc}")
        return 2
    names = [n for n in out.stdout.decode("utf-8", "replace").split("\0") if n]
    if not names:
        print("git lists no tracked files; that is not a repository worth trusting")
        return 2
    bad = offending(names)
    for name in bad:
        print(f"tracked, and shaped like a secrets file: {name}")
    if bad:
        return 1
    print(f"no secrets-shaped file among {len(names)} tracked files")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
