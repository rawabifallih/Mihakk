"""Structural guard: the dashboard must never turn data into markup.

The dashboard is the first component that needs JavaScript, so the report's
defence -- no script at all, `default-src 'none'` -- does not carry over. What
replaces it is not better sanitising but removing the executable context from the
data path: every value reaches the page through textContent or setAttribute on an
element the code created, and the constructs that would turn a string into markup
or into code are simply not used.

That is a property of the source, so it is checked against the source. This runs
in a second and needs no browser, which is what makes it the guard that fires on
every commit; the browser test proves the same property against a real DOM and
costs minutes.

Forbidden, and why each one:

  innerHTML, outerHTML, insertAdjacentHTML, document.write, document.writeln
      parse a string as markup, which is the whole failure mode
  eval, new Function, setTimeout/setInterval with a string
      parse a string as code
  srcdoc, javascript: URLs
      the same, by another door

    exit 0  none of them present
    exit 1  at least one present
    exit 2  the source could not be read, so nothing was established
"""

from __future__ import annotations

import pathlib
import re
import sys

EXIT_CLEAN = 0
EXIT_FOUND = 1
EXIT_UNVERIFIED = 2

# Each rule is (name, pattern, why it is refused).
RULES: list[tuple[str, re.Pattern[str], str]] = [
    ("innerHTML", re.compile(r"\binnerHTML\b"),
     "assigns a string as markup; build elements and set textContent instead"),
    ("outerHTML", re.compile(r"\bouterHTML\b"),
     "replaces an element from a string of markup"),
    ("insertAdjacentHTML", re.compile(r"\binsertAdjacentHTML\b"),
     "parses a string as markup"),
    # write(?:ln)? -- not writeln?, which matches "writel" and misses "write"
    # entirely. The unit test for this guard is what found that.
    ("document.write", re.compile(r"document\s*\.\s*write(?:ln)?\b"),
     "parses a string as markup"),
    ("eval", re.compile(r"(?<![\w.$])eval\s*\("),
     "executes a string as code"),
    ("new Function", re.compile(r"\bnew\s+Function\b"),
     "compiles a string into code"),
    ("setTimeout with a string", re.compile(r"setTimeout\s*\(\s*['\"`]"),
     "executes a string as code"),
    ("setInterval with a string", re.compile(r"setInterval\s*\(\s*['\"`]"),
     "executes a string as code"),
    ("srcdoc", re.compile(r"\bsrcdoc\b"),
     "renders a string as a document"),
    ("javascript: URL", re.compile(r"javascript\s*:", re.IGNORECASE),
     "makes a string executable through a URL"),
    ("document.domain", re.compile(r"document\s*\.\s*domain\b"),
     "relaxes the origin the page belongs to"),
]

# Lines a rule may legitimately appear on: the prose that explains why it is
# refused. A comment is not code, and a guard that forbade the word everywhere
# would forbid documenting itself -- the same mistake as banning a string from a
# report whose disclaimer contains it.
COMMENT = re.compile(r"^\s*(//|/\*|\*)")


def scan_text(source: str) -> list[tuple[int, str, str]]:
    """Return (line number, rule name, reason) for every occurrence in code."""
    found: list[tuple[int, str, str]] = []
    for number, line in enumerate(source.splitlines(), start=1):
        if COMMENT.match(line):
            continue
        for name, pattern, reason in RULES:
            if pattern.search(line):
                found.append((number, name, reason))
    return found


def scan_file(path: pathlib.Path) -> list[tuple[int, str, str]]:
    return scan_text(path.read_text(encoding="utf-8"))


def main() -> int:
    if len(sys.argv) != 2:
        print("UNVERIFIED\tusage: check_dashboard_js.py <dashboard-dir>")
        return EXIT_UNVERIFIED

    root = pathlib.Path(sys.argv[1])
    if not root.is_dir():
        print(f"UNVERIFIED\t{root} is not a directory")
        return EXIT_UNVERIFIED

    files = sorted(root.rglob("*.js"))
    if not files:
        print(f"UNVERIFIED\tno JavaScript found under {root}; "
              "this guard would pass by having nothing to check")
        return EXIT_UNVERIFIED

    problems = 0
    for path in files:
        try:
            hits = scan_file(path)
        except OSError as exc:
            print(f"UNVERIFIED\tcould not read {path}: {exc}")
            return EXIT_UNVERIFIED
        for number, name, reason in hits:
            problems += 1
            print(f"FAIL\t{path}:{number}: {name} — {reason}")

    if problems:
        return EXIT_FOUND

    print(f"PASS\t{len(files)} file(s) build the page without turning data into markup")
    return EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
