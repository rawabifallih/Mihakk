"""The operator's secrets file: created, read and handed on without being executed.

The file holds the two tokens the stack needs, and nothing else:

    MIHAKK_CONTROL_TOKEN=<64 lowercase hex characters>
    MIHAKK_DASHBOARD_TOKEN=<64 lowercase hex characters>

(plus blank lines and whole-line # comments). It lives OUTSIDE the repository by
default -- ${XDG_CONFIG_HOME:-~/.config}/mihakk/secrets.env -- with mode 0600.

Why this is Python and not a shell `source`: a sourced file is a program. A value
such as $(...) or `...` in it runs, with the operator's privileges, the moment the
stack is started. So nothing here evaluates the file. It is read as bytes and
matched line by line against the one shape it may have; anything else is refused,
and the refusal names the line and the key but never repeats what was on the line,
because what was on the line may be a token.

    generate PATH          create the file (refuses to overwrite, refuses inside
                           a git working tree); prints the path, never a value
    check PATH             validate it; prints "ok", never a value
    run PATH -- CMD ...    exec CMD with the two tokens added to its environment.
                           They travel by environment, not argv, which other
                           users can read from the process list.
    show-dashboard PATH    print the dashboard token, and only to a terminal:
                           with stdout redirected to a file or a pipe -- which is
                           what a test runner that keeps logs does -- it refuses.

Exit codes: 0 done, 1 refused (the reason is on stderr), 2 usage.
"""

from __future__ import annotations

import os
import re
import secrets
import stat
import sys

KEYS = ("MIHAKK_CONTROL_TOKEN", "MIHAKK_DASHBOARD_TOKEN")
TOKEN_RE = re.compile(r"[0-9a-f]{64}")
LINE_RE = re.compile(r"(MIHAKK_CONTROL_TOKEN|MIHAKK_DASHBOARD_TOKEN)=([0-9a-f]{64})")
MAX_BYTES = 4096

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2


class Refused(Exception):
    """The file is not one this tool will use. The message never carries a value."""


def parse(raw: bytes) -> dict:
    """Return {key: token} for exactly the two keys, or raise Refused.

    Deliberately narrow. No `export`, no quotes, no spaces around `=`, no
    carriage returns, no other keys: every one of those is either a shell-ism
    that invites treating the file as a script, or a way for a second variable to
    ride along into the environment of the command that is run.
    """
    if len(raw) > MAX_BYTES:
        raise Refused(f"the file is larger than {MAX_BYTES} bytes; it should hold two lines")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise Refused("the file is not plain ASCII") from None
    if "\r" in text:
        raise Refused("the file has carriage returns; write it with plain newlines")
    if "\x00" in text:
        raise Refused("the file contains a NUL byte")

    found: dict = {}
    for number, line in enumerate(text.split("\n"), start=1):
        if line == "" or line.startswith("#"):
            continue
        match = LINE_RE.fullmatch(line)
        if match is None:
            # Name the key if the line starts with one, so the operator can find
            # it; never echo the value, which may be a token.
            key = line.split("=", 1)[0] if "=" in line else ""
            named = f" ({key})" if key in KEYS else ""
            raise Refused(
                f"line {number}{named} is not KEY=<64 lowercase hex characters> "
                f"for one of {', '.join(KEYS)}")
        key, value = match.group(1), match.group(2)
        if key in found:
            raise Refused(f"{key} appears more than once (again on line {number})")
        found[key] = value

    missing = [key for key in KEYS if key not in found]
    if missing:
        raise Refused(f"the file does not set {', '.join(missing)}")
    if found[KEYS[0]] == found[KEYS[1]]:
        raise Refused("the two tokens are identical; they must be independent secrets")
    return found


def _inside_git_worktree(path: str) -> str | None:
    """The working tree containing path, if any. A secret there is one `git add` from a commit."""
    here = os.path.dirname(os.path.realpath(path))
    while True:
        if os.path.exists(os.path.join(here, ".git")):
            return here
        parent = os.path.dirname(here)
        if parent == here:
            return None
        here = parent


def _check_location(path: str) -> None:
    tree = _inside_git_worktree(path)
    if tree is not None:
        raise Refused(f"{path} is inside the git working tree {tree}; keep secrets "
                      "outside any repository")


def read(path: str) -> dict:
    """Read and validate the file, refusing one that others could read or swap."""
    _check_location(path)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        raise Refused(f"{path} does not exist; create it with scripts/init-secrets.sh") from None
    if stat.S_ISLNK(info.st_mode):
        raise Refused(f"{path} is a symbolic link; use the file itself")
    if not stat.S_ISREG(info.st_mode):
        raise Refused(f"{path} is not a regular file")
    if info.st_uid != os.getuid():
        raise Refused(f"{path} belongs to another user")
    if info.st_mode & 0o077:
        raise Refused(f"{path} is readable or writable by others (mode "
                      f"{stat.S_IMODE(info.st_mode):04o}); it must be 0600")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        raw = os.read(fd, MAX_BYTES + 1)
    finally:
        os.close(fd)
    return parse(raw)


def generate(path: str) -> None:
    """Create the file with two fresh tokens. Never overwrites, never prints them."""
    _check_location(path)
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory):
        os.makedirs(directory, mode=0o700)
    info = os.stat(directory)
    if info.st_uid != os.getuid():
        raise Refused(f"{directory} belongs to another user")
    if info.st_mode & 0o022:
        raise Refused(f"{directory} is writable by others (mode "
                      f"{stat.S_IMODE(info.st_mode):04o}); the file could be swapped")

    body = (
        "# Mihakk secrets, generated by scripts/init-secrets.sh.\n"
        "# Never commit this file. Read by scripts/stack.sh without executing it.\n"
        f"{KEYS[0]}={secrets.token_hex(32)}\n"
        f"{KEYS[1]}={secrets.token_hex(32)}\n"
    )
    parse(body.encode("ascii"))  # the generator must produce what the reader accepts

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise Refused(f"{path} already exists; it was not changed") from None
    try:
        os.fchmod(fd, 0o600)  # whatever the umask was
        os.write(fd, body.encode("ascii"))
    finally:
        os.close(fd)


def main(argv: list) -> int:
    if len(argv) < 2:
        print(__doc__.split("\n\n")[0], file=sys.stderr)
        return EXIT_USAGE
    command, path = argv[0], argv[1]
    try:
        if command == "generate" and len(argv) == 2:
            generate(path)
            print(f"created {path} (mode 0600)")
            return EXIT_OK
        if command == "check" and len(argv) == 2:
            read(path)
            print("ok")
            return EXIT_OK
        if command == "show-dashboard" and len(argv) == 2:
            if not sys.stdout.isatty():
                raise Refused("stdout is not a terminal, so the token would land in a "
                              "file or a pipe; run this directly in a terminal")
            print(read(path)[KEYS[1]])
            return EXIT_OK
        if command == "run" and len(argv) >= 4 and argv[2] == "--":
            tokens = read(path)
            env = dict(os.environ)
            env.update(tokens)
            os.execvpe(argv[3], argv[3:], env)
    except Refused as exc:
        print(f"secrets: refused: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    except OSError as exc:
        # The message names the path and the error, never the content.
        print(f"secrets: {exc.strerror or exc}: {exc.filename or path}", file=sys.stderr)
        return EXIT_REFUSED
    print("usage: secrets_file.py generate|check|show-dashboard PATH | run PATH -- CMD ...",
          file=sys.stderr)
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
