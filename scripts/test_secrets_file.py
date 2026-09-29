"""Tests for secrets_file.py: the file is data, never a program.

The hostile cases are the point. A value carrying $(...), backticks or a `;`
must be refused, must not run, and the refusal must not repeat it -- whatever was
on that line may be a real token that was pasted in the wrong place.
"""

from __future__ import annotations

import os
import pty
import stat
import subprocess
import sys
import tempfile
import unittest

import secrets_file
from secrets_file import KEYS, Refused, parse

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secrets_file.py")
A = "a" * 64
B = "b" * 64


def body(*lines: str) -> bytes:
    return ("\n".join(lines) + "\n").encode()


GOOD = body(f"{KEYS[0]}={A}", f"{KEYS[1]}={B}")


def _read(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


class TestTheOneShapeItMayHave(unittest.TestCase):
    def test_the_generated_shape_parses(self):
        self.assertEqual(parse(GOOD), {KEYS[0]: A, KEYS[1]: B})

    def test_comments_and_blank_lines_are_allowed(self):
        raw = body("# header", "", f"{KEYS[1]}={B}", "# between", f"{KEYS[0]}={A}", "")
        self.assertEqual(parse(raw)[KEYS[0]], A)


class TestHostileValuesAreRefusedNotRun(unittest.TestCase):
    """Each of these would do something if the file were sourced."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="mks")
        self.marker = os.path.join(self.dir, "pwned")

    def tearDown(self):
        for name in os.listdir(self.dir):
            os.unlink(os.path.join(self.dir, name))
        os.rmdir(self.dir)

    def hostile_lines(self):
        m = self.marker
        return [
            f"{KEYS[0]}=$(touch {m})",
            f"{KEYS[0]}=`touch {m}`",
            f"{KEYS[0]}={A}; touch {m}",
            f"{KEYS[0]}={A}$(touch {m})",
            f"{KEYS[0]}=\"$(touch {m})\"",
            f"{KEYS[0]}='{A}'",
            f"export {KEYS[0]}={A}",
            f"{KEYS[0]} = {A}",
            f"{KEYS[0]}={A} ",
            f"{KEYS[0]}={A.upper()}",
            f"{KEYS[0]}={A[:63]}",
            f"{KEYS[0]}={A}0",
            f"LD_PRELOAD=/tmp/evil.so",
            f"PATH={self.dir}",
            f"MIHAKK_ENGINE_URL=http://192.0.2.1:8900",
            f"touch {m}",
            f"{KEYS[0]}=${{IFS}}touch${{IFS}}{m}",
        ]

    def test_each_hostile_line_is_refused_without_repeating_it(self):
        for line in self.hostile_lines():
            raw = body(line, f"{KEYS[1]}={B}")
            with self.subTest(line=line):
                with self.assertRaises(Refused) as caught:
                    parse(raw)
                message = str(caught.exception)
                # The value side of the line never appears in the refusal.
                value = line.split("=", 1)[1] if "=" in line else line
                self.assertNotIn(value.strip(), message)
                self.assertNotIn(self.marker, message)
                self.assertIn("line 1", message)

    def test_nothing_ran_through_the_command_line_either(self):
        """The whole tool, as a process, on a file full of hostile lines."""
        path = os.path.join(self.dir, "secrets.env")
        for line in self.hostile_lines():
            with open(path, "wb") as handle:
                handle.write(body(line, f"{KEYS[1]}={B}"))
            os.chmod(path, 0o600)
            for command in (["check", path], ["run", path, "--", "true"]):
                result = subprocess.run([sys.executable, SCRIPT] + command,
                                        capture_output=True, text=True)
                with self.subTest(line=line, command=command[0]):
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertFalse(os.path.exists(self.marker), "a hostile value ran")
                    self.assertNotIn(B, result.stdout + result.stderr)
            os.unlink(path)

    def test_carriage_returns_nul_and_non_ascii(self):
        for raw in (GOOD.replace(b"\n", b"\r\n"), GOOD + b"\x00",
                    GOOD + "# م\n".encode()):
            with self.assertRaises(Refused):
                parse(raw)

    def test_a_duplicate_key_is_refused(self):
        with self.assertRaises(Refused) as caught:
            parse(GOOD + body(f"{KEYS[0]}={'c' * 64}"))
        self.assertNotIn("c" * 64, str(caught.exception))

    def test_a_missing_key_is_refused(self):
        with self.assertRaises(Refused):
            parse(body(f"{KEYS[0]}={A}"))

    def test_the_two_tokens_must_differ(self):
        with self.assertRaises(Refused) as caught:
            parse(body(f"{KEYS[0]}={A}", f"{KEYS[1]}={A}"))
        self.assertNotIn(A, str(caught.exception))

    def test_an_oversized_file_is_refused(self):
        with self.assertRaises(Refused):
            parse(GOOD + b"#" * 5000 + b"\n")


class TestTheFileItself(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="mks")
        self.path = os.path.join(self.dir, "secrets.env")

    def tearDown(self):
        for root, dirs, files in os.walk(self.dir, topdown=False):
            for name in files:
                os.unlink(os.path.join(root, name))
            for name in dirs:
                path = os.path.join(root, name)
                (os.unlink if os.path.islink(path) else os.rmdir)(path)
        os.rmdir(self.dir)

    def write(self, raw=GOOD, mode=0o600):
        with open(self.path, "wb") as handle:
            handle.write(raw)
        os.chmod(self.path, mode)

    def test_a_private_file_is_read(self):
        self.write()
        self.assertEqual(secrets_file.read(self.path)[KEYS[1]], B)

    def test_a_file_others_can_read_is_refused(self):
        for mode in (0o640, 0o604, 0o660, 0o644):
            self.write(mode=mode)
            with self.assertRaises(Refused):
                secrets_file.read(self.path)

    def test_a_symlink_is_refused(self):
        real = os.path.join(self.dir, "real.env")
        with open(real, "wb") as handle:
            handle.write(GOOD)
        os.chmod(real, 0o600)
        os.symlink(real, self.path)
        with self.assertRaises(Refused) as caught:
            secrets_file.read(self.path)
        # Refused for being a link: other checks (the link's own mode, O_NOFOLLOW)
        # would also stop it, which is exactly why the reason is pinned here.
        self.assertIn("symbolic link", str(caught.exception))

    def test_a_file_inside_a_git_working_tree_is_refused(self):
        os.mkdir(os.path.join(self.dir, ".git"))
        self.write()
        with self.assertRaises(Refused) as caught:
            secrets_file.read(self.path)
        self.assertIn("git working tree", str(caught.exception))
        os.unlink(self.path)
        with self.assertRaises(Refused):
            secrets_file.generate(self.path)
        self.assertFalse(os.path.exists(self.path))

    def test_generate_creates_a_private_file_and_never_overwrites(self):
        secrets_file.generate(self.path)
        info = os.stat(self.path)
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        first = _read(self.path)
        tokens = parse(first)
        self.assertNotEqual(tokens[KEYS[0]], tokens[KEYS[1]])
        with self.assertRaises(Refused):
            secrets_file.generate(self.path)
        self.assertEqual(_read(self.path), first, "an existing file was changed")

    def test_generate_prints_neither_token(self):
        result = subprocess.run([sys.executable, SCRIPT, "generate", self.path],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        tokens = secrets_file.read(self.path)
        for value in tokens.values():
            self.assertNotIn(value, result.stdout + result.stderr)

    def test_run_hands_the_tokens_over_by_environment(self):
        self.write()
        result = subprocess.run(
            [sys.executable, SCRIPT, "run", self.path, "--", sys.executable, "-c",
             "import os; print(os.environ['MIHAKK_CONTROL_TOKEN'] == 'a' * 64,"
             " os.environ['MIHAKK_DASHBOARD_TOKEN'] == 'b' * 64)"],
            capture_output=True, text=True)
        self.assertEqual(result.stdout.strip(), "True True", result.stderr)


class TestShowDashboardOnlyToATerminal(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="mks")
        self.path = os.path.join(self.dir, "secrets.env")
        with open(self.path, "wb") as handle:
            handle.write(GOOD)
        os.chmod(self.path, 0o600)

    def tearDown(self):
        os.unlink(self.path)
        os.rmdir(self.dir)

    def test_redirected_output_gets_nothing(self):
        result = subprocess.run([sys.executable, SCRIPT, "show-dashboard", self.path],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(B, result.stdout + result.stderr)
        self.assertIn("not a terminal", result.stderr)

    def test_a_terminal_gets_the_token(self):
        # A real pseudo-terminal, read here and compared, never printed.
        primary, secondary = pty.openpty()
        try:
            process = subprocess.Popen([sys.executable, SCRIPT, "show-dashboard", self.path],
                                       stdout=secondary, stderr=subprocess.DEVNULL)
            os.close(secondary)
            chunks = []
            while True:
                try:
                    chunk = os.read(primary, 1024)
                except OSError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
            process.wait(timeout=10)
        finally:
            os.close(primary)
        self.assertEqual(process.returncode, 0)
        self.assertEqual(b"".join(chunks).decode().strip(), B)


if __name__ == "__main__":
    unittest.main(verbosity=2)
