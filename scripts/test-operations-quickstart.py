#!/usr/bin/env python3
"""Run the documented quickstart literally in a private, namespaced stack."""

from __future__ import annotations

import copy
import html.parser
import json
import os
import pathlib
import pty
import re
import select
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid

from namespaced_compose import namespace
import secrets_file
import local_testbed_demo

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOC = ROOT / "docs/operations.md"
STACK = ROOT / "scripts/stack.sh"
NOTE = "Results are indicators that need verification, not confirmed vulnerabilities."


class CheckFailure(Exception):
    pass


def check(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


def cmd(args: list[str], env: dict | None = None, timeout: int = 90,
        must_pass: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(args, env=env, text=True, capture_output=True, timeout=timeout)
    if must_pass and result.returncode:
        # Compose may include interpolated tokens in diagnostics; never print it.
        raise CheckFailure(f"{args[0]} command failed (exit {result.returncode})")
    return result


def docker(args: list[str], timeout: int = 90) -> str:
    return cmd(["docker", *args], timeout=timeout).stdout.strip()


def inventory() -> dict[str, set[str]]:
    return {
        "containers": set(docker(["ps", "-a", "-q"]).split()),
        "networks": set(docker(["network", "ls", "-q"]).split()),
        "volumes": set(docker(["volume", "ls", "-q"]).split()),
    }


def prior_resources_unchanged(before: dict[str, set[str]]) -> None:
    now = inventory()
    for kind, identities in before.items():
        check(identities <= now[kind], f"a pre-existing Docker {kind} resource disappeared")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def require_free_names(config: dict, owner: str, owner_volume: str) -> None:
    containers = set(docker(["ps", "-a", "--format", "{{.Names}}"]).splitlines())
    networks = set(docker(["network", "ls", "--format", "{{.Name}}"]).splitlines())
    volumes = set(docker(["volume", "ls", "--format", "{{.Name}}"]).splitlines())
    intended_containers = {body["container_name"] for body in config["services"].values()}
    intended_networks = {body["name"] for body in config["networks"].values()
                         if not body.get("external")}
    intended_volumes = {body["name"] for body in config["volumes"].values()
                        if not body.get("external")}
    check(not ((intended_containers | {owner}) & containers),
          "a temporary container name is already in use")
    check(not (intended_networks & networks), "a temporary network name is already in use")
    check(not ((intended_volumes | {owner_volume}) & volumes),
          "a temporary volume name is already in use")


def validate_steps(block: str) -> None:
    required = ["./scripts/init-secrets.sh", "./scripts/stack.sh up",
                "./scripts/stack.sh status", "./scripts/show-dashboard-token.sh",
                "local_testbed_demo.py prepare", "local_testbed_demo.py start",
                "local_testbed_demo.py follow", "local_testbed_demo.py report",
                "--format json", "--format html", "./scripts/stack.sh down"]
    for phrase in required:
        check(phrase in block, f"documented quickstart omits {phrase}")
    check(block.count("local_testbed_demo.py report") == 2,
          "documented quickstart must open exactly JSON and HTML reports")
    positions = [block.index(phrase) for phrase in required]
    check(positions == sorted(positions), "documented quickstart steps are out of order")


def documented() -> str:
    text = DOC.read_text()
    start = text.index("# quickstart-acceptance: begin")
    end = text.index("# quickstart-acceptance: end", start)
    block = text[start:end]
    validate_steps(block)
    return block


class Text(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def report_checks(json_bytes: bytes, html_bytes: bytes, session: str) -> None:
    report = json.loads(json_bytes)
    page = Text()
    page.feed(html_bytes.decode())
    check(report.get("session_id") == session and report.get("status") == "completed",
          "JSON report does not describe the completed demo session")
    check(report.get("completeness", {}).get("complete") is True,
          "JSON report does not prove completeness")
    check(bool(report.get("groups")), "the demo produced no indicator groups")
    check(report.get("note") == NOTE, "JSON report omits the indicator warning")
    check(NOTE in "".join(page.parts), "HTML report omits the indicator warning")


def sensitivity(json_bytes: bytes, html_bytes: bytes, session: str) -> None:
    altered = json.loads(json_bytes)
    altered.pop("note", None)
    try:
        report_checks(json.dumps(altered).encode(), html_bytes, session)
    except CheckFailure as exc:
        check(str(exc) == "JSON report omits the indicator warning", "wrong JSON sensitivity")
    else:
        raise CheckFailure("JSON warning sensitivity did not fail")
    try:
        report_checks(json_bytes, html_bytes.replace(NOTE.encode(), b""), session)
    except CheckFailure as exc:
        check(str(exc) == "HTML report omits the indicator warning", "wrong HTML sensitivity")
    else:
        raise CheckFailure("HTML warning sensitivity did not fail")
    print("PASS: removing either report warning fails for its intended reason", flush=True)


def documented_sensitivity(block: str) -> None:
    changed = "\n".join(line for line in block.splitlines()
                        if "local_testbed_demo.py follow" not in line)
    try:
        validate_steps(changed)
    except CheckFailure as exc:
        check(str(exc) == "documented quickstart omits local_testbed_demo.py follow",
              "wrong documented-step sensitivity")
    else:
        raise CheckFailure("omitting the documented follow command went unnoticed")
    print("PASS: removing the documented follow step fails at the missing step", flush=True)


def terminal_secrets(output: bytes, tokens: dict) -> None:
    check(output.count(tokens["MIHAKK_DASHBOARD_TOKEN"].encode()) == 1,
          "dashboard token was absent from, or repeated in, the private terminal")
    check(tokens["MIHAKK_CONTROL_TOKEN"].encode() not in output,
          "control token reached the terminal")


def run_pty(script: str, env: dict, timeout: int = 360) -> bytes:
    master, slave = pty.openpty()
    diagnostic = "trap 'printf \"QUICKSTART_FAILED_LINE=%s\\n\" \"$LINENO\"' ERR\n"
    proc = subprocess.Popen(["bash", "-e", "-c", diagnostic + script], cwd=ROOT, env=env,
                            stdin=slave, stdout=slave, stderr=slave,
                            start_new_session=True)
    os.close(slave)
    chunks = bytearray()
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.3)
            if ready:
                try:
                    part = os.read(master, 65536)
                except OSError:
                    part = b""
                if part:
                    chunks.extend(part)
                    check(len(chunks) < 2_000_000, "quickstart output exceeded the private buffer")
                elif proc.poll() is not None:
                    break
            if proc.poll() is not None and not ready:
                break
        else:
            proc.terminate()
            raise CheckFailure("the documented quickstart timed out")
        if proc.wait(timeout=10) != 0:
            match = re.search(rb"QUICKSTART_FAILED_LINE=(\d+)", chunks)
            number = match.group(1).decode() if match else "unknown"
            detail = re.search(rb"local testbed demo: ([^\r\n]{1,180})", chunks)
            # The helper's error messages omit responses, headers and tokens.
            safe_detail = detail.group(1).decode(errors="replace") if detail else "no helper verdict"
            raise CheckFailure(f"a documented quickstart command failed at block line {number}: "
                               f"{safe_detail}")
        return bytes(chunks)
    finally:
        os.close(master)
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def volume_sessions(project: str, session: str) -> tuple[str, str]:
    engine_volume = f"{project}_engine-data"
    orch_volume = f"{project}_orchestrator-data"
    engine_args = ["run", "--rm", "--network", "none", "-v",
                     f"{engine_volume}:/db:ro", "python:3.11-alpine", "python3", "-c",
                     "import json,pathlib,sys; p=pathlib.Path('/db/sessions')/sys.argv[1]/'session.json'; "
                     "print(json.loads(p.read_text())['session_id'])", session]
    engine_result = cmd(["docker", *engine_args], must_pass=False)
    if engine_result.returncode:
        reason = engine_result.stderr.strip().splitlines()[-1:] or ["no diagnostic"]
        raise CheckFailure(f"engine data read failed: {reason[0][:150]}")
    engine = engine_result.stdout.strip()
    # SQLite may create a WAL shared-memory sidecar even for a read-only query.
    # The volume is this test's own; SQL itself still opens in mode=ro.
    orch_args = ["run", "--rm", "--network", "none", "-v",
                           f"{orch_volume}:/db", "python:3.11-alpine", "python3", "-c",
                           "import sqlite3,sys; c=sqlite3.connect('file:/db/mihakk.db?mode=ro',uri=True); "
                           "print(c.execute('select status from sessions where session_id=?',"
                           "(sys.argv[1],)).fetchone()[0])", session]
    orch_result = cmd(["docker", *orch_args], must_pass=False)
    if orch_result.returncode:
        reason = orch_result.stderr.strip().splitlines()[-1:] or ["no diagnostic"]
        raise CheckFailure(f"orchestrator data read failed: {reason[0][:150]}")
    orchestrator = orch_result.stdout.strip()
    return engine, orchestrator


def move_engine_record(project: str, session: str, hide: bool) -> None:
    # Sensitivity only: move one file inside this throwaway volume, then restore
    # it in a finally block. Never target an operator or shared project.
    volume = f"{project}_engine-data"
    check(project.startswith("mihakk-doc-"), "refusing to alter a non-test volume")
    action = "p.rename(p.with_suffix('.held'))" if hide else "p.with_suffix('.held').rename(p)"
    docker(["run", "--rm", "--network", "none", "-v", f"{volume}:/db",
            "python:3.11-alpine", "python3", "-c",
            "import pathlib,sys; p=pathlib.Path('/db/sessions')/sys.argv[1]/'session.json'; "
            + action, session])


def check_owner(name: str, volume: str, marker: str, identity: tuple[str, str, int]) -> None:
    detail = json.loads(docker(["inspect", name]))[0]
    observed = (detail["Id"], detail["State"]["StartedAt"], detail["RestartCount"])
    check(observed == identity and detail["State"]["Running"],
          "the neighbouring owner application was stopped or replaced")
    value = docker(["run", "--rm", "--network", "none", "-v",
                    f"{volume}:/data:ro", "python:3.11-alpine", "python3", "-c",
                    "import pathlib;print(pathlib.Path('/data/marker').read_text())"])
    check(value == marker, "the neighbouring owner's data changed")


def main() -> None:
    def interrupt(_signum, _frame):
        raise KeyboardInterrupt("interrupted")

    signal.signal(signal.SIGTERM, interrupt)
    project = f"mihakk-doc-{uuid.uuid4().hex[:10]}"
    owner = f"{project}-owner"
    owner_volume = f"{project}-owner-data"
    marker = uuid.uuid4().hex
    existing = inventory()
    made_owner = made_volume = touched_stack = False
    with tempfile.TemporaryDirectory(prefix="mihakk-8c-") as raw:
        work = pathlib.Path(raw)
        compose_path = work / "stack.json"
        secrets_path = work / "config/mihakk/secrets.env"
        demo_dir = work / "demo"
        demo_dir.mkdir()
        session = f"{project}-demo"
        port = free_port()
        env = {**os.environ, "MIHAKK_COMPOSE_FILE": str(compose_path),
               "MIHAKK_SECRETS_FILE": str(secrets_path),
               "MIHAKK_PORT": str(port), "MIHAKK_DEMO_DIR": str(demo_dir),
               "MIHAKK_DEMO_SESSION": session}
        try:
            check(project != "mihakk", "test project collided with the real one")
            resolved = json.loads(cmd(["docker", "compose", "-f",
                                       str(ROOT / "deploy/docker-compose.yml"),
                                       "config", "--no-interpolate", "--format", "json"]).stdout)
            derived = namespace(resolved, project)
            require_free_names(derived, owner, owner_volume)
            compose_path.write_text(json.dumps(derived, indent=2))
            docker(["volume", "create", owner_volume])
            made_volume = True
            docker(["run", "--rm", "--network", "none", "-v",
                    f"{owner_volume}:/data", "python:3.11-alpine", "python3", "-c",
                    "import pathlib,sys;pathlib.Path('/data/marker').write_text(sys.argv[1])", marker])
            docker(["run", "-d", "--name", owner, "--network", "none", "-v",
                    f"{owner_volume}:/data:ro", "python:3.11-alpine",
                    "python3", "-m", "http.server", "8000"])
            made_owner = True
            owner_detail = json.loads(docker(["inspect", owner]))[0]
            identity = (owner_detail["Id"], owner_detail["State"]["StartedAt"],
                        owner_detail["RestartCount"])
            touched_stack = True
            block = documented()
            documented_sensitivity(block)
            output = run_pty(block, env)
            tokens = secrets_file.read(str(secrets_path))
            check(stat.S_IMODE(secrets_path.stat().st_mode) == 0o600,
                  "secrets file is not 0600")
            terminal_secrets(output, tokens)
            try:
                terminal_secrets(output + tokens["MIHAKK_CONTROL_TOKEN"].encode(), tokens)
            except CheckFailure as exc:
                check(str(exc) == "control token reached the terminal", "wrong secret sensitivity")
            else:
                raise CheckFailure("a leaked control token went unnoticed")
            print("PASS: a leaked control token fails the terminal check", flush=True)
            check(b"Mihakk is up" in output and b"networks the engine is on" in output,
                  "up/status output was not observed")
            print("PASS: documented init/up/status/terminal-token/start/follow/JSON/HTML/down", flush=True)
            json_path = demo_dir / "report.json"
            html_path = demo_dir / "report.html"
            check(stat.S_IMODE(json_path.stat().st_mode) == 0o600 and
                  stat.S_IMODE(html_path.stat().st_mode) == 0o600,
                  "report file permissions are not 0600")
            report_checks(json_path.read_bytes(), html_path.read_bytes(), session)
            sensitivity(json_path.read_bytes(), html_path.read_bytes(), session)
            check(volume_sessions(project, session) == (session, "completed"),
                  "Mihakk session data was lost after the documented down")
            check_owner(owner, owner_volume, marker, identity)
            prior_resources_unchanged(existing)
            print("PASS: both Mihakk data volumes and the neighbouring owner survive down", flush=True)

            no_ack = demo_dir / "unacknowledged.json"
            refused = cmd([sys.executable, str(ROOT / "scripts/local_testbed_demo.py"),
                           "prepare", "--output", str(no_ack)], env=env, must_pass=False)
            check(refused.returncode != 0 and not no_ack.exists(),
                  "local testbed preparation accepted a missing acknowledgement")
            altered = json.loads((demo_dir / "session.json").read_text())
            local_ip = altered["scope"]["targets"][0]["allowed_addresses"][0].split("/")[0]
            altered["scope"]["targets"][0]["host"] = "example.com"
            edited_path = demo_dir / "public-target.json"
            edited_path.write_text(json.dumps(altered))
            original_address = local_testbed_demo.testbed_address
            local_testbed_demo.testbed_address = lambda: local_ip
            try:
                try:
                    local_testbed_demo.start(edited_path, session + "-public",
                                             local_testbed_demo.SEED)
                except local_testbed_demo.DemoError as exc:
                    check(str(exc) == "only a current local testbed configuration is accepted",
                          "wrong public-target refusal")
                else:
                    raise CheckFailure("the local demo accepted a public target")
            finally:
                local_testbed_demo.testbed_address = original_address
            print("PASS: no acknowledgement or public target is accepted", flush=True)

            # Force the documented up command to fail after its preflight by
            # occupying only this test's host port. It must not erase data or
            # touch the independently running application.
            with socket.socket() as blocker:
                blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                blocker.bind(("127.0.0.1", port))
                blocker.listen(1)
                failed = cmd([str(STACK), "up"], env=env, timeout=240, must_pass=False)
                check(failed.returncode != 0, "the injected port conflict did not fail up")
                combined = (failed.stdout + failed.stderr).encode()
                check(all(value.encode() not in combined for value in tokens.values()),
                      "the failed up printed a token")
            cmd([str(STACK), "down"], env=env)
            check(volume_sessions(project, session) == (session, "completed"),
                  "Mihakk session data was lost after failed up and down")
            check_owner(owner, owner_volume, marker, identity)
            prior_resources_unchanged(existing)
            print("PASS: failure and cleanup keep Mihakk data and owner app/data", flush=True)
            move_engine_record(project, session, True)
            try:
                try:
                    volume_sessions(project, session)
                except CheckFailure as exc:
                    check(str(exc).startswith("engine data read failed: FileNotFoundError:"),
                          "wrong data-loss sensitivity")
                else:
                    raise CheckFailure("hiding the engine record went unnoticed")
            finally:
                move_engine_record(project, session, False)
            check(volume_sessions(project, session) == (session, "completed"),
                  "the sensitivity test did not restore the engine record")
            print("PASS: hiding a stored engine session fails the data check, then restores it", flush=True)
        finally:
            original_failure = sys.exc_info()[1]
            if touched_stack and project != "mihakk":
                cmd(["docker", "compose", "-f", str(compose_path), "down", "-v"],
                    env={**env, "MIHAKK_CONTROL_TOKEN": "placeholder",
                         "MIHAKK_DASHBOARD_TOKEN": "placeholder"}, must_pass=False)
            if made_owner:
                cmd(["docker", "rm", "-f", owner], must_pass=False)
            if made_volume:
                cmd(["docker", "volume", "rm", owner_volume], must_pass=False)
            after = inventory()
            if after != existing:
                added = {kind: sorted(after[kind] - existing[kind]) for kind in existing}
                removed = {kind: sorted(existing[kind] - after[kind]) for kind in existing}
                raise CheckFailure(f"temporary Docker resources changed: added={added}, "
                                   f"removed={removed}; earlier failure type="
                                   f"{type(original_failure).__name__ if original_failure else 'none'}")
    print("PASS: temporary project and neighbouring guard cleaned; previous resources unchanged", flush=True)


if __name__ == "__main__":
    try:
        main()
    except CheckFailure as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
