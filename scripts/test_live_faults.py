"""Phase 8b: live, gated Unix-socket stream faults in throwaway Compose projects.

Each positive scenario and each negative control gets its own project. Only
project-labelled resources created by this run may be removed. The proxy never
prints bearer headers, tokens, or response bodies.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import re
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

from isolated_compose import strip_pinned_names
from local_api_transport import FUTURE_ACK, clock_diagnostic

ROOT = pathlib.Path(__file__).resolve().parent.parent
REAL_COMPOSE = ROOT / "deploy/docker-compose.yml"
CORPUS = json.loads((ROOT / "testbed/corpus.json").read_text())
PROXY = ROOT / "scripts/uds_fault_proxy.py"
MUTATIONS = ROOT / "scripts/fault_mutations/sitecustomize.py"
TOKEN = os.environ.get("MIHAKK_CONTROL_TOKEN") or secrets.token_hex(32)
DASHBOARD_TOKEN = os.environ.get("MIHAKK_DASHBOARD_TOKEN") or secrets.token_hex(32)
ENV = {**os.environ, "MIHAKK_CONTROL_TOKEN": TOKEN,
       "MIHAKK_DASHBOARD_TOKEN": DASHBOARD_TOKEN}


class Failure(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code


def sanitized(value: str) -> str:
    return value.replace(TOKEN, "[control token]").replace(DASHBOARD_TOKEN, "[dashboard token]")


def command(args: list[str], *, timeout: int = 180, check: bool = True) -> str:
    result = subprocess.run(args, env=ENV, text=True, capture_output=True,
                            timeout=timeout, check=False)
    if check and result.returncode:
        raise Failure("setup", f"command {args[:3]} exited {result.returncode}: "
                      f"{sanitized((result.stderr + result.stdout)[-1200:])}")
    return result.stdout


def wait_for(label: str, predicate, *, seconds: float = 25):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except (urllib.error.URLError, ValueError, KeyError, OSError, Failure) as exc:
            last = sanitized(str(exc))
        time.sleep(0.2)  # polling interval only; the predicate is the barrier
    raise Failure("setup", f"timed out waiting for {label}; last={last}")


def labelled(project: str) -> dict[str, set[str]]:
    label = f"label=com.docker.compose.project={project}"
    return {
        "containers": set(command(["docker", "ps", "-a", "-q", "--filter", label]).split()),
        "volumes": set(command(["docker", "volume", "ls", "-q", "--filter", label]).split()),
        "networks": set(command(["docker", "network", "ls", "-q", "--filter", label]).split()),
    }


def protected_state() -> dict[str, set[str]]:
    # Inspect all pre-existing Docker resources, not merely Mihakk's shared
    # project. Scenario cleanup must leave their exact identities unchanged.
    return {
        "containers": set(command(["docker", "ps", "-a", "-q"]).split()),
        "volumes": set(command(["docker", "volume", "ls", "-q"]).split()),
        "networks": set(command(["docker", "network", "ls", "-q"]).split()),
    }


class DataGuard:
    """A neighbouring volume with content the scenario must not alter."""

    def __init__(self):
        self.name = f"mihakk-fault-guard-{uuid.uuid4().hex[:8]}"
        self.marker = uuid.uuid4().hex
        self.created = False

    def create(self) -> None:
        if self.name in protected_state()["volumes"]:
            raise Failure("setup", "guard volume name is already in use")
        command(["docker", "volume", "create", self.name])
        self.created = True
        command(["docker", "run", "--rm", "--network", "none",
                 "-v", f"{self.name}:/guard", "python:3.11-alpine",
                 "python3", "-c", "import pathlib,sys; "
                 "pathlib.Path('/guard/marker').write_text(sys.argv[1])", self.marker])

    def check(self) -> None:
        actual = command(["docker", "run", "--rm", "--network", "none",
                          "-v", f"{self.name}:/guard:ro", "python:3.11-alpine",
                          "python3", "-c", "import pathlib; "
                          "print(pathlib.Path('/guard/marker').read_text())"]).strip()
        if actual != self.marker:
            raise Failure("cleanup", "the neighbouring guard volume's data changed")

    def close(self) -> None:
        if self.created:
            command(["docker", "volume", "rm", self.name])


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Stack:
    def __init__(self, name: str, mutation: str = ""):
        self.name = name
        self.mutation = mutation
        self.project = f"mihakk-fault-{name}-{uuid.uuid4().hex[:8]}"
        self.work = tempfile.TemporaryDirectory(prefix="mihakk-fault-")
        self.dir = pathlib.Path(self.work.name)
        self.port = free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.compose_file = self.dir / "compose.json"
        self.compose = ["docker", "compose", "-p", self.project,
                        "-f", str(self.compose_file)]
        self.started = False
        self.sessions: list[str] = []

    def dc(self, *args: str, timeout: int = 180, check: bool = True) -> str:
        return command([*self.compose, *args], timeout=timeout, check=check)

    def setup(self) -> None:
        if any(labelled(self.project).values()):
            raise Failure("setup", "the generated project name is already in use")
        raw = command(["docker", "compose", "-f", str(REAL_COMPOSE),
                       "config", "--format", "json"])
        resolved = json.loads(raw)
        real_name = resolved.get("name")
        if not real_name or self.project == real_name:
            raise Failure("setup", "could not distinguish the test project from the real one")
        config = strip_pinned_names(resolved,
                                   ("orchestrator", "127.0.0.1", str(self.port)))
        orchestrator = config["services"]["orchestrator"]
        orchestrator["environment"]["MIHAKK_ENGINE_URL"] = "unix:/run/mihakk/proxy.sock"
        orchestrator["depends_on"]["fault-proxy"] = {"condition": "service_healthy"}
        if self.mutation:
            orchestrator["volumes"].append({"type": "bind", "source": str(MUTATIONS),
                                             "target": "/probe/sitecustomize.py",
                                             "read_only": True})
            orchestrator["environment"].update({
                "PYTHONPATH": "/probe:/srv",
                "MIHAKK_TEST_MUTATION": self.mutation,
                "MIHAKK_MUTATION_SOURCE": f"{self.project}-b",
                "MIHAKK_MUTATION_DESTINATION": f"{self.project}-a",
            })
        config["services"]["fault-proxy"] = {
            "image": "python:3.11-alpine",
            "user": "10002:10010",
            "network_mode": "none",
            "environment": {"MIHAKK_CONTROL_TOKEN": TOKEN},
            "depends_on": {"engine": {"condition": "service_healthy"}},
            "volumes": [
                {"type": "volume", "source": "control-socket", "target": "/run/mihakk"},
                # SQLite may need to create its WAL shared-memory sidecar to
                # open a read-only connection after the service has stopped.
                {"type": "volume", "source": "orchestrator-data", "target": "/db"},
                {"type": "bind", "source": str(PROXY), "target": "/probe/proxy.py",
                 "read_only": True},
            ],
            "command": ["python3", "/probe/proxy.py", "serve",
                        "/run/mihakk/proxy.sock", "/run/mihakk/control.sock",
                        "/run/mihakk/admin.sock"],
            "healthcheck": {"test": ["CMD", "python3", "-c",
                                     "import socket; s=socket.socket(socket.AF_UNIX); "
                                     "s.connect('/run/mihakk/admin.sock'); s.close()"],
                            "interval": "2s", "timeout": "2s", "retries": 15},
            "read_only": True,
            "tmpfs": ["/tmp"],
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
        }
        self.compose_file.write_text(json.dumps(config, indent=2))
        os.chmod(self.compose_file, 0o600)
        self.started = True
        self.dc("up", "-d", "--build", "--wait", "--wait-timeout", "120", timeout=240)
        wait_for("orchestrator health", lambda: self.api("/healthz"), seconds=35)
        actual_url = self.dc("exec", "-T", "orchestrator", "python3", "-S", "-c",
                             "import os;print(os.environ.get('MIHAKK_ENGINE_URL',''))").strip()
        if actual_url != "unix:/run/mihakk/proxy.sock":
            raise Failure("setup", f"orchestrator uses unexpected engine URL: {actual_url}")
        cid = self.dc("ps", "-q", "testbed").strip()
        ip = command(["docker", "inspect", "-f",
                      "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", cid]).strip()
        if not re.fullmatch(r"[0-9.]+", ip):
            raise Failure("setup", "testbed address could not be verified")
        self.testbed_ip = ip
        self.make_config()

    def make_config(self) -> None:
        config = {
            "config_version": "1",
            "scope": {"targets": [{"scheme": "http", "host": "testbed", "port": 8000,
                                    "path_prefixes": ["/api"], "methods": ["GET", "POST"],
                                    "allowed_addresses": [f"{self.testbed_ip}/32"]}],
                      "max_redirects": 2},
            "limits": {"requests_per_second": 2, "burst": 1,
                       "max_total_requests": 400, "max_concurrency": 1,
                       "max_session_duration": "3m", "request_timeout": "10s",
                       "max_response_bytes": 1048576},
            "authorization": {"operator": "isolated-8b-test",
                              "statement": "I am authorised to test the targets listed in this scope.",
                              "acked_at": dt.datetime.now(dt.timezone.utc).strftime(
                                  "%Y-%m-%dT%H:%M:%SZ"),
                              "scope_digest": "sha256:" + "0" * 64},
        }
        path = self.dir / "session.json"
        path.write_text(json.dumps(config))
        args = ["docker", "run", "--rm", "--network", "none",
                "-v", f"{self.dir}:/work:ro", "mihakk-engine:dev",
                "scope-check", "-config", "/work/session.json"]
        result = subprocess.run(args, env=ENV, text=True, capture_output=True,
                                timeout=30, check=False)
        if result.returncode not in (0, 1):
            raise Failure("setup", "scope-check could not evaluate the isolated scope")
        result_text = result.stdout + result.stderr
        match = re.search(r"the configured scope is (sha256:[0-9a-f]{64})", result_text)
        if match is None:
            if FUTURE_ACK in result_text.encode():
                print(clock_diagnostic(config["authorization"]["acked_at"]),
                      file=sys.stderr, flush=True)
            raise Failure("setup", "could not obtain scope digest")
        config["authorization"]["scope_digest"] = match.group(1)
        self.session_config = config

    def api(self, path: str, *, body=None):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            self.url + path, data=data,
            headers={"Authorization": f"Bearer {DASHBOARD_TOKEN}",
                     "Content-Type": "application/json"},
            method="POST" if body is not None else "GET")
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.load(response)

    def proxy(self, op: str, session: str) -> dict:
        raw = self.dc("exec", "-T", "fault-proxy", "python3", "/probe/proxy.py",
                      "ctl", "/run/mihakk/admin.sock", op, session, timeout=15)
        body = json.loads(raw)
        if not body.get("ok"):
            raise Failure("setup", f"fault proxy refused {op}: {body.get('error')}")
        return body

    def engine_report(self, session: str) -> dict:
        raw = self.dc("exec", "-T", "fault-proxy", "python3", "/probe/proxy.py",
                      "engine-status", "/run/mihakk/control.sock", session, timeout=15)
        body = json.loads(raw)
        if body.get("http_status") != 200:
            raise Failure("setup", f"engine status returned {body.get('http_status')}")
        return body

    def engine_status(self, session: str) -> str:
        return self.engine_report(session).get("status", "")

    def db(self, session: str) -> dict:
        code = (
            "import json,sqlite3,sys; "
            "c=sqlite3.connect('file:/db/mihakk.db?mode=ro',uri=True); "
            "rows=c.execute('select seq,payload from events where session_id=? order by seq',"
            "(sys.argv[1],)).fetchall(); "
            "print(json.dumps({'seqs':[r[0] for r in rows],"
            "'ids':[json.loads(r[1]).get('session_id') for r in rows]}))"
        )
        raw = self.dc("exec", "-T", "fault-proxy", "python3", "-S", "-c",
                      code, session, timeout=15)
        return json.loads(raw)

    def start(self, suffix: str, seed: str, max_cases: int = 80) -> str:
        session = f"{self.project}-{suffix}"
        body = {"session_id": session, "config": self.session_config,
                "corpus": CORPUS, "seed": seed, "max_cases": max_cases}
        response = self.api(f"/v1/sessions/{session}/start", body=body)
        if response.get("status") != "running":
            raise Failure("setup", f"session {suffix} was not accepted")
        self.sessions.append(session)
        return session

    def guard(self, session: str) -> int:
        observed = {}
        def ready():
            view = self.api(f"/v1/sessions/{session}")
            rows = self.db(session)["seqs"]
            relay = self.proxy("status", session)
            engine = self.engine_status(session)
            observed.update(view=view.get("status"), stored=len(rows),
                            active=relay["active"], requests=relay["requests"], engine=engine)
            if (view.get("status") == "running" and len(rows) >= 3
                    and relay["active"] >= 1 and engine == "running"):
                return len(rows)
            return None
        try:
            return wait_for(f"live stream and stored events for {session}", ready, seconds=30)
        except Failure as exc:
            raise Failure("setup", f"{exc}; observed={observed}") from exc

    def terminal(self, session: str, seconds: float = 110) -> dict:
        def done():
            view = self.api(f"/v1/sessions/{session}")
            return view if view.get("status") != "running" else None
        return wait_for(f"terminal session {session}", done, seconds=seconds)

    def complete(self, session: str) -> tuple[dict, dict, dict]:
        view = self.terminal(session)
        events = self.api(f"/v1/sessions/{session}/events?limit=5000")
        findings = self.api(f"/v1/sessions/{session}/findings")
        rows = self.db(session)
        seqs = rows["seqs"]
        total = view.get("completeness", {}).get("total_seq")
        if not (view.get("status") == "completed" and view["completeness"]["complete"]
                and isinstance(total, int) and total > 3
                and seqs == list(range(1, total + 1))
                and len(seqs) == len(set(seqs))):
            raise Failure("incomplete_stream", f"{session}: status={view.get('status')}, "
                          f"total={total}, stored={len(seqs)}")
        if len(events["events"]) != total or any(x != session for x in rows["ids"]):
            raise Failure("mixed_or_empty_results", f"{session}: wrong or missing event owner")
        if not findings.get("findings"):
            raise Failure("mixed_or_empty_results", f"{session}: no findings")
        return view, events, findings

    def cleanup(self) -> None:
        try:
            if self.started:
                result = self.dc("down", "-v", "--timeout", "10", timeout=90, check=False)
                remaining = labelled(self.project)
                if any(remaining.values()):
                    raise Failure("cleanup", f"test resources remain: {remaining}")
        finally:
            self.work.cleanup()


def after_cut(stack: Stack, session: str) -> int:
    before = stack.engine_report(session)
    if before.get("status") != "running" or not isinstance(before.get("last_seq"), int):
        raise Failure("setup", "engine was not running before the stream cut")
    stack.proxy("cut", session)
    wait_for("held reconnect", lambda: stack.proxy("status", session)["pending"] >= 1)
    rows = stack.db(session)["seqs"]
    def engine_advanced():
        current = stack.engine_report(session)
        return (current if current.get("status") == "running"
                and isinstance(current.get("last_seq"), int)
                and current["last_seq"] > before["last_seq"] else None)
    wait_for("engine progress while the orchestrator stream is held",
             engine_advanced, seconds=8)
    if stack.db(session)["seqs"] != rows:
        raise Failure("stream_not_cut", "SQLite advanced while its stream was held")
    contiguous = 0
    for seq in rows:
        if seq != contiguous + 1:
            break
        contiguous = seq
    if contiguous < 3:
        raise Failure("setup", "too few persisted events at the cut")
    return contiguous


def stream_drop(stack: Stack) -> None:
    session = stack.start("a", "6d6968616b6b2d6661756c742d61")
    stack.guard(session)
    last = after_cut(stack, session)
    requests = stack.proxy("status", session)["requests"]
    if len(requests) < 2 or requests[-1] != last:
        raise Failure("wrong_resume_point", f"requested {requests[-1:]}, stored through {last}")
    stack.proxy("release", session)
    stack.complete(session)
    if stack.proxy("status", session)["cuts"] != 1:
        raise Failure("setup", "the intended stream was not cut exactly once")


def restart(stack: Stack) -> None:
    session = stack.start("a", "6d6968616b6b2d72657374617274")
    stack.guard(session)
    before = stack.proxy("status", session)["requests"]
    stack.dc("stop", "orchestrator", timeout=40)
    rows = stack.db(session)["seqs"]
    last = max(rows)
    if rows != list(range(1, last + 1)) or stack.engine_status(session) != "running":
        raise Failure("setup", "run was not active with contiguous stored events at restart")
    stack.dc("start", "orchestrator", timeout=40)
    wait_for("restarted orchestrator health", lambda: stack.api("/healthz"), seconds=30)
    def resumed():
        requests = stack.proxy("status", session)["requests"]
        return requests if len(requests) > len(before) else None
    try:
        requests = wait_for("restart follower request", resumed, seconds=8)
    except Failure as exc:
        if exc.code == "setup":
            raise Failure("restart_not_followed", "no new stream GET after service restart") from exc
        raise
    if requests[-1] != last:
        raise Failure("wrong_restart_point", f"requested {requests[-1]}, stored through {last}")
    stack.complete(session)


def concurrency(stack: Stack) -> None:
    # The established testbed seed/corpus yields findings at 120 cases. Case
    # IDs include the session ID, so the two result sets are nonempty and
    # distinguishable even though their input seed is intentionally identical.
    seed = "6d6968616b6b2d70686173652d352d35"
    a = stack.start("a", seed, max_cases=120)
    b = stack.start("b", seed, max_cases=120)
    def overlap():
        for session in (a, b):
            view = stack.api(f"/v1/sessions/{session}")
            if (view.get("status") != "running" or not stack.db(session)["seqs"]
                    or stack.engine_status(session) != "running"):
                return None
        return True
    try:
        wait_for("two active, nonempty sessions at once", overlap, seconds=30)
    except Failure as exc:
        # Distinguish a genuine isolation failure from a stack that never
        # started: both engine runs and both stream GETs must exist, while one
        # session's SQLite rows have gone missing.
        streams = [stack.proxy("status", s)["requests"] for s in (a, b)]
        rows = [stack.db(s)["seqs"] for s in (a, b)]
        engines = [stack.engine_status(s) for s in (a, b)]
        if all(streams) and all(s == "running" for s in engines) and any(rows) and not all(rows):
            raise Failure("mixed_or_empty_results",
                          f"both streams exist, but stored event counts are {[len(r) for r in rows]}") from exc
        raise
    _, events_a, findings_a = stack.complete(a)
    _, events_b, findings_b = stack.complete(b)
    ids_a = {item["case_id"] for item in findings_a["findings"]}
    ids_b = {item["case_id"] for item in findings_b["findings"]}
    if not (ids_a and ids_b and ids_a - ids_b and ids_b - ids_a):
        raise Failure("mixed_or_empty_results", "the sessions have no distinctive case results")
    if (any(e.get("session_id") != a for e in events_a["events"])
            or any(e.get("session_id") != b for e in events_b["events"])):
        raise Failure("mixed_or_empty_results", "an event belongs to the other session")


def impossible_resume(stack: Stack) -> None:
    session = stack.start("a", "6d6968616b6b2d6661696c6564")
    stack.guard(session)
    last = after_cut(stack, session)
    stack.proxy("fail", session)
    def exhausted():
        requests = stack.proxy("status", session)["requests"]
        # The configured five attempts include the first connection that was
        # cut; four subsequent GETs receive the injected 503.
        return len(requests) >= 5
    wait_for("exhausted stream retries", exhausted, seconds=15)
    try:
        view = stack.terminal(session, seconds=8)
    except Failure as exc:
        raise Failure("not_terminal", "all retries failed but the session remains running") from exc
    reason = view.get("incomplete_reason") or ""
    if (view.get("status") != "interrupted" or "503" not in reason
            or "attempt" not in reason or view["completeness"]["complete"]
            or not stack.db(session)["seqs"]):
        raise Failure("wrong_failure_reason", f"status={view.get('status')}, reason={reason[:150]}")
    if stack.proxy("status", session)["cuts"] != 1 or last < 3:
        raise Failure("setup", "the failure did not follow a real stream cut")


CASES = [
    ("stream", stream_drop, "from_seq_zero", "wrong_resume_point"),
    ("restart", restart, "no_restart_recovery", "restart_not_followed"),
    ("concurrent", concurrency, "mix_sessions", "mixed_or_empty_results"),
    ("unavailable", impossible_resume, "leave_running", "not_terminal"),
]


def run_case(name: str, scenario, mutation: str, expected: str,
             protected: dict[str, set[str]], guard: DataGuard) -> None:
    stack = Stack(name, mutation)
    failure = None
    cleanup_error = None
    try:
        stack.setup()
        scenario(stack)
    except Failure as exc:
        failure = exc
    finally:
        try:
            stack.cleanup()
            if protected_state() != protected:
                raise Failure("cleanup", "a pre-existing Docker resource changed")
            guard.check()
        except Failure as exc:
            cleanup_error = exc
    if cleanup_error is not None:
        raise cleanup_error
    if expected:
        if failure is None or failure.code != expected:
            raise Failure("sensitivity", f"{name}/{mutation}: expected {expected}, "
                          f"got {failure.code if failure else 'PASS'} "
                          f"({failure if failure else 'no failure'})")
        print(f"PASS {name}: disabling {mutation} fails at {expected} "
              f"({sanitized(str(failure))})", flush=True)
    elif failure is not None:
        raise failure
    else:
        print(f"PASS {name}: live scenario and per-scenario cleanup", flush=True)


def main() -> None:
    def interrupt(_signum, _frame):
        raise KeyboardInterrupt("interrupted")

    signal.signal(signal.SIGTERM, interrupt)
    guard = DataGuard()
    try:
        guard.create()
        protected = protected_state()
        for name, scenario, mutation, expected in CASES:
            if len(sys.argv) > 1 and name not in sys.argv[1:]:
                continue
            run_case(name, scenario, "", "", protected, guard)
            run_case(name, scenario, mutation, expected, protected, guard)
        print("all selected scenarios and negative controls passed; projects cleaned", flush=True)
    finally:
        guard.close()


if __name__ == "__main__":
    try:
        main()
    except Failure as exc:
        print(f"FAIL [{exc.code}] {sanitized(str(exc))}", file=sys.stderr)
        raise SystemExit(1)
