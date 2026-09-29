#!/usr/bin/env python3
"""Prove the local test helpers bypass an injected proxy, but no other URL."""

from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import local_api_transport
import local_testbed_demo
import test_stack_api
import test_live_faults


ROOT = pathlib.Path(__file__).resolve().parent.parent
ACK = "2026-09-29T00:00:00Z"


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        size = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(size))
        self.server.received.append((self.path, body.get("probe")))
        if self.server.role == "proxy":
            code, reply = 500, b"injected proxy 500"
        elif body.get("probe") == "future":
            code, reply = 403, b'{"detail":"acked_at is in the future"}'
        else:
            code, reply = 202, json.dumps({"status": "running", "probe": body["probe"]}).encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, *_args) -> None:
        pass  # Never log request headers, bearer tokens or a proxy URL.


def server(role: str) -> ThreadingHTTPServer:
    instance = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    instance.role = role
    instance.received = []
    threading.Thread(target=instance.serve_forever, daemon=True).start()
    return instance


def default_open(request: urllib.request.Request, *, timeout: int):
    return urllib.request.urlopen(request, timeout=timeout)


def main() -> None:
    backend, proxy = server("backend"), server("proxy")
    url = f"http://127.0.0.1:{backend.server_port}/v1/sessions/demo/start"
    env = {key: value for key, value in os.environ.items()
           if key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}}
    env.update({"http_proxy": f"http://127.0.0.1:{proxy.server_port}",
                "https_proxy": f"http://127.0.0.1:{proxy.server_port}",
                "no_proxy": "", "NO_PROXY": ""})
    try:
        with mock.patch.dict(os.environ, env, clear=True), tempfile.TemporaryDirectory(
                prefix="mihakk-loopback-") as raw:
            work = pathlib.Path(raw)
            # Positive control: the ordinary client really reaches the injected
            # proxy, so a helper pass cannot be vacuous.
            req = urllib.request.Request(url, data=b'{"probe":"control"}', method="POST")
            try:
                urllib.request.urlopen(req, timeout=3)
            except urllib.error.HTTPError as exc:
                check(exc.code == 500 and exc.read() == b"injected proxy 500",
                      "the default client did not receive the proxy's 500")
            else:
                raise AssertionError("the default client unexpectedly bypassed the proxy")
            check(len(proxy.received) == 1 and not backend.received,
                  "the positive control did not traverse only the proxy")
            print("PASS: default urllib reaches the injected 500 proxy")

            with (mock.patch.object(local_testbed_demo, "secrets",
                                    return_value={"MIHAKK_DASHBOARD_TOKEN": "fixture-only"}),
                  mock.patch.object(local_testbed_demo, "port",
                                    return_value=backend.server_port)):
                answer = local_testbed_demo.request("/v1/sessions/demo/start",
                                                     body={"probe": "walkthrough"})
                check(answer == {"status": "running", "probe": "walkthrough"},
                      "the walkthrough helper did not receive the API's 202")
                check(len(proxy.received) == 1 and backend.received[-1] ==
                      ("/v1/sessions/demo/start", "walkthrough"),
                      "the walkthrough helper sent a request to the proxy")

                # Sensitivity: replacing the bypass with default urllib must
                # fail for the injected proxy's 500, not a missing backend.
                with mock.patch.object(local_testbed_demo, "open_loopback",
                                       side_effect=default_open):
                    try:
                        local_testbed_demo.request("/v1/sessions/demo/start",
                                                    body={"probe": "walkthrough-old"})
                    except local_testbed_demo.DemoError as exc:
                        check(str(exc) == "API returned HTTP 500; response omitted",
                              "walkthrough sensitivity failed for the wrong reason")
                    else:
                        raise AssertionError("walkthrough sensitivity did not fail")
                check(len(proxy.received) == 2 and len(backend.received) == 1,
                      "walkthrough sensitivity did not reach only the proxy")
            print("PASS: walkthrough helper bypasses proxy; removing bypass gets 500")

            body_file, out_file = work / "request.json", work / "response.json"
            body_file.write_text('{"probe":"stack"}')
            child = subprocess.run([sys.executable, str(ROOT / "scripts/test_stack_api.py"),
                                    "POST", url, str(out_file), str(body_file)],
                                   env={**env, "MIHAKK_DASHBOARD_TOKEN": "fixture-only"},
                                   capture_output=True, text=True, timeout=10)
            check(child.returncode == 0 and child.stdout.strip() == "202"
                  and json.loads(out_file.read_text()) ==
                  {"status": "running", "probe": "stack"},
                  "the stack helper did not receive the API's 202")
            check(len(proxy.received) == 2 and backend.received[-1] ==
                  ("/v1/sessions/demo/start", "stack"),
                  "the stack helper sent a request to the proxy")

            with (mock.patch.dict(os.environ, {"MIHAKK_DASHBOARD_TOKEN": "fixture-only"}),
                  mock.patch.object(test_stack_api, "open_loopback", side_effect=default_open),
                  mock.patch.object(sys, "argv", ["test_stack_api.py", "POST", url,
                                                 str(out_file), str(body_file)]),
                  contextlib.redirect_stdout(io.StringIO()) as printed):
                test_stack_api.main()
            check(printed.getvalue().strip() == "500"
                  and out_file.read_bytes() == b"injected proxy 500"
                  and len(proxy.received) == 3 and len(backend.received) == 2,
                  "stack sensitivity did not fail on the proxy's 500")
            print("PASS: stack helper bypasses proxy; removing bypass gets 500")

            for remote in ("http://example.invalid:8100/x",
                           "http://127.0.0.1.evil.invalid:8100/x",
                           f"http://user@127.0.0.1:{backend.server_port}/x"):
                try:
                    local_api_transport.open_loopback(urllib.request.Request(remote), timeout=3)
                except ValueError:
                    pass
                else:
                    raise AssertionError("non-local or credentialed URL was accepted")
            check(len(proxy.received) == 3 and len(backend.received) == 2,
                  "URL validation contacted a server")
            print("PASS: non-loopback and credentialed URLs are rejected before network access")

            future = {"probe": "future", "config": {"authorization": {"acked_at": ACK}}}
            with (mock.patch.object(local_api_transport, "clock_diagnostic",
                                    return_value="clock diagnostic: safe fixture"),
                  mock.patch.object(local_testbed_demo, "secrets",
                                    return_value={"MIHAKK_DASHBOARD_TOKEN": "fixture-only"}),
                  mock.patch.object(local_testbed_demo, "port",
                                    return_value=backend.server_port),
                  contextlib.redirect_stderr(io.StringIO()) as errors):
                try:
                    local_testbed_demo.request("/v1/sessions/demo/start", body=future)
                except local_testbed_demo.DemoError as exc:
                    check(str(exc) == "API returned HTTP 403; response omitted",
                          "future acknowledgement was not refused")
                else:
                    raise AssertionError("future acknowledgement was accepted")
            check(errors.getvalue().strip() == "clock diagnostic: safe fixture"
                  and backend.received[-1][1] == "future",
                  "walkthrough future-ack diagnostic was absent or unsafe")

            body_file.write_text(json.dumps(future))
            with (mock.patch.object(local_api_transport, "clock_diagnostic",
                                    return_value="clock diagnostic: safe fixture"),
                  mock.patch.dict(os.environ, {"MIHAKK_DASHBOARD_TOKEN": "fixture-only"}),
                  mock.patch.object(sys, "argv", ["test_stack_api.py", "POST", url,
                                                 str(out_file), str(body_file)]),
                  contextlib.redirect_stdout(io.StringIO()) as printed,
                  contextlib.redirect_stderr(io.StringIO()) as errors):
                test_stack_api.main()
            check(printed.getvalue().strip() == "403"
                  and errors.getvalue().strip() == "clock diagnostic: safe fixture"
                  and len(backend.received) == 4 and len(proxy.received) == 3,
                  "stack future-ack diagnostic was absent, unsafe, or retried")
            print("PASS: both helpers log safe clock diagnostics on 403 without retry")

            prepared = work / "rejected-scope.json"
            refused = subprocess.CompletedProcess(["docker"], 1, "",
                                                  "acked_at is in the future")
            with (mock.patch.object(local_testbed_demo, "testbed_address",
                                    return_value="127.0.0.1"),
                  mock.patch.object(local_testbed_demo.subprocess, "run",
                                    return_value=refused) as scope_check,
                  mock.patch.object(local_testbed_demo, "clock_diagnostic",
                                    return_value="clock diagnostic: safe fixture"),
                  contextlib.redirect_stderr(io.StringIO()) as errors):
                try:
                    local_testbed_demo.prepare(prepared, acknowledged=True)
                except local_testbed_demo.DemoError as exc:
                    check("acked_at is in the future" in str(exc),
                          "scope-check future acknowledgement was not refused")
                else:
                    raise AssertionError("scope-check future acknowledgement was accepted")
            check(scope_check.call_count == 1 and not prepared.exists()
                  and errors.getvalue().strip() == "clock diagnostic: safe fixture",
                  "scope-check did not diagnose safely or retried the refusal")
            print("PASS: scope-check future refusal logs clock data without retry")

            fault_stack = test_live_faults.Stack.__new__(test_live_faults.Stack)
            fault_stack.dir = work
            fault_stack.testbed_ip = "172.20.0.2"
            with (mock.patch.object(test_live_faults.subprocess, "run",
                                    return_value=refused) as scope_check,
                  mock.patch.object(test_live_faults, "clock_diagnostic",
                                    return_value="clock diagnostic: safe fixture"),
                  contextlib.redirect_stderr(io.StringIO()) as errors):
                try:
                    fault_stack.make_config()
                except test_live_faults.Failure as exc:
                    check(exc.code == "setup" and str(exc) == "could not obtain scope digest",
                          "fault-test future acknowledgement was not refused")
                else:
                    raise AssertionError("fault-test future acknowledgement was accepted")
            check(scope_check.call_count == 1
                  and errors.getvalue().strip() == "clock diagnostic: safe fixture",
                  "fault-test scope-check did not diagnose safely or retried")
            print("PASS: live-fault scope-check logs clock data without retry")

            fake = subprocess.CompletedProcess(["docker"], 0, "1790633330\n", "secret-noise")
            with (mock.patch.object(local_api_transport.subprocess, "run", return_value=fake)
                  as docker_call,
                  mock.patch.object(local_api_transport.time, "time",
                                    side_effect=[1790633334.0, 1790633334.2])):
                diagnostic = local_api_transport.clock_diagnostic(ACK)
            check("ack_utc=2026-09-29T00:00:00+00:00" in diagnostic
                  and "container_minus_host_s=-4.1" in diagnostic
                  and "secret-noise" not in diagnostic
                  and docker_call.call_args.args[0][0:5] ==
                  ["docker", "run", "--rm", "--network", "none"],
                  "clock diagnostic omitted time data or exposed Docker output")
            print("PASS: clock diagnostic includes UTC times and offset, not command output")
    finally:
        for instance in (backend, proxy):
            instance.shutdown()
            instance.server_close()


if __name__ == "__main__":
    main()
