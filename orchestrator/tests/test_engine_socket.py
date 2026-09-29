"""The engine over a real Unix socket, and how its address is read.

Every other test here replaces the transport with httpx.MockTransport, which
skips the socket entirely. These do not: a real HTTP server listens on a real
Unix socket, and the orchestrator's own client -- built from Settings the way the
service builds it, not handed a transport -- has to reach it. That is the seam
phase 8a moved the control API onto.
"""

from __future__ import annotations

import asyncio
import json
import os
import socketserver
import tempfile
import threading
from http.server import BaseHTTPRequestHandler

import pytest

from app.config import Settings, engine_endpoint
from app.engine_client import EngineClient

TOKEN = "socket-test-token"


class _Handler(BaseHTTPRequestHandler):
    seen: list[tuple[str, str, str]] = []

    def do_GET(self):  # noqa: N802 -- the http.server naming
        self.seen.append(("GET", self.path, self.headers.get("Authorization", "")))
        if self.path == "/healthz":
            body = {"status": "ok", "engine_version": "socket-test"}
        elif self.path.startswith("/v1/runs/") and \
                self.headers.get("Authorization") == f"Bearer {TOKEN}":
            body = {"session_id": self.path.rsplit("/", 1)[-1], "status": "running"}
        else:
            self.send_response(401)
            self.end_headers()
            return
        raw = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


class _UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def get_request(self):
        # BaseHTTPRequestHandler expects a (host, port) client address.
        request, _ = super().get_request()
        return request, ("unix", 0)


@pytest.fixture
def socket_server():
    # Short: socket paths are limited to ~104 bytes.
    directory = tempfile.mkdtemp(prefix="mks", dir="/tmp")
    path = os.path.join(directory, "control.sock")
    _Handler.seen = []
    server = _UnixHTTPServer(path, _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield path
    server.shutdown()
    server.server_close()
    os.unlink(path)
    os.rmdir(directory)


def _settings(url: str) -> Settings:
    return Settings(database_path=":memory:", engine_base_url=url, engine_token=TOKEN,
                    reconnect_delay_seconds=0.0, reconnect_attempts=1)


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_the_client_reaches_the_engine_over_a_real_socket(socket_server):
    client = EngineClient(_settings(f"unix:{socket_server}"))

    async def go():
        try:
            health = await client.health()
            status = await client.run_status("abc")
            return health, status
        finally:
            await client.aclose()

    health, status = _run(go())
    assert health["engine_version"] == "socket-test"
    assert status["status"] == "running"
    # The token still travels: the socket is a second layer, not a replacement.
    assert ("GET", "/v1/runs/abc", f"Bearer {TOKEN}") in _Handler.seen


@pytest.mark.parametrize("url, socket_path", [
    ("unix:/run/mihakk/control.sock", "/run/mihakk/control.sock"),
    ("http://engine:8900", None),
    ("http://127.0.0.1:8900", None),
])
def test_well_formed_engine_addresses(url, socket_path):
    assert engine_endpoint(url).socket_path == socket_path


@pytest.mark.parametrize("url", [
    "",
    "unix:relative/control.sock",
    "unix://run/mihakk/control.sock",      # would read "run" as a host
    "unix:/run/mihakk/../etc/control.sock",
    "unix:/run/mihakk/./control.sock",
    "unix:/run/mihakk/control.sock?x=1",
    "unix:/run/mi hakk/control.sock",
    "unix:/run/mihakk/control.sock\n",
    "engine:8900",
    "ftp://engine:8900",
    "file:///run/mihakk/control.sock",
])
def test_malformed_engine_addresses_are_refused(url):
    with pytest.raises(ValueError):
        engine_endpoint(url)


def test_a_malformed_address_stops_the_client_being_built():
    """Refused at construction, not discovered at the first request."""
    with pytest.raises(ValueError):
        EngineClient(_settings("unix:control.sock"))
