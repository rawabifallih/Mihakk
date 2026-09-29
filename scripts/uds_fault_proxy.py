"""Test-only Unix-socket relay that can cut one orchestrator NDJSON stream.

It is mounted into a throwaway Compose project, never into the deployed stack.
Only the request path and ``from_seq`` are retained in memory. Request headers,
bearer tokens, and response bodies are forwarded but never logged or reported.
"""

from __future__ import annotations

import asyncio
import http.client
import json
import os
import re
import socket
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

RE = re.compile(r"^/v1/runs/([A-Za-z0-9._-]+)/events$")
LIMIT = 65536


class Stream:
    def __init__(self) -> None:
        self.requests: list[int] = []
        self.active: set[tuple[asyncio.StreamWriter, asyncio.StreamWriter]] = set()
        self.pending = 0
        self.mode = "pass"
        self.gate = asyncio.Event()
        self.gate.set()
        self.cuts = 0

    def public(self) -> dict:
        return {"requests": self.requests, "active": len(self.active),
                "pending": self.pending, "mode": self.mode, "cuts": self.cuts}


class Relay:
    def __init__(self, socket_path: str, upstream_path: str, admin_path: str):
        self.socket_path = socket_path
        self.upstream_path = upstream_path
        self.admin_path = admin_path
        self.streams: dict[str, Stream] = {}

    def stream(self, session: str) -> Stream:
        return self.streams.setdefault(session, Stream())

    async def admin(self, reader: asyncio.StreamReader,
                    writer: asyncio.StreamWriter) -> None:
        try:
            raw = await asyncio.wait_for(reader.readline(), timeout=5)
            if len(raw) > 4096:
                raise ValueError("control message too long")
            request = json.loads(raw)
            session = request.get("session", "")
            if not isinstance(session, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", session):
                raise ValueError("invalid session id")
            state = self.stream(session)
            op = request.get("op")
            if op == "cut":
                if not state.active:
                    raise ValueError("no active stream to cut")
                state.mode = "gate"
                state.gate.clear()
                state.cuts += 1
                for client, upstream in tuple(state.active):
                    client.close()
                    upstream.close()
            elif op == "release":
                state.mode = "pass"
                state.gate.set()
            elif op == "fail":
                state.mode = "fail"
                state.gate.set()
            elif op != "status":
                raise ValueError("unknown control operation")
            answer = {"ok": True, **state.public()}
        except (ValueError, json.JSONDecodeError, asyncio.TimeoutError) as exc:
            answer = {"ok": False, "error": str(exc)}
        writer.write(json.dumps(answer).encode() + b"\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def pipe(self, source: asyncio.StreamReader,
                   destination: asyncio.StreamWriter) -> None:
        try:
            while data := await source.read(16384):
                destination.write(data)
                await destination.drain()
        except (BrokenPipeError, ConnectionError, OSError):
            pass

    async def connection(self, reader: asyncio.StreamReader,
                         writer: asyncio.StreamWriter) -> None:
        upstream = None
        state = None
        pair = None
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
            if len(head) > LIMIT:
                raise ValueError("request headers too long")
            # Read only the request line. Headers are intentionally neither
            # decoded nor retained after forwarding.
            line = head.split(b"\r\n", 1)[0].decode("ascii")
            method, target, _version = line.split(" ", 2)
            parsed = urlsplit(target)
            # The orchestrator pools HTTP/1.1 connections. Give every request
            # its own upstream connection so a later /events request is visible
            # to this relay as a distinct stream that can be cut deliberately.
            lines = head[:-4].split(b"\r\n")
            lines = [lines[0]] + [part for part in lines[1:]
                                  if not part.lower().startswith(b"connection:")]
            head = b"\r\n".join(lines) + b"\r\nConnection: close\r\n\r\n"
            match = RE.fullmatch(parsed.path) if method == "GET" else None
            if match:
                state = self.stream(match.group(1))
                raw_seq = parse_qs(parsed.query).get("from_seq", ["0"])[0]
                seq = int(raw_seq)
                if seq < 0:
                    raise ValueError("negative from_seq")
                state.requests.append(seq)
                if state.mode == "gate":
                    state.pending += 1
                    try:
                        await state.gate.wait()
                    finally:
                        state.pending -= 1
                if state.mode == "fail":
                    body = b'{"detail":"injected stream outage"}'
                    writer.write(b"HTTP/1.1 503 Service Unavailable\r\n"
                                 b"Content-Type: application/json\r\n"
                                 + f"Content-Length: {len(body)}\r\n".encode()
                                 + b"Connection: close\r\n\r\n" + body)
                    await writer.drain()
                    return

            upstream_reader, upstream = await asyncio.open_unix_connection(self.upstream_path)
            upstream.write(head)
            await upstream.drain()
            if state is not None:
                pair = (writer, upstream)
                state.active.add(pair)
            tasks = [asyncio.create_task(self.pipe(reader, upstream)),
                     asyncio.create_task(self.pipe(upstream_reader, writer))]
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError,
                asyncio.TimeoutError, ValueError, OSError, ConnectionError):
            pass
        finally:
            if state is not None and pair is not None:
                state.active.discard(pair)
            writer.close()
            if upstream is not None:
                upstream.close()

    async def serve(self) -> None:
        for path in (self.socket_path, self.admin_path):
            Path(path).unlink(missing_ok=True)
        server = await asyncio.start_unix_server(self.connection, self.socket_path)
        admin = await asyncio.start_unix_server(self.admin, self.admin_path)
        os.chmod(self.socket_path, 0o660)
        os.chmod(self.admin_path, 0o660)
        async with server, admin:
            await asyncio.gather(server.serve_forever(), admin.serve_forever())


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str):
        super().__init__("engine", timeout=5)
        self.path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def control(path: str, op: str, session: str) -> None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(path)
        client.sendall(json.dumps({"op": op, "session": session}).encode() + b"\n")
        chunks = bytearray()
        while not chunks.endswith(b"\n"):
            part = client.recv(4096)
            if not part:
                raise RuntimeError("admin socket closed without a verdict")
            chunks.extend(part)
        print(chunks.decode().strip())


def engine_status(path: str, session: str) -> None:
    client = UnixConnection(path)
    try:
        client.request("GET", f"/v1/runs/{session}", headers={
            "Authorization": f"Bearer {os.environ['MIHAKK_CONTROL_TOKEN']}"})
        response = client.getresponse()
        body = json.loads(response.read())
        print(json.dumps({"http_status": response.status,
                          "status": body.get("status"),
                          "last_seq": body.get("last_seq")}, separators=(",", ":")))
    finally:
        client.close()


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "serve":
        asyncio.run(Relay(sys.argv[2], sys.argv[3], sys.argv[4]).serve())
    elif len(sys.argv) == 5 and sys.argv[1] == "ctl":
        control(sys.argv[2], sys.argv[3], sys.argv[4])
    elif len(sys.argv) == 4 and sys.argv[1] == "engine-status":
        engine_status(sys.argv[2], sys.argv[3])
    else:
        raise SystemExit("usage: proxy.py serve SOCK UPSTREAM ADMIN | "
                         "ctl ADMIN OP SESSION | engine-status UPSTREAM SESSION")
