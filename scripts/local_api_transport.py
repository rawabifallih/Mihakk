"""Loopback-only API transport and safe clock diagnostics for local tests."""

from __future__ import annotations

import datetime as dt
import json
import subprocess
import time
import urllib.parse
import urllib.request


FUTURE_ACK = b"acked_at is in the future"


def open_loopback(request: urllib.request.Request, *, timeout: int):
    """Bypass ambient proxies only after checking the complete API URL."""
    url = urllib.parse.urlsplit(request.full_url)
    if (url.scheme != "http" or url.hostname != "127.0.0.1"
            or url.username is not None or url.password is not None
            or url.fragment or not url.path.startswith("/")):
        raise ValueError("the test API destination must be local loopback")
    try:
        port = url.port
    except ValueError as exc:
        raise ValueError("the test API port is invalid") from exc
    if port is None or not 1024 <= port <= 65535:
        raise ValueError("the test API port is invalid")
    return urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
        request, timeout=timeout)


def clock_diagnostic(acked_at: str, *, container: str | None = None) -> str:
    """Return UTC times and Docker/host offset, never command output or secrets."""
    try:
        ack = dt.datetime.fromisoformat(acked_at.replace("Z", "+00:00"))
        if ack.tzinfo is None:
            raise ValueError("timezone missing")
        ack_text = ack.astimezone(dt.timezone.utc).isoformat()
    except (TypeError, ValueError, AttributeError):
        ack_text = "unavailable"

    command = (["docker", "exec", container, "date", "-u", "+%s"] if container else
               ["docker", "run", "--rm", "--network", "none", "--entrypoint", "date",
                "mihakk-engine:dev", "-u", "+%s"])
    before = time.time()
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        result = None
    after = time.time()
    host = (before + after) / 2
    host_text = dt.datetime.fromtimestamp(host, dt.timezone.utc).isoformat()
    if result is None or result.returncode:
        return (f"clock diagnostic: ack_utc={ack_text}; host_utc={host_text}; "
                "container_utc=unavailable; container_minus_host_s=unavailable")
    try:
        container_epoch = int(result.stdout.strip())
        container_text = dt.datetime.fromtimestamp(container_epoch, dt.timezone.utc).isoformat()
    except (ValueError, OverflowError):
        return (f"clock diagnostic: ack_utc={ack_text}; host_utc={host_text}; "
                "container_utc=unavailable; container_minus_host_s=unavailable")
    return (f"clock diagnostic: ack_utc={ack_text}; host_utc={host_text}; "
            f"container_utc={container_text}; "
            f"container_minus_host_s={container_epoch - host:+.1f}; "
            f"sample_span_s={after - before:.1f}")


def diagnostic_for_refusal(response: bytes, request_body: bytes,
                           *, container: str | None = None) -> str | None:
    """Inspect a refusal privately; emit only fixed-format clock information."""
    if FUTURE_ACK not in response:
        return None
    try:
        acked_at = json.loads(request_body)["config"]["authorization"]["acked_at"]
    except (ValueError, KeyError, TypeError):
        acked_at = ""
    return clock_diagnostic(acked_at, container=container)
