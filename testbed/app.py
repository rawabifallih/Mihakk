# Copyright (c) 2026 Rawabi Alharbi. SPDX-License-Identifier: MIT.

"""Mihakk local testbed: a deliberately imperfect web app for exercising the engine.

This app exists to be fuzzed. It has two planted behaviours that a detector
should find, and stable endpoints that it should leave alone. It is not a
demonstration of good practice, and several things here are wrong on purpose;
those spots are marked PLANTED.

Isolation is a property of how it is deployed, not of this file: it runs on a
Docker network declared `internal: true`, with no port published to the host.
See scripts/verify-testbed-isolation.sh, which checks that for real.

Standard library only, so the image needs no package installs and the
container needs no network access at any point.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# The slow path waits exactly this long, whatever the request says.
#
# The delay is a fixed constant and never a function of the input: no
# proportionality to a value's length, no repetition count, nothing a fuzzer
# could scale up. A mutation can trigger the slow path but cannot make it
# slower, so the worst case stays bounded no matter what is sent.
SLOW_PATH_DELAY_SECONDS = float(os.environ.get("MIHAKK_TESTBED_SLOW_DELAY", "0.4"))

# Bounds on the stable listing endpoint, so no input can inflate the response.
MAX_LIMIT = 50
DEFAULT_LIMIT = 20

# A fixed catalogue. Prices start at 100 so every one is three digits wide:
# with variable-width prices, page 1 and page 6 returned bodies differing by
# twenty bytes, which is exactly the kind of drift that makes a "stable"
# baseline useless for judging size anomalies.
CATALOGUE = [{"sku": f"A-{i:03d}", "name": f"item-{i:03d}", "price": 100 + i} for i in range(120)]

PORT = int(os.environ.get("MIHAKK_TESTBED_PORT", "8000"))
HOST = os.environ.get("MIHAKK_TESTBED_HOST", "0.0.0.0")


class BadRequest(Exception):
    """A client error the app handles deliberately, answered with 400."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def coerce_int(raw, default: int, minimum: int, maximum: int) -> int:
    """Best-effort integer coercion that never raises.

    The stable endpoints use this so that no query mutation can knock them
    over: they are the baseline, and a baseline that flaps is worthless.
    """
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, value))


# --- Handlers ---------------------------------------------------------------


def handle_health(_query, _body):
    """Stable. Constant response, constant work."""
    return 200, {"status": "ok", "service": "mihakk-testbed"}


def handle_items(query, _body):
    """Stable comparison path.

    Every parameter is coerced defensively, so any mutation of page, limit or
    q still returns 200 quickly. If a fuzzing run reports a 5xx, a timeout or
    a latency anomaly here, it is a false positive.

    The page offset is clamped into range rather than allowed to run off the
    end. A real API returning an empty final page is perfectly correct, but it
    makes the response size swing by a factor of fifty depending on the page
    number, and that swing would show up as size-anomaly noise in exactly the
    endpoint meant to be the quiet control. Clamping keeps the body size a
    function of `limit` alone; `page` and `q` do not affect it at all.
    """
    page = coerce_int(query.get("page", ["1"])[0], default=1, minimum=1, maximum=10_000)
    limit = coerce_int(query.get("limit", [str(DEFAULT_LIMIT)])[0],
                       default=DEFAULT_LIMIT, minimum=1, maximum=MAX_LIMIT)

    # Clamp the window so a page always comes back full.
    last_start = max(0, len(CATALOGUE) - limit)
    start = min((page - 1) * limit, last_start)
    items = CATALOGUE[start:start + limit]
    return 200, {"page": page, "limit": limit, "count": len(items), "items": items}


def handle_create_order(_query, body):
    """PLANTED BEHAVIOUR 1: a 5xx on a specific class of input.

    The bug is narrow and realistic: the quantity is parsed with int(), and
    only ValueError is handled. A value of the wrong *type* -- JSON null, a
    list, an object -- raises TypeError instead, which nobody catches here, so
    it reaches the top-level guard and becomes a 500.

    What this means in practice:
      {"qty": 2}      -> 200   valid
      {"qty": "2"}    -> 200   numeric string, parses fine
      {"qty": "abc"}  -> 400   ValueError, handled properly
      {"qty": null}   -> 500   TypeError, PLANTED
      {"qty": []}     -> 500   TypeError, PLANTED

    The 400 case matters as much as the 500: an app that answers badly-typed
    input correctly, next to one that falls over, is what separates a real
    indicator from ordinary input validation.

    The exception is raised, never a crash: the process stays up and the next
    request is served normally, so this is repeatable as often as a fuzzer
    likes without restarting the container.
    """
    if not isinstance(body, dict):
        raise BadRequest("body must be a JSON object")

    qty = body.get("qty", 1)
    try:
        qty = int(qty)
    except ValueError:
        # Handled deliberately: a non-numeric *string* is a client mistake.
        raise BadRequest("qty must be a number")
    # PLANTED: TypeError is not caught, and escapes to the top-level guard.

    sku = body.get("sku", "A-000")
    return 201, {"order": {"sku": sku, "qty": qty}, "status": "created"}


def handle_search(query, body):
    """PLANTED BEHAVIOUR 2: a bounded slow path on a different input.

    A search term that cannot use the index forces a full scan: one containing
    a wildcard anywhere, or one that is empty and therefore filters nothing.
    The fallback costs a fixed SLOW_PATH_DELAY_SECONDS -- always the same,
    regardless of how long or strange the term is.

    That constant is the point. A delay that grew with the input would turn a
    fuzzer into a denial-of-service tool against the very app it is meant to
    help; a fixed one is detectable as a latency anomaly while staying
    harmless however hard it is hit.

    The trigger deliberately covers a wildcard anywhere rather than only a
    leading one. With a leading-only condition, a full mutation run over the
    sample corpus produced zero requests that reached this path: a planted
    behaviour the engine cannot reach is no use for testing detection.
    """
    term = ""
    if isinstance(body, dict) and "term" in body:
        term = str(body.get("term") or "")
    elif "term" in query:
        term = query["term"][0]

    slow = ("%" in term) or ("*" in term) or (term.strip() == "")
    if slow:
        time.sleep(SLOW_PATH_DELAY_SECONDS)

    needle = term.replace("%", "").replace("*", "").strip().lower()
    matches = [item for item in CATALOGUE[:10] if needle and needle in item["name"]]
    return 200, {"term": term, "scan": "full" if slow else "index", "matches": len(matches)}


ROUTES = {
    ("GET", "/api/health"): handle_health,
    ("GET", "/api/items"): handle_items,
    ("POST", "/api/orders"): handle_create_order,
    ("GET", "/api/search"): handle_search,
    ("POST", "/api/search"): handle_search,
}

# Bodies larger than this are refused, so the testbed cannot be made to buffer
# an unbounded amount of memory.
MAX_REQUEST_BODY = 1 << 20


class Handler(BaseHTTPRequestHandler):
    server_version = "mihakk-testbed/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def _read_body(self):
        length = self.headers.get("Content-Length")
        if not length:
            return None
        try:
            size = int(length)
        except ValueError:
            raise BadRequest("invalid Content-Length")
        if size <= 0:
            return None
        if size > MAX_REQUEST_BODY:
            raise BadRequest("request body too large")

        raw = self.rfile.read(size)
        content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()

        if content_type == "application/x-www-form-urlencoded":
            parsed = urllib.parse.parse_qs(raw.decode("utf-8", "replace"))
            return {k: v[0] for k, v in parsed.items()}
        if content_type == "application/json" or not content_type:
            try:
                return json.loads(raw.decode("utf-8", "replace"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Malformed JSON is a client error, answered cleanly. Only the
                # planted bug produces a 5xx.
                raise BadRequest("body is not valid JSON")
        return {"_raw": raw.decode("utf-8", "replace")}

    def _dispatch(self, method: str) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        try:
            body = self._read_body()

            route = ROUTES.get((method, path))
            if route is None:
                if any(p == path for (_m, p) in ROUTES):
                    self._respond(405, {"error": "method_not_allowed", "path": path})
                else:
                    self._respond(404, {"error": "not_found", "path": path})
                return

            status, payload = route(query, body)
            self._respond(status, payload)

        except BadRequest as exc:
            self._respond(400, {"error": "bad_request", "detail": exc.message})

        except Exception as exc:  # noqa: BLE001
            # Top-level guard. A real framework does this too: an unhandled
            # exception in a handler becomes a 500 and the worker survives.
            #
            # PLANTED: the exception type and message are echoed in the
            # response so that a detector has a stable error signature to
            # cluster on. A production app should not leak this.
            self.log_message("unhandled %s: %s", type(exc).__name__, exc)
            self._respond(500, {
                "error": "internal_error",
                "type": type(exc).__name__,
                "detail": str(exc)[:200],
            })

    def _respond(self, status: int, payload) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve(host: str = HOST, port: int = PORT) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    return httpd


def main() -> None:
    httpd = serve()
    sys.stderr.write(
        f"mihakk-testbed listening on {HOST}:{PORT} "
        f"(slow path {SLOW_PATH_DELAY_SECONDS}s, fixed)\n"
    )
    sys.stderr.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()


if __name__ == "__main__":
    threading.current_thread().name = "main"
    main()
