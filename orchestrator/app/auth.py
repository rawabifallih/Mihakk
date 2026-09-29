"""Authentication for the dashboard and the API it reads.

Until this existed the orchestrator had no authentication at all: it was
protected only by being published on loopback. That was defensible while every
caller was a script or `curl`. The dashboard changes the caller into a browser
that carries other sites' sessions, and every endpoint it can reach is an
endpoint that starts fuzzing runs -- so cross-site requests and DNS rebinding
become real surfaces rather than theoretical ones.

Two credentials, and they are never the same one:

  - the dashboard token authenticates a person. It is exchanged for a session.
  - the control API token reaches the engine. It never leaves this process --
    not into a page, not into a script file, not into a response body.

What each control actually buys, stated honestly because the plan first got this
wrong:

  HttpOnly stops JavaScript READING the cookie's value. It does not stop an
  injected script from making authenticated requests: the browser attaches the
  cookie to same-origin requests by itself. So if XSS happens, the CSRF token is
  readable from page memory and the session is usable -- every control in this
  module is bypassed. Preventing XSS is the load-bearing defence; this module is
  layers on top of it, and worth having for what it does cover: a stolen cookie
  cannot be exfiltrated by script, a cross-site request cannot forge one, and a
  rebound DNS name cannot reach the API.

Sessions live in the database rather than in a signed token, so revoking one is
a delete and not a wait. Because the database persists, a service restart does
not by itself revoke existing sessions; expiry, logout or explicit deletion does.
"""

from __future__ import annotations

import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Optional

# Cookie and header names. The CSRF header is deliberately custom: a custom
# header cannot be set on a cross-origin request without a preflight, so it is a
# barrier in itself, and the token compared server-side is the second one.
SESSION_COOKIE = "mihakk_session"
PRELOGIN_COOKIE = "mihakk_prelogin"
CSRF_HEADER = "x-mihakk-csrf"
CSRF_FIELD = "csrf_token"

# Bytes of entropy for every generated identifier.
TOKEN_BYTES = 32

SCHEMA = """
CREATE TABLE IF NOT EXISTS dashboard_sessions (
    session_key   TEXT PRIMARY KEY,
    csrf_token    TEXT NOT NULL,
    created_at    REAL NOT NULL,
    last_seen_at  REAL NOT NULL,
    rotated_at    REAL NOT NULL
);

-- Failed logins, per address, for rate limiting. Rows are pruned as they age
-- out of the window rather than kept.
CREATE TABLE IF NOT EXISTS login_failures (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    address    TEXT NOT NULL,
    at         REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS login_failures_by_address ON login_failures(address, at);
"""


@dataclass
class Session:
    """A live dashboard session."""

    key: str
    csrf_token: str
    created_at: float
    last_seen_at: float
    rotated_at: float


class LockedOut(Exception):
    """Too many failed logins from this address."""


def new_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def tokens_equal(presented: str, expected: str) -> bool:
    """Constant-time comparison, so a wrong token does not leak by timing."""
    return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))


class SessionStore:
    """Dashboard sessions, held in the orchestrator's database."""

    def __init__(self, database, settings, now=time.time) -> None:
        self._db = database
        self._settings = settings
        self._now = now
        with self._db.transaction() as conn:
            conn.executescript(SCHEMA)

    # --- logging in ---------------------------------------------------------

    def locked_out(self, address: str) -> bool:
        """Whether this address has spent its attempts."""
        cutoff = self._now() - self._settings.login_window_seconds
        with self._db.transaction() as conn:
            conn.execute("DELETE FROM login_failures WHERE at < ?",
                         (self._now() - max(self._settings.login_window_seconds,
                                            self._settings.login_lockout_seconds),))
            row = conn.execute(
                "SELECT COUNT(*) AS n, MAX(at) AS latest FROM login_failures "
                "WHERE address = ? AND at >= ?", (address, cutoff)).fetchone()
        if row is None or row["n"] < self._settings.login_max_failures:
            return False
        # Spent: locked until the lockout elapses after the last attempt.
        return (self._now() - (row["latest"] or 0)) < self._settings.login_lockout_seconds

    def record_failure(self, address: str) -> None:
        with self._db.transaction() as conn:
            conn.execute("INSERT INTO login_failures (address, at) VALUES (?, ?)",
                         (address, self._now()))

    def clear_failures(self, address: str) -> None:
        with self._db.transaction() as conn:
            conn.execute("DELETE FROM login_failures WHERE address = ?", (address,))

    def create(self) -> Session:
        """Issue a session. Called only after the token has been verified."""
        now = self._now()
        session = Session(key=new_token(), csrf_token=new_token(),
                          created_at=now, last_seen_at=now, rotated_at=now)
        with self._db.transaction() as conn:
            conn.execute(
                "INSERT INTO dashboard_sessions "
                "(session_key, csrf_token, created_at, last_seen_at, rotated_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (session.key, session.csrf_token, now, now, now))
        return session

    # --- using one ---------------------------------------------------------

    def get(self, key: Optional[str]) -> Optional[Session]:
        """Return a live session, or None. Expired rows are deleted, not ignored."""
        if not key:
            return None
        with self._db.transaction() as conn:
            row = conn.execute(
                "SELECT session_key, csrf_token, created_at, last_seen_at, rotated_at "
                "FROM dashboard_sessions WHERE session_key = ?", (key,)).fetchone()
            if row is None:
                return None

            now = self._now()
            age = now - row["created_at"]
            idle = now - row["last_seen_at"]
            if (age > self._settings.session_absolute_seconds
                    or idle > self._settings.session_idle_seconds):
                conn.execute("DELETE FROM dashboard_sessions WHERE session_key = ?", (key,))
                return None

            conn.execute("UPDATE dashboard_sessions SET last_seen_at = ? "
                         "WHERE session_key = ?", (now, key))
            return Session(key=row["session_key"], csrf_token=row["csrf_token"],
                           created_at=row["created_at"], last_seen_at=now,
                           rotated_at=row["rotated_at"])

    def due_for_rotation(self, session: Session) -> bool:
        return (self._now() - session.rotated_at) >= self._settings.session_rotate_seconds

    def rotate(self, session: Session) -> Session:
        """Replace a session's key, keeping its age. The old key stops working.

        Rotation on login prevents a fixed id being planted beforehand; periodic
        rotation shortens how long a leaked id is worth anything.
        """
        now = self._now()
        fresh = Session(key=new_token(), csrf_token=new_token(),
                        created_at=session.created_at, last_seen_at=now, rotated_at=now)
        with self._db.transaction() as conn:
            conn.execute("DELETE FROM dashboard_sessions WHERE session_key = ?",
                         (session.key,))
            conn.execute(
                "INSERT INTO dashboard_sessions "
                "(session_key, csrf_token, created_at, last_seen_at, rotated_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (fresh.key, fresh.csrf_token, fresh.created_at, now, now))
        return fresh

    def destroy(self, key: Optional[str]) -> None:
        if not key:
            return
        with self._db.transaction() as conn:
            conn.execute("DELETE FROM dashboard_sessions WHERE session_key = ?", (key,))

    def count(self) -> int:
        with self._db.transaction() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM dashboard_sessions").fetchone()
        return int(row["n"]) if row else 0


def host_allowed(host_header: Optional[str], allowed: tuple[str, ...]) -> bool:
    """Whether a request's Host is one this service answers to.

    The check that blunts DNS rebinding: a name an attacker controls can be made
    to resolve to 127.0.0.1, which makes their page same-origin with this service
    as far as the browser is concerned. The Host header is what still says which
    name was asked for.

    An empty allowlist refuses everything. It used to accept everything, which is
    the wrong way round for a security check: a configuration mistake that emptied
    the list would have silently removed the defence rather than stopping the
    service, and nothing would have said so.
    """
    if not allowed:
        return False
    if not host_header:
        return False
    return host_header.strip().lower() in {a.lower() for a in allowed}


def origin_allowed(origin: Optional[str], scheme: Optional[str],
                   host_header: Optional[str]) -> bool:
    """Whether a cookie-authenticated state change came from this very origin.

    Only the cookie branch calls this, so a missing Origin is REFUSED. The earlier
    version accepted one, reasoning that non-browser clients send no Origin -- but
    those clients authenticate with a bearer header and never reach here, so the
    exemption applied to nobody it was written for and to every cross-site request
    it was meant to stop.
    """
    if origin is None or origin == "" or origin == "null":
        return False
    if not scheme or not host_header:
        return False
    return origin.strip() == f"{scheme}://{host_header.strip()}"
