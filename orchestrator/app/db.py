"""SQLite storage for sessions, events and findings.

Two properties matter more than the schema itself.

Storing an event is idempotent. The orchestrator reconnects to a dropped
stream by asking for everything after the last sequence number it has, and an
engine is free to resend from slightly earlier; a duplicate must be a no-op,
not a second row or an error.

Completeness is computed from what is actually stored, never assumed. A
session is complete only when the events it holds run contiguously from 1 to
the total the engine reported. Anything else -- a gap, a short stream, a
missing total -- leaves it incomplete, and the reason is recorded so a reader
knows what is missing rather than only that something is.

The interface is deliberately narrow so SQLite can be replaced later without
the rest of the service noticing.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id        TEXT PRIMARY KEY,
    status            TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    started_at        TEXT,
    ended_at          TEXT,
    engine_version    TEXT,
    scope_digest      TEXT,
    corpus_digest     TEXT,
    config_digest     TEXT,
    planned_cases     INTEGER NOT NULL DEFAULT 0,
    -- Completeness, recomputed from the stored events on every change.
    complete          INTEGER NOT NULL DEFAULT 0,
    events_received   INTEGER NOT NULL DEFAULT 0,
    events_dropped    INTEGER NOT NULL DEFAULT 0,
    last_seq          INTEGER NOT NULL DEFAULT 0,
    total_seq         INTEGER,
    incomplete_reason TEXT,
    -- What the engine itself said when the run ended, and why. A complete
    -- stream says the orchestrator received everything; it says nothing about
    -- whether the engine managed to persist what it found.
    engine_status            TEXT,
    engine_incomplete_reason TEXT
);

-- (session_id, seq) is the primary key, which is what makes storing an event
-- twice harmless: the second insert is ignored rather than duplicating a row.
CREATE TABLE IF NOT EXISTS events (
    session_id TEXT NOT NULL,
    seq        INTEGER NOT NULL,
    type       TEXT NOT NULL,
    at         TEXT,
    payload    TEXT NOT NULL,
    PRIMARY KEY (session_id, seq)
);

CREATE INDEX IF NOT EXISTS events_by_session ON events(session_id, seq);

CREATE TABLE IF NOT EXISTS findings (
    case_id    TEXT NOT NULL,
    session_id TEXT NOT NULL,
    seq        INTEGER,
    payload    TEXT NOT NULL,
    PRIMARY KEY (session_id, case_id)
);

-- Out-of-band notices carry no sequence number, so they cannot live in the
-- events table without breaking its primary key. They are kept separately and
-- counted towards a session's losses.
CREATE TABLE IF NOT EXISTS gap_notices (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id     TEXT NOT NULL,
    at             TEXT,
    events_dropped INTEGER NOT NULL DEFAULT 0,
    message        TEXT
);
"""

# Session statuses. `completed` is reserved for a session whose stored events
# are provably everything the engine produced.
CREATED = "created"
RUNNING = "running"
COMPLETED = "completed"
INCOMPLETE = "incomplete"
INTERRUPTED = "interrupted"
STOPPED = "stopped"
FAILED = "failed"


@dataclass
class Completeness:
    """Whether the stored events are everything the run produced."""

    complete: bool
    events_received: int
    events_dropped: int
    last_seq: int
    total_seq: Optional[int]
    reason: Optional[str] = None
    missing_seqs: list[int] = field(default_factory=list)


class Database:
    """A thin SQLite wrapper. Safe for concurrent use from one process."""

    def __init__(self, path: str) -> None:
        self._path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._migrate()
            self._conn.commit()

    def _migrate(self) -> None:
        """Add columns a database created by an earlier version lacks.

        CREATE TABLE IF NOT EXISTS leaves an existing table alone, so a new
        column has to be added explicitly or every read of it fails.
        """
        existing = {row["name"] for row in
                    self._conn.execute("PRAGMA table_info(sessions)").fetchall()}
        for column in ("engine_status", "engine_incomplete_reason"):
            if column not in existing:
                self._conn.execute(f"ALTER TABLE sessions ADD COLUMN {column} TEXT")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    # A public name for the same transaction scope. The auth module keeps its own
    # tables in this database, and reaching into a private helper from another
    # module would make that coupling invisible.
    transaction = _tx

    # --- sessions ---------------------------------------------------------

    def create_session(self, session_id: str, created_at: str, **fields: Any) -> None:
        columns = ["session_id", "status", "created_at"] + list(fields)
        values = [session_id, CREATED, created_at] + list(fields.values())
        placeholders = ", ".join("?" for _ in columns)
        with self._tx() as conn:
            conn.execute(
                f"INSERT INTO sessions ({', '.join(columns)}) VALUES ({placeholders})",
                values,
            )

    def update_session(self, session_id: str, **fields: Any) -> None:
        if not fields:
            return
        assignments = ", ".join(f"{name} = ?" for name in fields)
        with self._tx() as conn:
            conn.execute(
                f"UPDATE sessions SET {assignments} WHERE session_id = ?",
                list(fields.values()) + [session_id],
            )

    def get_session(self, session_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_sessions(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM sessions ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    # --- events -----------------------------------------------------------

    def append_event(self, session_id: str, event: dict[str, Any]) -> bool:
        """Store one event. Returns True if it was new.

        A repeat is ignored rather than rejected: reconnecting to a stream
        after a drop legitimately re-delivers events already held, and that
        must not be an error.
        """
        seq = int(event.get("seq", 0))
        with self._tx() as conn:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO events (session_id, seq, type, at, payload) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    session_id,
                    seq,
                    str(event.get("type", "")),
                    event.get("at"),
                    json.dumps(event, sort_keys=True),
                ),
            )
            return cursor.rowcount > 0

    def append_gap_notice(self, session_id: str, at: Optional[str],
                          events_dropped: int, message: str) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO gap_notices (session_id, at, events_dropped, message) "
                "VALUES (?, ?, ?, ?)",
                (session_id, at, events_dropped, message),
            )

    def gap_notices(self, session_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM gap_notices WHERE session_id = ? ORDER BY id",
                (session_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def events(self, session_id: str, after_seq: int = 0,
               limit: Optional[int] = None) -> list[dict[str, Any]]:
        """Stored events in sequence order."""
        query = ("SELECT seq, type, at, payload FROM events "
                 "WHERE session_id = ? AND seq > ? ORDER BY seq")
        params: list[Any] = [session_id, after_seq]
        if limit:
            query += " LIMIT ?"
            params.append(limit)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [json.loads(r["payload"]) for r in rows]

    def last_event(self, session_id: str, event_type: str) -> Optional[dict[str, Any]]:
        """The stored event of that type with the highest sequence number, if any."""
        with self._lock:
            row = self._conn.execute(
                "SELECT payload FROM events WHERE session_id = ? AND type = ? "
                "ORDER BY seq DESC LIMIT 1", (session_id, event_type)).fetchone()
        return json.loads(row["payload"]) if row else None

    def event_seqs(self, session_id: str) -> list[int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq FROM events WHERE session_id = ? ORDER BY seq", (session_id,)
            ).fetchall()
        return [int(r["seq"]) for r in rows]

    def highest_seq(self, session_id: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COALESCE(MAX(seq), 0) AS high FROM events WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        return int(row["high"])

    def last_contiguous_seq(self, session_id: str) -> int:
        """The highest sequence number with no gap before it.

        Resuming from here, rather than from the highest number held, means a
        gap gets one more chance to be filled by the engine's buffer instead
        of being written off immediately.
        """
        expected = 0
        for seq in self.event_seqs(session_id):
            if seq == expected + 1:
                expected = seq
            elif seq > expected + 1:
                break
        return expected

    # --- findings ---------------------------------------------------------

    def append_finding(self, session_id: str, case_id: str, seq: Optional[int],
                       payload: dict[str, Any]) -> bool:
        with self._tx() as conn:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO findings (case_id, session_id, seq, payload) "
                "VALUES (?, ?, ?, ?)",
                (case_id, session_id, seq, json.dumps(payload, sort_keys=True)),
            )
            return cursor.rowcount > 0

    def findings(self, session_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT payload FROM findings WHERE session_id = ? ORDER BY seq, case_id",
                (session_id,),
            ).fetchall()
        return [json.loads(r["payload"]) for r in rows]

    # --- completeness -----------------------------------------------------

    def compute_completeness(self, session_id: str) -> Completeness:
        """Work out, from the stored rows alone, whether anything is missing."""
        seqs = self.event_seqs(session_id)
        received = len(seqs)
        highest = seqs[-1] if seqs else 0

        session = self.get_session(session_id) or {}
        total_seq = session.get("total_seq")
        notices = self.gap_notices(session_id)
        dropped_from_notices = sum(int(n["events_dropped"]) for n in notices)

        missing: list[int] = []
        if seqs:
            held = set(seqs)
            missing = [n for n in range(1, highest + 1) if n not in held]

        reasons: list[str] = []
        if missing:
            shown = ", ".join(str(n) for n in missing[:10])
            if len(missing) > 10:
                shown += f", ... ({len(missing)} in total)"
            reasons.append(
                f"the stored events have gaps at sequence {shown}; those events were "
                "produced by the engine but never received"
            )
        if dropped_from_notices:
            reasons.append(
                f"the engine reported {dropped_from_notices} event(s) evicted from its "
                "buffer before they could be delivered; they are permanently lost"
            )
        if total_seq is None:
            reasons.append(
                "the run did not report a final sequence number, so whether anything "
                "is missing after the last stored event is unknown"
            )
        elif highest < int(total_seq):
            reasons.append(
                f"the engine produced {int(total_seq)} events but only {highest} were "
                f"received; the stream ended early"
            )

        dropped = dropped_from_notices + len(missing)
        if total_seq is not None and highest < int(total_seq):
            dropped += int(total_seq) - highest

        complete = not reasons
        return Completeness(
            complete=complete,
            events_received=received,
            events_dropped=dropped,
            last_seq=highest,
            total_seq=int(total_seq) if total_seq is not None else None,
            reason="; ".join(reasons) if reasons else None,
            missing_seqs=missing,
        )

    def refresh_completeness(self, session_id: str) -> Completeness:
        """Recompute and persist a session's completeness."""
        c = self.compute_completeness(session_id)
        self.update_session(
            session_id,
            complete=1 if c.complete else 0,
            events_received=c.events_received,
            events_dropped=c.events_dropped,
            last_seq=c.last_seq,
            incomplete_reason=c.reason,
        )
        return c


def resolve_status(engine_status: Optional[str], completeness: Completeness) -> str:
    """Decide the status the API reports for a finished session.

    `completed` is a claim that the stored results are everything the run
    found, and two separate things have to hold for it to be true:

      - the engine has to say the run completed. A complete NDJSON stream only
        proves the orchestrator received every event the engine emitted; the
        engine may still have failed to write a case or an audit record, and
        it reports that as `incomplete`. Treating a whole stream as proof of a
        whole result set promotes the engine's own admission of loss into a
        claim of completeness, which is precisely backwards.
      - the stored sequence has to be whole. Otherwise events the engine
        produced never arrived, whatever it thought at the end.

    `stopped` and `failed` are kept as they are: neither is a claim about
    completeness, and how much data arrived is reported separately.
    """
    if engine_status in (STOPPED, FAILED, INTERRUPTED):
        return engine_status
    if engine_status == INCOMPLETE:
        # The engine lost something of its own. A tidy stream does not undo
        # that.
        return INCOMPLETE
    if not completeness.complete:
        return INCOMPLETE
    if engine_status == COMPLETED:
        return COMPLETED
    if engine_status is None:
        # No done event: there is no statement from the engine to rely on.
        return INCOMPLETE
    return engine_status


def iter_findings(events: Iterable[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    """Pull the finding payloads out of a stream of events."""
    for event in events:
        if event.get("type") == "finding" and isinstance(event.get("finding"), dict):
            yield event["finding"]
