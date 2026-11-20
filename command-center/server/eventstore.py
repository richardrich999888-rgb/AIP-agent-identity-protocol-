"""Persistent append-only event store (enterprise WOW loop, item 2.1a). Stdlib only.

Properties, each covered by a test in test_eventstore.py:

- **Idempotent.** The key is SHA-256 over a domain tag plus the event's
  canonical JSON (sorted keys, no whitespace, no NaN). Appending the same
  event again, even with its keys in another order, is a no-op that returns
  the original sequence number (adversarial #14).
- **Persistent.** State lives in one SQLite file (WAL, synchronous=FULL).
  Reopening it after a close, or after a process exit, keeps every event
  and keeps duplicates as no-ops (adversarial #13).
- **Append-only.** SQLite triggers abort any UPDATE or DELETE on `events`.
- **Tamper-evident.** Each row stores `row_hash = SHA-256(prev_hash ||
  idem)`, and `idem` is recomputable from `body`. `verify()` recomputes both
  and reports every row that breaks, so an edit made with the triggers
  dropped is still detected. The chain cannot detect truncation of the
  newest rows unless the caller holds an older `head()`: a known limit.

Time is passed in (`ingested_at_ms`). Nothing here reads a clock.
"""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path

IDEM_DOMAIN = b"vanian-event/v1\n"
CHAIN_DOMAIN = b"vanian-event-chain/v1\n"
GENESIS = "0" * 64
MAX_BODY_BYTES = 256 * 1024  # one event; larger inputs are refused, not truncated
MAX_PAGE = 1000

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
    idem           TEXT    NOT NULL UNIQUE,
    kind           TEXT    NOT NULL,
    subject        TEXT,
    observed_at_ms INTEGER,
    body           TEXT    NOT NULL,
    ingested_at_ms INTEGER NOT NULL,
    prev_hash      TEXT    NOT NULL,
    row_hash       TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS events_subject ON events(subject, observed_at_ms);
CREATE INDEX IF NOT EXISTS events_kind ON events(kind, seq);
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
    BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
    BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
"""


class InvalidEvent(ValueError):
    """The input is not a storable event. Nothing was written."""


@dataclass(frozen=True)
class Appended:
    """Result of `append`: the row's sequence number, and whether it was new."""

    seq: int
    idem: str
    inserted: bool


@dataclass(frozen=True)
class StoredEvent:
    seq: int
    idem: str
    kind: str
    subject: str | None
    observed_at_ms: int | None
    event: dict
    ingested_at_ms: int


def _is_nonneg_int(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _reject_non_finite(o: object) -> None:
    # json.dumps(allow_nan=False) already refuses NaN/Infinity; this also
    # gives a clear message naming the problem.
    if isinstance(o, float) and not math.isfinite(o):
        raise InvalidEvent("non-finite number")
    if isinstance(o, dict):
        for k, v in o.items():
            if not isinstance(k, str):
                raise InvalidEvent("object keys must be strings")
            _reject_non_finite(v)
    elif isinstance(o, list):
        for v in o:
            _reject_non_finite(v)


def canonical(event: object) -> str:
    """Canonical JSON of a valid event, or raise InvalidEvent.

    Required: `kind`, a non-empty string. Optional: `subject`, a non-empty
    string; `observed_at_ms`, a non-negative int.
    """
    if not isinstance(event, dict):
        raise InvalidEvent("event must be a JSON object")
    if not isinstance(event.get("kind"), str) or not event["kind"]:
        raise InvalidEvent("kind must be a non-empty string")
    if "subject" in event and (not isinstance(event["subject"], str) or not event["subject"]):
        raise InvalidEvent("subject, if present, must be a non-empty string")
    if "observed_at_ms" in event and not _is_nonneg_int(event["observed_at_ms"]):
        raise InvalidEvent("observed_at_ms, if present, must be a non-negative integer")
    _reject_non_finite(event)
    try:
        text = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as e:
        raise InvalidEvent(f"not JSON-serialisable: {e}") from None
    if len(text.encode()) > MAX_BODY_BYTES:
        raise InvalidEvent("event too large")
    return text


def idempotency_key(canonical_json: str) -> str:
    """SHA-256 hex of the domain tag and the canonical JSON."""
    return hashlib.sha256(IDEM_DOMAIN + canonical_json.encode()).hexdigest()


def chain_hash(prev_hash: str, idem: str) -> str:
    """SHA-256 hex linking a row to its predecessor."""
    return hashlib.sha256(CHAIN_DOMAIN + bytes.fromhex(prev_hash) + bytes.fromhex(idem)).hexdigest()


class EventStore:
    """An append-only event log in one SQLite file.

    Thread-safe within a process: one connection, opened with
    `check_same_thread=False`, with every operation serialised by a lock.
    Callers such as LiteLLM run hooks on their own threads (found in 4.1a).
    Across processes, SQLite serialises writers. This class does not retry
    on SQLITE_BUSY.
    """

    def __init__(self, path: Path | str) -> None:
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def __enter__(self) -> EventStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def head(self) -> tuple[int, str]:
        """(last seq, last row_hash), or (0, GENESIS) when empty."""
        with self._lock:
            row = self._db.execute("SELECT seq, row_hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        return (row[0], row[1]) if row else (0, GENESIS)

    def append(self, event: object, ingested_at_ms: int) -> Appended:
        """Append `event` unless an identical one exists. Raise InvalidEvent on bad input."""
        if not _is_nonneg_int(ingested_at_ms):
            raise InvalidEvent("ingested_at_ms must be a non-negative integer")
        body = canonical(event)
        idem = idempotency_key(body)
        assert isinstance(event, dict)  # canonical() checked
        # The in-process lock, and BEGIN IMMEDIATE across processes, hold the
        # write lock from reading the head to the insert, so the chain cannot fork.
        with self._lock:
            return self._append_locked(event, body, idem, ingested_at_ms)

    def _append_locked(self, event: dict, body: str, idem: str, ingested_at_ms: int) -> Appended:
        self._db.execute("BEGIN IMMEDIATE")
        try:
            got = self._db.execute("SELECT seq FROM events WHERE idem = ?", (idem,)).fetchone()
            if got:
                self._db.execute("COMMIT")
                return Appended(got[0], idem, False)
            _, prev = self.head()
            cur = self._db.execute(
                "INSERT INTO events (idem, kind, subject, observed_at_ms, body, ingested_at_ms, prev_hash, row_hash)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (idem, event["kind"], event.get("subject"), event.get("observed_at_ms"), body,
                 ingested_at_ms, prev, chain_hash(prev, idem)),
            )
            self._db.execute("COMMIT")
            return Appended(cur.lastrowid, idem, True)
        except BaseException:
            self._db.execute("ROLLBACK")
            raise

    def count(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def events(self, *, kind: str | None = None, subject: str | None = None,
               after_seq: int = 0, limit: int = 100) -> list[StoredEvent]:
        """Events in sequence order, filtered; at most `limit` (≤ MAX_PAGE)."""
        if not (1 <= limit <= MAX_PAGE) or not _is_nonneg_int(after_seq):
            raise ValueError("limit must be 1..MAX_PAGE and after_seq non-negative")
        q, args = "SELECT seq, idem, kind, subject, observed_at_ms, body, ingested_at_ms FROM events WHERE seq > ?", [after_seq]
        if kind is not None:
            q, args = q + " AND kind = ?", args + [kind]
        if subject is not None:
            q, args = q + " AND subject = ?", args + [subject]
        with self._lock:
            rows = self._db.execute(q + " ORDER BY seq LIMIT ?", args + [limit]).fetchall()
        return [StoredEvent(r[0], r[1], r[2], r[3], r[4], json.loads(r[5]), r[6]) for r in rows]

    def last_observed_ms(self, subject: str) -> int | None:
        """Latest `observed_at_ms` for `subject`; None if never observed (not 0)."""
        with self._lock:
            return self._db.execute("SELECT MAX(observed_at_ms) FROM events WHERE subject = ?", (subject,)).fetchone()[0]

    def verify(self) -> list[str]:
        """Recompute every key and chain link. Returns problems; empty means intact."""
        problems: list[str] = []
        prev, expect_seq = GENESIS, None
        with self._lock:
            rows = self._db.execute("SELECT seq, idem, body, prev_hash, row_hash FROM events ORDER BY seq").fetchall()
        for seq, idem, body, prev_hash, row_hash in rows:
            if expect_seq is not None and seq != expect_seq:
                problems.append(f"seq {seq}: gap after {expect_seq - 1}")
            if idempotency_key(body) != idem:
                problems.append(f"seq {seq}: body does not match its key")
            if prev_hash != prev:
                problems.append(f"seq {seq}: prev_hash does not link to the previous row")
            if chain_hash(prev_hash, idem) != row_hash:
                problems.append(f"seq {seq}: row_hash mismatch")
            prev, expect_seq = row_hash, seq + 1
        return problems
