"""Sniffer Dog archive → event store, with coverage gaps (enterprise WOW loop, item 3.4a).

`ArchiveIngestor.poll()` reads the collector's `attested.archive.jsonl`. It
takes only complete lines: a line still being written is left for the next
poll. It has the real offline verifier (`aip-observe-verify`) check all of
those lines against the anchored collector key, and it appends them to the
event store **only if the verifier exits 0**. On any finding, error or
missing binary, nothing is ingested and the poll says why (fail closed).
Re-polling re-appends everything, and the store makes duplicates no-ops, so
the ingestor holds no offset state and is restart-safe.

`coverage()` is pure. It derives what the observer covered from the
batches' claimed windows, clipped at the collector's signed `attested_at_ms`
(an event cannot postdate its attestation). It reports:

- gaps between consecutive windows, larger than `slack_ms`;
- probe restarts (a change of `probe_run_id`), always reported as a gap
  boundary;
- losses: `dropped_events > 0`, and `dropped_events is None`, which means
  the loss is not countable (CANNOT_PROVE);
- state at `now_ms`:
  - NO_DATA: no batches;
  - DEGRADED: silent longer than `max_silence_ms`; the open gap runs to
    `now_ms`;
  - COVERED: otherwise.

`window_covered(cov, a, b)` answers whether [a, b] lies inside a covered
span. A window that is not covered is never shown as clean.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from eventstore import EventStore

BATCH_KIND = "observer.batch"
DEFAULT_SLACK_MS = 0  # measured: consecutive windows are exactly contiguous in both qualified runs
DEFAULT_MAX_SILENCE_MS = 10_000  # measured max window 3230 ms + max attest latency 2275 ms, ~2x margin
VERIFY_TIMEOUT_S = 60.0


@dataclass(frozen=True)
class Anchor:
    """The collector key a verifier anchors: (observer_id, key_version, public key file)."""

    observer_id: str
    key_version: int
    pubkey_file: Path


@dataclass(frozen=True)
class Window:
    sequence: int
    from_ms: int
    to_ms: int
    probe_run_id: str
    dropped_events: int | None


@dataclass
class Coverage:
    state: str  # "NO_DATA" | "COVERED" | "DEGRADED"
    spans: list[tuple[int, int]] = field(default_factory=list)
    gaps: list[dict] = field(default_factory=list)
    losses: list[dict] = field(default_factory=list)
    covered_to_ms: int | None = None


@dataclass(frozen=True)
class PollResult:
    verified: bool
    reason: str
    lines: int
    inserted: int
    findings: int | None


def _hex(v: object) -> str | None:
    if isinstance(v, list) and all(isinstance(x, int) and 0 <= x <= 255 for x in v):
        return bytes(v).hex()
    return None


def window_of(rec: dict) -> Window:
    """The covered window of one attested batch record; ValueError if malformed."""
    try:
        b = rec["batch"]
        seq, frm, to, att = rec["sequence"], b["claimed_from_ms"], b["claimed_to_ms"], rec["attested_at_ms"]
        run = _hex(b["probe_run_id"])
        dropped = b["dropped_events"]
    except (KeyError, TypeError) as e:
        raise ValueError(f"batch record missing field: {e}") from None
    ints = (seq, frm, to, att)
    if not all(isinstance(x, int) and not isinstance(x, bool) and x >= 0 for x in ints) or run is None:
        raise ValueError("batch record has a malformed field")
    if dropped is not None and (not isinstance(dropped, int) or isinstance(dropped, bool) or dropped < 0):
        raise ValueError("dropped_events malformed")
    end = min(to, att)
    if end < frm:
        raise ValueError("window ends before it starts")
    return Window(seq, frm, end, run, dropped)


def coverage(windows: list[Window], now_ms: int, *, slack_ms: int = DEFAULT_SLACK_MS,
             max_silence_ms: int = DEFAULT_MAX_SILENCE_MS) -> Coverage:
    """Covered spans, gaps, losses and state at `now_ms` (see module docstring)."""
    if not windows:
        return Coverage("NO_DATA", gaps=[{"from_ms": None, "to_ms": now_ms, "reason": "no observer batches"}])
    ws = sorted(windows, key=lambda w: w.sequence)
    cov = Coverage("COVERED")
    span_from, span_to = ws[0].from_ms, ws[0].to_ms
    for prev, w in zip(ws, ws[1:]):
        restarted = w.probe_run_id != prev.probe_run_id
        if restarted or w.from_ms - span_to > slack_ms:
            cov.spans.append((span_from, span_to))
            cov.gaps.append({"from_ms": span_to, "to_ms": max(span_to, w.from_ms),
                             "reason": "probe restarted" if restarted else "no batch covers this interval"})
            span_from = w.from_ms
        span_to = max(span_to, w.to_ms)
    cov.spans.append((span_from, span_to))
    for w in ws:
        if w.dropped_events is None:
            cov.losses.append({"sequence": w.sequence, "reason": "loss not countable (CANNOT_PROVE)"})
        elif w.dropped_events > 0:
            cov.losses.append({"sequence": w.sequence, "reason": f"{w.dropped_events} events dropped"})
    cov.covered_to_ms = span_to
    if now_ms - span_to > max_silence_ms:
        cov.state = "DEGRADED"
        cov.gaps.append({"from_ms": span_to, "to_ms": now_ms, "reason": "observer silent: no batch since"})
    return cov


def window_covered(cov: Coverage, a: int, b: int) -> bool:
    """True only if [a, b] lies inside one covered span and no loss was reported."""
    if cov.state == "NO_DATA" or a > b:
        return False
    inside = any(s <= a and b <= e for s, e in cov.spans)
    return inside and not cov.losses


def batch_event(rec: dict) -> dict:
    """The event-store event for one verified batch (metadata, not the kernel events)."""
    w = window_of(rec)
    b = rec["batch"]
    return {
        "kind": BATCH_KIND,
        "subject": f"probe:{b['probe_id']}",
        "observed_at_ms": rec["attested_at_ms"],
        "observer_id": rec["observer_id"],
        "key_version": rec["key_version"],
        "sequence": w.sequence,
        "batch_id": _hex(b.get("batch_id")),
        "probe_run_id": w.probe_run_id,
        "window_from_ms": w.from_ms,
        "window_to_ms": w.to_ms,
        "dropped_events": w.dropped_events,
        "kernel_events": len(b.get("kernel_events") or []),
        "observations": len(b.get("observations") or []),
        "evidence": "collector signature verified offline (aip-observe-verify)",
    }


def complete_lines(data: bytes) -> list[bytes]:
    """Non-empty lines terminated by a newline; a trailing partial line is excluded."""
    return [ln for ln in data.split(b"\n")[:-1] if ln.strip()]


def run_verifier(verifier: str, anchor: Anchor, lines: list[bytes]) -> tuple[bool, str, int | None]:
    """(ok, reason, findings) from aip-observe-verify over exactly `lines`."""
    with tempfile.NamedTemporaryFile("wb", suffix=".jsonl", delete=False) as f:
        f.write(b"".join(ln + b"\n" for ln in lines))
        path = f.name
    try:
        p = subprocess.run(
            [verifier, "--observer-id", anchor.observer_id, "--key-version", str(anchor.key_version),
             "--pubkey-file", str(anchor.pubkey_file), "--batches", path, "--json"],
            capture_output=True, timeout=VERIFY_TIMEOUT_S, check=False)
    except FileNotFoundError:
        return False, "verifier not found", None
    except subprocess.TimeoutExpired:
        return False, "verifier timeout", None
    finally:
        Path(path).unlink(missing_ok=True)
    try:
        findings = len(json.loads(p.stdout)["findings"])
    except (json.JSONDecodeError, KeyError, TypeError):
        findings = None
    if p.returncode == 0 and findings == 0:
        return True, "verified", 0
    return False, f"verifier exit {p.returncode}", findings


class ArchiveIngestor:
    """Polls one collector archive into an EventStore."""

    def __init__(self, store: EventStore, archive: Path, verifier: str, anchor: Anchor,
                 clock_ms: Callable[[], int]) -> None:
        self._store, self._archive, self._verifier, self._anchor, self._clock = store, archive, verifier, anchor, clock_ms

    def poll(self) -> PollResult:
        """Verify then ingest; never ingests anything the verifier did not accept."""
        try:
            lines = complete_lines(self._archive.read_bytes())
        except OSError as e:
            return PollResult(False, f"archive unreadable: {type(e).__name__}", 0, 0, None)
        if not lines:
            return PollResult(True, "empty", 0, 0, 0)
        ok, reason, findings = run_verifier(self._verifier, self._anchor, lines)
        if not ok:
            return PollResult(False, reason, len(lines), 0, findings)
        try:
            events = [batch_event(json.loads(ln)) for ln in lines]
        except (json.JSONDecodeError, ValueError, KeyError) as e:
            return PollResult(False, f"verified archive did not map: {e}", len(lines), 0, 0)
        now = self._clock()
        inserted = sum(self._store.append(e, now).inserted for e in events)
        return PollResult(True, reason, len(lines), inserted, 0)

    def windows(self) -> list[Window]:
        """Covered windows of every ingested batch for this observer."""
        out, after = [], 0
        while True:
            page = self._store.events(kind=BATCH_KIND, after_seq=after, limit=500)
            if not page:
                return out
            after = page[-1].seq
            out += [Window(e.event["sequence"], e.event["window_from_ms"], e.event["window_to_ms"],
                           e.event["probe_run_id"], e.event["dropped_events"])
                    for e in page if e.event.get("observer_id") == self._anchor.observer_id]
