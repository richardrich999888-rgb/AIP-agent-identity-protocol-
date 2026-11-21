"""The native enforcement point (item 3.1b; native, not P0-059).

`Gate.handle(envelope)` decides and, only on ALLOW, forwards. Steps, in order;
the first failure is a DENY that is recorded and **never forwarded**:

1. envelope shape: {"request": {...}, "signature_hex": "..."};
2. identity: agent_id is registered and the Ed25519 signature over the
   canonical request verifies under that agent's registered key (proof of
   possession — the gap #30 records for DecisionPoint is closed *here*);
3. freshness: |now − issued_at_ms| ≤ MAX_SKEW_MS;
4. replay: (agent_id, nonce) not seen before (seen nonces are persisted in
   the event store, so a restart does not reopen replay);
5. policy: OpaGate.decide with the operator-signed revocation list;
   any engine failure is DENY (fail closed, via opa_gate).

Outcomes: ALLOW → forward and record the upstream result digest;
DENY → record; PENDING_APPROVAL → record and hold (approval is item 3.2).
Every decision is a `gate.decision` event with the bundle hash.

Scope of PREVENTION: calls that go through this gate. A tool server reachable
by another path is not protected by it; that bypass is what the observer
(Sniffer Dog) is for. State this wherever the label is shown.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Callable

import signing
from agent_registry import Registry
from eventstore import EventStore
from opa_gate import OpaGate

DECISION_KIND = "gate.decision"
MAX_SKEW_MS = 30_000
NONCE = re.compile(r"^[0-9a-f]{16,64}$")
REQUEST_FIELDS = {"agent_id", "server", "tool", "args", "authority_jtis", "delegation_depth", "nonce", "issued_at_ms"}


@dataclass(frozen=True)
class Result:
    outcome: str  # ALLOW | DENY | PENDING_APPROVAL
    reasons: tuple[str, ...]
    forwarded: bool
    request_sha256: str | None
    upstream: object = None
    upstream_error: str | None = None

    def to_json(self) -> dict:
        return {"outcome": self.outcome, "reasons": list(self.reasons), "forwarded": self.forwarded,
                "request_sha256": self.request_sha256, "upstream": self.upstream, "upstream_error": self.upstream_error}


Forward = Callable[[str, str, dict], object]


class Gate:
    def __init__(self, registry: Registry, revoked_jtis: list[str], opa: OpaGate, store: EventStore,
                 forward: Forward, clock_ms: Callable[[], int]) -> None:
        self._reg, self._revoked, self._opa, self._store = registry, list(revoked_jtis), opa, store
        self._forward, self._clock = forward, clock_ms

    def _seen(self, agent_id: str, nonce: str) -> bool:
        after = 0
        while True:
            page = self._store.events(kind=DECISION_KIND, subject=f"agent:{agent_id}", after_seq=after, limit=500)
            if not page:
                return False
            if any(e.event.get("nonce") == nonce for e in page):
                return True
            after = page[-1].seq

    def _record(self, now: int, req: dict | None, rsha: str | None, outcome: str, reasons, *,
                bundle=None, input_sha=None, forwarded=False, upstream_sha=None, upstream_error=None) -> None:
        ev = {"kind": DECISION_KIND, "observed_at_ms": now, "label": "PREVENTION (calls through this gate only)",
              "outcome": outcome, "reasons": list(reasons), "forwarded": forwarded, "request_sha256": rsha,
              "bundle_sha256": bundle, "opa_input_sha256": input_sha, "upstream_sha256": upstream_sha,
              "upstream_error": upstream_error}
        if isinstance(req, dict):
            for k in ("agent_id", "server", "tool", "nonce"):
                if isinstance(req.get(k), str) and req[k]:
                    ev[k] = req[k]
            if isinstance(ev.get("agent_id"), str):
                ev["subject"] = f"agent:{ev['agent_id']}"
        self._store.append(ev, now)

    def _deny(self, now, req, rsha, reason) -> Result:
        self._record(now, req, rsha, "DENY", (reason,))
        return Result("DENY", (reason,), False, rsha)

    def handle(self, envelope: object) -> Result:
        now = self._clock()
        if not isinstance(envelope, dict) or set(envelope) != {"request", "signature_hex"}:
            return self._deny(now, None, None, "malformed envelope")
        req = envelope["request"]
        if not isinstance(req, dict) or set(req) != REQUEST_FIELDS:
            return self._deny(now, None, None, "malformed request")
        try:
            rsha = signing.digest(signing.DOMAIN_REQUEST, req)
        except (TypeError, ValueError):
            return self._deny(now, None, None, "request is not JSON")
        if not isinstance(req["args"], dict) or not isinstance(req["nonce"], str) or not NONCE.match(req["nonce"]) \
                or not isinstance(req["issued_at_ms"], int) or isinstance(req["issued_at_ms"], bool):
            return self._deny(now, req, rsha, "malformed request")
        key = self._reg.agent_key(req["agent_id"]) if isinstance(req["agent_id"], str) else None
        if key is None:
            return self._deny(now, req, rsha, "unknown agent")
        if not signing.verify(signing.DOMAIN_REQUEST, req, envelope["signature_hex"], key):
            return self._deny(now, req, rsha, "request signature invalid")
        if abs(now - req["issued_at_ms"]) > MAX_SKEW_MS:
            return self._deny(now, req, rsha, "request outside freshness window")
        if self._seen(req["agent_id"], req["nonce"]):
            return self._deny(now, req, rsha, "replayed nonce")
        opa_in = {"agent_id": req["agent_id"], "server": req["server"], "tool": req["tool"],
                  "authority_jtis": req["authority_jtis"], "revoked_jtis": self._revoked,
                  "delegation_depth": req["delegation_depth"]}
        d = self._opa.decide(opa_in)
        if d.outcome != "ALLOW":
            self._record(now, req, rsha, d.outcome, d.reasons, bundle=d.bundle_sha256, input_sha=d.input_sha256)
            return Result(d.outcome, d.reasons, False, rsha)
        try:
            upstream = self._forward(req["server"], req["tool"], req["args"])
            usha = hashlib.sha256(signing.canonical(upstream)).hexdigest()
            err = None
        except Exception as e:  # upstream failure is recorded, not hidden; the call was allowed and attempted
            upstream, usha, err = None, None, f"{type(e).__name__}: {e}"[:200]
        self._record(now, req, rsha, "ALLOW", (), bundle=d.bundle_sha256, input_sha=d.input_sha256,
                     forwarded=True, upstream_sha=usha, upstream_error=err)
        return Result("ALLOW", (), True, rsha, upstream, err)
