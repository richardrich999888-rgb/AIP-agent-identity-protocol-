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
DENY → record; PENDING_APPROVAL → record and hold.

Approval (item 3.2). The agent retries the **same** signed request with
`"approval": {"approval": {...}, "signature_hex": "..."}` attached. The gate
forwards only when all of the following hold:
- the request was previously held (its nonce was seen only as PENDING_APPROVAL);
- the approval names this request's sha256, says APPROVE, and is signed by a
  registered operator;
- the approval is inside its time window (decided_at ≤ now < expires_at,
  TTL ≤ MAX_APPROVAL_TTL_MS);
- OPA still says PENDING_APPROVAL, not DENY (for example, authority revoked
  since).
An approval is single use: once the request is forwarded, its nonce is
spent. A rejected approval attempt (APPROVAL_INVALID) and a plain replay leave
the request held. A policy DENY on retry closes it. The freshness window applies to the first submission. A retry is
bounded by the approval's own window instead.
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
MAX_APPROVAL_TTL_MS = 15 * 60_000  # an approval is valid at most 15 min after the operator signs it
APPROVAL_FIELDS = {"request_sha256", "operator_id", "decision", "decided_at_ms", "expires_at_ms"}
APPROVAL_INVALID = "APPROVAL_INVALID"
# Every record carries the stage it reached:
#   pre-auth: before the signature verified (anyone can cause these),
#   auth:     signature verified; freshness, replay or approval checks,
#   policy:   OPA evaluated (and, on ALLOW, the call was forwarded).
# Replay checks count only authenticated (auth or policy) records, so a
# forged request reusing someone's nonce cannot burn it. A held request
# closes only on a policy-stage ALLOW or DENY. A plain replay or a bad
# approval sent with a captured envelope cannot cancel a pending call.
PRE_AUTH, AUTH, POLICY = "pre-auth", "auth", "policy"
CLOSING = {"ALLOW", "DENY"}
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

    def _seen(self, agent_id: str, nonce: str) -> list[tuple[str, str]]:
        """(outcome, stage) of authenticated records for this (agent, nonce), oldest first."""
        out, after = [], 0
        while True:
            page = self._store.events(kind=DECISION_KIND, subject=f"agent:{agent_id}", after_seq=after, limit=500)
            if not page:
                return out
            out += [(e.event.get("outcome"), e.event.get("stage")) for e in page
                    if e.event.get("nonce") == nonce and e.event.get("stage") in (AUTH, POLICY)]
            after = page[-1].seq

    def _approval_problem(self, approval: object, rsha: str, now: int) -> str | None:
        """None if the approval authorizes forwarding request `rsha` now; else the reason."""
        if not isinstance(approval, dict) or set(approval) != {"approval", "signature_hex"}:
            return "approval malformed"
        a = approval["approval"]
        if not isinstance(a, dict) or set(a) != APPROVAL_FIELDS:
            return "approval malformed"
        if a["request_sha256"] != rsha:
            return "approval is for another request"
        if a["decision"] != "APPROVE":
            return "approval decision is not APPROVE"
        key = self._reg.operators.get(a["operator_id"]) if isinstance(a["operator_id"], str) else None
        if key is None:
            return "approval by unregistered operator"
        if not signing.verify(signing.DOMAIN_APPROVAL, a, approval["signature_hex"], key):
            return "approval signature invalid"
        at, exp = a["decided_at_ms"], a["expires_at_ms"]
        if not all(isinstance(x, int) and not isinstance(x, bool) for x in (at, exp)) \
                or not (at <= now < exp) or exp - at > MAX_APPROVAL_TTL_MS:
            return "approval outside its time window"
        return None

    def _record(self, now: int, req: dict | None, rsha: str | None, outcome: str, reasons, *, stage: str,
                bundle=None, input_sha=None, forwarded=False, upstream_sha=None, upstream_error=None,
                approved_by=None) -> None:
        ev = {"kind": DECISION_KIND, "observed_at_ms": now, "label": "PREVENTION (calls through this gate only)",
              "stage": stage,
              "outcome": outcome, "reasons": list(reasons), "forwarded": forwarded, "request_sha256": rsha,
              "bundle_sha256": bundle, "opa_input_sha256": input_sha, "upstream_sha256": upstream_sha,
              "upstream_error": upstream_error, "approved_by": approved_by}
        if isinstance(req, dict):
            for k in ("agent_id", "server", "tool", "nonce"):
                if isinstance(req.get(k), str) and req[k]:
                    ev[k] = req[k]
            if isinstance(ev.get("agent_id"), str):
                ev["subject"] = f"agent:{ev['agent_id']}"
        self._store.append(ev, now)

    def _deny(self, now, req, rsha, reason, stage=PRE_AUTH) -> Result:
        self._record(now, req, rsha, "DENY", (reason,), stage=stage)
        return Result("DENY", (reason,), False, rsha)

    def handle(self, envelope: object) -> Result:
        now = self._clock()
        if not isinstance(envelope, dict) or set(envelope) not in ({"request", "signature_hex"},
                                                                  {"request", "signature_hex", "approval"}):
            return self._deny(now, None, None, "malformed envelope")
        approval = envelope.get("approval")
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
        seen = self._seen(req["agent_id"], req["nonce"])
        if approval is None:
            if abs(now - req["issued_at_ms"]) > MAX_SKEW_MS:
                return self._deny(now, req, rsha, "request outside freshness window", AUTH)
            if seen:
                return self._deny(now, req, rsha, "replayed nonce", AUTH)
        else:
            # A retry must be of a request that was held by policy and not since closed by policy.
            held = ("PENDING_APPROVAL", POLICY) in seen
            closed = any(st == POLICY and o in CLOSING for o, st in seen)
            if not held or closed:
                return self._deny(now, req, rsha, "approval retry for a request that is not pending", AUTH)
            problem = self._approval_problem(approval, rsha, now)
            if problem:
                self._record(now, req, rsha, APPROVAL_INVALID, (problem,), stage=AUTH)
                return Result("DENY", (problem,), False, rsha)
        amount = req["args"].get("amount")
        opa_in = {"agent_id": req["agent_id"], "server": req["server"], "tool": req["tool"],
                  "authority_jtis": req["authority_jtis"], "revoked_jtis": self._revoked,
                  "delegation_depth": req["delegation_depth"]}
        if isinstance(amount, (int, float)) and not isinstance(amount, bool):
            opa_in["amount"] = amount
        d = self._opa.decide(opa_in)
        approved_by = None
        if d.outcome == "PENDING_APPROVAL" and approval is not None:
            approved_by = approval["approval"]["operator_id"]
        elif d.outcome != "ALLOW":
            self._record(now, req, rsha, d.outcome, d.reasons, stage=POLICY, bundle=d.bundle_sha256,
                         input_sha=d.input_sha256)
            return Result(d.outcome, d.reasons, False, rsha)
        try:
            upstream = self._forward(req["server"], req["tool"], req["args"])
            usha = hashlib.sha256(signing.canonical(upstream)).hexdigest()
            err = None
        except Exception as e:  # upstream failure is recorded, not hidden; the call was allowed and attempted
            upstream, usha, err = None, None, f"{type(e).__name__}: {e}"[:200]
        self._record(now, req, rsha, "ALLOW", (), stage=POLICY, bundle=d.bundle_sha256, input_sha=d.input_sha256,
                     forwarded=True, upstream_sha=usha, upstream_error=err, approved_by=approved_by)
        return Result("ALLOW", (), True, rsha, upstream, err)
