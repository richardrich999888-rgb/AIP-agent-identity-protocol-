"""Agent inventory over the registry and the event store (item 2.2; native, not P0-059). Pure.

One row per registered agent, plus one per id that reached the gate without
being registered (UNREGISTERED). Fields:

- registry: framework, host, runtime, owner, responsible_human, parent;
  `key_fingerprint` = SHA-256 of the public key (never a secret);
- `last_seen_ms`: the latest observed_at over this agent's gate decisions
  and LLM usage. None if never seen, never 0;
- counts: decisions, allowed, held for approval, approvals used, policy
  denials, signature failures against this id, revoked-authority uses,
  invalid approvals, replays, policy-engine outages, LLM calls;
- credential metadata: the key fingerprint only. There is no token expiry
  to report: the native gate uses per-request signatures, not bearer tokens;
- `risk`, by the declared rule below. A never-seen agent is UNKNOWN, not LOW.

Risk rule (declared, in order):
  HIGH   — any signature failure against the id, or any use of revoked authority;
  MEDIUM — any policy denial, or any invalid approval presented with a
           request signed by this agent;
  LOW    — seen, and none of the above;
  UNKNOWN — never seen.
Signature failures are counted against the *claimed* id. They mean someone
tried to act as that agent, not that the agent misbehaved, and the row says
so (`signature_failures_are_claims`). Replays and invalid approvals ride on a
request this agent did sign, but anyone holding a copy can resend it, so
replays do not raise risk. A policy-engine outage is the operator's fault,
not the agent's: it is counted and never raises risk.
"""

from __future__ import annotations

import hashlib

GATE_KIND = "gate.decision"
USAGE_KIND = "llm.usage"
SIG_FAIL = "request signature invalid"
REVOKED = "authority revoked"
ENGINE_DOWN = "policy engine unavailable"
REPLAY = "replayed nonce"
APPROVAL_INVALID = "APPROVAL_INVALID"


def fingerprint(public_key_hex: str) -> str:
    """SHA-256 (hex) of the raw public key bytes. Identifies the key without reproducing it."""
    return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()


def _blank() -> dict:
    return {"last_seen_ms": None, "decisions": 0, "allowed": 0, "policy_denials": 0, "signature_failures": 0,
            "revoked_authority_uses": 0, "held_for_approval": 0, "approvals_used": 0, "invalid_approvals": 0,
            "replays": 0, "engine_unavailable": 0, "llm_calls": 0}


def _risk(c: dict) -> str:
    if c["signature_failures"] or c["revoked_authority_uses"]:
        return "HIGH"
    if c["policy_denials"] or c["invalid_approvals"]:
        return "MEDIUM"
    return "LOW" if c["last_seen_ms"] is not None else "UNKNOWN"


def _seen(c: dict, t: object) -> None:
    if isinstance(t, int) and not isinstance(t, bool) and (c["last_seen_ms"] is None or t > c["last_seen_ms"]):
        c["last_seen_ms"] = t


def build(agents: dict[str, dict], events: list[dict]) -> list[dict]:
    """Inventory rows, registered agents first (sorted by id), then UNREGISTERED ids."""
    counts: dict[str, dict] = {aid: _blank() for aid in agents}
    for e in events:
        aid = e.get("agent_id")
        if not isinstance(aid, str) or not aid:
            continue
        kind = e.get("kind")
        if kind not in (GATE_KIND, USAGE_KIND):
            continue
        c = counts.setdefault(aid, _blank())
        if kind == USAGE_KIND:
            c["llm_calls"] += 1
            _seen(c, e.get("observed_at_ms"))
            continue
        reasons = e.get("reasons") or []
        if SIG_FAIL in reasons:
            # A claim of this id that failed verification: not evidence the agent acted.
            c["signature_failures"] += 1
            continue
        c["decisions"] += 1
        _seen(c, e.get("observed_at_ms"))
        if e.get("outcome") == "ALLOW":
            c["allowed"] += 1
            if e.get("approved_by"):
                c["approvals_used"] += 1
        elif e.get("outcome") == "PENDING_APPROVAL":
            c["held_for_approval"] += 1
        elif e.get("outcome") == APPROVAL_INVALID:
            c["invalid_approvals"] += 1
        elif any(isinstance(r, str) and r.startswith(ENGINE_DOWN) for r in reasons):
            c["engine_unavailable"] += 1
        elif REPLAY in reasons:
            c["replays"] += 1
        elif e.get("outcome") == "DENY" and e.get("stage") == "policy":
            c["policy_denials"] += 1
        if REVOKED in reasons:
            c["revoked_authority_uses"] += 1
    rows = []
    for aid in sorted(agents):
        a, c = agents[aid], counts[aid]
        rows.append({"agent_id": aid, "status": "REGISTERED", "framework": a["framework"], "host": a["host"],
                     "runtime": a["runtime"], "owner": a["owner"], "responsible_human": a["responsible_human"],
                     "parent": a["parent"], "key_fingerprint": fingerprint(a["public_key_hex"]), **c,
                     "risk": _risk(c), "signature_failures_are_claims": True})
    for aid in sorted(set(counts) - set(agents)):
        c = counts[aid]
        rows.append({"agent_id": aid, "status": "UNREGISTERED", "framework": None, "host": None, "runtime": None,
                     "owner": None, "responsible_human": None, "parent": None, "key_fingerprint": None, **c,
                     "risk": "HIGH" if c["decisions"] or c["signature_failures"] else "UNKNOWN",
                     "signature_failures_are_claims": True})
    return rows
