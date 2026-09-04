# TRUST_BOUNDARIES — as implemented at `377d5fc`

Boundaries that exist in code. Boundaries the target architecture requires but
which have no implementation are marked **ABSENT** and carry no row content
invented from documentation.

```
┌─ AGENT (untrusted) ─────────────────────────────────────────────┐
│  holds its own Ed25519 key. Asserts provenance, decision,       │
│  inputs, payloads, runtime facts. Signs the packet.             │
└───────────┬─────────────────────────────────────────────────────┘
            │ B1 packet bytes + (at the service) its own PRIVATE KEY
┌───────────▼─ AIP LIBRARY (no trust decision) ───────────────────┐
│  aip-crypto / aip-core / aip-protocol. Encodes, hashes, signs.  │
└───────────┬─────────────────────────────────────────────────────┘
            │ B2 EvidencePacket
┌───────────▼─ AUTHORITY (issuer-signed, verifier-anchored) ──────┐
│  ScopedToken + DelegationToken chain                            │
└───────────┬─────────────────────────────────────────────────────┘
            │ B3
┌───────────▼─ VERIFIER (trusted, external anchors) ──────────────┐
│  verify_packet → 14 rules → derived TrustFloor                  │
└───────────┬─────────────────────────────────────────────────────┘
            │ B4 VerificationReport
┌───────────▼─ SERVICE / STORAGE ─────────────────────────────────┐
│  aip-service, JSONL or PostgreSQL EvidenceStore                 │
└─────────────────────────────────────────────────────────────────┘

POLICY        ABSENT   no authorization decision point exists
GATEWAY       ABSENT   no in-path enforcement in production
RUNTIME       PARTIAL  runtime.rs, self-reported, unwired
KERNEL        ABSENT
NETWORK       ABSENT
OBSERVER      ABSENT
RECONCILER    ABSENT
PROOF SYSTEM  ABSENT   Merkle helpers only; roots always empty
CONTAINMENT   ABSENT
```

## B1 — Agent → AIP library

| Aspect | Reality |
|---|---|
| Trusted | AIP library code |
| Untrusted | the agent |
| Data crossing | `agent_id`, `ProvenanceTriple`, decision text, action payloads, and **at `/v1/evidence/generate`, the agent's private key seed** (`aip-service/src/evidence.rs:130`) |
| Cryptographic protection | none on the way in — the library signs what it is given |
| Authentication | none. Possession of a key is the only identity proof |
| Authorization | **none. No check exists** |
| Replay protection | none at this boundary |
| Integrity protection | applied *after* the boundary (packet is sealed post-hoc) |
| **Failure mode** | **fail-open.** Any input is faithfully sealed. Garbage in → cryptographically perfect garbage out |

Violates **I1**. This is the boundary Ghost must change.

## B2 — Evidence packet construction

| Aspect | Reality |
|---|---|
| Data crossing | full `EvidencePacket` (`aip-protocol/src/evidence_packet.rs:210-246`) |
| Cryptographic protection | `packet_hash = SHA-256(canonical_bytes)`; `agent_sig` over the same bytes (`:460-462`) |
| Integrity protection | **strong** — length-prefixed injective encoding (`canonical.rs`) |
| Replay protection | **NONE.** `VerificationContext` (`verification.rs:28-42`) has no seen-set; no rule consumes `packet_id` or `agent_sig.nonce` for uniqueness. The same packet verifies identically forever |
| Failure mode | tamper by a third party → R3/R4 fail. Tamper by the key holder → re-seal succeeds |

## B3 — Authority (issuer → holder)

| Aspect | Reality |
|---|---|
| Trusted | the issuer's signature, **for the fields it covers** |
| Untrusted | the token holder |
| Data crossing | `ScopedToken`, `Vec<DelegationToken>` |
| Cryptographic protection | Ed25519 over `canonical_token_payload` (`capability.rs:208`) / `canonical_delegation_payload` (`delegation.rs:369`) |
| **Not covered** | **`expires_at` is absent from both payloads** — verified by inspection of the parameter lists and by grep returning 0 in both function bodies |
| Authorization | attenuation enforced at creation (`delegation.rs:63-69`) and per hop at verification (`:200`) |
| Replay protection | none — `NonceTracker` is not wired to delegation |
| **Failure mode** | **fail-open on lifetime.** The holder rewrites its own expiry; R5/R6 cannot see it; R10 honours the forged value |

Violates **I6** and **I21**.

## B4 — Verifier

Two materially different implementations of the same boundary:

| | `aip-verify` (CLI) | `POST /v1/evidence/verify` |
|---|---|---|
| Anchor source | operator flags `--trust`, `--counterparty` (`aip-verify/src/main.rs:77-78`) | **the caller's own request body** — `VerifyRequest.trusted_issuers` (`evidence.rs:161`) → `ctx.issuer_public_keys` (`:307-309`) |
| Unknown issuer | R5 fails → exit 2 | R5 fails only if the caller omits the key |
| Trust decision made by | the auditor | **the party being audited** |
| Classification | correct trust boundary | **not a trust boundary — a calculator** |

The service endpoint is honestly documented as pure (`evidence.rs:363-365`).
The hazard is architectural: if any consumer treats its `valid: true` as an
authorization decision, invariant **I19** is violated and the agent
self-authorizes. Ghost must never consume this endpoint as an authority.

## B5 — Service → storage

| Aspect | Reality |
|---|---|
| Tenant isolation | enforced in the store layer: `store.rs:204-211` filter, `store/pg.rs:196-204` `WHERE id=$1 AND tenant_id=$2`. Wrong tenant → 404, no existence leak |
| Envelope integrity | **none.** `VaultRecord` has no MAC; `tenant_id` is outside the signed packet. File write access moves a packet between tenants undetected |
| Durability | JSONL: **no fsync, no cross-process lock** (`store.rs:174-202`). PostgreSQL: real transaction, PG fsync (`pg.rs:125-194`) |
| Rollback protection | none in either backend |
| Failure mode | acknowledged JSONL write can vanish; duplicate id can silently re-tenant a packet (`store.rs:142`) |

## Boundaries the target architecture requires and which do not exist

| Boundary | Status | Consequence |
|---|---|---|
| POLICY / authorization decision | **ABSENT** | no ExpectedExecution can be produced — see `OBSERVATION_MODEL.md` |
| OBSERVER (independent runtime) | **ABSENT** | verified: 0 files match `ebpf`, `XDP`, `perf_event`, `ring_buffer`, `procfs`, `netlink` in production |
| OBSERVER trust root | **ABSENT** | no attestation key exists that the observed agent does not control |
| RECONCILER | **ABSENT** | 0 files match `reconcile`/`Reconciliation` |
| PROOF SYSTEM | **ABSENT as protocol** | `merkle_leaf`/`merkle_internal` exist as primitives, called only from a test |
| CONTAINMENT | **ABSENT** | no actuation of any kind, by design |
