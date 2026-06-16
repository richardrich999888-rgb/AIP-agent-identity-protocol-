# 04 — Pilot Readiness Report (code-backed only)

No aspirational claims. Each line maps to code in this repository and a test
or command that demonstrates it.

## 1. Production-ready (mature, standards-based, heavily tested)

These are the cryptographic and verification fundamentals. "Production-ready"
here means the *logic* is sound and tested — not that the *service* around it
is hardened (see §4).

| Capability | Evidence |
|---|---|
| Ed25519 sign/verify, SHA-256, Base58 AIP-ID + checksum | `aip-crypto`; tests in-crate |
| EvidencePacket canonical encoding + deterministic hashing | `aip-protocol::evidence_packet` |
| 14-rule verification engine; derived trust floor; tamper classification | `aip-protocol::verification`; 17 integration tests where every tamper flips a named rule |
| Delegation lattice: per-hop signatures, depth limits, scope attenuation (MEET) | `aip-core::delegation`/`capability` |
| Offline / independent verification (pure function of packet + keys) | `verify_packet`; loan example runs with no network |
| Test status | `cargo test --workspace` → 214 pass, 2 release-only ignored |

## 2. Pilot-ready (works, tested, deployable for a scoped non-gating pilot)

| Capability | Evidence | Pilot caveat |
|---|---|---|
| Evidence generation API | `POST /v1/evidence/generate` | agent seed supplied in request (managed/dev mode); production wants client-side signing + `/ingest` |
| Evidence verification API | `POST /v1/evidence/verify` | stateless; auth required |
| Evidence retrieval | `GET /v1/evidence/{id}` | tenant-checked |
| Authority graph query | `GET /v1/authority/{id}` | rebuilt per query (fine at pilot volume) |
| Evidence Vault (durable store) | `vault.rs`, append-only JSONL, reload-tested | single file, single node |
| Authentication + tenant isolation | `auth.rs`; API keys (hashed), role + tenant; fail-closed | static keys (rotate = edit file + restart) |
| Service test status | `cd aip-service && cargo test` → 37 pass | — |
| HTTP behaviour verified | public 200; no/bad key 401; admin-only revoke 403/authd; tenant-scoped reads | — |

## 3. Prototype only (do not rely on for a pilot)

| Component | Status |
|---|---|
| Legacy JWT identity endpoints (`/v1/identity/issue`, `/delegate`, `/verify`) | Parallel implementation; now authenticated but **not** migrated onto `aip-core`; slated for consolidation |
| Reputation (BFT aggregation) | EXPERIMENTAL (rustdoc-flagged); overflow fixed but design unvalidated |
| Hardware attestation | EXPERIMENTAL — **structural checks only; does not verify vendor TEE quotes** |
| Liveness challenge-response | EXPERIMENTAL |

## 4. Must be completed before a *regulated production* deployment

Ordered by how often a bank/auditor will block on it:

1. **TLS + rate limiting** at ingress (deployment config; service runs HTTP behind a proxy today).
2. **Independent security assessment** (e.g. CERT-In empanelled) + remediation.
3. **Durable, backed-up storage** to replace single-file JSONL (DB + backup/retention/immutability), with DR/BCP.
4. **Key management:** KMS/HSM for the service signing key; **API-key rotation** endpoint (today: edit file + restart).
5. **Client-side signing SDK + `/v1/evidence/ingest`** (no agent key on the wire — the production custody model).
6. **Standalone signed verifier binary** + **audit-export bundle** endpoint (auditor self-service).
7. **HTTP-level integration test** of the full generate→verify→get→authority round-trip (today proven by unit tests against real crypto; handlers are thin adapters).
8. **RBAC beyond machine/admin** + structured audit logging/monitoring of all privileged actions.
9. **Model-provenance attestation** (today the provenance triple is a self-declared commitment, not a verified measurement).

## 5. One-paragraph honest summary

The cryptographic accountability core is production-grade and tested; the
deployable service is **pilot-grade** — authenticated, tenant-isolated, and
functional, but single-node, file-backed, with static keys and no built-in
TLS/rate-limiting. It is suitable **today** for a scoped, non-gating design-
partner pilot where AIP *records and proves* authority and integrity but does
not sit in the transaction's critical path. It is **not yet** suitable for a
regulated production rollout until items in §4 are closed.
