# 05 — Top 50 Questions (Bank / Auditor / Regulator)

Brutally honest. **Evidence** = where it's backed in code. **Gap** = what's
missing (blank = none material).

## A. Cryptography & evidence integrity

| # | Question | Answer | Evidence | Gap |
|---|---|---|---|---|
| 1 | What signs an EvidencePacket? | The acting agent's Ed25519 key over a canonical hash of all fields | `evidence_packet.rs`, `aip-crypto` | — |
| 2 | Can someone edit a packet undetected? | No — hash + signature fail on any change | `CANONICAL_HASH`,`AGENT_SIGNATURE` tests | — |
| 3 | What if they recompute the hash? | Signature still fails | demo tamper → UNVERIFIED | — |
| 4 | Which algorithms? | Ed25519 (RFC 8032), SHA-256 | `aip-crypto` | PQC reserved, not implemented |
| 5 | Is the encoding deterministic? | Yes, length-prefixed canonical bytes | `canonical.rs` | — |
| 6 | Do you verify embedded delegation signatures too? | Yes — they're covered by the packet hash and re-verified | `DELEGATION_CHAIN` | — |
| 7 | Are actions bound to their decision? | Yes — per-action signature covers the decision_id | `ACTION_ATTESTATIONS` | — |
| 8 | Replay protection? | Generation needs a valid key; verify idempotent; revoked JTIs checked | `REVOCATION` | per-request API nonce window not yet |
| 9 | Hash/sig of the receipt? | Receipt hash bound; counterparty can countersign, bound to decision | `RECEIPT_BINDING` | — |
| 10 | Key sizes/format documented? | Yes | `AIP_SPEC.md` | — |

## B. Authority & authorization

| # | Question | Answer | Evidence | Gap |
|---|---|---|---|---|
| 11 | How do you prove who authorized an action? | Human-rooted, signed delegation chain | `AUTHORITY_CHAIN` | AIP-ID↔employee join is the org's IAM |
| 12 | Can a sub-agent exceed its parent's authority? | No — lattice MEET; child scope ⊆ parent | `aip-core::capability`, `SCOPE_AUTHORITY` | — |
| 13 | Depth limit on delegation? | Yes (max 8) | `aip-core::delegation` | — |
| 14 | How do you revoke authority? | Revoke a token → cascade to its subtree | `aip-core::revocation` | legacy log is global, not tenant-partitioned |
| 15 | Is revocation checked at verification? | Yes, against the verifier's revocation set | `REVOCATION` | — |
| 16 | Can the human principal be impersonated? | Only with their private key; ID binds key+provenance | `AGENT_ID_BINDING` | principal key custody is the org's |
| 17 | Time-bounding of authority? | Tokens carry issue/expiry; checked | `TEMPORAL_VALIDITY` | — |
| 18 | What is "scope"? | Allowed/denied action sets (read/write/…/custom) | `aip-types` | domain vocab is config |
| 19 | Multi-hop chains supported? | Yes, each hop independently verified | 2-hop test passes | — |
| 20 | Who decides trust roots? | The verifier — keys supplied out of band, not by the packet | `VerificationContext` | — |

## C. Security & access control

| # | Question | Answer | Evidence | Gap |
|---|---|---|---|---|
| 21 | Are endpoints authenticated? | Yes (except health/discovery); API keys | `auth.rs` | static keys |
| 22 | How are API secrets stored? | Only SHA-256 hashes; never plaintext | `auth.rs` | — |
| 23 | Roles? | machine / admin; revoke is admin-only | `AdminPrincipal` | finer RBAC later |
| 24 | Default posture with no keys? | Fail closed (401 on all authed routes) | startup warn + tests | — |
| 25 | Key rotation? | Edit key file + restart | — | **no rotation endpoint (P1)** |
| 26 | TLS? | Terminate at ingress/proxy | deploy guide | **not in-service** |
| 27 | Rate limiting / DoS? | — | — | **not implemented (pre-prod)** |
| 28 | HSM/KMS for signing key? | — | — | **not yet (pre-prod)** |
| 29 | Memory safety? | Rust, no GC | whole codebase | — |
| 30 | Independent security assessment? | — | — | **not done (pre-prod)** |

## D. Multi-tenancy & data

| # | Question | Answer | Evidence | Gap |
|---|---|---|---|---|
| 31 | Is data tenant-isolated? | Yes — every record carries a tenant; reads tenant-checked | `vault.rs` tests | — |
| 32 | Can tenant A read tenant B? | No — returns "not found" (no existence leak) | `test_cross_tenant_get_is_denied` | — |
| 33 | Where does the tenant come from? | The API key, never the request body | `auth.rs`, handlers | — |
| 34 | Is evidence deletable? | No — append-only | `vault.rs` | — |
| 35 | Storage backend? | Append-only JSONL file | `vault.rs` | **single node; needs DB+backup (pre-prod)** |
| 36 | Data residency / sovereignty? | Fully on-prem; no foreign cloud in trust path | architecture | — |
| 37 | Is sensitive content stored? | Inputs/payloads referenced by **hash**; content can stay out of the packet | `evidence_packet.rs` | — |
| 38 | Retention policy? | Append-only; org-defined | — | **no retention/immutability tooling yet** |
| 39 | Backup/DR? | — | — | **org-provided in pilot; tooling pre-prod** |
| 40 | PII handling? | Hash-only binding avoids storing PII | design | classification handling is org policy |

## E. Operations, compliance, commercial

| # | Question | Answer | Evidence | Gap |
|---|---|---|---|---|
| 41 | Can we verify without you (vendor)? | Yes — offline, open format/rules | `AIP_SPEC.md`, example | standalone signed verifier binary (P1) |
| 42 | Is the format open / standard? | Spec is open (v0.1-draft); core proprietary | `AIP_SPEC.md` | not yet a recognised standard |
| 43 | Does AIP make decisions / autonomy? | No — records authority & integrity only | scope boundary | — |
| 44 | Availability requirement? | Pilot: non-gating (records, doesn't block txns) | pilot guide | HA not built |
| 45 | Audit export for regulators? | Packets are portable JSON, re-verify identically | `to_json` | **signed export-bundle endpoint (P1)** |
| 46 | Maps to which regs? | Supports EU AI Act/NIST AI RMF traceability, SOX authorization evidence | — | formal control mapping not written |
| 47 | SOC 2 / ISO 27001? | — | — | **none yet** |
| 48 | Monitoring/alerting? | Structured tracing logs | `tracing` | no metrics/SIEM integration yet |
| 49 | IP / licensing? | Core proprietary; provisional patents on audit binding | `reports_and_patents/` | GovPurpose/licence terms TBD |
| 50 | What breaks first at scale? | Per-query authority-graph rebuild + single-file vault | `04_PILOT_READINESS` | incremental index + DB (post-pilot) |
