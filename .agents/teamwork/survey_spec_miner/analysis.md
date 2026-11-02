# AIP Specification Mining & Technical Architecture Analysis
**AIP Enterprise Accountability Console (Syntriass)**
*Discovered by Spec Miner on 2026-11-02*

---

## 1. Executive Summary & Specification Sources

This document provides the authoritative, exhaustive specification for the **AIP Enterprise Accountability Console** (`aip-console`), derived directly from the authoritative Rust reference codebase, formal specifications, and regression test vectors:
- `AIP_SPEC.md` — Normative wire format, canonical encoding, and verification semantics.
- `aip-standalone/aip-protocol/src/` — Reference implementation of `EvidencePacket`, `verify_packet` (14 rules), `TrustFloor` derivation, `AccountabilityGraph`, and `bundle` (`.zip` audit export).
- `aip-standalone/aip-core/src/` — Capability lattice algebra (`scope_intersection`, `is_scope_subset`), delegation chain rules (`verify_delegation_chain`), and append-only cascade revocation (`RevocationLog`).
- `aip-standalone/aip-types/src/lib.rs` — Normative wire data structures, enum definitions, and error codes.
- `aip-standalone/aip-protocol/tests/` and `banking_demo` — End-to-end integration and adversarial tamper test fixtures.
- `aip-service/src/` — Enterprise multi-tenant REST endpoints (`/v1/evidence/verify`, `/v1/evidence/{id}`, `/v1/authority/{id}`, `/v1/evidence/{id}/export`).

---

## 2. Features Discovered

| # | Category | Feature | Description | Inputs | Outputs | Error Behavior | Discovered Via |
|---|----------|---------|-------------|--------|---------|----------------|----------------|
| 1 | Engine Verification | `STRUCTURE` | Validates wire magic ("AEP1"), version (1), non-empty IDs, summary, and actions | `EvidencePacket` header, agent, root authority, decision, actions | `pass: bool`, structural detail string | Fails with `"structural problems: <comma_separated_list>"` | `aip-protocol::verification::check_structure` |
| 2 | Engine Verification | `AGENT_ID_BINDING` | Validates agent AIP-ID format/checksum and cryptographic derivation from `(public_key, provenance)` | `agent.aip_id`, `agent.public_key`, `agent.provenance` | `pass: bool`, binding detail string | Fails with `"agent AIP-ID fails format/checksum validation"` or `"agent AIP-ID ... does not match derived ID ..."` | `aip-protocol::verification` line 102 |
| 3 | Engine Verification | `CANONICAL_HASH` | Recomputes SHA-256 of deterministic canonical byte stream and compares to `packet_hash` | `packet.canonical_bytes()`, `packet.packet_hash` | `pass: bool`, detail; sets `tamper_evidence = true` if false | Fails with `"packet_hash mismatch: stored ... recomputed ... — packet modified after sealing"` | `aip-protocol::verification` line 120 |
| 4 | Engine Verification | `AGENT_SIGNATURE` | Verifies agent Ed25519 signature over recomputed canonical bytes | `packet.agent_sig`, `agent.aip_id`, `agent.public_key`, canonical bytes | `pass: bool`, detail; sets `tamper_evidence = true` if false | Fails with signer mismatch, payload mismatch, or `"agent signature cryptographic verification failed"` | `aip-protocol::verification` line 138 |
| 5 | Engine Verification | `ROOT_TOKEN_SIGNATURE` | Verifies principal's Ed25519 signature on root scoped token using caller-trusted key | `root_authority.root_token`, `ctx.issuer_public_keys` | `pass: bool`, detail; sets `tamper_evidence = true` if trusted key present but sig invalid | Fails with `"no trusted public key for root issuer ..."` (gap) or `"root token signature verification failed"` (tamper) | `aip-protocol::verification` line 162 |
| 6 | Engine Verification | `DELEGATION_CHAIN` | Verifies all hops: per-hop Ed25519 signature, JTI linkage, depth monotonicity, scope subset | `root_token`, `delegation_chain`, `ctx.issuer_public_keys` | `pass: bool`, effective `CapabilityScope`; sets `tamper_evidence = true` (unless missing key) | Fails with `"delegation chain invalid: <err>"` (e.g. `AttenuationViolation`, `LineageInvalid`, `SignatureInvalid`) | `aip-protocol::verification` line 192 |
| 7 | Engine Verification | `AUTHORITY_CHAIN` | Verifies organizational connectivity: principal -> root token -> delegation hops -> acting agent | `root_authority`, `delegation_chain`, `agent.aip_id` | `pass: bool`, path detail string | Fails on issuer mismatch, broken handoff, or leaf grantee not equal to acting agent | `aip-protocol::verification::check_authority_chain` |
| 8 | Engine Verification | `SCOPE_AUTHORITY` | Verifies decision and every action fall within the effective (most-attenuated) scope | `decision.action_kind`, `actions[*].action_kind`, `effective_scope` | `pass: bool`, detail string | Fails if decision or action outside scope or if delegation chain failed | `aip-protocol::verification::check_scope_authority` |
| 9 | Engine Verification | `REVOCATION` | Checks every JTI (root token and delegation hops) against verifier's revocation set | `root_token.jti`, `delegation_chain[*].jti`, `ctx.revoked_jtis` | `pass: bool`, revoked token list | Fails with `"revoked tokens in chain: <list>"` (packet invalid, but `tampered` is false) | `aip-protocol::verification` line 232 |
| 10 | Engine Verification | `TEMPORAL_VALIDITY` | Verifies decided/performed timestamps fall within token issuance/expiry windows; actions >= decision | `decision.decided_at`, `actions[*].performed_at`, token `issued_at`/`expires_at` | `pass: bool`, temporal detail string | Fails if decision predates issuance, decision/action expired, or action predates decision | `aip-protocol::verification::check_temporal_validity` |
| 11 | Engine Verification | `ACTION_ATTESTATIONS` | Verifies each action's individual Ed25519 signature and hash binding to `decision_id` | `actions[*]`, `decision.decision_id`, `agent.aip_id`, `agent.public_key` | `pass: bool`, detail; sets `tamper_evidence = true` if false | Fails with signer mismatch, payload mismatch, or signature verification failure | `aip-protocol::verification::check_action_attestations` |
| 12 | Engine Verification | `TRACE_BINDING` | Optional external execution trace binding (W3C trace ID + SHA-256 hash) cross-checked against data | `trace_binding`, `ctx.trace_data` | `pass: bool`, detail; sets `tamper_evidence = true` on data mismatch | Fails if empty `trace_id` or if `trace_data` hash does not match `trace_hash` | `aip-protocol::verification::check_trace_binding` |
| 13 | Engine Verification | `RECEIPT_BINDING` | Optional external system receipt hash binding; verifies bilateral counterparty countersignature | `receipt_binding`, `ctx.receipt_data`, `ctx.counterparty_public_keys`, `decision.decision_id` | `pass: bool`, `countersigned: bool`; sets `tamper_evidence = true` on mismatch | Fails on hash mismatch, missing counterparty key, payload mismatch, or invalid signature | `aip-protocol::verification::check_receipt_binding` |
| 14 | Engine Verification | `TRUST_FLOOR` | Derives supported trust floor from actual rule evaluations; verifies claimed floor does not exceed it | `derived_floor` (0..3), `packet.claimed_trust_floor` | `pass: bool`, detail string comparing floors | Fails with `"claimed floor <Claimed> exceeds what the evidence supports (<Derived>)"` | `aip-protocol::verification` line 265 |
| 15 | Graph Architecture | Interactive DAG Reconstruction | Reconstructs DAG: Principal -> AuthorityGrant -> Delegation* -> Agent -> Decision -> Action+ -> Receipt? | `EvidencePacket`, optional `VerificationReport` | `AccountabilityGraph` (nodes, edges, claimed/derived floor) | Validates single principal root and reachability of all nodes via BFS/DFS (`validate_chain`) | `aip-protocol::accountability_graph` |
| 16 | Graph Architecture | Graphviz DOT Export | Exports accountability graph into formatted DOT digraph syntax for visual renderers | `AccountabilityGraph` | String (Graphviz DOT format) | Returns valid DOT string with designated node shapes (house, note, cds, component, diamond, box, tab) | `aip-protocol::accountability_graph::to_dot` |
| 17 | Audit Bundle | Audit ZIP Ingestion & Verification | Portable signed ZIP containing evidence, reports (JSON/MD), graphs (JSON/DOT), manifest, signature | ZIP byte array, `VerificationContext` | `BundleVerification` (`overall`: PASS/WARNING/FAIL, checks list) | Evaluates 7 bundle checks: `BUNDLE_STRUCTURE`, `MANIFEST_PARSE`, `FILE_HASHES`, `BUNDLE_HASH`, `BUNDLE_SIGNATURE`, `EVIDENCE_INTEGRITY`, `PACKET_VERIFICATION` | `aip-protocol::bundle::verify_zip` |
| 18 | Audit Bundle | Audit ZIP Export | Generates signed audit-export `.zip` with SHA-256 manifest and Ed25519 bundle signature | `tenant_id`, `EvidencePacket`, `VerificationReport`, signer keypair | ZIP binary bytes (`Vec<u8>`) | Errors on serialization, zip write, or crypto failure | `aip-protocol::bundle::build_zip` |
| 19 | Capability Engine | Lattice Scope Intersection (MEET) | Computes `Parent ⊓ Child` scope; intersection of allowed sets, union of denied sets | `parent: CapabilityScope`, `child: CapabilityScope` | `Option<CapabilityScope>` (None if allowed is empty: $\bot$) | Returns `None` (empty intersection $\bot$), rejecting illegal delegation expansion | `aip-core::capability::scope_intersection` |
| 20 | Capability Engine | Built-in Named Scopes | Hierarchy: ADMIN ⊇ ORCHESTRATOR ⊇ AUDIT_READER ⊇ SUBMITTER | None | `CapabilityScope` structs | Enforces least-privilege capability bounds | `aip-core::capability` |
| 21 | Delegation Engine | N-hop Delegation Chain Creation | Creates cryptographically chained delegation tokens up to depth 8 with parent JTI linkage | `parent_token`, `issuer_private_key`, `grantee_id`, `requested_scope` | `DelegationToken` with Ed25519 `issuer_sig` | `AttenuationViolation` if child exceeds parent; `LineageInvalid` if depth >= 8 | `aip-core::delegation` |
| 22 | Revocation Engine | Cascade Revocation Propagation | Append-only hash-chained revocation log; walks delegation tree to cascade revoke all child JTIs | `jti: [u8; 16]`, `reason: RevocationReason`, `cascade: bool`, `DelegationLog` | `Vec<RevocationEntry>` (chained by SHA-256) | Recursively invalidates full subtree; records `AdminRevocation` for descendants | `aip-core::revocation` |
| 23 | Service REST API | `/v1/evidence/verify` | Headless HTTP verification of EvidencePacket against caller-supplied trust keys | JSON `VerifyRequest` | JSON `VerificationReport` | 400 Bad Request on invalid JSON or bad hex formatting | `aip-service::evidence::verify` |
| 24 | Service REST API | `/v1/evidence/{id}` | Multi-tenant fetch of stored EvidencePacket by 32-character hex ID | `id: String`, `Principal` (tenant auth) | JSON `EvidencePacket` | 404 Not Found if missing or belongs to another tenant (no existence leak) | `aip-service::evidence::get_evidence` |
| 25 | Service REST API | `/v1/authority/{id}` | Query authority path and graph by action ID, principal ID, or agent ID | `id: String`, `Principal` | JSON `AuthorityResponse` (path, DOT, packet lists) | Returns empty lists/None if unknown; 200 OK | `aip-service::evidence::get_authority` |
| 26 | Service REST API | `/v1/evidence/{id}/export` | Download signed audit-export ZIP bundle | `id: String`, `Principal` | Binary `application/zip` response | 404 Not Found on cross-tenant or missing packet | `aip-service::evidence::export_evidence` |

---

## 3. Edge Cases

| # | Feature | Input | Observed Behavior |
|---|---------|-------|-------------------|
| 1 | `STRUCTURE` | Empty `actions` list (`actions: []`) | Fails with `"structural problems: no action attestations"`. A packet must contain at least 1 action. |
| 2 | `STRUCTURE` | Empty `summary` in decision record | Fails with `"structural problems: empty decision summary"`. |
| 3 | `STRUCTURE` | Corrupted magic bytes (`b"BAD1"`) or version `2` | Fails with `"structural problems: bad magic"` or `"unsupported version"`. |
| 4 | `AGENT_ID_BINDING` | Modified provenance commitment (e.g. model hash flipped) | Recomputed AIP-ID differs from `agent.aip_id`; fails with `"agent AIP-ID ... does not match derived ID ..."`. |
| 5 | `AGENT_ID_BINDING` | Agent AIP-ID with invalid base58 checksum | Fails with `"agent AIP-ID fails format/checksum validation"`. |
| 6 | `CANONICAL_HASH` | Any single byte mutated in payload after sealing | `recomputed != packet.packet_hash`; fails with detailed mismatch message; sets `tamper_evidence = true`. |
| 7 | `AGENT_SIGNATURE` | Smart attacker recalculates `packet_hash` to match mutated payload | `CANONICAL_HASH` passes, but `sig.payload_hash != recomputed` and Ed25519 fails; sets `tamper_evidence = true`. |
| 8 | `ROOT_TOKEN_SIGNATURE` | Root issuer public key not supplied in `ctx.issuer_public_keys` | Fails with `"no trusted public key for root issuer ..."`; does NOT set `tamper_evidence` (classified as verifiability gap). |
| 9 | `ROOT_TOKEN_SIGNATURE` | Root token signature corrupted under a trusted key | Fails with `"root token signature verification failed"`; sets `tamper_evidence = true`. |
| 10 | `DELEGATION_CHAIN` | Intermediate delegation hop scope expanded beyond parent | Fails with `AttenuationViolation`; sets `tamper_evidence = true`. |
| 11 | `DELEGATION_CHAIN` | Chain depth exceeds `MAX_DELEGATION_DEPTH` (8 hops) | Fails with `LineageInvalid`; sets `tamper_evidence = true`. |
| 12 | `AUTHORITY_CHAIN` | Empty delegation chain, but root token grantee is not acting agent | Fails with `"root token holder ... is not the acting agent ..."`. |
| 13 | `AUTHORITY_CHAIN` | Broken handoff: `hop[1].issuer_id != hop[0].grantee_id` | Fails with `"broken handoff: hop issuer ... is not previous grantee ..."`. |
| 14 | `SCOPE_AUTHORITY` | Agent executes `Action::Delete` when effective scope is Write-only | Fails with `"action ... performs Standard(Delete) outside the effective scope"`. |
| 15 | `REVOCATION` | Root token JTI or delegation hop JTI present in `revoked_jtis` | Fails with `"revoked tokens in chain: ..."`; marks `revocation_clear = false`, but `tampered = false`. |
| 16 | `TEMPORAL_VALIDITY` | Decision timestamp `decided_at` predates token `issued_at` | Fails with `"decision predates issuance of <token>"`. |
| 17 | `TEMPORAL_VALIDITY` | Action performed prior to authorizing decision (`performed_at < decided_at`) | Fails with `"action ... performed before its authorizing decision"`. |
| 18 | `ACTION_ATTESTATIONS` | Action attestation transplanted to another decision record | Recomputed payload includes `decision_id`; signature check fails; sets `tamper_evidence = true`. |
| 19 | `TRACE_BINDING` | Trace binding present with valid ID, but no external trace data supplied | Passes with note: `"trace binding present ...; no external trace data supplied to cross-check"`. |
| 20 | `TRACE_BINDING` | Supplied external trace bytes hash to different SHA-256 | Fails with `"supplied trace data does NOT match the bound trace_hash"`; sets `tamper_evidence = true`. |
| 21 | `RECEIPT_BINDING` | Receipt present without countersignature (hash only) | Passes with floor eligible up to `AUTHORITY_BOUND`, but not `COUNTERPARTY_SIGNED`. |
| 22 | `RECEIPT_BINDING` | `counterparty_id` provided without `counterparty_sig` (or vice versa) | Fails with `"counterparty id/signature must be present together"`. |
| 23 | `TRUST_FLOOR` | Packet claims `COUNTERPARTY_SIGNED` but receipt is uncountersigned | Derived floor is `AUTHORITY_BOUND`; fails with `"claimed floor CounterpartySigned exceeds what the evidence supports (AuthorityBound)"`. |
| 24 | Graph Connectivity | Disconnected delegation or orphan action node in graph | `validate_chain()` detects unvisited nodes; returns `"node ... is not reachable from the principal"`. |
| 25 | Audit Bundle | File in ZIP modified without updating manifest | `FILE_HASHES` fails with `"<file> hash mismatch (tampered)"`. |
| 26 | Audit Bundle | Manifest modified without valid re-signature | `BUNDLE_SIGNATURE` fails with `"bundle signature invalid — manifest not signed by the embedded key"`. |

---

## 4. Section 1: The 14 Verification Rules of the AIP Engine

The AIP verification engine (`aip-protocol::verification::verify_packet`) is strictly normative and non-short-circuiting: every rule is evaluated for every packet, ensuring that an auditor receives a complete, non-truncated audit record.

```
                           ┌────────────────────────┐
                           │   EvidencePacket v1    │
                           └───────────┬────────────┘
                                       │
                    ┌──────────────────┴──────────────────┐
                    ▼                                     ▼
        [Agent Level Verification]            [Authority Level Verification]
        R1. STRUCTURE                         R5. ROOT_TOKEN_SIGNATURE
        R2. AGENT_ID_BINDING                  R6. DELEGATION_CHAIN
        R3. CANONICAL_HASH                    R7. AUTHORITY_CHAIN
        R4. AGENT_SIGNATURE                   R8. SCOPE_AUTHORITY
                    │                         R9. REVOCATION
                    ▼                         R10. TEMPORAL_VALIDITY
        [Level 1: AGENT_SIGNED]               R11. ACTION_ATTESTATIONS
                    │                                     │
                    └──────────────────┬──────────────────┘
                                       ▼
                          [Level 2: AUTHORITY_BOUND]
                                       │
                      ┌────────────────┴────────────────┐
                      ▼                                 ▼
           R12. TRACE_BINDING                 R13. RECEIPT_BINDING
                      │                                 │
                      └────────────────┬────────────────┘
                                       ▼
                       [Level 3: COUNTERPARTY_SIGNED]
                                       │
                                       ▼
                             R14. TRUST_FLOOR
```

### Detailed Rule Breakdown

#### Rule 1: `STRUCTURE`
- **Identifier**: `STRUCTURE`
- **Inputs**: `packet.magic`, `packet.version`, `packet.agent.aip_id`, `packet.root_authority.principal_id`, `packet.decision.summary`, `packet.actions`
- **Logic**:
  - `packet.magic == [0x41, 0x45, 0x50, 0x31]` (`"AEP1"`)
  - `packet.version == 1`
  - `!packet.agent.aip_id.is_empty()`
  - `!packet.root_authority.principal_id.is_empty()`
  - `!packet.decision.summary.is_empty()`
  - `!packet.actions.is_empty()` (at least one action attestation must exist)
- **Success Output**: `"AEP1 v1 structure valid: {delegation_chain.len()} delegation hop(s), {actions.len()} action(s)"`
- **Failure Output**: `"structural problems: {problems.join(', ')}"`
- **Tamper Evidence**: `false` (structural failure)

#### Rule 2: `AGENT_ID_BINDING`
- **Identifier**: `AGENT_ID_BINDING`
- **Inputs**: `packet.agent.aip_id`, `packet.agent.public_key.key_bytes`, `packet.agent.provenance`
- **Logic**:
  - Validates Base58 checksum: `validate_aip_id(aip_id) == Ok(())`
  - Derives expected ID: `derived = derive_aip_id(public_key, provenance)`
  - Verifies: `derived == packet.agent.aip_id`
  - Derivation algorithm: `AIP-ID = "aip1" || base58(SHA-256(pubkey || provenance)[0..26]) || base58(checksum)`
- **Success Output**: `"agent AIP-ID derives from embedded public key and provenance"`
- **Failure Output**:
  - Format/checksum error: `"agent AIP-ID fails format/checksum validation"`
  - Cryptographic mismatch: `"agent AIP-ID {aip_id} does not match derived ID {derived}"`
- **Tamper Evidence**: `false` (binding discrepancy, but identity unverified)

#### Rule 3: `CANONICAL_HASH`
- **Identifier**: `CANONICAL_HASH`
- **Inputs**: `packet.canonical_bytes()`, `packet.packet_hash`
- **Logic**:
  - Computes `recomputed = SHA-256(packet.canonical_bytes())`
  - Canonical bytes deterministically serialize header, agent identity, root authority, delegation chain, decision, action attestations (with action signatures), trace binding, receipt binding, and claimed trust floor (excluding `packet_hash` and `agent_sig`).
  - Verifies: `recomputed == packet.packet_hash`
- **Success Output**: `"recomputed canonical hash matches packet_hash"`
- **Failure Output**: `"packet_hash mismatch: stored {hex} recomputed {hex} — packet modified after sealing"`
- **Tamper Evidence**: `true` (direct evidence of post-signing tampering)

#### Rule 4: `AGENT_SIGNATURE`
- **Identifier**: `AGENT_SIGNATURE`
- **Inputs**: `packet.agent_sig`, `packet.agent.aip_id`, `packet.agent.public_key.key_bytes`, recomputed canonical hash
- **Logic**:
  - Check signer: `agent_sig.signer_id == packet.agent.aip_id`
  - Check payload hash: `agent_sig.payload_hash == recomputed`
  - Verify Ed25519 signature: `verify_ed25519(agent_public_key, agent_sig) == Ok(true)`
- **Success Output**: `"agent packet signature verifies over canonical bytes"`
- **Failure Output**:
  - Signer mismatch: `"signature signer_id {signer} is not the packet agent {agent}"`
  - Payload mismatch: `"signature payload hash does not cover current packet contents"`
  - Crypto error: `"agent signature cryptographic verification failed"`
- **Tamper Evidence**: `true`

#### Rule 5: `ROOT_TOKEN_SIGNATURE`
- **Identifier**: `ROOT_TOKEN_SIGNATURE`
- **Inputs**: `packet.root_authority.root_token`, `ctx.issuer_public_keys`
- **Logic**:
  - Looks up `ctx.issuer_public_keys.get(root_token.issuer_id)`
  - If key missing: returns `false` with verifiability gap notice.
  - If key present: computes canonical token payload `canonical_token_payload(jti, issuer_id, agent_id, scope, issued_at)` and verifies Ed25519 signature `root_token.issuer_sig`.
- **Success Output**: `"root token signed by trusted issuer {issuer_id}"`
- **Failure Output**:
  - Missing key: `"no trusted public key for root issuer {issuer_id}"` (tamper: `false`)
  - Bad signature: `"root token signature verification failed"` (tamper: `true`)
- **Tamper Evidence**: `true` if trusted key exists and signature fails; `false` if untrusted key.

#### Rule 6: `DELEGATION_CHAIN`
- **Identifier**: `DELEGATION_CHAIN`
- **Inputs**: `root_authority.root_token`, `delegation_chain`, `ctx.issuer_public_keys`
- **Logic**:
  - Calls `aip_core::delegation::verify_delegation_chain`.
  - For hop 0: `parent_jti == root_token.jti`, `depth == 1`, `scope ⊆ root_token.scope`.
  - For hop $i \in [1, n-1]$: `hop[i].parent_jti == hop[i-1].jti`, `hop[i].depth == hop[i-1].depth + 1`, `hop[i].scope ⊆ hop[i-1].scope`.
  - Max depth check: `chain.len() < 8`.
  - Each hop's `issuer_sig` is verified against `ctx.issuer_public_keys.get(hop.issuer_id)`.
  - Returns effective leaf scope: `effective_scope`.
- **Success Output**: `"{n}-hop delegation chain verified (per-hop signatures, JTI linkage, depth, scope attenuation)"`
- **Failure Output**: `"delegation chain invalid: {error}"` (e.g. `AttenuationViolation`, `LineageInvalid`, `SignatureInvalid`)
- **Tamper Evidence**: `true` for all errors except `InvalidPublicKey`.

#### Rule 7: `AUTHORITY_CHAIN`
- **Identifier**: `AUTHORITY_CHAIN`
- **Inputs**: `root_authority`, `delegation_chain`, `agent.aip_id`
- **Logic**:
  - Root issuer check: `root_token.issuer_id == root_authority.principal_id`.
  - If delegation chain is empty: `root_token.agent_id == agent.aip_id`.
  - If delegation chain is non-empty:
    - First hop: `delegation_chain[0].issuer_id == root_token.agent_id`.
    - Intermediate handoffs: `delegation_chain[i].issuer_id == delegation_chain[i-1].grantee_id` for all consecutive hops.
    - Leaf grantee: `delegation_chain.last().grantee_id == agent.aip_id`.
- **Success Output**: `"authority chain connects principal {principal_id} to acting agent {agent_id}"`
- **Failure Output**: Semicolon-separated connection violations.
- **Tamper Evidence**: `false`

#### Rule 8: `SCOPE_AUTHORITY`
- **Identifier**: `SCOPE_AUTHORITY`
- **Inputs**: `decision.action_kind`, `actions[*].action_kind`, `effective_scope`
- **Logic**:
  - If `effective_scope` is `None` (delegation chain failed), fails immediately with `"no effective scope available (delegation chain failed verification)"`.
  - Verifies: `scope_permits(effective_scope, &decision.action_kind)` is true.
  - Verifies: `scope_permits(effective_scope, &action.action_kind)` is true for every action.
- **Success Output**: `"decision and all actions fall within the effective (most-attenuated) scope"`
- **Failure Output**: Semicolon-separated list of prohibited actions.
- **Tamper Evidence**: `false`

#### Rule 9: `REVOCATION`
- **Identifier**: `REVOCATION`
- **Inputs**: `root_token.jti`, `delegation_chain[*].jti`, `ctx.revoked_jtis`
- **Logic**:
  - Inspects `ctx.revoked_jtis.contains(&root_token.jti)`.
  - Inspects `ctx.revoked_jtis.contains(&hop.jti)` for every hop in the chain.
- **Success Output**: `"no token in the authority chain is revoked"`
- **Failure Output**: `"revoked tokens in chain: {revoked_list.join(', ')}"`
- **Tamper Evidence**: `false` (revocation causes packet invalidity, not tamper classification)

#### Rule 10: `TEMPORAL_VALIDITY`
- **Identifier**: `TEMPORAL_VALIDITY`
- **Inputs**: `decision.decided_at`, `actions[*].performed_at`, token `issued_at` and `expires_at`
- **Logic**:
  - For root token and all delegation hops:
    - `decision.decided_at >= token.issued_at` (decision cannot predate token issuance).
    - If `token.expires_at.is_some()`: `decision.decided_at <= token.expires_at` and `action.performed_at <= token.expires_at` for all actions.
  - For all actions: `action.performed_at >= decision.decided_at` (action cannot precede authorizing decision).
- **Success Output**: `"decision and actions fall within the validity window of every token in the chain"`
- **Failure Output**: Semicolon-separated list of temporal violations.
- **Tamper Evidence**: `false`

#### Rule 11: `ACTION_ATTESTATIONS`
- **Identifier**: `ACTION_ATTESTATIONS`
- **Inputs**: `actions[*]`, `decision.decision_id`, `agent.aip_id`, `agent.public_key`
- **Logic**:
  - For each `action`:
    - Check signer: `action.agent_sig.signer_id == agent.aip_id`.
    - Compute payload: `canonical_bytes = action.canonical_bytes(&decision.decision_id)` (covers `decision_id`, `action_id`, `action_kind`, `description`, `payload_hash`, `performed_at`).
    - Check payload hash: `action.agent_sig.payload_hash == SHA-256(canonical_bytes)`.
    - Verify Ed25519 signature: `verify_ed25519(agent_public_key, &action.agent_sig) == Ok(true)`.
- **Success Output**: `"all {actions.len()} action attestation(s) signed by the agent and bound to decision {decision_id_hex}"`
- **Failure Output**: Semicolon-separated list of action signature failures.
- **Tamper Evidence**: `true`

#### Rule 12: `TRACE_BINDING`
- **Identifier**: `TRACE_BINDING`
- **Inputs**: `packet.trace_binding`, `ctx.trace_data`
- **Logic**:
  - If `trace_binding` is `None`: passes optionally (detail: `"no trace binding present (optional)"`).
  - If `trace_binding` is `Some(t)` and `ctx.trace_data` is `None`: passes if `!t.trace_id.is_empty()`.
  - If `trace_binding` is `Some(t)` and `ctx.trace_data` is `Some(data)`: verifies `SHA-256(data) == t.trace_hash` and `!t.trace_id.is_empty()`.
- **Success Output**: `"supplied trace data hashes to the bound trace_hash for {trace_id}"` or `"trace binding present ...; no external trace data supplied"`
- **Failure Output**: `"supplied trace data does NOT match the bound trace_hash"`
- **Tamper Evidence**: `true` on hash mismatch.

#### Rule 13: `RECEIPT_BINDING`
- **Identifier**: `RECEIPT_BINDING`
- **Inputs**: `packet.receipt_binding`, `ctx.receipt_data`, `ctx.counterparty_public_keys`, `decision.decision_id`
- **Logic**:
  - If `None`: passes optionally (detail: `"no receipt binding present (optional)"`).
  - If `Some(r)`:
    - Verifies `!r.receipt_system.is_empty()` and `!r.receipt_id.is_empty()`.
    - If `ctx.receipt_data` is supplied: checks `SHA-256(receipt_data) == r.receipt_hash`.
    - If `counterparty_id` and `counterparty_sig` are both `Some`:
      - Verifies `counterparty_sig.signer_id == counterparty_id`.
      - Looks up `ctx.counterparty_public_keys.get(counterparty_id)`.
      - Recomputes receipt payload: `canonical_receipt_payload(&decision.decision_id)` (covers `decision_id`, `receipt_system`, `receipt_id`, `receipt_hash`).
      - Verifies `counterparty_sig.payload_hash == SHA-256(payload)`.
      - Verifies Ed25519 signature under trusted key.
      - Marks `countersigned = true`.
- **Success Output**: `"receipt {receipt_id} @ {receipt_system} countersigned by {counterparty_id}"` (or `"bound by hash (no countersignature)"`)
- **Failure Output**: Semicolon-separated list of receipt binding issues.
- **Tamper Evidence**: `true` on hash mismatch or invalid signature under trusted key.

#### Rule 14: `TRUST_FLOOR`
- **Identifier**: `TRUST_FLOOR`
- **Inputs**: `derived_floor`, `packet.claimed_trust_floor`
- **Logic**:
  - Computes `derived_floor` per §5 below.
  - Verifies: `derived_floor >= packet.claimed_trust_floor`.
- **Success Output**: `"derived floor {derived:?} supports claimed floor {claimed:?}"`
- **Failure Output**: `"claimed floor {claimed:?} exceeds what the evidence supports ({derived:?})"`
- **Tamper Evidence**: `false`

---

## 5. Section 2: Trust Floor Progression Mechanics

Trust Floors provide a mathematically ordered trust ladder. Verifiers derive the floor independently from evidence; a packet's claim is verified against the derived floor.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Level 3: COUNTERPARTY_SIGNED (Assurance: Full Bilateral Enterprise)         │
│ Requires: AUTHORITY_BOUND + verified external counterparty countersignature │
├─────────────────────────────────────────────────────────────────────────────┤
│ Level 2: AUTHORITY_BOUND (Assurance: Organizational Authorization)          │
│ Requires: AGENT_SIGNED + verified root token + delegation chain + scope MEET│
│           + revocation clearance + temporal validity + action attestations  │
├─────────────────────────────────────────────────────────────────────────────┤
│ Level 1: AGENT_SIGNED (Assurance: Cryptographic Integrity)                  │
│ Requires: STRUCTURE + AGENT_ID_BINDING + CANONICAL_HASH + AGENT_SIGNATURE   │
├─────────────────────────────────────────────────────────────────────────────┤
│ Level 0: UNVERIFIED (Assurance: None)                                       │
│ Default parse state or failure in any Layer 1 integrity rule                │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Exact Mathematical Transition Prerequisites

1. **`UNVERIFIED` (0)**:
   - Base state. Assigned if any of `STRUCTURE`, `AGENT_ID_BINDING`, `CANONICAL_HASH`, or `AGENT_SIGNATURE` fails.

2. **`AGENT_SIGNED` (1)**:
   - Condition:
     $$\text{agent\_signed} \iff \text{STRUCTURE} \land \text{AGENT\_ID\_BINDING} \land \text{CANONICAL\_HASH} \land \text{AGENT\_SIGNATURE}$$
   - Guarantees: The agent's identity derives correctly from its key/provenance, the payload has not been modified since sealing, and the agent signed the exact bytes.

3. **`AUTHORITY_BOUND` (2)**:
   - Condition:
     $$\begin{aligned}
     \text{authority\_bound} \iff & \text{agent\_signed} \land \text{ROOT\_TOKEN\_SIGNATURE} \land \text{DELEGATION\_CHAIN} \\
     & \land \text{AUTHORITY\_CHAIN} \land \text{SCOPE\_AUTHORITY} \land \text{REVOCATION} \\
     & \land \text{TEMPORAL\_VALIDITY} \land \text{ACTION\_ATTESTATIONS}
     \end{aligned}$$
   - Guarantees: The action was authorized by the declared human principal, through a validly attenuated delegation chain, within permissible validity windows, with zero revoked tokens, and each action is bound to the decision.

4. **`COUNTERPARTY_SIGNED` (3)**:
   - Condition:
     $$\text{counterparty\_signed} \iff \text{authority\_bound} \land \text{RECEIPT\_BINDING} \land \text{receipt\_countersigned}$$
   - Guarantees: Full bilateral accountability; an independent external system (e.g., core bank, clearinghouse, database) has countersigned the receipt for the action under the same `decision_id`.

---

## 6. Section 3: R2 Interactive Accountability Graph Specification

From every `EvidencePacket`, the console derives an interactive Directed Acyclic Graph (DAG) visualizing the full accountability chain:

```
[Principal] ──Issues──▶ [AuthorityGrant] ──Delegates──▶ [Delegation Hop(s)] ──ActsUnder──▶ [Agent]
                                                                                              │
                                                                                           Decides
                                                                                              │
                                                                                              ▼
                                              [Receipt] ◀──Produces── [Action Attestation(s)] ◀──Performs── [Decision]
```

### Node Schemas & Verification Badges

| Node Kind | ID Convention | Visual Shape | Graphviz Shape | Core Display Label | Inspection Panel Fields | Cryptographic Verification Badges |
|---|---|---|---|---|---|---|
| `Principal` | `principal` | House / Executive Shield | `house` | `{display_role} ({principal_id})` | `principal_id`, `display_role`, root token issuer key fingerprint | `[ROOT ISSUER TRUSTED]` (green) or `[UNTRUSTED ROOT]` (amber) |
| `AuthorityGrant` | `authority_grant` | Note / Certificate | `note` | `root token {jti[0..8]} → {agent_id}` | `jti`, `issuer_id`, `agent_id`, `scope.allowed`, `scope.denied`, `issued_at`, `expires_at`, `issuer_sig` | `[SIG VALID]` (green), `[EXPIRED]` (red), `[REVOKED]` (red) |
| `Delegation` | `delegation:{i}` | CDS / Delegation Hop | `cds` | `hop {i} (depth {depth}): {issuer_id} → {grantee_id}` | `jti`, `parent_jti`, `issuer_id`, `grantee_id`, `scope`, `depth`, `issued_at`, `expires_at`, `issuer_sig` | `[ATTENUATION OK]` (green), `[LINKAGE OK]` (green), `[HOP SIG]` (green) |
| `Agent` | `agent` | Component / Microchip | `component` | `{agent.aip_id}` | `aip_id`, `algorithm`, `public_key` (hex), `provenance` (model, environment, toolchain SHA-256 hashes) | `[AIP-ID BOUND]` (green), `[PROVENANCE VALID]` (green) |
| `Decision` | `decision` | Diamond / Brain Core | `diamond` | `{decision.summary}` | `decision_id`, `action_kind`, `summary`, `input_hash`, `rationale_hash`, `decided_at` | `[SCOPE PERMITTED]` (green), `[BOUND BY HASH]` (green) |
| `Action` | `action:{i}` | Box / Terminal Action | `box` | `{action.description}` | `action_id`, `action_kind`, `description`, `payload_hash`, `performed_at`, `agent_sig` | `[PER-ACTION SIG]` (green), `[DECISION BOUND]` (green), `[IN SCOPE]` (green) |
| `Receipt` | `receipt` | Tab / Ledger Stamp | `tab` | `{receipt_id} @ {receipt_system}` | `receipt_system`, `receipt_id`, `receipt_hash`, `counterparty_id`, `counterparty_sig` | `[COUNTERSIGNED]` (emerald) or `[HASH ONLY]` (sky blue) |

### Graph Edge Relations
1. `Relation::Issues`: From `principal` to `authority_grant`.
2. `Relation::Delegates`: From `authority_grant` to `delegation:0`, and `delegation:i` to `delegation:i+1`.
3. `Relation::ActsUnder`: From leaf delegation (or `authority_grant` if empty chain) to `agent`.
4. `Relation::Decides`: From `agent` to `decision`.
5. `Relation::Performs`: From `decision` to each `action:i`.
6. `Relation::Produces`: From each `action:i` to `receipt`.

### Chain Connectivity Invariant
A valid accountability graph must have **exactly 1 Principal node** and **every node must be reachable from that Principal** via breadth-first search (`validate_chain()`). Any unreachable node indicates an orphaned action or broken delegation link.

---

## 7. Section 4: R3 Adversarial Tamper Simulator Specification

The Adversarial Tamper Simulator provides an interactive sandbox enabling security analysts and auditors to inject mutations into any valid `EvidencePacket` and observe real-time verification engine failure feedback.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ADVERSARIAL TAMPER SANDBOX                          │
│                                                                             │
│  [ Preset Attack Vectors ]                                                  │
│  ┌───────────────────────┐ ┌───────────────────────┐ ┌───────────────────┐  │
│  │ 1. Decision Summary   │ │ 2. Action Payload     │ │ 3. Scope Escalation│ │
│  └───────────────────────┘ └───────────────────────┘ └───────────────────┘  │
│  ┌───────────────────────┐ ┌───────────────────────┐ ┌───────────────────┐  │
│  │ 4. Identity Hijack    │ │ 5. Receipt Tampering  │ │ 6. Temporal Expiry│ │
│  └───────────────────────┘ └───────────────────────┘ └───────────────────┘  │
│                                                                             │
│  [ Mutation Controls ]                                                      │
│  Payload Field: [ decision.summary                       ▼ ]                │
│  Original:      "Approve vendor payment INV-2026-0142 for $48,200.00"       │
│  Tampered:      "Approve vendor payment INV-2026-0142 for $4,820,000.00"    │
│                                                                             │
│  [ ] Recalculate packet_hash (Smart Attacker / Hash-Fixing Simulation)      │
│                                                                             │
│  [ Real-Time Engine Feedback ]                                              │
│  ❌ OVERALL STATUS: TAMPERED & INVALID (Derived Floor: UNVERIFIED)           │
│  ├─ ❌ CANONICAL_HASH: packet_hash mismatch (stored ... recomputed ...)      │
│  ├─ ❌ AGENT_SIGNATURE: signature payload hash does not cover current bytes │
│  └─ ❌ TRUST_FLOOR: claimed floor CounterpartySigned exceeds Unverified    │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Mutation Vector Matrix & Expected Engine Failures

| Attack Vector | Field Mutated | Mutation Action | Expected Rule Failures | Tamper Evidence Flag |
|---|---|---|---|---|
| **Payload Tampering (Simple)** | `decision.summary` | Alter amount or recipient string | `CANONICAL_HASH`, `AGENT_SIGNATURE`, `TRUST_FLOOR` | `true` |
| **Smart Attacker (Hash Fixing)** | `decision.summary` + `packet_hash` | Alter amount + recompute `packet_hash` | `AGENT_SIGNATURE`, `TRUST_FLOOR` (`CANONICAL_HASH` passes) | `true` |
| **Action Payload Modification** | `actions[0].payload_hash` | Replace with random SHA-256 hash | `CANONICAL_HASH`, `AGENT_SIGNATURE`, `ACTION_ATTESTATIONS`, `TRUST_FLOOR` | `true` |
| **Action Context Transplant** | `actions[0].agent_sig` | Move valid action from another packet | `CANONICAL_HASH`, `AGENT_SIGNATURE`, `ACTION_ATTESTATIONS` (fails decision binding) | `true` |
| **Scope Escalation (Insider)** | `delegation_chain[0].scope` | Expand scope to `CapabilityScope::all()` | `CANONICAL_HASH`, `AGENT_SIGNATURE`, `DELEGATION_CHAIN` | `true` |
| **Unauthorized Action Kind** | `actions[0].action_kind` | Change from `Write` to `Delete` or `Admin` | `CANONICAL_HASH`, `AGENT_SIGNATURE`, `SCOPE_AUTHORITY` | `true` |
| **Identity Substitution** | `agent.public_key` & `aip_id` | Replace with attacker keypair | `AGENT_ID_BINDING`, `CANONICAL_HASH`, `AGENT_SIGNATURE`, `AUTHORITY_CHAIN` | `true` |
| **Provenance Commitment Tamper** | `agent.provenance.model` | Change model hash string | `AGENT_ID_BINDING`, `CANONICAL_HASH`, `AGENT_SIGNATURE` | `true` |
| **Receipt Content Tampering** | `receipt_data` | Flip 1 byte in external receipt bytes | `RECEIPT_BINDING`, `TRUST_FLOOR` (downgrades to `AUTHORITY_BOUND`) | `true` |
| **Counterparty Signature Forgery**| `receipt.counterparty_sig`| Alter counterparty signature bytes | `CANONICAL_HASH`, `AGENT_SIGNATURE`, `RECEIPT_BINDING` | `true` |
| **Trace Data Tampering** | `trace_data` | Supply modified trace payload | `TRACE_BINDING` (hash mismatch) | `true` |
| **Temporal Expiry Attack** | `actions[0].performed_at` | Set timestamp beyond `token.expires_at` | `CANONICAL_HASH`, `AGENT_SIGNATURE`, `TEMPORAL_VALIDITY` | `true` |
| **Retroactive Action Attack** | `actions[0].performed_at` | Set timestamp prior to `decided_at` | `CANONICAL_HASH`, `AGENT_SIGNATURE`, `TEMPORAL_VALIDITY` | `true` |
| **Trust Floor Inflation** | `claimed_trust_floor` | Inflate from `AgentSigned` to `CounterpartySigned` | `CANONICAL_HASH`, `AGENT_SIGNATURE`, `TRUST_FLOOR` | `true` |

---

## 8. Section 5: R4 Authority Management & Visual Lattice Builder

The Authority Management view provides cryptographic capability modeling, scope attenuation visualization, and cascade revocation simulation.

### Standard Named Scopes & Hierarchy
```text
ADMIN (0x04)
  │
  ├── allowed: Read, Write, Delete, Admin, Execute, Delegate
  └── denied:  []
       │
       ▼
ORCHESTRATOR
  │
  ├── allowed: Read, Write, Execute, Delegate
  └── denied:  Admin
       │
       ▼
AUDIT_READER
  │
  ├── allowed: Read
  └── denied:  Write, Admin, Delete
       │
       ▼
SUBMITTER (Lowest Privilege)
  │
  ├── allowed: Write
  └── denied:  Admin, Delete
```

### Lattice Meet Operator ($\sqcap$) Formula
When authority is delegated from parent token $P$ to child token $C$, the effective capability is governed by the lattice meet:
$$Allowed(P \sqcap C) = C.Allowed \cap (P.Allowed \setminus P.Denied)$$
$$Denied(P \sqcap C) = P.Denied \cup C.Denied$$
If $Allowed(P \sqcap C) = \emptyset$, the delegation yields $\bot$ (bottom) and is rejected with `AttenuationViolation`.

### Scope Matrix Table Schema

| Action Verb | Hex Code | SUBMITTER | AUDIT_READER | ORCHESTRATOR | ADMIN | Custom Action (e.g. `loan:approve`) |
|---|---|---|---|---|---|---|
| `Read` | `0x01` | ❌ Denied / Not in scope | ✅ **ALLOWED** | ✅ **ALLOWED** | ✅ **ALLOWED** | Configurable |
| `Write` | `0x02` | ✅ **ALLOWED** | 🚫 **EXPLICIT DENY** | ✅ **ALLOWED** | ✅ **ALLOWED** | Configurable |
| `Delete` | `0x03` | 🚫 **EXPLICIT DENY** | 🚫 **EXPLICIT DENY** | ❌ Not in scope | ✅ **ALLOWED** | Configurable |
| `Admin` | `0x04` | 🚫 **EXPLICIT DENY** | 🚫 **EXPLICIT DENY** | 🚫 **EXPLICIT DENY** | ✅ **ALLOWED** | Configurable |
| `Execute` | `0x05` | ❌ Not in scope | ❌ Not in scope | ✅ **ALLOWED** | ✅ **ALLOWED** | Configurable |
| `Delegate` | `0x06` | ❌ Not in scope | ❌ Not in scope | ✅ **ALLOWED** | ✅ **ALLOWED** | Configurable |

### Cascade Revocation Architecture
- Each token (`ScopedToken` and `DelegationToken`) is identified by a 16-byte CSPRNG `jti`.
- Revocation log is append-only and hash-chained:
  $$\text{entry\_hash} = \text{SHA-256}(jti \parallel revoked\_at \parallel reason \parallel revoked\_by \parallel cascade)$$
- When `cascade = true`:
  1. The primary token is marked revoked.
  2. The delegation graph is traversed using `DelegationLog::subtree_jtis(jti)`.
  3. Every descendant token JTI is appended to the revocation log with `RevocationReason::AdminRevocation`.
- Visual UI Behavior: Clicking "Revoke Token" on any delegation node instantly marks that node and its entire downstream subtree in red (`#EF4444`) with animated cascade links.

---

## 9. Section 6: R6 Syntriass Branding Specification

The application branding reflects Syntriass's identity as a high-assurance cryptographic infrastructure provider for autonomous enterprise AI agents.

### Brand Identity & Meaning
- **Name**: **SYNTRIASS**
- **Etymology**: Synthesis + Trias (Triad) — representing the tripartite core of autonomous accountability:
  1. **Identity**: Agent provenance & cryptographic keys (`aip-crypto`).
  2. **Authority**: Scoped capability tokens & lattice attenuation (`aip-core`).
  3. **Accountability**: Tamper-evident, signed EvidencePackets (`aip-protocol`).
- **Tagline**: *"Prove what the agent did and who authorized it."*

### Enterprise Cyber/Crypto Color Palette

| Token | Hex Code | Role in UI | Contrast Ratio / Usage |
|---|---|---|---|
| `bg-background` | `#080B11` | Primary App Background | Deepest obsidian void |
| `bg-card` | `#0E131F` | Surface 1 (Cards, Node Panels) | High-contrast card surface |
| `bg-muted` | `#161F31` | Surface 2 (Table Rows, Hover, Inputs) | Subtle dark slate elevation |
| `border` | `#222F46` | Structural Borders & Dividers | Crisp cyber hairline stroke |
| `primary` (Electric Cyan) | `#00E5FF` | Brand Accent, CTA Buttons, Active Tabs | Glow & high-visibility highlights |
| `primary-gradient` | `linear-gradient(135deg, #00E5FF 0%, #3B82F6 100%)` | Brand Mark, Gradients, Active Badges | Neon cyan to cobalt flow |
| `secondary` (Indigo Trust) | `#6366F1` | Cryptographic Signatures, Keys, JTIs | Verification badges & tokens |
| `floor-unverified` | `#64748B` | Level 0 Trust Floor Badge | Neutral slate gray |
| `floor-agent-signed` | `#F59E0B` | Level 1 Trust Floor Badge | Amber / Warning gold |
| `floor-authority-bound` | `#06B6D4` | Level 2 Trust Floor Badge | Cyan / Sky blue |
| `floor-counterparty-signed` | `#10B981` | Level 3 Trust Floor Badge | Cryptographic emerald |
| `status-tampered` | `#EF4444` | Verification Tamper Failure Alert | High-alert crimson |
| `text-primary` | `#F8FAFC` | Primary Typography | Crisp high-legibility off-white |
| `text-muted` | `#94A3B8` | Secondary Metadata & Labels | Medium slate gray |

### Typography Hierarchy
- **Brand Wordmark & Section Headers**: Geometric sans-serif (Inter / Plus Jakarta Sans / Geist) with tracked uppercase styling (`tracking-wider`, `font-semibold`).
- **UI Body & Controls**: Inter or Geist Sans, weights 400 (regular) and 500 (medium).
- **Cryptographic Values**: Monospace (JetBrains Mono / Geist Mono) for all AIP-IDs (`aip1...`), packet hashes, Ed25519 signatures, JTIs, and JSON payloads.

### Vector Inline SVG Logo Specifications

#### 1. Full Wordmark + Icon (`viewBox="0 0 200 40"`)
```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 40" fill="none" class="h-8 w-auto">
  <defs>
    <linearGradient id="syntriass-grad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00E5FF" />
      <stop offset="50%" stop-color="#3B82F6" />
      <stop offset="100%" stop-color="#6366F1" />
    </linearGradient>
    <linearGradient id="syntriass-core" x1="0%" y1="100%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#10B981" />
      <stop offset="100%" stop-color="#00E5FF" />
    </linearGradient>
  </defs>
  <!-- Tripartite Cryptographic Knot Icon -->
  <g transform="translate(4, 4)">
    <!-- Outer Shield Delta Knot -->
    <path d="M16 2 L29 25 L3 25 Z" stroke="url(#syntriass-grad)" stroke-width="2.5" stroke-linejoin="round" fill="none" />
    <!-- Inner Interlocking Keyhole Lattice -->
    <polygon points="16,8 24,22 8,22" fill="#0E131F" stroke="#222F46" stroke-width="1.5" />
    <circle cx="16" cy="14" r="2.5" fill="url(#syntriass-core)" />
    <path d="M16 16.5 L16 20" stroke="url(#syntriass-core)" stroke-width="2" stroke-linecap="round" />
    <!-- Three Vertex Node Rings -->
    <circle cx="16" cy="2" r="2" fill="#00E5FF" />
    <circle cx="29" cy="25" r="2" fill="#3B82F6" />
    <circle cx="3" cy="25" r="2" fill="#6366F1" />
  </g>
  <!-- Wordmark -->
  <text x="44" y="24" fill="#F8FAFC" font-family="system-ui, -apple-system, sans-serif" font-weight="700" font-size="16" letter-spacing="0.12em">SYNTRIASS</text>
  <text x="44" y="34" fill="#00E5FF" font-family="monospace" font-weight="500" font-size="7.5" letter-spacing="0.2em">ACCOUNTABILITY CONSOLE</text>
</svg>
```

#### 2. Standalone App Icon (`viewBox="0 0 36 36"`)
```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 36 36" fill="none" class="h-9 w-9">
  <defs>
    <linearGradient id="syn-icon-grad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00E5FF" />
      <stop offset="50%" stop-color="#3B82F6" />
      <stop offset="100%" stop-color="#6366F1" />
    </linearGradient>
    <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="2" result="blur" />
      <feComposite in="SourceGraphic" in2="blur" operator="over" />
    </filter>
  </defs>
  <rect width="36" height="36" rx="8" fill="#0E131F" stroke="#222F46" stroke-width="1.5" />
  <path d="M18 6 L30 27 L6 27 Z" stroke="url(#syn-icon-grad)" stroke-width="2.2" stroke-linejoin="round" fill="none" filter="url(#glow)" />
  <polygon points="18,12 25,24 11,24" fill="#080B11" stroke="#222F46" stroke-width="1.2" />
  <circle cx="18" cy="17" r="2.2" fill="#00E5FF" />
  <path d="M18 19.2 L18 22.5" stroke="#00E5FF" stroke-width="1.8" stroke-linecap="round" />
  <circle cx="18" cy="6" r="1.8" fill="#00E5FF" />
  <circle cx="30" cy="27" r="1.8" fill="#3B82F6" />
  <circle cx="6" cy="27" r="1.8" fill="#6366F1" />
</svg>
```

---

## 10. Conclusion & Recommendations for Downstream Agents

1. **`aip-wasm` Bridge**: The WebAssembly bindings must expose `verify_packet(packet_json, ctx_json)` returning `VerificationReport` exactly as implemented in `aip-protocol`. No verification logic should be duplicated in TypeScript.
2. **React Flow DAG**: Nodes should map directly to `GraphNode.kind` with inspection panels rendering the fields discovered in Section 3.
3. **Adversarial Tamper Simulator**: Use the 14 mutation vectors discovered in Section 4 to provide both one-click preset tamper buttons and free-form JSON editing, plus the "Recompute packet_hash" toggle to demonstrate hash-fixing attacker detection.
4. **Authority Management**: Render the 4 built-in named scopes in a visual matrix with toggleable actions and an attenuation tree that highlights cascade revocation propagation.
5. **Styling & Branding**: Enforce dark mode as the default, applying the deep obsidian palette (`#080B11`, `#0E131F`) with electric cyan highlights and the vector SVG Syntriass logo.
