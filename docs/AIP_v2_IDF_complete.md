# AIRON AIP v2 — Invention Disclosure Form (Complete)

**Document ID**: AIRON-IDF-AIP-002
**Version**: 2.0
**Date**: 2026-03-21
**Patent Jurisdiction**: Indian CRI 2025 + US USPTO 35 USC §101/§103
**Related IDF**: AIRON-IDF-1B (main patent), PATENT_IDF_AIRON.md

---

## Executive Summary

The Agent Identity Protocol v2 (AIP v2) introduces four patentable mechanisms that extend
the base AIP token issuance system with scope-constrained delegation, cascade revocation,
scope-bound audit trail binding, and well-known service discovery. These mechanisms
collectively implement a **Verifiable Delegation Lattice (VDL)** — a novel construction
that provably bounds a delegated agent's authority to the intersection of all ancestor
scopes in the delegation chain.

---

## Section 1: NM-A1 — Scope-Constrained Delegation Lattice

### 1.1 Summary

A delegation token system where child capability scopes are provably constrained by the
lattice MEET operation of all ancestor scopes. The delegating authority can never grant
more rights than it currently holds.

### 1.2 Technical Detail

The `CapabilityScope` is a pair `(allowed: HashSet<Action>, denied: HashSet<Action>)`.
The **effective allowed set** is `allowed − denied` (denied always wins).

The `meet()` operation computes:
```
child_effective = intersection(self_effective, other_effective)
combined_denied = union(self_denied, other_denied)
```

**Key property**: `child_effective ⊆ parent_effective` for all possible inputs.
This is the mathematical guarantee that a child can never exceed its parent's authority.

### 1.3 Implementation

File: `services/aip/src/capability.rs`

- `Action` enum: 6 actions (`EvaluateContent`, `SubmitAuditEntry`, `IssueSubDelegation`,
  `ReadAuditLog`, `RevokeToken`, `Custom(String)`)
- 4 named scopes: `SUBMITTER`, `AUDIT_READER`, `ORCHESTRATOR`, `ADMIN`
- `meet()` returns `Option<CapabilityScope>` — `None` when intersection is empty
- `is_subset_of()` for chain validation
- `permits(action)` checks deny first (deny always wins)

### 1.4 Prior Art Differentiation

Existing systems (OAuth 2.0, ABAC, RBAC) define scopes as flat string sets. They do not
implement a **lattice operation** on scope sets during delegation chain construction.
AIP v2's `meet()` is novel because it:
1. Operates on two structured scope objects (not strings)
2. Preserves deny semantics across the union of deny sets
3. Provably guarantees the subset property at compile time (type system)

### 1.5 Claims Support

**Claim NM-A1**: A method for scope-constrained capability delegation comprising:
- representing agent capabilities as a lattice element with allowed and denied action sets;
- computing a delegation token whose effective scope is the lattice meet of the parent scope
  and the requested child scope;
- wherein the child scope is provably a subset of the parent scope at delegation time;
- wherein denied actions propagate through the union of all ancestor deny sets.

---

## Section 2: NM-A2 — Verifiable Delegation Chain with Depth Limit

### 2.1 Summary

A delegation chain protocol where each delegation token cryptographically references its
parent (by JTI), records its chain depth, and a maximum depth limit (8) is enforced at
issue time. The chain is verifiable offline using only the root AIP public key.

### 2.2 Technical Detail

Each `DelegationToken` contains:
- `delegation_id`: UUID of this delegation
- `parent_jti`: JTI of the parent token (root AIP JWT or parent delegation)
- `depth`: chain depth from root (1 = direct, MAX_DEPTH = 8 = maximum)
- `entry_hash`: SHA3-256 of `"delegation_id={}&parent_jti={}&delegatee_id={}&depth={}&issued_at={}"` — tamper evidence
- `scope`: the effective `CapabilityScope` (post-meet of parent scope)

**Verification algorithm** (POST /v1/identity/verify-chain):
1. Verify root JWT signature using AIP Ed25519 public key
2. Check root JTI not in revocation set
3. For each delegation_id in the ordered chain:
   a. Look up the delegation entry by ID
   b. Verify `parent_jti` matches expected (previous delegation_id or root JTI)
   c. Check delegation_id not in revocation set
   d. Narrow effective scope: `prev_scope.meet(entry.scope)` — returns None on empty intersection
4. Return `valid=true`, `effective_scope`, `chain_depth`

### 2.3 Implementation

File: `services/aip/src/delegation.rs`
- `DelegationToken` struct with SHA3-256 `entry_hash`
- `MAX_DEPTH = 8` constant
- `DelegationLog = Arc<Mutex<Vec<DelegationToken>>>` — append-only JSONL, loaded at startup
- `append_delegation()` — writes to JSONL and updates in-memory log
- `build_parent_to_children()` — constructs the BFS graph for cascade revocation

Handler: `POST /v1/identity/delegate` in `services/aip/src/handlers.rs`
Handler: `POST /v1/identity/verify-chain` in `services/aip/src/handlers.rs`

### 2.4 Claims Support

**Claim NM-A2**: A delegation chain system comprising:
- a root identity token signed with Ed25519;
- one or more delegation tokens each referencing the parent by JTI and recording chain depth;
- a maximum chain depth of 8 hops from the root;
- a tamper-evidence hash over delegation fields;
- an offline-verifiable chain check requiring only the root public key.

---

## Section 3: NM-A3 — Cascade Revocation via BFS Delegation Walk

### 3.1 Summary

A revocation mechanism that, when given a root JTI to revoke, performs a BFS walk of the
delegation graph and atomically revokes all descendant delegations. Each revocation entry
is appended to an append-only JSONL log with a SHA3-256 tamper-evidence hash.

### 3.2 Technical Detail

Revocation entries are persisted to `AIP_REVOCATION_LOG_PATH` (JSONL format).
Each `RevocationEntry` has:
- `jti`: the JTI being revoked
- `revoked_by`: JTI of the revoking authority
- `revoked_at`: ISO 8601 timestamp
- `reason`: human-readable reason
- `entry_hash`: SHA3-256(`"jti={}&revoked_by={}&revoked_at={}&reason={}"`)

**Cascade algorithm**:
```
BFS queue = {root_jti}
while queue non-empty:
  jti = dequeue()
  if not already revoked:
    create RevocationEntry, append to log, insert into in-memory HashSet
  for each child_delegation_id of jti in parent_to_children map:
    enqueue(child_delegation_id)
```

The `is_revoked()` check in the `POST /v1/identity/verify` hot path is O(1) (HashSet lookup).

### 3.3 Implementation

File: `services/aip/src/revocation.rs`
- `RevocationEntry` with SHA3-256 `entry_hash`
- `RevocationSet = Arc<Mutex<HashSet<String>>>`
- `load_revocation_set()` — populates from JSONL at startup
- `revoke()` — append to JSONL + insert into HashSet atomically
- `cascade_revoke()` — BFS walk, revokes all descendants
- `is_revoked()` — O(1) HashSet lookup (hot path)

Handler: `POST /v1/identity/revoke` with `cascade: bool` field

### 3.4 Claims Support

**Claim NM-A3**: A cascade revocation method comprising:
- an append-only revocation log with tamper-evidence hashes;
- an in-memory set populated at startup for O(1) hot-path verification;
- a BFS walk of the delegation graph that atomically revokes a root token
  and all tokens that transitively descend from it;
- verification that revoked tokens are rejected even when their cryptographic signature is valid.

---

## Section 4: NM-A4 — Scope-Constrained Audit Trail Binding

### 4.1 Summary

A Chrono audit entry system where the `delegation_binding` (the specific delegation
authorising the audit submission) is included in the SHA3-256 entry hash computation.
This ensures that any tampering with the authorization record — changing which delegation
was used — breaks the hash chain and is detected at verification time.

### 4.2 Technical Detail

The Chrono entry hash is computed as:
```
canonical = "{seq}|{event}|{data_json}|{previous_hash}"        # without binding
canonical = "{seq}|{event}|{data_json}|{previous_hash}|{binding_json}"  # with binding
entry_hash = SHA3-256(canonical)
```

The `DelegationBinding` struct (JSON):
```json
{"delegation_id": "...", "delegatee_id": "..."}
```

**Backward compatibility**: entries without `delegation_binding` use the original 4-field
canonical. The format is extended, not replaced, so existing logs verify correctly.

**Security property**: An auditor can verify not only WHAT was logged, but WHO was
authorised to log it. Replacing `delegation_id` with a forged value changes `binding_json`,
which changes the canonical, which changes `entry_hash`, which breaks the chain at
verification (`GET /v1/trace/{id}/verify`).

### 4.3 Implementation

File: `services/chrono/src/chain.rs` — `canonical_input()` updated to accept `binding_json`
File: `services/chrono/src/models.rs` — `DelegationBinding` struct, updated `AppendRequest`
File: `services/chrono/src/store.rs` — `LogEntry.delegation_binding: Option<DelegationBinding>`
File: `services/gateway/src/models.rs` — `DelegationBinding` struct for gateway→Chrono transport
File: `services/gateway/src/clients.rs` — `append_chrono()` updated to pass binding

### 4.4 Test Coverage

Three new unit tests in `services/chrono/src/chain.rs`:
1. `test_delegation_binding_included_in_hash` — valid 2-entry chain with binding verifies
2. `test_tampered_delegation_binding_detected` — tampered binding breaks chain at seq=1
3. `test_hash_differs_with_and_without_binding` — presence of binding changes hash

### 4.5 Claims Support

**Claim NM-A4**: An audit trail binding method comprising:
- a Chrono audit entry hash that includes the delegation_binding fields when present;
- wherein tampering with the delegation_id or delegatee_id breaks the SHA3-256 hash chain;
- backward-compatible canonical format (entries without binding use 4-field format);
- an auditor-accessible verify endpoint that detects any such tampering.

---

## Section 5: Combined Composition Claim

### 5.1 Summary

The four mechanisms compose into the **Verifiable Delegation Lattice (VDL)**, a novel
end-to-end system property:

```
AIP root JWT
    → scope-constrained delegation chain (NM-A1 + NM-A2)
        → O(1) revocation check on every verify call (NM-A3)
            → delegation binding in every audit entry hash (NM-A4)
```

**The composition guarantee**: If agent A holds delegation D with scope S, and A submits
an audit entry to Chrono under D, then:
1. S is provably ⊆ scope of any ancestor of D (NM-A1)
2. D is valid only if the full chain to root is unbroken (NM-A2)
3. D becomes invalid the instant any ancestor JTI is revoked (NM-A3)
4. The audit entry's hash commits to D — forging the authorization record breaks the chain (NM-A4)

This four-way composition has no prior art. RBAC, ABAC, OAuth, and SPIFFE/SPIRE implement
some of these properties individually; none implement all four with the specific construction
of a lattice MEET scope operation combined with hash-chain audit binding.

### 5.2 Combined Claim

**Combined Claim VDL-1**: A verifiable delegation lattice system for AI agent authorization comprising:
- a root identity token (`AIP JWT`) with Ed25519 signature;
- a delegation chain where each child scope is the lattice meet of parent and requested scope (NM-A1);
- a maximum delegation depth of 8, with SHA3-256 tamper-evidence on each delegation entry (NM-A2);
- an append-only revocation log with cascade BFS walk and O(1) in-memory lookup (NM-A3);
- a hash-chain audit log that includes delegation binding fields, making authorization tampering
  cryptographically detectable (NM-A4);
- an offline-verifiable chain: auditors need only the root public key from `/.well-known/jwks.json`
  to verify the full authorization chain and audit log integrity.

---

## Appendix A: Test Coverage Summary

| Test | File | Description |
|------|------|-------------|
| T-CAP-1 | `capability.rs` | meet() intersection of overlapping scopes |
| T-CAP-2 | `capability.rs` | meet() of disjoint scopes returns None |
| T-CAP-3 | `capability.rs` | denied always wins over allowed |
| T-CAP-4 | `capability.rs` | child cannot exceed parent via meet() |
| T-CAP-5 | `capability.rs` | is_subset_of() checks effective set |
| T-DEL-1 | `delegation.rs` | MAX_DEPTH == 8 |
| T-DEL-2 | `delegation.rs` | delegation token persists and reloads |
| T-DEL-3 | `delegation.rs` | build_parent_to_children covers full graph |
| T-REV-1 | `revocation.rs` | revoke and is_revoked round-trip |
| T-REV-2 | `revocation.rs` | revocation set is persisted and reloaded |
| T-REV-3 | `revocation.rs` | cascade_revoke covers all descendants |
| T-REV-4 | `revocation.rs` | entry_hash is 64 hex chars (SHA3-256) |
| T-WK-1  | `wellknown.rs` | JWKS x field is 43 base64url chars (32 bytes) |
| T-WK-2  | `wellknown.rs` | x decodes back to 32 bytes |
| T-NMA4-1 | `chain.rs` | entry with delegation_binding verifies correctly |
| T-NMA4-2 | `chain.rs` | tampered delegation_binding breaks chain |
| T-NMA4-3 | `chain.rs` | hash differs with vs without binding |

**Total AIP v2 tests**: 14 new tests
**Total workspace tests**: 71 (all passing)

---

## Appendix B: Well-Known Endpoints

### `GET /.well-known/aip-configuration`
```json
{
  "issuer": "http://aip:8081",
  "token_endpoint": "http://aip:8081/v1/identity/issue",
  "verification_endpoint": "http://aip:8081/v1/identity/verify",
  "delegation_endpoint": "http://aip:8081/v1/identity/delegate",
  "revocation_endpoint": "http://aip:8081/v1/identity/revoke",
  "jwks_uri": "http://aip:8081/.well-known/jwks.json",
  "algorithms_supported": ["EdDSA"],
  "delegation_max_depth": 8
}
```

### `GET /.well-known/jwks.json`
```json
{
  "keys": [{
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "<43-char base64url of raw 32-byte public key>",
    "use": "sig",
    "kid": "<SHA-256 fingerprint of public key>",
    "alg": "EdDSA"
  }]
}
```

---

## Appendix C: §101 Alice/Mayo Defense

### Directed to Patent-Eligible Subject Matter

**Problem**: AIP v2 addresses a concrete technical problem — delegating authority across
AI agent chains without introducing scope escalation vulnerabilities that are not present
in human-operated systems. The lattice MEET construction specifically prevents the
"confused deputy" attack at the protocol level.

**Specific hardware/software improvement**: The delegation chain is verified in O(chain_depth)
time with O(n_revocations) space (in-memory HashSet), a concrete improvement over:
- RBAC/ABAC: O(policy_db_size) per verification call
- JWT chain: no formal scope narrowing guarantee
- OAuth: no cryptographic chain linkage between tokens

**Analogous cases**:
- *DDR Holdings*: functional improvement to computer operation (scope narrowing at protocol level)
- *Enfish*: improvement to computer system (O(1) revocation lookup via HashSet)
- *McRO*: specific rules applied by machine (lattice MEET rule, BFS cascade algorithm)

---

*Prepared by: AIRON Engineering*
*Review required by: Patent Counsel before filing*
