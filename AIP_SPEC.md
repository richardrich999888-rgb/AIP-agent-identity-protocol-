# AIP Specification — Accountability Infrastructure for Autonomous AI

**Version:** 0.1-draft &nbsp;|&nbsp; **Status:** Open specification, seeking implementations and feedback
**Tagline:** *Prove what the agent did and who authorized it.*

This document specifies the **EvidencePacket** format, its verification
rules, the delegation semantics it depends on, and the accountability graph
derived from it. The reference implementation is the `aip-protocol` Rust
crate in this repository; every normative rule below is implemented and
tested there.

The specification is intended to be open. The value of an evidence format
grows with the number of independent parties who can verify it.

---

## 1. Concepts

| Term | Meaning |
|---|---|
| **Principal** | The root human or organizational authority (e.g. a CFO). |
| **Root token** | A scoped capability token issued and signed by the principal. |
| **Delegation chain** | Zero or more delegation tokens handing an attenuated subset of the root scope down to the acting agent. |
| **Agent** | The autonomous actor. Identified by an AIP-ID derived from its public key and provenance commitments. |
| **Decision** | What the agent decided, with inputs and rationale bound by hash. |
| **Action attestation** | A performed action, individually signed by the agent and bound to its authorizing decision. |
| **Receipt binding** | A hash binding to an external system's receipt, optionally **countersigned** by that system. |
| **Trust floor** | The minimum trust a verifier may place in a packet, derived — never asserted. |
| **EvidencePacket** | The self-contained, tamper-evident artifact binding all of the above. |

## 2. Identity (informative summary)

- Keys: Ed25519. Hash: SHA-256.
- `AIP-ID = "aip1" || base58(SHA-256(pubkey || provenance)[0..26]) || base58(checksum)`
  where `checksum = SHA-256(SHA-256("aip1" || fingerprint_b58))[0..4]`.
- The provenance triple is three caller-supplied SHA-256 **commitments**
  (model, environment, toolchain). v0.1 binds identity to commitments; it
  does **not** verify the commitments against real artifacts.

## 3. Delegation semantics (normative)

1. A **scope** is `{allowed: [action], denied: [action]}`. An action is
   permitted iff it is in `allowed` and not in `denied`.
2. **Attenuation:** a delegation's scope MUST be a subset of its parent's
   scope, computed by lattice intersection (MEET): allowed sets intersect,
   denied sets union. Empty intersection (⊥) MUST be rejected.
3. **Linkage:** each delegation references its parent token by JTI;
   `depth(child) = depth(parent) + 1`; maximum depth 8.
4. **Signatures:** each delegation is signed by its issuer over the
   canonical encoding of `(jti, parent_jti, issuer, grantee, scope, depth,
   issued_at)`.
5. **Lifetime:** a delegation MUST NOT outlive its parent.
6. **Revocation:** revoking a token invalidates its entire subtree
   (cascade). Verifiers check every JTI in the chain against their
   revocation set.

## 4. EvidencePacket v1 format (normative)

Magic: `"AEP1"`. Version: `1`.

```text
EvidencePacket {
  magic            [4]u8          // "AEP1"
  version          u16            // 1
  packet_id        [16]u8
  created_at       u64            // Unix ms

  agent {
    aip_id         string
    public_key     {algorithm u8, key_bytes []u8}
    provenance     {model, environment, toolchain: [32]u8}
  }

  root_authority {
    principal_id   string         // AIP-ID of the root principal
    display_role   string         // e.g. "CFO" (covered by hash)
    root_token     ScopedToken    // signed by the principal
  }

  delegation_chain []DelegationToken   // possibly empty

  decision {
    decision_id    [16]u8
    action_kind    ScopeAction    // capability the decision exercises
    summary        string
    input_hash     [32]u8         // SHA-256 of decision inputs
    rationale_hash [32]u8         // SHA-256 of reasoning/rationale
    decided_at     u64
  }

  actions []ActionAttestation {   // at least one
    action_id      [16]u8
    action_kind    ScopeAction
    description    string
    payload_hash   [32]u8
    performed_at   u64
    agent_sig      Signature      // over canonical(decision_id || action fields)
  }

  trace_binding?   {trace_id string, trace_hash [32]u8}

  receipt_binding? {
    receipt_system string
    receipt_id     string
    receipt_hash   [32]u8
    counterparty_id?  string
    counterparty_sig? Signature   // over canonical(decision_id || receipt fields)
  }

  claimed_trust_floor u8          // see §6

  packet_hash      [32]u8         // SHA-256(canonical_bytes)
  agent_sig        Signature      // payload_hash == packet_hash
}
```

### 4.1 Canonical encoding

All hashing and signing operates on a deterministic byte encoding, not on
JSON. Rules:

- Fixed-width integers are little-endian.
- Every variable-length field (strings, byte arrays, lists) is prefixed
  with its length as `u32` LE, making the encoding prefix-free.
- Optional fields are encoded as a presence byte (`0`/`1`) followed by the
  value when present.
- `canonical_bytes` covers **every field except `packet_hash` and
  `agent_sig`** — including embedded delegation signatures and the
  counterparty countersignature, so modifying any embedded signature is
  itself tamper-evident.

### 4.2 Binding rules

- **Action↔decision binding:** the per-action signature payload begins with
  `decision_id`, so an attestation cannot be transplanted into another
  decision context.
- **Receipt↔decision binding:** the counterparty signs
  `decision_id || receipt_system || receipt_id || receipt_hash`.
- **Assembly order:** countersignatures are obtained before sealing; the
  agent's packet signature covers them.

### 4.3 JSON representation

Packets serialize to JSON for transport and archival (`to_json` /
`from_json` in the reference implementation). JSON is a *carrier*: verifiers
MUST re-derive the canonical bytes from the parsed structure and MUST NOT
trust any hash present in the JSON without recomputation.

## 5. Verification rules (normative)

A verifier evaluates **all** rules (no short-circuit) and reports each:

| Rule | Requirement |
|---|---|
| `STRUCTURE` | Magic, version, non-empty agent/principal/decision, ≥1 action. |
| `AGENT_ID_BINDING` | `aip_id` validates and equals `derive_aip_id(public_key, provenance)`. |
| `CANONICAL_HASH` | Recomputed SHA-256 of canonical bytes equals `packet_hash`. |
| `AGENT_SIGNATURE` | `agent_sig.signer_id == aip_id`, payload hash equals recomputed hash, Ed25519 verifies against the embedded key. |
| `ROOT_TOKEN_SIGNATURE` | Root token verifies against a key the **verifier** trusts for the principal. |
| `DELEGATION_CHAIN` | Every hop: signature, parent-JTI linkage, depth monotonicity, scope ⊆ parent. |
| `AUTHORITY_CHAIN` | Principal issued the root token; each hop's issuer is the previous grantee; leaf grantee is the acting agent. |
| `SCOPE_AUTHORITY` | Decision `action_kind` and every action's `action_kind` are permitted by the effective (most-attenuated) scope. |
| `REVOCATION` | No JTI in the chain appears in the verifier's revocation set. |
| `TEMPORAL_VALIDITY` | Decision/actions fall within issuance↔expiry of every token; actions do not precede their decision. |
| `ACTION_ATTESTATIONS` | Every action signature verifies and is bound to the packet's decision. |
| `TRACE_BINDING` | If trace data is supplied, its hash matches `trace_hash`. |
| `RECEIPT_BINDING` | If receipt data is supplied, hash matches; if countersigned, the countersignature verifies against a trusted counterparty key. |
| `TRUST_FLOOR` | The claimed floor must not exceed the derived floor (§6). |

`valid` ⇔ all rules pass. `tampered` ⇔ at least one failure is positive
evidence of post-signing modification (hash or signature-payload mismatch),
as distinct from e.g. revocation.

## 6. Trust floors (normative)

| Floor | Derivation |
|---|---|
| `UNVERIFIED` (0) | Default. |
| `AGENT_SIGNED` (1) | STRUCTURE + AGENT_ID_BINDING + CANONICAL_HASH + AGENT_SIGNATURE pass. |
| `AUTHORITY_BOUND` (2) | AGENT_SIGNED + root token, delegation chain, authority chain, scope, revocation, temporal, and action rules pass. |
| `COUNTERPARTY_SIGNED` (3) | AUTHORITY_BOUND + a verified counterparty countersignature on the receipt. |

The verifier derives the floor from evidence; the packet's claim is checked
against it and MUST NOT exceed it.

## 7. Accountability graph (normative shape)

From any packet, derive:

```text
Principal --Issues--> AuthorityGrant --Delegates--> Delegation* --ActsUnder--> Agent
   Agent --Decides--> Decision --Performs--> Action+ --Produces--> Receipt?
```

A packet is **chain-complete** iff every node is reachable from the single
Principal node. The reference implementation exports JSON and Graphviz DOT.

## 8. Trust model and non-goals

- The verifier's key registry (principal, intermediate issuers,
  counterparties) and revocation set are **out of band** by design: the
  verifier — an auditor, a regulator, a counterparty — decides whom to
  trust. Packets carry evidence, not trust.
- v0.1 does **not** provide: model-weight attestation, TEE quote
  verification, transparency-log anchoring, or post-quantum signatures.
  These are roadmap items; the format reserves the algorithm byte for
  agility.

## 9. Versioning

- Wire format versioned by `(magic, version)`. Breaking changes increment
  `version`.
- Verification rules are versioned with this document. Implementations MUST
  report which spec version they verified against.

## 10. Reference implementation and test vectors

- `aip-standalone/aip-protocol` — packet, engine, graph (`cargo test -p aip-protocol`).
- `aip-standalone/banking_demo` — end-to-end CFO→payment→ledger demo with
  tamper detection (`cargo run -p banking-demo`).
- Every tamper scenario in the test suite must flip a specific named rule;
  a change that makes a tamper test pass silently is a spec violation.
