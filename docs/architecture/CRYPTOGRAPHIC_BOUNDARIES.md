# CRYPTOGRAPHIC_BOUNDARIES

Distinguishes, per **I15**, what is a *primitive* from what is a *protocol*.

## 1. Inventory as verified

| Element | Status | Evidence |
|---|---|---|
| Ed25519 (ed25519-dalek 2.2.0) | **PRIMITIVE, correct** | `aip-crypto/src/lib.rs:8,102,115,127,175` |
| SHA-256 (sha2 0.10.9) | **PRIMITIVE, correct** | `aip-crypto/src/lib.rs:21` |
| Base58 AIP-ID + checksum | **PROTOCOL, correct, single implementation** | `aip-crypto/src/lib.rs:37-97`; matches `AIP_SPEC.md:34-35` |
| Packet canonical encoding | **PROTOCOL, correct** | `aip-protocol/src/canonical.rs` — u32-LE length prefix on all variable-length data, presence tags, collection counts |
| `aip-core` signing payloads | **PROTOCOL, DEFECTIVE** | `capability.rs:208-230`, `delegation.rs:369-393` — see §2, §3 |
| Hash chain (`scoped_audit`) | **PRIMITIVE ONLY, unwired** | `scoped_audit.rs:88-141`; unkeyed, unsigned, in-memory, no caller |
| **Merkle** | **PRIMITIVE ONLY** | `merkle_leaf:211`, `merkle_internal:217`, `merkle_empty:224`. No tree builder, no root over a set, no inclusion proof |
| Merkle in production | **UNPOPULATED** | `merkle_leaf`/`merkle_internal` are called **only** from the test at `aip-crypto/src/lib.rs:289-292`. All three production roots are `merkle_empty()` — `aip-core/src/lib.rs:62,63,647` |
| Domain separation | **ABSENT** | no context string or type tag in any signed preimage |
| Sequence numbers | present in `scoped_audit` only | unwired |
| Nonces | generated (`aip-crypto:147-149`, `OsRng`) | **never checked** — `NonceTracker` unwired from delegation and packet verification |
| Timestamps | present | R10 never consults a wall clock; `is_token_expired` (`capability.rs:175`) has no caller in `verification.rs` |
| Key versions / rotation | **ABSENT** | no `kid` set, single key |
| HKDF, HMAC, AEAD, PQC | **ABSENT** | no crate, no code. `AlgorithmId::MlDsa65`/`Hybrid` are declared (`aip-types:13-14`) but `sign_ed25519` hardcodes Ed25519 (`:155,165`) |
| `zeroize` | **ABSENT** repo-wide | present in `Cargo.lock` only transitively |

## 2. The critical defect — and the proof it is a defect

`expires_at` is **not covered by the issuer signature** on either authority
type that flows through `EvidencePacket`:

| Type | Signing payload | Covers `expires_at`? |
|---|---|---|
| `ScopedToken` | `canonical_token_payload(jti, issuer_id, agent_id, scope, issued_at)` — `capability.rs:208-214` | **NO** |
| `DelegationToken` | `canonical_delegation_payload(jti, parent_jti, issuer_id, grantee_id, scope, depth, issued_at)` — `delegation.rs:369-377` | **NO** |
| `CapabilityGrant` | `canonical_encode_capability_grant` — `aip-core/src/lib.rs:119-143` | **YES** — `:135-142`, with a correct presence tag |

The third row is decisive. The same crate, same author, encodes an
`Option<u64>` into a signed payload **correctly**:

```rust
// aip-core/src/lib.rs:135-142  — the pattern to copy
match grant.expires_at {
    Some(ts) => { buf.push(1); buf.extend_from_slice(&ts.to_le_bytes()); }
    None => buf.push(0),
}
```

This establishes the omission in the other two as an **oversight, not a
documented trade-off** (**I6**), and supplies the exact fix.

### Exploit path, verified end to end

1. `expires_at` **is** inside the packet canonical bytes
   (`evidence_packet.rs:275,288`), so an external tamperer is caught by
   R3/R4.
2. But the **acting agent legitimately holds the packet-signing key**. It
   rewrites `root_token.expires_at` and every `delegation_chain[i].expires_at`,
   recomputes `packet_hash`, and re-signs.
3. R5 (`verification.rs:166-190`) recomputes `canonical_token_payload` — which
   excludes the field → **passes**.
4. R6 (`delegation.rs:209-225`) recomputes `canonical_delegation_payload` —
   excludes the field → **passes**.
5. R10 (`verification.rs:471-497`) reads `rt.expires_at` (`:495`) and
   `hop.expires_at` (`:497`) — the **rewritten** values → **passes**.
6. Result: `valid = true`, `tampered = false`, floor `COUNTERPARTY_SIGNED`.

**Test evidence:** no test mutates `expires_at`. The only temporal adversarial
test, `test_action_after_token_expiry_rejected`
(`aip-protocol/tests/evidence_packet.rs:411-414`), *reads* the expiry and moves
the **action** past it. The inverse — move the **expiry** past the action — is
untested and would pass today.

## 3. Second defect — non-injective `aip-core` encoders

```rust
// aip-core/src/delegation.rs:381-382
buf.extend_from_slice(issuer_id.as_bytes());   // no length prefix
buf.extend_from_slice(grantee_id.as_bytes());  // no prefix, no separator
```

`("ab","c")` and `("a","bc")` produce byte-identical signed payloads. Same
pattern at `capability.rs:217-218`, `aip-core/src/lib.rs:122-124,154-155`.
`ScopeAction::Custom(s)` is encoded `0x01 ‖ s ‖ 0x00` — a NUL terminator over a
`String` that may contain interior NUL.

Contrast `aip-protocol/src/canonical.rs`, which does this correctly. Two
encoders with different security properties coexist; **the weaker one guards
authority**. Violates **I14**.

## 4. Boundary rules for Ghost

| Rule | Rationale |
|---|---|
| Any new signed structure uses `aip-protocol/src/canonical.rs` helpers | **I14**; do not extend the raw-concatenation pattern |
| Every signed payload gets a **domain-separation tag** | none exists today; `ObservedExecution` and `ExpectedExecution` must not be confusable with a packet or a token |
| A Merkle *root* claim requires a tree, a root computation over a real set, and an inclusion-proof verifier | **I15**; `merkle_empty()` is not a commitment |
| Commitments must be *populated* before they are *claimed* | today all three roots are the empty hash |
| Observer keys are separate from agent keys and from the service key | **I10**; note the service currently reuses one seed for JWT signing *and* bundle manifests (`aip-service/src/main.rs:82,118`) |
| Replay protection must be explicit | the packet has no nonce check and no seen-set; do not assume `Signature.nonce` provides it |

## 5. What must not be claimed

- Do **not** describe AIP as having "Merkle commitments" — it has three helper
  functions and three empty roots.
- Do **not** describe the audit chain as tamper-evident against an adversary —
  it is unkeyed with a public `compute_hash` and a `pub entries` field
  (`scoped_audit.rs:154-156`), so any holder can re-run the chain.
- Do **not** describe AIP as post-quantum ready — the algorithm byte is
  reserved; no PQC code exists.
