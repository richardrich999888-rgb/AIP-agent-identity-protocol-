---
name: aip-protocol-change-guard
description: Guard rails for changing AIP's cryptographic core — aip-crypto, aip-core (capability.rs, delegation.rs, revocation.rs, scoped_audit.rs) and aip-protocol (canonical.rs, evidence_packet.rs, verification.rs, bundle.rs). Use whenever adding or modifying a signed or hashed field, a canonical encoder, a verification rule, a trust-floor derivation, an AIP-ID derivation, or the packet/bundle wire format. Also use when a change touches Ed25519 signing/verification, SHA-256 hashing, or delegation chain semantics.
---

# AIP protocol change guard

The protocol crates are the load-bearing security surface. A mistake here is not
a bug, it is a silently forged evidence packet. Work through the invariants
below before and after the change.

## The five invariants

### 1. Every field a verifier trusts must be inside the signature that vouches for it

This is the class of defect that produced the audit's only CRITICAL finding.

`expires_at` is present in `ScopedToken` (`aip-standalone/aip-types/src/lib.rs:281-289`)
and `DelegationToken` (`:296-306`), and is read by rule R10 `TEMPORAL_VALIDITY`
(`aip-standalone/aip-protocol/src/verification.rs:495,497`) — but it is **absent
from both issuer-signing payloads**:

- `canonical_token_payload` — `aip-standalone/aip-core/src/capability.rs:208-230`
- `canonical_delegation_payload` — `aip-standalone/aip-core/src/delegation.rs:369-393`

Consequence: the acting agent holds the packet-signing key legitimately, so it
can rewrite the embedded expiries, recompute `packet_hash`, re-sign, and pass
all 14 rules with `tampered = false`. Delegated authority has no enforceable end
date.

**Before merging any change that adds a field to a signed struct, answer in the PR:**

- Which signing payload covers this field? Name the function and line.
- Which verification rule reads it? Name the rule constant.
- If a rule reads it and no issuer signature covers it, the change is rejected.

Cross-check the field-level binding table in `docs/TECH_AUDIT_AND_ROADMAP.md`
and `AIP_SPEC.md` §4.2 before adding to `EvidencePacket`.

### 2. Canonical encodings must be injective — use the length-prefixed encoder

Two encoders exist and they do **not** have the same properties.

| Encoder | Location | Property |
|---|---|---|
| **Correct** | `aip-standalone/aip-protocol/src/canonical.rs` | u32-LE length prefix on every variable-length field (`put_bytes:23`, `put_str:29`), presence tag on every `Option`, u32 count on every collection |
| **Not injective** | `aip-core/src/capability.rs:217-218`, `delegation.rs:381-382`, `aip-core/src/lib.rs:122-124,154-155` | adjacent variable-length strings concatenated raw, no prefix, no separator |

`(issuer_id="ab", grantee_id="c")` and `(issuer_id="a", grantee_id="bc")`
produce byte-identical signed payloads under the `aip-core` encoders.
`ScopeAction::Custom(s)` is encoded `0x01 ‖ s ‖ 0x00` — a NUL terminator, and
Rust `String` permits interior NUL, so a one-element scope can collide with a
two-element scope.

**Rules:**

- New canonical encoding MUST use `aip-protocol/src/canonical.rs` helpers.
- Never concatenate two variable-length values without a length prefix.
- Never use a terminator byte where the payload can contain that byte.
- If you touch an `aip-core` encoder, migrate it to the shared helpers rather
  than extending the raw-concatenation pattern.

### 3. A wire-format change bumps the version and keeps the old verifier

`EvidencePacket` is versioned by `(magic, version)` — `PACKET_MAGIC` / `PACKET_VERSION`,
checked by rule R1 `STRUCTURE` (`verification.rs:328,331`). `AIP_SPEC.md` §9 requires
implementations to report which spec version they verified against.

Any change to `canonical_bytes` field order, field set, or encoding is a
**breaking wire change**:

- Bump `PACKET_VERSION`.
- Keep a verification path for the previous version, or state explicitly in
  `CHANGELOG.md` that old packets no longer verify.
- Update `AIP_SPEC.md` §4 and the rule table in §5 in the same commit.
- Batch breaking changes — do not ship two version bumps where one would do.

### 4. Every verification rule ships with a test that pins that specific rule

The engine evaluates all 14 rules with no short-circuit
(`verification.rs:92-322`) and `valid = all(pass)` (`:305`). The existing suite
is strong precisely because tests assert the *named* rule that failed, via the
`assert_rule_failed` helper in
`aip-standalone/aip-protocol/tests/evidence_packet.rs:163-173`.

When adding or modifying a rule:

- Add a test that tampers with exactly the thing the rule guards and asserts
  **that rule** fails — not merely that `valid == false`.
- Model the real adversary: the strongest existing tests recompute
  `packet_hash` after tampering (`tests/evidence_packet.rs:235`) and even
  **re-sign with a valid key** (`:276`, `:335`, `:387`, `:411`). A rule that only
  survives naive edits is not tested.
- Distinguish `tampered` from merely invalid. Tamper means positive evidence of
  post-signing modification (`record_tamper`); revocation and unknown-issuer are
  invalid but **not** tampered — see `:310` and `:324`.

### 5. Verification stays a pure, offline function

`verify_packet(&packet, &ctx)` must remain deterministic with no network, no
database, no filesystem, and no clock affecting any rule. Today the only clock
read is `verification.rs:319` for the `verified_at` report field, which feeds no
boolean.

- Trust anchors come from `VerificationContext` only — never from the artifact
  under verification. `aip-verify` sources them exclusively from `--trust` and
  `--counterparty` (`aip-standalone/aip-verify/src/main.rs:77-78`). Preserve that.
- If a rule needs time, add an explicit `ctx.verification_time: Option<u64>`.
  Do not call `SystemTime::now()` inside a rule.
- Adding external state to `VerificationContext` is fine; reading external state
  inside `verification.rs` is not.

## Fail-open checklist

Fail-open paths already exist. Do not add more, and prefer closing these when
you are nearby:

- R12 `TRACE_BINDING` passes on a non-empty `trace_id` alone when
  `ctx.trace_data` is `None` — `trace_hash` unchecked (`verification.rs:580-595`).
- R13 skips `receipt_hash` when `ctx.receipt_data` is `None` (`:641-647`).
- R10 skips all expiry checks when `expires_at` is `None` (`:479`).
- R9 passes vacuously on an empty `ctx.revoked_jtis`.
- `aip-core/src/wellknown.rs:124` verifies a signature envelope **without**
  binding it to the token payload — unlike its sibling at `capability.rs:168`.

New rule: a missing optional input must never be recorded as a pass without the
report exposing that it was unchecked.

## Known dead or unwired code — do not build on it

- `aip-core/src/scoped_audit.rs` — in-memory only, unsigned, `pub entries`, no
  caller outside its own tests.
- `aip-core/src/runtime.rs` — `RuntimeBinding` is entirely self-reported
  (`agent_id` is an unvalidated argument, `hostname` reads `$HOSTNAME` first,
  `exe_hash` hashes the *path string* not the binary, `pid` is never compared at
  verification). It never reaches signed evidence.
- `merkle_leaf`/`merkle_internal` exist but no tree, root, or inclusion proof
  does; production roots are always `merkle_empty()`.
- `check_token_valid` / `check_delegation_valid` in `revocation.rs` — zero callers.

If your change makes one of these load-bearing, it needs its own design review.

## Before you finish

```bash
cd aip-standalone
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings   # CI sets RUSTFLAGS=-D warnings
cargo test --workspace                                   # baseline: 223 passed, 3 ignored
```

CI uses `dtolnay/rust-toolchain@stable`, so a new stable release can introduce a
lint that breaks the build independently of your change. Reproduce with the
current stable before assuming the failure is yours.
