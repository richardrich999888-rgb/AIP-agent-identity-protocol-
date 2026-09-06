# AIP CORRECTNESS REPORT

Skill 3 (`syntriass-aip-correctness`) / Orchestrator Stage 0 — AIP authority
correctness. This report records what was proven broken, what was changed,
what is now proven, and what SYNTRIASS still must not claim.

## Commit audited

- Baseline (production code unmodified): `1d1a984`
  (`docs/architecture/IMPLEMENTATION_BASELINE.md` records the 223/0/3 test
  baseline taken at this commit).
- Invariant normalization `45e5702` verified present as an ancestor.

## Correction commits (in order)

| Commit | Content |
|---|---|
| `22d7b3f` | RED adversarial tests reproducing the `expires_at` extension against the unmodified implementation (all 8 fail there), plus `IMPLEMENTATION_BASELINE.md` |
| `830c1e5` | Bind `expires_at` into authority signatures; injective, domain-tagged payloads; `PACKET_VERSION` 1→2; `AIP_VERSION` 3→4; adversarial and boundary tests |
| `14da5a8` | `validate_aip_id` non-ASCII guard — no panic on malformed input |
| `228b02e` | `KeyPair` `Debug` redacts `private_key` |
| (this commit) | This report; service trust-boundary doc comment |

## BEFORE state (verified from source at `1d1a984`, not from the audit)

| Concern | Observed |
|---|---|
| `aip-core/src/capability.rs::canonical_token_payload` | `jti ‖ issuer_id ‖ agent_id ‖ allowed… ‖ 0xFF ‖ denied… ‖ issued_at`. **No `expires_at`.** No length prefixes. No domain tag. |
| `aip-core/src/delegation.rs::canonical_delegation_payload` | `jti ‖ parent_jti ‖ issuer_id ‖ grantee_id ‖ depth ‖ allowed… ‖ 0xFF ‖ denied… ‖ issued_at`. **No `expires_at`.** Same defects. |
| `encode_scope_action` (both files) | `Custom(s)` → `0x01 ‖ s ‖ 0x00`: NUL-terminated, not length-prefixed. |
| `verify_delegation_chain` | Never read `expires_at`; no check that a child does not outlive its parent. |
| `aip-protocol/src/evidence_packet.rs::canonical_bytes` | Includes `expires_at` → covered by packet hash / **agent** signature only. |
| `aip-protocol/src/verification.rs::check_temporal_validity` (R10) | Reads `expires_at` from the packet, i.e. from a field the issuer never signed. |
| `aip-core/src/lib.rs` encoders (AID self-sig, lineage, CapabilityGrant, ReputationVote) | Raw concatenation of variable-length strings; no domain tags. |
| `aip-crypto/src/lib.rs::validate_aip_id` | Byte-index slicing; multi-byte UTF-8 at the split point panics. |
| `aip-types::KeyPair` | `#[derive(Debug)]` prints the private key. |
| `aip-protocol/src/canonical.rs` | Correct injective encoder — but `pub(crate)` and downstream of `aip-core`, so unusable by the authority layer. |

## Vulnerability reproduction (RED, commit `22d7b3f` against `1d1a984`)

Threat: an agent legitimately holds its own packet-signing key. It rewrites
only `expires_at` on an authority token it did **not** issue, recomputes
`packet_hash`, re-signs the packet with its own key, and presents it. Every
issuer signature is byte-for-byte the original.

Tests written, then run against the unmodified implementation:

```
capability::tests::test_mutate_expires_at_extend_rejected ............ FAILED
capability::tests::test_mutate_expires_at_some_to_none_rejected ...... FAILED
capability::tests::test_mutate_expires_at_none_to_some_rejected ...... FAILED
delegation::tests::test_mutate_delegation_expires_at_extend_rejected . FAILED
delegation::tests::test_mutate_delegation_expires_at_some_to_none_rejected FAILED
  panicked: "SECURITY: expires_at extended without re-signing but token still verifies"

test_root_token_expiry_extension_resealed_packet_rejected ............ FAILED
test_root_token_expiry_removal_resealed_packet_rejected .............. FAILED
test_delegation_hop_expiry_extension_resealed_packet_rejected ........ FAILED
  panicked: "expected rule ROOT_TOKEN_SIGNATURE to FAIL, but it passed:
             root token signed by trusted issuer aip1…"
  panicked: "expected rule DELEGATION_CHAIN to FAIL, but it passed:
             1-hop delegation chain verified (per-hop signatures, …)"
```

At the packet level the mutated packet produced `valid = true`,
`tampered = false` — all 14 rules passed with `expires_at = u64::MAX`.

## Exact root cause

`expires_at` was computed **after** the signing payload was built and simply
attached to the struct (`capability.rs`: payload built at issue-time from
`(jti, issuer_id, agent_id, scope, now_ms)`, then `expires_at:
expires_in_ms.map(|d| now_ms + d)`). Verification recomputed the same
payload, so any `expires_at` value hashed to the same `payload_hash`. The same
omission existed in `delegation.rs`. The packet's canonical bytes covered
`expires_at`, but those bytes are signed by the **agent** — the party the
authority is supposed to constrain.

## Implementation change

### Canonical encoder relocation

`aip-protocol/src/canonical.rs` was moved to `aip-types/src/canonical.rs`
(public) and re-exported `pub(crate)` from `aip-protocol`. Reason: the
dependency direction is `aip-types ← aip-crypto ← aip-core ← aip-protocol`,
so `aip-core` could not use the existing encoder without a cycle. There is
still exactly one encoder. Added: `put_domain`, `put_u32`.

### Expiry integrity

- `canonical_token_payload(jti, issuer_id, agent_id, scope, issued_at, expires_at)`
- `canonical_delegation_payload(jti, parent_jti, issuer_id, grantee_id, scope, depth, issued_at, expires_at)`

Both end with `put_opt_u64(expires_at)`: `None` → `0x00`; `Some(t)` →
`0x01 ‖ t_le64`. `issue_scoped_token` now computes `expires_at` before
signing; `verify_scoped_token`, `create_delegation`, `create_sub_delegation`,
`verify_delegation_chain` all pass the stored `expires_at` into the payload.

`verify_delegation_chain` gained step 5 (after signature verification): if
the parent has `Some(p)`, a hop with `None` or `Some(c) where c > p` is
rejected with `AttenuationViolation`. Ordering is deliberate: a *forged*
expiry fails as `SignatureInvalid`; an issuer who *genuinely* over-delegated
fails as `AttenuationViolation`.

### Canonical encoding

All authority payloads now use `put_str` (u32 LE length prefix) for every
variable-length field, `encode_scope` (explicit `allowed`/`denied` counts;
`Custom(s)` length-prefixed, NUL-safe), explicit counts for grant actions and
constraints, and `put_opt_u64` for every `Option<u64>`. Fixed-width fields
(`[u8;16]` JTIs, `[u8;32]` roots, 4-byte magic) are appended raw, which is
injective because their width is fixed.

### Domain separation

Every signed payload produced by `aip-core` begins with a length-prefixed tag:

| Payload | Tag |
|---|---|
| ScopedToken | `AIP/ScopedToken/v1` |
| DelegationToken | `AIP/DelegationToken/v1` |
| AID self-signature | `AIP/AgentIdentityDocument/v1` |
| Lineage proof | `AIP/LineageProof/v1` |
| CapabilityGrant | `AIP/CapabilityGrant/v1` |
| ReputationVote | `AIP/ReputationVote/v1` |

The tag enters the bytes that are hashed into `Signature.payload_hash`, so the
domain is part of the signed preimage. `sign_ed25519`'s envelope
(`0x01 ‖ signer_id ‖ ts ‖ nonce ‖ sha256(payload)`) was not changed.

## AFTER state

The 8 RED tests pass. Mutating `expires_at` in any direction on a validly
signed ScopedToken or DelegationToken changes the payload hash, so
`verify_scoped_token` returns `false` and `verify_delegation_chain` returns
`SignatureInvalid`; at the packet level R5 `ROOT_TOKEN_SIGNATURE` / R6
`DELEGATION_CHAIN` fail and the report is `valid = false`.

## Expiry integrity — audit trail

    FINDING:  ScopedToken / DelegationToken expiry not covered by issuer signature.
    LOCATION: aip-core/src/capability.rs, aip-core/src/delegation.rs
    ROOT CAUSE: expires_at omitted from canonical_token_payload /
              canonical_delegation_payload.
    ATTACK:   Holder rewrites expires_at, recomputes packet_hash, re-signs
              packet with own key; all 14 rules pass.
    FIX:      put_opt_u64(expires_at) appended to both payloads; expiry
              computed before signing; chain verifier enforces child ≤ parent.
    SECURITY PROPERTY RESTORED: authority validity window is bound by the
              issuer's signature (I6).
    TEST:     test_mutate_expires_at_{extend,some_to_none,none_to_some}_rejected,
              test_mutate_delegation_expires_at_{extend,some_to_none}_rejected,
              test_{root_token,delegation_hop}_expiry_*_resealed_packet_rejected,
              test_legitimately_signed_hop_outliving_parent_rejected
    LIMITATION: tokens issued under the old encoding cannot be verified;
              see Compatibility.

## Canonical encoding — audit trail

    FINDING:  Raw concatenation of variable-length fields in signed payloads.
    LOCATION: capability.rs, delegation.rs, lib.rs (aid, grant, lineage, vote)
    ROOT CAUSE: field.as_bytes() appended without length; NUL terminator on
              Custom scope actions; no element counts.
    ATTACK:   ("ab","c") and ("a","bc") share a preimage; Custom("x\0y") vs
              Custom("x") + Custom("y") share a preimage; moving an action from
              denied to allowed can share a preimage.
    FIX:      Shared aip_types::canonical encoder (length prefix, counts,
              presence bytes) used by every authority payload.
    SECURITY PROPERTY RESTORED: encode(a) == encode(b) ⇒ a == b for every
              representable value (I14).
    TEST:     aip_types::canonical::tests::{adjacent_strings_are_injective,
              interior_nul_is_unambiguous, option_presence_is_explicit,
              scope_counts_prevent_allowed_denied_migration},
              test_token_payload_adjacent_ids_do_not_collide,
              test_token_payload_custom_action_interior_nul_unambiguous,
              test_token_payload_expiry_presence_is_distinct,
              test_delegation_payload_adjacent_ids_do_not_collide,
              test_capability_grant_encoding_adjacent_ids_do_not_collide,
              test_lineage_encoding_adjacent_fields_do_not_collide,
              test_reputation_vote_encoding_adjacent_ids_do_not_collide
    LIMITATION: `sign_ed25519`'s own envelope (`signer_id ‖ ts ‖ nonce`) was
              not re-encoded; it is injective because `sha256(payload)` and
              `nonce` are fixed-width and `signer_id` is the only
              variable-length element preceding fixed-width data — but it
              carries no domain tag of its own. Domain separation is provided
              by the payload, not the envelope.

## Domain separation — audit trail

    FINDING:  Signed payloads had no type tag.
    ATTACK:   A signature over one object type could be presented as a
              signature over another type with coincidentally equal bytes.
    FIX:      put_domain(tag) as the first element of every aip-core payload.
    TEST:     test_scoped_token_signature_cannot_verify_as_delegation
              (genuine ScopedToken issuer_sig transplanted onto a
              field-matching DelegationToken → SignatureInvalid),
              test_token_payload_starts_with_domain_tag,
              test_signed_payload_domains_are_pairwise_distinct
    LIMITATION: EvidencePacket canonical bytes (`AEP1` magic + version) and
              ActionAttestation / ReceiptBinding payloads in aip-protocol were
              not re-tagged in this stage; they were already length-prefixed
              and are distinguished by the `AEP1` magic. Re-tagging them is a
              further wire break and is deferred to the next wire-version
              change, recorded in Findings deferred.

## Verification-time semantics

Decision: **no `verification_time` field was added.**

Source inspection (`verification.rs::check_temporal_validity`) shows R10
already has explicit, offline temporal semantics: every token's
`issued_at`/`expires_at` is compared against the packet's own `decided_at`
and each action's `performed_at`. The verifier's wall clock is never
consulted, so verification is deterministic and reproducible years later —
the correct property for evidence. Adding ambient system time would have
introduced an unanchored trust source (I21) without a defined contract.

With `expires_at` now issuer-signed, R10's inputs are all signed by the party
responsible for them: window by the issuer, `decided_at`/`performed_at` by the
agent. The remaining limitation is that the agent controls its own timestamps
(no trusted time source) — recorded below.

Boundary convention (now tested): a timestamp **equal** to `expires_at` is
inside the window; `expires_at + 1` is outside. `is_token_expired`
(`now > exp`) uses the same inclusive convention.

Tests: `test_action_at_exact_expiry_boundary_accepted`,
`test_action_one_past_expiry_rejected`, `test_decision_after_expiry_rejected`,
`test_unbounded_root_token_accepts_far_future_action`,
`test_delegation_hop_expiry_bounds_action`, plus the pre-existing
`test_action_after_token_expiry_rejected`.

## Service authority boundary (§16, §17)

Inspected `aip-service/src/{capability.rs, delegation.rs, evidence.rs,
authority.rs, tokens.rs, handlers.rs}`.

**§16 duplicate authority logic — identified, DEFERRED.**
`aip-service/src/capability.rs` re-implements `CapabilityScope` with its own
`meet` / `is_subset_of` / `permits`; `aip-service/src/delegation.rs` keeps a
separate `DelegationToken` + SHA3-hex delegation log with its own `MAX_DEPTH`
and string `expires_at`; `handlers.rs` computes effective scope by folding
`meet` over that log. This is a second attenuation model (violates I18).
It is **not** on the evidence-packet path: `evidence.rs` builds and verifies
packets exclusively through `aip_core` / `aip_protocol` (the 38 service tests
pass unchanged with the new encoding). Migrating the service's scope/delegation
API onto `aip_core::capability` / `aip_core::delegation` changes the service's
persisted delegation log format and HTTP models and needs cross-tenant
isolation tests of its own; it is out of the minimum-change scope of Stage 0
and is recorded in `GAP_MATRIX` terms as an open I18 item.

**§17 trust anchors — documented, correct as a calculator.**
`verify_request` accepts caller-supplied `trusted_issuers` /
`trusted_counterparties` and runs `verify_packet` deterministically. The
service does not select trust anchors and does not decide authorization; a
`valid` report means "consistent with the anchors the caller supplied". A doc
comment now states this on `verify_request`. This is a verifier, not a
decision point; the Ghost decision point is Stage 2 and was not built here.

## Key handling (§18)

- `KeyPair` `Debug` now redacts `private_key` (`<redacted N bytes>`).
- `Serialize`/`Deserialize` on `KeyPair` were **kept**: `aip_core::store`
  persists `StoredIdentity { aid, keypair }` as JSON. Removing the derives
  would be a key-management redesign, which this skill prohibits. The
  plaintext-at-rest persistence is a documented limitation.
- No debug-printing or logging of key pairs was found in production code.
- `zeroize` was not added: key lifetime in this codebase is process-scoped
  `Vec<u8>` handed to `ed25519-dalek`; without a persistence/HSM boundary to
  protect, adding it would be security theatre.

## Input validation (§19)

`validate_aip_id` now rejects non-ASCII input before any slicing (Base58 is
ASCII). Test `test_aip_id_malformed_never_panics` runs 12 malformed inputs
and a 12-position boundary sweep under `catch_unwind`; each returns `Err`,
none panics.

## Adversarial tests (Layer 2)

| Test | Location | Result |
|---|---|---|
| mutate `ScopedToken.expires_at` (extend / Some→None / None→Some) | `capability.rs` | rejected |
| mutate `DelegationToken.expires_at` (extend / Some→None) | `delegation.rs` | `SignatureInvalid` |
| legitimately signed hop outliving parent (later / unbounded) | `delegation.rs` | `AttenuationViolation`; equal expiry accepted (control) |
| ScopedToken signature transplanted onto DelegationToken | `delegation.rs` | `SignatureInvalid` |
| `("ab","c")` vs `("a","bc")` — token, delegation, grant, lineage, vote, raw encoder | `capability.rs`, `delegation.rs`, `lib.rs`, `aip-types/canonical.rs` | bytes differ |
| interior NUL in `Custom` scope action | `capability.rs`, `canonical.rs` | unambiguous |
| `Option<u64>` `None` vs `Some(0)` | `capability.rs`, `delegation.rs`, `canonical.rs` | bytes differ |
| allowed↔denied migration with same multiset | `canonical.rs` | bytes differ |
| domain tags pairwise distinct | `lib.rs` | pass |
| malformed / non-ASCII AIP-ID | `aip-crypto` | `Err`, no panic |

## Integration tests (Layer 3, through `verify_packet`)

| Test | Rule that fails | Result |
|---|---|---|
| root token `expires_at` → `u64::MAX`, packet re-sealed | R5 `ROOT_TOKEN_SIGNATURE` | rejected |
| root token `expires_at` → `None`, packet re-sealed | R5 | rejected |
| hop `expires_at` → `u64::MAX`, packet re-sealed | R6 `DELEGATION_CHAIN` | rejected |
| action at exactly `expires_at` | — | accepted, `valid = true` |
| action at `expires_at + 1` | R10 `TEMPORAL_VALIDITY` | rejected |
| decision at `expires_at + 1` | R10 | rejected |
| unbounded root, action 10 years out | — | accepted |
| action past hop expiry; detail names `delegation hop 0` | R10 | rejected |
| packet `version = 1`, re-sealed | R1 `STRUCTURE` (`unsupported version 1`) | rejected |
| all 17 pre-existing packet tests (honest path, JSON round-trip, every tamper class, trust-floor, two-hop, revocation, …) | as before | pass |

## Test results

| Suite | Before (`1d1a984`) | After (`228b02e`) |
|---|---|---|
| aip-core | 109 | 125 (+16) |
| aip-crypto | 7 | 8 (+1) |
| aip-types | 0 | 5 (+5) |
| aip-protocol unit | 4 | 4 |
| aip-protocol tests/bundle.rs | 6 (1 ignored) | 6 (1 ignored) |
| aip-protocol tests/evidence_packet.rs | 17 | 26 (+9) |
| aip-test | 13 | 13 |
| aip-real-tests | 67 (2 ignored) | 67 (2 ignored) |
| **aip-standalone total** | **223 / 0 / 3** | **254 / 0 / 3** |
| aip-service | 38 | 38 |

`cargo clippy --workspace --all-targets -- -D warnings`: clean in both
workspaces. `cargo fmt --all -- --check`: clean in both workspaces.

## Compatibility / versioning

- `PACKET_VERSION` bumped **once**, `1 → 2`, for the whole correction set.
  R1 `STRUCTURE` now reports
  `unsupported version 1 (this verifier implements v2; embedded authority
  signatures of other versions are not comparable)`. A v1 packet's embedded
  issuer signatures were produced over the defective payload; accepting them
  would re-open the vulnerability, so there is no compatibility shim.
- `AIP_VERSION` bumped once, `0x0003 → 0x0004`, because the AID
  self-signature and lineage-proof payloads changed. `validate_aid` rejects
  `0x0003` documents with `UnsupportedVersion`.
- No JSON fixtures, known-answer vectors, or persisted artefacts exist in the
  repository; nothing had to be regenerated. Any externally stored v1 packets,
  v3 AIDs, tokens, grants, or votes must be re-issued.
- `aip-service` persisted state (`store/`, delegation log) does not embed
  aip-core signatures and was unaffected (38/38 tests pass).

## Findings addressed

F-01 expiry not signed (ScopedToken, DelegationToken) · F-02 non-injective
authority encodings (token, delegation, grant, AID, lineage, vote) · F-03 no
domain separation · F-04 `validate_aip_id` panic · F-05 `KeyPair` Debug leak ·
chain child-outlives-parent not enforced · v1 packets rejected explicitly.

## Findings deferred (with reason)

| Item | Reason |
|---|---|
| `aip-service` duplicate scope/delegation model (I18) | Service-API and persisted-format change; needs its own cross-tenant tests; not on the evidence path. |
| Domain tags for aip-protocol payloads (EvidencePacket canonical bytes, ActionAttestation, ReceiptBinding countersign) | Already length-prefixed and magic-distinguished; adding tags is a further wire break — batch into the next `PACKET_VERSION` change. |
| Domain tag inside `sign_ed25519`'s envelope | Envelope is injective; domain lives in the payload. Changing the envelope would invalidate every signature type at once — defer to a deliberate crypto-envelope version. |
| `create_delegation` doc claims "parent token is not expired" but does not check wall-clock expiry | Wall-clock policy is explicitly out of scope (§15); the docstring overstates and should be corrected when the temporal contract is defined. |
| Plaintext `KeyPair` persistence in `aip_core::store` | Key-management redesign prohibited by §18. |
| `AlgorithmId::MlDsa65` / `Hybrid` exist as identifiers only | No implementation; must not be represented as capability. Unchanged, documented. |

## Remaining limitations

1. Timestamps inside a packet (`decided_at`, `performed_at`) are asserted by
   the agent. R10 is sound relative to those values, but there is no trusted
   time source (I21).
2. Trust anchors are caller-supplied everywhere (library `VerificationContext`,
   service `VerifyRequest`). Verification proves consistency with the
   anchors, not that the anchors are right.
3. Only Ed25519 is implemented. The `MlDsa65`/`Hybrid` identifiers are
   inert.
4. Private keys at rest in `aip_core::store` are plaintext JSON.
5. The service's second attenuation model (I18) remains.
6. `MAX_DELEGATION_DEPTH` semantics: the existing
   `test_chain_exceeding_max_depth_rejected` is vacuous (noted in the audit);
   not changed here as it is not a P0 signature defect.

## Security claims that are now justified

- The validity window (`expires_at`) of a ScopedToken and of every
  DelegationToken hop is bound by the **issuer's** Ed25519 signature; a holder
  or packet-signer cannot extend, shorten, add, or remove it without the
  issuer's key. (Tests: 8 RED→GREEN + `test_legitimately_signed_hop_outliving_parent_rejected`.)
- A delegation hop cannot outlive its parent even when signed by the
  legitimate delegator.
- Every `aip-core` signed payload is injective and domain-tagged.
- Packet verification remains deterministic and offline; all 14 rules and
  their semantics are unchanged except that R5/R6 now also fail on expiry
  tampering (a strict tightening) and R1 explains version rejection.
- Malformed AIP-ID input cannot panic the verifier.
- Formatting a `KeyPair` with `{:?}` does not reveal the private key.

## Security claims that remain prohibited

SYNTRIASS must **not** claim any of the following on the basis of this
repository state:

- independent execution observation, process attribution, PID-reuse
  resistance, or executable-content identity (no ExecutionBinding — Stage 1);
- an independent authorization decision point or `ExpectedExecution`
  (Stage 2);
- observer attestation, observer continuity, or sensor-health semantics
  (Stage 3);
- reconciliation results of any class, including `VERIFIED_EXECUTION`,
  `PHANTOM_CLAIM`, or `CANNOT_PROVE` (Stage 4);
- evidence-strength classification (`Heuristic`/`Correlated`/`Attested`/`Proven`),
  warrants, or containment (Stages 5–8);
- NEXORA commitments, Merkle inclusion proofs, or externally anchored history
  (`merkle_leaf`/`merkle_internal`/`merkle_empty` are primitives only);
- post-quantum security (`MlDsa65`/`Hybrid` are identifiers with no
  implementation);
- hardware attestation (`evaluate_hardware_trust` is structural only);
- trusted time, or that a packet's timestamps are independently verified;
- "tamper-proof", "immutable", "zero-trust", or "independently verified" for
  any artefact — the correct statement is: *tamper-evident with respect to
  caller-supplied trust anchors, with the authority window now bound by the
  issuer signature*.

## Files changed

| File | Change |
|---|---|
| `aip-standalone/aip-types/src/canonical.rs` | **new** — shared injective encoder + tests |
| `aip-standalone/aip-types/src/lib.rs` | `pub mod canonical`; `AIP_VERSION` 3→4; `KeyPair` redacting `Debug` |
| `aip-standalone/aip-protocol/src/canonical.rs` | now `pub(crate) use aip_types::canonical::*` |
| `aip-standalone/aip-core/src/capability.rs` | domain tag; `expires_at` in payload; shared encoder; tests |
| `aip-standalone/aip-core/src/delegation.rs` | domain tag; `expires_at` in payload; child ≤ parent expiry check; tests |
| `aip-standalone/aip-core/src/lib.rs` | domain tags + injective encoding for AID, lineage, grant, vote; tests |
| `aip-standalone/aip-crypto/src/lib.rs` | non-ASCII guard in `validate_aip_id`; panic tests |
| `aip-standalone/aip-protocol/src/evidence_packet.rs` | `PACKET_VERSION` 2 with history doc |
| `aip-standalone/aip-protocol/src/verification.rs` | R1 version-mismatch detail names versions |
| `aip-standalone/aip-protocol/tests/evidence_packet.rs` | RED tests, R10 boundary tests, v1 rejection, fixture expiry parameter |
| `aip-service/src/evidence.rs` | trust-boundary doc comment on `verify_request` |
| `docs/architecture/IMPLEMENTATION_BASELINE.md` | **new** — Phase 0 snapshot |
| `docs/architecture/AIP_CORRECTNESS_REPORT.md` | **new** — this report |

## Next gate

Skill 3 completion gate: every P0 item in §26 is satisfied or explicitly
deferred with reason above. The repository is ready for
**SKILL 4 — EXECUTION BINDING**, pending explicit authorization. No Stage ≥1
code was written.
