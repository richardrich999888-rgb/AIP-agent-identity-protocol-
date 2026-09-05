# SNIFFER DOG 2.0 — IMPLEMENTATION REPORT

Companion to `SNIFFER_DOG_2_0_SPECIFICATION.md` (architecture) and
`SNIFFER_DOG_2_0_GAP_MATRIX.md` (Phase A inventory). One section per phase,
in the orchestrator's §15 format. A phase not listed here has not started.

---

# Phase B — identity / profile data model

## Status

**PASS in the reduced form authorized by `SNIFFER_DOG_2_0_GAP_MATRIX.md`
A.4.** A new crate, `aip-standalone/aip-agent`, provides a validated agent
identity (SD-01, reused primitives), a read-only authority projection (SD-05,
reused tokens) and a dimension-separated profile view (SD-02 skeleton). It
introduces no key, no signed object, no authority, no store and no summary
field. Identity lifecycle, identity issuer, lineage classification,
experience, history and API remain **MISSING** and are labelled so inside
the profile itself.

## Commits

| Commit | Content |
|---|---|
| `3798614` | Phase A: baseline, governing gate, gap matrix |
| `4e3961d` | RED: crate with no items; `tests/characterization.rs` (3 pins, passing); `tests/profile.rs` (16 tests, 87 compile errors) |
| *(this report's implementation commit)* | GREEN: `src/identity.rs`, `src/authority.rs`, `src/profile.rs`, `src/lib.rs`; workspace member |
| *(this report's documentation commit)* | this report; spec, gap-matrix, plan pointers |

Edits to the RED test files after `4e3961d`, verified by `git diff -w`:
rustfmt reflow; `DecisionId::from` → `DecisionId::from_bytes` (the type has
no `From` impl by design, `aip-reconcile/src/ids.rs`); removal of a redundant
fixture input (`agent_public_key`) because the builder must use the validated
identity's key rather than a caller-supplied one; one clippy borrow. **No
assertion was changed.**

## Current State

| Symbol | What it is | Authority behind it |
|---|---|---|
| `AgentIdentity::from_document(aid, parent)` | validated identity from an `AgentIdentityDocument` via `aip_core::validate_aid` / `validate_aid_with_parent` | the agent's self-signature; optionally the parent's lineage signature against the key the caller asserts |
| `AgentIdentity::from_summary(summary)` | validated identity from a packet's `AgentIdentitySummary`: well-formed id, Ed25519 only, 32-byte key, `derive_aip_id` re-derivation (packet rule R2 outside `verify_packet`) | derivation only |
| `LifecycleAssertion::{NotEstablished, SelfAsserted{status, sequence}}` | the agent's lifecycle statement; **no authoritative variant exists** | the agent |
| `LineageProofState::{NotCarried, Absent, Present{signer_id, verified}}` | the parent proof as a proof, not as a parent | parent key holder (when verified) |
| `IssuerKeys`, `AuthorityChain`, `project_authority(agent, chains, keys, as_of)` | per-chain outcome under the decision point's rules 1–4 and 7: `SelfIssuedRoot`, `UntrustedIssuer`, `RootSignatureInvalid`, `ChainInvalid(AipError)`, `LeafNotAgent`; verified chains split into `authorized` / `not_in_standing` (`Expired` / `NotYetValid`) | token issuers, by signature, through `aip_core::verify_scoped_token` and `verify_delegation_chain` |
| `AuthorityProjection::issuers()` → `IssuerAssertion` | the issuer partition, from verified chains only | token issuers |
| `InstanceAssertion::{Claimed, AuthorizedTarget{decision_id, decision_point_id}}` | who vouched for an `ExecutionBinding` | agent / trusted decision point via `verify_expected_execution_for_agent` with the **validated** agent key |
| `ReconciledRecord{record, source: VerifierLocal}` | a `Reconciliation` carried verbatim, admitted only if its `decision_id` is one of this agent's verified expectations | the reconciler, in the builder's own trust domain |
| `AgentProfile` | twelve fixed partitions incl. `excluded_expectations`, `excluded_bindings`, `excluded_reconciliations`, `lineage: NotEvaluated`, `experience: NotDerived` | each partition names its own |
| `build_profile(&ProfileInputs)` | fails only when the identity does not validate; every other defect lands in an `excluded_*` partition with its reason | — |

Trust anchors (`IssuerKeys`, `DecisionPointTrustAnchors`) are supplied by the
builder. Nothing about whom to trust is read from the artifacts.

## Evidence

`aip-standalone/aip-agent/tests/characterization.rs` (pins of the existing
primitives; unchanged by GREEN):

| Test | Pinned fact |
|---|---|
| c01 | `activate_identity` / `suspend_identity` mutate `status` and `sequence` in place; `validate_aid` then returns `SignatureInvalid`. No lifecycle transition has a signer. |
| c02 | `lineage_depth` is 1 for a child and 1 for a grandchild; the proofs chain, the depth does not. |
| c03 | a root document carries only the agent's own signature; the parent lineage proof is the only external identity endorsement in the system. |

`aip-standalone/aip-agent/tests/profile.rs`:

| Test | Property |
|---|---|
| p01 | identity by re-derivation; other key → `DerivationMismatch`; malformed id → `MalformedId`; 3-byte key → `KeyLength` |
| p02 | a document mutated after signing is refused (`Document(SignatureInvalid)`), not relabelled |
| p03 | `LifecycleAssertion` has no authoritative variant (exhaustive `match`; a new variant is a compile error) |
| p04 | identity → instance link is the validated AIP-ID only; same pid, other agent → not this identity's |
| p05 | lineage proof reported as `Absent` / `Present{verified: None}` / `Present{verified: Some(true)}`; wrong parent key → `Document(LineageInvalid)` |
| p06 | projection reproduces the decision point's acceptance of the fixture chain: path, issuers, effective scope, `Valid` |
| p07 | untrusted issuer, rewritten root expiry (Skill 3 attack), rewritten hop grantee, chain ending at another agent, self-issued root → each excluded with the named reason, none authorized |
| p08 | expired / not-yet-valid chains are verified but `not_in_standing`, apart from both `authorized` and `excluded` |
| p09 | top-level partitions are exactly the twelve named; no key anywhere in the serialized profile contains score / trust / confiden / reputation / rating / rank / grade; placeholders explicit |
| p10 | self-declared text carries `SELF_DECLARED · UNVERIFIED` and appears under no other key, whatever it says |
| p11 | issuers derive only from verified authority; a rewritten root yields no issuer and one exclusion |
| p12 | DP-signed expectation → `AuthorizedTarget`; packet binding → `Claimed`; binding naming another agent → `excluded_bindings`; untrusted DP, agent-key DP (`DecisionKeyIsAgentKey`), expectation for another agent → `excluded_expectations` with reason |
| p13 | records join through `decision_id` of this agent's verified expectations; carried verbatim incl. `PHANTOM_CLAIM`; foreign decision and `None` decision excluded with reason |
| p14 | an empty profile asserts nothing: empty partitions, explicit placeholders, lifecycle = the document's own `Pending` |
| p15 | an identity that fails validation yields `ProfileError::Identity`, no profile |
| p16 | crate sources contain none of `calculate_reputation`, `ReputationVote`, `reputation_root`, `aggregate_reputation`, `evaluate_hardware_trust`, `verify_liveness`, `score`, `trust_level` |

## Security Findings (unchanged by this phase, recorded)

- **Lifecycle without authority.** The AID lifecycle state machine in
  `aip-core` has no signer and its mutations invalidate the self-signature
  (c01). The CLI activates and stores documents without re-validating. Phase
  B does not repair this; it refuses to trust it. Repair belongs to whoever
  becomes the identity authority (spec §8, NOT DETERMINED).
- **Depth does not chain** (c02). Ancestry must be rebuilt from proofs
  (Phase C).
- **Reconciliation records are unsigned.** The profile admits only
  `VerifierLocal` records; a profile built from records it did not compute is
  outside this phase's contract.
- **`aip-service` duplicate authority model** (P1, unchanged). The profile
  layer does not touch the service.

## Changes Made

| File | Change |
|---|---|
| `aip-standalone/Cargo.toml` | member `aip-agent` |
| `aip-standalone/aip-agent/Cargo.toml` | new crate; depends on aip-types, aip-crypto, aip-core, aip-authorize, aip-protocol, aip-reconcile, serde; dev: aip-observe, serde_json |
| `aip-standalone/aip-agent/src/{lib,identity,authority,profile}.rs` | new |
| `aip-standalone/aip-agent/tests/{characterization,profile}.rs` | new (RED commit), formatting + fixture fixes (GREEN commit) |

No file in aip-crypto, aip-core, aip-protocol, aip-authorize, aip-observe,
aip-reconcile, ghost-demo or aip-service was modified. No canonical encoder,
signed field, verification rule or wire format changed; the protocol change
guard did not apply.

## Tests

| Suite | Result |
|---|---|
| `cargo test -p aip-agent` | 19 passed (3 characterization + 16 profile), 0 failed |
| `cargo test --workspace` (aip-standalone) | 567 passed, 0 failed, 3 ignored (baseline 548 / 0 / 3; +19) |
| `cargo test` (aip-service) | 39 passed, 0 failed (unchanged) |
| `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| `cargo fmt --all --check` | clean |

All previous tests are unchanged. tracefs was mounted by hand so the Stage
7b/7c live tests ran rather than skipped.

## Remaining Gaps

Identity issuer and lifecycle authority (NOT DETERMINED); four-way parent
classification, `LineageEdge`, `LINEAGE_VIOLATION` reachability (Phase C);
delegation graph (Phase D); signed reconciliation records and reconciler key
(Phase E precondition, NOT DETERMINED); ledger, experience (Phases E–F);
persistence, API, export (Phase G); `aip-service` duplicate authority model.

## Security Claims

Supported by implementation and tests:

- An `AgentIdentity` exists only if the AIP-ID re-derives from the presented
  key and provenance and, for a document, the document's own signature
  verifies.
- The profile's `authority` partition contains only chains the decision
  point itself would accept, under the same `aip_core` verification calls.
- The profile's `reconciled` partition contains only records whose decision
  the builder verified as this agent's, carried verbatim.
- Nothing the agent writes about itself appears outside `self_declared`.
- The profile has no numeric or categorical summary across partitions.

Not claimed: that any agent is who it says beyond key possession; that any
lifecycle state is true; that any instance ran; that any authority was used;
that the profile is complete, persistent, portable or signed.

## Next Gate

Phase C (parent/child lineage): identity lineage from AID proofs across
generations, process lineage edges from Stage 7c fork/exec events, authority
lineage from tokens; the four-way `CLAIMED / AUTHORIZED / OBSERVED /
RECONCILED` classification for parent and child; `LINEAGE_VIOLATION`
precondition in the reconciler under `syntriass-reconciliation` rules. RED
first. Skill 8 remains the next numbered Ghost gate and is untouched.
