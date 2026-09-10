# NEXORA IMPLEMENTATION PLAN

**Skill 10, Gate 0.** Baseline forensics and the plan the remaining gates
execute against. Produced before any production code was written.

**Baseline commit:** `82da7a6` (audit), `5057ac7` (test-robustness fix made
during this gate — see §0.3). Branch
`claude/codebase-production-readiness-wm6idp`.

---

## 0. What this gate established

### 0.1 Documents read

`SECURITY_INVARIANTS.md`, `CURRENT_SYSTEM.md`, `OBSERVATION_MODEL.md`,
`EXECUTION_BINDING.md`, `RECONCILIATION_MODEL.md`, `OBSERVER_ATTESTATION.md`,
`CONTAINMENT_MODEL.md`, `GAP_MATRIX.md`, `NEXORA_BOUNDARY.md`,
`SNIFFER_DOG_COMPLETE_IMPLEMENTATION_REPORT.md`,
`SNIFFER_DOG_PR3_HARVEST_REPORT.md`, `SNIFFER_DOG_PLAIN_ENGLISH.md`.

### 0.2 What already exists of NEXORA

`NEXORA_BOUNDARY.md` §1 says `NEXORA = MISSING`. That statement described
`377d5fc` and is **stale**: Gates 6 and 7 of the completion mandate built
`aip-nexora`, and §4 of the same document records the rows they closed. The
state at this baseline is:

| Layer | State | Where |
|---|---|---|
| Merkle tree (RFC 6962), domain-separated leaves, inclusion + consistency proofs and verifiers | **EXISTS** | `aip-nexora/src/merkle.rs`, tests `merkle.rs` m01–m16 |
| Signed chained heads, commitment log, single-record proof object, offline inclusion verifier, head tracker, anchor sink | **EXISTS** | `aip-nexora/src/commitment.rs`, tests `nexora.rs` x01–x15 |
| A **portable proof over an execution** — subject, authority, expectation, binding, observer evidence, lineage, reconciliation, continuity, warrant, commitments — and a verifier for it | **MISSING** | this plan |

So Skill 10's Gate 3 (commitment protocol) is largely already satisfied and
must be *reused*, not rebuilt. The work is Gates 1–2 and 4–16: the proof
object, its binding, and an offline verifier that re-derives the verdict.

### 0.3 Test baseline

`cargo test --workspace` at `82da7a6` produced one intermittent failure: the
run aborted after exactly 374 passing tests, twice out of five. Cumulative
per-target counts place that boundary inside `aip-observe/tests/fanotify.rs`.
The cause is structural: the watch uses `FAN_MARK_MOUNT` and the temp
directory is on the root filesystem, so its queue is shared with every
writer on that mount — cargo's own artifact writes included. Two assertions
in the live tests were about the host being quiet rather than about the
observer. They were replaced (commit `5057ac7`) with the invariant that
belongs to this code — kernel-reported loss is counted and carried into the
batch, so the collector degrades rather than claiming coverage it never
had — and with an explicit skip when an overflow means the evidence never
arrived. No property was weakened; no production code changed.

The baseline for Skill 10 is therefore: **`aip-standalone` 787 passed, 0
failed, 3 ignored; `aip-service` 39 passed, 0 failed; clippy `-D warnings`
and `cargo fmt --check` clean in both.**

---

## 1. Existing reusable primitives

Every one of these is already adversarially tested and is reused unchanged.

| Primitive | Where | Why it is safe to reuse |
|---|---|---|
| Canonical encoders `put_domain / put_u8 / u16 / u32 / u64 / bytes / str / opt_str / opt_u64` | `aip-types/src/canonical.rs` | Length-prefixes every variable field, tags every `Option`, counts every collection. Collision vectors tested in `aip-protocol/tests/evidence_packet.rs` |
| `sha256`, `sign_ed25519`, `verify_ed25519`, the `Signature` envelope (`algorithm`, `signer_id`, `timestamp`, `nonce`, `payload_hash`) | `aip-crypto`, `aip-types` | One implementation, already the substrate of five signed object types |
| `merkle_leaf` (`0x00 ‖ …`), `merkle_internal` (`0x01 ‖ l ‖ r`), `merkle_empty` | `aip-crypto` | Domain-separated so a leaf can never be read as an internal node |
| `LeafKind`, `leaf_hash`, `MerkleTree`, `InclusionProof`, `ConsistencyProof`, `verify_inclusion`, `verify_consistency` | `aip-nexora::merkle` | Gate 6; RFC 6962/9162, proofs bound to index and size |
| `SignedHead`, `NexoraSigner`, `NexoraTrustAnchors`, `verify_signed_head`, `CommitmentLog`, `ProofObject`, `verify_proof`, `HeadTracker`, `AnchorSink` | `aip-nexora::commitment` | Gate 7; heads chain, rollback/fork/broken-chain are named refusals |
| `ExpectedExecution`, `verify_expected_execution_for_agent`, `DecisionPointTrustAnchors`, `ActionParameters` | `aip-authorize` | The decision point's signature covers every authorisation field |
| `AttestedBatch`, `verify_attested_batch(_independent_of_agent)`, `SignedSensorHealth`, `verify_signed_health`, `SignedContinuityReport`, `verify_continuity_report`, `ObserverTrustAnchors`, `ObserverState`, `ObservationAvailability` | `aip-observe` | The observer's trust root, its coverage vocabulary and its continuity vocabulary |
| `Reconciliation` (+ `canonical_bytes`, `digest`), `reconcile_expectation`, `reconcile_lineage`, `reconcile_observation`, `ReconciliationContext`, `ObserverEvidence`, `LineageInputs`, `EvidenceRef`, `EvidenceStrength` | `aip-reconcile` | **Pure functions of their inputs** — this is what makes offline re-derivation possible (§5) |
| `Warrant`, `verify_warrant`, `verify_warrant_distinct`, `WarrantTrustAnchors` | `aip-warrant` | A warrant may be referenced and checked without recreating any of its logic |
| `ScopedToken`, `DelegationToken`, `verify_delegation_chain`, `AgentIdentityDocument`, `derive_aip_id` | `aip-core`, `aip-crypto` | The single identity and authority implementation (I16, I18) |

## 2. Primitives that must NOT be reused

| Must not reuse | Why |
|---|---|
| `aip-core::scoped_audit::verify_chain` | Checks internal consistency only. A prefix of the chain verifies exactly as well as the whole, so it cannot detect truncation. `NEXORA_BOUNDARY.md` §5 already records this; a portable proof must not rest on it |
| The `merkle_empty()` placeholders at `aip-core/src/lib.rs:62,63,647` | Roots of the empty set presented as commitments over real history. They are not commitments and must never be exported as such (I15) |
| `aip-service::{delegation, capability}` | The second, weaker authority model (`CURRENT_SYSTEM.md` §5). NEXORA consumes `aip-core` authority only (I18) |
| `aip-core::simulation` | Declared not for production in its own module docs |
| The PR #3 `NexoraAnchorType` lifecycle anchors | Hash-chained JSON with no signature and no external anchor, on a second encoding (I14, I15). Design input only (`OT_SENTINEL_HARVEST_AUDIT.md`) |
| Any new canonical encoder | One encoder exists and is injective; a second is an attack surface (I14) |

## 3. Exact trust roots

A NEXORA proof carries evidence signed by up to six independent authorities.
**NEXORA adds none of its own trust to any of them**; the verifier supplies
an anchor set per authority and every component is checked against its own.

| # | Authority | Signs | Anchor type the verifier supplies |
|---|---|---|---|
| 1 | Issuer / delegator | `ScopedToken`, `DelegationToken` | issuer public keys by AIP-ID |
| 2 | Decision point | `ExpectedExecution`, `DecisionPointCoverageStatement` | `DecisionPointTrustAnchors` |
| 3 | Observer / collector | `AttestedBatch`, `SignedSensorHealth`, `SignedContinuityReport` | `ObserverTrustAnchors` |
| 4 | Warrant authority | `Warrant` | `WarrantTrustAnchors` |
| 5 | NEXORA | `SignedHead` — and only that | `NexoraTrustAnchors` |
| 6 | Proof assembler (optional) | the bundle envelope | `NexoraTrustAnchors` (separate id) |

**The ambiguity in the trust model, resolved rather than left open.** A
signature by the assembler over the bundle could be mistaken for a
statement that the contents are true. It is not one, and the implementation
must make that impossible to misread:

- the assembler's signature covers the bundle's canonical bytes and means
  exactly *"this party assembled this set of components at this time"*;
- the verifier reports it as `assembled_by`, never as a component verdict;
- a bundle with **no** assembler signature verifies exactly as well as one
  with it, provided every component verifies. Nothing in the output improves
  because the envelope was signed.

A second ambiguity, also resolved: `ReconciliationContext::agent_public_key`
is optional, and when absent the reconciler skips two independence checks
(I1 — the decision key is not the agent's; I10 — the observer key is not the
agent's). A portable proof must not hide that. The bundle records whether
the key was supplied, and the verifier's output carries
`independence: Checked | NotChecked` accordingly. It is never silently a
pass.

## 4. Exact proof inputs

The bundle is the *inputs*, plus the claimed verdict, plus the commitment
that ties it to a log. Every field is `Option` where the architecture
permits absence, and absence is represented explicitly — never omitted
silently (Gate 1).

```text
NexoraProof
├── version, proof_id (= digest of canonical bytes), issued_at_ms
├── subject          : agent_id, optional AgentIdentityDocument
├── authority        : optional { root ScopedToken, chain of DelegationToken }
├── expectation      : optional ExpectedExecution   (carries the ExecutionBinding)
├── observer         : optional { batches: Vec<AttestedBatch>, health: SignedSensorHealth }
├── continuity       : optional SignedContinuityReport
├── lineage          : optional { peer expectations, identity documents, revoked jtis }
├── coverage         : declared completeness (§6) — what was and was not observed
├── parameters       : the ReconciliationContext knobs, declared, not trusted
│                      (verification_time_ms, health_max_age_ms,
│                       window_tolerance_ms, expected_side, agent_key_supplied)
├── claim            : the Reconciliation record the assembler claims
├── warrant          : optional Warrant (referenced, never recreated)
├── commitment       : optional ProofObject (Gate 7 inclusion of the claim in a log)
└── envelope         : optional assembler signature
```

What the bundle deliberately does **not** contain: any payload, any file
content, any scalar score, any field named `trusted`, `permitted`, `safe` or
`verified`, and any statement NEXORA itself authored about the world.

## 5. Exact verification outputs

`verify_nexora_proof(&proof, &anchors, policy) -> VerifiedProof` — offline,
deterministic, no clock read, no network, no filesystem.

```text
VerifiedProof
├── proof_id, log/commitment position when present
├── per-component verdicts:
│     subject, authority, expectation, observer, continuity,
│     lineage, warrant, commitment, envelope
│     each ∈ { Verified, Absent, Unverifiable(reason) }
├── rederived : the Reconciliation the verifier recomputed from the inputs
├── result    : the reconciliation result — the re-derived one
├── strength  : the re-derived evidence strength, never raised
├── coverage  : OBSERVED | NOT_OBSERVED | AMBIGUOUS | DEGRADED |
│               UNAVAILABLE, with COMPLETE | PARTIAL
├── independence : Checked | NotChecked
└── verdict   : Valid | Invalid(reason)
```

**The load-bearing property (Gates 5 and 11).** The verifier does not trust
`claim`. It re-runs the repository's own reconciler over the bundled inputs
with the anchors *the verifier supplied* and the parameters the bundle
declared, and compares the result's canonical digest with the claim's. A
mismatch is `Invalid(ClaimNotDerivable)`. This is what "replay" means here
and the only thing it means: recomputing canonical bytes, commitments,
signatures and the reconciliation verdict from the evidence. It is never a
replay of any model's reasoning.

Because the re-derivation runs the real reconciler, its refusals are
inherited for free: mutate a batch and the observer chain fails; remove one
and coverage is not established; alter the binding and identity diverges;
alter the result and the digests differ. `CANNOT_PROVE` re-derives as
`CANNOT_PROVE`; `Attested` re-derives as `Attested`. There is no code path
that could raise either, because there is no code that writes them — they
come out of `aip-reconcile`.

## 6. Compatibility and version strategy

| Decision | Choice |
|---|---|
| Proof version | New constant `NEXORA_PROOF_VERSION = 1`, inside the canonical bytes. Independent of `NEXORA_VERSION = 1`, which stays the head/inclusion-proof version and is not bumped |
| Domains | New: `SYNTRIASS/NEXORA/PROOF_BUNDLE/v1` (bundle), `SYNTRIASS/NEXORA/ENVELOPE/v1` (assembler signature). Existing `LEAF`, `HEAD`, `PROOF` domains unchanged |
| Leaf kinds | Existing codes `0x01`–`0x05` are frozen. New kinds append: `ContinuityReport = 0x06`, `ContainmentRecord = 0x07`, `ProofBundle = 0x08`. Old proofs keep verifying |
| Algorithm identifiers | The existing `AlgorithmId` enum is carried explicitly in every `Signature`; the verifier refuses any value it does not implement rather than assuming Ed25519 |
| Wire format | JSON container (`serde_json`), no maps and no floats, so field order is the struct's. **The container is not security-relevant**: every hash and signature is over the canonical encoding recomputed from the parsed structure, so reformatting, whitespace and key order cannot change a verdict. `proof_id = SHA-256(canonical_bytes)` is stable across a round trip, and a test asserts it |
| Existing artefacts | Nothing changes for `AttestedBatch`, `SignedSensorHealth`, `Reconciliation`, `Warrant`, `SignedHead` or `ExpectedExecution`. No protocol version anywhere else is bumped |
| Crate layout | New modules in `aip-nexora`: `proof.rs`, `verify.rs`, `export.rs`. `merkle.rs` and `commitment.rs` keep their current dependency-light footprint. `aip-nexora` gains `aip-authorize`, `aip-observe`, `aip-reconcile`, `aip-warrant`, `aip-core` as dependencies — no cycle, since nothing depends on `aip-nexora` |

## 7. Gate order and what each must prove

| Gate | Deliverable | The property that must fail if removed |
|---|---|---|
| 1 | `NexoraProof`, semantic rules | absence is representable; a claim cannot be relabelled |
| 2 | canonical binding | no component transplants across identity, authority, execution, observer, lineage, reconciliation |
| 3 | commitment binding | the claim's inclusion in a log is checked, and a wrong root, index or size is refused |
| 4 | `verify_nexora_proof` | verification needs only supplied anchors — no network, no services, no state |
| 5 | re-derivation | a proof whose claim is not derivable from its own inputs is invalid |
| 6 | coverage | a proof cannot imply complete visibility the observer never had |
| 7 | lineage | no lineage is synthesised from names or self-report |
| 8 | continuity | a continuity-compromised observer cannot present as uninterrupted |
| 9 | warrant | a referenced warrant is checked; NEXORA authorises nothing |
| 10 | export/import/verify + CLI | a proof verifies on another machine from anchors alone |
| 11 | replay semantics | documented as evidence-layer only |
| 12 | 30-case adversarial suite | each attack has one named expected failure |
| 13 | cross-crate audit | no raw concatenation, untagged hash, or implicit version |
| 14 | offline demonstrator | live execution → proof → verified in isolation; mutation → rejected |
| 15 | measurement | proof size and timings on this host only |
| 16 | documentation | eight documents plus `NEXORA_IMPLEMENTATION_REPORT.md` |

## 8. Standing prohibitions carried into every gate

NEXORA must never turn telemetry into proof by signing it; never raise
`Attested` to `Proven`; never collapse `CANNOT_PROVE` into a positive
result; never invent lineage; never assume observer completeness; never
accept an agent-controlled observer key; never bypass `ExpectedExecution`,
`ExecutionBinding` or reconciliation; never authorise containment; never
become a second identity or authority engine; and never claim deterministic
replay of a model's internals.

**No unresolved trust-model ambiguity remains.** The two candidates —
the meaning of an assembler signature, and the optional agent key — are
resolved in §3 and are enforced in the verifier's output type rather than
in prose.
