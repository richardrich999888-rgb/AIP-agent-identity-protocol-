# RECONCILIATION IMPLEMENTATION REPORT

Skill 7 (reconciliation) / Orchestrator Stage 4. Crate: `aip-standalone/aip-reconcile`.

> **Corrective pass (commits `6b2f5c7` RED, `b821a23` GREEN).** The first
> implementation (`ad9642a`) was audited again against Skill 7, the security
> invariants and the PR3 boundaries. Eight weaknesses were found, six of them
> letting a positive verdict be produced from evidence that did not support
> it. All are fixed and each has a test that failed before the fix. The
> sections below describe the engine **as it now stands**; §"Corrective pass"
> records what was wrong and how it was proven wrong. Record format is now
> `RECONCILIATION_VERSION = 2`.

## Status

**PASS** at the Skill 7 boundary. Reconciliation exists, is deterministic and
offline, defaults to `CANNOT_PROVE`, and every positive result class it can
emit has a signed-evidence precondition that is tested adversarially. Three of
the eight result classes are **unreachable by construction** with the current
evidence and are documented as such rather than approximated:
`VERIFIED_EXECUTION`, `UNATTRIBUTED_EFFECT` (no producer for the required
input), `LINEAGE_VIOLATION`.

The reconciler holds no key, signs nothing, authorizes nothing, revokes
nothing, issues no warrant and contains nothing. `AUTHORIZATION ≠ OBSERVATION ≠
RECONCILIATION` is preserved by type: the decision point's signature is
verified with `aip-authorize`, the observer's with `aip-observe`, and
`aip-reconcile` adds no third authority.

## Baseline

- Predecessors: Skill 3 PASS (`AIP_CORRECTNESS_REPORT.md`), Skill 4 PASS
  (`EXECUTION_BINDING_IMPLEMENTATION_REPORT.md`), Skill 5 PASS
  (`DECISION_POINT_IMPLEMENTATION_REPORT.md`), Skill 6 + 6.5 PASS
  (`OBSERVER_IMPLEMENTATION_REPORT.md`, `SNIFFER_DOG_IMPLEMENTATION_REPORT.md`),
  PR3 corrective review **READY WITH EXPLICIT CANNOT_PROVE BOUNDARIES**
  (`PR3_GAP_REVIEW.md` §14a, commit `991f749`). The PR3 readiness decision and
  its §10 list of things that must remain `CANNOT_PROVE` were treated as
  authoritative and adopted verbatim as preconditions (see "What remains
  CANNOT_PROVE").
- Start of Stage 4: HEAD `991f749`, working tree clean.
- Test baseline at start: aip-standalone 408 passed / 0 failed / 3 ignored;
  aip-service 39 passed.
- Hard-stop checklist (Skill 7): no stop condition was met. In particular no
  effect-level sensor was required — the stage was scoped so that its absence
  makes `VERIFIED_EXECUTION` unreachable instead of being papered over.

## Readiness analysis (performed before implementation)

| Question | Answer from source |
|---|---|
| Is there a signed expected side? | Yes — `aip_authorize::ExpectedExecution`, verified by `verify_expected_execution` against `DecisionPointTrustAnchors`. Carries `decision_id`, `ExecutionBinding`, `action_kind`, `parameter_digest`, `issued_at`, `valid_until`. |
| Is there a signed observed side? | Yes — `aip_observe::AttestedBatch` (collector-signed, chained by recomputed head) and `SignedSensorHealth` (state, continuity, `probe_policy`, `attested_coverage`, per-mechanism `covered_by`). |
| Is the join key stable? | Yes — `decision_id` (`RECONCILIATION_MODEL.md` §2). On the observed side it is a **claim** (`claimed_decision_id`) and is treated as one. |
| Can identity be compared without comparing digests? | Yes — `ObservedProcess::matches_process_of(&ExecutionBinding)` is structural (process tuple + executable content hash); the two identity digests are deliberately non-comparable (PR3 E-1). |
| Can non-execution ever be stated? | Only under signed kernel-pushed coverage of the exact window (`covered_by_kernel_pushed_source()`), in a `RegisteredOnly` regime, from a contiguous chain that spans the window. Never from polled coverage or silence (I8). |
| Can action/parameters be compared? | **No.** No `ObservedEffect` or `KernelLifecycleEvent` carries an action kind or parameter digest. `VERIFIED_EXECUTION` is therefore unreachable and stated so. |
| Can expected-side completeness be established? | Only by a decision-point-signed statement. None is produced today. `UNATTRIBUTED_EFFECT` is therefore unreachable in production and stated so. |
| Can lineage be judged? | Only when both ends of a fork are bound. Not produced today. `LINEAGE_VIOLATION` is unreachable and stated so. |

## Files changed (commit `ad9642a`)

| File | Lines | Purpose |
|---|---|---|
| `aip-standalone/Cargo.toml` | +1 | workspace member `aip-reconcile` |
| `aip-standalone/Cargo.lock` | +14 | lockfile |
| `aip-reconcile/Cargo.toml` | +17 | deps: `aip-types`, `aip-crypto`, `aip-authorize`, `aip-observe`, `serde`; dev: `aip-core`, `serde_json` |
| `aip-reconcile/src/ids.rs` | +85 | identifier newtypes `DecisionId`, `BatchId`, `ProbeRunId` (`[u8;16]`, explicit `from_bytes`/`as_bytes`, no `From`/`Deref`), `ObserverSequence(u64)`, `ObserverId(String)`, `DecisionPointId(String)` |
| `aip-reconcile/src/result.rs` | +485 | `ReconciliationResult` (8 variants, `#[default] CannotProve`), `EvidenceStrength` (enum, `Ord`), `ReasonCode` (closed, 30 variants), `IdentityComparison`, `ActionComparison`, `TemporalComparison`, `EvidenceRef`, `Reconciliation` with canonical encoding under `SYNTRIASS/GHOST/RECONCILIATION/v1` |
| `aip-reconcile/src/inputs.rs` | +137 | `ObserverEvidence`, `DecisionPointCoverageStatement` (domain `GHOST/DecisionPointCoverage/v1`, `verify`), `ExpectedSideCoverage::{Unknown, Attested(Box<_>)}`, `ReconciliationContext`, `ObservationTarget` |
| `aip-reconcile/src/reconcile.rs` | +635 | the engine: `reconcile_expectation`, `reconcile_observation` |
| `aip-reconcile/src/lib.rs` | +50 | crate contract and re-exports |
| `aip-reconcile/tests/adversarial.rs` | +1417 | 30 adversarial tests |
| `aip-test/Cargo.toml`, `aip-test/src/domain_audit.rs` | +7 −2 | domain-tag audit now covers 18 tags (two new) |

No predecessor crate was modified. No `aip-service` change. No refactor
outside the new crate.

Corrective pass (`6b2f5c7`, `b821a23`), same crate:

| File | Change |
|---|---|
| `src/reconcile.rs` | `recompute_coverage` (gap sweep, health anchor, probe-run, mechanism intersection); `Draft::precondition_holds` central guard + `coverage_recomputed`; exhaustive `classify_observer_error` and expected-side error classification; `claim_pair` consistency; agent-key independence; future-health check; newtypes in evidence refs; 3 unit tests |
| `src/result.rs` | `RECONCILIATION_VERSION` 1 → 2; 9 new `ReasonCode` variants with explicit discriminants; `IdentityComparison::ClaimInconsistent`; `ActionEvidenceSeal` sealing `ActionComparison::Match`/`Mismatch`; `EvidenceRef` carries newtypes plus `batch_id` and `probe_run_id` |
| `src/inputs.rs` | `ReconciliationContext::agent_public_key`; `ObservationTarget` uses `ObserverSequence` |
| `src/lib.rs` | re-export `ActionEvidenceSeal` |
| `tests/corrective.rs` | new — 9 tests (6 committed failing in `6b2f5c7`) |
| `tests/adversarial.rs` | construction updated for newtypes and the sealed variants; **no assertion changed** |

## Data model

```
ExpectedExecution  (aip-authorize; DP-signed)
        +
ObserverEvidence { batches: Vec<AttestedBatch>, health: SignedSensorHealth }  (collector-signed)
        +
ReconciliationContext { decision_point_anchors, observer_anchors,
                        verification_time_ms, health_max_age_ms,
                        window_tolerance_ms, expected_side,
                        agent_public_key: Option<Vec<u8>> }
        ↓
Reconciliation {
  version, result, strength, reason, decision_id: Option<DecisionId>,
  availability: ObservationAvailability,   // the OBSERVATION_UNAVAILABLE input state, carried
  identity: IdentityComparison, action: ActionComparison, temporal: TemporalComparison,
  replay_detected, evidence: Vec<EvidenceRef>, verification_time_ms }
```

Closed types throughout. There is no boolean that collapses states, no
`confidence: f32`, no severity field, no score, and no caller-supplied
`trusted`/`permitted` flag. `serde` output was checked for the vocabulary
`severity | confidence | score | risk | malicious | permitted | authorized |
allowed | denied | revoke | terminated | containment | isolate | kill`.

## Verification order (never skipped, never upgraded)

1. Expected signature, trust and structure (`verify_expected_execution`).
   Failure → `CANNOT_PROVE` with `ExpectedSignatureInvalid` /
   `ExpectedUntrustedDecisionPoint` / `ExpectedStructurallyInvalid`; the
   observer is never consulted.
2. Observer health signature → untrusted key: `CANNOT_PROVE
   (ObserverUntrusted)`; bad bytes: `SENSOR_INTEGRITY_FAILURE (Proven,
   ObserverSignatureInvalid)`.
3. Every batch signature (same mapping); `observer_id` must equal the
   health's (`MixedObservers`); exact `(sequence, head)` duplicates are
   collapsed and flagged `replay_detected`.
4. Chain arithmetic: two different validly signed batches at one sequence →
   `SENSOR_INTEGRITY_FAILURE (Proven, ObserverChainBroken)`; sequence gap →
   `CANNOT_PROVE (ObservationSetIncomplete)`; `prev_head` not linking →
   `ObserverChainBroken (Proven)`; the last supplied batch must equal the
   health record's `sequence` and `head`, else `ObservationSetIncomplete`
   (withheld or rolled-back evidence is visible, never silently accepted).
5. Availability for the expectation's window (`availability_for`); stale
   health → `CANNOT_PROVE (HealthStale)`.
6. Reference collection over the verified chain: each observation / kernel
   event is `Match` (structural instance + executable match), `Divergent`
   (carries this `decision_id` claim but a different instance), `UnboundPid`
   (same pid or same claim, no bound instance), or none; references in
   batches whose claimed window does not overlap the expectation's window
   (± verifier tolerance) are counted as outside.
7. Observer state gate: `Quarantined` → `SENSOR_INTEGRITY_FAILURE (Attested)`;
   `Recovering`/`ContinuityUnverified` → `CONTINUITY_FAILURE (Attested)`;
   `Degraded` → `CANNOT_PROVE (ObserverDegraded)`.
8. `Active` only: `Ambiguous` → `CANNOT_PROVE`; `Match` → `CANNOT_PROVE
   (ActionEvidenceUnavailable)`; `Divergent` → `IDENTITY_DIVERGENCE
   (Attested)` unless `probe_policy == Open`; `UnboundReferencesOnly` and
   `ClaimInconsistent` → `CANNOT_PROVE`; `NoReference` → `PHANTOM_CLAIM
   (Attested)` only if availability is `Covered` **and** `probe_policy ==
   RegisteredOnly` **and** signed `covered_by` contains a kernel-pushed
   mechanism **and** the supplied contiguous chain's claimed windows span the
   window **and** `recompute_coverage` succeeds; otherwise `CANNOT_PROVE`
   with the specific missing precondition (`ObservationOutsideWindow`,
   `WindowNotCovered`, `ProvenanceUnverifiedOpenPolicy`,
   `CoverageNotKernelPushed`, `ObservationSetIncomplete`,
   `CoverageGapInWindow`, `CoverageEndsAfterHealth`,
   `CoverageProbeRunChanged`).
9. Whatever a branch proposes, `Draft::finish` re-checks that the class's
   precondition is visible in the record being emitted and downgrades to
   `CANNOT_PROVE (InvariantNotSatisfied)` if it is not.

## Reachability of the result classes

| Result | Reachable | Strength | Precondition enforced |
|---|---|---|---|
| `CANNOT_PROVE` | yes (default) | `Heuristic` | none — it is the absence of a verdict |
| `PHANTOM_CLAIM` | yes | `Attested` | see step 8 |
| `IDENTITY_DIVERGENCE` | yes | `Attested` | Active observer, RegisteredOnly, a measured instance carrying this decision claim that fails the structural match, no matching instance |
| `SENSOR_INTEGRITY_FAILURE` | yes | `Proven` (signature / chain arithmetic) or `Attested` (collector-declared `Quarantined`) | recomputable failure, or signed quarantine |
| `CONTINUITY_FAILURE` | yes | `Attested` | signed `Recovering` / `ContinuityUnverified` |
| `VERIFIED_EXECUTION` | **yes, for two action classes only** (Stage 7, `63c5e0a`; Stage 7b; Stage 7c `1d52f93`): an established TCP connection authorized as `ghost.net.connect.v1`, as `Presence` (polled table) or `Transition` (kernel-reported creation); a process execution authorized as `ghost.process.exec.v1`, as `Transition` (kernel-reported fork by the bound instance + exec of the child, image content hash recomputed); **no** for every other action kind | `Attested` | `ActionComparison::Match` requires an `ActionEvidenceSeal` whose constructors are `pub(crate)` and are called only by the action-derivation step; the central guard requires a sealed Match, identity Match, `action_continuity_verified` and exactly `Attested`. See `ACTION_EVIDENCE.md` §5 |
| `UNATTRIBUTED_EFFECT` | **only with a `DecisionPointCoverageStatement`**, which no production component emits | `Attested` | verified DP-signed completeness statement covering agent and window; claim not in its set; instance bound; attribution claimed; RegisteredOnly |
| `LINEAGE_VIOLATION` | **yes, since Phase C2** through `reconcile_lineage` only | `Attested` | `lineage == Contradicted` set only by `reconcile_lineage` when both the observed side (bound edge, covered, parent attributed to one agent) and the claimed side (verified unrevoked authority chain matching `AuthorityRef`, verified identity lineage proof) are complete and the spawner is on neither; `precondition_holds` refuses it otherwise |

"Identity corroborated" is the ceiling for an expectation: it is reported as
`CANNOT_PROVE` with `reason = ActionEvidenceUnavailable` and `identity =
Match`, so a consumer sees exactly what was and was not established. No fake
action matcher was added.

## Canonical encoding, domain separation, signature coverage

- `Reconciliation::canonical_bytes()` — domain `SYNTRIASS/GHOST/RECONCILIATION/v1`
  first (length-prefixed), then every field with explicit discriminants and
  presence bytes via `aip_types::canonical`. Mutation of any field changes the
  bytes (tested); `action` is the exception, because it has only one
  constructible value — that unconstructibility is the property being kept.
  `ReasonCode` carries explicit discriminants so inserting a variant cannot
  silently renumber another's canonical code. The record is **not signed** by this crate: it holds no key.
  A party that is one may sign the canonical bytes.
- `DecisionPointCoverageStatement::signing_preimage()` — domain
  `GHOST/DecisionPointCoverage/v1`, version, `decision_point_id`, `agent_id`,
  window, count-prefixed `decision_ids`, `issued_at_ms`. `verify()` requires
  the anchored DP key, `signer_id == decision_point_id`, `payload_hash ==
  sha256(preimage)`, valid Ed25519. Every field's mutation changes the
  preimage (tested).
- The workspace domain audit (`aip-test/src/domain_audit.rs`) now asserts all
  18 tags are pairwise distinct, versioned, in a known namespace, and that no
  tag is a prefix of another.

## Identifier newtypes

`DecisionId`, `BatchId`, `ProbeRunId` wrap `[u8;16]` with explicit
construction only; `ObserverSequence`, `ObserverId`, `DecisionPointId` wrap
their scalars. Inside the crate a `batch_id` cannot be passed where a
`DecisionId` is expected without writing the conversion. Upstream crates keep
their `[u8;16]` fields (PR3 §12 future hardening); the boundary conversion is
`DecisionId::from_bytes(ee.decision_id)` at the entry points.

Every one of them is *used* at the boundary: `EvidenceRef` and
`ObservationTarget` carry them rather than bare `String`/`u64`/`[u8;16]`.
This was a correction — in the first implementation `BatchId` and
`ProbeRunId` were declared and never used while this report cited them as a
property, which is precisely the "a type exists, therefore the property
holds" failure the architecture warns about (I15). `ProbeRunId` now has a
job: `recompute_coverage` requires one probe run across the batches covering
a window, and the run id is recorded in each batch reference so a reader can
re-derive that argument.

## Adversarial tests (`aip-reconcile/tests/adversarial.rs`, 30) and unit tests (4)

Skill 7 §28 case → test:

| # | Case | Test | Asserted result |
|---|---|---|---|
| 1 | identity match | `t01_…` | `CANNOT_PROVE`, `ActionEvidenceUnavailable`, `identity = Match{1}`, `action = Unobservable`, availability `Covered`; never `VERIFIED_EXECUTION` |
| 2 | expected, poll-only coverage, silence | `t02_…` | `CANNOT_PROVE (CoverageNotKernelPushed)` |
| 2b | kernel event present, connector not covering epoch | `t02b_…` | `CANNOT_PROVE (CoverageNotKernelPushed)` — coverage from signed `covered_by`, not event presence |
| 3 | expected, kernel coverage, registered, silence | `t03_…` | `PHANTOM_CLAIM (Attested)`, health + both batches referenced |
| 3b | batch with the observation withheld / chain truncated | `t03b_…` | `CANNOT_PROVE (ObservationSetIncomplete)` in all three omission shapes |
| 3c | Open probe policy | `t03c_…` | `CANNOT_PROVE (ProvenanceUnverifiedOpenPolicy)` for both phantom and divergence shapes |
| 4 | observed only, expected side unknown | `t04_…` | `CANNOT_PROVE (ExpectedSideCompletenessUnknown)` |
| 5 | observed only, DP-signed completeness | `t05_…` | `UNATTRIBUTED_EFFECT (Attested)`; claim in set → `ExpectationExistsForObservation`; other agent / narrower window → `DoesNotCover`; tampered or unanchored statement → `ExpectedSideStatementInvalid`; every field enters the preimage |
| 5b | unclaimed observation | `t05b_…` | `CANNOT_PROVE (AttributionNotEstablished)`; missing index → `TargetNotFound` |
| 6 | divergent instance under same claim | `t06_…` | `IDENTITY_DIVERGENCE (Attested)`, `Divergent{1}` |
| 6b | match + divergent together | `t06b_…` | `CANNOT_PROVE (AmbiguousObservations)` |
| 7 | pid reuse (ticks / boot / exe differ, no claim) | `t07_…` | `CANNOT_PROVE (UnboundReferencesOnly)`, never a match, never phantom |
| 7b | unbound kernel exec about the expected pid | `t07b_…` | `CANNOT_PROVE (UnboundReferencesOnly)` on both entry points |
| 8/9 | action / parameters | `t08_t09_…` | `ActionComparison::Unobservable` in every result; no `VERIFIED_EXECUTION`, no `LINEAGE_VIOLATION` |
| 10 | matching observation outside window | `t10_…` | `CANNOT_PROVE (ObservationOutsideWindow)`, `temporal = OutsideWindow` |
| 11 | window not covered | `t11_…` | `CANNOT_PROVE (WindowNotCovered)`, availability `Unavailable{WindowNotCovered}` |
| 11b | stale health | `t11b_…` | `CANNOT_PROVE (HealthStale)` |
| 12 | tampered / unanchored expectation | `t12_…` | `CANNOT_PROVE (ExpectedSignatureInvalid / ExpectedUntrustedDecisionPoint)`, observer never consulted |
| 13 | tampered batch / health; unanchored observer | `t13_…` | `SENSOR_INTEGRITY_FAILURE (Proven)`; unanchored → `CANNOT_PROVE (ObserverUntrusted)` |
| 14/18 | degraded observer with kernel coverage and silence | `t14_t18_…` | `CANNOT_PROVE (ObserverDegraded)` |
| 15 | replayed batch | `t15_…` | collapsed, `replay_detected = true`, identity counted once, digest differs |
| 15b | fork / unlinked batch signed with the collector key | `t15b_…` | `SENSOR_INTEGRITY_FAILURE (Proven, ObserverChainBroken)` |
| 16 | rolled-back health / truncated chain | `t16_…` | `CANNOT_PROVE (ObservationSetIncomplete)` |
| 16b | batches from a second trusted observer | `t16b_…` | `CANNOT_PROVE (MixedObservers)` |
| 17 | continuity unverified / recovering | `t17_…` | `CONTINUITY_FAILURE (Attested)` with the specific reason |
| 17b | collector-declared quarantine | `t17b_…` | `SENSOR_INTEGRITY_FAILURE (Attested)`, not `Proven` |
| 19–21 | strength by kind; no severity | `t19_t21_…` | `Heuristic`/`Attested`/`Proven` fixed by result; forbidden vocabulary absent from serialized output |
| 22 | no observer evidence | `t22_…` | `CANNOT_PROVE (NoObserverEvidence)`, availability `NoObserver`, `default()` |
| — | determinism / canonical | `reconciliation_is_deterministic_and_canonically_encoded` | equal inputs → equal record and digest; each field changes the bytes; domain tag first |
| — | newtypes | `decision_id_is_the_only_correlation_key_and_is_explicitly_typed` | explicit construction |

Unit tests: default is `CannotProve`; result/strength codes distinct and
strength ordered; no severity/score/authorization vocabulary in output;
newtype round-trip.

Test discipline, reported faithfully: the engine was written to the result
table above after the readiness analysis; the 30 adversarial tests were then
written against it. Two tests failed on first run and both failures were in
the test fixtures, not the engine: a kernel event was ingested before the
epoch-start batch and so landed in it (fixed by ordering the fixture), and the
forbidden-word `terminate` matched inside `Indeterminate` (fixed by using
`terminated`; `isolate`/`kill`/`containment` added). No assertion was weakened
and no engine behaviour was changed to satisfy a test. One clippy finding
(`large_enum_variant` on `ExpectedSideCoverage`) was fixed by boxing the
statement.

## Test results

| Suite | Stage 4 start | First implementation | After corrective pass |
|---|---|---|---|
| aip-standalone `cargo test --workspace` | 408 / 0 / 3 ignored | 442 / 0 / 3 | **454 / 0 / 3 ignored** |
| aip-service `cargo test` | 39 / 0 | 39 / 0 | 39 / 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` (both) | clean | clean | clean |
| `cargo fmt --all --check` (both) | clean | clean | clean |

The corrective pass added 9 integration tests (`aip-reconcile/tests/corrective.rs`)
and 3 unit tests for the central guard. The 30 tests in `adversarial.rs` pass
with **every assertion unchanged**; only construction was updated for the
identifier newtypes and for the now-unconstructible `ActionComparison::Match`.

All predecessor security suites (`aip-core` 141, `aip-protocol` 46,
`aip-authorize` 35, `aip-observe` 89, `aip-real-tests` 67, `aip-test` 16)
ran unchanged and passed.

## Vulnerabilities pinned by tests

| Attack | Pinned by |
|---|---|
| Silence under polled coverage → non-execution | t02, t02b |
| Inferring kernel coverage from event presence | t02b |
| Withholding the batch that corroborates identity to fabricate a phantom | t03b |
| Rolled-back health / truncated or gapped chain | t03b, t16 |
| Fork at one sequence, unlinked batch, both collector-signed | t15b |
| Replay to inflate observation counts | t15 |
| Merging a second observer's chain | t16b |
| Extending `valid_until` or swapping the binding after DP signing | t12 |
| Editing batch or health bytes after collector signing | t13 |
| PID reuse / boot change / binary swap presented as the expected instance | t07 |
| Bare kernel pid presented as identity | t07b |
| Unverified provenance (Open policy) supporting a verdict | t03c |
| Degraded / recovering / unverified / quarantined observer upgraded to a verdict | t14_t18, t17, t17b |
| Absence of an expectation in a database treated as absence of an expectation | t04, t05 |
| Tampered or foreign completeness statement | t05 |
| Identity match promoted to verified execution | t01, t08_t09 |

## What can now be proven (and at what strength)

- That a supplied observer chain is internally inconsistent or its bytes were
  altered: `Proven` (anyone holding the bytes and anchors recomputes it).
- That, under a `RegisteredOnly` collector whose signed health says a
  kernel-pushed mechanism covered the whole window, and whose complete
  contiguous chain over that window — **re-derived by the reconciler** as
  gap-free, produced by one probe run, declaring a kernel-pushed source, and
  ending no later than the collector's own signed clock — contains no
  reference to the expected instance, its pid, or its decision, **the
  observer recorded no such instance**: `Attested`. This is a statement about
  the attested record, bounded by the observer's threat model
  (`SNIFFER_DOG.md`), not a proof that nothing executed.
- That a measured instance carrying this decision's claim differs from the
  authorized instance: `Attested`.
- That the observer itself declared a continuity break or quarantine over the
  window: `Attested`.
- That the authorized instance was measured, alive, with the authorized
  executable contents, inside the window: reported as identity `Match` under
  `CANNOT_PROVE`, because the action is unobservable.

## What remains CANNOT_PROVE (PR3 §10, adopted verbatim; all enforced)

1. Truth of any procfs-derived content on a root-compromised host — content
   results are capped at `Attested`; only signature/chain arithmetic is
   `Proven`.
2. Identity of an unbound kernel event — `UnboundReferencesOnly`.
3. Action-level verification — `ActionComparison::Unobservable`;
   `VERIFIED_EXECUTION` unreachable.
4. Non-execution without kernel-pushed coverage in signed `covered_by` —
   `CoverageNotKernelPushed`.
5. Zero loss without a counter — inherited: a `Degraded` state from counted
   loss blocks every verdict; an absent counter never widens coverage.
6. Continuity across collector or probe restart — `Recovering` /
   `ContinuityUnverified` → `CONTINUITY_FAILURE`, never coverage.
7. Absolute time or any cross-clock equality — `verification_time_ms` is used
   only for health freshness; batch windows are probe claims used as a filter
   with explicit tolerance; kernel timestamps are never compared to wall time.
8. Truth of a `Claimed` attribution — used only to locate the expected side.
9. Lineage unless both fork ends are bound — `LINEAGE_VIOLATION` unreachable.
10. Expected-side completeness — `ExpectedSideCoverage::Unknown` →
    `CANNOT_PROVE`; only a DP-signed statement can change that, and none is
    produced.
11. Provenance under `ProbePolicy::Open` — `ProvenanceUnverifiedOpenPolicy`.
12. Observation is not authorization — the reconciler never reads an
    observation as permission and never writes a permission.

Added by the corrective pass:

13. **What happened inside a claimed-coverage hole.** A gap between claimed
    intervals is `CoverageGapInWindow`, never coverage.
14. **Anything after the collector last signed.** The window must end at or
    before `health.emitted_at_ms`; a probe may claim the future, the
    collector cannot have signed for it.
15. **Where a health record sits in time when the verifier's clock disagrees
    with the collector's.** Future-dated health is `HealthNotYetEmitted`, not
    fresh evidence. The two clocks are never equated; `window_tolerance_ms`
    is the verifier's declared slack, not a measurement.
16. **Continuity across a probe restart inside the window** — independently
    of what the collector's epoch bookkeeping says (`CoverageProbeRunChanged`).
17. **Which party a claim belongs to when its `decision_id` and `agent_id`
    disagree.** `ClaimInconsistent` — it supports no statement about either.
18. **Observer independence when the verifier does not supply the agent's
    public key.** With `agent_public_key: None` the reconciler cannot see
    that an anchored observer key is the agent's own; the check exists but is
    skipped. Supplying the key is a verifier obligation, pinned by `r7`.
19. **Whether evidence newer than the supplied health exists.** A caller can
    withhold batches produced after the health record it hands over; the
    reconciler bounds this only by `health_max_age_ms`. It cannot detect
    withheld *future* evidence — see "Unresolved architectural risks".

## Interaction with predecessors

- **ExpectedExecution (Skill 5)**: consumed read-only through
  `verify_expected_execution`; its window `[issued_at, valid_until]` is the
  reconciliation window; its `ExecutionBinding` is the identity reference; its
  `decision_id` is the only correlation key.
- **Observer coverage (Skill 6)**: `SignedSensorHealth::availability_for`
  supplies the `OBSERVATION_UNAVAILABLE` input state, carried unchanged in the
  result; observer state gates every positive statement.
- **Sniffer Dog (Skill 6.5)**: `covered_by` (signed per-mechanism intersection
  over the epoch) and `SourceMechanism::is_kernel_pushed` are the only source
  of "kernel coverage" — never event presence; `probe_policy` gates
  `PHANTOM_CLAIM` and `IDENTITY_DIVERGENCE`; `KernelLifecycleEvent.bound` is
  the only way a kernel event can match or diverge, an unbound one is a pid
  reference at most; counted loss surfaces as `Degraded` and blocks verdicts.
- **Cross-stage contract audit (PR3 §13)**: every row is now consumed: join
  key, process identity (structural), authority ref (carried in
  `EvidenceRef::Expected`), coverage (mechanism now present), provenance,
  continuity; "strength" is now a separate type, `EvidenceStrength`.

## Trust boundaries

| Party | Holds | Reconciler trusts |
|---|---|---|
| Decision point | DP signing key | its signature over `ExpectedExecution` and over a coverage statement, via verifier-supplied anchors |
| Collector (observer) | observer signing key, ledger, registry | its signature over batches and health, via verifier-supplied anchors; its *content* only as attested-by-collector |
| Host probe / observed agent | no key | nothing — every field it authored is a claim (`claimed_decision_id`, `Claimed` attribution, claimed windows, `active_mechanisms` bounded by the registry) |
| Verifier | both anchor sets, its clock, tolerances, and optionally the agent's public key | itself; the reconciler reads no clock and holds no anchors |
| Reconciler | nothing | — |

The agent's public key is the verifier's contribution to two invariants the
reconciler cannot otherwise check: I1 (the agent must not hold the decision
key) and I10 (the observer key must not be the agent's). Both are checked
only when `ReconciliationContext::agent_public_key` is `Some`. `None` is a
skipped check, not a passed one.

## Unresolved architectural risks

Stated, not worked around. None can be closed inside Skill 7 without a new
evidence producer or an architecture change.

1. **Withheld future evidence.** The caller chooses which health record and
   which batches to supply. Batches produced *after* that health record are
   invisible to the reconciler, so a caller can present a truthful,
   internally consistent chain that stops just before the observation it
   wants hidden. `health_max_age_ms` bounds how stale that record may be and
   nothing else does. Closing it requires an external anchor for the
   observer's head (the NEXORA boundary) — evidence that a *newer* head
   exists. Until then this is a deployment assumption: the verifier must
   obtain health from the collector, not from the party under scrutiny.
2. **Coverage rests on probe claims that no one countersigns.** The
   reconciler now checks those claims for internal consistency (no holes, one
   run, ending before the collector's clock) but cannot verify that a probe
   claiming to sample `[t₀, t₁]` did so. A host with root can run a probe
   that reports honestly-shaped nothing. This caps `PHANTOM_CLAIM` at
   `Attested` permanently; only an evidence source outside the host's control
   could raise it.
3. **Attribution is a claim.** `AgentAttribution::Claimed` is what some
   party told the probe. The corrective pass requires the claim to be
   internally consistent before it can support `IDENTITY_DIVERGENCE`, which
   narrows framing to parties that can claim *as that agent* — the same trust
   level as the claim itself. It does not make attribution verified, and no
   verified variant exists.
4. **Independence checks depend on the verifier.** I1 and I10 are only
   checked when the agent's public key is supplied. A verifier that anchors
   an observer key without knowing whose it is gets no warning.
5. **The reconciliation record is unsigned and unstored.** Nothing binds a
   result to the evidence it cites beyond the canonical encoding a caller may
   choose to sign. Producing signed, ordered reconciliation history is the
   NEXORA boundary and is out of scope here.

## Deployment assumptions

- Anchors for decision points and `(observer_id, key_version)` pairs are
  distributed to verifiers out of band.
- The verifier supplies the observer's chain contiguous up to the current
  signed health head; a verifier that only holds part of the chain receives
  `ObservationSetIncomplete`, not a verdict.
- `health_max_age_ms` and `window_tolerance_ms` are verifier policy; they
  filter, they never add evidence.
- Everything in `SNIFFER_DOG_IMPLEMENTATION_REPORT.md` and `PR3_GAP_REVIEW.md`
  §11: collector off-host, `RegisteredOnly` in production, authenticated
  probe→collector channel, DP process isolated from the agent.
- No persistence: results are in-memory records; durability, signing and
  storage of reconciliation records are out of scope for this stage.

## Prohibited claims after this stage

SYNTRIASS still must **not** claim:

- verified execution of any action or parameter set;
- that an agent "did not execute" — `PHANTOM_CLAIM` is a statement about an
  attested kernel-covered record in a registered-only regime, capped at
  `Attested`, and bounded by the observer's threat model;
- `UNATTRIBUTED_EFFECT` in production (no producer for the required
  statement exists);
- lineage violations;
- maliciousness, intent, risk or severity of anything — no such field exists;
- any warrant, revocation, constraint, isolation or containment — none is
  implemented and none is reachable from this crate;
- real-time or in-line operation, eBPF/tracepoint/XDP sensing, performance
  figures, or any technology-readiness level;
- that reconciliation records are signed, persisted or anchored.

## Not implemented (deliberately, per Skill 7 scope)

Effect-level (sentinel-style) sensor; producer for
`DecisionPointCoverageStatement`; warrant engine; containment; NEXORA; PQC;
key lifecycle; durable persistence; `aip-service` integration; `[u8;16]`
newtypes in upstream crates.

## Stage 7b note

Record version 3: `ActionEvidenceSeal { mechanism, kind }`,
`TemporalComparison::{BeforeWindow, AfterWindow, Unanchored}`,
`EvidenceRef::Batch.attested_at_ms`, reasons `ActionPrecedesAuthorization`,
`ActionTransitionIncomplete`, `KernelTimeUnanchored`. `recompute_coverage`
for `PHANTOM_CLAIM` now requires process-lifecycle coverage
(`SourceMechanism::covers_process_lifecycle`) rather than any kernel-pushed
mechanism, because a socket-state stream says nothing about processes. See
`ACTION_EVIDENCE.md` §14 and `ACTION_EVIDENCE_IMPLEMENTATION_REPORT.md`.

## Stage 7c note

Record version unchanged (v3): no new result class, reason, kind or seal
field was needed. `aip-reconcile::action` gains `ProcessExecution`,
`ExecutedImage`, `derive_executions` (fork/exec pairing by `child_pid`,
kernel-time order and the anchored child's start tick) and the
`TransitionEvidence` enum that lets `compare_action` run the same claim,
placement, coverage, provenance and guard path for a socket transition and
a process execution. The `SchedTracepoint` stream is **not** accepted as
process-lifecycle coverage for `PHANTOM_CLAIM` (`xe15`). Sixteen fixture
tests in `tests/exec_evidence.rs` (`xe01`–`xe16`); every earlier test file is
byte-for-byte unchanged except the `BootClockAnchor` literals in
`transition_evidence.rs`, which gained the two new fields with no assertion
touched. See `ACTION_EVIDENCE.md` §15 and
`ACTION_EVIDENCE_IMPLEMENTATION_REPORT.md`.

## Sniffer Dog 2.0 Phase C1 note

`aip-reconcile::action` gains `LineageEdge` and `derive_lineage_edges`: a
pure derivation over collector-signed batches that keeps only completed,
start-verified `ProcessExecution`s (both ends pidfd-anchored). It adds no
result class, no reason, no guard change; `LINEAGE_VIOLATION` remains
refused by `Draft::precondition_holds`. Seven fixture tests in
`tests/lineage_edges.rs`. Consumed by `aip-agent` as a verifier-local input.

## Phase C2 note (Gate 1 of the completion mandate)

Record version 3 → 4: `Reconciliation.lineage: LineageComparison` (encoded
after `temporal`), `LineageLink`, nine reason codes `0x70–0x78`. The two
entry points now share `prologue()` (expectation verification, window,
observer verification, availability, health freshness) — a pure extraction;
every pre-existing test passed unchanged. `reconcile_lineage` is the third
entry point. `LineageInputs { peer_expectations, authority: Option<DecisionAuthority>,
issuer_keys, revoked_jtis, identity: Option<IdentityLineageInput> }`; all of
it is verified inside the reconciler through `aip_authorize` and `aip_core`
(`aip-core` became a regular dependency). The guard unit test that pinned
"refused unconditionally" now pins "refused without a contradicted lineage".
Sixteen tests, `tests/lineage_violation.rs`. See `RECONCILIATION_MODEL.md`
"The lineage question".

## Corrective pass

### Phase 0 — audit of the first implementation

| Requirement | Implementation at `362695b` | Test coverage | Gap | Severity | Fix |
|---|---|---|---|---|---|
| Coverage of the exact window is attested (Skill 7 §13) | union of probe-claimed intervals, hull check only | none for holes | probe-claimed intervals need not abut; a hole inside the window read as coverage | **P0** | `recompute_coverage` sweep → `CoverageGapInWindow` |
| Coverage may not describe the future | none | none | probe could claim an unfinished window; collector never compared it with its own clock | **P0** | window must end at/before `health.emitted_at_ms` → `CoverageEndsAfterHealth` |
| Health freshness has explicit temporal semantics (§22) | `availability_for` bounded old health only | `t11b` (stale) | future-dated health saturated to age 0 and read as fresh | **P0** | `HealthNotYetEmitted` |
| Kernel-pushed provenance from signed coverage (PR3 A-3) | read `health.covered_by` | `t02`, `t02b` | derived scalar trusted although the batches it derives from were in hand | **P1** | recomputed intersection over the covering batches |
| One continuous sampling run over the window (I9) | relied on collector epoch bookkeeping | none | `probe_run_id` present in evidence, never checked | **P1** | `CoverageProbeRunChanged` |
| `IDENTITY_DIVERGENCE` needs attested divergence (§14) | keyed on `claimed_decision_id` alone | `t06`, `t06b` | claim is unauthenticated; anyone able to register one could frame another agent's decision | **P1** | claim's `agent_id` must name the expectation's agent → `ClaimInconsistent` |
| Observation must be independent of the agent (I10, §29) | never checked | none | a self-signed "observer" produced `Attested` evidence and `PHANTOM_CLAIM` | **P1** | `agent_public_key` in the context; `ObserverKeyIsAgentKey` |
| Errors distinguish malformed / untrusted / invalid (§32) | `Err(_)` catch-all → `Proven` integrity failure | `t13` | a malformed **anchor** (verifier's own config) accused the observer of tampering at `Proven` | **P1** | exhaustive classification |
| Positive verdicts have enforced preconditions (§11) | per-branch only | per-branch | nothing central; a future edit could emit a class without its evidence | **P1** | `Draft::precondition_holds` choke point |
| `VERIFIED_EXECUTION` structurally unreachable | comment + no call site | `t08_t09` | `ActionComparison::Match` freely constructible | **P2** | `ActionEvidenceSeal` with a private field and no constructor |
| Identifier newtypes at the boundary | `DecisionId` only; `BatchId`/`ProbeRunId` **dead** | `ids` unit test | report cited a property the code did not have (I15) | **P2** | newtypes used throughout `EvidenceRef` / `ObservationTarget` |
| Canonical codes stable under edit | `*self as u8` | distinctness only | inserting a variant silently renumbered others | **P2** | explicit discriminants |
| `CANNOT_PROVE` default; no score/severity | correct | `t19_t21`, unit | none | — | — |
| Replay / fork / rollback / gap distinct (§24) | correct | `t15`, `t15b`, `t16` | none | — | — |
| Reconciler holds no key, signs nothing, no warrant/containment | correct | whole suite | none | — | — |

Audit items that found **no** gap are recorded above as "none" rather than
omitted, so the absence of a fix is a stated result and not an oversight.
Items B (bypass of the default), G (silence as non-execution), H/I
(observation ↔ authorization collapse), K (procfs strength cap), N
(transplanted window/boot/sequence), O (replay/rollback/fork/truncation) and
P (withheld evidence) were re-tested and held, except where they appear as
gaps above.

### Weaknesses, and why each mattered

The five coverage weaknesses share one root cause: **`claimed_from_ms`,
`claimed_to_ms`, `active_mechanisms` and `probe_run_id` are authored by the
host-side probe**, which the threat model treats as untrusted, and
`CollectorSigner::attest` validates none of them beyond the registry bound.
The first implementation then consumed the collector's *derived* scalars
(`attested_coverage`, `covered_by`) rather than re-deriving them from the
batches it already held — the opposite of the rule `aip-observe` applies to
chain heads, which are always recomputed and never read from a field. A
compromised host could therefore manufacture coverage over an interval
nothing sampled, and `PHANTOM_CLAIM` is precisely a statement about such an
interval.

R6 mattered for a different reason: it is a **false-accusation channel**.
`claimed_decision_id` is an unauthenticated claim, so keying divergence on it
alone let any process able to register a claim attach itself to another
party's decision and produce an `IDENTITY_DIVERGENCE` naming that party.

### RED → GREEN trail

| Test | Weakness | Verdict before the fix | Now |
|---|---|---|---|
| `r1_gap_between_claimed_windows_…` | hole inside the window | `PHANTOM_CLAIM` | `CANNOT_PROVE` / `CoverageGapInWindow` |
| `r2_coverage_claimed_beyond_health_emission_…` | coverage of the future | `PHANTOM_CLAIM` | `CoverageEndsAfterHealth` |
| `r3_health_emitted_after_the_verification_time_…` | future-dated health | `PHANTOM_CLAIM` | `HealthNotYetEmitted` |
| `r4_kernel_coverage_must_be_recomputed_…` | derived `covered_by` trusted | `PHANTOM_CLAIM` | `CoverageNotKernelPushed` |
| `r5_probe_restart_inside_the_window_…` | restart inside the window | `PHANTOM_CLAIM` | `CoverageProbeRunChanged` |
| `r6_divergence_requires_the_claim_to_name_the_expected_agent` | framing via a claim | `IDENTITY_DIVERGENCE` | `AttributionInconsistent` |
| `r7_observer_key_equal_to_the_agent_key_…` | agent is its own observer | `PHANTOM_CLAIM` | `ObserverKeyIsAgentKey` |
| `positive_classes_without_their_precondition_are_downgraded` (unit) | no central guard | class emitted as proposed | `InvariantNotSatisfied` |

R1–R6 were committed **failing** in `6b2f5c7` with no production change, so
the trail is verifiable by checking out that commit. R7 could not be
expressed before the fix — the context had no `agent_public_key` field — so
it was red at compile time, the same pattern recorded for PR3 A-3; it pins
both the fixed behaviour and the residual limitation that the verifier must
supply the key.

## Positive-verdict proof matrix

| Result | Minimum required evidence | Produced by | Signed by | Verified by the reconciler | Remains unknown | False positive blocked by | Test |
|---|---|---|---|---|---|---|---|
| `PHANTOM_CLAIM` (`Attested`) | signed `ExpectedExecution`; contiguous `AttestedBatch` chain ending at the signed health head; `SignedSensorHealth` with `Active`, `RegisteredOnly`, `attested_coverage ⊇ window`, kernel-pushed `covered_by` | probe (measurements), collector (chain, health), decision point (expectation) | collector (Ed25519, off-host key); decision point | both signatures; chain arithmetic; chain ends at health head; **re-derived** gap-free coverage, single `probe_run_id`, kernel-pushed intersection, window ending no later than `health.emitted_at_ms`; no reference of any kind to the instance, its pid, or its decision | whether an execution occurred that the observer's sensors cannot see (no syscall/file/exec-argument source exists); truth of procfs content under host root | recomputation from primary evidence, not derived scalars; any reference at all removes `NoReference`; `Degraded`/`Recovering`/`Quarantined` block; Open policy blocks; central guard requires `coverage_recomputed` | `t03`, `r1`–`r5`, `t02`, `t02b`, `t03b`, `t03c`, `t10`, `t11`, `t14_t18` |
| `IDENTITY_DIVERGENCE` (`Attested`) | signed expectation; attested observation of a measured instance whose claim names this decision **and** this agent; instance differs from the binding | probe | collector | both signatures; structural instance comparison (tuple + executable digest, never pid alone); claim-pair consistency; `Active`; `RegisteredOnly` | whether the claim was truthful — attribution is `Claimed`, never verified; whether procfs content was forged under host root | claim must name the expectation's agent; Open policy blocks; capped at `Attested` because the content is procfs-derived | `t06`, `t06b`, `r6`, `t03c` |
| `SENSOR_INTEGRITY_FAILURE` (`Proven`) | two batches at one sequence with different heads, a non-linking `prev_head`, or a signature that does not cover the bytes | — (the adversary) | collector key (validly, for a fork) | recomputes heads and signatures from the held bytes; any third party can repeat it | who caused it; whether the collector was compromised or buggy | trust and configuration failures are classified separately and never reach `Proven` | `t13`, `t15b`, `r7` |
| `SENSOR_INTEGRITY_FAILURE` (`Attested`) | signed health with `state = Quarantined` | collector | collector | health signature only — the state is the collector's own statement | whether the quarantine is accurate | not `Proven`: nothing was recomputed | `t17b` |
| `CONTINUITY_FAILURE` (`Attested`) | signed health with `Recovering` or `ContinuityUnverified` | collector | collector | health signature; state read, never inferred | what happened during the gap | never upgraded to a claim about the workload; coverage is `None` in these states | `t17` |
| `CANNOT_PROVE` (`Heuristic`) | anything else, including no evidence at all | — | — | whatever was supplied | the proposition itself | it is the `Default`; every other class must earn its way out | `t22`, and every negative case |

### Unreachable, by construction

> **Stage 7 update (`63c5e0a`).** `VERIFIED_EXECUTION` is now reachable for
> exactly one action class — an established TCP connection — through
> `aip-reconcile::action::derive_action`, the one deliberate constructor site
> this table anticipated. **Stage 7c (`1d52f93`)** adds a second class, a
> process execution of an authorized image, through
> `derive_executions`/`derive_transition_evidence` behind the same sealed
> constructors. For every other action kind the row below still holds. See
> `ACTION_EVIDENCE.md` and `ACTION_EVIDENCE_IMPLEMENTATION_REPORT.md`.

| Result | Why unreachable | What would have to change |
|---|---|---|
| `VERIFIED_EXECUTION` (any action other than `ghost.net.connect.v1`) | `ActionComparison::Match` requires an `ActionEvidenceSeal` built only by `action::derive_action`, which maps only ESTABLISHED TCP socket-table rows; no other `ObservedEffect` or `KernelLifecycleEvent` carries action content. | an evidence source that measures the action itself and binds it to the process instance — a new producer, and a new arm in `derive_action` |
| `UNATTRIBUTED_EFFECT` | requires a verified `DecisionPointCoverageStatement` in the evidence list; **no component emits one**. The verifier contract exists and is tested with a test-signed statement. | a decision point that publishes signed completeness statements |
| `LINEAGE_VIOLATION` | refused unconditionally by the central guard; no lineage input type exists and a kernel fork binds at most one end | bound parent **and** child, plus an ancestry comparison |

If any of these becomes reachable, the change is visible in exactly one
place per class (a constructor in `result.rs`, a producer for the statement,
a lineage input) — not distributed across the engine.

## Gate decision

Skill 7 complete. The next permitted gate is **SKILL 8 — WARRANT**, which may
consume `Reconciliation { result, strength, availability }` and must refuse to
act on `CANNOT_PROVE` or any `Unavailable` availability. Nothing in this stage
pre-empts it: no policy, severity or response type was introduced.

## Gate 2 note (wire corroboration, record v5)

`RECONCILIATION_VERSION` 4 → 5: `Reconciliation.wire: WireCorroboration`
(`NotEvaluated` 0x00 / `Unavailable` 0x01 / `NotObserved` 0x02 /
`Ambiguous{handshakes}` 0x03 / `Corroborated` 0x04), encoded after the
lineage comparison. `compare_action` now names the transition that carried a
`Verified` outcome; for a socket transition `corroborate_wire` (in
`reconcile.rs`) answers the device layer's question from `WireTapAfPacket`
segments — tap declared live inside attested coverage with counted zero
loss over the transition's window, segments placed through their batch's
clock anchor, exactly one SYN and its SYN-ACK on the tuple within one second
of the kernel transition — and cites both segments. No branch of it touches
`result`, `strength` or `reason`; `precondition_holds` is unchanged. Model:
`RECONCILIATION_MODEL.md` "The wire question". Tests:
`tests/wire_corroboration.rs` wc01–wc15. The `lv15` pin on the record
version became a compile-time `>= 4` bound.

## Gate 3 note (socket send)

`action.rs`: `SocketSend` and `derive_sends` — a bound `SocketSend` event
with a positive count, its endpoint the one named by the latest attested
`SocketState` transition of the same `sk` not later than the send and not a
close, unless a close of that `sk` lies between (unresolved); digest through
`net_send_parameters`. `TransitionEvidence::Send` (completion is the
initiation). `reconcile.rs`: `ActionOutcome::Unresolved` →
`ReasonCode::SendSocketUnresolved` (0x4f); a transition that is one event
is cited once; the wire question is asked of socket transitions only. Record
version unchanged (v5). Tests: `tests/send_evidence.rs` ss01–ss13.
