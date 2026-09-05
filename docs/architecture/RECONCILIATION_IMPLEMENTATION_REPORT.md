# RECONCILIATION IMPLEMENTATION REPORT

Skill 7 (reconciliation) / Orchestrator Stage 4. Crate: `aip-standalone/aip-reconcile`.

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

## Data model

```
ExpectedExecution  (aip-authorize; DP-signed)
        +
ObserverEvidence { batches: Vec<AttestedBatch>, health: SignedSensorHealth }  (collector-signed)
        +
ReconciliationContext { decision_point_anchors, observer_anchors,
                        verification_time_ms, health_max_age_ms,
                        window_tolerance_ms, expected_side }
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
   (Attested)` unless `probe_policy == Open`; `UnboundReferencesOnly` →
   `CANNOT_PROVE`; `NoReference` → `PHANTOM_CLAIM (Attested)` only if
   availability is `Covered` **and** `probe_policy == RegisteredOnly` **and**
   signed `covered_by` contains a kernel-pushed mechanism **and** the supplied
   contiguous chain's claimed windows span the window; otherwise
   `CANNOT_PROVE` with the specific missing precondition
   (`ObservationOutsideWindow`, `WindowNotCovered`,
   `ProvenanceUnverifiedOpenPolicy`, `CoverageNotKernelPushed`,
   `ObservationSetIncomplete`).

## Reachability of the result classes

| Result | Reachable | Strength | Precondition enforced |
|---|---|---|---|
| `CANNOT_PROVE` | yes (default) | `Heuristic` | none — it is the absence of a verdict |
| `PHANTOM_CLAIM` | yes | `Attested` | see step 8 |
| `IDENTITY_DIVERGENCE` | yes | `Attested` | Active observer, RegisteredOnly, a measured instance carrying this decision claim that fails the structural match, no matching instance |
| `SENSOR_INTEGRITY_FAILURE` | yes | `Proven` (signature / chain arithmetic) or `Attested` (collector-declared `Quarantined`) | recomputable failure, or signed quarantine |
| `CONTINUITY_FAILURE` | yes | `Attested` | signed `Recovering` / `ContinuityUnverified` |
| `VERIFIED_EXECUTION` | **no** | — | `ActionComparison` is always `Unobservable`; nothing constructs `Match` |
| `UNATTRIBUTED_EFFECT` | **only with a `DecisionPointCoverageStatement`**, which no production component emits | `Attested` | verified DP-signed completeness statement covering agent and window; claim not in its set; instance bound; attribution claimed; RegisteredOnly |
| `LINEAGE_VIOLATION` | **no** | — | both fork ends bound; not produced |

"Identity corroborated" is the ceiling for an expectation: it is reported as
`CANNOT_PROVE` with `reason = ActionEvidenceUnavailable` and `identity =
Match`, so a consumer sees exactly what was and was not established. No fake
action matcher was added.

## Canonical encoding, domain separation, signature coverage

- `Reconciliation::canonical_bytes()` — domain `SYNTRIASS/GHOST/RECONCILIATION/v1`
  first (length-prefixed), then every field with explicit discriminants and
  presence bytes via `aip_types::canonical`. Mutation of any field changes the
  bytes (tested). The record is **not signed** by this crate: it holds no key.
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

| Suite | Before | After |
|---|---|---|
| aip-standalone `cargo test --workspace` | 408 / 0 / 3 ignored | **442 / 0 / 3 ignored** (+4 unit, +30 adversarial) |
| aip-service `cargo test` | 39 / 0 | 39 / 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` (both) | clean | clean |
| `cargo fmt --all --check` (both) | clean | clean |

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
  kernel-pushed mechanism covered the whole window and whose complete
  contiguous chain over the window contains no reference to the expected
  instance or pid and no claim of its decision, **the observer recorded no
  such instance**: `Attested`. This is a statement about the attested record,
  bounded by the observer's threat model (`SNIFFER_DOG.md`), not a proof that
  nothing executed.
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
| Verifier | both anchor sets, its clock, tolerances | itself; the reconciler reads no clock and holds no anchors |
| Reconciler | nothing | — |

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

## Gate decision

Skill 7 complete. The next permitted gate is **SKILL 8 — WARRANT**, which may
consume `Reconciliation { result, strength, availability }` and must refuse to
act on `CANNOT_PROVE` or any `Unavailable` availability. Nothing in this stage
pre-empts it: no policy, severity or response type was introduced.
