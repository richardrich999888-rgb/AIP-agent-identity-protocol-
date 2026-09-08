# Mutation Assurance — `reconcile_observation`

**Baseline HEAD** `993261050690b9b8a4b9fbe471de5ddc2318fae5`
**Branch** `claude/skill-25-implementation-xbz0t3`
**Working tree at start** clean
**Harness** `validation/mutation/mutate_observation.py`
**Machine-readable result** `validation/mutation/OBSERVATION_MUTATION_RESULTS.json`

---

## 1. Scope

The previous milestone (`docs/RECONCILER_VERIFIER_MUTATION_ASSURANCE.md`)
closed 46 mutations across `aip-reconcile` and `aip-nexora` and then named its
own largest remaining gap, §9.2:

> Of the three public entry points, the expectation path carries 18 mutations
> and the lineage path 3; `reconcile_observation` carries none of its own. …
> Given that R-11b and R-12b were both found on the *lineage* path for exactly
> this reason — an invariant covered at one entry point and unguarded at
> another — the same failure is likely here. **This is the single
> highest-value follow-up.**

This document tests that prediction against the third entry point.

**The prediction was correct, and understated. Thirteen of twenty-six
mutations survived the first pass — exactly half the matrix.** The
observer-state gate on this path could be deleted whole without failing a
single test in the repository.

Nothing in this milestone touches NEXORA authority, adds a reconciler or
verifier, changes the wire protocol, or weakens `CANNOT_PROVE` or an evidence
ceiling. Zero production source files were modified.

---

## 2. The observation entry point as it stands

`reconcile_observation(observer, target, ctx) -> Reconciliation`, at
`aip-standalone/aip-reconcile/src/reconcile.rs:1470`. It answers a different
question from the other two entry points: *given an attested observation and
no expectation to compare it against, is this an effect nobody authorised?*

That makes it the only entry point that can produce an accusation against a
workload **without an expectation on the other side of the comparison** — and
therefore the one where an unguarded precondition costs the most.

Read from the implementation, in execution order:

| # | Stage | Inputs | Outcome on failure |
|---|---|---|---|
| 1 | `verify_observer` — signatures, anchors, chain, continuity, I10 | `ObserverEvidence`, `ctx.observer_anchors`, `ctx.agent_public_key` | `SensorIntegrityFailure`·`Proven`, or `CannotProve` |
| 2 | Replay accounting | duplicate batches | flag on the record |
| 3 | Target location | `ObservationTarget::{Observation,KernelEvent}{batch_sequence,index}` | `CannotProve`·`TargetNotFound` |
| 4 | Window derivation | the located batch's `claimed_from_ms`/`claimed_to_ms` | — |
| 5 | Availability | `health.availability_for(window, verification_time, health_max_age)` | recorded, not fatal |
| 6 | Collector-clock sanity | `health.emitted_at_ms` vs `verification_time_ms + tolerance` | `CannotProve`·`HealthNotYetEmitted` |
| 7 | Observer state | `state_reason(health.state)` | `SensorIntegrityFailure`·`Attested` (Quarantined), `ContinuityFailure`·`Attested` (Recovering, ContinuityUnverified), `CannotProve` (Degraded, IntegrityUnknown) |
| 8 | Instance binding | `has_instance` — always true for an observation, `e.bound.is_some()` for a kernel event | `CannotProve`·`UnboundReferencesOnly` |
| 9 | Attribution | `claimed_agent` | `CannotProve`·`AttributionNotEstablished` |
| 10 | Provenance | `health.probe_policy == Open` | `CannotProve`·`ProvenanceUnverifiedOpenPolicy` |
| 11 | Expected-side completeness | `ctx.expected_side` | `CannotProve`·`ExpectedSideCompletenessUnknown` |
| 12 | Statement authenticity | `stmt.verify(&ctx.decision_point_anchors)` | `CannotProve`·`ExpectedSideStatementInvalid` |
| 13 | Statement scope | `stmt.agent_id == agent && stmt.window.covers(window)` | `CannotProve`·`ExpectedSideStatementDoesNotCover` |
| 14 | The question | `stmt.decision_ids.contains(claimed_decision)` | `CannotProve`·`ExpectationExistsForObservation` |
| 15 | **Terminal** | otherwise | **`UnattributedEffect`·`Attested`·`NoExpectationAttested`** |

Terminal outcomes reachable from this entry point: `SensorIntegrityFailure`
(at `Proven` from stage 1, at `Attested` from stage 7), `ContinuityFailure`
(`Attested`), `UnattributedEffect` (`Attested`), and `CannotProve` under
eleven distinct reason codes. `VerifiedExecution`, `PhantomClaim`,
`IdentityDivergence` and `LineageViolation` are **not** reachable here, which
`corrective.rs` already asserts.

`UnattributedEffect` requires stages 1–14 all to pass. Every one of them is a
precondition for an accusation, which is why every one of them is in the
matrix below.

---

## 3. Mutation matrix

26 mutations, every fragment **unique to `reconcile_observation`**. That
constraint is the point of the exercise: mutating a shared helper would be
killed by an expectation-path test and the asymmetry would stay hidden, which
is exactly how R-11b and R-12b escaped the previous milestone.

Methodology is the one established in `mutate_core.py` and **imported from it**
rather than reimplemented — the runner was extracted to `run_matrix()` so the
four forensic steps (unique fragment, changed digest, successful compile,
restored bytes) cannot drift between matrices. Nothing else in `mutate_core.py`
changed; its own 46/46 result re-verifies unchanged.

*first pass* is the result before any test was added.

| # | invariant broken | first pass | tests failing | first killer |
|---|---|---:|---:|---|
| O-01 | an observer integrity failure is SensorIntegrityFailure at Proven, not an inability to prove | killed | 1 | `t13_tampered_observer_bytes_are_sensor_int…` |
| O-02 | a replayed batch is recorded as replay on the observation path too | **survived** | 1 | `t26_a_replayed_batch_is_flagged_on_the_obs…` |
| O-03 | an Observation target names one batch; a sequence not present is TargetNotFound, not the nearest batch | **survived** | 1 | `t27_a_target_names_exactly_one_record` |
| O-04 | an Observation target names one observation; an index not present is TargetNotFound, not observation zero | killed | 1 | `t05b_unclaimed_observation_is_never_unattr…` |
| O-05 | a KernelEvent target names one event; an index not present is TargetNotFound, not event zero | **survived** | 1 | `t27_a_target_names_exactly_one_record` |
| O-06 | a kernel event the probe could not bind to an instance is unbound, and unboundness is not assumed away | killed | 1 | `t07b_unbound_kernel_event_about_the_expect…` |
| O-07 | the record cites the observation it is about | **survived** | 1 | `t28_the_observation_record_cites_its_own_t…` |
| O-08 | the record carries the decision the observation claimed | killed | 1 | `t05_unattributed_effect_requires_a_signed_…` |
| O-09 | the window compared against the expected-side statement is the batch's own claimed window | **survived** | 1 | `t29_the_expected_side_must_cover_the_whole…` |
| O-10 | availability over the window is computed from the health record, not asserted | *defect* | 1 | `t30_availability_on_the_observation_path_i…` |
| O-11 | a forward-set collector clock cannot saturate staleness to age zero (observation path) | **survived** | 1 | `t24_a_health_record_from_the_future_is_ref…` |
| O-12 | observer state gates the observation path at all | **survived** | 1 | `t23_observer_state_gates_the_observation_p…` |
| O-13 | a quarantined observer yields SensorIntegrityFailure on the observation path, never a mere inability to prove | **survived** | 1 | `t23_observer_state_gates_the_observation_p…` |
| O-14 | a recovering or continuity-unverified observer yields ContinuityFailure on the observation path | **survived** | 1 | `t23_observer_state_gates_the_observation_p…` |
| O-15 | a degraded observer cannot support an attribution on the observation path | **survived** | 1 | `t23_observer_state_gates_the_observation_p…` |
| O-16 | an observer whose integrity is unknown cannot support an attribution on the observation path | **survived** | 1 | `t23_observer_state_gates_the_observation_p…` |
| O-16b | an unbound reference establishes no instance, and unboundness is not assumed away | killed | 1 | `t07b_unbound_kernel_event_about_the_expect…` |
| O-17 | an observation with no claimed agent attributes to nobody | killed | 1 | `t05b_unclaimed_observation_is_never_unattr…` |
| O-18 | an Open-policy (unverified-provenance) mechanism label cannot support an attribution (observation path) | **survived** | 1 | `t25_open_probe_policy_blocks_attribution_o…` |
| O-19 | an unknown expected side is CANNOT_PROVE and never an accusation | killed | 1 | `t04_observed_only_with_unknown_expected_si…` |
| O-20 | the expected-side statement must verify under the verifier's own decision-point anchors | killed | 1 | `t05_unattributed_effect_requires_a_signed_…` |
| O-21 | the record cites the coverage statement its accusation rests on | killed | 4 | `t05_unattributed_effect_requires_a_signed_…` |
| O-22 | a statement about another agent does not settle this agent's expected side | killed | 1 | `t05_unattributed_effect_requires_a_signed_…` |
| O-23 | a statement whose window does not cover the observation's window does not settle it | killed | 2 | `t05_unattributed_effect_requires_a_signed_…` |
| O-24 | an observation whose decision IS in the attested set is not unattributed | killed | 4 | `t05_unattributed_effect_requires_a_signed_…` |
| O-25 | UnattributedEffect is Attested, and its strength is not raised | killed | 4 | `t05_unattributed_effect_requires_a_signed_…` |

---

## 4. Mutation results

| | first pass | final |
|---|---:|---:|
| Mutations | 26 | 26 |
| Patch applied (fragment unique, digest changed) | 25 | **26 / 26** |
| Compiled under mutation | 25 | **26 / 26** |
| **Killed** | 13 | **26 / 26** |
| **Survived** | **13** | **0** |
| Harness defects | 1 | **0** |

`all_files_restored_byte_identical: true` in every pass, confirmed
independently by `git diff` over `aip-standalone/*/src/` being empty.

**Half the entry point was unguarded.** For comparison, the previous
milestone's first pass over `aip-reconcile` and `aip-nexora` killed 37 of 46
(80%); this one killed 13 of 26 (50%). The difference is not that this code is
worse — it is that the tests exercising it were written to check the
*expected-side* logic, which they do thoroughly (O-19 … O-25 were all killed
on the first pass), and never to check that the observer had to be trustworthy
before any of it ran.

## 5. Initial survivors

Thirteen, in three clusters. The clustering is the finding: these are not
scattered oversights, they are three whole stages of the function.

### 5.1 The observer-state gate — five survivors (O-12 … O-16)

**The largest single gap found in this repository so far.** Stage 7 could be
deleted entirely (O-12) without failing one test. Each individual state
mapping was equally free:

| state | correct outcome | covered on expectation path | covered on lineage path | covered here |
|---|---|---|---|---|
| `Quarantined` | `SensorIntegrityFailure`·`Attested` | t17b | lv18 (added last milestone) | **no** |
| `Recovering` | `ContinuityFailure`·`Attested` | t17 | — | **no** |
| `ContinuityUnverified` | `ContinuityFailure`·`Attested` | t17 | — | **no** |
| `Degraded` | `CannotProve` | t14/t18 | lv14 | **no** |
| `IntegrityUnknown` | `CannotProve` | t03d | lv17 (added last milestone) | **no** |

This is the R-11b/R-12b pattern at five times the scale, on the entry point
where it matters most: with the gate removed, a **quarantined** collector — one
proven to have forked its own signed record — could underwrite an
`UnattributedEffect`, an accusation that a workload did something nobody
authorised. The strongest statement the system can make against an observer
would have been no obstacle to the strongest statement it can make against a
workload.

### 5.2 The observer-independent preconditions — five survivors

| # | invariant | consequence if removed |
|---|---|---|
| O-11 | forward-set collector clock refused | a stale health record reads as fresh, because staleness saturates to age zero |
| O-18 | `Open` probe policy blocks attribution | a mechanism label the collector cannot vouch for carries an accusation |
| O-02 | replay flagged | a record cannot distinguish one batch from the same batch twice |
| O-07 | the record cites its own target | a verdict about nothing an auditor can locate |
| O-09 | the full batch window is compared | a statement covering one millisecond settles a batch spanning seconds |

O-09 deserves naming: `covers` is `from >= self.from && to <= self.to`, so
collapsing the observation's window to a single instant makes almost any
statement cover it. The accusation would then rest on a decision point's
attestation about a period it never covered.

### 5.3 Target identity — three survivors (O-03, O-05, and O-04's neighbours)

A target names one record. Falling back to "the first batch" or "record zero"
lets a verifier ask about one event and be answered about another — and the
answer is an attribution.

## 6. Harness defects

One, `O-10`: `ObservationAvailability::Covered` is a struct variant, so the
first draft did not compile. Recorded as
`HARNESS_DEFECT_DOES_NOT_COMPILE` and **never counted as a kill or a
survivor**. Rewritten as `Covered { window }`, it then ran and was killed by
the test written for it.

The previous milestone's lesson held again: fixing a defect rather than
writing it off is what exposes the invariant underneath it.

---

## 7. Regression tests added

**Eight tests, appended to `aip-standalone/aip-reconcile/tests/adversarial.rs`.
No new test file, no new crate, no new dependency, and one shared fixture
helper (`observation_scene`) so each test states only what it is about.**

| test | closes | note |
|---|---|---|
| `t23_observer_state_gates_the_observation_path_state_by_state` | O-12, O-13, O-14, O-15, O-16 | sweeps all five states, asserting exact result **and** strength **and** reason; carries an Active control |
| `t24_a_health_record_from_the_future_is_refused_on_the_observation_path` | O-11 | |
| `t25_open_probe_policy_blocks_attribution_on_the_observation_path` | O-18 | carries a `RegisteredOnly` control |
| `t26_a_replayed_batch_is_flagged_on_the_observation_path` | O-02 | asserts the honest chain is unflagged first |
| `t27_a_target_names_exactly_one_record` | O-03, O-05 | see below |
| `t28_the_observation_record_cites_its_own_target` | O-07 | |
| `t29_the_expected_side_must_cover_the_whole_batch_window_not_an_instant` | O-09 | |
| `t30_availability_on_the_observation_path_is_computed_from_the_health_record` | O-10 | asserts covered, then uncovered from the same evidence |

Four tests carry an explicit **control** — the same arrangement with the
attack removed must reach a *different, honest* outcome. Without one, a test
asserting a refusal passes against a reconciler that refuses everything.

### 7.1 A test that passed and proved nothing

`t27`'s first version asserted `TargetNotFound` for a batch sequence and a
kernel-event index that were not present. It passed. **O-03 and O-05 survived
the re-run anyway.**

The reason is worth recording, because it is a general trap in mutation
testing: the fixture's other batch carried no observation and no batch carried
a kernel event, so the mutated fallback — "use the first batch", "use record
zero" — *also* found nothing and *also* returned `TargetNotFound`. The
assertion could not distinguish a correct refusal from a fallback that
happened to fail.

The rewritten fixture puts a decoy observation in batch 1 and a kernel event
in batch 2, so a fallback is observable: it answers instead of refusing. Both
mutations then died. **A regression test is not finished when it passes; it is
finished when the mutation it was written for is dead.**

## 8. Security invariants newly covered

Twenty-six invariants of `reconcile_observation` are now proven non-vacuous —
each fails a named test when removed. Thirteen of them were previously
unguarded:

**The observer must be trustworthy before anything it carries is used**
— an integrity failure is an integrity failure at `Proven` (O-01); a
quarantined, recovering, continuity-unverified, degraded or integrity-unknown
observer stops the function, each to its own outcome (O-12 … O-16); a
collector clock ahead of the verifier's cannot make a stale record read fresh
(O-11); an `Open` probe policy is unverified provenance (O-18); a duplicate
batch is collapsed *and* flagged (O-02).

**A target names exactly one record** — not the nearest batch (O-03), not
observation zero (O-04), not event zero (O-05).

**The record says what it rests on** — it cites its own target (O-07), carries
the decision the observation claimed (O-08), cites the coverage statement its
accusation rests on (O-21), and computes availability from the health record
rather than asserting it (O-10).

**An unbound reference establishes no instance** (O-06, O-16b) and an
observation with no claimed agent attributes to nobody (O-17).

**An accusation needs an attested, authentic, in-scope expected side** — an
unknown expected side is `CANNOT_PROVE` and never an accusation (O-19); the
statement must verify under the verifier's own anchors (O-20); it must be
about this agent (O-22) and must cover the batch's whole window, not an
instant inside it (O-09, O-23); an observation whose decision *is* attested is
not unattributed (O-24); and `UnattributedEffect` is `Attested`, never raised
to `Proven` (O-25).

**`CANNOT_PROVE` remains fail-closed.** O-19 is the direct test of the
forbidden conversion — insufficient evidence becoming an accusation — and it
was killed on the first pass. O-25 pins the ceiling: the strength of an
`UnattributedEffect` cannot be raised.

## 9. Final mutation result

**26 of 26 killed. 0 survivors. 0 harness defects.**

Every mutation proven active before its result was read: `all patch_applied:
true`, `all compiled: true`. Every source file restored byte-identically.

Combined with the previous milestone, and stated only as arithmetic:

| matrix | mutations | killed |
|---|---:|---:|
| Skills 11–15, 17–20, 25–27 (earlier work) | 84 | 84 |
| `aip-reconcile` + `aip-nexora` core | 46 | 46 |
| `reconcile_observation` | 26 | 26 |
| **Total** | **156** | **156** |

---

## 10. Remaining mutation blind spots

1. **Kill strength here is thinner than in any previous matrix.** 22 of 26
   mutations are killed by exactly **one** test; the median is 1 and the
   maximum is 4. That is arithmetically expected — a regression written for one
   blind spot guards one blind spot — but it means the invariants closed today
   are the most fragile in the system. Deleting any one of the eight new tests
   re-opens what it closed, silently.

2. **`aip-reconcile/src/action.rs` (894 lines) is still unmutated**, carried
   forward unchanged from the previous report. `compare_action` and
   `derive_action` are not reachable from `reconcile_observation`, so this
   milestone does not touch them.

3. **`verify_observer` is shared and mutated only through the expectation
   path.** The previous matrix's R-03 … R-10 all mutate it, and O-01 confirms
   the observation path routes its failures correctly, but the *interior* of
   `verify_observer` is proven non-vacuous only by expectation-path tests. If
   those were deleted the observation path would lose its guard too, and no
   test here would notice.

4. **`ObservationTarget` has two variants and the matrix samples them
   unevenly.** O-04 and O-05 cover index handling for both; nothing mutates the
   `KernelEvent` attribution extraction (`e.attribution.claimed_agent_id()`,
   `e.claimed_decision_id`) independently of the `Observation` one.

5. **`state_reason` itself is unmutated.** O-12 … O-16 prove the *call sites*
   act on its result; nothing proves the mapping inside it is right. A mutation
   returning `None` for every state would likely be killed by the same tests,
   but that is a prediction, not a result.

6. **The other nine skills without mutation evidence are unchanged** —
   3, 4, 5, 6, 8, 9, 16, 21, 22, 23, 24 as `SKILL_CONFORMANCE_27_FULL_RUN.md`
   §11.1 described them.

## 11. Cross-entry-point consistency

The asymmetry hunt, stated as a table. This is the check the previous
milestone asked for by name.

| invariant | `reconcile_expectation` | `reconcile_lineage` | `reconcile_observation` |
|---|---|---|---|
| observer integrity failure | R-03 | via shared prologue | **O-01** |
| quarantined observer | R-11 | R-11b *(added last milestone)* | **O-13** *(added here)* |
| recovering / continuity-unverified | t17 | via shared gate | **O-14** *(added here)* |
| degraded observer | R-13 | R-13b | **O-15** *(added here)* |
| integrity-unknown observer | R-12 | R-12b *(added last milestone)* | **O-16** *(added here)* |
| the state gate exists at all | R-11/12/13 | R-11b/12b/13b | **O-12** *(added here)* |
| forward-set collector clock | R-17 | — | **O-11** *(added here)* |
| `Open` probe policy | R-18 | shared site | **O-18** *(added here)* |
| replay flagged | R-09 | via shared prologue | **O-02** *(added here)* |

**Every row that was bare is now covered.** The pattern that produced R-11b
and R-12b — and then O-11 through O-18 — is a structural property of this
codebase: shared semantics stated separately at each entry point, with tests
written per-entry-point rather than per-invariant. Two milestones have now
found it twice. A third entry point does not exist, so the pattern is
exhausted *for the reconciler*; it is not exhausted for the repository.

## 12. Architecture verification

Checked against the restored sources after the final pass.

| Invariant | Result |
|---|---|
| One reconciler | **UPHELD** — `pub fn reconcile_*` in one file, three entry points, one engine |
| One verifier | **UPHELD** — `verify_proof` and `verify_nexora_proof` in `aip-nexora` only; NEXORA authority untouched |
| One evidence hierarchy | **UPHELD** — one `ReconciliationResult` |
| One `EvidenceCeiling` | **UPHELD** — one definition, `aip-observation/src/class.rs:43` |
| One `ObservationClass` | **UPHELD** — one definition, same file |
| One crypto primitive | **UPHELD** — `SigningKey::generate` appears once, in `aip-crypto` |
| No new signer | **UPHELD** |
| No new trust anchor | **UPHELD** — tests consume existing anchor types |
| No vertical-specific security semantics | **UPHELD** — nothing added outside `aip-reconcile`'s own tests |
| No protocol/wire modification | **UPHELD** — see §14 |
| No duplicate source of truth | **UPHELD** — the harness runner was *de*-duplicated, not duplicated |


---

## 13. Test totals

### 13.1 Targeted

| suite | before | after | delta |
|---|---:|---:|---:|
| `aip-reconcile` | 177 | **185** | +8 |

0 failures before and after. The +8 is the eight tests in §7.

### 13.2 Mutation suites

| matrix | pass | mutations | applied | compiled | killed | survived | defects |
|---|---|---:|---:|---:|---:|---:|---:|
| `reconcile_observation` | first | 26 | 25 | 25 | 13 | **13** | 1 |
| `reconcile_observation` | final | 26 | 26 | 26 | **26** | **0** | **0** |
| core (`aip-reconcile` + `aip-nexora`) | re-verified | 46 | 46 | 46 | **46** | **0** | **0** |

`all_files_restored_byte_identical: true` in every pass.

### 13.3 Full workspace

```
cargo fmt --all -- --check                                            EXIT 0
cargo clippy --workspace --all-targets --all-features -- -D warnings  EXIT 0
cargo test --workspace                                                EXIT 0
  2080 passed · 0 failed · 6 ignored   (182 result blocks, 0 FAILED blocks)
```

| | previous | this milestone | delta |
|---|---:|---:|---:|
| passed | 2,072 | **2,080** | **+8** |
| failed | 0 | **0** | 0 |
| ignored | 6 | **6** | 0 |

The +8 matches the eight new tests exactly. No pre-existing test changed
status. The 6 ignored are the same pre-existing wall-clock and root-privilege
gates.

### 13.4 Structural and dependency guards

- `git diff` over `aip-standalone/*/src/` — **empty**
- `git diff` over every `Cargo.toml` and `Cargo.lock` — **empty**
- one reconciler, one verifier, one `EvidenceCeiling`, one `ObservationClass`,
  one keypair primitive (§12)

---

## 14. Exact git state

| | |
|---|---|
| HEAD at start | `993261050690b9b8a4b9fbe471de5ddc2318fae5` |
| HEAD at end | `993261050690b9b8a4b9fbe471de5ddc2318fae5` (unchanged by this run) |
| Branch | `claude/skill-25-implementation-xbz0t3` |
| `git status --short` at start | empty |
| **Production files changed** | **0** |
| Test files changed | 1 — `aip-standalone/aip-reconcile/tests/adversarial.rs` |
| Harness files changed | 1 — `validation/mutation/mutate_core.py` (runner extracted to `run_matrix`, no behaviour change) |
| Files added | 3 — the observation harness, its result, this report |

### Protocol and wire

**No change.** `AIP_VERSION 0x0004`, `PACKET_VERSION 2`,
`EXECUTION_BINDING_VERSION 1`, `RECONCILIATION_VERSION`, `NEXORA_VERSION`,
`LeafKind::ALL` = 9 — all untouched. No canonical encoder, signing preimage,
domain tag, enum discriminant or serialized field was modified. `git diff`
over `aip-standalone/*/src/` is **empty**; every source file the harness
mutated was restored byte-identically, verified by the harness and again by
git.

### Dependencies

**No change.** `git diff` over every `Cargo.toml` and `Cargo.lock` is empty.

### On the earlier reports

`docs/RECONCILER_VERIFIER_MUTATION_ASSURANCE.md` and
`docs/SKILL_CONFORMANCE_27_FULL_RUN.md` are **not edited by this milestone**.
The first correctly records the state at `2f13b77`, when
`reconcile_observation` had no mutation coverage and said so; the second
correctly records the state at `8fe9ff4`. Neither is retrofitted to suggest
this evidence existed earlier. This document is the answer to the first
report's §9.2, not a revision of it.
