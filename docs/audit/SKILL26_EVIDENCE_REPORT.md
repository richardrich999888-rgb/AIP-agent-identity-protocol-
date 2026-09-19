# Skill 26 — Evidence Report

**Specification** `.claude/skills/26-disconnected-space-autonomy-profile/SKILL.md`
— one authoritative document, byte-identical on both branches carrying it.
**Baseline** `742517c` · **Branch** `claude/skill-25-implementation-xbz0t3`
**Related** ADR-011, ADR-012, `SKILL26_27_PLAN_AND_INVARIANTS.md`

---

## 1. Acceptance criteria

| # | criterion (from the specification) | status | where |
|---|---|---|---|
| R1 | Define `SpaceExecutionProfile` | met | `profile.rs` |
| R2 | Define `AutonomyModeTransition` | met | `mode.rs` |
| R3 | Define `DelayedEvidence` | met | `delayed.rs` |
| R4 | Define `StoreAndForwardBundle` | met | `bundle.rs` |
| R5 | Define `GroundVerificationContext` | met | `ground.rs` |
| R6 | Long-duration sequence/continuity semantics and recovery from intermittent links | met | `segment.rs` over `aip-observe::ObserverLedger`; `link.rs` |
| R7 | NEXORA packaging for offline reconstruction and verification | met | `tests/mission.rs::offline_reconstruction_flows_through_the_existing_verifier` |
| R8 | Delayed ground commands and delayed observation arrival without inventing real-time certainty | met | `CommandTiming` (six moments, no cross-clock order), `DelayedEvidence` |
| R9 | Adversarial tests for missing segments, delayed segments, branch/fork histories, replay across contacts | met | `tests/adversarial.rs` s1–s15 |
| N1 | Offline operation is a first-class mode, not a bypass | met | `LinkState::changes_evidential_standing() == false`; `link_state_changes_capability() == false` |
| N2 | Delayed arrival is not non-occurrence | met | `event_time_established() == false`; `receipt_time_is_event_time() == false` |
| N3 | Continuity gaps stay explicit and are not papered over | met | latched `gap_observed`; `unfilled_gaps()` records exact sequences |
| N4 | No timing/order claimed beyond the trust model | met | `cross_clock_order_established() == false` |
| G1 | A simulated disconnected mission executes, collects locally and is verified later without cloud dependence | met | `tests/mission.rs`, on a real execution; `requires_network() == false` |
| G2 | Continuity failures are explicit and do not silently downgrade into success | met | `tests/mission.rs::the_same_mission_with_a_lost_contact_preserves_the_gap_and_never_succeeds` |

**14 of 14.**

## 2. The twelve required adversarial cases

| # | case | outcome | test |
|---|---|---|---|
| 1 | missing middle segment | exact sequences recorded; non-occurrence refused | s1 |
| 2 | delayed middle segment after later evidence | `LateArrival`; gap stays open | s2 |
| 3 | replayed old segment after reconnection | `ContinuityFault::Replay` | s3 |
| 4 | duplicated bundle | `BundleAlreadySeen` | s4 |
| 5 | reordered evidence | reassembled by sequence; no gap | s5 |
| 6 | forked history A/B | `ContinuityFault::Fork`, permanent quarantine | s6 |
| 7 | delayed ground command | six moments distinct, no order asserted | s7 |
| 8 | observation after command | says nothing about event time | s8 |
| 9 | forged continuity restoration | link state grants nothing | s9 |
| 10 | forged bundle metadata | digest differs | s10 |
| 11 | malformed bundle | refused at construction | s11 |
| 12 | truncated bundle | `BundleRangeMismatch` at the receiver | s12 |

Plus three standing negatives (s13–s15).

## 3. Evidence classes

**CODE-PROVEN** — the crate names no continuity fault vocabulary, no ledger
type, no reconciler, no verifier, no identifier, no key and no leaf kind; twelve
guard tests assert this over its own source with comments stripped. There is
exactly one place a ledger fault is handled and no `repair`, `heal`,
`bridge_gap`, `close_gap`, `force_admit`, `clear_gaps` or `reset_continuity`
function anywhere.

**TEST-PROVEN** — 98 tests over constructed values (71 unit, 15 adversarial, 12
structural). All 15 invariants in the plan document.

**EXECUTION-PROVEN** — 4 tests running the Skill 22 three-process reference as a
spacecraft's onboard computer: real processes, real procfs and socket-table
measurement, a real off-process collector, the real verdict engine reaching
`VERIFIED_EXECUTION`, and a real NEXORA proof exported, re-parsed and verified
against separately provisioned anchors. **What is real is the onboard Linux
execution and the offline verification path.**

**SIMULATION-PROVEN** — the link outage. Contacts are modelled by which bundles
the ground station is handed and when. This is a distinct class from
EXECUTION-PROVEN and the test module says so in its own header.

**DOCUMENTED** — ADR-012 (six decisions, six rejected alternatives, three open
questions), ADR-011, the plan and invariant matrix.

**INFERRED** — that the eleven sensing sources are the right taxonomy for a
spacecraft; that a late arrival should not rewind the chain (Decision 4 — the
sharpest judgement call, and reasonable people could want a checkpoint-replay
protocol instead); that `DegradedCarrier` earns its place as a distinct state.

**UNKNOWN** — everything about real orbital operation. Link budgets, real
contact scheduling, onboard clock drift, radiation-induced faults, and how any
of this behaves on flight hardware. Also whether a real mission's bundle sizes
and contact durations make the contiguous-run requirement practical.

**Not claimed:** no spacecraft, no orbital hardware, no real radio and no real
link timing were involved. The acceptance gate is a **simulated** disconnected
mission, which is what the specification asks for and is not real-world
validation.

## 4. Mutation testing

16 mutations targeting Skill 26's security-sensitive rules. For every one the
harness asserted the fragment was present, wrote the file, confirmed it changed,
confirmed the crate still compiled, and only then ran the suite.

| mutation | outcome | killed by |
|---|---|---|
| S1 event time established | KILLED | `arrival_time_is_never_event_time` |
| S2 receipt time is event time | KILLED | same |
| S3 absence becomes non-occurrence | KILLED | `a_gap_never_becomes_evidence_of_non_occurrence` |
| S4 gaps not recorded | KILLED | `a_gapped_mission_concludes_incomplete...` |
| S5 gap status not latched | KILLED | `a_missing_middle_segment_records...` |
| S6 duplicate bundle accepted | KILLED | `a_duplicate_bundle_is_refused_at_the_second_contact` |
| S7 non-contiguous bundle accepted | KILLED | `a_bundle_with_a_hole_is_refused` |
| S8 truncated bundle accepted | KILLED | `a_truncated_bundle_fails_its_own_range_check` |
| S9 reconnection grants standing | KILLED | `no_link_state_changes_evidential_standing` |
| S10 late arrival rewinds the chain | KILLED | `a_delayed_middle_segment_arriving_later_does_not_rewind_the_chain` |
| S11 completeness ignores late arrivals | KILLED | `a_late_arrival_on_an_otherwise_complete_run_blocks_completeness` |
| S12 cross-clock order asserted | KILLED | `s7_a_delayed_ground_command_keeps_its_six_moments_distinct` |
| S13 conclusion asserts non-occurrence | KILLED | `a_gapped_mission_concludes_incomplete...` |
| S14 agreement raises ceiling | KILLED | `agreement_never_raises_the_ceiling` |
| S15 mission state echoes always | KILLED | `a_self_reported_completion_is_never_asserted` |
| S16 completeness ignores continuity | KILLED | `a_missing_middle_segment_records...` |

**REQUIRED 16 · APPLIED 16 · PATCH APPLIED 16/16 · KILLED 16 · SURVIVORS 0.**

Two mutations survived the first run — S8 and S11 — and both were **real
findings, fixed in the code rather than in the tests**. Each targeted a
defensive branch that an earlier check already made unreachable: the bundle span
check was shadowed by the contiguity check, and two conjuncts of
`completeness_claimable` were shadowed by the continuity status. Unreachable
branches were removed, the truncation defence was consolidated into `check()`,
and a missing test case — a late arrival on a run with no gap — was added. A
predicate with unkillable branches is a predicate nobody can check.

## 5. Wire, version and dependency impact

| item | result |
|---|---|
| production files changed outside the new crate | **0** (workspace member list and `Cargo.lock` only) |
| wire/protocol version changes | **none** — `OBSERVE_PROTOCOL_VERSION` stays 9 |
| signed field changes | **none** |
| new `SourceMechanism` variants | **0** |
| new `LeafKind` variants | **0** — `ALL.len() == 9`, asserted in this crate's tests |
| new reconcilers / verifiers / ledgers | **0** |
| new trust anchors / signers / keys | **0** |
| new identifiers | **0** — `SystemId`, `MissionId`, `PlatformId` reused |
| new domain tags | 1, with 3 structure discriminants |
| new parameter keys | 1, versioned in the key |
| new external dependencies | **0** |

## 6. Known limitations

1. **A gap can never be closed.** By design (ADR-012 §4). A checkpoint-replay
   protocol is conceivable and would need its own ADR.
2. **No clock discipline is modelled**, so cross-clock ordering stays
   unestablishable even where a deployment has a disciplined onboard clock.
3. **No spacecraft, no radio, no orbital timing.** Simulated outage only.
4. **`GroundRadiometricTracking` and `ThirdPartyTracking` are unmechanised**,
   so the only independent view of a vehicle is capped at `Corroborative`.
5. **Physical effect in orbit is unreachable**, as in every embodied vertical.
