# Skill 29 — Autonomous Edge Threat Model: Evidence Report

**Specification** `.claude/skills/29-autonomous-edge-threat-model/SKILL.md`
**Baseline** `cc70add` · **Branch** `claude/skill-25-implementation-xbz0t3`
**Plan** `docs/architecture/SKILL29_PLAN_AND_INVARIANTS.md` (written before implementation)
**Companion** `docs/architecture/EDGE_TRUST_AND_CUSTODY.md` (trust roots, key custody,
transport authenticity, recovery obligations)
**Amended by** `docs/audit/THREAT_MODEL_EXECUTION_REPORT.md`, which executed the
model. Where the two differ, that report is later and its numbers are the ones
to use: §2's totals moved by one cell, and §7.1's first limitation no longer
holds.
**Related** Skill 28 (`docs/audit/SKILL28_EVIDENCE_REPORT.md`), ADR-014

This report states what is CODE-PROVEN, TEST-PROVEN, EXECUTION-PROVEN,
DOCUMENTED, INFERRED and UNKNOWN. Nothing is promoted to a stronger class
because a fixture was built to demonstrate it, and no cell is a defence
because prose says so.

---

## 1. Acceptance criteria

| # | criterion (from the specification) | status | where |
|---|---|---|---|
| R1 | Threat-model the thirteen named threats | met | `aip-conformance/src/threat.rs`, `Threat::ALL` (13) |
| R2 | Map each threat to the seven named layers | met | 91 cells, exhaustive `answer(t, l)` match |
| R3 | Trust roots, key custody, transport authenticity, recovery obligations | met | `docs/architecture/EDGE_TRUST_AND_CUSTODY.md` |
| R4 | Scenario-driven adversarial tests: UAS, robotics, industrial, disconnected | met | `tests/threat.rs`, four `scenario_*` tests |
| R5 | Track inherited blockers until closure is **independently verified** | met | `src/blocker.rs`; `tests/blocker.rs` (10 tests) |
| G1 | Every high-impact threat has an explicit response **or** an explicit CANNOT_PROVE boundary | met | `threats_with_no_answer()` is empty; `tests/threat.rs::the_model_is_total` |
| G2 | No threat is marked mitigated merely because a log or callback exists | met **by construction** | `Disposition` has four variants and no `Mitigated`; `tests/threat.rs::the_vocabulary_has_no_word_for_mitigated` |

G2 is not satisfied by review discipline. The word does not exist in the type,
so the claim is unwritable — the same technique Skill 28 used to remove
`Waived` from `Conformance`. `Detected` carries a mandatory mechanism string
and `tests/threat.rs::every_cell_names_a_mechanism_and_no_answer_is_bare`
fails on an empty one, so "we log it" cannot be smuggled in as a mechanism-free
detection either.

## 2. What the model says

**Thirteen threats × seven layers = 91 cells, all filled.**

| disposition | cells |
|---|---:|
| `Prevented` | 5 |
| `Detected` | 33 |
| `Uncertainty` | 13 |
| `NotDetectable` | 40 |

*(As corrected by the executed run: `(CompromisedAgent, Warrant)` moved from
`NotDetectable` to `Detected` when execution showed the warrant gate refuses a
record the agent authored. The original declaration and the adjudication are in
`THREAT_MODEL_EXECUTION_REPORT.md` §4.)*

`NotDetectable` is 44% of the model. That is the intended shape, not a
shortfall: a layer that does nothing about a threat says so, with a reason and
— where one applies — the non-establishment that already said so. Filling a
cell with a neighbouring layer's answer would be the "mitigated because
something somewhere handles it" failure one level up.

`threats_with_no_answer()` — the gate's failure condition — counts a threat as
answered only if some layer reaches `Prevented`, `Detected` or `Uncertainty`.
A threat that were `NotDetectable` at all seven layers would therefore **fail**
the gate: blanket non-detectability is neither a system response nor a
CANNOT_PROVE boundary. That is stricter than the specification's mapping rule,
deliberately, and it is why X10 (§4.2) passes the gate on two `Uncertainty`
cells rather than on nothing.

Non-establishments cited by cells: **N-1, N-2, N-3, N-4, N-5, N-6, N-7, N-8,
N-9, N-11** (10 of the 11 in `docs/architecture/AIRI_LIMITATIONS.md`).

### 2.1 Per-threat disposition

| threat | P | D | U | N | has a defence anywhere |
|---|--:|--:|--:|--:|---|
| CompromisedAgent | 1 | 4 | 0 | 2 | yes |
| CompromisedFramework | 0 | 3 | 1 | 3 | yes |
| CompromisedModelRuntime | 0 | 1 | 2 | 4 | yes |
| CompromisedTool | 0 | 2 | 2 | 3 | yes |
| CompromisedProcess | 1 | 3 | 0 | 3 | yes |
| CompromisedHost | 1 | 2 | 3 | 1 | yes |
| ForgedTelemetry | 1 | 3 | 0 | 3 | yes |
| LostConnectivity | 0 | 2 | 1 | 4 | yes |
| PartialObservation | 0 | 2 | 1 | 4 | yes |
| **SensorDeception** | **0** | **0** | **2** | **5** | **no** |
| ObserverFailure | 0 | 4 | 0 | 3 | yes |
| Replay | 0 | 5 | 1 | 1 | yes |
| StaleAuthority | 1 | 2 | 0 | 4 | yes |

## 3. Evidence classification

### EXECUTION-PROVEN
**At the time this report was written: nothing.** The model was an account of
behaviour established elsewhere.

That is no longer true. `THREAT_MODEL_EXECUTION_REPORT.md` records **83 of the
91 cells executed** — each attack staged as real signed artifacts and pushed
through all seven layers, with the observed disposition compared against the
declared one. The eight that remain are named there and counted separately.

### CODE-PROVEN
Claims that hold because the code admits no other shape, independent of any
test:

- `Disposition` has no `Mitigated` variant (`src/threat.rs`).
- `answer(t, l)` is an exhaustive match over `Threat × Layer`. A new threat or
  layer is a compile error, not a silently missing row.
- `Disposition::is_a_defence()` excludes `Uncertainty`, so the "no defence
  anywhere" computation cannot be satisfied by an uncertainty answer.
- B-4's attack surface: `SignedHead` carries no public-key field, so a
  bundle-supplied signer key is unrepresentable rather than rejected.
- B-9: `ReconciliationResult` construction is sealed; `CannotProve` is
  discriminant `0x00`, so the default value is the conservative verdict.

### TEST-PROVEN
- **21 tests added at this baseline, all passing**: `tests/threat.rs` (11),
  `tests/blocker.rs` (10). A further 10 arrived with the executed model
  (`tests/empirical.rs`), bringing the crate to 31.
- Model totality — every threat has an answer at every layer.
- Every cell names a mechanism; no answer is bare.
- The committed `docs/audit/THREAT_MODEL_MATRIX.{json,csv}` matches what the
  generator emits now (`the_committed_threat_artifact_is_current`), so a stale
  artifact fails the build rather than misleading a reader.
- Four adversarial scenarios: UAS and robotics physical rung unreachable;
  industrial acknowledgement is not a process change; disconnected — delayed
  evidence is never read as non-occurrence.
- Nine blockers re-derived **from the repository as it stands now**, not from
  the audit prose that recorded them.

### DOCUMENTED
`docs/architecture/EDGE_TRUST_AND_CUSTODY.md` — trust roots, key custody,
transport authenticity, recovery obligations. Where a statement there is
enforced by code or test, the enforcement is cited; where it is an operator
obligation, it is labelled as one. Operator obligations are DOCUMENTED and
nothing stronger: the repository cannot test a deployment's key ceremony.

### INFERRED
At this baseline, every cell: a disposition was a judgement about what a layer
does, derived by reading it, and 91 cells were not 91 tests.

After the executed run, **eight** — the cells that could not be staged, each
naming why. Every other cell is EXECUTION-PROVEN.

### UNKNOWN
- Whether any of these dispositions holds against a *real* adversary. The model
  is analytic. No red-team exercise was run.
- The residual risk of `SensorDeception` in any specific deployment.
- Whether B-3 can be closed at all (see §5).

## 4. Two findings a reader should not skip

### 4.1 Four of the thirteen threats had no prior model

`docs/architecture/AUTONOMOUS_EXECUTION_THREAT_MODEL.md`,
`docs/architecture/AIRI_THREAT_MODEL.md` and
`docs/OBSERVATION_INTEGRITY_THREAT_MODEL.md` between them enumerate no threat
for **lost connectivity, partial observation, observer failure or sensor
deception**. Two appear in passing as *aggravators* of other entries — a
disconnected deployment sharpening compromised-host, an independent sensor as a
control boundary — but none is enumerated as a threat and none has a
layer-by-layer disposition. The behaviours existed in code (ADR-012's
continuity model, `SensorHealth`, the observation ceilings); the threat model
did not account for them. That gap is what this skill closed, and it is why the
skill named those four explicitly.

### 4.2 SensorDeception is answered by no defence at any layer

X10 is the only threat in the model with zero `Prevented` and zero `Detected`
cells:

| layer | disposition | mechanism |
|---|---|---|
| AIP | NotDetectable | AIP models no sensor |
| AIRI | NotDetectable | AIRI models no sensor |
| Observation | **Uncertainty** | a sensor reading is content read from a device, root-forgeable exactly as procfs is |
| Reconciliation | **Uncertainty** | no verdict rests on a physical quantity; the top evidence tier of every embodied profile is unreachable |
| Warrant | NotDetectable | consumes a verdict |
| Containment | NotDetectable | acts on a warrant |
| NEXORA | NotDetectable | NEXORA commits to what it was given; a deceived sensor produces a faithfully committed *false* reading |

This is guarded by `tests/threat.rs::sensor_deception_is_the_one_threat_with_no_defence_anywhere`,
which fails in **both** directions: if X10 acquires a defence, or if a second
threat loses all of its defences. It is a tripwire on the model's shape, not a
celebration of the gap.

The system's honest response to a deceived sensor is to *decline to assert*,
which is why the two live cells are `Uncertainty`. That is the designed
behaviour and it is not a defence. Anyone deploying against an adversary who
can manipulate the physical environment should read this row as the limit of
what the protocol offers, and note that it is the same limit Skill 25 hit: the
physical rung is unreachable, so a physical lie has nothing to contradict it.

## 5. Inherited blockers — independently verified

Nine blockers were re-derived from the current tree, not inherited from prose.

| blocker | status | verified by |
|---|---|---|
| B-1a temporal bound | CLOSED-AND-VERIFIED | `b1a_the_service_applies_a_temporal_bound` |
| B-3 containment reachability | **OPEN** | `b3_is_still_open_and_is_recorded_open` |
| B-4 bundle-supplied signer key | CLOSED-AND-VERIFIED | `b4_a_bundle_supplied_signer_key_is_unrepresentable` |
| B-5 seed mode | CLOSED-AND-VERIFIED | `b5_the_seed_mode_is_set_at_creation_not_afterwards` |
| B-6 key handling | CLOSED-AND-VERIFIED | `b6_key_handling_fails_closed` |
| B-7 managed signing | CLOSED-AND-VERIFIED | `b7_managed_signing_is_off_unless_a_deployment_opts_in` |
| B-8 anti-replay at both layers | CLOSED-AND-VERIFIED | `b8_anti_replay_exists_at_both_layers` |
| B-9 sealed reconciliation | CLOSED-AND-VERIFIED | `b9_reconciliation_construction_is_sealed` |
| B-10 workspace membership | CLOSED-AND-VERIFIED | `b10_the_service_is_a_workspace_member` |

`BlockerStatus` has a third variant, `ClosedNotVerifiedHere`, and
`no_blocker_is_recorded_closed_without_being_verified_here` fails if a blocker
is recorded `ClosedAndVerified` without a test in this crate that re-derives
it. Nothing is currently in that third state — which is the point of having it:
the honest label exists, so recording a closure the crate cannot demonstrate
requires choosing the weaker word rather than lying with the stronger one.

**B-3 remains OPEN and is recorded OPEN.** No part of this skill closes it, and
nothing here should be read as evidence that containment is reachable from a
genuine reconciliation verdict.

## 6. Validation

Full workspace, at the tree this report describes:

```
cargo fmt --all -- --check                                      exit 0
cargo clippy --workspace --all-targets --all-features -- -D warnings   exit 0
cargo test --workspace                                          exit 0
  193 suites · 2138 passed · 0 failed · 6 ignored
```

Baseline before this skill was 2117 passed (`docs/audit/SKILL28_EVIDENCE_REPORT.md`
§6, 190 result blocks). The delta is **+21 passed, +3 suites**, matching the 21
tests added.

Two existing files were modified, both non-semantically:
`src/lib.rs` (two `pub mod` lines and their re-exports) and `src/matrix.rs`
(`fn csv_field` → `pub(crate) fn csv_field`, so the threat generator reuses the
RFC 4180 quoting rather than writing a second one). **No test was changed, and
no crate outside `aip-conformance` was touched at all.**

## 7. Known limitations

1. **Superseded, and replaced by a narrower limitation.** This said the model
   was analytic and no adversary had been run against it. Thirteen attacks have
   since been staged and 83 of the 91 cells executed
   (`THREAT_MODEL_EXECUTION_REPORT.md`). What remains true, and is the honest
   version of the original point: **a staged attack is not an adversary.**
   Every attack was written by the same author as the model, so a move neither
   of them thought of appears in none of the 91 cells.
2. **Superseded.** This said "91 cells, 11 tests", and that 91 cells were not
   91 tests. 83 of them have since been executed; the remaining 8 are named in
   `THREAT_MODEL_EXECUTION_REPORT.md` §§6–7.
3. **Sensor deception is unanswered** (§4.2). This is a real gap, stated rather
   than dressed.
4. **B-3 is open.**
5. **Operator obligations are unenforceable from here.** Key ceremony, trust-root
   distribution and recovery procedure are documented obligations; the
   repository cannot test whether a deployment honours them.
6. **The `NotDetectable` reasons are load-bearing prose.** A test asserts each
   is non-empty; no test asserts each is *correct*. Reasons that cite a
   non-establishment are the strongest, because that citation is checkable.

## 8. What this skill did not change

No production crate was modified. `aip-conformance` is a leaf: nothing in the
workspace depends on it (`tests/no_second_architecture.rs::nothing_in_the_workspace_depends_on_the_conformance_program`),
it holds no key and signs nothing, it mints no identifier, and it defines no
security semantics of its own. NEXORA remains the authoritative verifier; there
is one reconciler; the wire contract is unchanged.
