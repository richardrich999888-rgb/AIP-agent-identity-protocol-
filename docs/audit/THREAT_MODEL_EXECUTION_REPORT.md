# The Threat Model, Executed

**Baseline** `1552e80` · **Branch** `claude/skill-25-implementation-xbz0t3`
**Plan** `docs/architecture/SKILL29_EMPIRICAL_PLAN.md` (written before implementation)
**Artifact** `docs/audit/THREAT_EXECUTION_LOG.{json,csv}` — 91 rows, one per cell
**Amends** `docs/audit/SKILL29_EVIDENCE_REPORT.md` §7.1, which said the model
was analytic and no adversary had been run against it. It has now been run.

---

## 1. The result in one table

| | cells |
|---|---:|
| in the declared model | 91 |
| **executed** — the attack was staged and the layer's response observed | **83** |
| of those, observation agreed with the declaration | **83** |
| of those, observation contradicted the declaration | **0** ¹ |
| **not stageable here** | **8** |
| of those, cells declaring a defence | **1** |

¹ Zero *after* one correction. The first run produced one disagreement and it
was a real defect in the model — see §4.

Thirteen attacks were staged. Each was pushed through all seven layers, so the
83 observations come from 13 adversarial artifacts, not 83 unrelated fixtures.
Every artifact is real: keys are generated, expectations come out of a
`DecisionPoint`, batches out of a `CollectorSigner`, and a forgery is made by
editing signed bytes or by re-signing with the key a real attacker would hold.

```
cargo test --workspace   194 suites · 2148 passed · 0 failed · 6 ignored
cargo fmt --all -- --check                                      exit 0
cargo clippy --workspace --all-targets --all-features -D warnings  exit 0
```

## 2. How an observation becomes a disposition

Execution yields an `Outcome`. Four of the five map to exactly one
`Disposition`; the fifth maps to none.

| observed | corroborates | count |
|---|---|---:|
| `Unrepresentable` — every attempt to construct what the attacker needed produced something else | `Prevented` | 5 |
| `Rejected` — the layer denied the attacker what they were after, by a named mechanism | `Detected` | 32 |
| `Declined` — the layer refused to settle: `CANNOT_PROVE`, or a ceiling below what the attack needed | `Uncertainty` | 11 |
| `Unnoticed` — the layer's output was what it would have been anyway | `NotDetectable` | 35 |
| `NotStageable` | **nothing** | 8 |

The declared model does not grade itself. The executor computes the observed
disposition from what happened and
`empirical.rs::every_executed_cell_agrees_with_the_declared_model` compares the
two.

**What is and is not mechanical.** The outcome→disposition mapping is fixed in
code. Deciding *which outcome an observation is* is not: `Rejected` and
`Unnoticed` are distinguished by whether the layer's output denied the attacker
their goal at that layer, and the goals differ per threat. So the same warrant
response is `Rejected` for X06 — which wanted containment and did not get it —
and `Unnoticed` for X07, whose forgery the reconciler had already named. That
the gate's behaviour is nonetheless determined by the verdict alone is measured
separately, in §5.

## 3. Coverage by layer

| layer | Unrepr. | Rejected | Declined | Unnoticed | not stageable |
|---|--:|--:|--:|--:|--:|
| AIP | 4 | 1 | 1 | 6 | 1 |
| AIRI | 0 | 0 | 4 | 8 | 1 |
| Observation | 0 | 9 | 1 | 2 | 1 |
| Reconciliation | 0 | 7 | 5 | 0 | 1 |
| Warrant | 0 | 3 | 0 | 9 | 1 |
| Containment | 1 | 0 | 0 | 10 | 2 |
| NEXORA | 0 | 12 | 0 | 0 | 1 |

The AIRI row is the shape the architecture predicts and is worth reading twice:
across thirteen staged attacks, AIRI **rejected nothing**. Eight attacks passed
through it unnoticed and four left it declining to settle. That is not a
failure — AIRI is the agent's own account of itself, and every fabricated event
in this run verified as authorship. It is what N-1 says, executed.

The NEXORA row is its opposite: twelve of thirteen attacks were refused, none
merely absorbed.

## 4. Finding 1 — the model understated a defence, and execution found it

The first run produced exactly one disagreement:

```
X01/Warrant: declared NOT-DETECTABLE but execution showed DETECTED
```

The declared cell read *"the warrant gate consumes a verdict and detects
nothing itself"*. The attack — a compromised agent authoring its own
accountability record, serialising it and submitting it — is refused by
`aip_warrant::evaluate` with `Refusal::ReconciliationNotEngineProduced`, before
any response class is computed. That is AUDIT §14's guard, and it is a named
mechanism, not a log.

**Adjudication: the model was wrong, not the run.** The code plainly carries
the defence; the cell failed to credit it. `src/threat.rs` was corrected to
`Detected` with the real mechanism, and the correction is marked in the source
as having come from the executed model. The declared totals moved from
32 `Detected` / 41 `NotDetectable` to **33 / 40**.

This is the single most useful thing the exercise produced. A threat model
that has never been run drifts in both directions, and this one had drifted
toward *understating* a control — the direction nobody audits for, because it
looks conservative.

## 5. The negative control for every "consumes a verdict" cell

Nineteen cells say the Warrant or Containment layer does nothing of its own.
Executing them means showing the layer contributes no threat-specific
discrimination — and showing it without restating the gate's logic, which
would just be a second implementation agreeing with the first.

Every executed threat's real `Reconciliation` was put to `evaluate()` under the
most permissive policy an operator can set, so that whatever stops a response
is structure and not configuration. Each answer was keyed by
`(result, strength, observation_unavailable, cited, protected)` — everything
the engine is supposed to read. **No key produced two different answers.**

The test additionally requires the keys to *collide*: at least two different
threats must reach the same key. A negative control with no collisions proves
nothing, and asserting the collision exists is what stops this check from
passing vacuously.

## 6. Finding 2 — one declared defence could not be reached to be tested

`(Replay, Containment)` declares `Detected`: *"containment consults a replay
ledger before acting, so one warrant cannot actuate twice."* The code does
that. It is gate 14.

Gates 5 and 6 come first, and they require `EvidenceStrength::Proven` together
with a workload-violation result. The engine reaches `Proven` for exactly one
result class, `SensorIntegrityFailure`, which gate 6 names and refuses; every
workload-violation class is capped at `Attested`. The two are jointly
unsatisfiable from engine output, so **gate 14 is never reached**.

Submitting this threat's real warrant twice gives `Refused(ResponseNotContain)`
both times — a refusal about the warrant's class, not a replay detection.
Classifying that as a detection would be exactly the "mitigated because
something happened" failure the model's vocabulary exists to prevent.

Staging the ledger would require fabricating a `Proven` workload-violation
warrant. `aip-containment/tests/engine_to_containment.rs` explicitly refuses to
do that, on the grounds that no such verdict exists outside a fixture, and this
run honours that. The cell is recorded `NotStageable` and counted as **the one
declared defence this run could not verify**.

It is not evidence that the ledger is broken, and it is not a reason to relax a
gate. It is the empirical face of blocker **B-3**, which remains OPEN.

## 7. Finding 3 — the undefended threat is also the unexecutable one

All seven `SensorDeception` cells are `NotStageable`. There is no sensor in
this workspace to deceive and no physical actuator to observe; Skill 25's
physical extension is BLOCKED.

X10 was already the only threat with no defence at any layer. It is now also
the only threat whose attack could not be staged at all. Those two facts
compound, and neither substitutes for the other:

- the model says nothing prevents or detects it, and
- nothing here has tested even that claim by attack.

What *is* executed is the structural reason the cells are true —
`ObservationClass::PhysicalEffect::is_implemented()` is `false`, and no
`SourceMechanism` maps to it. That is asserted in a **separate** test,
deliberately: asserting why a cell is true is not the same as executing the
attack the cell is about, and merging the two would let 7 unexecuted cells read
as covered.

## 8. What was proved about containment

For the X06 attack — root on the observed host — the run swept **every**
`(result, strength)` pair the engine can draw, each under the most permissive
policy, and drove each resulting warrant into `contain()` with a recording
actuator. The actuator was reached **0 times**.

That establishes, by execution rather than by reading, that a warrant which
actuates has no representation reachable from a rooted host. It is a real
defence against X06 and it is the same unreachability B-3 records as a
limitation. **It closes nothing.** B-3 stays OPEN.

## 9. Evidence classes after this run

| class | what moved |
|---|---|
| **EXECUTION-PROVEN** | 83 of 91 cells. Previously 0 — the model was read, not run. |
| **CODE-PROVEN** | unchanged: the exhaustive `answer(t, l)` match, the absent `Mitigated` variant, `is_a_defence()` excluding `Uncertainty`. |
| **TEST-PROVEN** | 31 tests, up from 21: 11 threat, 10 blocker, 10 empirical. |
| **INFERRED** | **8 cells**, down from ~80. Every remaining one is a `NotStageable` cell, each naming why. |
| **UNKNOWN** | whether any disposition holds against a *real* adversary. This run stages attacks; it does not hire one. |

The honest summary of what changed: the model's dispositions are no longer
claims about code read by their author. Eighty-three of them are recordings of
what the code did when attacked.

## 10. What this still does not establish

1. **A staged attack is not an adversary.** Every attack here was written by
   the same author as the model. An attacker who thinks of a move neither
   contains is not represented anywhere in these 91 cells.
2. **Sensor deception is untested and undefended** (§7).
3. **One declared defence is unverifiable by execution** (§6).
4. **B-3 is open.** Nothing in this run closes it, and §8 is not a closure.
5. **The classification of `Rejected` versus `Unnoticed` is goal-relative**
   (§2). It is stated in the source and in the artifact, not hidden, but a
   reader who disagrees with a threat's stated goal will disagree with its
   cell.
6. **No production code was changed.** The only source edit outside the
   conformance crate's own tests is the corrected `src/threat.rs` cell in §4,
   which is a threat-model statement, not a control.
