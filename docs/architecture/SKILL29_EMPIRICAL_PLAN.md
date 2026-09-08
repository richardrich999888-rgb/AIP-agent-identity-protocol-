# Skill 29 (continued) — Making the Threat Model Empirical

**Baseline** `1552e80` · **Branch** `claude/skill-25-implementation-xbz0t3`
**Supersedes nothing.** `SKILL29_PLAN_AND_INVARIANTS.md` planned the model;
this plans its falsification.

---

## 1. The defect being fixed

`docs/audit/SKILL29_EVIDENCE_REPORT.md` §7.1 states it plainly:

> The model is analytic, not empirical. No adversary was run against it.
> Every disposition is a claim about code, verified against code — not
> against an attacker.

91 cells rested on reading the layers. Reading is how the cells were *written*;
it is not evidence that they are *true*. A threat model whose dispositions have
never been executed is a document, not a control.

## 2. What "empirical" has to mean here

Not "more tests". Three specific properties:

**P1 — The attack is staged, not described.** Each threat is staged once as
real adversarial artifacts built with real keys through the production
constructors: a forged batch is signed, a diverged instance is a genuinely
different `ObservedProcess`, a replay is the same bytes submitted twice.

**P2 — One attack, seven observations.** The same staged artifact is pushed
through all seven layers. Thirteen stagings produce ninety-one observations.
This is stronger than 91 independent micro-tests, because every layer's
disposition is measured against *the same* adversarial object.

**P3 — Negative controls are mandatory.** A model that only executes its
defences is confirmation bias. Every `NotDetectable` cell must be executed too,
and must be observed to do nothing. That is what separates an honest boundary
from an untested assumption.

## 3. The classification rule

Execution yields an `Outcome`. Exactly one `Outcome` corroborates each
`Disposition`, fixed in code, with no judgement at classification time:

| observed `Outcome` | corroborates |
|---|---|
| `Unrepresentable` — the adversarial value has no representation; every attempt to construct it yields something that is not the one the attacker needed | `Prevented` |
| `Rejected` — the layer accepted the input and named a fault, refusal or verdict about it | `Detected` |
| `Declined` — the layer refused to settle: `CANNOT_PROVE`, or a ceiling below what the attack needed | `Uncertainty` |
| `Unnoticed` — the layer processed it and produced no adverse signal | `NotDetectable` |
| `NotStageable` — could not be staged here, with the reason | **nothing** |

**The falsifier.** For every executed cell, `corroborates(observed)` must equal
the *declared* disposition in `src/threat.rs`. A disagreement fails the suite.
The declared model does not get to grade itself: the executor computes an
observed disposition from what happened, and the two are compared.

`NotStageable` is never promoted, never counted as agreement, and is reported
as its own number. Missing evidence does not become success — the same rule the
reconciler applies to `CANNOT_PROVE`.

## 4. Where the code lives, and why it is split

`tests/no_second_architecture.rs::the_program_holds_no_key_and_signs_nothing`
forbids `generate_ed25519_keypair`, `sign_ed25519`, `private_key` and
`CollectorSigner` in this crate's **library** sources. Staging real attacks
requires all four.

That guard is right and is not being weakened. A conformance library that could
sign could manufacture the evidence it reports on. So:

- `src/empirical.rs` — **vocabulary only.** `Outcome`, the classification rule,
  `ExecutedCell`, `ExecutionLog`, its counts and its serialisation. Holds no
  key, signs nothing, mints nothing, and states no security semantics. Passes
  all three structural guards unchanged.
- `tests/staging/mod.rs` — the fixture builders. Real keys, real signatures.
- `tests/empirical.rs` — the thirteen attacks and the falsifier.

Consequence: the execution log is emitted **by a test**, not by a binary. That
is the honest shape — the artifact is the record of a run, so it should be
produced by running.

`aip-containment` is added to `[dev-dependencies]` (not `[dependencies]`): the
threat model grades Containment as one of its seven layers, and a model that
cannot call the layer it grades cannot be empirical about it. The library's
dependency surface is unchanged.

## 5. Determinism

The log must be byte-identical across runs, so no evidence string may contain a
key, a digest, a random id or a wall-clock time. Evidence records the *outcome*
in stable terms — `"reconcile_expectation -> IDENTITY_DIVERGENCE @ Attested
(IdentityDiverged)"` — which is the load-bearing content anyway. A test runs the
whole execution twice and compares.

## 6. The staging, per threat

| threat | staged as | notes |
|---|---|---|
| X01 CompromisedAgent | an agent claiming an execution it did not perform, and claiming another identity | reconciles to `PHANTOM_CLAIM` under kernel-pushed coverage |
| X02 CompromisedFramework | a framework asserting authority it was not granted | `framework_grants_authority()` is non-overridable |
| X03 CompromisedModelRuntime | a declared model identity with no observing mechanism | N-3/N-4/N-5 |
| X04 CompromisedTool | a tool returning success for an effect that did not land | local half observable, remote half not (N-2) |
| X05 CompromisedProcess | an observation of a different `exe_content_sha256` under the same decision | `IDENTITY_DIVERGENCE` |
| X06 CompromisedHost | root-forgeable procfs content driven to the actuator | `Attested` ceiling; containment unreachable |
| X07 ForgedTelemetry | observer bytes altered after signing, and re-signed with the collector key | `SENSOR_INTEGRITY_FAILURE @ Proven` |
| X08 LostConnectivity | evidence that has not arrived yet | delay must never read as non-occurrence |
| X09 PartialObservation | a withheld tail batch and a counted drop | the gap must be named, not absorbed |
| X10 SensorDeception | a physical quantity no mechanism observes | expected to be largely `NotStageable` — see §8 |
| X11 ObserverFailure | a single-batch epoch, a probe restart, and a fork at one sequence | `CONTINUITY_FAILURE`, `SENSOR_INTEGRITY_FAILURE` |
| X12 Replay | the same signed artifacts submitted twice at every layer that holds a ledger | observer, reconciler, containment, NEXORA |
| X13 StaleAuthority | a token whose expiry has passed at the verifier's present time | `StaleSince` |

## 7. The Warrant and Containment negative controls

Most `(threat, Warrant)` and `(threat, Containment)` cells say "consumes a
verdict" / "acts on a warrant". Executing them means showing the layer
contributes **no threat-specific discrimination**.

The experiment restates none of the gate's logic. Every executed threat's real
`Reconciliation` is fed to `evaluate()`. Across the whole executed set, the
observed `(response, target)` is keyed by
`(result, strength, observation_unavailable, cited, protected)`. If any key maps
to two different answers, some threat-specific rule exists and the
`NotDetectable` cells are wrong. If no key does, the gate is a function of the
verdict — which is exactly what those cells claim.

## 8. What will not become empirical, and why that is the finding

X10 SensorDeception is deception of the physical world. There is no sensor in
this workspace to deceive, and Skill 25's physical extension is BLOCKED. Its
cells are expected to divide into:

- executable, because the claim is about *absence of a mechanism* — the
  physical-effect observation class reports `is_implemented() == false`, and no
  reconciliation path reaches the top tier; and
- `NotStageable`, because the attack itself needs hardware.

**Neither is a defence.** This must not be reported as coverage. Whatever the
split, X10 remains the threat answered by no defence anywhere, and the count of
`NotStageable` cells is reported as its own number in the evidence report.

## 9. Prohibitions honoured

No production crate is modified. NEXORA remains the authoritative verifier.
There is one reconciler. No wire constant changes. No mutation weakens
`CANNOT_PROVE` or an evidence ceiling. B-3 stays OPEN — the X06 containment
observation records that actuation is unreachable from a root-forged verdict,
which is a defence against X06 *and* the same unreachability B-3 records as a
limitation; it closes nothing.

## 10. Acceptance for this piece of work

1. Every executed cell's observed disposition equals its declared disposition.
2. Every `NotStageable` cell carries a reason and is counted separately.
3. The log is deterministic and the committed artifact is current.
4. `cargo fmt`, `cargo clippy -D warnings`, `cargo test --workspace` all clean.
5. The evidence report's §7.1 limitation is rewritten to the measured truth --
   not deleted, and not overstated.
