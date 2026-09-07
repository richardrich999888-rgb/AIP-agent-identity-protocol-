# B-3 — Design-only trace: independent observation → actuator

**Status** DESIGN ONLY. No code changed by this document.
**Method** Read the implementation and the executed tests. Every claim below
cites a file and a line range, or an executed test. Nothing is inferred from
prose, a README, or a commit message.

This is the investigation required before any B-3 implementation. Its output
is ADR-001; it is not itself a decision.

---

## 0. The path, as implemented

```
DecisionPoint::authorize_at            aip-authorize
  → ExpectedExecution (DP-signed)
ProcfsProbe → CollectorSigner::attest  aip-observe
  → AttestedBatch, SignedSensorHealth (observer-signed, hash-chained)
reconcile_expectation(ee, evidence, ctx)          aip-reconcile/src/reconcile.rs
  → Reconciliation { result, strength, availability, evidence, provenance }
evaluate(finding, policy, now)                    aip-warrant/src/warrant.rs:181
  → Warrant { response, target, evidence_strength, observation_unavailable }
contain(req, policy, anchors, ledger, actuator …) aip-containment/src/contain.rs:279
  → gates() : aip-containment/src/contain.rs:150-272
  → Actuator::apply                     (cgroup v2 freezer)
```

Executed end to end on engine output by
`aip-standalone/aip-containment/tests/engine_to_containment.rs` (5 tests).

---

## A. Which reconciliation results are currently reachable

From the engine's own test suite (`aip-reconcile/tests/*.rs`), counting
assertions against `reconcile_expectation` / `reconcile_observation` output:

| Result | Reached | Strength observed |
|---|---|---|
| `CannotProve` | yes | `Heuristic` |
| `VerifiedExecution` | yes | `Attested` |
| `SensorIntegrityFailure` | yes | **`Proven`** |
| `PhantomClaim` | yes | `Attested` |
| `IdentityDivergence` | yes | `Attested` |
| `ContinuityFailure` | yes | `Attested` |
| `UnattributedEffect` | yes | `Attested` |
| `LineageViolation` | yes | `Attested` |

`Proven` is assigned at exactly four sites in `reconcile.rs`
(`:1179`, `:1477`, and two in-module tests). Both production sites produce
`SensorIntegrityFailure`. Confirmed against the source, not inferred from the
test names.

`LineageViolation` is documented in `result.rs:47-49` as *"Requires both fork
ends bound; unreachable today."* — the crate says so itself.

## B. Why a Proven workload violation is currently impossible

Three independent closures. Each is sufficient alone; all three hold.

**B.1 — The strength contract.** `result.rs:87-91`:

> `Proven` is reserved for facts a third party can recompute from held bytes
> (signature and chain arithmetic). Anything that depends on the *content* of
> an observation is capped at `Attested`, because content is procfs-derived
> and root-forgeable.

Every workload-violation class is defined in terms of observation *content*:

- `PhantomClaim` — coverage is recomputed from the signed batch chain
  (`recompute_coverage`, `reconcile.rs:1061`), which *is* held-bytes
  arithmetic; but the conclusion "and the action is not in the observed set"
  depends on the observer having actually seen and reported everything. A
  root-compromised host suppresses observations before the collector signs.
  → capped at `Attested`.
- `IdentityDivergence` — the measured instance is content. → `Attested`.
- `UnattributedEffect` — the decision point's "no expectation covers this"
  (`ExpectedSideCoverage::Attested`, `inputs.rs:111-112`) is a signed
  artifact, but the *effect* half is procfs content. A pair is capped by its
  weaker half. → `Attested`.
- `LineageViolation` — unreachable, per the crate.

The cap is therefore not an oversight. It is the strength contract applied
correctly to the evidence these classes rest on.

**B.2 — The result gate.** `contain.rs:194-205` admits only
`UnattributedEffect | PhantomClaim | IdentityDivergence | LineageViolation`
and names `SensorIntegrityFailure` in the refusing arm. The one class the
engine draws at `Proven` is the one class this gate rejects — correctly: an
accusation about the sensor is not grounds to freeze a workload.

**B.3 — The availability cap, and it is the tightest.** A
`SensorIntegrityFailure` means the observer's evidence could not be trusted,
so the record necessarily carries
`ObservationAvailability::Unavailable`. Observed directly:

```
result=SensorIntegrityFailure strength=Proven
availability=Unavailable { reason: NoObserver }
```

`evaluate` step 4 (`warrant.rs:~254`) lowers any unavailable, uncited or
protected finding to `Alert`; `contain()` gate 7 (`contain.rs:206-209`)
refuses `observation_unavailable` outright. So the only verdict strong enough
to clear the strength gate is, by its own nature, a verdict about *missing*
observation.

Observed refusal in the executed test is `ResponseNotContain("Alert")` — gate
3 fires first, before gates 5, 6 and 7 get a chance. All four would refuse.

## C. Which evidence class could legitimately support a Proven workload violation

Apply the contract in B.1 as a requirement rather than a limit. `Proven`
needs **both sides of the contradiction to be artifacts the verifier holds**.
Observer-side integrity failures qualify because the contradiction is
signature-versus-bytes; no trust in content is involved.

There is exactly one shape with that property on the workload side:

> **Agent-side cryptographic equivocation** — two validly signed, mutually
> exclusive statements under one agent identity and one decision.

A verifier holding both signatures recomputes the contradiction with no
observer, no procfs, and no trust in any host. At most one statement can be
true; the agent's key attests both. That is the same epistemic footing as
`ObserverChainBroken`, pointed at the workload instead of the sensor.

Nothing else qualifies. Absence arguments (`PhantomClaim`) cannot reach
`Proven` because completeness of observation is not recomputable. Content
arguments (`IdentityDivergence`, `UnattributedEffect`) cannot, because
content is forgeable by host root.

## D. Does that evidence class already exist, unconnected?

**Partly, in two places, and in neither is it connected to the reconciler.**

1. **`ActionAttestation`** (`aip-protocol/src/evidence_packet.rs:119`) is
   agent-signed over `(agent_id, decision_id, kind, description, payload_hash,
   performed_at)`. Two contradictory attestations under one `decision_id` are
   an equivocation. Rule **R18 `REPLAY_SCOPE`**, added under B-8, already
   detects the reuse case — but it lives in `aip-protocol`'s packet verifier
   and produces a `RuleResult`, not a `Reconciliation`.
2. **AIRI events** (`aip-airi`) are agent-signed and hash-chained per
   execution. A forked chain — two validly signed events at one sequence — is
   an equivocation. `aip-airi` computes `chain_intact`, and `annotate()` is
   *deliberately* forbidden from influencing the verdict; that constraint is
   itself pinned by `aip-airi/tests/reconcile_integration.rs`.

So the primitive exists twice and is connected neither time. Connecting it is
an architectural decision — specifically, a decision to let agent-signed
material influence a verdict — not a defect to be repaired.

## E. Is a genuinely new evidence primitive required?

**No new cryptographic primitive.** Signed statements, canonical encodings and
hash chains all exist and are tested.

**Yes, a new evidence *path*.** `reconcile_expectation` today takes an
`ExpectedExecution` and `ObserverEvidence`. It has no input carrying "the set
of statements this agent signed", so there is nowhere for an equivocation to
enter. That input, its trust anchoring, and its completeness semantics are the
actual work — and completeness is the hard part: *finding* an equivocation
proves one; *not* finding one proves nothing, and must stay `CannotProve`.

## F. Does the strength ladder need extension?

**No — and this is the load-bearing conclusion of the trace.**

The `Proven` contract already admits agent-side equivocation without any
change: a contradiction between two held signatures is precisely "a fact a
third party can recompute from held bytes". The ladder is correct as written.

Any change to `EvidenceStrength` — adding a rung, or relaxing what `Proven`
means — would be changing the measuring instrument to obtain a reading. It is
explicitly out of scope, now and later.

## G. Would this require new epistemic result classes?

**NOT_DETERMINABLE from the trace alone.** Recorded as an open question with
the options, not decided:

| Option | For | Against |
|---|---|---|
| Reuse `PhantomClaim` | At least one of two contradictory claims *is* phantom; the shape matches | Its definition requires signed kernel coverage proving absence, which equivocation neither has nor needs. Reusing it means **loosening** a definition — prohibited |
| Reuse `LineageViolation` | An AIRI chain fork is literally a lineage contradiction; the class is currently unreachable, so no existing meaning is disturbed | Defined as *"observed ancestry"* — observer-side. Reusing it blurs the self-report / independent-observation boundary, which is a core invariant |
| One new class (e.g. `AgentEquivocation`) | Names exactly one epistemic state that no existing class names; needs no existing definition to move | Adds a result class, and the standing rule is not to |

The rule is *"no new result class unless the evidence semantics genuinely
require one"*. On this trace they may — a self-contradiction under one key is
not an absence, not a content mismatch, and not an observer fault — but that
must be decided by the skill that implements the evidence path, against real
inputs, not here against a hypothetical.

## H. The second decision B-3 hides

Even granted a `Proven` workload equivocation, it would still not reach the
actuator today.

An equivocation needs no observer. Its record would therefore carry
`ObservationAvailability::Unavailable { NoObserver }` — and by B.3 that is
capped at `Alert` and refused by gate 7.

So closing B-3 requires **two** decisions, not one:

1. an agent-side equivocation evidence path (§C–§E), and
2. whether "observation unavailable" should cap a verdict **that does not
   depend on observation at all**.

(2) is subtle and dangerous. The current rule — absence never escalates — is
correct for every verdict that rests on observation. A verdict resting purely
on held signatures is a different kind of object, and the rule was not written
with it in mind. Changing the rule without that distinction being explicit and
enforced in the type system would let genuine observation gaps escalate. That
is a strictly worse failure than the one B-3 describes.

---

## Summary for ADR-001

| Question | Answer | Class |
|---|---|---|
| A. Reachable results | All 8; `Proven` only for `SensorIntegrityFailure` | CODE-PROVEN |
| B. Why no Proven workload violation | Strength contract + result gate + availability cap | CODE-PROVEN |
| C. What could support it | Agent-side cryptographic equivocation | DESIGN |
| D. Does it exist | Primitives yes (`ActionAttestation`+R18, AIRI chain); path no | CODE-PROVEN |
| E. New primitive needed | No. New evidence *path* and completeness semantics: yes | DESIGN |
| F. Ladder extension | **No. Explicitly refused.** | DECIDED |
| G. New result class | NOT_DETERMINABLE — three options, decided later | OPEN |
| H. Availability cap | A second, separate decision; not to be made implicitly | OPEN |
