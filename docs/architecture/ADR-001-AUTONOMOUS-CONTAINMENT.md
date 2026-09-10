# ADR-001 — Autonomous Containment Evidence Boundary

**Status** PROVISIONAL / IMPLEMENTATION-GUIDING
**Date** 2026-09-06
**Branch** `claude/autonomous-accountability-skills-16-30`
**Supersedes** nothing. **Superseded by** nothing.
**Evidence base** `docs/architecture/B3-CONTAINMENT-EVIDENCE-TRACE.md`
(design-only trace) and `docs/audit/SKILL16_EVIDENCE_REPORT.md`.

This ADR records a boundary. It does not authorise production use, and it
does not make the system production-ready. Nothing in it creates a verdict,
relaxes a definition, or grants a capability.

---

## Context

Autonomous containment is the only path in this system that stops a running
process. Skill 16 required the reconciler to be driven end to end into that
path on genuine engine output. It now is
(`aip-containment/tests/engine_to_containment.rs`, 5 tests), and the crossing
terminates in a refusal every time.

The refusal is structural, not a bug. Recording *which* structure, and what
would have to be true to change it, is what this ADR is for.

---

## The current condition, stated plainly

> **Real reconciliation output does not currently reach the
> containment-eligible `Proven` workload-violation state.**

Three independent closures, each sufficient alone, all verified in code and
by executed test:

1. **Strength.** `Proven` is reserved for facts recomputable from held bytes.
   Every workload-violation class rests on observation *content*, which is
   procfs-derived and root-forgeable, so all are capped at `Attested`.
2. **Result class.** The only class the engine draws at `Proven` is
   `SensorIntegrityFailure`, which `contain()` gate 6 names and refuses — an
   accusation about the sensor is not grounds to freeze a workload.
3. **Availability.** A sensor-integrity verdict necessarily carries
   `Unavailable`, which `evaluate` step 4 caps at `Alert` and gate 7 refuses.

This ADR **does not** resolve that by changing `EvidenceStrength`, by
loosening a result class definition, or by widening a containment gate. See
*Decision*.

---

## Decision

### D1. The strength ladder is not the instrument to adjust

`EvidenceStrength` and its `Proven` contract stay exactly as they are.

The contract already admits the evidence class that would legitimately
support a workload violation (see Q13); it is not the constraint. Adjusting a
measuring instrument to obtain a reading is prohibited here, permanently, and
not only in the narrow case that prompted this ADR.

### D2. Containment eligibility is a conjunction, and stays one

A verdict is eligible for autonomous containment only when **every** condition
below holds. No condition may be traded against another, and no policy may
raise a ceiling — policy can only lower.

### D3. The missing piece is an evidence path, not a verdict

Closing the gap requires a new *evidence path* into the reconciler carrying
agent-signed statements, plus explicit completeness semantics. It does not
require a new cryptographic primitive, and it must not be simulated by
constructing a verdict.

### D4. Two decisions remain open and must not be made implicitly

Q15 records them. Neither may be resolved as a side effect of making a test
pass.

---

## The boundary, question by question

### 1. What constitutes a workload-directed violation?

A verdict whose subject is the **autonomous system's own conduct** — it acted
without authority, acted differently from what was authorised, or asserted
something its own signed record contradicts.

Explicitly **not** a workload-directed violation:

- a fault in the *sensor* (`SensorIntegrityFailure` — the subject is the
  observer),
- a gap in *observation* (`ContinuityFailure`, any `Unavailable`),
- an inability to establish anything (`CannotProve`).

Current implementation: `contain.rs:194-205` admits `UnattributedEffect`,
`PhantomClaim`, `IdentityDivergence`, `LineageViolation`. **CODE-PROVEN.**

### 2. Which evidence classes can establish that violation?

Only evidence where **both sides of the contradiction are artifacts the
verifier holds**, so a third party recomputes the contradiction without
trusting any host.

Two shapes satisfy this:

- **(a) Implemented, observer-directed.** Signature or hash-chain arithmetic
  over observer-signed material. Reaches `Proven`. Its subject is the sensor,
  so it is not workload-directed.
- **(b) Not implemented, workload-directed.** *Agent-side cryptographic
  equivocation*: two validly signed, mutually exclusive statements under one
  agent identity and one decision. At most one can be true; the agent's own
  key attests both. Needs no observer, no procfs, no trusted host.

(b) is the evidence class this ADR identifies as the legitimate future path
to a `Proven` workload violation. **DESIGN — not implemented.**

### 3. Which evidence classes cannot establish it?

- **Self-report alone.** AIRI is application-layer provenance. An agent's
  account of itself is not evidence against a third party — except in the
  narrow equivocation case, where the evidence is not the *content* of the
  claim but the *contradiction between two signatures*.
- **Telemetry.** Not independent observation.
- **Observation content.** procfs-derived and root-forgeable → `Attested`
  ceiling. This is the cap that makes `PhantomClaim`, `IdentityDivergence`
  and `UnattributedEffect` containment-ineligible today.
- **Absence.** "We did not observe it" cannot reach `Proven`, because
  completeness of observation is not recomputable from held bytes. A
  root-compromised host suppresses observations before the collector signs.
- **Accumulation.** No quantity of `Attested` evidence sums to `Proven`.
  Pinned by `aip-airi/tests/reconcile_integration.rs::no_amount_of_airi_evidence_reaches_proven`.

### 4. Minimum evidence strength before autonomous containment

`EvidenceStrength::Proven`. Exact, not a floor to be negotiated.
`contain.rs:186-192` matches explicitly, with no ordering and no arithmetic,
so a future rung inserted into the ladder cannot silently qualify.
**CODE-PROVEN.**

### 5. What independent observation is required?

For any verdict resting on observation: a trusted, anchored, `Active`
observer; a signed health statement no older than
`policy.max_health_age_ms`; that observer among those the record cites; and a
contiguous attested batch chain whose coverage recomputes over the window.
**CODE-PROVEN** (`contain.rs` gates 8, 13; `recompute_coverage`).

For a verdict resting purely on held signatures — class (b) in Q2 — the
honest answer is **none is logically required**, and that is exactly the
tension recorded in Q15.2. It must not be resolved by quietly dropping the
requirement.

### 6. What identity and execution binding is required?

- The warrant must name a subject agent (`SubjectUnbound` otherwise).
- The subject must equal the containment target's agent id
  (`SubjectMismatch` otherwise).
- The target must be attributed **live**, through a pidfd, over the full
  `ExecutionBinding` tuple — agent id, pid, pid start ticks, boot id,
  executable content hash. A pid alone can never reach an actuator; the
  function signature does not accept one.

**CODE-PROVEN** (`contain.rs` gates 10-11; `attribution.rs:100`).

Skill 17 note: when `AutonomousSystem` lands, this binding stays a binding to
an **execution instance**, never to a platform, a vehicle, or a system id. A
platform is not a containment subject.

### 7. What happens when observation is unavailable?

The response is capped at `Alert` (`evaluate` step 4) and containment refuses
outright (gate 7, `Refusal::ObservationUnavailable`). Absence never escalates.

This is correct for every verdict that rests on observation, and it is the
tightest of the three closures in the current condition. Whether it should
also bind a verdict that does not rest on observation is **open** — Q15.2.

### 8. What happens when continuity is broken?

`ContinuityFailure` targets the **observer**, capped at `Alert`. A gap in the
record is a fact about the record, not an accusation against the workload. It
never contributes to containment eligibility.

### 9. What happens when evidence is insufficient?

`CannotProve`, at `Heuristic`, capped at `Alert`. It is the engine's default:
absence of evidence is absence of a verdict, not a verdict of absence.

`CannotProve` is **not a failure**, is **not an accusation**, and must never
be escalated by accumulation, by policy, or by a caller's disappointment.

### 10. What operator policy is required for autonomous containment?

All of:

- `WarrantPolicy::autonomous_containment = true` — without it `evaluate`
  lowers `Contain` to `Alert` (step 5);
- `ContainmentPolicy::mode` = `AutonomousEnabled`, or `OperatorEnabled` with
  a matching `OperatorAcknowledgement` for that exact warrant id;
- a warrant signed by an anchored warrant authority, distinct from the
  containment authority (`verify_warrant_distinct`, gate 1);
- an unconsumed warrant id (gate 14) — one warrant, one actuation.

Policy can only lower a ceiling. There is no policy value that raises one.
**CODE-PROVEN.**

### 11. What happens for protected identities and workloads?

A protected subject, decision point or observer caps the response at `Alert`
(`evaluate` step 4) and containment refuses (`Refusal::Protected`, gate 11).
One `ProtectedIdentitySet` model is shared by the warrant and containment
layers — deliberately one, not two, so the two cannot disagree.

### 12. What is the fail-safe behaviour?

**Refuse, and record the refusal.** Every attempt — refused, advisory,
applied, failed, released — produces a signed `ContainmentRecord` under the
containment authority's own key. There is no silent path.

Specifically:
- gates are evaluated in order and return the **first** refusal;
- the actuator is unreachable unless every gate passes;
- actuation failure is recorded as `Failed`, never retried into success;
- an unknown record version is refused, never guessed.

Current state is the fail-safe state operating at full closure. That is not a
malfunction, and this ADR does not treat it as one.

### 13. What evidence path must eventually produce a legitimate Proven workload violation?

```
agent signs statement S1  ─┐
                           ├─ both held by the verifier
agent signs statement S2  ─┘
        │
        ▼
S1 and S2 are mutually exclusive under one (agent_id, decision_id)
        │  recomputable from held bytes — no observer, no procfs, no host trust
        ▼
Proven, workload-directed
```

Primitives that already exist and are **not connected** to the reconciler:

- `ActionAttestation` (`aip-protocol`) — agent-signed over
  `(agent_id, decision_id, kind, description, payload_hash, performed_at)`.
  Rule R18 `REPLAY_SCOPE` already detects reuse across packets, but produces a
  `RuleResult`, not a `Reconciliation`.
- AIRI events (`aip-airi`) — agent-signed, hash-chained per execution. A
  forked chain is an equivocation. `annotate()` is *deliberately* forbidden
  from influencing a verdict, and that constraint is itself under test.

What is genuinely missing:

1. an input to `reconcile_expectation` carrying the agent-signed statement
   set, with its own trust anchoring;
2. **completeness semantics** — the hard half. *Finding* an equivocation
   proves one. *Not* finding one proves nothing and must remain
   `CannotProve`. An implementation that treats "no equivocation found" as
   exoneration would be a worse defect than the gap it closes;
3. a decision on the result class (Q15.1);
4. a decision on the availability cap (Q15.2).

Connecting agent-signed material to a verdict is a change to what AIRI is
allowed to do. It requires its own justification, its own adversarial tests,
and its own gate. It is **not** authorised by this ADR.

### 14. Which parts are CODE-PROVEN now?

- The full gate chain, in order, with first-refusal semantics.
- `Proven`-only strength admission, by explicit match.
- The workload-violation result set, with `SensorIntegrityFailure` refused.
- Unavailable / uncited / protected capping at `Alert`.
- Live pidfd attribution over the full binding tuple.
- Distinct warrant and containment authorities; anchored, signed warrants.
- One-warrant-one-actuation via the replay ledger.
- Signed records for every outcome including refusals.
- The warrant is bound to its record's digest and carries its citations
  verbatim.
- A reconciliation that travelled as bytes is refused
  (`ReconciliationNotEngineProduced`) — verified against a *genuine engine
  verdict*, not a fixture.
- **That actuation is unreachable from engine output.** Asserted as a test
  (`no_verdict_the_engine_draws_reaches_actuation`), so a future change that
  opens the path fails loudly rather than silently.

### 15. Which parts remain NOT_DETERMINABLE or OPEN?

**15.1 — Result class for agent equivocation. NOT_DETERMINABLE.**

Three options, none adopted here:

| Option | For | Against |
|---|---|---|
| Reuse `PhantomClaim` | At least one of two contradictory claims is phantom | Its definition requires signed kernel coverage proving absence. Reuse means **loosening** a definition — prohibited |
| Reuse `LineageViolation` | A chain fork is literally a lineage contradiction, and the class is currently unreachable | Defined as *observed* ancestry. Reuse blurs the self-report / independent-observation boundary |
| One new class | Names an epistemic state no existing class names: not an absence, not a content mismatch, not an observer fault | Adds a result class against the standing rule |

To be decided by the skill implementing the evidence path, against real
inputs. **Preference recorded:** reuse if and only if an existing definition
can be *narrowed* to fit; never if it must be widened.

**15.2 — Whether `Unavailable` should cap a verdict that does not rest on
observation. OPEN, and the more dangerous of the two.**

An equivocation verdict needs no observer, so it would carry
`Unavailable { NoObserver }` and be capped at `Alert` by Q7's rule — a rule
that is correct for every verdict it was written for.

Changing it without a type-level distinction between "unavailable and it
mattered" and "unavailable and irrelevant" would let genuine observation gaps
escalate to containment. **That is a strictly worse failure than the gap B-3
describes.** If this is ever changed, the distinction must be enforced by the
type system, not by a comment.

**15.3 — Whether full closure is the intended end state. OPEN.**

A fail-closed system observed fully closed may be correct. Deciding otherwise
is a product and safety decision with a named owner, not an engineering
cleanup.

**15.4 — Not covered by any evidence here.** The PostgreSQL store was never
compiled or exercised. Live cgroup actuation is exercised only by
`live_freeze.rs` on Linux. No claim in this ADR extends to either.

---

## Consequences

**Accepted.** Autonomous containment is unreachable from genuine
reconciliation output today, and remains so until Q15.1 and Q15.2 are decided
and the Q13 path is built. The system alerts; it does not act. For an
accountability system whose actuation stops running processes, refusing to
act on evidence it cannot recompute is the correct default.

**Enforced.** `no_verdict_the_engine_draws_reaches_actuation` fails if a
future change makes the actuator reachable. That is deliberate: reaching it
must be a decision someone makes and defends, not a side effect.

**Prohibited by this ADR**, permanently and not merely until B-3 closes:

- changing `EvidenceStrength` or the meaning of `Proven` to make a path
  reachable;
- widening a `contain()` gate to admit a class or strength it currently
  refuses;
- constructing a `Reconciliation` outside the engine for any purpose other
  than a test fixture, which the `Provenance` seal already prevents;
- treating "no equivocation found" as evidence of correctness;
- citing this ADR as evidence that containment works.

**Not decided.** Everything in Q15.

---

## Status rationale

**PROVISIONAL / IMPLEMENTATION-GUIDING.** It binds implementation — D1-D4 and
the prohibitions are in force now — while leaving Q15 open. It becomes
ACCEPTED only when Q15.1 and Q15.2 are resolved with code-backed evidence,
and it does not become ACCEPTED by the passage of time or by a later skill
assuming it did.

**This ADR does not make the system production-ready and must not be cited as
though it does.**
