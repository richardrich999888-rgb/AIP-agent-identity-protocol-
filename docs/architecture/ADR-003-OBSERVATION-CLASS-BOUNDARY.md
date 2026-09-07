# ADR-003 — Observation Class Boundary and the Physical-Effect Ceiling

**Status** ACCEPTED (scope: Skill 20's abstraction only)
**Date** 2026-09-06
**Related** ADR-001 (containment evidence boundary), ADR-002 (hardware
attestation — **remains PROPOSED, untouched by this ADR**)

Two decisions are recorded here because both are architectural, both are
consumed by every later environment profile, and both are easy to get wrong in
a way that would not show up until a vertical profile needed them.

---

## Decision 1 — An observation class layer sits above `SourceMechanism`

### Context

`SourceMechanism` is a closed enum of nine Linux mechanisms — procfs polling,
pidfd-anchored reads, the proc connector, kernel socket tables, three perf
tracepoints, `AF_PACKET` wiretap and fanotify. Each is documented precisely
and each maps to a real kernel facility.

That precision is the problem for reuse. A UAS altimeter, a UGV wheel encoder,
an industrial flow meter and a spacecraft attitude sensor are all observation
sources, and none of them is a Linux mechanism. Representing one would mean
adding a variant to a core-protocol enum that participates in signed bytes —
a schema fork of the accountability core, per environment, which is exactly
what the architecture forbids and exactly what would force the core protocol
to be rewritten for each new deployment.

### Decision

Introduce `ObservationClass`: an environment-neutral layer *above* mechanism.
Every existing `SourceMechanism` maps into a class. A future environment adds
an **implementation of a class**, not a variant of a Linux enum.

`SourceMechanism` is unchanged, keeps its wire codes, and remains the
authoritative statement of *how* an observation was obtained on Linux.
`ObservationClass` states *what kind of thing* was observed, which is the part
a vertical profile reasons about.

### Consequences

- A UAS profile can require `PhysicalEffect` observation and be told, honestly,
  that this deployment cannot provide it — without editing `aip-observe`.
- Two layers must stay consistent. The mechanism→class mapping is total and
  exhaustive over `SourceMechanism::ALL`, asserted by test, so a mechanism
  added later cannot silently lack a class.
- The class layer must not become a second taxonomy that drifts. It carries no
  mechanism detail and no trust decision; it is a grouping with a ceiling.

### Rejected alternatives

- **Extend `SourceMechanism` per environment.** Rejected: it forks the core
  schema per vertical and puts device-specific variants into signed bytes that
  every verifier must understand.
- **A free-form string class.** Rejected: an open vocabulary cannot carry a
  ceiling, and two deployments would spell the same class differently.
- **No class layer; let profiles name mechanisms.** Rejected: it makes every
  vertical profile Linux-shaped, which is the opposite of the goal.

---

## Decision 2 — `PhysicalEffect` is representable, its ceiling is `Attested`, and it has no mechanism

### Context

The system's widest gap is that a physical action — a valve closing, a
waypoint reached, a payload released — has no independent evidence path
(Skill 18's threat model, T15). Skill 20 could have left the class out
entirely, or invented one.

### Decision

Declare the class. Declare its ceiling. Provide **no mechanism**, so it is
unreachable in this build.

The ceiling is `Attested`, **never `Proven`**, and the reason is structural
rather than a limitation of current sensors: a physical sensor's reading is
content read from a device. On the observed host it is root-forgeable exactly
as procfs content is (threat T8). ADR-001's contract reserves `Proven` for
facts recomputable from held bytes; a sensor reading is not one, however good
the sensor.

### Consequences

- A deployment that cannot observe physical effect says so explicitly, and
  that absence is a recorded fact rather than a silent hole.
- **A physical-effect observation, when Skill 21 implements one, still cannot
  reach `Proven`.** Anyone expecting hardware sensing to unlock the top
  evidence class should read this before designing around it.
- The class being present must not be read as the capability being present.
  Declared ≠ implemented, and a test asserts no mechanism maps to it.

### What this ADR explicitly does not do

- It does **not** implement physical-effect observation. Skill 21.
- It does **not** touch ADR-002. Hardware attestation remains PROPOSED, no
  class accepts an attestation as input, and an observer relaying a TPM quote
  is relaying an attestation — the trust-anchor question is unchanged by which
  process carries the bytes.
- It does **not** change `EvidenceStrength`, `precondition_holds`, or any
  reconciliation semantics. The ceiling table is asserted **consistent with**
  the reconciler, not substituted for it.

---

## Prohibited by this ADR

- Raising a class ceiling. A profile may lower one; nothing may raise one.
- Mapping any mechanism to `PhysicalEffect` without an ADR revising this one.
- Declaring a `Proven` ceiling for any class other than `ObserverIntegrity`.
- Accepting attestation-shaped material into an observation class as though it
  were independent observation.
- Citing this ADR as evidence that physical-effect observation exists.
