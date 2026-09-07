# ADR-005 — UAS Telemetry Evidence Boundary

**Status** ACCEPTED (scope: the UAS profile's evidence semantics only)
**Date** 2026-09-07
**Branch** `claude/codebase-production-readiness-wm6idp`
**Baseline** `7a5cd55`
**Related** ADR-002 (hardware attestation — **PROPOSED**, unchanged by this
decision), ADR-003 (observation class boundary — ACCEPTED, unchanged),
ADR-004 (effect binding granularity — ACCEPTED, unchanged)

---

## Context

Skill 23 specialises the accountability core for uncrewed aerial systems. The
core's observation model requires, for an `ObservationRecord` to exist at all,
an `AttestedBatch` whose observations carry a `SourceMechanism`. That enum is a
closed set of nine Linux kernel facilities, each mapped to a real mechanism and
each characterised for forgeability.

A UAS reports through none of them. Its position comes from a GNSS receiver,
its attitude from an IMU, its height from a barometer, its state from an
autopilot over a serial or CAN bus. `class_of` maps no mechanism to
`ObservationClass::PhysicalEffect`, so even the class that would describe an
aircraft moving has nothing behind it (ADR-003, decision 2).

The decision is what to do about that.

## The problem, stated precisely

Every avionics source shares one property that no amount of engineering
removes at this layer: **it is inside the system being judged.** A compromised
autonomy stack, a compromised autopilot, or an attacker on the vehicle bus can
write any of them. Signing does not help — a signature establishes that the
autopilot said 100 m and that the message is intact, and says nothing about the
aircraft's height. The two facts are routinely conflated, and the conflation is
the failure mode a UAS accountability system exists to prevent.

There is a second, weaker case: sources genuinely outside the aircraft — a
ground radar track, an RTK base station, an independent radio observer. These
are positionally independent and would be real evidence. None is implemented in
this build, and none has an anchored collector.

## The decision

**Represent the boundary in the profile; do not move it.**

1. `TelemetrySource::mechanism()` returns `Some` for exactly two sources — the
   companion computer's process and socket observation — and `None` for the
   other nine. `can_produce_observation_record()` follows from it. A source
   with no mechanism has nothing to hand `from_attested`.

2. Every onboard source is ceilinged at `EvidenceCeiling::Corroborative`, not
   `Attested`. `Attested` means *an anchored observer measured this*, and no
   anchored observer measured anything a subject reported about itself.

3. `NavigationEvidence::establishes()` reads `independently_observed` **alone**.
   `cryptographically_authenticated` is carried, reported, and never on the
   occurrence path.

4. No navigation quantity can reach `EvidenceCeiling::Proven` under any
   declared source set. `Proven` is reserved for facts a third party recomputes
   from bytes it holds; no telemetry is recomputable, only re-checkable for who
   signed it.

5. Mission states that are claims about the aircraft — `Aborted`, `Returning`,
   `Landed`, `Completed` — require a physical observation, which does not
   exist, so they resolve to `Unknown` for every real aircraft.

The consequence, stated plainly and in the profile's own output: **Vanian can
account for the autonomy computer's execution on a UAS. It cannot account for
the airframe's motion.**

## Alternatives rejected

**Add `SourceMechanism` variants for avionics sensors.** The obvious move and
the reason this ADR exists. `SourceMechanism` is inside signed bytes that every
verifier must understand; adding `GnssFix` or `ImuSample` forks the
accountability schema per vertical, which is exactly what ADR-003 established
the class layer to prevent. It would also be dishonest in a specific way: the
existing nine variants each carry a characterised forgeability, and a GNSS
variant would carry "forgeable by anyone with an antenna and anyone on the bus",
which is not a mechanism so much as a warning.

**Treat authenticated telemetry as `Attested`.** Attractive, common in the
industry, and wrong. It reads a property of a signature as a property of the
world. A UAS whose autonomy stack is compromised emits perfectly authenticated
telemetry describing a flight it is not making, and a system that accepts this
mapping believes it — with a green tick.

**Introduce a `UasObservationRecord`.** A second observation type with its own
constructor and its own trust rules is a second observation architecture, and
the second one is always the one without the adversarial suite behind it. The
brief forbids it and the forbidding is correct.

**Resolve conflicting sensors by fusion.** Three onboard sensors agreeing are
one report with three names on it; they share a trust boundary and an attacker
who owns the bus owns all three. A consensus rule would turn a fusion filter
into an amplifier for whoever owns the bus. Agreement is counted and never
promoted; conflict is reported and never resolved.

**Wait for hardware attestation.** ADR-002 remains PROPOSED, and nothing here
depends on it moving. A TPM on the companion computer would raise what can be
said about *the companion computer*; it would say nothing about the airframe,
so it is not the missing piece for the questions this profile leaves open.

## What this decision does not settle

**It does not make aircraft state observable.** It makes the absence visible
and computed. A deployment that anchors a ground tracker, a range-safety radar
or an independent navigation receiver — and supplies a mechanism whose
observations reach `from_attested` — gets different answers from the same code,
because every determination in the profile is derived from the declared source
set rather than written as a literal.

**It does not change ADR-002, ADR-003 or ADR-004.** No hardware mechanism is
introduced, `PhysicalEffect` remains representable with nothing behind it, and
effect binding granularity is untouched.

**It does not touch `EvidenceStrength` or the reconciler.** The profile
produces inputs and classifications. `aip-reconcile` remains the only thing
that assigns a strength or a result, and `aip-uas` names neither type anywhere
in its code.

**It does not claim the reference is a flight test.** The live validation runs
the Skill 22 three-process reference and reads it as a companion computer,
which is honest about the companion computer and silent about aircraft — which
is the whole point.
