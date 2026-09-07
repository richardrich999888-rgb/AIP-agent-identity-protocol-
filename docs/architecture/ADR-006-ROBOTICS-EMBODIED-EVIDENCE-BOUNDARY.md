# ADR-006 — Robotics Embodied Evidence Boundary

**Status** ACCEPTED (scope: the robotics profile's evidence semantics only)
**Date** 2026-09-07
**Branch** `claude/codebase-production-readiness-wm6idp`
**Baseline** `2c79363`
**Related** ADR-005 (UAS telemetry evidence boundary — the neighbouring
decision), ADR-003 (observation class boundary — ACCEPTED, unchanged), ADR-004
(effect binding granularity — ACCEPTED, unchanged), ADR-002 (hardware
attestation — **PROPOSED**, unchanged)

---

## Context

ADR-005 settled how a UAS profile treats telemetry: onboard sources are inside
the subject, no avionics sensor has an implemented mechanism, and authenticated
telemetry is not `Attested`.

Robotics inherits all of that and adds a problem the UAS case does not have.
**A robot makes contact.** Between "close the gripper" and "the object is held"
there are five separate physical events, each of which can occur without the
next, and each producing the same signal on the wire: a controller
acknowledgement and an aperture that stopped changing.

There is a second, related problem. Robotics measurements are routinely
reported in language that outruns them, and the gap is where people get hurt:

| measured | commonly said |
|---|---|
| a range sensor returned 1.0 m | safe separation was achieved |
| a proximity field changed | a human is present |
| a joint current spiked | a collision occurred |
| a gripper aperture stopped closing | the object was grasped |
| wheel encoders counted 2.1 m | the robot travelled 2.1 m |

Every left column is a fact about a transducer. Every right column is a claim
about the world requiring a classification, a geometry, or a model of what was
supposed to happen — none of which the measurement contains.

## Decision 1 — eight rungs, not one boundary

The command path is modelled as eight named boundaries, each carrying its
author, whether that author is inside the subject, and what could observe it:

```
autonomous decision · task command · controller command · actuator execution ·
observed actuator state · contact interaction · physical outcome · task success
```

Two are observable in this build, and the profile reports
`unobserved_boundaries_to_outcome() == 5` — because *"we verified the robot"*
and *"we verified two of eight rungs and there are five boundaries before
anything moved"* are the same run described honestly and dishonestly.

Rungs three to five are classified `SelfReported` **even though a different
device authors them.** A motion controller sits on a bus the subject owns; a
compromise that reaches the autonomy stack usually reaches that bus, and a
compromise of the controller needs no help from anyone. This is ADR-005's
autopilot argument, and it matters more here, because a robot's controller
moves a mass through a space people stand in.

## Decision 2 — semantic claims are refused, not derived

`SemanticClaim::establishable_from_measurement()` is `false` for all nine
claims, and it is **computed**: a claim is establishable only if some source
producing a bearing measurement is both outside the subject and backed by an
implemented mechanism. No robot sensor is, so the conjunction is empty. A
future build that implements one makes this return `true` and fails the
module's tests, which is the intended way to find out.

`support_for(measurement, claim)` returns `Bears`, never `Establishes`, for
every pairing people actually use.

`HumanPresent` is called out specifically. **No sensor here detects a human.** A
camera detects light, a lidar detects returns, a proximity sensor detects a
field change; a *classifier* labels one of those "person", and the label is a
model output under conditions nobody characterised. This profile records the
measurement and refuses the label.

## Decision 3 — object state is a third party

`ObjectStateClaim` is separate from the embodied rung, because the rung is
about the robot and the claim is about an object with a mass, a shape and a
position none of the robot's sensors measures. The seven claims form a chain
with two roots — contact starts it, and **nothing bears on `Undamaged` at
all**, which is itself the finding: damage is routinely asserted from a
collision claim that was itself asserted from a strain reading.

## Decision 4 — safety actions get no exemption

An emergency stop is the action most likely to be assumed effective: it is
commanded when something has already gone wrong, its acknowledgement is
immediate, and the alternative to believing it is unattractive. So it is
exactly where an accountability system should be least willing to infer.

`SafetyAction::effect_establishable()` is `false` for all nine responses. A
stop that a controller accepted and a seized brake, a welded contactor or a
stuck valve did not perform produces the same acknowledgement as one that
worked.

## Alternatives rejected

**Add `SourceMechanism` variants for encoders, force sensors and lidar.** The
same move ADR-005 rejected for avionics, for the same reason: `SourceMechanism`
is inside signed bytes every verifier must understand, and adding device
variants forks the accountability schema per vertical. Worse here, because the
honest forgeability note for a wheel encoder would read "forgeable by anyone on
the internal bus, and wrong without any attacker whenever a wheel slips".

**Treat controller telemetry as `Attested`.** It is a different device, which
makes it feel independent. It is not: it is inside the machine being judged, on
a bus the machine controls.

**Derive semantic claims with a confidence score.** A score invites a
threshold, a threshold invites tuning, and the tuned system asserts "human
present" from a field change with a number attached. Refusing the claim is the
only version that stays honest under pressure.

**Resolve conflicting sensors by fusion.** Three onboard sensors agreeing are
one report with three names on it. The failure mode does not even need an
attacker: a robot whose wheels are spinning on a polished floor reports encoder
motion, an odometry integral, and a localisation estimate that has been dragged
along by both. Agreement is counted, never promoted; conflict is reported,
never resolved.

**Model the robot as a single identity.** Six identities are kept apart, and
only the process and the companion boot are independently established. A
controller substitution and a chassis replacement are both undetectable here,
and the profile answers `NotEstablished` rather than reporting continuity —
because software continuity is not physical continuity.

## What this decision does not settle

**It does not make any physical state observable.** It makes the absence
visible and computed. A deployment that anchors an external tracker or a
workspace camera — and supplies a mechanism whose observations reach
`from_attested` — gets different answers from the same code.

**It does not change ADR-002, ADR-003, ADR-004 or ADR-005.**

**It does not touch `EvidenceStrength` or the reconciler.** The profile
produces inputs and classifications; `aip-reconcile` remains the only thing
that assigns a strength or a result, and `aip-robotics` names neither type
anywhere in its code.

**It does not create a robotics enforcement path.** `aip-warrant` and
`aip-containment` remain the only enforcement in the workspace. The `safety`
module produces no warrant, no severity and no action.
