# Robotics Autonomy Accountability Profile (Skill 24)

**Status** PROFILE — NOT_PRODUCTION_CAPABILITY
**Date** 2026-09-07
**Baseline** `2c79363`
**Related** ADR-006 (embodied evidence boundary), ADR-007 (vertical
composition), ADR-005 (UAS), ADR-002 (PROPOSED), ADR-003, ADR-004,
`UAS_ACCOUNTABILITY_PROFILE.md`, `LINUX_EDGE_REFERENCE.md`

---

## 1. The one-sentence claim

Vanian can account for a robot's **autonomy runtime execution**. It cannot
account for what the robot's body did, and every claim about motion, contact,
object state or task outcome resolves to `CANNOT_PROVE` unless a deployment
supplies an independent physical mechanism, which this build does not have.

## 2. Why this is harder than the UAS case

An aircraft's honest failure mode is being somewhere other than it says. A
manipulator's is reporting a successful grasp while holding nothing, having
closed on air, having crushed the object, or having grasped the wrong one — and
every one of those produces the same controller acknowledgement and the same
aperture reading.

## 3. The eight rungs

| rung | author | observable here |
|---|---|---|
| autonomous decision | the autonomy stack | **yes** |
| task command | the autonomy stack | **yes** |
| controller command | a controller, on the subject's bus | no |
| actuator execution | a controller | no |
| observed actuator state | a sensor on the robot | no |
| contact interaction | the world | no |
| physical outcome | the world | no |
| task success | a judgement | no |

`EmbodiedChain::unobserved_boundaries_to_outcome() == 5`.

The specific failures each boundary hides: a controller that acknowledges while
in a fault state; a disabled drive, a tripped brake, a blown fuse; a shaft that
turns with a slipped belt or a wheel off the ground; a gripper closed on
nothing at its mechanical limit; an object moved with something else moved
alongside it; everything measured going right and the goal not met.

## 4. Fourteen sensing sources

Two have a mechanism — the companion computer's process and socket observation.
The other twelve do not, so `can_produce_observation_record()` is false for
them: `from_attested` has no input it could be given.

Ten of fourteen are **onboard the subject**, including the onboard camera and
lidar. A picture the robot took, of the robot's workspace, delivered through the
robot's software, is the robot's account of its surroundings.

Every onboard source is capped at `Corroborative`, not `Attested` — `Attested`
means *an anchored observer measured this*, and no anchored observer measured
anything the subject reported about itself. Nothing reaches `Proven`.

`ExternalCamera` and `ExternalTracking` are outside the subject and still
capped, because positional independence without an implemented mechanism is
nobody observing.

## 5. The semantic boundary

| measurement | actually establishes | commonly read as |
|---|---|---|
| range reading | something returned energy on that ray | safe separation achieved |
| proximity field change | the field changed | a human is present |
| contact switch closure | the switch closed | the object was grasped |
| force magnitude | the element was strained | a collision occurred |
| drive current | a drive reported a command | the robot moved |
| shaft angle | the shaft turned | the robot moved |
| gripper aperture | how far apart the fingers are | the object was grasped |
| image frame | light arrived | the object was identified |
| pose estimate | what the estimator computed | the goal was reached |
| integrated odometry | the sum, under an unchecked no-slip assumption | the goal was reached |

All nine semantic claims are unestablishable from measurement, **computed** from
the class table. `support_for` returns `Bears`, never `Establishes`.

**No sensor here detects a human.** A classifier labels a return "person"; the
label is a model output, not a measurement.

**Nothing bears on `DamageOccurred` at all** — damage is asserted from a
collision claim that was itself asserted from a strain reading.

## 6. Six identities

| kind | independently established | across component replacement |
|---|---|---|
| process | **yes** | NotEstablished |
| container | no | NotEstablished |
| controller | no | NotEstablished |
| companion boot | **yes** | NotEstablished |
| platform (chassis) | no | NotEstablished |
| system | no (declared) | Survives |

Only the process and the companion boot are measured, and both are measured
about the *computer*. `Platform` is a verifier assertion keyed on the boot id,
so what is measured is the computer and the chassis is inherited by assertion —
stated here rather than assumed.

**Software continuity is not physical continuity.** A component replacement
leaves the process and the boot untouched; the profile reports
`NotEstablished`, never continuity of the machine. Platform continuity across a
*process* restart is genuine — it is continuity of an assertion keyed on an
unchanged boot — and across a component replacement it is not.

## 7. Task and authority

A `TaskPlan` carries no authority. It commits its digest into `ActionParameters`
under `aip.robotics.task.v1`; a decision point signs that as
`ExpectedExecution.parameter_digest`. **No new authorization engine, no new
signer.** The preimage covers task id, revision, system, platform, window,
workspace and the sorted action set — so a different robot, revision or cell is
a different document. Authorizing `Pick` never implies `Place`.

Cancellation needs no revocation channel: expectations are bounded, so
cancelling is declining to authorize.

## 8. Task state

| tier | states | reachable |
|---|---|---|
| Declared | Planned | yes |
| DecisionSigned | Authorized, AbortRequested | yes |
| ExecutionObserved | Started, Executing, Degraded, Paused | yes |
| **PhysicallyObserved** | **Aborted, Recovering, Completed** | **no** |

`assertable` may only echo or weaken. Self-reported `COMPLETED` resolves to
`Unknown` at every tier, including the top one — because the top tier is itself
unreachable.

## 9. Safety

Not a second enforcement engine: no warrant, no severity, no action.
`aip-warrant` and `aip-containment` remain authoritative.

`effect_establishable()` is false for all nine safety responses. The *request*
is observable for the six that begin as commands; the effect is not. Four are
not authorizable at all — a collision stop, an avoidance manoeuvre, a docking
failure and an operator takeover are things that happen, and authorizing them
would be a category error.

## 10. Corroboration

Three agreeing onboard sensors are one report with three names on it. The
failure mode needs no attacker: a robot whose wheels spin on a polished floor
reports encoder motion, an odometry integral, and a localisation estimate
dragged along by both.

`ceiling_after_agreement` returns the base unchanged for any count. Conflict
wins over agreement and is never resolved by majority, recency, apparent
strength or self-reported confidence — the last worth naming because an
estimator's covariance is an output of its own model.

## 11. Live validation

`aip-robotics/tests/integration.rs` runs the Skill 22 three-process reference
as a robot's companion computer: the workload is the autonomy stack, its TCP
connection is the link to a motion controller, the observer is anchored on the
companion computer. On real kernel evidence the run reaches
`VERIFIED_EXECUTION` — and the profile simultaneously reports every pose
quantity and every object-state claim as unestablished, task `Completed` as
`Unknown`, an emergency stop as commanded-but-not-performed, and physical
effect as unreachable.

The cross-execution injection case is exercised from the start, having learned
in Skill 23 that a profile whose tests only drive the honest scenario is
insensitive to the core guard it rests on.

## 12. Known gaps

1. **No robot sensor evidence path exists** (ADR-006). Closing it needs a
   mechanism whose observations reach `from_attested` — an `aip-observation`
   change, outside Skill 24.
2. **Controller and chassis substitution are undetectable.** Nothing measures
   either.
3. **`ExternalCamera` and `ExternalTracking` are the shortest path to real
   robotics evidence.** Each needs an anchored collector and a mechanism;
   neither exists.
4. **Hardware attestation absent.** ADR-002 PROPOSED. A TPM on the companion
   computer would strengthen claims about the companion computer and say
   nothing about the arm.
5. **The three generic rules are duplicated across two verticals.** Guarded by
   `tests/cross_vertical.rs`; extraction deferred to the third vertical
   (ADR-007).
6. **No robot was involved.** Nothing here has been validated against physical
   hardware.
