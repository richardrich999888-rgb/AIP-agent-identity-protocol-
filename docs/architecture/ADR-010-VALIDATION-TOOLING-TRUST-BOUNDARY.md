# ADR-010 — The Validation-Tooling Trust Boundary

**Status** ACCEPTED
**Date** 2026-09-07
**Branch** `claude/skill-25-implementation-xbz0t3`
**Baseline** `12767ea` · Skill 25 core at `7ffc37c`
**Related** ADR-003 (observation class boundary — this ADR depends on it and
does not modify it), ADR-008, ADR-009,
`docs/SKILL_25_PHYSICAL_AI_VALIDATION.md`

---

## Context

The Skill 25 validation roadmap requires external robotics, UAS and industrial
tooling: ROS 2, Gazebo, `ros2_control`, Nav2, MoveIt 2, `rosbag2`,
`ros2_tracing`, OpenCV, AprilTag, PX4, MAVLink, MAVSDK, open62541 and 4diac.

Every one is a mature, well-engineered project. That is what makes them
dangerous here. A pipeline with fifteen high-quality instruments in it acquires,
somewhere in the middle, a function that turns a timestamped binary telemetry
stream into an evidence record — and by the time anyone asks where the promotion
happened, the answer is "in the integration glue, two years ago".

The failure mode is not a bad decision. It is the absence of a place where the
decision is made.

## Decision 1 — one gate, and it is a type

All external tooling enters the evidence model through a single crate,
`validation/physical_ai/adapters/vanian-external-adapter`, and through one
function, `admit`. There is no second path, and the crate is structured so that
adding one requires deleting a guard test.

`admit` is a pure function of its inputs: it reads no clock, no configuration
and no environment. `now_ms` and the freshness policy are supplied by the
caller. Every branch is therefore reachable from a test, which is what makes the
mutation results meaningful.

## Decision 2 — provenance is a closed enum, and independence is derived

`ProvenanceClass` has eight members. Every property that matters —
`subject_controls_source`, `is_external_to_subject`, `is_anchored`, `mechanism`,
`max_ceiling`, `can_support_execution`, `can_support_physical_effect`,
`is_trust_anchor` — is a method on it.

`ExternalObservation` has **no settable `independent` field.** The brief's
conceptual interface lists one; implementing it as a boolean an integrator can
assign would allow exactly the sentence this ADR exists to prevent:
`obs.independent = true` on a `/odom` topic. `is_independent()` reads the
provenance class instead, and a guard test counts assignments to make sure no
second decision point appears.

## Decision 3 — the ceiling vocabulary is consumed, never redefined

`EvidenceCeiling` and `SourceMechanism` are `aip-observation`'s and
`aip-observe`'s. The adapter imports them.

This is the one place where a validation crate depending on production crates is
correct rather than suspect: the alternative is an adapter with its own ceiling
type, which is the second evidence hierarchy every ADR from 003 onward exists to
prevent. The dependency points one way — nothing in `aip-*` depends on the
adapter, and the adapter is not a workspace member, so no production build can
reach it.

## Decision 4 — the top rung is unreachable, and it is computed

`Admission::EligibleForObservationRecord` says the production observation path
could be handed an observation. It requires a class that is external to the
subject, anchored, **and** backed by an implemented `SourceMechanism`.

No optical or simulator class has a mechanism, so the rung is unreachable for
every external sensor in this build. That is not written as `false`; it falls
out of `ProvenanceClass::mechanism()` returning `None`. If an optical mechanism
is ever implemented, the rung becomes reachable and the guard tests fail — which
is the intended way to discover that the evidence model changed.

The consequence, stated plainly because it is the finding people most want to
round off: **a real camera, on a separate machine, behind a collector holding its
own key, watching a real robot, reaches `AdmittedAsCorroboration` at
`Corroborative` and stops.** Buying hardware does not reach `from_attested`.

## Decision 5 — three absences, never one

`ObserverPosture` has four states: `Present`, `PresentAndSilent`, `Unavailable`,
`IntegrityUnknown`. The last three are three different refusals with three
different reasons.

This is the `12767ea` observation-integrity finding carried into the physical
layer. A camera that was unplugged, a camera whose view was occluded, and a
camera that returned an empty frame are three different facts, and collapsing
any of them into "nothing happened" turns absence of evidence into evidence of
absence. `silence_establishes_non_occurrence()` returns `false` for all four
postures, including `PresentAndSilent`.

## Decision 6 — no consensus semantics, anywhere

`SourceAgreement::ceiling_after_agreement` returns the base ceiling unchanged,
for any count, and contains no arithmetic. Conflict wins over agreement and is
never resolved by majority, recency, apparent quality or a confidence score.

Three ROS 2 topics agreeing is one node's world model published three times.
Three telemetry streams from one platform is one platform. This mirrors
`aip-uas`, `aip-robotics` and `aip-industrial` exactly, because four components
answering the same question differently would be four accountability models.

## Decision 7 — no external framework is a production dependency

None of the fourteen named tools is a workspace member or a dependency of any
`aip-*` crate. The adapter itself links none of them: it describes them by
string, and a guard test asserts its source contains no `rclcpp`, `rclpy`,
`gz::`, `opencv::`, `mavlink::`, `mavsdk`, `open62541` or `UA_Client`.

Had Skill 25's specification required production integration of any framework,
this ADR would not exist and the requirement would have been reported before any
coupling was written. It does not: the specification names "adapters for
representative edge protocols without hard-coding a protocol as trusted", which
is satisfied inside `aip-industrial` with no framework linked at all.

## Alternatives rejected

**Let each tool's integration decide its own evidence class.** This is the
default outcome of not making a decision, and it is the failure described in the
Context. Fifteen integrations means fifteen places where a promotion can happen
and no place where it is reviewed.

**Give the adapter a `TrustLevel` enum of its own.** Superficially cleaner — the
validation layer would not depend on production crates. It is the second
evidence hierarchy, and the two would diverge within a skill.

**Let `ExternalSensorAnchored` reach `Attested`.** Tempting, because an anchored
external camera genuinely is the best evidence in the table, and `Corroborative`
feels ungenerous. It is wrong: `Attested` means *an anchored observer measured
this through a characterised mechanism*, and there is no characterised optical
mechanism. Granting it would make the ceiling a statement about how much we like
the source rather than about what carries it.

**Add a `SourceMechanism::Camera` variant.** This is the schema fork ADR-003
exists to prevent, and it would be the fourth time it was refused (ADR-005 for
avionics, ADR-006 for encoders, ADR-008 for transmitters). A camera is not a
Linux kernel facility, and putting a device-specific value into signed bytes
every verifier must understand forks the accountability core per instrument.

**Treat Gazebo ground truth as independent evidence.** It is independent of the
simulated robot, which is why the temptation exists. It is not a fact about any
world, and a physical claim from it is refused by name
(`SimulatorGroundTruthOfferedAsPhysical`) rather than silently downgraded, so
the refusal appears in the run output where someone will read it.

**Stub the blocked tools so the pipeline appears complete.** Refused outright. A
fabricated environment produces fabricated telemetry, and telemetry from it is
worse than none, because it invites a claim.

## Migration impact

None. No production crate changes, no workspace member is added, no public API
moves, no wire or signed-field changes. The adapter carries its own
`[workspace]` table, matching the existing convention for `validation/airi/agent`
and the exp01 recorder.

## What this decision does not settle

**Whether an optical mechanism should ever exist.** It would be an
`aip-observation` change under ADR-003's constraints, it is outside Skill 25,
and it is the only route from `Corroborative` to a physical-effect claim. The
question is open and this ADR deliberately does not pre-answer it.

**Whether the eight provenance classes survive contact with a real ROS 2 graph.**
They were derived from the architecture, not from running the tools. The first
real robotics environment is where that gets tested.

**How a partially-trusted collector should be modelled** — one that is a
separate machine but shares an administrator with the subject. Currently it is
`ExternalSensorAnchored` like any other, which is probably too generous and
costs nothing today because the class is capped anyway.
