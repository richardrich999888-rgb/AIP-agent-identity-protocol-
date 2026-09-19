# Skill 25 — Physical-AI validation tooling

**Status** VALIDATION TOOLING — PHYSICAL ACCOUNTABILITY UNVALIDATED
**Date** 2026-09-07
**Branch** `claude/skill-25-implementation-xbz0t3`
**Baseline** `12767ea` · Skill 25 core at `7ffc37c`
**Related** ADR-010 (validation-tooling trust boundary), ADR-008, ADR-009,
`validation/physical_ai/README.md`, `validation/robotics/STATUS.md`,
`validation/scenarios/TEST_PLAN.md`

---

## 1. What this document is

Skill 25's accountability profile — `aip-industrial` — was implemented at
`add8c91` and is documented in `INDUSTRIAL_CRITICAL_EDGE_PROFILE.md`. This
document covers the **validation tooling** added beside it: the environment,
adapters, scenarios and instruments that would let the profile be exercised
against real robotics, UAS and industrial stacks.

The two are deliberately separate commits and separate documents. The profile is
production code. Nothing here is.

## 2. The claim this tooling protects

> **The actor must not control the evidence used to judge the actor.**

ROS 2, Gazebo, `ros2_control`, Nav2, MoveIt 2, `rosbag2`, `ros2_tracing`,
OpenCV, AprilTag, PX4, MAVLink, MAVSDK, open62541 and 4diac are **test subjects,
environments, telemetry sources and reference observers**. None is a trust
anchor. None is automatically independent proof.

The danger in adding them is not that anyone would deliberately declare a
`/odom` topic to be independent evidence. It is that a pipeline with fifteen
tools in it acquires, somewhere in the middle, a function that turns a
high-rate, timestamped, binary telemetry stream into an evidence record — and
nobody can point at the line where the promotion happened.

So the tooling has exactly one entry point into the evidence model, and that
entry point is a gate.

## 3. Tooling architecture

```
  external tool          adapter                          production core
  ─────────────          ───────                          ───────────────
  ROS 2 topic       ┐
  rosbag2           │
  ros2_tracing      │    RAW          RawCapture
  controller ack    ├──► NORMALIZED   ExternalObservation ──► (nothing)
  Gazebo truth      │    CLASSIFY     Admission
  PX4 / MAVLink     │                     │
  OPC UA / PLC      ┘                     ├─ Refused              ─► nothing
  external camera   ──────────────────────┼─ AdmittedAsClaim      ─► a claim
  AprilTag          ──────────────────────┼─ AdmittedAsCorrob.    ─► corroboration
  anchored collector ─────────────────────┴─ EligibleForObsRecord ─► aip-observation
                                                (unreachable in this build)
```

Three layers, kept apart on purpose. `RawCapture` holds the bytes the tool
emitted and a digest taken at capture; `ExternalObservation` is derived from it
and does not replace it; `Admission` is derived from that. Each layer can be
checked against the one below, and the stored artefact is the raw bytes, so a
classification can be re-derived offline months later. `tests/trace_replay.rs`
does exactly that against a checked-in trace.

**The adapter constructs no `ObservationRecord`.** It cannot: that needs an
attested batch from a collector holding its own key, and the adapter holds no
key. Its strongest verdict says the production path *could* be handed this
observation — and that rung is unreachable for every optical and simulator
source, computed rather than asserted.

## 4. The independence model

`ProvenanceClass` has eight members and every derived property is computed from
them. `EVIDENCE_INDEPENDENCE_MATRIX.csv` is **generated from this code** by the
`emit-matrix` binary, so the matrix cannot drift from the rules it documents.

| class | subject controls it? | anchored? | mechanism | ceiling |
|---|---|---|---|---|
| `SubjectSelfReport` | yes | no | none | `Corroborative` |
| `SubjectControlledRecording` | yes | no | none | `Corroborative` |
| `ControllerAcknowledgement` | yes | no | none | `Corroborative` |
| `SubjectMiddlewareInstrumentation` | yes | no | none | `Corroborative` |
| `SimulatorGroundTruth` | no | no | none | `Corroborative` |
| `ExternalSensorUnanchored` | no | no | none | `Corroborative` |
| `ExternalSensorAnchored` | no | **yes** | none | `Corroborative` |
| `HostRuntimeObservation` | no | **yes** | `PidFdAnchored` | `Attested` |

Three rows repay attention.

**`ros2_tracing` is inside the subject.** LTTng trace points are precise and are
emitted by the process whose behaviour is in question. Independent of the
*application logic*, not of the *subject*.

**`SimulatorGroundTruth` is external and still proves nothing physical.** Gazebo's
physics state is genuinely not controlled by the simulated robot. It is also not
a fact about any world, and offering it as a physical claim is refused by name.

**`ExternalSensorAnchored` — the best case — is capped at `Corroborative`.** A
real camera, on a separate machine, behind a collector with its own key, watching
a real robot, reaches corroboration and stops. Not because of caution: because
`ProvenanceClass::mechanism()` returns `None`, and `ObservationRecord::from_attested`
has no input it could be given. **This is the finding that matters most in this
document.**

## 5. What was executed, and what it establishes

| what | result | class |
|---|---|---|
| adapter suite: 66 tests | pass | TEST-PROVEN |
| adapter mutations: 11 required, 11 applied, 11 killed, 0 survivors | pass | TEST-PROVEN |
| `observe_fiducial.py --source synthetic` — real OpenCV/AprilTag detector over a rendered scene | detected 400 px, as rendered | TOOLING-EXECUTION-PROVEN |
| `admit-trace` over that trace | **REFUSED, every record** | TOOLING-EXECUTION-PROVEN |
| deterministic offline replay of the checked-in trace | reproduces the refusals | TOOLING-EXECUTION-PROVEN |
| `preflight.sh` | STATUS PARTIAL: 8 ready, 2 partial, 18 blocked | EXECUTION-PROVEN |

The synthetic run's result being a **refusal** is the point, not a shortfall. A
rendered scene is not an observation of any world; the detector is real and the
scene is not. The run establishes that the pipeline works end to end and
establishes nothing about any robot.

## 6. What is blocked, and what would unblock it

| tool | status | blocker |
|---|---|---|
| ROS 2, Gazebo, `ros2_control`, Nav2, MoveIt 2, `rosbag2`, `ros2_tracing` | BLOCKED | `packages.ros.org` HTTP 403; Docker daemon unreachable |
| PX4 SITL, MAVSDK | BLOCKED | `github.com` HTTP 403 |
| open62541, 4diac FORTE, ROS-Industrial | BLOCKED | same |
| **any physical observation** | BLOCKED | **no `/dev/video*`. There is no camera.** |
| OpenCV, AprilTag 36h11, NumPy | READY | installed from PyPI |
| `pymavlink`, `asyncua` | READY | installed; nothing to talk to |

An allowlist entry for `packages.ros.org` and `deb.debian.org`, or for the
Docker Hub layer host, or a pre-provisioned ROS 2 + Gazebo image, turns most of
the first three rows into installable in a single pass. **None of them turns the
fourth row into anything.** That one needs hardware.

Nothing is stubbed to make a blocked tool appear present.

## 7. Safety controls

**Default: SIMULATION ONLY.** No physical robot or UAS may be armed or moved by
anything in this tree.

For UAS: **`ARM = DISABLED`, `TAKEOFF = DISABLED`, `MISSION EXECUTION =
DISABLED`.** MAVSDK was deliberately not installed even though its dependencies
resolve, because its surface is vehicle command and adding an armed-vehicle
control surface in exchange for no observational capability is a bad trade.

HITL is a requirements document (`validation/physical_ai/uas/hitl/README.md`),
not a configuration. A configuration checked into a repository can be run by
someone who did not read the warning above it.

## 8. Licence position

`validation/physical_ai/LICENSES.md` records twenty tools with licences read
from each project's own licence file this session. Four rows are marked
**UNVERIFIED** rather than filled from memory.

**No entry is a production dependency.** Three carry real commercial-coupling
risk and all three are validation-only, separate processes, never vendored and
never linked: Nav2's LGPL-2.1 portions, `pymavlink`/`asyncua` under LGPL-3.0,
and open62541's file-level MPL-2.0. The MAVLink generator is (L)GPLv3 with an
explicit MIT exception for generated output — the subtlest of the four and the
one to read before relying on generated headers.

## 9. Evidence classes

**CODE-PROVEN** — the adapter links no external framework, mints no identifier,
holds no key, builds no observation record, defines no verdict or strength
vocabulary and adds no proof tree; ten guard tests assert this over its own
source with comments stripped. `can_support_physical_effect()` is computed from
the class table, not written as `false`.

**TEST-PROVEN** — 66 adapter tests including all seven cases of
ROBOTICS-PHYSICAL-OBSERVATION-001 over constructed observations; 11 mutations
applied with compile confirmation and all killed.

**EXECUTION-PROVEN** — `preflight.sh` against this host. The environment report
is a real measurement of a real machine.

**TOOLING-EXECUTION-PROVEN** — a class introduced here deliberately, because
neither EXECUTION-PROVEN nor TEST-PROVEN describes it honestly. The OpenCV /
AprilTag detector really ran and really measured; the scene was rendered. It
proves the instrument chain and nothing about a world. **It must never be
reported as EXECUTION-PROVEN for a physical quantity.**

**EXTERNAL-CORROBORATED** — nothing. No external instrument has corroborated any
Vanian claim about a physical quantity, because no external physical instrument
has been run.

**DOCUMENTED** — three scenario specifications with their cases, blockers and
acceptance gates; five layer READMEs; the licence registry; ADR-010.

**INFERRED** — that fiducials are the right first quantity; that an anchored
external camera would behave as the counterfactual test predicts; that the
provenance classification of each named tool is correct. The last is the one
worth challenging: it was written from the architecture, not from running the
tools.

**UNKNOWN** — everything about physical accuracy, calibration, marker
attachment, occlusion behaviour, and how any of this degrades on real hardware.
Also whether the eight provenance classes survive contact with a real ROS 2
graph; three verticals suggested they would, and three verticals is not a robot.

## 10. TRL impact

**None.**

Adding validation tooling does not advance a technology readiness level. A
simulator running does not raise physical TRL, and neither does a detector
finding a tag in a picture that a script drew.

The first genuine physical-accountability milestone remains, unchanged and
unreached:

> **ONE PHYSICAL QUANTITY + EXTERNAL MECHANISM + VALID OBSERVATION PATH +
> REACHES `from_attested`.**

Two things stand between the repository and it:

1. **Hardware.** A camera, a robot, and a separate machine for the collector.
   Procurement and provisioning.
2. **A `SourceMechanism` that carries an optical observation.** Even with the
   hardware, the best available path stops at `Corroborative`. Closing that is
   an `aip-observation` change constrained by ADR-003, and it is **outside Skill
   25**.

The second is the one that gets missed. Buying a camera does not reach the gate.

## 11. Known gaps

1. **No physical observation has been performed.** No camera exists here.
2. **No robotics runtime is installed**, so the controller boundary the profile
   describes has never been driven by a real controller.
3. **No PX4, so UAS-SITL-001 has never run.** Its verification list is
   unexercised.
4. **No OPC UA server or PLC**, so INDUSTRIAL-ACCOUNTABILITY-001 has never run.
5. **The optical path cannot reach `from_attested` even in principle** in this
   build. This is the structural gap, and it is larger than the hardware one.
6. **Calibration and marker attachment are declared, not measured**, and both
   are recorded as such in every manifest the collector writes.
7. **Four licence rows are unverified** and must be checked before any
   distribution decision rests on them.
8. **The provenance classification of each tool is architectural judgement**,
   not an experimental result.
