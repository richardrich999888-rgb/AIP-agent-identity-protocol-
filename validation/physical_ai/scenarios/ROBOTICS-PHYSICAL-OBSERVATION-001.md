# ROBOTICS-PHYSICAL-OBSERVATION-001

**Status: DESIGNED — PARTIALLY EXECUTED (decision procedure only). The physical
observation has NOT been performed.**

## What this experiment is for

It is the pivotal milestone. Every other validation in this repository observes
software with software. This one is the first that would put a sensor outside
the subject and measure something in the world.

## Topology

```
                        ROBOT (subject)
                          │
                onboard telemetry ─────────────► self-report, Corroborative
                controller ack    ─────────────► self-report, Corroborative
                          │
                          X   ← the trust boundary
                          │
                   PHYSICAL SPACE
                          │
                          ▼
                  EXTERNAL CAMERA          ← must be a different machine
                          │
                  OpenCV / AprilTag 36h11
                          │
                  EXTERNAL COLLECTOR       ← holds its own key
                          │
                          ▼
                  ExternalObservation      ← normalize
                          │
                          ▼
                  admission gate           ← classify
                          │
                          ▼
                  Vanian core              ← only if EligibleForObservationRecord
```

## Cases

| case | setup | expected admission | expected physical claim |
|---|---|---|---|
| A | normal movement, all three sources agree | telemetry CLAIM, ack CLAIM, camera CORROBORATION | none |
| B | command rejected by the controller | ack CLAIM | none |
| C | command accepted, nothing moved | all admitted; camera **disagrees** | none; the conflict stands |
| D | movement with no expected command | camera CORROBORATION | none |
| E | stale telemetry | REFUSED (`Stale`) | none |
| F | observer unavailable | REFUSED (`ObserverUnavailable`) | none |
| G | external observer disagrees with N onboard sources | conflict, unresolved for every N | none |

Case C is the one the experiment exists for. Case G is the one that keeps it
honest: **no number of agreeing onboard sources resolves a disagreement with one
external observation.**

## What has actually been run

`adapters/vanian-external-adapter/tests/scenario_robotics_001.rs` — nine tests
driving all seven cases through the real admission gate over constructed
observations. **TEST-PROVEN.** No robot, no camera.

`physical_observation/collector/observe_fiducial.py --source synthetic` — the
real OpenCV/AprilTag detector over a rendered scene, producing the trace in
`../traces/ROBOTICS-PHYSICAL-OBSERVATION-001-synthetic-seed1/`. The detector
measured 400 px of rendered displacement. The adapter **refused every record**
as a physical claim, because a rendered scene is not an observation of any
world. **TOOLING-EXECUTION-PROVEN.** That refusal is the correct result.

## What has not been run, and what it needs

The experiment proper. It needs, at minimum:

1. **A camera.** There is no `/dev/video*` in this environment. Nothing
   substitutes for one.
2. **A robot**, real or simulated with a real controller boundary. ROS 2 and
   Gazebo are both blocked here.
3. **A second machine** for the collector. If the collector runs on the robot,
   the actor controls the evidence and the experiment measures nothing.
4. **A calibration** relating pixels to millimetres, performed and recorded.
   The collector currently takes `--mm-per-px` as a *declared* number and says
   so in its manifest.
5. **A marker-attachment check.** A fiducial binds to a marker; that the marker
   is on the robot is an assumption, recorded as `is_measured_binding() == false`.

## The acceptance gate

This experiment passes only when **one physical quantity** is measured by an
**external mechanism**, through a **valid observation path**, and the result
**reaches `from_attested`** in the production observation layer.

It cannot pass today even with a camera and a robot, because no
`SourceMechanism` carries an optical observation — `ProvenanceClass::mechanism()`
returns `None` for every external sensor class. Reaching the gate therefore
requires an `aip-observation` change that is **outside Skill 25**, and which
ADR-003 deliberately constrains.

The honest current ceiling for an anchored external camera is
`AdmittedAsCorroboration` at `Corroborative`, asserted in
`tests/trace_replay.rs::the_counterfactual_anchored_camera_reaches_corroboration_and_stops`.
