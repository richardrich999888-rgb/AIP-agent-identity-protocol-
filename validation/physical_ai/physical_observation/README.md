# Physical observation — the one layer that runs, and what it does not prove

## What is here

`collector/observe_fiducial.py` — an external fiducial observer built on OpenCV
5.0.0 and the AprilTag **36h11** family, via OpenCV's own dictionary. It
detects tags, computes displacement, and emits `ExternalObservation` records for
the admission adapter.

It is the only physical-observation instrument that runs in this environment,
and it runs **without a camera**, which is the whole caveat.

## The topology it is built for

The robot's own camera is **not** the independent observer. A picture taken by
the robot, of the robot's workspace, delivered through the robot's software, is
the robot's account of its surroundings. The observer must be a different sensor
on a different machine.

```
ROBOT ──onboard telemetry──► self-report
  │
  X  trust boundary
  │
EXTERNAL CAMERA ─► OpenCV/AprilTag ─► EXTERNAL COLLECTOR (own key) ─► adapter
```

## The three modes, and their honest labels

| invocation | provenance class | what it establishes |
|---|---|---|
| `--source synthetic` | `SimulatorGroundTruth` | that the pipeline works. Nothing about any world. |
| `--source camera` | `ExternalSensorUnanchored` | that *someone* measured something; the verifier cannot name them |
| `--source camera --anchored-collector` | `ExternalSensorAnchored` | the strongest available, and still `Corroborative` |

`--anchored-collector` is an **operator assertion** that the collector is a
separate machine holding its own key. The script cannot check that and does not
pretend to; it records the assertion in the manifest and says it was not
verified. Passing it for a synthetic scene is refused outright — there is no
camera and nothing outside the subject to anchor.

## Why fiducials first

They give a deterministic reference without SLAM. The first quantities worth
attempting, in order of difficulty: robot position, displacement, zone entry,
pose, object position, gripper position.

## What even a perfect run does not reach

`ProvenanceClass::mechanism()` returns `None` for every external sensor class,
because a camera is not a Linux kernel facility and adding a `SourceMechanism`
variant for one would put a device-specific value into signed bytes every
verifier must understand — the schema fork ADR-003 exists to prevent.

So an anchored external camera on a separate machine, observing a real robot,
reaches `AdmittedAsCorroboration` at `Corroborative` and stops. It does **not**
reach `from_attested`, and it does not support a physical-effect claim. This is
asserted in
`tests/trace_replay.rs::the_counterfactual_anchored_camera_reaches_corroboration_and_stops`.

Closing that gap is an `aip-observation` change and is outside Skill 25.

## Calibration and attachment, both unperformed

- `--mm-per-px` is a **declared** scale. No calibration is performed, and the
  manifest records `calibration_performed: false`.
- A fiducial binds to a *marker*. That the marker is on the subject is an
  assumption; `SubjectIdentity::is_measured_binding()` returns `false` for every
  variant, and the manifest records `marker_attachment_verified: false`.

Both are real gaps in any physical claim and both are recorded rather than
assumed away.
