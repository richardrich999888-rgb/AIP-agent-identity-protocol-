# `validation/` — external instruments, kept outside the trust boundary

This tree holds **reference instruments and experiment scaffolding**. It is not
part of Vanian. Nothing here is compiled into the workspace, nothing here is a
dependency of any crate, and nothing here may become an input to a
Reconciliation, a NEXORA proof, an `EvidenceCeiling`, or a warrant decision.

The separation is deliberate and it is the point of the exercise:

> **The actor should not control the evidence used to judge the actor.**

Vanian is the actor under test. So is every tool in here, from the other
direction: an external instrument that Vanian *consumed* would become part of
Vanian, and the comparison it exists to make would stop being a comparison.

## What lives where

| Directory | Contents |
|---|---|
| `external/` | Third-party instruments: provenance, licence, build recipe, and the assessment that decided whether to install them. |
| `robotics/` | Robotics/autonomy instruments (ROS 2, Gazebo, rosbag2, PX4, MAVLink) and the record of why they are or are not present. |
| `linux/` | Host-runtime reference observers that need no installation. |
| `scenarios/` | Experiment definitions, the independence matrix and the phased test plan. |
| `traces/` | Recorded evidence from experiment runs. Gitignored. |
| `replay/` | Deterministic re-derivations from `traces/`. Gitignored. |
| `reports/` | Per-run comparison output. Gitignored. |

`traces/`, `replay/` and `reports/` are outputs. If a file in one of them ever
becomes an input to a decision in `aip-*`, that is a defect, not a feature.

## Safety posture — read before running anything

Every instrument in this tree defaults to **observe, record, replay, analyse**.

Nothing here may, by default:

- command a robot,
- move an actuator,
- arm a UAS,
- send a MAVLink control or parameter message,
- alter a flight-safety configuration.

Instruments that *can* do those things are recorded in `robotics/` with that
capability named, and are **not installed**. Enabling one is a deliberate,
separate, human decision — not a side effect of running a preflight script.

**No real vehicle is to be armed or moved by anything in this tree.**
Simulation and SITL first, always.

## What installing a tool does and does not establish

Installing an instrument proves that the instrument installed.

It does not prove that Vanian observed anything, that an observation was
independent, or that a claim was validated. The ladder is in
`scenarios/TEST_PLAN.md` and the current rung is stated in
`../docs/VANIAN_REAL_WORLD_VALIDATION_TOOLING.md`. Do not skip rungs and do
not describe a rung you are standing below.

## Running the preflight

```sh
./validation/preflight.sh
```

It reports `READY`, `PARTIAL` or `BLOCKED` per instrument, prints the reason
for anything that is not `READY`, and never installs, downloads or configures
anything. It is a report, not a setup step.

## AIRI validation (added by AIRI-INDEPENDENT-OBSERVATION-001)

`airi/` holds AIRI-specific findings; `external/{a3s_observer,obi,otel,langfuse}/`
hold per-tool status with the exact commands executed and their observed
output; `scenarios/airi_independent_observation_001/` is the experiment.

The report is `../docs/AIRI_REAL_WORLD_VALIDATION.md`.

A **second, independently built AIRI experiment** also lives here:
`airi/run_airi_validation.sh` with `airi/analyze.py`, `airi/observers/`,
`airi/mutate.py`, its matrix at
`airi/AIRI_INDEPENDENT_OBSERVATION_MATRIX.csv`, its committed run set under
`traces/airi-final/`, and its report at
`../docs/AIRI_INDEPENDENT_OBSERVATION_REPORT.md`. `airi/README.md` compares the
two. It uses the Linux audit subsystem as a mechanism-independent observer,
which `linux/INDEPENDENCE.md` had concluded did not exist here — that document
surveyed tracing facilities, and audit is not one. See
`airi/OBSERVER_INDEPENDENCE.md`.

**Read `external/a3s_observer/TRACEPOINT_INTERFERENCE.md` before running two
kernel observers at once.** Running A3S Observer alongside Sniffer Dog 2.0
silently blinds Sniffer Dog's perf tracepoint sensors — zero events, zero
reported loss — because a BPF program attached to a tracepoint gates that
tracepoint's perf submission host-wide. It is the most consequential finding
in this tree.
