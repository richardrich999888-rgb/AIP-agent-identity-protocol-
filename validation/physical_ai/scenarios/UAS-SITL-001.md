# UAS-SITL-001

**Status: DESIGNED — NOT EXECUTED. PX4 SITL is unavailable in this environment.**

## Scenario

```
PX4 SITL  +  companion computer  +  signed mission plan  +  Vanian observation
```

1. A mission plan is written and its digest committed into `ActionParameters`.
2. A decision point signs an `ExpectedExecution` over that parameter digest.
3. The companion computer's autonomy process issues mission commands over
   MAVLink to PX4 SITL.
4. An anchored observer on the companion computer measures the process and its
   sockets.
5. PX4 reports mission progress and completion.
6. The reconciler compares.

## What must be verified

| # | check | mechanism |
|---|---|---|
| 1 | the task digest reaches `ExpectedExecution.parameter_digest` | `aip-authorize`, already implemented |
| 2 | the execution identity is the companion process that was authorized | `aip-observe` pidfd anchor, already implemented |
| 3 | mission/action sequencing matches the signed plan | reconciler |
| 4 | **no physical flight effect is claimed** | `aip-uas` profile; `PhysicalEffect` has no mechanism |

Checks 1–3 reuse mechanisms that already exist and are tested. Check 4 is the
one this experiment exists to demonstrate under a running autopilot.

## Evidence classification, fixed in advance

| source | class | ceiling |
|---|---|---|
| PX4 telemetry | `SubjectSelfReport` | `Corroborative` |
| MAVLink stream | `SubjectSelfReport` | `Corroborative` |
| MAVSDK client state | `SubjectSelfReport` | `Corroborative` |
| Gazebo/jMAVSim truth | `SimulatorGroundTruth` | `Corroborative`, refused for physical claims |
| companion process/socket observation | `HostRuntimeObservation` | `Attested` |

**Command sent ≠ command accepted ≠ flight-controller execution ≠ aircraft state
≠ physical outcome.** The experiment must produce a distinct record for each of
the first four and no record at all for the fifth.

## Safety

**ARM = DISABLED. TAKEOFF = DISABLED. MISSION EXECUTION = DISABLED.**

SITL only. No hardware in the loop, no vehicle, no arming authority. Nothing in
this tree may enable any of the three without an explicit, separately authorized
physical test with a safety case. See `../uas/hitl/README.md`.

## Blockers

- PX4 SITL: `github.com/PX4/PX4-Autopilot` returns HTTP 403 through this
  environment's egress policy; the build toolchain is apt and `packages.ros.org`
  and `deb.debian.org` are also denied.
- Gazebo: same channel.
- MAVSDK: same channel. `pymavlink` **is** installed and would serve for
  protocol instrumentation, but it has nothing to talk to.
