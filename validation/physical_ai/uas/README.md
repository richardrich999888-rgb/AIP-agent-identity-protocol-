# UAS validation layer — blocked, and safety-gated regardless

## Status

PX4 SITL, Gazebo and MAVSDK are unavailable: `github.com` returns HTTP 403
through this environment's egress policy and the apt toolchain channel is
denied. `pymavlink` **is** installed and has nothing to talk to.

## Safety, which is not conditional on the blockage

**ARM = DISABLED. TAKEOFF = DISABLED. MISSION EXECUTION = DISABLED.**

No vehicle may be armed or moved by anything in this tree, in any environment,
by default. There is no vehicle here, and there would be no arming if there
were.

`MAVSDK` was deliberately **not** installed even though its PyPI dependencies
resolve, for the reason `../../robotics/STATUS.md` already gave: its surface is
vehicle *command* — arm, disarm, takeoff, land, goto, mission upload, parameter
set. Adding an armed-vehicle control surface to a validation session in exchange
for no observational capability is a bad trade in every environment.

## Staging

| stage | status | gate |
|---|---|---|
| SITL | blocked — no PX4 | a reachable clone path and the apt toolchain |
| HITL | **not prepared for execution** | see `hitl/README.md` |
| physical flight | **out of scope** | a safety case, a test authority, and hardware |

## Classification, fixed in advance

PX4 telemetry, MAVLink and MAVSDK client state are all `SubjectSelfReport` at
`Corroborative`. A flight controller's account of the flight controller does not
become independent by crossing a serial link.

**Command sent ≠ command accepted ≠ flight-controller execution ≠ aircraft
state ≠ physical outcome.** `UAS-SITL-001` requires a distinct record for each
of the first four and none at all for the fifth.
