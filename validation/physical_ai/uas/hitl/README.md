# PX4 hardware-in-the-loop — documented, NOT executable

**Nothing in this directory arms, moves, or configures any vehicle. There is no
HITL configuration here that a script could run. This is a requirements
document for a later, separately authorized milestone.**

## Why it is a document and not a configuration

HITL puts a real flight controller, with real outputs, in the loop. The
difference between HITL and SITL is not fidelity; it is that a mistake can
energise a motor. A configuration checked into a repository can be run by
someone who did not read this file.

## What a HITL milestone would require

**Hardware**
- A flight controller board (PX4-supported), on a bench, with **propellers
  removed**.
- A separate host running the simulator.
- A physically separate observer machine for any external observation.
- An external, hardware, operator-controlled kill path — not a software one.

**Flight-controller boundary**
- Which firmware version, and its hash.
- Which parameters differ from defaults, and why.
- Which outputs are physically disconnected, verified by inspection rather than
  by configuration.

**Sensors**
- Whatever the airframe needs for the mode under test, and a written statement
  of which are simulated and which are real. A HITL run mixes them, and a report
  that does not say which is which is not a report.

**Safety controls**
- Arming inhibited in hardware, not in software.
- A test authority who is a person, present, with the authority to stop.
- A written safety case, reviewed before power-on.

**Isolation**
- The vehicle network isolated from any network that can reach the internet.
- The observer's key material on the observer's machine and nowhere else.

**Evidence collection**
- Which quantity is being observed externally, and by what mechanism.
- The calibration relating the sensor's units to physical units, performed and
  recorded — not declared.
- The marker-attachment check, if a fiducial is used.

## The standing prohibition

No arming authority may be enabled automatically, by any script, in any
environment, at any time. Enabling it is a human decision made with a safety
case in hand, and it is not a software configuration change.
