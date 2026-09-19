# INDUSTRIAL-ACCOUNTABILITY-001

**Status: DESIGNED — NOT EXECUTED. No OPC UA server, PLC or `ros2_control`
stack is available in this environment.**

## Scenario

```
autonomous task → command → controller → machine-state transition
```

Realisable two ways; either is sufficient:

- **A.** ROS 2 + `ros2_control` with a simulated hardware interface, or
- **B.** an OPC UA server (open62541, or `asyncua` as a protocol stand-in) with
  a client issuing writes.

## Injected conditions

| # | condition | expected result |
|---|---|---|
| 1 | command accepted, machine did not change | conflict; **no** physical claim either way |
| 2 | machine changed with no expected command | recorded; unexplained; no override may close it |
| 3 | stale machine state | `Stale` refusal |
| 4 | duplicate command | replay detected; evidence not inflated |
| 5 | missing acknowledgement | `NotObserved`, never "did not happen" |
| 6 | operator intervention | `OverrideClaim`; admitted as authority only if attributed |

## The separation the experiment must demonstrate

Four things that industrial practice routinely conflates:

```
command        the write left the edge node
execution      the controller says its scan ran the logic
state          a status bit or an OPC UA node reads a value
physical effect  the plant is different
```

`aip-industrial` already encodes this as eight `ControlRung`s with two
observable and six not. This experiment would drive the first two rungs with a
real protocol and confirm that the remaining six stay unestablished under a
running controller.

## Evidence classification, fixed in advance

| source | class | ceiling |
|---|---|---|
| OPC UA server state | `ControllerAcknowledgement` | `Corroborative` |
| PLC / controller ack | `ControllerAcknowledgement` | `Corroborative` |
| `ros2_control` state interface | `ControllerAcknowledgement` | `Corroborative` |
| edge-node process/socket observation | `HostRuntimeObservation` | `Attested` |
| external observation of the machine | none available | — |

**A PLC acknowledgement is not a physical effect. An OPC UA node value is not
independent evidence. Controller telemetry is not independent evidence. A
machine's self-report is not physical proof.**

## Blockers

- open62541 and 4diac FORTE: clone path denied (HTTP 403).
- `ros2_control`: requires ROS 2, whose apt repository is denied.
- `asyncua` **is** installed and could carry condition set 1–6 at the protocol
  level, against a Python OPC UA server. That would exercise the *protocol*
  boundary and no controller and no machine — worth doing, and it is not the
  experiment. It is recorded here as the reachable subset rather than presented
  as the whole.
