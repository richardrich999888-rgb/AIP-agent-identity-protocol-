# Industrial validation layer — blocked, with one reachable subset

## Status

| tool | status | reason |
|---|---|---|
| open62541 | blocked | `github.com` HTTP 403 |
| Eclipse 4diac FORTE | blocked | same |
| ROS-Industrial | blocked | requires ROS 2, whose apt repository is denied |
| `ros2_control` | blocked | same |
| `asyncua` | **installed** | PyPI is reachable |

`asyncua` is a Python OPC UA implementation. It is a **stand-in for open62541 at
the protocol level and is not open62541**; the distinction is recorded in
`../LICENSES.md` rather than blurred, and it matters because a protocol-level
experiment against a Python server exercises the protocol boundary and no
controller and no machine.

## The chain the layer is for

```
autonomous task → command → controller → PLC/robot → machine state
                                              → external observation
                                              → Vanian evidence
```

## The four sentences this layer exists to keep apart

- **A PLC acknowledgement is not a physical effect.**
- **An OPC UA node value is not automatically independent evidence.**
- **Controller telemetry is not independent evidence.**
- **A machine's self-report is not physical proof.**

All four are already encoded in `aip-industrial`: `ProtocolInteraction`'s
evidence ceiling is a function of the observation mechanism and of nothing about
the protocol, and `establishes_process_change()` is false for every protocol,
response and authentication state. This layer would drive that under a running
server rather than under constructed values.

See `../scenarios/INDUSTRIAL-ACCOUNTABILITY-001.md` for the six injected
conditions and the reachable subset.
