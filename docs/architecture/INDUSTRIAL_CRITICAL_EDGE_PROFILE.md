# Industrial and Critical-Edge Accountability Profile (Skill 25)

**Status** PROFILE — NOT_PRODUCTION_CAPABILITY
**Date** 2026-09-07
**Baseline** `12767ea`
**Related** ADR-008 (industrial process evidence boundary), ADR-009 (deferred
profile-kit extraction), ADR-006 (robotics), ADR-005 (UAS), ADR-002
(PROPOSED), ADR-003, ADR-004, `ROBOTICS_ACCOUNTABILITY_PROFILE.md`,
`UAS_ACCOUNTABILITY_PROFILE.md`, `LINUX_EDGE_REFERENCE.md`,
`OBSERVATION_INTEGRITY_REQUIREMENTS.md`

---

## 1. The one-sentence claim

Vanian can account for what a **critical-edge node's software** did — which
binary ran, on which host-boot, which sockets it held, how many bytes the kernel
accepted for them, which configuration files it wrote. It cannot account for
what the plant did, and every claim about a valve, a breaker, a flow, a
pressure, an interlock or a completed shutdown resolves to `CANNOT_PROVE` unless
a deployment supplies an independent physical mechanism, which this build does
not have.

## 2. Why this is a different problem from the robotics case

A robot's controller sits on a bus the robot owns. An industrial controller is a
separate certified device, on a separate network, running a program written by a
separate party, executing on a scan cycle nobody outside it can see — and it
answers every command with the same positive response code whether or not
anything happened.

And the protocol is legible in a way a sensor bus is not, which makes the
temptation worse: a response code is easy to log, easy to parse, and looks like
a receipt.

## 3. The eight rungs

| rung | author | observable here |
|---|---|---|
| supervisory decision | the supervisory software | **yes** |
| command issued | the supervisory software | **yes** |
| protocol accepted | whatever answered at that endpoint | no |
| controller logic executed | a controller | no |
| output energised | a controller | no |
| actuator response | the plant | no |
| process variable change | an instrument inside the control system | no |
| physical process effect | the plant | no |

`ControlLoopChain::unobserved_boundaries_to_effect() == 6`.

The specific failures each boundary hides: a simulator, a gateway cache or a
device that inherited an address answering; a controller in program mode
accepting writes into memory no scan reads; a forced output point reporting the
commanded state and driving nothing; loss of instrument air, a seized stem, a
sheared pin; a blocked impulse line reading a steady, plausible, wrong value;
everything measured going right and the process being somewhere else.

## 4. Seventeen sensing sources, six with a mechanism

Six is more than the robotics profile's two, and the difference is real rather
than generous: a critical-edge node is a Linux host that talks a routable
protocol over a network device, so five of the nine implemented mechanisms see
something about it.

| source | mechanism | class | ceiling |
|---|---|---|---|
| edge process observation | `PidFdAnchored` | ProcessIdentity | `Attested` |
| edge lifecycle observation | `ProcConnector` | ProcessLifecycle | `Attested` |
| edge network observation | `ProcNetTable` | NetworkSocket | `Attested` |
| edge data-transfer observation | `SockSendTracepoint` | DataTransfer | `Attested` |
| protocol wire observation | `WireTapAfPacket` | NetworkWire | `Corroborative` |
| edge config-write observation | `Fanotify` | FilesystemEffect | `Attested` |

The other eleven have none: a transmitter, an actuator feedback, a historian, an
HMI log, a safety-system status, a meter, an independent plant sensor, a field
inspection, a regulator's feed, a controller status report and the supervisory
software's own account. `can_produce_observation_record()` is false for all of
them — `from_attested` has no input it could be given.

Eight of seventeen are **inside the control system**, including the historian
and the HMI log, which are archives *of what the control system said*, and
including the safety system, which is a separate box for process safety and the
same station, networks and integrator for accountability.

Every unmechanised source is capped at `Corroborative`, whether it is inside the
control system or outside it: positional independence without an implemented
mechanism is nobody observing. Nothing reaches `Proven`.

Three of the six mechanised sources are **gate-independent** — the netlink
process connector, the AF_PACKET wire tap and fanotify. The other three pass
through the per-tracepoint eBPF submission gate, so a foreign program can blind
them host-wide with no dropped-record accounting.

## 5. The semantic boundary

| measurement | actually establishes | commonly read as |
|---|---|---|
| protocol response code | something at that endpoint answered | the command executed |
| controller status bit | what the bit was when it was read | the interlock is intact |
| valve limit switch | the stem reached the switch | the valve opened |
| breaker auxiliary contact | the auxiliary's position | the circuit is de-energised |
| transmitter reading | what the transmitter output | the pressure is 4.2 bar |
| motor run feedback | the contactor picked up | the pump is delivering |
| historian trend point | what was reported | what was true |
| meter totaliser | the count at that meter | the quantity delivered |
| alarm annunciation | the expression evaluated true | the interlock is intact |

`ProcessClaim::establishable_from_measurement()` is `false` for all eight
claims, computed from the source table rather than written as a literal. The
interlock case is the one worth naming: a protective function is only ever
tested by the demand it exists for, and a bypass reports healthy.

## 6. Protocols

Nine, each declaring transport, message-authentication posture, replay defence,
who can forge it and what its positive response does not establish. Three ship
as adapters: Modbus/TCP, DNP3, OPC UA.

**No protocol is trusted, and the library has no vocabulary for trusting one.**
`evidence_ceiling` is a function of the observation mechanism and of nothing
about the protocol; `establishes_process_change()` is `false` for every
protocol, response and authentication state. An adapter may only *lower* an
authentication claim — asking a Modbus adapter for an authenticated interaction
produces an unauthenticated one.

Eight of nine cannot distinguish a replayed command from a fresh one. A
sequence or transaction counter is not treated as a weak yes.

`ModbusSerial` has no socket and no frame on a network device: a deployment that
speaks only serial is observable at the edge node's process boundary and nowhere
else, and the profile records that rather than leaving a silent hole.

## 7. Commands and authority

Eighteen commands under the `ics.` namespace, disjoint from `uas.`, `robot.`
and `ghost.`. Seventeen are process-affecting; alarm acknowledgement is the
only one whose whole effect is inside the observable boundary. Four are
safety-related: bypass interlock, restore interlock, trip safety function,
emergency shutdown.

A write's parameters commit the **device, the address space, the point, the
value and the unit** together. The same number on two controllers is two
commands; the same number in two units is two commands. This is the industrial
form of the coordinate-frame confusion ADR-006 named.

Authority is the existing mechanism: a `ControlLoopExecution` and a
`SafetyBoundary` each commit their digest into `ActionParameters` under distinct
keys, which a decision point signs as `ExpectedExecution.parameter_digest`. No
new authorization engine, no new signer, no new trust anchor.

Cancellation is declining to authorize. No revocation list.

## 8. Freshness

A control-loop execution carries a half-open window and a `CommandFreshness`
that is `NotYetValid`, `Fresh` or `Stale`. `admit_at` **refuses** rather than
weakening, and staleness is not repaired by any amount of observation:
freshness is a property of the authorization, not of the evidence. Replaying a
captured write is the cheapest attack on a control network with no session
cryptography, which is most of them, and the bounded window is what refuses it.

## 9. Safety boundaries

A `SafetyBoundary` is a signed document — protective functions in force,
limits, permitted commands, and whether a bypass was declared — under its own
parameter key and its own structure discriminant. Permitting a setpoint write
does not permit a bypass; nothing is inferred.

`enforcement_establishable()` is `false`. The commitment says what was
*declared*; whether the plant honoured it is a `PhysicalProcessEffect` question
and nothing here can answer it. A bypass applied and not declared produces a
document that does not match reality, and nothing here can tell — the bypass is
a jumper in a cabinet.

Two of the eight protective functions — a relief valve and a hard-wired manual
trip station — are addressable from no network at all, which is the strongest
safety property in the table and belongs in the document rather than in a slide.

## 10. Operator and manual override

Seven kinds. Three could be routed through a decision point; one could be seen
by an anchored observer; four happen at a controller or in the plant and appear
nowhere, permanently.

| kind | authority expressible | edge observable | lineage when silent |
|---|---|---|---|
| HMI write on an observed host | yes | yes | `NotObserved` |
| engineering workstation download | yes | no | `NotObservable` |
| maintenance bypass | yes | no | `NotObservable` |
| controller keyswitch to LOCAL | no | no | `NotObservable` |
| forced I/O point | no | no | `NotObservable` |
| field manual operation | no | no | `NotObservable` |
| manual trip station | no | no | `NotObservable` |

**`excuses_divergence()` returns `false` for every kind, at every tier,
attributed or not.** An attributed override establishes that *an* override was
permitted; it does not establish that *this* divergence is that override. The
divergence stays a divergence and a human decides.

## 11. Coverage in three domains

| domain | classes | observable with an edge observer |
|---|---|---|
| compute | process lifecycle, process identity, filesystem effect, platform binding | yes, `Attested` |
| network | socket, wire, data transfer | yes, `Attested` |
| process state | physical effect | **no, in every deployment** |

`ObserverIntegrity` belongs to no domain: it is evidence about the observer, and
folding it in would let an observer's own signature arithmetic count as coverage
of a plant.

Non-occurrence requires three things at once: a domain with an implemented
class, a declared gate-independent kernel-pushed mechanism, and an observer
whose *signed* health vouches for the window. The third is delegated to
`SignedSensorHealth::covered_by_kernel_pushed_source` rather than re-derived, so
the profile inherits the production observation-integrity fix instead of
duplicating it.

## 12. Observation integrity

The finding closed in `12767ea` is part of this profile's boundary:

```
observer integrity unknown  →  cannot_prove
observer integrity unknown  ↛  healthy coverage
```

`non_occurrence_admissible` is `false` for every domain under
`ObserverState::IntegrityUnknown`, and under every other non-`Active` state. The
declared *capability* is unchanged — the deployment still has its mechanisms —
and what changed is what may be concluded, which is the whole distinction.

## 13. Containment

`ContainmentScope::EdgeCompute` has a mechanism (the cgroup v2 freezer);
`ProcessActuation` has none. Both require a warrant. **Neither restores a safe
process state.** Freezing the supervisory process stops new commands; the
controller keeps running the program it has, outputs hold their last commanded
state, and a process with stored energy keeps converting it.

The crate has no runtime dependency on `aip-warrant` or `aip-containment`, and
the structural guard asserts it names no actuator, no warrant type and no
containment function.

## 14. Live validation

`aip-industrial/tests/integration.rs` runs the Skill 22 three-process reference
as a critical-edge node: the workload is the supervisory software, its TCP
connection is the protocol session to a PLC, the observer is anchored on the
edge node. Ten tests over six scenarios — honest, cross-execution injection,
replayed observation, observer loss, wrong boot, wrong platform — on real kernel
evidence.

On the honest run the reference reaches `VERIFIED_EXECUTION` — and the profile
simultaneously reports every process claim as unestablished, `SHUTDOWN_COMPLETE`
as `Unknown`, an emergency shutdown as commanded-but-not-performed, the
process-state domain as unobservable, and physical effect as unreachable.

The cross-execution injection and replay cases are exercised from the start,
having learned in Skills 23 and 24 that a profile whose tests only drive the
honest scenario is insensitive to the core guard it rests on.

## 15. Migration and versioning

**No wire version changes.** `OBSERVE_PROTOCOL_VERSION` stays at 9,
`EXPECTED_EXECUTION_VERSION`, `SYSTEM_EXECUTION_VERSION` and
`OBSERVATION_PROFILE_VERSION` are untouched, and no signed field in any core
structure gains, loses or reinterprets a byte.

What is new is one domain tag —
`SYNTRIASS/AUTONOMY/INDUSTRIAL_PROFILE/v1` — with three structure
discriminants inside it (`0x01` control loop, `0x02` profile document, `0x03`
safety boundary), and two action-parameter keys,
`aip.industrial.control_loop.v1` and `aip.industrial.safety_boundary.v1`, both
versioned in the key itself. A verifier that does not implement this profile
sees a `ProfileRef` it does not recognise and an opaque parameter value, which
is the behaviour Skill 17 designed the slot for.

`ProcessLimit` encodes its fixed-point value through the existing `put_u64` via
a two's-complement bit cast rather than adding a signed encoder to `aip-types`:
the map is a bijection on bit patterns, so the encoding stays injective, and the
shared canonical vocabulary is not changed for one profile's convenience.

`IndustrialProfile`, `ControlLoopExecution` and `SafetyBoundary` all carry
`version: u16` and `check_version()`, and refuse an unknown version rather than
guessing what the fields mean.

## 16. Known gaps

1. **No plant evidence path exists** (ADR-008). Closing it needs a mechanism
   whose observations reach `from_attested` — an `aip-observation` change,
   outside Skill 25.
2. **A bypass applied and not declared is undetectable.** The document records
   what a deployment says; nothing measures a cabinet.
3. **A forced I/O point, a keyswitch and a hand wheel are undetectable and
   always will be.** Four of seven override kinds sit outside every mechanism.
4. **`IndependentPlantSensor` is the shortest path to real industrial
   evidence.** It needs an anchored collector and a mechanism; neither exists.
5. **A serial-only deployment is observable at the process boundary and nowhere
   else.** Recorded, not solved.
6. **Hardware attestation absent.** ADR-002 PROPOSED. A TPM on the edge node
   would strengthen claims about the edge node and say nothing about a PLC.
7. **The three generic rules are now duplicated across three verticals.**
   Guarded by `aip-industrial/tests/cross_vertical.rs`; extraction deferred to
   the first non-embodied vertical (ADR-009).
8. **No plant was involved.** Nothing here has been validated against physical
   process equipment, a real PLC, or a real protocol stack. The live runs
   exercise a Linux host, which is genuinely half the chain and is not the half
   anyone worries about.
