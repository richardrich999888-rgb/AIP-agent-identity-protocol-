# ADR-008 — Industrial Process Evidence Boundary

**Status** ACCEPTED (scope: the industrial profile's evidence semantics only)
**Date** 2026-09-07
**Branch** `claude/skill-25-implementation-xbz0t3`
**Baseline** `12767ea`
**Related** ADR-006 (robotics embodied evidence boundary — the neighbouring
decision), ADR-005 (UAS telemetry evidence boundary), ADR-003 (observation
class boundary — ACCEPTED, unchanged), ADR-004 (effect binding granularity —
ACCEPTED, unchanged), ADR-002 (hardware attestation — **PROPOSED**, unchanged),
ADR-009 (deferred profile-kit extraction)

---

## Context

ADR-005 settled how a UAS profile treats telemetry. ADR-006 added the embodied
chain: a robot makes contact, so between a command and an outcome there are
five physical events that each produce the same signal.

Industrial control inherits all of that and adds two problems neither vertical
has.

**The controller is a separate party that answers positively either way.** A
robot's motion controller sits on a bus the robot owns. A PLC, RTU or DCS
controller is a separate certified device, on a separate network, running a
program written by a separate party, executing on a scan cycle nobody outside
it can see. It answers every write with the same positive response code whether
the logic read the value, whether an output followed, and whether a final
element moved.

**The protocol is the temptation.** Industrial protocols are legible in a way
sensor buses are not. A Modbus write returns a response; a DNP3 select-before-
operate completes; an OPC UA write returns a good status code. Each is a
message that a system logged, is easy to parse, and looks like a receipt. The
pressure to treat one as proof of a process change is the strongest in this
domain, and it is exactly wrong.

There is a third problem, smaller in the model and larger in the field: **a
plant can be operated by hand.** A hand wheel, a jumper, a keyswitch turned to
LOCAL, a point forced at a controller — none of which any Linux mechanism can
observe, and all of which are the readiest explanation for any divergence
between what was authorized and what was seen.

## Decision 1 — eight rungs, not one boundary

The command path is modelled as eight named boundaries, each carrying its
author, whether that author is inside the control system, and what could
observe it:

```
supervisory decision · command issued · protocol accepted ·
controller logic executed · output energised · actuator response ·
process variable change · physical process effect
```

Two are observable in this build, and the profile reports
`unobserved_boundaries_to_effect() == 6` — because *"we verified the control
system"* and *"we verified two of eight rungs and there are six boundaries
before anything in the plant moved"* are the same run described honestly and
dishonestly.

Rungs three to five are classified `SelfReported` **even though a separate,
often safety-certified, device authors them.** A controller's response arrives
over a network the subject reaches and that, for most of these protocols,
anything on the segment can write. This is ADR-005's autopilot argument and
ADR-006's motion-controller argument, and it matters more here because the
consequence is measured in tonnes and volts.

## Decision 2 — the protocol contributes no evidence weight

`ProtocolInteraction::evidence_ceiling` is computed from **the observation
mechanism that saw the exchange, and from nothing about the protocol.** An
authenticated OPC UA write and a bare Modbus write, observed the same way, are
worth the same.

That is not a slight against OPC UA's security model. Message authentication
establishes *who spoke*; the question this layer asks is *what happened*, and no
signature answers it. It is the same rule ADR-005 stated for authenticated
telemetry and ADR-006 restated for a signed controller report.

Consequences, all enforced by tests rather than by review:

- `establishes_process_change()` is `false` for every protocol, every response
  code and every authentication state, computed from the source table.
- There is no `is_trusted`, no `trusted_protocol`, no `assume_authenticated`
  and no `TrustedProtocol` anywhere in the library; the structural guard
  asserts the absence of the vocabulary, so introducing protocol trust requires
  introducing the words for it.
- Nine protocols declare their transport, their message-authentication
  posture, their replay defence, who can forge them and what their positive
  response does not establish. Every one of them gets the *same sentence* for
  what a positive response establishes.
- An adapter may only lower an authentication claim: asking a Modbus adapter
  for an authenticated interaction produces an unauthenticated one, because the
  protocol defines no message authentication to have negotiated.

Replay follows from the same table. `replay_distinguishable()` requires a
protocol with a cryptographic session **and** a deployment that can show the
session was negotiated. Eight of nine protocols cannot tell a captured write
replayed tomorrow from a fresh one; a sequence or transaction counter is
deliberately not treated as a weak yes, because an adversary positioned to
replay a frame is positioned to observe and increment its counter.

## Decision 3 — safety boundaries and process effects are separate objects

The specification requires them to be distinct commitments and distinct
observations. They are, structurally:

| | `SafetyBoundary` | `PhysicalProcessEffect` |
|---|---|---|
| what it is | a document a decision point signs | what sources could establish |
| how it binds | digest in `ActionParameters` | nothing; it is a finding |
| parameter key | `aip.industrial.safety_boundary.v1` | none |
| structure discriminant | `0x03` | none; it is not committed |
| the sentence | "this was declared in force" | "this is what may be said happened" |

There is no method turning one into the other.
`SafetyBoundary::enforcement_establishable()` is `false`, computed from the
class table, so a reader looking for "the interlock held" is told where it is
not rather than reading the commitment as the answer.

A declared bypass is part of the signed document. A bypass that was applied and
not declared produces a document that does not match what is in force, and
nothing here can tell — which is the honest position, because the bypass is a
jumper in a cabinet.

## Decision 4 — an override never closes a divergence

`OverrideClaim::excuses_divergence()` returns `false` for every kind, at every
evidence tier, attributed or not.

An attributed override establishes that *an* override was permitted. It does
not establish that *this* divergence is that override, and the two are joined
only by the assumption that nothing else could have caused it — which is the
assumption an attacker needs. Admitting an override as an explanation would
convert the one fact this architecture can establish, a mismatch, into an
unfalsifiable excuse.

An override is admitted **as authority** only when it is attributed: a decision
behind it, and a kind of override a decision point could have gated at all.
Four of the seven kinds — a keyswitch, a forced point, a field manual
operation, a hard-wired trip station — can never be attributed, because there
is no software in the path to have asked.

## Decision 5 — compute containment is not process containment

`ContainmentScope::restores_process_safe_state()` is `false` for both scopes,
and `requires_warrant()` is `true` for both.

Freezing the supervisory process on the edge node stops new commands. The
controller keeps running the program it has, outputs hold their last commanded
state, the valve stays where it was, and a process with stored energy keeps
converting it. A deployment that reads "contained" as "safe" has made the most
expensive category error available in this domain, and the profile states the
fail-safe direction per scope so a containment design has to confront it.

The crate has no runtime dependency on `aip-warrant` or `aip-containment`, and
the structural guard asserts it names no actuator, no warrant type and no
containment function.

## Decision 6 — coverage is reported in three domains, one of which is empty

Compute, network and process state, as the specification names them.
`class_domain` is total over `ObservationClass`, so a class added later cannot
silently join a domain, and `ObserverIntegrity` deliberately belongs to none:
it is evidence about the observer, and folding it into a domain would let an
observer's own signature arithmetic count as coverage of a plant.

Process state is unobservable in every deployment, for every instrument set,
and `CoverageDomain::ProcessState.can_support_non_occurrence()` is `false` —
so "the valve did not move" is not sayable here regardless of observer health.

## Alternatives rejected

**Add `SourceMechanism` variants for transmitters, meters and actuator
feedback.** This is the schema fork ADR-003 exists to prevent, applied a third
time. A pressure transmitter is not a Linux kernel facility, and putting a
device-specific value into signed bytes every verifier must understand would
fork the accountability core per vertical.

**Give OPC UA a higher evidence ceiling than Modbus.** Superficially
attractive: one has a real security model and the other has none. It is wrong
because the difference is about authorship and the ceiling is about occurrence,
and encoding it would mean a deployment could raise what its evidence is worth
by changing protocol rather than by observing anything.

**Parse protocol payloads to record what was written.** Rejected: a payload
read off the subject's own network is the subject's account of the payload, and
parsing one would make this crate the thing that decides what a write meant. The
point address, value and unit are committed in `ActionParameters` by the party
that *authorized* the write, which is the only party whose account of it is
recomputable by a third party.

**Treat a two-out-of-three transmitter vote as corroboration that raises a
ceiling.** Rejected for the reason `corroborate.rs` states: the vote is
computed by the controller, so "the vote agreed" is the subject reporting on
itself once more; and voting is excellent against random transmitter failure
and useless against common cause — a shared tapping, a shared impulse line, a
shared engineering error.

**Let an attributed override close a divergence.** Rejected under Decision 4.

**Model a safety boundary as a property of the control loop commitment.**
Rejected: one commitment carrying both would mean a signature over a command
was also a signature over the safety case, and a deployment could change what
was declared in force without changing what was authorized, or the reverse.

## What this decision does not settle

**Whether an independent plant sensor could ever be evidence.**
`IndependentPlantSensor`, `FieldInspection` and `RegulatoryTelemetry` are
outside the control system and capped at `Corroborative` because no mechanism
anchors them. An anchored external collector with a real mechanism is the
shortest path to genuine industrial evidence, and it is an `aip-observation`
change, outside Skill 25.

**Whether a serial fieldbus deployment can be accounted for at all.**
`ModbusSerial` has no socket and no frame on a network device, so a deployment
that speaks only serial is observable at the edge node's process boundary and
nowhere else. The profile records this rather than leaving a silent hole; what
to do about it is a deployment question.

**Hardware attestation.** ADR-002 remains PROPOSED. A TPM on the edge node
would strengthen claims about the edge node and say nothing about a PLC.
