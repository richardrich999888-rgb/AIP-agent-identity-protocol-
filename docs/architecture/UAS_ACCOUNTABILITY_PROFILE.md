# UAS Accountability Profile (Skill 23)

**Status** PROFILE — NOT_PRODUCTION_CAPABILITY
**Date** 2026-09-07
**Baseline** `7a5cd55`
**Related** ADR-005 (this profile's evidence boundary), ADR-002 (PROPOSED),
ADR-003, ADR-004, `LINUX_EDGE_REFERENCE.md`

---

## 1. The one-sentence claim

Vanian can account for the **autonomy computer's execution** on a UAS. It
cannot account for the **airframe's motion**, and every navigation, actuation
and mission-outcome question resolves to `CANNOT_PROVE` unless a deployment
supplies an independent physical mechanism, which this build does not have.

## 2. What was reused, and what was added

The core had already reserved the space. `SystemType::UncrewedAerial` existed
at wire code `0x02`; `ProfileKind::Environment` was documented as *"the slot
vertical profiles will occupy"*; `PlatformId` as *"airframe, chassis, hull,
cabinet"*; `HardwareId` noted that *"a flight computer swapped in the field
leaves the platform identity untouched"*.

| concern | reused | added |
|---|---|---|
| system, platform, hardware, mission identity | `aip-system` newtypes | nothing |
| authority | delegation chains, `DecisionPoint`, `ExpectedExecution` | a mission commitment in `ActionParameters` |
| action vocabulary | `ScopeAction::Custom` | nine `uas.*` action kinds |
| execution ladder | `ExecutionStage`, `RuntimeAction`, `EffectOutcome` | a five-rung command mapping onto it |
| platform binding | `PlatformBinding`, `ObservedBoot`, `PlatformRegistry` | nothing |
| observation | `ObservationProfile`, `ObservationRecord`, `ObservationClass` | a source taxonomy that projects into them |
| effect | `EffectAssessment`, `EffectBinding` | nothing |
| verdict | `reconcile_expectation` | nothing |
| proof | NEXORA, nine leaf kinds | nothing |

**One crate, `aip-uas`. No identifier, no record type, no verdict class, no
key, no signer, no proof tree.** Asserted over comment-stripped source in
`tests/no_second_architecture.rs`.

## 3. Six identities, kept apart

```
UAS system identity      SystemId          uas:tail-07      durable
airframe identity        PlatformId        airframe:tail-07 outlives its compute
flight-controller id     HardwareId        fc:...           a compute element
companion computer id    HardwareId        cc:...           another one
container identity       — not established —
hardware attestation     — not established, ADR-002 PROPOSED —
```

A flight controller and a companion computer are two `HardwareId`s in different
namespaces under one `PlatformId`. `aip-platform`'s registry already supported
this — *"a UAS with a mission computer and a flight controller is two hardware
elements under one platform, and each boots separately"* — so the profile
expresses it with existing types rather than beside them.

Mission identity is `MissionId` and is distinct from execution identity, which
is the AIRI `execution_id`: many executions serve one mission.

## 4. Telemetry sources

Eleven sources, each carrying the six-part treatment. The load-bearing column:

| source | onboard? | mechanism | ceiling |
|---|---|---|---|
| flight-controller telemetry | yes | — | Corroborative |
| companion autonomy report | yes | — | Corroborative |
| GNSS receiver (onboard) | yes | — | Corroborative |
| IMU (onboard) | yes | — | Corroborative |
| barometer (onboard) | yes | — | Corroborative |
| airspeed probe (onboard) | yes | — | Corroborative |
| external navigation receiver | no | — | Corroborative |
| ground-station track | no | — | Corroborative |
| independent radio observation | no | — | Corroborative |
| **companion process observation** | no | `PidFdAnchored` | **Attested** |
| **companion network observation** | no | `ProcNetTable` | **Attested** |

Two of eleven can produce an `ObservationRecord`. Nine cannot, and the reason
is structural rather than a policy choice: `from_attested` takes a batch of
`ObservedExecution`s each carrying a `SourceMechanism`, and no avionics sensor
is one. See ADR-005.

Independence is necessary and **not sufficient**: a ground tracker nobody
implemented is still nobody observing, so the three external-but-unmechanised
sources contribute nothing.

## 5. Navigation evidence

Seven quantities × five independent determinations. Authentication is
deliberately not on the occurrence path.

| quantity | typical airframe | with a companion observer |
|---|---|---|
| position | self-reported, signed, **not established** | unchanged |
| altitude | self-reported, signed, **not established** | unchanged |
| velocity | self-reported, signed, **not established** | unchanged |
| attitude | self-reported, signed, **not established** | unchanged |
| heading | self-reported, signed, **not established** | unchanged |
| time | self-reported, signed, **not established** | unchanged |
| link state | self-reported | **established, Attested** |

Exactly one of the seven becomes establishable, and it is the one about the
computer rather than the aircraft.

**No quantity can reach `Proven` under any declared source set.** `Proven` is
for facts a third party recomputes from held bytes; no telemetry is
recomputable, only re-checkable for who signed it.

## 6. Mission and authority

A `MissionPlan` carries no authority. It becomes authoritative by committing
its digest into `ActionParameters` under `aip.uas.mission.v1`, which a decision
point signs as `ExpectedExecution.parameter_digest`. Same mechanism as Skill
18's execution binding; **no new signer, no new authority system**.

The plan's preimage covers mission id, revision, system, platform, window,
region and the sorted action set. A revision change is a different document. A
different airframe is a different document. Authorizing `Takeoff` never implies
`Land`.

**Cancellation** needs no revocation channel: an expectation is bounded, so a
mission stops being authorized when the last expectation committing to it
expires and no further one is issued. Cancelling is declining to authorize,
which is a decision point's existing power.

## 7. Mission state

Eleven states, each naming the evidence tier that would justify it.
`assertable(claimed, available)` may only echo or weaken.

| tier | states | reachable here |
|---|---|---|
| Declared | Planned | yes |
| DecisionSigned | Authorized, AbortRequested | yes |
| ExecutionObserved | Started, InProgress, Degraded | yes |
| **PhysicallyObserved** | **Aborted, Returning, Landed, Completed** | **no** |

Self-reported `COMPLETED` resolves to `Unknown` at every tier, including the
top one — because the top tier is itself unreachable.

## 8. Flight-control boundary

```
autonomy decision  →  command transmitted  →  FC accepted  →  actuator  →  vehicle state
   observable            observable            not             not          not
```

A flight-controller acknowledgement is classified `SelfReported` **even though
a different device authored it**. The autopilot is inside the system under
scrutiny; a compromise that reaches the autonomy stack usually reaches the bus,
and a compromise of the autopilot needs no help. Treating an autopilot ack as
independent evidence is the most attractive mistake available in this domain.

## 9. Geofence

`Violation` is reachable only from a position whose `establishes()` is true.
A self-reported position establishes **neither violation nor compliance**, and
an unanswerable question is never compliance.

Coordinate frame and altitude reference are carried explicitly and refused on
mismatch rather than converted — a silent conversion is a wrong answer with a
confident face. The frame check runs before staleness so the more specific
structural fault is the one reported. Boundaries are inclusive; bounds are
integer micro-degrees and centimetres, so two verifiers checking one fence
agree.

For every aircraft flying today the honest answer is `CannotAssess`.

## 10. Link and failsafe

No method in `link` returns a conclusion about the aircraft.
`establishes_non_occurrence()` returns `false` for every state, permanently. An
uncovered window is `Unknown`, not `Lost`: an observer that was not looking has
not established silence. The aircraft's own report of its link health yields
`Unknown` whatever it says.

Failsafe actions — RTH, emergency landing, geofence response, loss-of-link,
battery, navigation and sensor failure — are ordinary `UasAction`s: they can be
REQUESTED, AUTHORIZED, and observed leaving the companion computer, and their
completion is a physical claim that resolves to `Unknown`. The profile
describes evidence; the existing warrant and containment path remains
authoritative for enforcement.

## 11. Multi-sensor corroboration

Three agreeing onboard sensors are **one report with three names on it**.
`ceiling_after_agreement` returns the base ceiling unchanged for any count and
contains no arithmetic. Conflict wins over agreement and is never resolved by
majority, recency, apparent source strength or self-reported confidence.

## 12. Live validation

`aip-uas/tests/integration.rs` runs the Skill 22 three-process reference and
reads it as a UAS companion computer: the workload is the autonomy stack, its
TCP connection is the link to a flight controller, the observer is anchored on
the companion computer. On real kernel evidence the run reaches
`VERIFIED_EXECUTION` and establishes the named effect — and the profile
simultaneously reports position, altitude, velocity, attitude and heading as
unestablished, mission `Completed` as `Unknown`, the geofence question as
`CannotAssess`, and physical effect as unreachable.

There is no aircraft. There is a companion computer, and on a real UAS that is
a Linux host. The mapping is honest in both directions.

## 13. Known gaps

1. **No avionics evidence path exists.** ADR-005. Closing it needs a mechanism
   whose observations reach `from_attested`, and that is an `aip-observation`
   change.
2. **No aircraft state is establishable**, so four mission states and every
   navigation quantity but link state are permanently `Unknown`.
3. **The three independent-but-unmechanised sources** — ground track, external
   navigation receiver, radio observer — are the shortest path to real UAS
   evidence. Each needs an anchored collector and a mechanism; neither exists.
4. **Hardware attestation is absent.** ADR-002 PROPOSED. A TPM on the companion
   computer would strengthen claims about the companion computer and say
   nothing about the airframe.
5. **The reference is not a flight test.** Nothing here has been validated
   against an aircraft.
