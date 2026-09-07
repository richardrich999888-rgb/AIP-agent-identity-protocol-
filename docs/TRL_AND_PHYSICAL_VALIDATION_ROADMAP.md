# TRL ASSESSMENT AND PHYSICAL VALIDATION ROADMAP

**Companion to** `docs/ENGINEERING_MATURITY_AND_STRATEGIC_READINESS.md` §C and §J
**Date:** 2026-09-07
**Assessed head:** `12767ea` on `claude/codebase-production-readiness-wm6idp`

> **ENGINEERING STATUS**
> TRL 5 overall; AIRI/Sniffer Dog software accountability core approaching TRL 6;
> physical autonomous-system validation pending.

**NASA-style TRL terminology is used as an engineering assessment only. This is
not an official certification, and no certifying body has assessed this
programme.**

---

## 1. TRL assessment

| element | assessment | why not higher |
|---|---|---|
| **Overall Vanian programme** | **≈ TRL 5** | validation in a relevant environment has occurred for software autonomy only |
| AIRI + Sniffer Dog software accountability core | **≈ TRL 5, approaching TRL 6** | the subject agent is synthetic; no non-synthetic framework under representative load |
| Linux runtime observation | **≈ TRL 5** | one host, one kernel, one architecture; `CONFIG_KPROBES` absent |
| Observation-integrity mechanism | **≈ TRL 5** | detector not exercised outside the reproduction environment or across kernels |
| NEXORA evidence / proof infrastructure | **≈ TRL 5** | no external verifier deployment; anchor distribution is a deployment obligation |
| UAS accountability profile | **≈ TRL 4** | no PX4, no SITL, no HITL, no airframe |
| Robotics accountability profile | **≈ TRL 4** | no robot; the live run proves the companion computer |
| Physical autonomous-system accountability | **≈ TRL 2–3 until actually demonstrated** | no mechanism exists whose physical observations reach `from_attested` |
| Full integrated autonomous-system product | **≈ TRL 4–5** | the software chain runs end to end; the physical half does not exist |

### 1.1 What the TRL 5 assessment rests on

1. Real Linux runtime evidence exists — sealed captures on kernel
   6.18.44-fc-v24, not simulation.
2. AI-agent accountability has been exercised — a signed false claim was
   refused corroboration by two mechanism-independent observers.
3. Mechanism-independent observation has been demonstrated — a different probe
   site, a different mechanism, a different project's decoder.
4. Observation interference was reproduced — deterministically, with a
   minimal-cause interferer and audit-subsystem ground truth.
5. The observation-integrity weakness was mitigated in production — one
   deliberate wire-version bump, re-verified against the reproduction.
6. Physical autonomous-system validation remains outstanding.

### 1.2 The specific gap to TRL 6, per element

| element | the one thing that moves it |
|---|---|
| Software core | a non-synthetic agent framework, under representative load, with a characterised false-positive rate for `uncorroborated` |
| Linux runtime | a second kernel, a second architecture, and a multi-host run |
| Observation integrity | the detector run against co-resident mainstream eBPF tooling (Falco / Tetragon / Tracee) on more than one kernel |
| NEXORA | a verifier operated by someone other than the party that produced the package |
| UAS | PX4 SITL, with the flight stack correctly classified as **onboard, not independent** |
| Robotics | ROS2 + Gazebo, with the simulator's ground truth **declared non-independent** |
| Physical accountability | **one** physical quantity established by a mechanism reaching `from_attested` |

---

## 2. Physical AI validation roadmap

Eight stages. Each states its objective, environment, independent evidence
source, acceptance criteria, and — as importantly — **what is still not proven
when the stage passes**.

---

### Stage 1 — Real Linux AI-agent accountability
**STATUS: demonstrated in controlled real-runtime validation.**

| | |
|---|---|
| **Objective** | show that an agent's signed claims can be reconciled against independent kernel-sourced observation, and that a false claim gains nothing |
| **Environment** | Linux 6.18.44-fc-v24, x86_64, root; real `perf_event_open`, real processes |
| **Independent evidence source** | A3S Observer 0.11.0 at `syscalls:sys_enter_execve` (different probe site, different project); `NETLINK_AUDIT`; ftrace reader (weakly independent — same probe site) |
| **Acceptance criteria** | 10 adversarial scenarios execute; a signed false claim resolves to `SELF_REPORTED`, never `PROVEN`; an unobservable claim is never called false; sealed, digested evidence |
| **Result** | 10 executed, 10 passed; one unprompted finding (observation interference); evidence sealed with `SHA256SUMS` |
| **Not yet proven** | that a non-synthetic agent behaves the same; model invocations are structurally unobservable; exit status, tool outcome and egress ordering are not independently checkable on this host; `REAL_WORLD_VALIDATION_PROVEN` is **withheld** |

---

### Stage 2 — ROS2 + Gazebo
**STATUS: validation environment / next relevant stage. Not started.**

| | |
|---|---|
| **Objective** | run the accountability core against a robotics autonomy stack, with a task plan committed into a signed `ExpectedExecution` |
| **Environment** | ROS2 + Gazebo on Linux; the autonomy stack is the workload; the observer is anchored on the same host as a companion computer |
| **Independent evidence source** | kernel-sourced process and socket observation (as today). **The simulator's ground truth is declared a non-independent reference** — it is the world the subject also lives in |
| **Acceptance criteria** | a task plan digest reaches `ExpectedExecution.parameter_digest`; the autonomy process reaches `VERIFIED_EXECUTION`; every pose, contact and task-completion claim resolves to `CANNOT_PROVE`; an injected cross-execution claim is rejected |
| **Not yet proven** | anything physical. A simulator does not make a physical claim establishable; treating simulator state as independent observation would be the exact error the profiles exist to prevent |

---

### Stage 3 — Physical UGV / mobile robot
**TARGET: real controller + external observation.**

| | |
|---|---|
| **Objective** | put a real controller boundary between the autonomy stack and the actuators, and see what the accountability chain can and cannot say across it |
| **Environment** | a physical UGV with a companion computer running the observer, and a separate motion controller on the vehicle bus |
| **Independent evidence source** | companion-computer process/socket observation (implemented today) **plus** at least one off-machine source |
| **Acceptance criteria** | the companion computer's execution is `Attested`; controller acknowledgement is recorded and explicitly **not** treated as actuation evidence; `unobserved_boundaries_to_outcome()` is reported honestly; a disabled drive or a wheel off the ground still yields `CANNOT_PROVE` for motion |
| **Not yet proven** | that the robot moved. Encoder, odometry and localisation agreement is one report with three names on it — `ceiling_after_agreement` returns the base unchanged for any count |

---

### Stage 4 — ExternalCamera / ExternalTracking
**TARGET: independent physical-state observation.**

| | |
|---|---|
| **Objective** | **the decisive stage.** Create the first mechanism whose *physical* observations reach `from_attested`, so a physical quantity can become evidence rather than an assertion |
| **Environment** | an instrumented cell: fixed external camera and/or motion-capture tracking, anchored off the machine, with its own collector and its own key |
| **Independent evidence source** | the external tracker itself — outside the subject's authority, with a `SourceMechanism` the observation layer recognises |
| **Acceptance criteria** | an `ObservationRecord` is produced from a non-onboard physical mechanism; a claimed pose contradicted by the tracker reaches a contradiction rather than being resolved by majority; a tracker outage yields `CANNOT_PROVE`, never non-occurrence; the ceiling for a single physical mechanism is stated and enforced |
| **Blocked on** | an `aip-observation` change: `from_attested` currently takes a batch of `ObservedExecution`s each carrying a `SourceMechanism`, and no physical sensor is one. This is ADR-006's named gap and is **outside the robotics profile** |
| **Not yet proven** | that the tracker itself is trustworthy — this stage creates a new trust anchor and must say so |

---

### Stage 5 — PX4 SITL
**TARGET: UAS accountability.**

| | |
|---|---|
| **Objective** | exercise the UAS profile against a real flight stack in software-in-the-loop |
| **Environment** | PX4 SITL with a companion computer running the autonomy and the observer |
| **Independent evidence source** | companion-computer process/socket observation only. **Flight-controller telemetry is onboard and is capped at `Corroborative` by the profile** |
| **Acceptance criteria** | a mission plan digest reaches `ExpectedExecution`; link state is the **one** of seven navigation quantities that becomes establishable; position, altitude, velocity, attitude, heading and time all remain unestablished; self-reported `COMPLETED` resolves to `Unknown` |
| **Not yet proven** | anything about an airframe. SITL has no airframe |

---

### Stage 6 — PX4 HITL
**TARGET: real flight-controller boundary.**

| | |
|---|---|
| **Objective** | introduce a real flight controller as a second hardware element under one `PlatformId`, and validate that identities stay separate |
| **Environment** | hardware-in-the-loop: real flight controller, simulated airframe |
| **Independent evidence source** | as stage 5, plus the flight controller as a distinct `HardwareId` in its own namespace |
| **Acceptance criteria** | flight-controller and companion-computer identities are distinct and separately booted; a controller swap leaves `PlatformId` intact and is reported as `NotEstablished` for continuity; no controller telemetry is promoted above `Corroborative` |
| **Not yet proven** | that the aircraft flew |

---

### Stage 7 — Controlled UAS
**TARGET: representative mission validation.**

| | |
|---|---|
| **Objective** | a real flight, with a real mission, and post-flight forensic verification |
| **Environment** | a permitted flight range under the applicable civil-aviation regime |
| **Independent evidence source** | ground-station track and independent radio observation — **both currently unmechanised** in the profile and requiring the stage-4 work first |
| **Acceptance criteria** | a signed mission authorisation exists before the flight; the companion computer's execution is attested; a NEXORA package is verified **offline, after the flight, by a party that did not produce it**; every claim the evidence does not support is `CANNOT_PROVE` in that package |
| **Not yet proven** | that the accountability layer scales beyond one airframe, or that it survives an operator who is not the developer |

---

### Stage 8 — Defence / industrial pilot
**TARGET: operationally representative deployment.**

| | |
|---|---|
| **Objective** | the first deployment where the evidence is consumed by someone with an operational reason to distrust it |
| **Environment** | an operationally representative site, operated by the customer |
| **Independent evidence source** | operator-side collectors and operator-held anchors — the customer must be able to verify without the vendor |
| **Acceptance criteria** | the pre-production blocker list in `PRODUCTION_READINESS.md` is closed; an independent security assessment has been completed and remediated; the operator verifies a package offline using anchors the vendor did not supply; a false-positive budget is agreed **before** deployment, not after |
| **Not yet proven** | until it is done: nothing about defence deployment is currently evidenced anywhere in this repository |

---

## 3. Dependency structure

```
Stage 1  ──►  Stage 2  ──►  Stage 3  ──►  Stage 4 ◄── the decisive one
(done)        (ROS2/Gazebo) (real UGV)    (external mechanism reaching from_attested)
                                                │
                                                ▼
Stage 5  ──►  Stage 6  ──►  Stage 7  ──────►  Stage 8
(PX4 SITL)   (PX4 HITL)   (controlled UAS)  (defence/industrial pilot)
```

Stages 5 and 6 can proceed in parallel with 2 and 3, because they exercise the
same software boundary on a different vertical. **Stage 4 gates every physical
claim in the programme**: until a mechanism exists whose observations reach
`from_attested`, stages 3, 6 and 7 can only ever demonstrate accountability for
the *computer*, never for the *machine*.

---

## 4. What must not happen along this roadmap

Stated as prohibitions, because each is a way the programme could appear to
advance while actually regressing:

1. **Do not let simulator state become independent observation.** A simulator
   is the world the subject also lives in.
2. **Do not let onboard sensor agreement raise a ceiling.** Three agreeing
   onboard sensors are one report with three names on it.
3. **Do not read a controller acknowledgement as actuation.** A controller in a
   fault state acknowledges identically.
4. **Do not let a classifier's label become a measurement.** No sensor in the
   profile detects a human; a model output labelled "person" is a model output.
5. **Do not weaken `CANNOT_PROVE` to make a demo look better.** The mitigation
   at `12767ea` was accepted specifically because it can only ever make the
   observer *more* conservative.
6. **Do not add a second reconciliation authority for a vertical.** UAS and
   robotics added none, and `tests/no_second_architecture.rs` enforces it.
