# Phased validation plan

Seven phases. Each states its hypothesis, its independent observation source,
the evidence it expects, what makes it fail, what it accepts as a pass — and,
mandatorily, **what would not count as proof even if the phase passes**.

The last section of every phase is the one that matters. A phase that passes
while its "does not establish" list is ignored has produced a false claim, not
a result.

## The ladder

```
CODE-PROVEN                 the implementation does what its tests say
    │
TEST-PROVEN                 adversarial tests fail it in the ways they should
    │
REAL RUNTIME-PROVEN         it holds against a live kernel on real workloads
    │
REAL AUTONOMOUS-            it holds against a real autonomous system doing
SYSTEM-PROVEN               real things
```

Vanian is at **TEST-PROVEN**, with parts of **REAL RUNTIME-PROVEN** established
by the live kernel runs already in the repository. Phases 1–2 below address the
rest of REAL RUNTIME-PROVEN. Phases 3–7 address REAL AUTONOMOUS-SYSTEM-PROVEN
and **cannot start in this environment** (`../robotics/STATUS.md`).

---

# Phase 1 — Independent Linux runtime observation

**Status: READY.** Implemented as
`exp01_linux_runtime_observation/`.

**Hypothesis.** Sniffer Dog 2.0 can establish process-execution events from the
kernel without asking the subject, and correctly classifies the cases where the
subject's claim differs from what the kernel reported.

**Setup.** A Linux workload that behaves like an autonomous agent — spawns
children, execs binaries, writes files, opens sockets — and which emits its own
event log. The log is deliberately made to disagree with reality in specified
ways.

**Independent observation source.** The ftrace tracepoint reader (matrix row 5).
Interface-independent of Sniffer Dog; **not** mechanism-independent
(`../linux/INDEPENDENCE.md`).

**Expected evidence.** Three accounts of one execution window: subject
self-report, Sniffer Dog observation, kernel-rendered ftrace capture. A
comparison classifying every event as agreed, subject-only, kernel-only, or
disputed.

**Failure conditions.**
- Sniffer Dog reports an exec with no counterpart in the kernel capture
  (fabrication or decode error).
- Sniffer Dog misses an exec both other sources contain, without reporting loss.
- Sniffer Dog accepts a subject claim the kernel contradicts.
- Sniffer Dog emits anything stronger than `CANNOT_PROVE` for a window it did
  not cover.
- Timestamps disagree beyond the measured clock bound.

**Acceptance.** Every event in the kernel capture within the window is present
in Sniffer Dog's account or explicitly reported as lost; every fabricated
subject claim is classified as unsupported; every suppressed subject claim
still appears in Sniffer Dog's account; no unsupported claim is upgraded above
`CANNOT_PROVE`.

**What would NOT count as proof.**
- Agreement between Sniffer Dog and ftrace does **not** prove the event
  occurred. Both read one tracepoint; anything corrupting that tracepoint
  corrupts both identically.
- It does not establish resistance to a root-privileged subject.
- It does not establish anything about robots, vehicles or physical effects.
- A clean run on this synthetic workload is not a clean run on a real agent.

---

# Phase 2 — Mechanism-independent runtime corroboration

**Status: BLOCKED — `# CONFIG_KPROBES is not set` on this kernel.**

**Hypothesis.** Sniffer Dog's account of an execution is corroborated by an
instrument observing through a *different kernel mechanism*, so that agreement
is evidence about the event rather than about the reading.

**Setup.** Phase 1's workload, on a host with `CONFIG_KPROBES=y`, with Tetragon
running in observation-only mode (`../external/tetragon/BUILD.md` builds it).

**Independent observation source.** Tetragon (matrix row 6) — eBPF on kernel
functions via kprobes. Different probe site, different mechanism, different
project's decoder.

**Expected evidence.** A four-way comparison: subject, Sniffer Dog, ftrace,
Tetragon. Cases where Tetragon and ftrace agree but Sniffer Dog differs isolate
Sniffer Dog defects; cases where Tetragon differs from *both* tracepoint
readers isolate the tracepoint layer's own blind spots.

**Failure conditions.** Tetragon observes an execution neither tracepoint reader
sees, and Sniffer Dog reports full coverage for that window — meaning Sniffer
Dog's coverage claim is broader than its mechanism supports.

**Acceptance.** Any three-way disagreement is explained by a named mechanism
difference, not left unexplained; Sniffer Dog's coverage assertions never exceed
what its mechanisms can carry.

**What would NOT count as proof.** Still nothing about robots. Still not
root-compromise resistance — Tetragon on the observed host is inside the same
blast radius. Still nothing physical.

---

# Phase 3 — Autonomous-system self-report vs simulator ground truth

**Status: BLOCKED — no ROS 2, no Gazebo (`../robotics/STATUS.md`).**

**Hypothesis.** Vanian correctly distinguishes what an autonomous node *claims*
from what the environment *did*, and refuses to upgrade the former.

**Setup.** A ROS 2 node in Gazebo, commanded to a waypoint, publishing odometry.

**Independent observation source.** Gazebo ground-truth pose (matrix row 9) —
independent of the node, within the simulation.

**Expected evidence.** Node-published pose (self-report) and simulator pose
(independent-within-sim) reconciled; divergence classified.

**Failure conditions.** Vanian treats a published topic as independent
observation. Vanian reports agreement when the node's odometry has been made to
lie. Vanian assigns provenance above what the source supports.

**Acceptance.** Published telemetry is classified as self-report in every case,
including when it is accurate. Divergence is detected. Simulator truth is never
labelled as a fact about a vehicle.

**What would NOT count as proof.** **Everything here is a fact about a
simulation.** A pass says nothing about any physical vehicle, and describing it
otherwise is the central error this plan exists to prevent.

---

# Phase 4 — Recording and deterministic replay

**Status: BLOCKED — rosbag2 unavailable.**

**Hypothesis.** Evidence recorded during a run re-derives the same conclusions
offline, and the original evidence is unmutated by replay.

**Setup.** Record Phase 3 with rosbag2 alongside Vanian's own evidence. Replay
both. Re-run verification offline.

**Independent observation source.** The recording itself, compared byte-for-byte
before and after.

**Expected evidence.** Identical verification outcomes online and offline;
original evidence files unchanged (digest before == digest after).

**Failure conditions.** Replay produces a different outcome. Replay mutates the
original. Replay reaches a conclusion the live run could not.

**Acceptance.** Deterministic re-derivation; originals provably untouched.

**What would NOT count as proof.** A bag is a faithful recording of *claims*
(matrix row 8). Replaying it re-derives what was claimed, never what happened.

---

# Phase 5 — Adversarial autonomous behaviour

**Status: BLOCKED — RoboFuzz needs ROS 2 and Gazebo.**

**Hypothesis.** Under fuzzed and hostile inputs, Vanian degrades to
`CANNOT_PROVE` and `UNKNOWN` rather than to a confident wrong answer.

**Setup.** RoboFuzz against the Phase 3 system: malformed messages, invalid
states, timing violations.

**Independent observation source.** Simulator ground truth plus host-runtime
observation.

**Expected evidence.** Vanian's classifications across the fuzz campaign, with
the proportion reaching each outcome.

**Failure conditions.** Any input causes an unsupported claim to be upgraded.
Any crash or panic in the evidence path. Any silent coverage gap. Containment
reachable without `Proven`.

**Acceptance.** Degradation is always toward *less* certainty. No path from
anomaly to containment. No panic.

**What would NOT count as proof.** Surviving a fuzz campaign is not surviving an
adversary. RoboFuzz explores malformed input, not a competent attacker with host
access.

---

# Phase 6 — Effect boundary under simulated flight

**Status: BLOCKED — PX4 SITL unavailable; would require Phases 3–5 first.**

**Hypothesis.** Vanian distinguishes a commanded effect, an observed effect, and
a *proven* effect, and refuses the third without a source that can carry it.

**Setup.** PX4 SITL, a commanded mission, MAVLink telemetry, simulator truth.

**Independent observation source.** Simulator ground truth only. MAVLink and PX4
telemetry are self-reports (matrix rows 10, 11).

**Expected evidence.** Every commanded effect classified against what the
simulator did, with the self-report kept separate throughout.

**Failure conditions.** MAVLink or PX4 telemetry treated as independent.
Physical-effect language applied to a simulated effect.

**Acceptance.** No physical-effect claim is produced at all — because no source
present can support one.

**What would NOT count as proof.** SITL is software. **No real vehicle is armed
or moved.** HITL is explicitly out of scope for this plan.

---

# Phase 7 — Physical-effect observation

**Status: BLOCKED — requires instrumented hardware and an external sensor.**

**Hypothesis.** With an external sensor independent of the vehicle, Vanian can
support a claim about physical effect.

**Setup.** Instrumented hardware on a test stand, observed by a sensor outside
the vehicle's trust boundary (matrix row 12).

**Failure conditions.** Any physical-effect claim resting on vehicle-originated
telemetry.

**Acceptance.** Not defined here. This phase requires a safety case, a test
authority, and hardware — none of which is a software decision, and none of
which this document may pre-authorise.

**What would NOT count as proof.** Everything from Phases 1–6. They are all
software observing software.

---

## Where this environment stops

| Phase | Status |
|---|---|
| 1 | **READY** |
| 2 | BLOCKED — kernel lacks `CONFIG_KPROBES` |
| 3 | BLOCKED — no ROS 2 / Gazebo |
| 4 | BLOCKED — no rosbag2 |
| 5 | BLOCKED — no RoboFuzz prerequisites |
| 6 | BLOCKED — no PX4 SITL |
| 7 | BLOCKED — no hardware, no safety case |

One of seven is executable.

Phase 1 passing moves one component of Sniffer Dog from TEST-PROVEN to a
**narrow slice** of REAL RUNTIME-PROVEN: correct reading of one kernel
tracepoint, and correct classification of subject claims against it.

It does not reach REAL AUTONOMOUS-SYSTEM-PROVEN, and no combination of things
runnable in this environment does.
