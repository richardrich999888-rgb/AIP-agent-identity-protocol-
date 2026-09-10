# Independence matrix

For every candidate evidence source: what it is, whether the subject controls
it, and what it is capable of proving.

The organising principle:

> **The actor should not control the evidence used to judge the actor.**

A source the subject can author, edit, suppress or fabricate is a *self-report*,
whatever it is called and however much telemetry it contains. Self-reports are
admissible as *claims*. They are never admissible as *corroboration of
themselves*.

## Column meanings

- **Controlled by subject** — can the observed workload alter what this source
  says, without compromising anything outside its own trust boundary?
- **Independent of Sniffer Dog** — would a defect in Sniffer Dog's own code
  show up as a disagreement here?
- **Mechanism** — the kernel or system facility the fact originates from.
- **Max provenance** — the strongest Vanian provenance this source can support.
  This column is a *ceiling*, never a grant.

## The matrix

| # | Source | Available here | Controlled by subject | Independent of Sniffer Dog | Mechanism | Max provenance |
|---|---|---|---|---|---|---|
| 1 | **Subject process self-report** (workload's own log/claim) | yes | **fully** | n/a | application code | **self-report — never corroboration** |
| 2 | **Sniffer Dog 2.0** — sched tracepoints via `perf_event_open` | yes | no (unless root) | — it *is* the subject of the test | tracepoint | subject under test |
| 3 | **Sniffer Dog 2.0** — netlink proc connector | yes | no (unless root) | — | netlink connector | subject under test |
| 4 | **Sniffer Dog 2.0** — fanotify / socksend / AF_PACKET / pidfd+procfs | yes | no (unless root) | — | mixed | subject under test |
| 5 | **ftrace tracepoint reader** | **yes** | no (unless root) | **yes — interface only** | **same tracepoint as #2** | corroborates *reading*, not *event* |
| 6 | **Tetragon** (eBPF on kernel functions) | **no** — `CONFIG_KPROBES` unset | no (unless root) | **yes — mechanism** | kprobe + eBPF | would corroborate the *event* |
| 6a | **Linux audit subsystem** via `NETLINK_AUDIT` | **yes** — `CONFIG_AUDITSYSCALL=y` | no (unless root) | **yes — mechanism** | audit syscall hook | **corroborates the *event*, at the syscall boundary** |
| 7 | ROS 2 topic telemetry | no | **yes** — the node publishes it | no | application | **self-report** |
| 8 | rosbag2 recording | no | **yes** — records #7 verbatim | no | application | **self-report, durably stored** |
| 9 | Gazebo simulator ground truth | no | no — the simulator owns physics | yes | simulator | independent *within the simulation only* |
| 10 | PX4 flight-controller telemetry | no | **yes** — the autopilot is the subject | no | firmware | **self-report** |
| 11 | MAVLink message stream | no | **yes** — subject-originated | no | protocol | **self-report in transit** |
| 12 | External physical sensor | no | no | yes | physics | **the only source that could prove physical effect** |

## The rows that matter most

### Rows 7, 8, 10, 11 — robot telemetry is a self-report

This is the correction the mandate demanded and the matrix must not soften.

A ROS 2 node publishing `/odom` is the subject describing its own position. A
rosbag2 file is that description, recorded faithfully — recording a claim
verbatim makes it *durable*, not *true*. PX4 telemetry is the autopilot's
account of the autopilot. MAVLink is a transport for that account.

None of these become independent by being binary, timestamped, high-rate, or
labelled "telemetry". Treating them as independent proof would put the actor
back in control of the evidence used to judge the actor, which is precisely the
failure this whole exercise exists to avoid.

Their correct role is the **left-hand side** of a reconciliation: what the
subject claims. Never the right.

### Row 9 — simulator ground truth, and its exact limit

Gazebo is genuinely independent of a ROS node running inside it: it computes
physics, and the node cannot edit that computation without escaping its own
boundary. This is the strongest robotics source on the list.

Its limit is absolute and easy to forget: **it proves things about the
simulation.** "The simulated vehicle reached the simulated waypoint" is a fact
about Gazebo. It is not a fact about any vehicle. Simulator ground truth may
support statements about *behaviour under simulated conditions* and never
statements about physical effect.

### Row 12 — the only route to physical-effect proof

Nothing else on this list can establish that a physical thing moved. This row is
unavailable here and remains unavailable until there is instrumented hardware
observed by something that is not the vehicle. Until then, no physical-effect
claim is available to Vanian by any path.

### Row 6a — added after row 6 was tested rather than assumed

Rows 5 and 6 were written from a survey of *tracing* facilities. The audit
subsystem is not one, and it is compiled into this kernel. It hooks the syscall
path rather than the `sched_*` tracepoints, assembles records in
`kernel/auditsc.c`, and delivers kernel-formatted text over a netlink unicast
to one registered consumer. Every layer below the event differs from Sniffer
Dog's, so a disagreement is evidence about the event.

This does **not** promote any other row, and it does not raise the ceiling on
anything outside the host: audit observes syscalls. It is also not
root-resistant, and its single-consumer delivery is a real availability
constraint. The full analysis, including a clock-granularity defect it exposed,
is in `../airi/OBSERVER_INDEPENDENCE.md`.

### Rows 5 and 6 — the gap that limits everything runnable here

Row 6 is the instrument that would have made Experiment 1 a test of the
*event*. It is blocked by the kernel, not by policy or effort
(`../external/tetragon/BUILD.md`).

Row 5 is what remains. It is a real cross-check, and it is a cross-check on
Sniffer Dog's *reading of a shared source* — not a second witness. The analysis
is in `../linux/INDEPENDENCE.md`.

**Consequence, as originally written:** the strongest available result is
"Sniffer Dog reads the kernel tracepoint correctly and classifies subject
self-reports correctly against it."

**Revised by row 6a:** an agent's execution claims can be checked against a
mechanism-independent witness at the syscall boundary of this host. That is
strictly stronger, and it is still not real-world validation of an autonomous
system: nothing here observes anything outside the host, and rows 9 and 12
remain unavailable.

## What must never happen to this matrix

- No row may be promoted because a tool was installed.
- No row's "Max provenance" may be raised to make an experiment conclude.
- Rows 7, 8, 10 and 11 may not be reclassified as independent. If a future
  design wants to derive stronger evidence from robot telemetry, it needs a
  *different mechanism* — an attesting flight recorder outside the autopilot's
  trust boundary, say — and that would be a new row, not an edit to these.
- **Availability and independence are different axes.** A source does not
  become more independent by being the only one that runs.

## Reachability of Vanian's evidence classes from here

| Vanian outcome | Reachable in this environment? |
|---|---|
| `CANNOT_PROVE` | yes — and it is the correct default |
| `UNKNOWN` provenance | yes |
| Subject claim vs kernel disagreement detected | yes — via row 5 |
| Independent *event* corroboration | **yes, at the syscall boundary** — via row 6a |
| Autonomous-system behavioural validation | **no** — needs rows 7–9 |
| Physical-effect proof | **no** — needs row 12 |

Three of six are out of reach. That is the honest state of this environment,
and the test plan is built around it rather than around what would be
convenient.
