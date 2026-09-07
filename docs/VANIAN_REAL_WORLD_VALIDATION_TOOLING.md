# Real-world validation tooling for Sniffer Dog 2.0

**Status: EXPERIMENT EXECUTED (Phase 1 only).**

Eleven instruments assessed, one usable. One experiment of seven runnable, run
three times, passing. Nothing here validates Vanian against an autonomous
system, and this document is written so that nobody can read it as though it
does.

---

## 1. The principle this is organised around

> **The actor should not control the evidence used to judge the actor.**

Two consequences shaped every decision below, and both cut against the obvious
reading of the brief.

**Claude is not the trusted evidence source.** The reference instrument used
here renders nothing: `/sys/kernel/tracing` produces the event text with kernel
code, and the script copies a buffer. Where a stronger instrument would have
required writing a second observer in this repository, that was declined —
same author for subject and reference is a weaker form of the same problem
(§5).

**Robot telemetry is not automatically independent proof.** A ROS 2 topic, a
rosbag2 file, PX4 telemetry, a MAVLink stream — these are the *subject
describing itself*. Recording a claim faithfully makes it durable, not true.
They belong on the left of a reconciliation, never the right. This is stated
in the independence matrix and it is not softened anywhere.

## 2. What was installed

| Instrument | Status |
|---|---|
| ftrace tracepoint reader | **READY** — installed, verified, in use |
| Tetragon | built from source; **runtime blocked by the kernel** |
| ROS 2, Gazebo, rosbag2, PX4, RoboFuzz, ROS 2 MCP, Gazebo MCP | **UNAVAILABLE** — no reachable channel |
| MAVLink MCP | **NOT INSTALLED** — by decision (§4) |
| ROBOT.md MCP | **NOT INSTALLED** — by decision (§4) |
| Webots | **NOT PURSUED** — by instruction |

Full per-tool assessment against all ten questions of installation rule A:
`validation/external/TOOL_INVENTORY.md`.

**Nothing was substituted for anything unavailable, and no installation command
was invented.** Every command in `validation/external/tetragon/BUILD.md` was
executed and its output observed.

## 3. Two blockers, both measured

### 3.1 The kernel has no kprobes

Tetragon builds and starts. It discovers BTF, detects features, creates its
maps and ring buffer — then fails loading its mandatory base sensor:

```
attaching 'event_exit_acct_process' failed: creating probe entry on tracefs:
open /sys/kernel/tracing/kprobe_events: no such file or directory
```

From the running kernel's own `/proc/config.gz`:

```
# CONFIG_KPROBES is not set
CONFIG_HAVE_KPROBES=y      <- the architecture could; this kernel was built without
```

Corroborated twice: `/sys/kernel/tracing/` has `uprobe_events` and no
`kprobe_events`; `/sys/bus/event_source/devices/` has a `uprobe` PMU and no
`kprobe` PMU.

Not a permission problem — root, BPF programs loaded, maps created. Not a build
problem — binaries built clean. Not fixable from inside a Firecracker guest.

**Consequence, and it is the most important sentence in this document:** with
Tetragon blocked, **no instrument available here observes process execution
through a mechanism Sniffer Dog does not already use.** That is a ceiling on
everything runnable in this environment (§5).

### 3.2 The robotics stack has no reachable channel

Measured, not assumed:

| Host | Result |
|---|---|
| `packages.ros.org` | blocked |
| `deb.debian.org` | blocked |
| `production.cloudfront.docker.com` | 403 at CONNECT — policy denial |
| `quay.io` | blocked |
| `github.com`, `pypi.org`, `npm`, `crates.io`, `proxy.golang.org` | reachable |

Source is obtainable; a robot runtime is not. `apt` cannot run. Docker image
pulls fail at layer fetch even though the daemon runs — it was started here and
`docker run hello-world` still fails.

Reported rather than routed around, as `/root/.ccr/README.md` requires.

**No partial or hand-assembled ROS was attempted.** A fabricated environment
produces fabricated telemetry, which is worse than none because it invites a
claim.

## 4. Two tools that would have installed, and did not

**MAVLink MCP.** Its PyPI dependencies all resolve. Declined for two
independent reasons: its surface is vehicle *command* — arm, disarm, takeoff,
goto, mission upload, parameter set — which rule B requires to be off by
default, leaving an empty server; and `mavsdk` needs a vehicle or SITL behind
it, and PX4 SITL is blocked, so it would connect to nothing. Installing it
would have put an armed-vehicle control surface into this session in exchange
for zero observational capability.

**ROBOT.md MCP.** npm-installable, read-only, harmless — and a **self-report
source**. It serves a robot's declared capabilities. Adding it would add a
second thing that describes itself, not a second observer.

**No vehicle was armed or moved. There is no vehicle here, and there would have
been no arming if there were.**

## 5. The independence finding

Sniffer Dog 2.0 samples `sched:sched_process_fork` and `sched:sched_process_exec`
through `perf_event_open` (`aip-observe/src/{sched,perf}.rs`).

The ftrace reader reads **the same two tracepoints**.

```
                    Sniffer Dog 2.0          ftrace reader
  kernel event      sched_process_exec  ==   sched_process_exec   SAME
  probe site        tracepoint          ==   tracepoint           SAME
  buffer            perf per-CPU ring   !=   ftrace instance ring DIFFERENT
  decoder           own binary decoder  !=   kernel print handler DIFFERENT
```

It is **interface-independent** of Sniffer Dog and **not mechanism-independent**.

That distinction decides what any experiment here may conclude:

> An observation corroborated by this instrument has been shown to be
> **correctly read from the kernel tracepoint**. It has **not** been shown to be
> independently witnessed.

Detectable: decode errors, pid attribution errors, clock errors, unreported
loss, outright fabrication. Undetectable: anything that corrupts, suppresses or
forges at or below the shared tracepoint — both instruments would agree,
confidently and wrongly.

A netlink-connector reader *would* give mechanism diversity with no
installation. It was not built, deliberately: writing a second observer in this
repository makes the same author responsible for subject and reference. The
ftrace reader escapes that because the kernel authors the event text.

Full analysis: `validation/linux/INDEPENDENCE.md`.
Full matrix (12 sources): `validation/scenarios/INDEPENDENCE_MATRIX.md`.

## 6. Experiment 1 — executed, three runs, PASS

`validation/scenarios/exp01_linux_runtime_observation/`

Three accounts of one execution window: the subject's own log, Sniffer Dog
2.0's live sensor, and the kernel's rendering. The subject lies on purpose —
one execution suppressed from its log, one misreported as a different binary,
one fabricated outright.

| Check | Result |
|---|---|
| A. Sniffer Dog reports no execution the kernel did not | PASS |
| B. No in-window execution missed without reporting loss | PASS |
| C. Fabricated claims left uncorroborated | PASS |
| D. Suppressed executions still observed | PASS |

Three consecutive runs: 19 in-window execs in both accounts each time, zero
reported loss, all four checks holding every time. The suppressed `wc`, the
misreported `basename`/`dirname` pair and the fabricated `sha256sum` were
classified correctly in every run.

Evidence is written once, made read-only, digested before analysis and
re-verified after. `compare.py` is a pure reader and issues no Vanian verdict.

### A harness bug that is worth recording

The first version compared across the whole reference capture and reported two
failures — three binaries apparently "missed" by Sniffer Dog. They were
`exp01-recorder`, `seq` and `tee`, executed **~74 ms before Sniffer Dog's sensor
attached**, including Sniffer Dog's own launch.

The harness had manufactured a coverage gap and then blamed the observer for
it — the same error as reading absence as non-execution, which is the rule
Vanian is most explicit about. Fixed in the harness: both accounts are now
bounded by markers written into the reference capture, `window open` only after
the sensor reports attached. **The assertions were not weakened**, and events
outside the window are still reported — as outside coverage, never as findings.

## 7. Where this leaves the ladder

```
CODE-PROVEN                  ██████████  established previously
TEST-PROVEN                  ██████████  established previously
REAL RUNTIME-PROVEN          ███·······  one narrow slice, this work
REAL AUTONOMOUS-SYSTEM-      ··········  not started, not startable here
  PROVEN
```

Experiment 1 establishes one narrow thing about one component: **Sniffer Dog
reads one kernel tracepoint correctly, and correctly classifies subject
self-reports against it.** That is worth having and it is a slice, not the
rung.

| Phase | Status |
|---|---|
| 1 Independent Linux runtime observation | **EXECUTED, PASS ×3** |
| 2 Mechanism-independent corroboration | BLOCKED — no kprobes |
| 3 Autonomous self-report vs simulator truth | BLOCKED — no ROS 2 / Gazebo |
| 4 Recording and deterministic replay | BLOCKED — no rosbag2 |
| 5 Adversarial autonomous behaviour | BLOCKED — no RoboFuzz prerequisites |
| 6 Effect boundary under simulated flight | BLOCKED — no PX4 SITL |
| 7 Physical-effect observation | BLOCKED — no hardware, no safety case |

## 8. What Vanian may and may not now say

**May say.** That Sniffer Dog's process-exec observations were compared against
the kernel's own rendering on a live 6.18 kernel, over a delimited coverage
window, across three runs, and matched exactly with no unreported loss; and
that fabricated, suppressed and misreported subject claims were each classified
correctly.

**May not say — none of this is established:**

- that Sniffer Dog independently *witnessed* any execution (shared tracepoint);
- anything about robots, autonomous systems, vehicles or physical effects;
- anything about resistance to a root-privileged subject;
- that installing tools validated anything;
- that Vanian is "validated in the real world".

## 9. The nine questions

1. **Which tools were installed?** The ftrace tracepoint reader. Tetragon was
   built but cannot run. Nothing else.
2. **Which were unavailable, and why?** ROS 2, Gazebo, rosbag2, PX4, RoboFuzz
   and the two ROS-dependent MCP servers — no reachable distribution channel
   (§3.2). Tetragon — kernel without `CONFIG_KPROBES` (§3.1).
3. **What was deliberately not installed?** MAVLink MCP (control surface, no
   target) and ROBOT.md MCP (self-report, not observation). Webots, by
   instruction. §4.
4. **Was anything substituted?** No.
5. **What independence does the available instrument provide?** Interface
   independence from Sniffer Dog; **not** mechanism independence. §5.
6. **Was an experiment executed?** Yes — Experiment 1, three times, all PASS. §6.
7. **Was any production Vanian semantics changed?** No. See §10.
8. **Is Sniffer Dog 2.0 validated in the real world?** **No.** One narrow slice
   of one component was exercised against a live kernel. §7, §8.
9. **What would unblock the rest?** For Phase 2, a host with `CONFIG_KPROBES=y`
   — the Tetragon build recipe already works. For Phases 3–6, an egress
   allowlist entry for `packages.ros.org` and `deb.debian.org`, or for the
   Docker Hub layer host, or a pre-provisioned ROS 2 + Gazebo image. For Phase 7,
   instrumented hardware, an external sensor and a safety case — none of which
   is a software decision.

## 10. What was not touched

No file under `aip-*` was modified by this work. Verifiable from the diff.

Specifically unchanged: provenance definitions, `EvidenceCeiling`,
`ObservationRecord` trust semantics, `EffectAssessment`, NEXORA authority,
identity / authority / delegation, independent-observation requirements, and
`UNKNOWN` / `CANNOT_PROVE` behaviour.

No second Reconciliation authority and no second NEXORA verifier was created.
`compare.py` deliberately issues no verdict for exactly this reason.

Everything new lives under `validation/`, nothing in `aip-*` depends on it, and
the instrument driver carries its own `[workspace]` so that the production
workspace manifest — whose members are listed explicitly so new crates are
intentional — is untouched.

Skill 24 was not started. Nothing was promoted. `main` was not modified.

---

## The rule this document exists to enforce

> Do not confuse "Claude can observe the test environment" with "Vanian has
> independently proven the autonomous system's behaviour."

Claude can observe this test environment. Vanian has proven nothing about any
autonomous system, and this environment cannot let it.
