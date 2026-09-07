# OBSERVATION-INTEGRITY-001 — experiment plan and results

Status: **THREAT_REPRODUCED and THREAT_CHARACTERIZED.**

This document is both the plan and the record, because the experiment ran. The
expected behaviour was defined before the analysis was written, and the
analyzer's verdict vocabulary encodes it so a run cannot be argued into a
conclusion after the fact.

Companion: `OBSERVATION_INTEGRITY_THREAT_MODEL.md` (the security property and
the attack surface). Harness and raw evidence: `validation/observation_integrity/`.

---

## 1. Question

Can Sniffer Dog 2.0 detect that its own observation capability has been
disabled, blinded, or interfered with?

The experiment does not assume the answer is "yes". The goal is not detection
for its own sake. The goal is to prevent

> healthy observer + zero events  ⟶  "nothing happened"

from being a sound inference when observer integrity is actually unknown.

## 2. Design, and the two ambiguities it must exclude

A subject performs known executions; the observer is then deliberately
interfered with. Five outcomes must be kept apart (mandate §7):

- A. event genuinely absent
- B. event occurred and was observed
- C. event occurred but the observer failed
- D. the observer was actively blinded
- E. observer health cannot be established

Two ambiguities would wreck the experiment if not designed out:

**Lifecycle ordering.** A two-arm test (observer alone, then observer +
interferer) restarts the observer, and a restart is exactly when an observer
legitimately misses events. Excluded by construction: the interference happens
**inside one observer lifetime, with no restart**. One `exp01-recorder` process
runs three phases — BEFORE attach, DURING attach, AFTER detach — and recovery
in the third phase is as important as loss in the second. A one-way failure
would be consistent with the observer merely dying, and the analyzer reports
`ONE_WAY_FAILURE`, not interference, if recovery is absent.

**Ring-buffer overflow.** Excluded by the reported loss counter: overflow
raises `PERF_RECORD_LOST`; this attack does not. A run where loss is nonzero is
reported `SUPPRESSION_WITH_REPORTED_LOSS` (a visible gap), not the silent
finding.

## 3. Observers and roles

| Role | Instrument | Purpose |
|---|---|---|
| Subject under test | `exp01-recorder` → `aip_observe::ProcessTracer` | the production sensor; `perf_event_open` on sched tracepoints |
| Interferer | A3S Observer collector (local build) | eBPF on sched + syscall tracepoints |
| Ground truth | `audit_observer.py` | audit syscall hook, NETLINK_AUDIT; **not on the perf submission path** |

Ground truth is what makes B distinguishable from A: it establishes that the
phase-2 executions really happened, so "the observer saw nothing" cannot be
read as "nothing occurred".

## 4. Arms

| Arm | Interferer attaches to | Isolates |
|---|---|---|
| `none` | nothing | negative control — the harness must not manufacture the signature |
| `both` | fork + exec tracepoints (A3S as shipped) | the raw effect |
| `exec_only` | exec tracepoint only | whether gating is per-tracepoint |
| `fork_only` | fork tracepoint only | the control: exec must survive |

The per-tracepoint arms need a control switch in the interferer. It is a
42-line env-gated patch to the **local** A3S build only
(`validation/observation_integrity/instruments/a3s_control_switch.patch`); it is
not upstreamed and touches nothing in this repository.

## 5. Attribution without a clock

Sniffer Dog's exec record carries `filename` and pids, not argv. Cross-clock
comparison against the harness wall clock is forbidden (it produced a false
result earlier in this programme). So:

- **Exec** is attributed by `filename`: each phase execs its own copy of
  `/bin/true` at a distinct path, and the phase is in the observed record's own
  content.
- **Fork** is attributed by matching the observed `child_pid` against the pids
  the ground-truth observer recorded for the phase.
- The **confirmed-attached window** is fixed in audit's own event order by two
  anchor execs the harness runs immediately after attach and immediately before
  detach; `window_analysis.py` then asks, per exec audit placed inside that
  window, whether the observer under test saw it — matched on pid. No clock is
  used anywhere in the analysis.

## 6. Expected behaviour, defined before the result

| Arm | Expected verdict | Expected per-tracepoint | Expected window result |
|---|---|---|---|
| `none` | `NEGATIVE_CONTROL_CLEAN` | n/a | `NO_ANCHORS` |
| `both` | `INTERFERENCE_REPRODUCED_SILENTLY` | n/a | `TOTAL_SUPPRESSION` |
| `exec_only` | `INTERFERENCE_REPRODUCED_SILENTLY` | `PER_TRACEPOINT_CONFIRMED` | `TOTAL_SUPPRESSION` |
| `fork_only` | `INTERFERENCE_REPRODUCED_SILENTLY` (fork stream) | `PER_TRACEPOINT_CONFIRMED` | `NO_SUPPRESSION` (exec stream intact) |

Any other outcome is a finding about the harness, not the system, and the
vocabulary forces it to say so (`NOT_REPRODUCED`, `ONE_WAY_FAILURE`,
`SUPPRESSION_WITH_REPORTED_LOSS`, `NEGATIVE_CONTROL_DIRTY`,
`INCONCLUSIVE_*`).

## 7. Results

All arms behaved as specified. Canonical evidence:
`validation/observation_integrity/evidence/` (one run per arm; more can be
generated).

```
arm         verdict                          per-tracepoint            window
none        NEGATIVE_CONTROL_CLEAN           NOT_TESTED_IN_THIS_ARM    NO_ANCHORS
both        INTERFERENCE_REPRODUCED_SILENTLY NOT_TESTED_IN_THIS_ARM    TOTAL_SUPPRESSION
exec_only   INTERFERENCE_REPRODUCED_SILENTLY PER_TRACEPOINT_CONFIRMED  TOTAL_SUPPRESSION
fork_only   INTERFERENCE_REPRODUCED_SILENTLY PER_TRACEPOINT_CONFIRMED  NO_SUPPRESSION (exec)
```

Representative phase counts (`both`, 6 execs/phase):

```
phase   sniffdog_exec  sniffdog_fork   audit(truth)   a3s
P1                  6              6              6     0     before attach
P2                  0              0              6     6     during attach
P3                  6              6              6     0     after detach
sniffer dog reported lost: 0
```

Confirmed-attached window, `both`, resolved through audit's shared order:
**15 execs audit placed inside the window (anchors, sleep, tee, date, seq, and
the phase-2 markers) — 0 seen by the observer under test.** Total suppression,
not selective; the events that appeared "seen" in a naive marker-to-marker
interval were in the attach transition and the detach drain, outside the
confirmed window.

### What is established, in the mandated vocabulary

- **PROVEN (this host, this mechanism):** the interference is real, silent
  (loss = 0), per-tracepoint, and total within the confirmed window, with a
  clean negative control and independent ground truth.
- **CODE-PROVEN:** the current health model cannot represent it. `ObserverState`
  reaches `Active` unless `probe_faults` is non-empty, and `probe_faults` is
  fed only by loss > 0, probe-sequence discontinuity, or restart
  (`aip-observe/src/attest.rs::track_probe_stream`, `::state`). The attack
  produces none, so a blinded window is admitted as `Active` and
  `permits_attested_use()` returns true.
- **CORROBORATIVE:** the kernel mechanism (perf submission gated on a BPF
  program's return value, per `trace_event_call`) is the concurrent
  experiment's reading of kernel source, corroborated here by the
  per-tracepoint isolation and the ftrace-survives asymmetry. Not re-derived
  from kernel source on this host.
- **UNKNOWN:** reachability by an unprivileged subject.
- **CANNOT_PROVE:** any claim that Sniffer Dog is secure against this. It is not.

## 8. AIRI and Vanian implications

Reasoned from the code and the evidence; where it is reasoning rather than a
run, it says so. **No code was changed to make any answer come out.**

The question the mandate puts directly:

> Can AIRI safely classify a missing independent observation as "no execution"?

**No.** And the codebase already largely agrees — this finding sharpens where it
does not.

- **AgentExecutionStarted, ModelInvocation*, ExecutionCompleted:** already
  self-reports with no host-observable footprint; classified SELF_REPORTED in
  the AIRI experiment regardless. Unaffected — they never rested on observation.
- **ToolInvocationRequested / ToolExecutionReported / SubprocessExecution:**
  these are the claims that a host observer is supposed to check. The finding
  says the check can be silently disabled. So a *missing* observation for one of
  these must map to OBSERVATION_COVERAGE_UNKNOWN → the reconciler's existing
  `CANNOT_PROVE`, **never** to a "did not happen" / PHANTOM finding — unless
  positive coverage for the window is independently established.
- **ObservationRecord:** its constructor already requires an `AttestedBatch`
  whose observations carry a `SourceMechanism`. The gap is upstream: a batch
  can be attested, contiguous, and loss-free while covering a window in which
  the sensor was gated. The batch is not lying; the coverage inference from its
  cleanliness is too strong.
- **EvidenceCeiling:** unaffected as a type. The finding does not raise any
  ceiling; it warns against treating an `Attested` batch's *silence* as
  evidence of absence. Ceilings bound what presence proves, not what absence
  proves.
- **Reconciliation:** the one place a change would matter. A reconciler that
  concludes "claimed but not observed ⟹ phantom" is unsound while coverage can
  be silently gated. The conservative reading — absence of observation is not
  evidence of non-execution — is Vanian's own stated rule (I8); this finding is
  a concrete case where the rule must hold and shows a path by which a naive
  implementation would violate it.
- **EffectAssessment:** already conservative — a successful call is not proof of
  effect. Unaffected.
- **NEXORA:** consumes reconciler output; inherits whatever the reconciler
  concludes. No direct exposure beyond the above.

**Net:** the finding does not demand a new evidence type. It demands that
"unobserved" fail toward CANNOT_PROVE / COVERAGE_UNKNOWN, which the architecture
already espouses, and that the coverage model stop treating loss-free silence as
positive coverage — the fail-closed change (option J), not a new engine.

## 9. External-observer roadmap

What each stronger observer needs, and none of it obtained by bypassing this
kernel:

| Observer | Needs | Why it is not available here |
|---|---|---|
| **Tetragon** | `CONFIG_KPROBES=y` in the running kernel | `# CONFIG_KPROBES is not set`; requires booting a different kernel — a host change to a Firecracker microVM this session does not control |
| **OBI** | same kprobe support | built, zero spans — its process sensors need kprobes |
| **A3S (full)** | `CONFIG_KPROBES=y` for the `do_exit` kprobe | 23/24 probes attach; only the exit-code kprobe fails, same cause |
| **Audit (stronger use)** | nothing — works now | the recommended second observer; different submission path, held coverage throughout the attack |
| **Hardware-backed** | a hypervisor or hardware witness below the kernel | the only thing that addresses a root/kernel adversary; not present |

The single environmental change that unlocks the most is a kernel with
`CONFIG_KPROBES=y`: it brings Tetragon, OBI, and A3S's exit path, giving a
mechanism-diverse observer *below* the syscall boundary, which is where a
subject manipulating syscall-path instrumentation could still be caught.

## 10. Next experiment

**OBSERVATION-INTEGRITY-002 (design only, not started):** run `aip-observe`'s
**full attest pipeline** (not just `ProcessTracer`) under the same interference,
and record the `SensorHealth` / `ObserverState` / `attested_coverage` it
actually emits for the blinded window. §8 predicts `Active` + covered from the
code; 002 would turn that CODE-PROVEN claim into an EXPERIMENT-PROVEN one, or
refute it. This is the correct next step before any mitigation is chosen,
because it measures the real gap the mitigation must close.

Physical robotics remains deferred: the observation boundary does not yet have a
defensible integrity model, and per the mandate that question comes first.
