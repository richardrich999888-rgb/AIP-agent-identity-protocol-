# A3S Observer — evaluation

Phase 4 of the real-world validation mandate.

**This document contained a wrong result and has been corrected.** An earlier
version recorded A3S as BLOCKED because `bpf-linker` failed to compile against
the system LLVM. That was a conclusion drawn from one failed build, not from
the tool. A concurrent experiment
(`../a3s_observer/STATUS.md`) had it working, and the build was then reproduced
here to settle the contradiction rather than defer to either account.

## Status: BUILDS AND RUNS

```sh
rustup toolchain install nightly --component rust-src --profile minimal
export LLVM_SYS_181_PREFIX=/usr/lib/llvm-18 PATH=/usr/lib/llvm-18/bin:$PATH
cargo install bpf-linker --version 0.9.13 --locked   # 0.11.x needs an LLVM newer than 18
cargo +nightly build --release -p a3s-observer-collector
```

Attach result on this kernel:

```
WARN  proc_exit (do_exit kprobe) failed — exit signals unavailable  error=attach kprobe do_exit
INFO  probes attached; streaming  attached=23 total=24  mode=observe
```

23 of 24 probes attach. The one that does not is the `do_exit` kprobe, for the
same reason Tetragon is blocked entirely: `# CONFIG_KPROBES is not set`. Exit
codes and terminating signals are unavailable; everything else works.

| | |
|---|---|
| Repository | `github.com/A3S-Lab/Observer` |
| Commit evaluated | `06105bbf647e0653b92034e597e932a593f8fc12` (2026-08-26) |
| Licence | MIT |
| Carries argv | **yes**, reassembled from kernel fragments |

## Mechanism, and what a comparison against it is worth

From `a3s-observer-ebpf/src/main.rs`, not from the README: exec capture is eBPF
on **syscall and sched tracepoints** — `sys_enter_execve`,
`sched:sched_process_exec`, plus `sys_enter_openat`/`openat2`/`open`/`close`
for files. That is the same tracepoint Sniffer Dog 2.0 samples through
`perf_event_open`.

So for process execution A3S is **interface-independent** of Sniffer Dog, not
mechanism-independent: a disagreement is evidence about one of the two
readings of a shared source. Its one mechanism-diverse probe site, the
`do_exit` kprobe, is the part this kernel refuses.

That distinction survives the correction above. Being installable and being
mechanism-independent are different properties, and the first does not imply
the second.

**Relative to the Linux audit observer** used by this experiment, A3S *is*
mechanism-independent — audit hooks the syscall path in `kernel/auditsc.c`, A3S
reads tracepoints — and it carries argv, which the ftrace reader does not. That
makes it the best available second witness for argv-level facts on this host.

## The interference finding, and a cross-check of it

`../a3s_observer/TRACEPOINT_INTERFERENCE.md` reports that attaching A3S
silently blinds Sniffer Dog 2.0's perf sensors: the kernel gates a tracepoint's
*perf* submission on the return value of any BPF program attached to that
tracepoint, per `trace_event_call` and host-wide
(`perf_trace_run_bpf_submit()`). Sniffer Dog went from 4 exec events to 0 and
reported `"lost":0` while blind.

That explanation makes a testable prediction: observers **not** on the perf
submission path should be unaffected. Tested here, with A3S attached for a full
AIRI-001 run
(`../../traces/airi-a3s-interference/AIRI-001-20260907T154917Z-20877/`):

| Observer | Path | Result with A3S attached |
|---|---|---|
| linux-audit | `audit_syscall` hook → NETLINK_AUDIT | unaffected; recorded the declared argv |
| ftrace-sched | ftrace ring on `sched_process_exec` | unaffected; 9 exec pids corroborated, 0 disagreements |
| A3S | eBPF on the same tracepoint | 73 `ToolExec` events, including the declared argv |

Scenario verdict PASS, classification OBSERVED, cross-observer disagreements
zero.

The prediction holds. **The defect is in Sniffer Dog's choice of interface, not
in the tracepoint**, and an audit-based observer is structurally immune to it.
That is a second, independent line of support for the finding — arrived at by
testing its mechanism rather than by repeating its experiment.

## What this does not establish

A3S was **not** used as an observer in the canonical 18-run set
(`../../traces/airi-final/`), which used audit and ftrace only. No result in
`../../../docs/AIRI_INDEPENDENT_OBSERVATION_REPORT.md` rests on A3S, and the
report's statement that argv-level facts there have a single witness is
accurate for that run set. Adding A3S as a second argv witness is item 2 of the
next-experiment list.
