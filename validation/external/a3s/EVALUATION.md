# A3S Observer — evaluation

Phase 4 of the real-world validation mandate. Assessed as a candidate
independent observer for the AIRI experiment.

## What it is

| | |
|---|---|
| Source | `github.com/A3S-Lab/a3s-observer` |
| Commit evaluated | `06105bbf647e0653b92034e597e932a593f8fc12` (2026-08-26) |
| Licence | MIT |
| Language | Rust, eBPF via `aya` |
| Crates | `a3s-observer-ebpf` (kernel side), `a3s-observer-collector`, `a3s-observer-common` |

## Verdict: BLOCKED, and it would not have been mechanism-independent anyway

Two separate findings. The second matters more than the first.

### 1. It does not build here

`a3s-observer-ebpf/rust-toolchain.toml` pins the nightly channel and requires
the `rust-src` component; `bpf-linker` fails to compile against the system
LLVM in this image. Neither is a defect in A3S — it is a toolchain the
environment does not have and cannot fetch (`apt` and crates that need a
nightly `rust-src` are unreachable from this network).

### 2. Its process instrumentation overlaps Sniffer Dog's

From `a3s-observer-ebpf/src/main.rs`, not from the README: the file-and-exec
path is built on **syscall tracepoints** — `sys_enter_openat`,
`sys_enter_openat2`, `sys_enter_open`, `sys_enter_close`, plus `sched_*`
tracepoints. That is the same mechanism class Sniffer Dog 2.0 already reads
through `perf_event_open(PERF_TYPE_TRACEPOINT)`.

Its one genuinely different probe site is a **`do_exit` kprobe**
(`main.rs:1834`), for process exit codes and terminating signals. That is
exactly the mechanism this kernel does not have:

```
$ zgrep CONFIG_KPROBES /proc/config.gz
# CONFIG_KPROBES is not set
```

So even with a working toolchain, the part of A3S that would have added
mechanism diversity is the part this kernel refuses, and the part that would
have run reads what is already read.

## What this does and does not mean

A3S is not being judged as a product. The question asked of it was narrow:
*would a disagreement between A3S and Sniffer Dog be evidence about the event,
or only about one reading of a shared source?* For process execution on this
kernel, the answer is the latter.

**Installing it successfully would not have produced a validation result.** It
is recorded here as evaluated and blocked, and no claim in
`docs/AIRI_INDEPENDENT_OBSERVATION_REPORT.md` rests on it.

## What was used instead

The Linux audit subsystem, which is compiled into this kernel, hooks the
syscall path rather than the tracepoints, and delivers over `NETLINK_AUDIT`.
See `../../airi/OBSERVER_INDEPENDENCE.md`.
