# A3S Observer — INSTALLED AND WORKING

| | |
|---|---|
| Repository | `github.com/A3S-Lab/Observer` |
| Version | 0.11.0, HEAD `06105bb`, last commit 2026-08-26 |
| Licence | **MIT** (`LICENSE`) — genuinely open source, single licence, no EE carve-out |
| Language | Rust + Aya eBPF |
| Maintained | yes |
| Linux | yes, built and validated by upstream on 6.8; runs here on 6.18.44 |
| Offline | yes, once built |
| Privileges | root (eBPF load, ring buffers) |
| Modifies AIRI? | **no** — zero instrumentation of the subject |
| Observe-only? | **yes, and structurally so here** — see below |

## Install (executed, not hypothetical)

Its container images live on registries this environment blocks, so it was
built from source.

```sh
git clone --depth 1 https://github.com/A3S-Lab/Observer /tmp/airi_Observer
rustup toolchain install nightly --component rust-src --profile minimal

# bpf-linker must match the host LLVM. LLVM here is 18, and bpf-linker 0.11.1
# needs a newer one and fails to compile; 0.9.13 is the LLVM-18 version.
export LLVM_SYS_181_PREFIX=/usr/lib/llvm-18 PATH=/usr/lib/llvm-18/bin:$PATH
cargo install bpf-linker --version 0.9.13 --locked

cd /tmp/airi_Observer && cargo +nightly build --release -p a3s-observer-collector
```

## Run (observe-only)

```sh
A3S_OBSERVER_JSON=1 ./target/release/a3s-observer-collector > events.ndjson
```

## Attach result on this kernel

```
proc_exit (do_exit kprobe) failed — exit signals unavailable
a3s-observer-collector: probes attached; streaming  attached=23 total=24  mode=observe
```

**23 of 24 probes attached.** The single failure is the `do_exit` **kprobe**,
and `# CONFIG_KPROBES is not set` on this kernel. A3S treats that as a warning
and continues, so the tool is usable — with one named coverage loss:
**process-exit evidence is unavailable**, so no claim about exit status or
termination signal can be independently checked here.

Everything else attaches, because A3S is overwhelmingly tracepoint-based:
28 tracepoints, 2 uprobes, 1 kprobe. `CONFIG_UPROBE_EVENTS=y` and tracepoints
are fully available.

## Why it is a genuinely independent observer here

It observes execution at `syscalls:sys_enter_execve`, confirmed by
`sched:sched_process_exec`. Sniffer Dog 2.0 samples `sched:sched_process_exec`
only. **`sys_enter_execve` is a different probe site**, reached by a different
mechanism (eBPF programs, not perf record decoding), decoded by a different
project's code. That is real mechanism independence — materially stronger than
the ftrace reader, which shares Sniffer Dog's tracepoint.

Observed in the runs: argv (with truncation and reassembly accounting), pid,
ppid, uid, cwd, exe path, boot_id, cgroup, `exec_confirmed`, plus egress with
peer and port — and explicit per-ring `ring_dropped`/`queue_dropped` accounting,
so loss is reported rather than inferred.

## Safety posture

A3S can enforce: deny egress via cgroup-BPF `connect4`, deny open/exec via
fanotify. **None of that is configured, and none of it is reachable from the
binary used here** — the collector's loader contains no cgroup or fanotify
attach path at all, and its heartbeat reports `mode: "observe"`. Enforcement is
a separate, opt-in deployment concern, and it was not built, configured, or
run.

## The important caveat

Running A3S alongside Sniffer Dog **silently blinds Sniffer Dog's perf
tracepoint sensors**. That is not an A3S defect; it is a property of the kernel
and a real blind spot in Sniffer Dog's coverage model.

**Read `TRACEPOINT_INTERFERENCE.md`.** It is the most consequential finding of
this work.
