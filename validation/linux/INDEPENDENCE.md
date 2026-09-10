# What the ftrace reference observer is independent *of*

Read this before treating anything in `../traces/` as corroboration.

## The claim being tested

Vanian's Sniffer Dog 2.0 asserts that it can establish what a process did
without asking the process. The way to test that is to observe the same events
with an instrument the subject does not control, and see whether the two
accounts agree — and, more importantly, whether Sniffer Dog *correctly*
classifies the cases where they do not.

That requires knowing precisely what the second instrument is independent of.
Overstating it is the failure mode this document exists to prevent.

## What Sniffer Dog 2.0 actually uses

From the implementation, not the documentation
(`aip-standalone/aip-observe/src/`):

| Module | Mechanism |
|---|---|
| `sched.rs` + `perf.rs` | `perf_event_open(PERF_TYPE_TRACEPOINT)` on `sched:sched_process_fork` and `sched:sched_process_exec`, `CLOCK_MONOTONIC`, per-CPU ring buffers, record layout read from tracefs at open time |
| `linux.rs` | netlink process-event connector; `pidfd`; kernel socket tables |
| `fanotify.rs` | `fanotify` `FAN_CLOSE_WRITE` |
| `socksend.rs` | `sock_send_length` |
| `wiretap.rs` | `AF_PACKET` header tap |
| `probe.rs` | procfs, read under a `pidfd` anchor |

The relevant row is the first one. **For process fork and exec, Sniffer Dog's
source is the `sched_*` tracepoints.**

## What the ftrace reader uses

The **same `sched_*` tracepoints**, read through the ftrace ring buffer in a
dedicated instance, rendered by the kernel's own `trace_event` print handlers.

## Therefore

```
                    Sniffer Dog 2.0            ftrace reader
  kernel event      sched_process_exec    ==   sched_process_exec   SAME
  kernel probe site tracepoint            ==   tracepoint           SAME
  buffer            perf per-CPU ring     !=   ftrace instance ring DIFFERENT
  reader            aip-observe (Rust)    !=   kernel print handler DIFFERENT
  decoder           own binary decoder    !=   kernel's own format  DIFFERENT
  process           Sniffer Dog           !=   separate reader      DIFFERENT
```

The ftrace reader is **interface-independent** of Sniffer Dog and **not
mechanism-independent** of it.

### What that buys

A disagreement is real signal. If Sniffer Dog reports an exec the kernel's own
rendering does not contain, or renders a `filename` differently, or attributes
an event to a different pid, then Sniffer Dog is wrong — about decoding,
attribution, timing, or the fact itself. These are exactly the defect classes a
self-consistent observer cannot find in itself:

- binary tracepoint record decoding errors (`__data_loc` offset/length maths),
- pid/tid attribution errors,
- timestamp or clock-domain errors,
- silent event loss that Sniffer Dog fails to report as loss,
- fabricated events with no kernel origin at all.

### What it does not buy

Agreement is **not** proof that the event happened. Both instruments read one
kernel tracepoint. Anything that corrupts, suppresses or forges *at or below
that tracepoint* corrupts both identically, and they will agree — confidently
and wrongly. Specifically it cannot detect:

- an event the `sched_*` tracepoints never fire for,
- a root-level subject that disables the tracepoints, starves the buffers, or
  unloads the instrumentation,
- kernel-level compromise of any kind,
- anything about *why* an execution happened, or whether it was authorised.

**A comparison against this instrument cannot upgrade evidence above what one
tracepoint can carry.** It is a cross-check on Sniffer Dog's *reading*, not a
second witness to the *event*.

## The instrument that would have been mechanism-independent

Tetragon. Its process sensors attach eBPF programs to **kernel functions** via
kprobes — a different probe site from the `sched_*` tracepoints, reached
through a different mechanism, decoded by a different project's code. A
disagreement between Tetragon and Sniffer Dog would have been evidence about
the *event*, not merely about the reading of a shared source.

It cannot run here: `# CONFIG_KPROBES is not set` in this kernel. The full
diagnosis is in `../external/tetragon/BUILD.md`.

**This is the single most consequential gap in this environment.** With
Tetragon blocked, no instrument available here observes process execution
through a mechanism Sniffer Dog does not already use. That is a ceiling on what
any experiment run here can conclude, and it is why the test plan stops where
it does.

## A partial improvement that exists and is not yet used

The netlink process-event connector is a genuinely different kernel mechanism
from tracepoints. Sniffer Dog already uses it (`linux.rs`), so a *separate*
connector reader would give mechanism diversity for fork/exec without any
installation.

It is not built here, deliberately. Writing a second observer in this repository
would make the same author responsible for both the subject and the reference —
a weaker version of exactly the problem this exercise exists to avoid. The
ftrace reader escapes that because it renders nothing: the event text is
produced by kernel code, and the script only copies a buffer.

If a connector-based reference is wanted later, it should come from outside
this repository, or its authorship should be recorded as a stated limitation of
every result derived from it.

## Root, and what it does to all of this

A root-privileged subject can disable tracepoints, clear buffers, or kill
readers. That is true of the ftrace reader and it would have been true of
Tetragon-on-host. Neither instrument is a root-compromise-resistant witness,
and nothing in this tree may be described as one.

What the design does provide is that interference is **visible**: a disabled
tracepoint or a cleared buffer produces an absence, and absence is not
non-execution. That is Vanian's own rule and it applies to its instruments too.

## The rule this yields

> An observation corroborated by the ftrace reader has been shown to be
> **correctly read from the kernel tracepoint**. It has not been shown to be
> independently witnessed.

Any result in `../reports/` that claims more than that is wrong, regardless of
how the runs came out.
