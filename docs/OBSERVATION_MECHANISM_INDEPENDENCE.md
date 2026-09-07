# Observation mechanism independence

The finding in `docs/OBSERVATION_INTEGRITY_REQUIREMENTS.md` is, at bottom, a
statement about independence: two tools that appear to be separate observers
were not independent, because they depended on the same kernel submission path,
and one could close it for both. This document works out, for each mechanism
Vanian could use or has used, what it actually depends on and what it can and
cannot witness about the others.

> **The rule this establishes.** Two tools consuming the same underlying kernel
> tracepoint are **not** independent observers, however different their user-space
> code. Independence is a property of the kernel path, not of the process.

## The mechanisms

| Mechanism | Kernel path | Used by | Notes |
|---|---|---|---|
| perf on tracepoint | `perf_event_open(PERF_TYPE_TRACEPOINT)` → `perf_trace_run_bpf_submit()` → perf ring | **Sniffer Dog 2.0** (`sched.rs`, `socksend.rs`, `sockstate.rs`) | submission gated by any BPF prog on the tracepoint |
| ftrace on tracepoint | tracefs ring via `trace_event_raw_event_*` | validation ftrace reader | same tracepoint, **different submission path** — not BPF-gated |
| eBPF on tracepoint | BPF program attached to the tracepoint | A3S Observer, OBI | the thing that does the gating |
| eBPF on kprobe | BPF program on a kernel function | Tetragon, A3S (`do_exit`), OBI | different probe site; **unavailable here** (`# CONFIG_KPROBES is not set`) |
| eBPF on uprobe | BPF program on a userspace symbol | A3S (`SSL_*`), OBI | userspace attach; available here |
| netlink proc connector | `NETLINK_CONNECTOR` / `CN_IDX_PROC` | Sniffer Dog (`linux.rs`) | kernel-pushed fork/exec/exit, **not tracepoint, not BPF-gated** |
| audit subsystem | `NETLINK_AUDIT`, `kernel/auditsc.c` syscall hook | validation audit observer (sibling work) | **mechanism-independent of the tracepoint path**, compiled in here (`CONFIG_AUDITSYSCALL=y`) |
| procfs poll | `/proc/<pid>/*` reads | Sniffer Dog (`probe.rs`) | polled snapshot; races; root-forgeable content |
| fanotify | `fanotify` FS event queue | Sniffer Dog (`fanotify.rs`), A3S (fileguard) | FS events; own queue, own loss mode |
| AF_PACKET | `packet_rcv` on a socket | Sniffer Dog (`wiretap.rs`) | link-layer copy; independent of tracepoints |
| external host observation | off the observed host entirely | (none yet) | the only path outside the host's own kernel |

## Pairwise: can one interfere with another, and can it tell?

"Interfere" = can mechanism A cause mechanism B to miss events. "Detect" = can
B tell that it happened.

| | can it blind perf-tracepoint? | detected by perf-tracepoint? |
|---|---|---|
| eBPF-on-same-tracepoint | **yes** — the finding | **no**, not from loss accounting |
| ftrace-on-same-tracepoint | no (read-only reader) | — |
| netlink connector | no | — |
| AF_PACKET | no | — |
| kprobe eBPF | no (different site) | — |

And the converse — what can *witness* an event that the gated perf tracepoint
missed:

| Witness mechanism | Independent of the perf-tracepoint gate? | Basis |
|---|---|---|
| ftrace on the same tracepoint | **partly** | different submission path, so it still fires — but same probe site, so a probe-site-level attack blinds both |
| netlink proc connector | **yes** | entirely different kernel facility; not a tracepoint |
| kprobe eBPF (Tetragon) | **yes** | different probe site and mechanism — but blocked on this kernel |
| AF_PACKET | for network egress only | different subsystem |
| external host observation | **yes, fully** | not on the observed host's kernel at all |

## Per-mechanism assessment

For each: underlying mechanism, the common kernel dependency that limits its
independence, whether it can interfere with or detect interference in others,
whether it yields independent evidence, and the maximum evidence classification
it can support **on its own**.

### Sniffer Dog 2.0 (perf on tracepoints)
- **Mechanism.** `perf_event_open` on `sched_process_{fork,exec}`,
  `sock_*`, sampled per-CPU.
- **Common dependency.** The tracepoint's `perf_trace_run_bpf_submit()` gate.
  Any BPF program on the same tracepoint sits upstream of it.
- **Interferes with others?** No — it is a passive reader.
- **Detects interference?** No, not the BPF gate; yes, ordinary loss.
- **Independent evidence?** Of the *kernel event*, yes — against a userspace
  self-report. Not against another perf/tracepoint consumer of the same
  tracepoint.
- **Max classification alone.** `Attested` at best (content-derived facts are
  ceilinged below `Proven` by `EvidenceCeiling`); and only when
  `OBSERVATION_ACTIVE` holds. A single tracepoint is not `Proven`.

### A3S Observer (eBPF on tracepoints + uprobes + one kprobe)
- **Mechanism.** BPF programs on `sys_enter_execve`, `sched_process_exec`,
  `sys_enter_connect`, etc.
- **Common dependency.** Shares tracepoints with Sniffer Dog, and its programs
  are what gate them.
- **Interferes with others?** **Yes** — this is the finding. Its
  `sched_process_exec` program returning 0 blinds every perf reader of that
  tracepoint.
- **Detects interference?** It would not detect *another* tool gating a
  tracepoint it does not itself gate.
- **Independent evidence?** Of exec via `sys_enter_execve`, yes — a genuinely
  different probe site from Sniffer Dog's `sched_process_exec`.
- **Max classification alone.** `Attested`. Being eBPF does not raise the
  ceiling.

### Tetragon (eBPF on kprobes)
- **Mechanism.** BPF on kernel functions.
- **Common dependency.** `CONFIG_KPROBES`, absent here.
- **Interferes / detects.** Different site; would be a strong
  mechanism-independent cross-check if it ran.
- **Independent evidence?** Yes, of the *event*, via a probe site neither
  Sniffer Dog nor ftrace uses.
- **Max classification alone.** `Attested`. **Unavailable on this kernel.**

### ftrace reader
- **Mechanism.** tracefs ring on the same `sched_*` tracepoints.
- **Common dependency.** The tracepoint (probe site) — but **not** the BPF
  submission gate, which is why it kept working in the reproduction while
  Sniffer Dog went dark.
- **Interferes?** No.
- **Detects interference?** Partially — it detects the *perf-gate* form of the
  finding (it survives it), so a perf-vs-ftrace disagreement is a positive
  signal that the perf path is gated. It does **not** survive a probe-site or
  kernel-level attack.
- **Independent evidence?** Interface-independent of Sniffer Dog, not
  mechanism-independent — same probe site.
- **Max classification alone.** Corroborates Sniffer Dog's *reading*, not the
  *event*. Below `Attested` on its own.

### perf_event (as a facility)
Covered by Sniffer Dog; the facility's independence is exactly the tracepoint
gate story above.

### eBPF (as a facility)
The double edge: it is the strongest on-host observation facility and the one
that can silently disable the others. Independence between two eBPF observers
requires *different probe sites*, not merely different programs.

### procfs
- **Mechanism.** Polled `/proc` reads.
- **Common dependency.** The kernel's `/proc` presentation, root-forgeable.
- **Independent evidence?** Weak — content is forgeable by root, and polling
  races miss short-lived processes entirely.
- **Max classification alone.** `Heuristic`/`Correlated`. Never a sole basis.

### fanotify
- **Mechanism.** FS event queue.
- **Common dependency.** Its own queue and overflow mode (`FAN_Q_OVERFLOW`),
  independent of the tracepoint gate.
- **Interferes with tracepoints?** No — different subsystem.
- **Independent evidence?** Of filesystem effects, yes, and independent of the
  exec tracepoint gate. It is a genuinely separate path for the file-write
  event class.
- **Max classification alone.** `Attested` for FS events.

### netlink proc connector
- **Mechanism.** Kernel-pushed process events over netlink.
- **Common dependency.** None with the tracepoint gate — **this is the key
  point**. It is a different kernel facility for the *same event class*
  (fork/exec/exit) that Sniffer Dog already consumes.
- **Interferes?** No.
- **Detects interference?** A netlink-vs-perf disagreement on exec would expose
  the tracepoint gate directly, with no new dependency and no new tool.
- **Independent evidence?** Yes, of process lifecycle, via a path a
  tracepoint-gating attacker does not touch. Its own loss signal is `ENOBUFS`.
- **Max classification alone.** `Attested`. **Sniffer Dog already reads it
  (`linux.rs`)** — so mechanism diversity for exec is already in the codebase,
  unused for this purpose.

### external host observation
- **Mechanism.** Observation from outside the observed host.
- **Common dependency.** None with the host kernel.
- **Independent evidence?** The only mechanism independent of a root or
  kernel-module compromise of the observed host.
- **Max classification alone.** The only path that could support `Proven`
  against a host-level adversary — and it does not exist in Vanian yet.

## What this means for `PROVEN`

The AIRI experiment paired **A3S (eBPF on `sys_enter_execve`) + ftrace (ftrace
ring on `sched_process_exec`)** and called an exec `PROVEN` when both agreed.
This document sharpens what that was worth:

- A3S and ftrace are on **different probe sites** (`sys_enter_execve` vs
  `sched_process_exec`) reached by **different mechanisms** (BPF vs ftrace
  ring). That is real mechanism independence, and it survives the *perf-gate*
  form of the finding.
- It does **not** survive a probe-site-level or kernel-level attack, and A3S
  itself, being the eBPF actor, is the thing that gates tracepoints. So the
  pairing is independent against a `CAP_PERFMON` or accidental-interference
  adversary, and not against a `CAP_BPF` adversary who targets both sites, nor
  against root.

Two in-tree cross-checks share no dependency with the perf tracepoint gate and
would each make the specific finding visible with no new trust anchor:

- The **netlink proc connector** — Sniffer Dog already reads it (`linux.rs`),
  it observes the exact fork/exec/exit class the finding suppresses, and it is
  a different kernel facility.
- The **audit subsystem** (`NETLINK_AUDIT`) — established as mechanism-independent
  of the tracepoint path and verified usable on this kernel by the concurrent
  AIRI observer work; its full analysis, including a clock-granularity defect it
  exposed, is in `validation/airi/OBSERVER_INDEPENDENCE.md`. It hooks the
  syscall exit path, not the `sched_*` tracepoints, so a disagreement is
  evidence about the *event*, not about a reading of a shared source — the same
  property Tetragon would have provided, on a facility that is actually present
  here.

Requiring perf-and-(connector|audit) agreement for exec would surface the
finding directly. The limits of both — still on-host, still defeated by root or
a kernel compromise — are in the decision record.
