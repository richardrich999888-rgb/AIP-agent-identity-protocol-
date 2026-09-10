# What the audit observer is independent *of*

Read this before treating anything in `../traces/airi-final/` as corroboration.
It is the companion to `../linux/INDEPENDENCE.md`, and it revises that
document's central conclusion.

## What the prior analysis concluded

`../linux/INDEPENDENCE.md` states:

> With Tetragon blocked, no instrument available here observes process
> execution through a mechanism Sniffer Dog does not already use. That is a
> ceiling on what any experiment run here can conclude.

That was correct about Tetragon and incomplete about the kernel. It surveyed
tracing facilities — tracepoints, kprobes, eBPF — and did not consider the
audit subsystem, which is not a tracing facility and is compiled in here.

## The probe, verified rather than assumed

```
$ zgrep -E 'CONFIG_AUDIT(SYSCALL)?=' /proc/config.gz
CONFIG_AUDIT=y
CONFIG_AUDITSYSCALL=y
```

A `NETLINK_AUDIT` socket answers `AUDIT_GET`, accepts an
`-a always,exit -F arch=b64 -S execve` rule, and delivers SYSCALL (1300),
EXECVE (1309), PATH (1302), CWD (1307), PROCTITLE (1327) and EOE (1320)
records. The transcript of that probe is the observer itself
(`observers/audit_observer.py`); every run writes the records it received.

Verdict: **AUDIT_MECHANISM_USABLE**.

## Mechanism comparison

```
                     Sniffer Dog 2.0             this observer
  kernel event       process exec            ==  process exec          SAME
  probe site         sched_process_exec      !=  audit_syscall_exit    DIFFERENT
                     tracepoint                  syscall hook
  kernel subsystem   kernel/trace            !=  kernel/auditsc.c      DIFFERENT
  assembly           binary tracepoint rec.  !=  kernel text record    DIFFERENT
  delivery           perf per-CPU ring       !=  NETLINK_AUDIT unicast DIFFERENT
  decoder            aip-observe's own       !=  kernel's own format   DIFFERENT
  process            Sniffer Dog             !=  separate reader       DIFFERENT
```

Every row below the event differs. For process execution this observer is
**mechanism-independent** of Sniffer Dog, which the ftrace reader is not.

### What that buys, precisely

A disagreement is evidence about the **event**, not merely about one reading of
a shared source. Specifically, this observer can detect what the ftrace reader
cannot:

- an execution the `sched_*` tracepoints do not fire for, or that Sniffer Dog
  drops between the tracepoint and its own decoder,
- a subject that manipulates the perf ring or the tracepoint enable state
  without also manipulating audit,
- fabricated events with no kernel origin in *either* subsystem.

### What it still does not buy

- **Not root-resistant.** Root can `auditctl -e 0`, delete rules, or kill this
  process, exactly as root can disable tracepoints. Interference produces an
  *absence*, and absence is not non-execution — that is Vanian's own rule and
  it applies to its instruments.
- **Not kernel-compromise-resistant.** A compromised kernel defeats audit and
  Sniffer Dog identically.
- **Not a physical-effect witness.** It observes syscalls. Nothing here says
  anything about the world outside the host.
- **Single consumer.** Audit delivers to exactly one registered pid. If
  anything else on the host consumes audit, this observer refuses to run
  rather than contend for the socket. That is a real availability constraint on
  any production use.

## Two authorship caveats that must not be softened

1. **The same author wrote the subject and this observer.** That is the
   weakness `../linux/INDEPENDENCE.md` names, and it is not removed by the
   mechanism being different. It is mitigated only by the observer rendering
   nothing of its own: `kernel_record` in the output is the bytes the kernel
   produced, and every field the analysis reads is parsed from that text. It is
   not eliminated. A result derived from this observer carries that as a stated
   limitation.

2. **The beacon is the subject's own assertion.** Ordering a claim against an
   execution uses `AIRIEV_<nonce>_<seq>_<kind>` markers the *subject* execs. The
   subject chooses when to run them. The beacon does not make a claim true; it
   places the claim's position into a channel the subject does not author, so a
   subject emitting events in one order and beacons in another is caught by the
   disagreement rather than by trusting either.

## The clock finding

The kernel stamps audit records with `ktime_get_coarse_real_ts64()`, which
advances once per timer tick. An audit record can therefore carry a millisecond
timestamp **earlier** than a fine-grained `SystemTime::now()` taken before the
syscall ran. In this experiment that produced a 2 ms inversion: an execution
appeared to precede a claim that in fact preceded it.

Two consequences, both load-bearing:

- **Audit timestamps must not be used to order a claim against an
  observation.** They are recorded (`kernel_ms`) and used for nothing else.
  Ordering uses the audit **serial**, a monotonic kernel counter, so the
  comparison happens entirely inside one observer's stream with no clock in it.
- More generally, any future reconciliation that compares an agent-supplied
  timestamp against an observer-supplied one across subsystems must state the
  granularity of both. Vanian does not currently do this anywhere, and this is
  a real gap for a *future* design decision — it is not a defect in the shipped
  trust semantics, which do not perform such a comparison.

## The rule this yields

> An execution corroborated by this observer has been independently witnessed
> **at the syscall boundary of this host**, by a kernel subsystem Sniffer Dog
> does not read. It has not been shown to have had any effect outside that
> host, and it has not been shown to be resistant to a root or kernel
> adversary.

Any statement in `../../docs/AIRI_INDEPENDENT_OBSERVATION_REPORT.md` claiming
more than that is wrong, regardless of how the runs came out.
