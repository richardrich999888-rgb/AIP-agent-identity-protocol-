# Finding: an attached eBPF program silently blinds Sniffer Dog's perf sensors

**Severity: high. Not a defect in A3S Observer. A blind spot in Sniffer Dog
2.0's coverage model, found by putting it next to an independent observer.**

This is the headline result of AIRI-INDEPENDENT-OBSERVATION-001, and it is the
kind of result the exercise existed to produce: it was invisible to Vanian's
own test suite, because Vanian's own test suite is written by the same people
who wrote Vanian.

## What was observed

Running A3S Observer and Sniffer Dog 2.0 at the same time, Sniffer Dog stopped
seeing `exec` events entirely — and reported **zero loss** while doing so.

Isolated with a two-arm test, same host, same workload (`/usr/bin/wc`,
`/bin/true`):

| Arm | Sniffer Dog exec events |
|---|---|
| A — Sniffer Dog alone | **4** |
| B — Sniffer Dog with A3S Observer running | **0** |

And within a single experiment window, the three observers disagreed in a very
specific pattern:

| Observer | Path | Saw `/usr/bin/wc`? |
|---|---|---|
| A3S Observer | eBPF on `syscalls:sys_enter_execve` + `sched:sched_process_exec` | **yes** |
| ftrace | ftrace ring on `sched:sched_process_exec` | **yes** |
| Sniffer Dog 2.0 | `perf_event_open` on `sched:sched_process_exec` | **no** |

Sniffer Dog's summary line for that window:

```json
{"kind":"summary","events":2,"lost":0}
```

Two kernel-thread spawns, no execs, **no loss reported**.

## Why

A3S attaches a BPF program to `sched:sched_process_exec`
(`a3s-observer-ebpf/src/main.rs`, `track_process_exec`). That program returns
`0` on every path — it does its own work through its own ring buffer and has
no reason to return anything else.

The kernel gates a tracepoint's *perf* submission on the return value of any
BPF program attached to that tracepoint, in `perf_trace_run_bpf_submit()`. The
gate is keyed on the `trace_event_call` — that is, **per tracepoint, host-wide**
— not per perf event. So when any BPF program attached to `sched_process_exec`
returns 0, the sample is dropped for **every** `perf_event_open` consumer of
that tracepoint.

The ftrace path (`trace_event_raw_event_*`) is a different submission path and
is not gated by the BPF return value. That asymmetry is what makes the
diagnosis certain rather than plausible: in the same window, the ftrace reader
kept working while the perf reader went silent, and the only thing that
distinguishes them is the BPF-gated perf submission.

## Why it matters to Vanian

The interference itself is a nuisance. The security consequence is not.

**Any process that can load a BPF program can silently blind Sniffer Dog's
tracepoint sensors**, by attaching a no-op program that returns 0 to the
tracepoints Sniffer Dog samples. It needs `CAP_BPF` (or `CAP_SYS_ADMIN`), it
does not need to touch Sniffer Dog, and it leaves Sniffer Dog reporting healthy.

Sniffer Dog's loss accounting cannot see it. That accounting detects **ring
buffer overrun** — the kernel telling the reader "I dropped N records". This is
not overrun. The records are never generated for that consumer at all, so
there is nothing to count, and `lost` stays 0.

### What Vanian gets right anyway

Vanian's `CANNOT_PROVE` default and its rule that **absence of observation is
never evidence of non-execution** mean this does not produce a *false verdict*.
A blinded Sniffer Dog produces silence, and silence correctly degrades to
"cannot say". `aip_airi::corroborate` returns `NotEvaluated`/`Uncorroborated`,
never `Corroborated`. The failure direction is toward less certainty, which is
the design working.

### What is actually wrong

**The coverage claim.** `aip-observe`'s health model distinguishes `ACTIVE`
from `DEGRADED` so that a verifier knows which windows are covered. Under this
attack a sensor is `ACTIVE`, reports no loss, and is covering nothing. A
verifier that asks "was the window covered?" gets `yes` and is wrong.

That is a real gap between an asserted property and an enforced one:

> `I5` — independent observation. Independence assumed the observer's *own*
> trust boundary. It did not account for a third party silently gating the
> observer's evidence path from inside the kernel.

## What was NOT done about it

Nothing. This is validation work, and the mandate is explicit that production
security semantics are not to be changed here. No `aip-*` file was modified.

The finding is recorded so that a decision can be made deliberately, by people,
in a change that carries its own tests.

## Directions a fix might take — none implemented, none endorsed

Recorded as analysis, not as a plan:

1. **Detect the gate.** Enumerate BPF programs attached to the tracepoints a
   sensor depends on (`bpf_prog_query` / `perf_event_query_bpf`) at sensor
   open and periodically. A foreign program on a sampled tracepoint is a
   coverage fact and could drive `DEGRADED`.
2. **Liveness canary.** Emit a known exec at a known cadence and require the
   sensor to observe it. Failing the canary is positive evidence of blindness,
   as against the absence of evidence that this attack produces.
3. **Diversify the path.** Sniffer Dog already reads the netlink process-event
   connector, which is not BPF-gated. Requiring agreement between the perf and
   connector paths would make single-path suppression visible.
4. **Do nothing, and document the limit.** Defensible if the threat model
   already excludes an adversary with `CAP_BPF` — but that must then be written
   down, because the current documents do not say it.

Option 4 is not free: several documents in this repository describe Sniffer Dog
as establishing what happened without trusting the subject. A subject with
`CAP_BPF` can prevent that, and the claim needs the qualifier either way.

## Consequence for the experiment

A3S Observer and Sniffer Dog 2.0 **cannot both observe `sched_process_exec` at
once**. The harness therefore records which sources were genuinely live, and
the correlator excludes a suppressed source from the independent set instead of
reading its silence as "saw nothing" — that misreading is the exact error this
whole exercise exists to prevent.

The mechanism-independent pair actually used in the runs is therefore
**A3S (eBPF on `sys_enter_execve`) + ftrace (ftrace ring on
`sched_process_exec`)**, which coexist without interference.

## Reproducing

```sh
# arm A — alone
exp01-recorder /tmp/sd_alone.jsonl 5000 &
sleep 1; /usr/bin/wc -c /etc/hostname >/dev/null; /bin/true; wait
grep -c '"kind":"exec"' /tmp/sd_alone.jsonl      # -> 4

# arm B — with A3S attached
A3S_OBSERVER_JSON=1 a3s-observer-collector >/dev/null 2>&1 &
sleep 4
exp01-recorder /tmp/sd_with.jsonl 5000 &
sleep 1; /usr/bin/wc -c /etc/hostname >/dev/null; /bin/true; wait
grep -c '"kind":"exec"' /tmp/sd_with.jsonl       # -> 0
```

Kernel 6.18.44-fc-v24, x86_64, root.
