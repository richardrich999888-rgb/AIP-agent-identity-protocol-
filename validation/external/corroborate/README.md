# Independent-observer corroboration

**Status: executed. Two independently built runtime observers watched the same
kernel over the same window as AIP, and both report no AIP blind spot.**

This is the evidence behind subsection 10a of the RBI technical brief, which
raises the one criticism the rest of the programme cannot answer with more of
our own tests: *every sensor that has so far agreed with this system is a
sensor we built.*

## What was run

| | |
|---|---|
| AIP | `aip-probe` (no key) → `aip-collector` (holds the only key) over the confidential transport |
| Observer 1 | **bpftrace 0.20.2** — independent eBPF implementation on `sched:sched_process_exec` |
| Observer 2 | **auditd 3.1.2** — the kernel audit subsystem, `-S execve` |
| Workload | 75 plain execs, plus the real LangGraph agent when its venv is present |
| Comparison | `aip-corroborate`, which verifies the archive under the anchor **before** comparing anything |

Reproduce: `validation/external/corroborate/run.sh`. Sealed output of the
recorded run is in `results/sealed/`.

## Result

```
bpftrace : 113 agreed, 1 AIP-only, 0 third-party-only   → NO AIP BLIND SPOT
auditd   : 112 agreed, 2 AIP-only, 0 third-party-only   → NO AIP BLIND SPOT
           938 failed execve ATTEMPTS excluded (nothing executed)
```

"AIP-only" is not a defect: the third-party tracers start and stop as processes
of their own and are configured for a narrower scope.

## Independence has two strengths, and they are not equal

- **bpftrace** is an independent *implementation* reading the **same**
  tracepoint AIP's perf sensor reads. It corroborates that AIP faithfully
  reported what that tracepoint emitted. A foreign eBPF gate on that tracepoint
  would blind **both** observers identically, so this does not corroborate
  coverage.
- **auditd** reaches the kernel through a **different subsystem**. A tracepoint
  gate does not blind it. This is the stronger corroboration, and it is why
  auditd is carried alongside bpftrace rather than instead of it.

`aip-corroborate` carries this distinction in its output as
`IndependenceClass`, so the two cannot be read as the same claim.

## Why Falco and Tetragon were not used

They are the first-choice observers named in the brief. Their distribution
channels are not reachable from the build environment: the egress proxy denies
`download.falco.org` and `github.com`, and neither is packaged in the
distribution's own archive. The comparison core is source-agnostic and already
carries a `Falco` variant; an adapter for its JSON output is the only missing
piece. This is stated rather than quietly substituted.

## Two defects this run found — in the harness, not in AIP

Both are recorded because the process of finding them is the reason to trust
the result.

**1. Failed execve attempts were counted as AIP blind spots (275 of them).**
`auditd` audits the execve *syscall* and records every *attempt*: running
`/usr/bin/env true` makes `env` search `$PATH`, and each miss is an execve
returning `ENOENT`. AIP's `sched:sched_process_exec` fires only on a
**successful** exec, which is correct — a failed execve is not an execution and
nothing ran. The first run compared the two classes and reported 275 fabricated
defects against a system behaving exactly correctly. The split was exact: 106
`success=yes` against 106 agreed, and 275 `success=no` with `exit=-2`.
`ExecOutcome` now separates them; the attempts are still counted and reported
as a scope difference, because "auditd sees attempts, AIP sees executions" is a
real difference a reader should know. Locked by
`x15_a_failed_execve_attempt_is_not_an_aip_blind_spot`.

**2. The comparison window ran to the instant of teardown.** The second run
reported exactly one AIP gap: a `/usr/bin/sleep` that auditd recorded **3 ms**
before the window closed. bpftrace missed it too — which is what identified it
as a boundary artefact rather than a gap: it was the harness's own teardown
`sleep`, and AIP batches on an interval, so an execution received milliseconds
before the probe stops has not necessarily reached an attested batch. The
window now closes at the end of the **workload**, with both observers still
running through a settle period, so nothing inside the window can be missed by
them.

Neither fix weakens a verdict. The first stops the tool demanding that AIP
record executions that never happened; the second stops it measuring a flush
race instead of observer agreement. `x16` guards that the exclusion cannot hide
a genuinely missed **successful** exec.

## What this establishes, and what it does not

**Establishes.** AIP's signed evidence contains every execution two
independently built observers recorded inside the window AIP claimed to cover —
one of them reaching the kernel by a different mechanism entirely. AIP's
observations are no longer corroborated only by AIP.

**Does not establish.** It does not make the host kernel trustworthy. Two
observers raise the cost of a consistent lie; they do not eliminate it, and
where both read the same kernel mechanism one gate blinds both. It is also a
single run of ~113 executions over a few seconds on a development virtual
machine — not a soak test, not representative load, and not an institution's
hardware (blocker B8, unchanged).
