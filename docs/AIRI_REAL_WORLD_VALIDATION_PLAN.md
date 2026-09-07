# AIRI real-world validation plan

The plan the experiment in `../validation/airi/` implements. Written to be
falsifiable: every claim it proposes to test names the observation that would
refute it.

## 1. The question

Vanian asserts that it can establish what an AI agent did without asking the
agent. The plan tests one specific consequence of that:

> Given an agent that emits AIRI events and a runtime that executes, can the
> system distinguish what the agent CLAIMED, what AIRI RECORDED, what the
> runtime ACTUALLY did, and what an INDEPENDENT OBSERVER saw — and classify the
> result honestly when those disagree?

Not tested here, and not claimed: anything about physical effect, anything
about a root or kernel adversary, anything about a host other than this one.

## 2. The organising rule

> **The actor should not control the evidence used to judge the actor.**

Everything below follows from it.

- The subject is a real process that emits real signed `AiriEvent`s. Every
  field it writes is a **claim**.
- The observers are separate processes reading kernel facilities the subject
  does not author.
- The harness compares them. It is **not a reconciler**: it constructs no
  `ReconciliationResult`, no `EvidenceStrength`, no `ObservationRecord`, and
  nothing it produces feeds Vanian's engine.

## 3. Roles, and what each is allowed to conclude

| Component | Role | May conclude |
|---|---|---|
| `validation/airi/agent` | subject under test | nothing; it makes claims |
| `validation/airi/observers/audit_observer.py` | independent observer A | what the kernel's audit records say |
| `validation/linux/ftrace_observer.sh` | independent observer B | what the sched tracepoints say |
| `validation/airi/analyze.py` | comparison | where A, B and the claims agree and differ |
| Claude Code | orchestrator | nothing. **It is not a source of proof.** |

## 4. Observers, and the independence each actually has

| Observer | Probe site | Independent of `aip-observe` | Carries argv |
|---|---|---|---|
| linux-audit | `audit_syscall` hook on the syscall path | **mechanism** | yes |
| ftrace-sched | `sched_process_exec` tracepoint | interface only — same tracepoint `aip-observe` samples | **no** |
| Tetragon | kprobe on kernel functions | mechanism, *below* the syscall boundary | n/a |
| A3S Observer | syscall tracepoints + `do_exit` kprobe | overlaps for exec; kprobe part blocked | n/a |
| OpenTelemetry | inside the subject | **none — it is a self-report** | n/a |

Tetragon and A3S are blocked by `# CONFIG_KPROBES is not set`. OTel is blocked
by the network and would be classified `SELF_REPORTED` if it ran. Analyses:
`../validation/external/`.

The two observers that do run are mechanism-independent **of each other** for
process execution, so their agreement is mechanism-diverse corroboration. It is
not proof, and it does not extend to argv: observer B cannot see argv at all,
so every argv-level fact rests on one observer.

## 5. Scenario design

Eighteen scenarios in three groups.

**Subject-side (the agent misbehaves).** AIRI-001 to -009, -012, -013, -014,
-017, -018. The subject executes, over-executes, under-reports, misreports,
executes what it did not commit to, or dies mid-stream.

**Observation-path (the evidence misbehaves).** AIRI-010 delayed delivery,
AIRI-011 duplicated delivery, AIRI-015 observer loss, AIRI-016 two observers
contradicting. The subject behaves exactly as in AIRI-001; the defect is
injected into what the analyser is *given*. Each preserves the untouched
capture beside the modified one and records precisely what was injected.

**Not executable here.** Anything requiring a kprobe-capable kernel, a second
host, or a physical sensor.

## 6. The observation window, and the mistake it exists to avoid

An earlier experiment counted startup events that fell outside its window as
misses. That is a manufactured false failure, and the plan forbids repeating
it.

The window is established **inside the observed stream**:

1. start observer B, then observer A, and wait for A's readiness file;
2. exec a distinctive `WINDOW_OPEN_<nonce>` marker — both observers record it;
3. wait a quiet guard interval;
4. run the subject;
5. wait the guard interval again;
6. exec `WINDOW_CLOSE_<nonce>`;
7. drain observer A until it sees the close marker, stop observer B;
8. analyse.

Both observers' windows are bounded by **the same two marker `execve` calls**,
identified by the pids audit recorded for them — not by each observer's own
markers, which are different events at different instants and produced false
contradictions when used.

Anything outside the window is dropped. **An absence outside the window is not
evidence of non-execution, and an absence inside an unclosed window is not
either**: a run whose window never closes yields `UNKNOWN`, and no divergence
may be asserted from it.

## 7. Ordering

Ordering a claim against an observation must not use clocks. Audit stamps
records with `ktime_get_coarse_real_ts64()`, which advances once per timer
tick, so an audit record can carry a timestamp earlier than a fine-grained
`SystemTime::now()` taken before the syscall.

Instead the subject execs an `AIRIEV_<nonce>_<seq>_<kind>` beacon after each
event it writes. Ordering is then a comparison of two audit serials inside one
observer's stream. The beacon is still the subject's assertion; what it changes
is that the assertion's *position* is recorded by something the subject does
not author.

## 8. Classification vocabulary

`SELF_REPORTED`, `OBSERVED`, `CORROBORATIVE`, `CORROBORATION_ONLY`, `PROVEN`,
`UNKNOWN`, `CANNOT_PROVE`.

`PROVEN` is **unreachable by construction**. Vanian reserves it for facts a
third party recomputes from bytes it holds; an `execve` record is content
measured on the observed host, which host root can forge. The ceiling here is
`OBSERVED`.

Contradictory evidence resolves to `UNKNOWN`. It is not resolved by preferring
whichever observer is convenient.

## 9. How the plan can fail

The harness is only worth its output if its checks can fail. Every scenario
check asserts the property its scenario is named for, and a mutation suite
(`validation/airi/mutate.py`) injects one defect at a time, asserts the bytes on
disk changed, and requires at least one guard scenario to stop reporting PASS.
A mutation that survives is reported as a survivor.

## 10. Status vocabulary

Results are reported using only: `TOOLING_READY`, `ENVIRONMENT_READY`,
`EXPERIMENT_READY`, `EXPERIMENT_EXECUTED`, `EXPERIMENT_PASSED`,
`EXPERIMENT_FAILED`, `INDEPENDENT_OBSERVER_BLOCKED`,
`REAL_WORLD_VALIDATION_PROVEN`.

A tool that installs is `TOOLING_READY`. It is never a validation result.

## 11. Results

`AIRI_INDEPENDENT_OBSERVATION_REPORT.md`.
