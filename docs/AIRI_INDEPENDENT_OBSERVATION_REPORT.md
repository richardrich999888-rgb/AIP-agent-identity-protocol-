# AIRI independent observation report

Experiment `AIRI-INDEPENDENT-AGENT-OBSERVATION-001`.

**Validation status: EXPERIMENT_PASSED.**

Not `REAL_WORLD_VALIDATION_PROVEN`. What was demonstrated is bounded, and
section 15 states the bound precisely.

---

## 1. Objective

Determine whether the AIRI/Sniffer Dog accountability chain can distinguish
four things that are routinely conflated:

- what an agent **claimed**,
- what AIRI **recorded**,
- what the runtime **actually did**,
- what an **independent observer** saw,

and classify the result honestly — `OBSERVED`, `CANNOT_PROVE` or `UNKNOWN` —
when those accounts disagree.

The organising rule throughout: *the actor should not control the evidence used
to judge the actor.*

## 2. Environment

| | |
|---|---|
| Kernel | `6.18.44-fc-v24` (Firecracker microVM) |
| `CONFIG_AUDIT` / `CONFIG_AUDITSYSCALL` | `y` / `y` |
| `CONFIG_KPROBES` | **not set** |
| `CONFIG_BPF_SYSCALL` / `CONFIG_DEBUG_INFO_BTF` | `y` / `y` |
| Privilege | root (uid 0) |
| Git commit of the run set | `f5999bbb3b6a` |
| Branch | `claude/codebase-production-readiness-wm6idp` |

Full per-run metadata — commit, branch, dirty flag, kernel, `uname -a`,
observer configuration, scenario, guard interval, start/end timestamps, subject
exit code — is in each run's `metadata.json` under
`validation/traces/airi-final/`.

## 3. Subject workload

`validation/airi/agent`, a real process that:

- generates an Ed25519 keypair and an AIP agent identity,
- makes a **real TCP connection** and HTTP request to a local model endpoint,
- emits **real signed `AiriEvent`s** through `aip-airi`'s own signing path,
  hash-chained on `prev_event_hash`,
- collects a real `runtime_binding` via `aip_core::execution_binding`,
- executes a real declared tool via `execve`.

Its manifest excludes `aip-observe`, `aip-observation` and `aip-effect`: the
subject cannot link the observation machinery, so it cannot produce evidence
about itself. Its `Cargo.toml` declares its own `[workspace]`, so the
production manifest is untouched by validation scaffolding.

**Every field the subject writes is a claim.** Nothing it emits is treated as
evidence of anything at any point in this experiment.

## 4. AIRI instrumentation

Six to seven signed events per run: `AgentExecutionStarted`,
`ModelInvocationRequested`, `ModelInvocationObserved`,
`ToolInvocationRequested`, `ToolExecutionReported`, optionally
`SubprocessExecution`, and `ExecutionCompleted`. The tool argv is committed to
via `parameter_commitment` and reproduced verbatim in the process, so an
observer can match one against the other.

The event chain is checked for **ordering** only. Recomputing `prev_event_hash`
needs `AiriEvent::signing_preimage`, which is Rust and deliberately not
reimplemented in the harness: a second implementation of a security-relevant
encoding is exactly the duplication this programme forbids.

## 5. Independent observers

| | Observer A | Observer B |
|---|---|---|
| Name | `linux-audit` | `ftrace-sched` |
| Implementation | `validation/airi/observers/audit_observer.py` | `validation/linux/ftrace_observer.sh` |
| Probe | `audit_syscall_entry/exit` hook | `sched_process_exec` tracepoint |
| Delivery | `NETLINK_AUDIT` unicast | ftrace instance ring |
| Rendering | kernel text | kernel text |
| Carries argv | **yes** | **no** |
| Status | READY, all 18 runs | READY, 17 of 18 runs |

Observer B was unavailable on AIRI-015 by design — that scenario removes
observer A, and B's window is bounded by events A identifies, so B's capture
could not be bounded either. It is reported `INDEPENDENT_OBSERVER_BLOCKED` for
that run rather than compared over the wrong interval.

Evaluated and blocked: **Tetragon** (`# CONFIG_KPROBES is not set`; re-verified,
`validation/external/tetragon/RECHECK.md`), **A3S Observer** (nightly toolchain
unavailable, and its exec instrumentation overlaps Sniffer Dog's anyway;
`validation/external/a3s/EVALUATION.md`), **OpenTelemetry** (not installed, and
a self-report if it were; `validation/external/OTEL.md`).

## 6. Observation mechanisms

```
                 Sniffer Dog 2.0        observer A            observer B
  probe site     sched tracepoint       audit syscall hook    sched tracepoint
  subsystem      kernel/trace           kernel/auditsc.c      kernel/trace
  delivery       perf per-CPU ring      NETLINK_AUDIT         ftrace ring
  decoder        aip-observe's own      kernel text           kernel text
  argv           yes                    yes                   NO
```

Observer A is **mechanism-independent** of Sniffer Dog for process execution.
Observer B is **interface-independent** of Sniffer Dog and mechanism-independent
of observer A.

## 7. Independence analysis

Full analysis: `validation/airi/OBSERVER_INDEPENDENCE.md`. In summary:

**What it buys.** A disagreement between A and B is evidence about the *event*,
not merely about one reading of a shared source. This is stronger than the
prior analysis (`validation/linux/INDEPENDENCE.md`) concluded was reachable
here; that document surveyed tracing facilities and did not consider audit,
which is not one and is compiled in.

**What it does not buy.**

- Not root-resistant. Root can disable audit or the tracepoints. Interference
  produces an *absence*, and absence is not non-execution.
- Not kernel-compromise-resistant. A compromised kernel defeats both.
- Not a physical-effect witness. Both observe syscalls on one host.
- **Argv is single-observer.** Observer B carries filename and pid only, so no
  argv-level fact in this report has two witnesses.
- **Same author.** The subject and observer A were written by the same author.
  Mitigated by observer A rendering nothing of its own — `kernel_record` is the
  bytes the kernel produced — but not eliminated. It is a stated limitation of
  every result below.

## 8. Experiment windows

Both observers' windows are bounded by the same two marker `execve` calls,
identified by the pids audit recorded for them. A quiet guard interval of
0.25 s sits inside each boundary, and the comparison excludes execs within
100 ms of a boundary — a **stated tolerance** for the fact that the two
observers assign event ordering at different points in the same syscall, so a
process straddling a boundary lands on different sides for them.

Across the 18 runs the tolerance excluded exactly 3 unrelated host processes
per run and no subject activity.

Ordering of claims against observations uses the **audit serial**, a monotonic
kernel counter, never a timestamp.

## 9. Test matrix

`validation/airi/AIRI_INDEPENDENT_OBSERVATION_MATRIX.csv`, 18 rows, 16 fields,
generated from the run set by `validation/airi/build_matrix.py` — not typed in
by hand.

## 10. Results

**18 scenarios executed, 18 PASS, 0 FAIL, 0 not executed.**

Classifications: 11 `OBSERVED`, 5 `CANNOT_PROVE`, 2 `UNKNOWN`, 0 `PROVEN`.

| Scenario | What it tests | Classification | Divergence surfaced |
|---|---|---|---|
| AIRI-001 | normal tool execution | OBSERVED | none |
| AIRI-002 | claims execution; tool never runs | CANNOT_PROVE | `CLAIMED_SUCCESS_NOT_OBSERVED` |
| AIRI-003 | tool runs; agent claims failure | OBSERVED | `CLAIMED_FAILURE_BUT_EXECUTION_OBSERVED` |
| AIRI-004 | runs twice; reports once | OBSERVED | `COUNT_MISMATCH claimed=1 observed=2` |
| AIRI-005 | undeclared subprocess | OBSERVED | `UNDECLARED_EXECUTION observed=1` |
| AIRI-006 | undeclared network connection | OBSERVED | `UNDECLARED_NETWORK connects=2 declared=1` |
| AIRI-007 | AIRI event, no execution evidence | CANNOT_PROVE | `CLAIMED_SUCCESS_NOT_OBSERVED` |
| AIRI-008 | completion claimed before execution | OBSERVED | `COMPLETION_CLAIMED_BEFORE_ANY_OBSERVED_EXECUTION` |
| AIRI-009 | execution after completion | OBSERVED | `COUNT_MISMATCH`; `EXECUTION_OBSERVED_AFTER_COMPLETION_CLAIM` |
| AIRI-010 | delayed observation (2 s stall) | OBSERVED | none — a late stream gave the same answer |
| AIRI-011 | duplicated observation (176 dups) | OBSERVED | none — collapsed on the audit serial |
| AIRI-012 | replayed signed event stream | CANNOT_PROVE | `EVENT_COUNT_MISMATCH claimed=6 beacons=0` |
| AIRI-013 | agent dies before completion | OBSERVED | `EXECUTION_OBSERVED_WITHOUT_COMPLETION_CLAIM` |
| AIRI-014 | child survives parent | OBSERVED | `UNACCOUNTED_CHILD_PROCESS`; `SUBPROCESS_ARGV_COMMITMENT_UNVERIFIABLE` |
| AIRI-015 | observer disappears | **UNKNOWN** | none — and none may be asserted |
| AIRI-016 | observers contradict | **UNKNOWN** | `CONTRADICTORY_OBSERVATIONS second_observer_only=[999001]` |
| AIRI-017 | declared argv run outside the tree | CANNOT_PROVE | `DECLARED_ARGV_NOT_ATTRIBUTED_TO_SUBJECT` |
| AIRI-018 | committed argv ≠ executed argv | CANNOT_PROVE | `COMMITTED_ARGV_NOT_THE_ARGV_EXECUTED` |

Cross-observer agreement on the 17 runs where both ran: 8 to 13 corroborated
exec pids per run, **zero unexplained disagreements**, and on AIRI-016 exactly
the one fabricated pid and nothing else.

### The critical test

Phase 11 of the mandate names the strongest first demonstration. Both
directions were run.

**Agent claims success; the tool did not run** (AIRI-002, AIRI-007). The claim
stream asserts `ToolExecutionReported{outcome: Success}` and
`ExecutionCompleted`. The independent observer recorded no execution of the
committed argv. Classification: **`CANNOT_PROVE`**, with
`CLAIMED_SUCCESS_NOT_OBSERVED`. The agent's claim moved the classification
**not at all**. Mutation M-OBS-1 confirms this is load-bearing: rewiring the
count to come from the claim instead of the observer flips AIRI-002 to FAIL.

**Agent under-reports; the tool did run** (AIRI-004, AIRI-009). Two executions
observed against one reported. The observer established the second execution
independently and the count mismatch surfaced.

**Contradictory evidence is not resolved by guessing** (AIRI-016). One observer
asserts an execution the other does not. The classification drops to `UNKNOWN`;
neither account is promoted, neither is discarded.

### Relationship to the concurrent experiment

A second experiment ran independently and in parallel:
`docs/AIRI_REAL_WORLD_VALIDATION.md`, with its subject, correlator and matrix
under `validation/scenarios/airi_independent_observation_001/` and
`validation/reports/`. It was not coordinated with this one. Both are kept,
because two independent attempts at the same question are worth more than one,
and where they differ the difference is itself information.

**Where they agree.** An agent's success claim never becomes evidence; an
execution can be established without asking the agent; a missing observer
yields a refusal to conclude rather than a finding against the subject.

**What that experiment has and this one does not.** It ran **A3S Observer**, an
eBPF instrument written by a third party, and it ran **Sniffer Dog 2.0 itself**
alongside. That produced the single most consequential result in either
experiment — see `validation/external/a3s_observer/TRACEPOINT_INTERFERENCE.md`:
a BPF program attached to `sched:sched_process_exec` causes the kernel to drop
the sample for *every* `perf_event_open` consumer of that tracepoint, because
`perf_trace_run_bpf_submit()` gates on the BPF return value per
`trace_event_call`, host-wide. Sniffer Dog saw four exec events alone and zero
with A3S running, **and reported `"lost":0` while blind**. The ftrace path is
not gated the same way and kept working, which is what makes the diagnosis
certain rather than plausible.

That is a coverage defect in Sniffer Dog 2.0 found by putting it next to an
independent observer, and it is exactly the class of finding a self-written
test suite cannot produce. It is not a defect in A3S.

**What this experiment has and that one does not.** A mechanism-independent
observer that carries argv (audit); scenarios for delayed, duplicated,
replayed and contradictory observation; a mutation suite proving the checks can
fail; and eighteen scenarios against ten.

**Where they disagree, substantively.** That report labels an
externally-observed execution **`PROVEN`**. This one refuses to, and labels the
same class of fact `OBSERVED`. Both documents state that their labels are
external-validation labels and not Vanian verdicts, so neither is claiming a
Vanian `EvidenceStrength`. The disagreement is still real and worth resolving
in favour of the stricter reading: `aip-observation::ObservationClass::ceiling`
reserves `Proven` for facts a third party recomputes from bytes it holds, and
an `execve` record is content measured on the observed host, which host root
can forge. **No syscall observation on the observed host should be labelled
`PROVEN`, however many independent instruments record it.** §15 sets out the
reasoning in full.

## 11. Mismatches

Every mismatch listed above was surfaced by the observers, and none by the
claim stream. The claim stream is internally consistent in all 18 runs —
signatures verify, sequences are monotonic — including the runs where it is
lying. **Internal consistency of a self-report carries no information about
its truth**, and this experiment demonstrates that directly.

`SUBPROCESS_ARGV_COMMITMENT_UNVERIFIABLE` (AIRI-014) is a limitation of the
harness, not a finding against AIRI: recomputing `parameter_commitment` would
require reimplementing a security-relevant encoding in Python, which is
forbidden. It is reported rather than silently dropped.

## 12. False positives

**Zero in the final run set**, after three were found and fixed. A false
positive here means the harness asserting a divergence that did not occur —
exactly the manufactured false failure the mandate forbids.

1. **Record truncation.** The audit subsystem sets `nlmsg_len` to the payload
   size, not `NLMSG_HDRLEN + payload` as other netlink families do. Reading it
   the usual way truncated every record by 16 bytes, cutting the run nonce off
   hex-encoded `execve` arguments, and produced `declared_execs=0` on the
   honest scenario. Guarded by M-OBS-2.
2. **Cross-clock ordering.** Comparing the subject's `emitted_at_ms` against
   audit's coarse (tick-granularity) timestamp reported a 2 ms inversion: an
   execution appeared to precede a claim that in fact preceded it. Cross-clock
   comparison was removed entirely. Guarded by M-OBS-4.
3. **Mismatched observer windows.** Bounding observer A's window with marker
   `execve`s and observer B's with its own `trace_marker` writes made the two
   intervals different, producing four to five "contradictions" on every honest
   run *including the baseline*. Both are now bounded by the same two kernel
   events, with a stated boundary tolerance. Guarded by M-OBS-6.

## 13. False negatives

**Zero known.** Three were found and fixed; each is now a guarded regression.

1. **Vacuous attribution.** Audit emits SYSCALL before EXECVE. Attaching
   SYSCALL fields to the EXECVE already seen left every `pid` and `ppid` null,
   so every attribution test passed without testing anything. Records are now
   grouped on the audit serial. Guarded by M-OBS-3.
2. **Vacuous ordering.** AIRI-008's check (`after >= 1, before == 0`) is
   satisfied by an implementation that reports *everything* as after. Mutation
   M-OBS-4 survived against AIRI-008 alone and was killed only by AIRI-009,
   which requires executions on both sides of the claim. Mutation guards are
   now scenario sets.
3. **Leaked audit rules.** Audit rules are global and outlive the process that
   installed them; an observer killed with `SIGKILL` — which AIRI-015 does
   deliberately — leaks its rules. A later run then captured through rules it
   did not install: an observer asked to watch only `openat` still received
   `execve` records and the scenario passed while testing nothing. Found by
   mutation M-OBS-5 surviving. The observer now clears the global rule set at
   start, verifies the loaded set by asking the kernel, and refuses to record
   if it cannot. A related bug was found in the same place: `_ack` was reading
   one message and treating whatever arrived as the acknowledgement, so
   interleaved *event records* were misread as successful rule installs.

**Mutation results: 9 mutations, 9 killed, 0 survivors**
(`validation/airi/MUTATION_RESULTS.json`). Each asserts the bytes on disk
changed before any result is interpreted, and restores the file afterwards.

## 14. UNKNOWN and CANNOT_PROVE cases

Five `CANNOT_PROVE` and two `UNKNOWN`, and the distinction is load-bearing.

- **`CANNOT_PROVE`** (AIRI-002, -007, -012, -017, -018): the window was sound,
  the observers ran, and no independent record of the committed argv exists
  inside it. The note attached to every such result states explicitly that
  *absence of observation is not evidence of non-execution*. The harness does
  not say the tool did not run. It says it cannot establish that it did.
- **`UNKNOWN`** (AIRI-015, AIRI-016): the interval is uninterpretable — the
  window never closed, or two observers disagree. **No divergence may be
  asserted from an uninterpretable window**, and the analyser enforces this by
  computing no divergences at all when the window did not close. Mutation
  M-OBS-8 confirms it: removing that guard makes AIRI-015 report the subject as
  having failed to act, which is precisely the error being prevented.

## 15. Evidence-ceiling analysis

**The ceiling is `OBSERVED`. `PROVEN` was not reached and is unreachable by
this experiment's construction.**

Vanian reserves `Proven` (`aip-observation::ObservationClass::ceiling`) for
facts a third party recomputes from bytes it holds — signature and chain
arithmetic. An `execve` record is *content measured on the observed host*. Host
root can forge it. No number of observers on that host changes this.

Per fact class:

| Fact | Observers | Ceiling reached |
|---|---|---|
| a process exec'd, with this pid, in this window | 2, mechanism-diverse | `OBSERVED` |
| the argv it exec'd with | **1** (audit only) | `OBSERVED`, single-witness |
| the process tree it belongs to | 1 | `OBSERVED` |
| a connect(2) occurred, attributed to the tree | 1 | `OBSERVED` |
| the ordering of a claim against an execution | 1 stream, kernel serial | `OBSERVED` |
| the AIRI event chain's integrity | recomputable from held bytes | would be `Proven` — **not checked here**, deliberately |
| any effect outside this host | **0** | `CANNOT_PROVE` |

The one fact class that could legitimately reach `Proven` — signature and chain
arithmetic over the AIRI events — was deliberately not verified by this
harness, because doing so would mean reimplementing `signing_preimage` in
Python. That is Vanian's own engine's job and remains so.

## 16. Security interpretation

What the run set supports:

1. **An agent's success claim does not create evidence.** The strongest
   demonstration of the mandate: a fully-signed, internally-consistent,
   chain-intact claim of successful execution yields `CANNOT_PROVE` when no
   observer saw the execution. Confirmed load-bearing by mutation.
2. **An execution can be established without asking the agent.** Observer A
   recorded executions the claim stream understated (AIRI-004, -009) and
   omitted entirely (AIRI-005), and a network connection the claim stream did
   not declare (AIRI-006).
3. **The right command line is not enough.** AIRI-017 runs the committed argv
   byte-identically from outside the subject's process tree. It is not
   credited. Attribution comes from the observer's own `(pid, ppid)` closure,
   not from anything the subject said.
4. **A commitment is checked against reality, not against itself.** AIRI-018
   commits to one argv and executes another; the divergence is surfaced.
5. **Observation defects do not become subject findings.** A 2 s delivery delay
   (AIRI-010) and 176 duplicated records (AIRI-011) both give AIRI-001's answer.
   A lost observer (AIRI-015) gives `UNKNOWN` and asserts nothing against the
   subject.
6. **Contradiction is not resolved by preference** (AIRI-016).
7. **A replayed authentic event stream is not an execution** (AIRI-012). Every
   signature verifies and every chain link holds; the beacons the observer
   would have seen are absent, and the classification is `CANNOT_PROVE`.

What the run set does **not** support, and no reader should infer:

- nothing about a root or kernel adversary,
- nothing about physical or external effect,
- nothing about any host but this one,
- nothing about argv with more than one witness,
- nothing about Vanian's own reconciliation engine, which this harness does not
  invoke.

## 17. Limitations

1. **Same author.** The subject and observer A share an author. Mitigated by
   observer A rendering nothing of its own; not eliminated.
2. **Argv has one witness.**
3. **Root defeats both observers.** So does a compromised kernel.
4. **Audit has a single consumer.** If anything else on the host consumes
   audit, observer A refuses to run rather than contend for the socket. That is
   a real availability constraint on any production use.
5. **Audit rules are global.** The observer clears and verifies them, but a
   concurrent audit user would be disrupted.
6. **The beacon is the subject's own assertion.** It places a claim's position
   into a channel the subject does not author; it does not make the claim true.
7. **Process-tree closure is built from `execve` records only.** A fork that
   never execs is invisible to it. Pid reuse inside one window would
   mis-attribute; the windows are seconds long and the pid space is nowhere
   near wrapping here, but that is a property of this environment, not a
   guarantee.
8. **Boundary tolerance is 100 ms.** An event within 100 ms of a window
   boundary is excluded from the cross-observer comparison.
9. **One host, one kernel, one architecture** (x86-64). The audit rules are
   `-F arch=b64`; a 32-bit syscall would not be seen.
10. **The tool is a shell command.** No result here speaks to containers,
    remote APIs, or anything not a local `execve`.

## 18. Reproducibility

```
# all eighteen scenarios into a fresh trace root
TRACE_ROOT=$PWD/validation/traces/airi-final \
  bash -c 'for S in AIRI-001 AIRI-002 AIRI-003 AIRI-004 AIRI-005 AIRI-006 \
                    AIRI-007 AIRI-008 AIRI-009 AIRI-010 AIRI-011 AIRI-012 \
                    AIRI-013 AIRI-014 AIRI-015 AIRI-016 AIRI-017 AIRI-018; do
             bash validation/airi/run_airi_validation.sh "$S"; done'

# regenerate the matrix from the run set
python3 validation/airi/build_matrix.py \
  --trace-root validation/traces/airi-final \
  --out validation/airi/AIRI_INDEPENDENT_OBSERVATION_MATRIX.csv

# prove the checks can fail
python3 validation/airi/mutate.py
```

Requires root, `CONFIG_AUDITSYSCALL=y`, and — for the second observer —
`tracefs` mountable at `/sys/kernel/tracing`. Build the subject first with
`(cd validation/airi/agent && cargo build)`.

Raw artefacts are preserved under `validation/traces/airi-final/`: the audit
record stream, the ftrace capture, the signed AIRI events, the subject's
stdout and stderr, the window record, the analysis, and per-run metadata.
Runs with an injected observation defect additionally preserve the untouched
capture and an `INJECTION.txt` stating exactly what was changed.

## 19. Next experiment

In priority order.

1. **A kprobe-capable kernel.** Tetragon probes kernel functions *below* the
   syscall boundary and would survive a subject manipulating syscall entry.
   This is the single largest gap and it needs a host change, not effort.
2. **A second argv witness.** Every argv-level fact here has one. A second
   mechanism carrying argv would remove the largest single-point dependency in
   the result.
3. **An observer authored by someone else.** Removes the same-author caveat
   from every conclusion.
4. **Sniffer Dog 2.0 itself as the subject under observation.** This experiment
   validated the *method*; it did not run `aip-observe` and therefore says
   nothing about whether Sniffer Dog reads its tracepoints correctly. The
   concurrent experiment did run it and found that it can go silently blind —
   see the tracepoint-interference finding referenced in §10. Following that up
   is now the highest-value target, and audit is the right instrument for it,
   because audit is not on the perf submission path the finding implicates.
5. **A hostile subject.** The subject here is honest-but-configurable. A
   subject that actively attacks the observers — clearing audit rules, exiting
   the process tree, racing the window — would test the failure modes rather
   than the happy paths of the failure modes.
6. **Physical effect.** Out of reach until there is instrumented hardware
   observed by something that is not the vehicle. Until then no physical-effect
   claim is available to Vanian by any path, and the robotics profile in
   `aip-standalone/aip-robotics` correctly represents that boundary rather than
   moving it.
