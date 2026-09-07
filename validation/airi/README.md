# `validation/airi/` — AIRI-specific validation notes

## Two experiments live here, and they were not coordinated

They ran independently and in parallel, against the same question. Both are
kept: two independent attempts are worth more than one, and where they differ
the difference is information.

| | Experiment 1 | Experiment 2 |
|---|---|---|
| Subject | `../scenarios/airi_independent_observation_001/agent/` | `agent/` (this directory) |
| Runner | `../scenarios/airi_independent_observation_001/run.sh` | `run_airi_validation.sh` |
| Correlator | `.../correlate.py` | `analyze.py` |
| Observers | A3S Observer (eBPF), Sniffer Dog 2.0, ftrace | Linux audit, ftrace |
| Scenarios | 10 | 18 |
| Matrix | `../reports/AIRI_VALIDATION_MATRIX.csv` | `AIRI_INDEPENDENT_OBSERVATION_MATRIX.csv` |
| Report | `../../docs/AIRI_REAL_WORLD_VALIDATION.md` | `../../docs/AIRI_INDEPENDENT_OBSERVATION_REPORT.md` |

Experiment 1's headline result is the tracepoint-interference finding
(`../external/a3s_observer/TRACEPOINT_INTERFERENCE.md`) — a coverage defect in
Sniffer Dog 2.0 found by running it next to an independent observer. Read it
before running two kernel observers at once.

Experiment 2 adds a mechanism-independent observer that carries argv,
scenarios for delayed, duplicated, replayed and contradictory observation, and
a mutation suite proving its own checks can fail.

**They label evidence differently, and experiment 2's report says which reading
should win and why** — see its §10, "Relationship to the concurrent
experiment". Neither labels anything a Vanian verdict.

## What follows

This file records what experiment 1 learned about AIRI itself, as distinct from
what was learned about the observers.

## What AIRI already gets right

Verified by reading `aip-standalone/aip-airi/`, not by taking the docs' word:

- **`ModelInvocationObserved` is named "Observed" by the AIRI specification and
  is not independent observation.** The crate says so at the enum variant, and
  treats it as a self-report like any other. A reader who assumed the name
  meant what it says would be wrong, and the crate refuses to let that
  assumption become a capability.
- **`Corroboration::Corroborated` cannot be forged by a caller.** It carries a
  `CorroborationSeal` whose field is private and whose only constructor is
  `pub(crate)`, reachable solely through `corroborate()` after comparing
  against attested observer batches. No adapter or SDK can hand one in.
- **`corroborate()` fails toward "cannot say".** Each step that cannot be
  completed stops at `NotEvaluated` with a reason, rather than falling through
  to a stronger answer.
- **`is_externally_observable()` is honest about the model layer.** Model
  invocation kinds return `false`, because a hosted inference call leaves no
  local mark that belongs to the model layer — the socket belongs to the tool
  layer, and attributing it twice would be double-counting.

The experiment confirmed each of these empirically rather than assuming them.

## What the experiment found about AIRI

1. **Half the event chain is structurally unvalidatable by host observation.**
   Every `AgentExecutionStarted`, `ModelInvocation*`, `ExecutionCompleted` and
   `ExecutionFailed` claim classified as `SELF_REPORTED` in every run — not
   because the agent lied, but because no host observer can attribute them.
   This is correct behaviour and it is also a real limit on what AIRI can
   establish. Corroborating the model layer needs evidence from outside the
   host: a provider-side attestation, or a proxy in a different trust boundary.

2. **AIRI has no network event kind.** The chain describes tools and
   subprocesses, not sockets. So an observed connection is undeclared *by
   construction* — scenarios 5 and 13 could attribute egress to the subject but
   could not score the agent for failing to declare it, because there is no
   event with which it could have. That is a gap in AIRI's vocabulary rather
   than agent dishonesty, and it is recorded as such.

3. **`ToolExecutionReported` names a tool, not a program**, so it carries
   nothing to join an observation on. It classified `UNKNOWN` in every run
   where the tool was not also the subject of a `SubprocessExecution` event.
   Not wrong — `UNKNOWN` is the honest answer for a claim with no joinable
   identity — but it means tool reports are corroborated only via their
   accompanying subprocess events.

4. **The signature is not the weak point, and the experiment is built to prove
   that.** Every event the subject emitted verified. Scenario 1's fabricated
   claim was correctly signed, structurally valid and chain-consistent, and
   still failed to reach `PROVEN`. Authorship and occurrence stayed separate
   under direct attack.

## What was NOT changed

Nothing in `aip-airi`. No event kind was added, no `is_externally_observable`
mapping altered, no `Corroboration` variant introduced. Findings 2 and 3 are
design observations for people to decide on, not defects to patch from a
validation harness.
