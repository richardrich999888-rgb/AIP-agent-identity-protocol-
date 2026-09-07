# OBSERVATION-INTEGRITY-001 — the observer under seven conditions

Design for the next experiment. It extends the reproduction
(`reproduce_interference.sh`, which covers the normal and interfered cases)
into a full matrix of observer conditions, each with a declared expected
observer status, expected evidence, and expected Vanian classification.

**No production code change is required for the first version.** The
experiment reads the observer's existing outputs and the independent evidence,
and asks whether the *observer's own reported status* is honest about each
condition. Where the honest status is not representable in today's outputs,
that is the experiment's finding, not a licence to change production.

## The subject and the observers

- **Subject.** The AIRI subject agent
  (`../scenarios/airi_independent_observation_001/agent`) or the fixed `wc`
  workload from the reproduction — a known, countable set of execs inside an
  explicit window.
- **Observer under test.** Sniffer Dog 2.0's live sensor (the recorder).
- **Interference instrument.** `tracepoint_interferer` (no-op BPF gate).
- **Independent cross-checks, where available.** ftrace reader (survives the
  perf gate); netlink proc connector (different facility — not yet wired into
  the harness, noted where it would change a row).

## The forbidden inference, restated as the pass condition

For every condition below, the experiment passes if and only if the system
does **not** conclude "no event occurred" from the observer's silence unless
the observer was genuinely `ACTIVE` — attached and evidenced-capable — across
the window. A condition may "pass" by correctly reaching `CANNOT_PROVE`; that
is the intended outcome for most of these, not a shortfall.

## Conditions

### A. normal observer
- **Setup.** Observer attached, no interference, workload runs in-window.
- **Expected observer status.** `OBSERVATION_ACTIVE`.
- **Expected evidence.** All N execs observed; reported loss 0; independent
  cross-check agrees.
- **Expected Vanian classification.** Exec claims corroborated; eligible for
  the normal ceiling (`Attested` for a single mechanism). This is the only
  condition from which occurrence may be asserted.

### B. observer stopped (graceful)
- **Setup.** Observer sent SIGTERM before the workload; workload runs; observer
  restarted after.
- **Expected observer status.** `OBSERVATION_UNAVAILABLE` for the gap window.
- **Expected evidence.** No events for the gap; the gap is explicit and
  bounded by the stop/start times.
- **Expected Vanian classification.** `CANNOT_PROVE` for events in the gap.
  Absence is expected and carries no information. **Must not** yield
  non-execution.

### C. observer crashed
- **Setup.** Observer killed with SIGKILL mid-window (ungraceful); no clean
  final batch.
- **Expected observer status.** `OBSERVATION_UNAVAILABLE`, and on restart
  `CONTINUITY_UNVERIFIED` until re-established.
- **Expected evidence.** A truncated capture; possibly a sequence
  discontinuity; **no** clean "covered, saw nothing".
- **Expected Vanian classification.** `CANNOT_PROVE` for the uncovered span.
  A crash must never present as coverage.

### D. ring-buffer overflow
- **Setup.** Flood `sched_process_exec` (many rapid execs) so the perf ring
  overruns while the workload's target execs occur.
- **Expected observer status.** `OBSERVATION_DEGRADED`, with a non-zero
  reported loss.
- **Expected evidence.** `PERF_RECORD_LOST` count > 0; some events observed,
  some counted as lost.
- **Expected Vanian classification.** `CANNOT_PROVE` for the lossy window,
  distinguished from the interference case by the **non-zero** loss count.
  This is the control that shows loss accounting works when it should.

### E. tracepoint interference (the finding)
- **Setup.** `tracepoint_interferer` holds the gate; observer attached;
  workload runs.
- **Expected observer status.** Honest status is `OBSERVATION_INTEGRITY_UNKNOWN`.
  **Today's observer reports `ACTIVE` with zero loss** — that gap is the
  finding, and the experiment records it as the delta between honest and actual
  status.
- **Expected evidence.** Zero target execs observed; reported loss 0; the
  ftrace cross-check **still sees** the execs (proving they occurred and the
  perf path was gated).
- **Expected Vanian classification.** `CANNOT_PROVE`. Reached today only
  because the reconciler defaults to it — **not** because the observer reported
  a problem. The experiment's job is to make that distinction visible.

### F. competing BPF program (benign, e.g. A3S)
- **Setup.** A second legitimate eBPF observer attached to the same tracepoint,
  gating it as a side effect.
- **Expected observer status.** Same as E — honest `INTEGRITY_UNKNOWN`, actual
  `ACTIVE`.
- **Expected evidence.** Indistinguishable from E at the perf reader; the
  presence of the foreign BPF program is enumerable as the distinguishing
  fact.
- **Expected Vanian classification.** `CANNOT_PROVE`. The point of this
  condition is that benign and malicious interference are indistinguishable by
  *effect*, so detection must key on the foreign program's presence, not its
  intent.

### G. observer restart (continuity)
- **Setup.** Observer stopped and restarted mid-window; workload spans the
  restart.
- **Expected observer status.** `UNAVAILABLE` during the gap, then
  `CONTINUITY_UNVERIFIED` → `ACTIVE` once re-established; the pre- and
  post-restart spans are covered, the gap is not.
- **Expected evidence.** Two covered spans with a bounded gap; no silent
  bridging of the gap.
- **Expected Vanian classification.** Covered spans normal; gap
  `CANNOT_PROVE`. A restart must not manufacture continuity across the gap —
  the existing continuity model already tests this; this condition confirms it
  interacts correctly with the integrity states.

## The matrix to fill

| Cond | Honest status | Today's reported status | Independent cross-check | Expected Vanian verdict | Gap between honest and reported? |
|---|---|---|---|---|---|
| A | ACTIVE | ACTIVE | agrees | corroborated | none |
| B | UNAVAILABLE | (gap visible) | n/a | CANNOT_PROVE | to measure |
| C | UNAVAILABLE / CONT_UNVERIFIED | (truncation visible) | n/a | CANNOT_PROVE | to measure |
| D | DEGRADED | DEGRADED (loss>0) | agrees on seen | CANNOT_PROVE (lossy) | none expected |
| E | INTEGRITY_UNKNOWN | **ACTIVE, loss 0** | ftrace still sees | CANNOT_PROVE | **the finding** |
| F | INTEGRITY_UNKNOWN | **ACTIVE, loss 0** | ftrace still sees | CANNOT_PROVE | **the finding** |
| G | mixed | (gap visible) | n/a | covered spans + CANNOT_PROVE gap | to measure |

The security-critical result is that **E and F are the only conditions where
the observer's reported status is dishonest** — it says `ACTIVE`/no-loss when
the truthful status is `INTEGRITY_UNKNOWN`. Every other condition is already
represented honestly by existing outputs. That localises exactly what a
production change, if any, would need to address.

## What would count as a pass

1. Conditions A–D, G: the observer's reported status matches the honest status,
   and Vanian's verdict matches the expected column.
2. Conditions E, F: Vanian still reaches `CANNOT_PROVE` (no false
   non-execution), **and** the experiment demonstrably identifies the honest
   status as `INTEGRITY_UNKNOWN` using evidence available outside the observer
   (foreign BPF program enumeration and/or the ftrace cross-check), even though
   the observer itself reports `ACTIVE`.

## What would NOT count as a pass

- Any condition producing "no event occurred" from silence.
- Detecting E/F only by the ftrace cross-check seeing the execs, without also
  establishing that the perf observer's `ACTIVE` claim was unjustified — that
  would show the events happened but not that the observer's self-report was
  the problem.
- Reaching `CANNOT_PROVE` in E/F *by luck* (reconciler default) and reporting
  it as if the observer had flagged the interference.

## Production-code posture

The first version changes nothing in `aip-observe` or elsewhere. It is
instrumented entirely from validation code reading existing outputs plus
independent evidence. If it demonstrates that the honest status in E/F cannot
be surfaced without a production change — which is likely, since the observer
cannot today represent `INTEGRITY_UNKNOWN` — that becomes the trigger for the
STOP-and-report gate in section 9 of the mandate, not an in-line edit here.
