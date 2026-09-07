# `validation/observation_integrity/` — the observer-integrity boundary

This directory characterises one finding from the AIRI validation work and
turns it into a specified, reproducible security requirement. It changes no
production code.

> **The finding.** An observer can report healthy coverage while its
> observation mechanism has been silently disabled. A no-op eBPF program
> attached to the `sched:sched_process_exec` tracepoint suppresses that
> tracepoint's perf submission host-wide, so Sniffer Dog 2.0 — a separate
> process reading the same tracepoint through `perf_event_open` — observes
> nothing and reports zero loss. Silence and "no event occurred" become
> indistinguishable from the observer's own outputs.

## Contents

| Path | What it is |
|---|---|
| `tracepoint_interferer.c` | the finding reduced to its minimal cause — a 2-instruction BPF program that returns 0, attached to the tracepoint. No A3S code. |
| `reproduce_interference.sh` | deterministic two-arm experiment: Sniffer Dog alone vs Sniffer Dog with the gate held |
| `OBSERVATION-INTEGRITY-001.md` | the next experiment: seven observer conditions and their expected classifications |
| `results/` | sealed raw artifacts per run (environment, per-arm counts, verdict, `SHA256SUMS`) |

The specifications live in `docs/`:

- `docs/OBSERVATION_INTEGRITY_REQUIREMENTS.md` — the property and its states
- `docs/OBSERVATION_MECHANISM_INDEPENDENCE.md` — which observers are actually independent
- `docs/OBSERVATION_INTEGRITY_DECISION_RECORD.md` — options, no mitigation selected

## Reproducing

```sh
sudo ./reproduce_interference.sh
```

Exit 0 means the finding reproduced: baseline observed the execs, the
interfered arm observed zero, and reported zero loss. Both arms are bounded by
an explicit observation window so that Sniffer Dog's own startup execs are
never counted as the workload.

## Why the minimal interferer rather than A3S

A3S Observer demonstrated the effect, but A3S does many things, and "A3S
blinds Sniffer Dog" leaves open *which* of them is the cause. The interferer
here does exactly one thing — hold the perf-submission gate shut by returning
0 — so a reproduction with it attached proves the mechanism, not a
correlation. It carries no observation logic, reads no events, and enforces
nothing.

Observed corroboration of the mechanism, visible in the results: in the
interfered arm Sniffer Dog's `sched_process_exec` count drops to zero while its
`sched_process_fork` count is unaffected. Fork is a **different tracepoint**
with no BPF program attached, so it flows normally. Only the gated tracepoint
goes dark. That asymmetry is the mechanism's fingerprint.

## Status

`THREAT_REPRODUCED`, `THREAT_CHARACTERIZED`, `MITIGATION_OPTIONS_DEFINED`.
No mitigation implemented. No production code changed.
