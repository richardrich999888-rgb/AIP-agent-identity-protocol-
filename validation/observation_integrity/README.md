# `validation/observation_integrity/` — the observer-integrity boundary

Two experiments, built independently and in parallel, characterise the same
finding from the AIRI validation work and turn it into a specified,
reproducible security requirement. Both are kept. Neither changes production
code.

> **The finding.** An observer can report healthy coverage while its
> observation mechanism has been silently disabled. A no-op eBPF program
> attached to `sched:sched_process_exec` suppresses that tracepoint's perf
> submission for every `perf_event_open` consumer of it, so Sniffer Dog 2.0 —
> a separate process reading the same tracepoint — observes nothing and reports
> zero loss. Silence and "no event occurred" become indistinguishable from the
> observer's own outputs.

**Status: THREAT_REPRODUCED, THREAT_CHARACTERIZED. No mitigation implemented.
No production code changed.**

## The two experiments, and what each adds

They agree on the finding and are complementary in method. Where they overlap
(both define observation states, both evaluate mitigation options), treat them
as two independent characterisations of the same thing, not one derived from
the other.

### Experiment 2b — minimal-cause isolation
| | |
|---|---|
| Interferer | `tracepoint_interferer.c` — a 2-instruction BPF program that returns 0. No A3S code, no observation logic. |
| Harness | `reproduce_interference.sh` — two arms, Sniffer Dog alone vs Sniffer Dog with the gate held |
| Evidence | `results/<ts>/` with per-arm counts, `environment.txt`, `verdict.json`, `SHA256SUMS` |
| Next experiment | `OBSERVATION-INTEGRITY-001.md` — seven observer conditions and expected classifications |
| Specs | `docs/OBSERVATION_INTEGRITY_REQUIREMENTS.md`, `docs/OBSERVATION_MECHANISM_INDEPENDENCE.md`, `docs/OBSERVATION_INTEGRITY_DECISION_RECORD.md` |

**Its strength:** the interferer does exactly one thing — hold the
perf-submission gate shut — so a reproduction proves the mechanism rather than
a correlation. "A3S blinds Sniffer Dog" leaves open which of A3S's many actions
is the cause; a 2-instruction return-0 program does not.

### Experiment 2a — ambiguity exclusion
| | |
|---|---|
| Interferer | A3S with a 42-line env-gated control switch (`instruments/a3s_control_switch.patch`, local build only) to attach one sched tracepoint at a time |
| Harness | `harness/interference_probe.sh` — one observer lifetime, three phases (BEFORE / DURING / AFTER attach), no restart |
| Ground truth | `harness/` uses the audit subsystem (different submission path) to prove the phase-2 executions really happened |
| Resolution | `harness/window_analysis.py` fixes the confirmed-attached window in audit's shared event order and resolves TOTAL vs SELECTIVE suppression with no clock |
| Evidence | `evidence/OI-001-*/`, one run per arm (`none`, `both`, `exec_only`, `fork_only`) |
| Specs | `docs/OBSERVATION_INTEGRITY_THREAT_MODEL.md`, `docs/OBSERVATION_INTEGRITY_EXPERIMENT_PLAN.md` |

**Its strength:** interference inside one observer lifetime with no restart
excludes lifecycle ordering by construction; the audit ground truth and window
analysis exclude the "selective vs total" ambiguity (suppression is total
within the confirmed window — all 15 execs missed, `sleep`/`date`/`seq`
included); the per-tracepoint control arms confirm the gate is per
`trace_event_call` (gating exec suppresses exec, gating fork does not).

## Where they agree, and the one wording to reconcile

Both establish: the effect is real; it is silent (loss = 0); it is
per-tracepoint (the fork stream is untouched when only exec is gated); and the
current health model does not represent it. "Host-wide" in experiment 2b means
host-wide **across perf consumers of the gated tracepoint** — which is the same
per-tracepoint gate experiment 2a isolates, not a claim that unrelated
tracepoints go dark. The two are consistent.

## Reproducing

Minimal-cause (2b):
```sh
sudo ./reproduce_interference.sh          # exit 0 = finding reproduced
```

Ambiguity-exclusion (2a):
```sh
(cd ../scenarios/exp01_linux_runtime_observation/recorder && cargo build --release)
# build the interferer with the control switch (local A3S checkout)
git -C /tmp/a3s apply "$PWD/instruments/a3s_control_switch.patch"   # if not applied
(cd /tmp/a3s && LLVM_SYS_181_PREFIX=/usr/lib/llvm-18 PATH=/usr/lib/llvm-18/bin:$PATH \
   cargo +nightly build --release -p a3s-observer-collector)
for A in none both exec_only fork_only; do ARM=$A bash harness/interference_probe.sh; done
```

Both require root, `CONFIG_AUDITSYSCALL=y`, and a mountable `tracefs`.

## The boundary — read before citing any result

Together these establish, on this host with this mechanism, that the
interference is real, silent, per-tracepoint, and total within the
confirmed-attached window, and that `aip-observe`'s health model cannot
represent it (CODE-PROVEN from `aip-observe/src/attest.rs`: `ObserverState`
reaches `Active` unless `probe_faults` is non-empty, and that is fed only by
loss > 0, sequence discontinuity, or restart — none of which this attack
produces).

They do **not** establish that an unprivileged subject can reach the gate
(UNKNOWN — it required root/`CAP_BPF` here), and make **no** claim that any host
observer resists a root or kernel adversary (out of boundary). The kernel
mechanism is corroborated behaviourally (per-tracepoint isolation, ftrace
surviving on a different submission path), not re-derived from kernel source on
this host.
