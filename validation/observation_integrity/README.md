# `validation/observation_integrity/` — OBSERVATION-INTEGRITY-001

Reproduces, isolates, and characterises the observation-path interference found
during the AIRI experiment: an eBPF program attached to a sched tracepoint
silently blinds Sniffer Dog 2.0's `perf_event_open` sensor for that tracepoint,
with zero reported loss.

**Status: THREAT_REPRODUCED and THREAT_CHARACTERIZED. No production code changed.**

Read first: `../../docs/OBSERVATION_INTEGRITY_THREAT_MODEL.md` (the security
property and attack surface) and `../../docs/OBSERVATION_INTEGRITY_EXPERIMENT_PLAN.md`
(design, expected behaviour, results, AIRI implications).

## Layout

| Path | What |
|---|---|
| `harness/interference_probe.sh` | one run: ground truth + observer-under-test (single lifetime) + interferer across BEFORE/DURING/AFTER phases |
| `harness/analyze_interference.py` | per-phase counts and the guarded verdict |
| `harness/window_analysis.py` | resolves TOTAL vs SELECTIVE suppression using audit's shared event order (no clock) |
| `harness/summarize.py` | prints one run's result table |
| `instruments/a3s_control_switch.patch` | 42-line env-gated patch to the LOCAL A3S build enabling per-tracepoint arms; not upstreamed, touches nothing in this repo |
| `evidence/OI-001-*/` | raw artefacts, one run per arm |

## Run it

```sh
# build the observer-under-test driver (uses the production aip_observe sensor)
(cd ../scenarios/exp01_linux_runtime_observation/recorder && cargo build --release)

# build the interferer with the control switch (local A3S checkout)
git -C /tmp/a3s apply <this dir>/instruments/a3s_control_switch.patch   # if not already applied
(cd /tmp/a3s && LLVM_SYS_181_PREFIX=/usr/lib/llvm-18 PATH=/usr/lib/llvm-18/bin:$PATH \
   cargo +nightly build --release -p a3s-observer-collector)

# the four arms
for A in none both exec_only fork_only; do ARM=$A bash harness/interference_probe.sh; done
```

Requires root, `CONFIG_AUDITSYSCALL=y`, and a mountable `tracefs`. Each run
writes `result.json`, `window_analysis.json`, `metadata.json`, `timeline.txt`,
and every observer's raw stream to a fresh `evidence/OI-001-*` directory.

## What each arm shows

- `none` — negative control; the harness does not manufacture the signature.
- `both` — the raw effect: total suppression of the observer under test with
  loss = 0, while audit records every execution.
- `exec_only` / `fork_only` — the gate is per-tracepoint: gating one sched
  tracepoint suppresses that stream and leaves the other intact.

## The boundary — read before citing any result

This establishes, on this host with this mechanism, that the interference is
real, silent, per-tracepoint, and total within the confirmed-attached window,
and that the current health model cannot represent it (CODE-PROVEN from
`aip-observe/src/attest.rs`). It does **not** establish that an unprivileged
subject can reach the gate (UNKNOWN), and it makes **no** claim that any host
observer resists a root or kernel adversary (out of boundary). The kernel
mechanism itself is corroborated behaviourally here, not re-derived from kernel
source on this host — see the threat model §5.
