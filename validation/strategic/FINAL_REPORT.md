# VANIAN strategic validation report

**Dates:** 2026-10-28 (cycle 1), 2026-10-29 (cycle 2)
**Branch:** `claude/strategic-validation-loop`, based on
`integration/snifferdog-complete-enterprise-validation` @ `4ca5a4d`.
**Code under test (cycle 2):** `5b146be`. Cycles used: 2 of 12.

This is an evidence report. Assurance levels are kept separate; nothing is
promoted from a lower level; failed and superseded runs are kept beside the
ones that passed.

## Engineering changes (5b146be)

Two defects stopped the RBI honest path from ever reaching `Active`. Both were
reproduced before repair (`run_rbi_repro_1/`, `run_rbi_repro_2/`).

| Defect | Root cause (evidence) | Repair | Regression test |
|---|---|---|---|
| D1 control `Degraded` | batch 1 carried counted loss in 3/3 runs (connector `ENOBUFS`); Degraded is sticky for the epoch | connector drained first; keep reading after `ENOBUFS` (bounded); buffer enlarged to 8 MiB via `SO_RCVBUFFORCE` (`AIP_PROBE_CONNECTOR_RCVBUF_BYTES`, `0` = old) | `t15c` (live) |
| D2 control `IntegrityUnknown` with no attack | connector drained last → a sched exec fell into the next batch while its connector exec sat in this one; every control divergence had its counterpart in an adjacent batch; connector ts trails sched 591/591 | connector drained first; collector lets the previous **attested** batch of the **same probe run** corroborate (same pid/tgid, same 50 ms window) | sink + divergence unit tests; the boundary test fails with the carry removed |

Also: `AIP_SENSOR_LOSS sensor=<name> n=<n>` diagnostics. Loss is still
counted; detection of a blinded tracepoint is unchanged (negative tests N9).
Not shown: that the larger buffer is what fixed D1 — the kernel-default arm
also had zero loss in E2. It is kept as defence in depth and claimed as nothing
more.

Workspace tests: 3248 passed, 15 failed — all in `aip-hsm` softhsm, because
SoftHSM2 is not installed (environmental).

## Real agents executed

LangGraph 1.2.11 subject with a real child process (M1, 8 runs, cycle 1). The
pilot workload (E2) and the synthetic exec workload (E3) are not agents and
are not presented as such.

## Independent evidence

- **M1:** real agent → key-less probe → separate-process collector (sole key)
  → VERIFIED offline under `observer.pub` alone → lineage edge. `run_m1/`.
- **E2 (6 live pilot runs):** 6/6 control `Active` with coverage (RBI
  `check_control` PASS), live attack → signed `IntegrityUnknown` + coverage
  withdrawn, recovery without backfill, offline verify, deletion refused.
- **E3 (benchmark):** ground truth = workload-launched AND ftrace-confirmed
  (`GROUND_TRUTH.json`). ftrace is interface-independent from the sched sensor
  (same tracepoint) and facility-independent from the connector.

## Security results
`NEGATIVE_TESTS.md`: 11 negative tests, all behaved as required — tamper
rejection, deletion refusal, live interference → `IntegrityUnknown`, no
recovery backfill, unsynced-clock refusal, carry cannot mask blinding, starved
buffer counted, 0 fabricated records in 2000.

## Benchmark results (E3 run 3: release, drained window, 10 × 200)

| Metric | Result | Denominator / caveat |
|---|---|---|
| Sched recall | 1.0 | 2000/2000 |
| Connector recall | 1.0 | 2000/2000 |
| Sched precision | 1.0 | 0 duplicates, 0 fabricated |
| Attribution (pid) | 1.0 | pid only, not `ExecutionBinding` |
| Counted loss | 0 | |
| Offline verify | 10/10 | |
| exec→signed latency | p50 795 ms, p95 909 ms, max 950 | 1 s batch interval dominates; unsynced clock |
| Capture latency | NOT_RESOLVABLE | below ~1 ms anchor resolution |
| Overhead ON/OFF | median ×1.09 (0.91–1.51) | upper bound (includes ftrace); ~80 ms workload; n=10 |
| Attested coverage | 0 trials | all `ContinuityUnverified`: signed observations, not coverage |

Superseded and kept: runs 1 and 2 (debug, fixed 3 s window) had whole trials
with no signed batch (1/5, 3/10). gdb showed the probe CPU-bound, not hung; the
window closed before shipping. Harness amended (`METHODOLOGY.md`, Amendment 1).
These are numbers for one host, a synthetic workload and small n, not
general performance claims.

## RBI readiness — PARTIAL
The unmodified five-act rehearsal **fails on this host** because the collector
correctly refuses an unsynchronized clock (acts 3, 4, 4b pass). With clock
enforcement off, the system acts' requirements now pass 6/6. Gate: the
unmodified rehearsal on an NTP-synced host. (`RBI_READINESS.md`)

## Enterprise design-partner readiness — PARTIAL
See `PILOT_READINESS.md`.

## Production readiness
Not claimed. Open: synced-clock rehearsal; host-separated custody; M2
same-run authz→receipt→`VERIFIED_EXECUTION`; M3 multi-framework; installation;
kprobe sensors; HSM path; minor finding (collector overwrites a probe's
`ForeignTracepointGate` with generic `Unverifiable` — diagnostic only).

## Artifacts
`run_m1/`, `run_rbi_*` (pre-fix and post-fix), `e2_pilot_repeats/`,
`e3_benchmark/`, `measure/`, `STATUS.json`, `EVIDENCE_MANIFEST.json`,
`TEST_MATRIX.csv`, `BENCHMARK_RESULTS.csv`, `GROUND_TRUTH.json`,
`METHODOLOGY.md`, `NEGATIVE_TESTS.md`, `EXECUTION_JOURNAL.md`, `BLOCKERS.md`.
All throwaway key material removed before commit.

Reproduce (root, Linux, tracefs, `CAP_NET_ADMIN`):
```
cargo build -p aip-probe -p aip-collector -p aip-observe-verify            # debug: pilot
cargo build --release -p aip-probe -p aip-collector -p aip-observe-verify  # release: benchmark
validation/strategic/measure/repeat_pilot.sh <out> 3 fixed                 # E2
validation/strategic/measure/measure.sh <out> 10 200 4                     # E3
validation/rbi_demo/run.sh <out>                                           # needs NTP sync
# Unsynced host only: AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=0 (signs the error bound)
```

## Next three actions
1. Run the unmodified RBI rehearsal on an NTP-synchronized host (ideally with
   the collector on a second host).
2. M2: one task through authorization → MCP gateway receipt → kernel
   observation → reconciler `VERIFIED_EXECUTION`, same run.
3. E3 over a longer window that reaches attested coverage, plus a real agent
   workload; then M3 across ≥3 frameworks.
