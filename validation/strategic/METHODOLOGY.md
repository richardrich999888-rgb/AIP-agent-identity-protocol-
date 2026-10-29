# Measurement methodology (E2, E3)

## E3 — recall, precision, attribution, latency, overhead
Harness: `measure/measure.sh` → `measure/workload.py` → `measure/analyze.py`.
Matching rules and denominators are written in the header of `measure.sh` and
were fixed before results were read. Summary:

- **Ground truth:** see `GROUND_TRUTH.json` (workload-launched AND
  ftrace-confirmed).
- **Sched recall** = GT execs with a signed `SchedTracepoint ProcessExec` of the
  same unique filename / |GT|.
- **Sched precision** = marker-path records matched to GT / all marker-path
  records (duplicates counted against it). Records for paths the workload never
  ran are counted separately as fabrication.
- **Connector recall** = GT execs whose pid appears in a signed `ProcConnector`
  Exec / |GT|.
- **Attribution accuracy** = matched sched records whose pid equals the
  workload-recorded pid. This is *pid* attribution, not `ExecutionBinding`
  identity and not a reconciler verdict.
- **Latency:** exec→signed = collector `attested_at_ms` − kernel exec time
  (converted with the batch's clock anchor). Launch→exec capture latency is
  reported as NOT_RESOLVABLE because values straddle zero below the ~1 ms
  anchor resolution.
- **Overhead:** workload wall time ON/OFF, paired per trial, same K and CONC.
  ON includes the ftrace reference, so it is an upper bound for the pipeline.

Only signed evidence counts: a batch the probe observed but never shipped is a
miss. Each trial is verified offline under its own `observer.pub`.

### Amendment 1 and the superseded runs (kept, not hidden)
Runs 1 and 2 (debug build, window closed on a fixed 3 s sleep) had trials with
**no signed batch at all** (1/5, 3/10). gdb on a stalled probe showed it
CPU-bound measuring/encoding (debug build), not hung: the window closed before
the batches covering the workload were shipped. The window rule was changed to
"close after two further acknowledged batches post-workload, 60 s ceiling,
undrained trials recorded" and the build profile became a recorded parameter.
Run 3 (release) used it: 10/10 drained. Debug-vs-release was not separately
benchmarked, so run 3 does not say how a debug build would do under the
drained rule.

## E2 — repeated pilot runs
Harness: `measure/repeat_pilot.sh`. Pass rule fixed in its header: pilot exit 0
AND `validation/rbi_demo/check_control.py` exit 0. Reported beside it: counted
loss per sensor (`AIP_SENSOR_LOSS`), and `measure/divergence_replay.py` totals.
Two arms: `AIP_PROBE_CONNECTOR_RCVBUF_BYTES=0` (kernel default) and unset (8 MiB
requested). Clock enforcement off (`AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=0`) on
this unsynced host; the collector signs the 16 s error bound.

## Scope limits
One host, 4 vCPU, kernel 6.18.44; collector process-separated not
host-separated; unsynchronized clock; synthetic exec workload (not an agent)
for E3; small samples (n=10 trials, n=3 runs per arm).
