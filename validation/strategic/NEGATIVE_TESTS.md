# Negative tests (things that must fail, and did)

| # | Test | Expected | Observed | Evidence |
|---|---|---|---|---|
| N1 | Verify M1 archive under wrong observer id | reject | NOT VERIFIED | run_m1/ |
| N2 | Mutate signed `attested_at_ms` | reject | NOT VERIFIED | EXECUTION_JOURNAL cycle 1 |
| N3 | Mutate signed `observer_id` | reject | NOT VERIFIED | same |
| N4 | Mutate kernel-event `child_pid` | reject | NOT VERIFIED | same |
| N5 | Delete one record mid-archive (pilot, every E2 run) | reject, chain break named | refused 6/6 | e2_pilot_repeats/*/run_*/transcript.txt |
| N6 | Live foreign BPF on sched tracepoint (pilot attack, every E2 run) | collector signs IntegrityUnknown, coverage withdrawn | 6/6 | same; 148 no-counterpart divergences per run |
| N7 | Recovery must not backfill coverage over the unknown interval | no backfill | check_control PASS 6/6 | e2_pilot_repeats/*/run_*/check_control.log |
| N8 | Collector start on unsynchronized clock (default posture) | refuse | refused (STA_UNSYNC, 16 s) | run_rbi_postfix_unmodified/system/collector.refusal.log |
| N9 | Divergence carry must not hide a blinded tracepoint (reverse order, other probe run, other pid, outside 50 ms) | finding raised | raised | aip-observe divergence + aip-collector sink unit tests |
| N10 | Starved connector buffer (1 byte) | ENOBUFS counted, Degraded | PASS | sniffer_dog t15 |
| N11 | Fabrication check: signed exec records for paths the workload never ran | 0 | 0 over 2000 | e3_benchmark/run3_release_drained |

Not run: forged probe transport key, replayed batch, rolled-back collector
state, PID-reuse attack at reconciler level (component tests exist elsewhere in
the tree; not exercised in these live runs).
