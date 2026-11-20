# Hardware sizing (W8.3) — PARTIAL: one machine measured, two required

The brief requires measured runs on at least two machines. Only one has been
available, so this is **not yet sizing guidance**. It records what one machine
did, so the second machine can be compared like for like.

**Machine A:** cloud sandbox, 4 vCPU, 15 GB RAM, no GPU, Linux 6.18. Docker and
auditd are local; the clock is not NTP-synchronised.

| Workload | Measured | n | Source |
|---|---|---|---|
| Catch the lying agent (security mode, end to end) | 24.8 s median, 25.0 s max wall time | 10 | `docs/demos/REHEARSAL_LOG.md` |
| Quantum X-ray (sample build + scan + report) | 1.0 s median, 1.2 s max | 10 | same |
| Full file scan of the sample container | 5 ms over 8 files | 1 | OVERLAY `demos/quantum-xray/README.md` |
| PQ switch demo (6 phases + 40 timed deliveries) | 35.4 s median, 35.6 s max | 10 | `docs/demos/REHEARSAL_LOG.md` |
| PQ overlay, per connection | +13.2 KB on the wire; time not separable from ~70 ms container exec noise | 3×20 | OVERLAY `demos/pq-switch/README.md` |
| Taught capability, per use | 0.4 ms median wall time; ≤ 0.02 CPU-s per item | 30 items, 1 run | `research/capability-learning/results/run1/report.json` |
| Runtime + sidecar memory, RSS (capability path) | 6.2–7.2 MiB runtime + 153.8–153.9 MiB sidecar | 40 items, 1 run | same |
| Local model server, 1.5B Q8 (baselines) | 3.7 GB peak | 1 run | `research/capability-learning/results/baselines_q8/summary.json` |

**Not measured:**
- Sniffer Dog's CPU and memory overhead on the observed host.
- The overlay under load.
- Any GPU.
- Any machine but A.

**To finish W8.3:** run `demos/launch.py rehearse MODE 10` for each mode on a
second machine with a different CPU and memory size, then add a column per
machine. Don't merge the two into averages.
