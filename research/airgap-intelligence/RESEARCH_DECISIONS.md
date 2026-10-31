# Experiment ranking

Scores 1–5 (5 = best for priority). Cost is inverted (5 = cheapest).

| # | Experiment | Customer value | Falsifiable on this host | Cost | Difficulty (5=easy) | Total | Decision |
|---|---|---|---|---|---|---|---|
| 1 | Hard extraction test set rules cannot solve + compact interpreters vs Qwen extraction | 5 | 5 | 4 | 4 | 18 | **Now (iteration 2)** |
| 2 | Cascade cost on a stated traffic mix vs always-largest-model | 5 | 4 | 3 | 3 | 15 | Next |
| 3 | Integrate best interpreter into the sovereign offline workflow (demo) | 5 | 4 | 3 | 3 | 15 | After 1 |
| 4 | AIP observer (aip-probe/collector) around the sandbox + aip-reconcile | 4 | 4 | 2 | 2 | 12 | After 3 |
| 5 | Signed model manifest + chunk verification (no P2P) | 4 | 5 | 4 | 4 | 17 | Small, any time |
| 6 | P2P model distribution vs single server (Dragonfly as baseline) | 2 | 2 (one host; needs a LAN testbed) | 2 | 2 | 8 | Defer |
| 7 | Task distribution scheduler | 2 | 1 | 1 | 1 | 5 | Defer |
| 8 | Distributed inference | 1 | 1 | 1 | 1 | 4 | Expect to reject (Petals evidence) |
| 9 | Kev-0.5b decision baseline (CPU, torch) | 3 | 4 | 2 | 3 | 12 | Optional baseline |

P2P experiments are deferred, not rejected: this host is one 2-vCPU VM, so any
"network" result would be loopback and meaningless for a LAN claim.
