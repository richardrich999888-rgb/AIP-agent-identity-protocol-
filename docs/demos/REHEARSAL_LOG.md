# Rehearsal log (W7.3)

Written by `demos/launch.py rehearse`, one row per rehearsal, from the result files. A mode passes only with N consecutive passes. Each run's result file (commits,
hardware, exit code) is kept under the Results path; the full run folders stay on the
machine that ran them.

Discarded, 2026-11-08: a `customer-banking` batch (10/10 PASS, 54.3 s median)
recorded its commit as DIRTY. The only modified tracked file was this log,
which the pull-the-plug batch before it had just appended to. Run files now
list every changed file and do not count this log as a change
(`demos/common/harness.py` `OUTPUT_FILES`). The batch was run again.

Not rehearsed: `teach` (the teaching-demo loop has not reported ready) and any
`customer-<sector>` other than banking and defence (not defined by the owner). OVERLAY `3d63f95` was pushed to its `feature/wow-demos` on 2026-11-19.

| Started (UTC) | Mode | Passes | Verdict | Wall time | Commits | Hardware | Results |
|---|---|---|---|---|---|---|---|
| 2026-11-07T13:32Z | quantum | 10/10 consecutive | PASS | 1.0 s median, 1.2 s max | AIP-agent-identity-protocol- 7ccbd4d; overlay 3d63f95 | 4 vCPU, 15 GB RAM, no GPU | `demos/rehearsal-evidence/2026-11-07/quantum/` |
| 2026-11-07T13:32Z | security | 10/10 consecutive | PASS | 24.8 s median, 25.0 s max | AIP-agent-identity-protocol- 7ccbd4d | 4 vCPU, 15 GB RAM, no GPU | `demos/rehearsal-evidence/2026-11-07/security/` |
| 2026-11-07T13:37Z | pq | 10/10 consecutive | PASS | 35.4 s median, 35.6 s max | AIP-agent-identity-protocol- 7ccbd4d; overlay 3d63f95 | 4 vCPU, 15 GB RAM, no GPU | `demos/rehearsal-evidence/2026-11-07/pq/` |
| 2026-11-08T04:18Z | pull-the-plug | 10/10 consecutive | PASS | 31.8 s median, 34.1 s max | AIP-agent-identity-protocol- 4876c75 | 4 vCPU, 15 GB RAM, no GPU | `demos/rehearsal-evidence/2026-11-08/pull-the-plug/` |
| 2026-11-08T04:40Z | customer-banking | 10/10 consecutive | PASS | 54.1 s median, 54.8 s max | AIP-agent-identity-protocol- 6ad92ae | 4 vCPU, 15 GB RAM, no GPU | `demos/rehearsal-evidence/2026-11-08/customer-banking/` |
| 2026-11-08T04:49Z | customer-defence | 10/10 consecutive | PASS | 86.6 s median, 87.9 s max | AIP-agent-identity-protocol- 6ad92ae; overlay 3d63f95 | 4 vCPU, 15 GB RAM, no GPU | `demos/rehearsal-evidence/2026-11-08/customer-defence/` |
| 2026-11-08T05:04Z | investor-3min | 10/10 consecutive | PASS | 56.9 s median, 58.8 s max | AIP-agent-identity-protocol- 6ad92ae; overlay 3d63f95 | 4 vCPU, 15 GB RAM, no GPU | `demos/rehearsal-evidence/2026-11-08/investor-3min/` |
