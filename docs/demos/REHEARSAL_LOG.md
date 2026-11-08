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
`customer-<sector>` other than banking and defence (not defined by the owner). OVERLAY `3d63f95` is local only; it is not pushed (no write access yet).

| Started (UTC) | Mode | Passes | Verdict | Wall time | Commits | Hardware | Results |
|---|---|---|---|---|---|---|---|
| 2026-11-07T13:32Z | quantum | 10/10 consecutive | PASS | 1.0 s median, 1.2 s max | AIP-agent-identity-protocol- 7ccbd4d; overlay 3d63f95 | 4 vCPU, 15 GB RAM, no GPU | `demos/rehearsal-evidence/2026-11-07/quantum/` |
| 2026-11-07T13:32Z | security | 10/10 consecutive | PASS | 24.8 s median, 25.0 s max | AIP-agent-identity-protocol- 7ccbd4d | 4 vCPU, 15 GB RAM, no GPU | `demos/rehearsal-evidence/2026-11-07/security/` |
| 2026-11-07T13:37Z | pq | 10/10 consecutive | PASS | 35.4 s median, 35.6 s max | AIP-agent-identity-protocol- 7ccbd4d; overlay 3d63f95 | 4 vCPU, 15 GB RAM, no GPU | `demos/rehearsal-evidence/2026-11-07/pq/` |
| 2026-11-08T04:18Z | pull-the-plug | 10/10 consecutive | PASS | 31.8 s median, 34.1 s max | AIP-agent-identity-protocol- 4876c75 | 4 vCPU, 15 GB RAM, no GPU | `demos/results/rehearse-pull-the-plug-20261108T041836Z` |
