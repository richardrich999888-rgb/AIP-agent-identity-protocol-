# Rehearsal log (W7.3)

Written by `demos/launch.py rehearse`, one row per rehearsal, from the result files. A mode passes only with N consecutive passes. Each run's result file (commits,
hardware, exit code) is kept under the Results path; the full run folders stay on the
machine that ran them.

| Started (UTC) | Mode | Passes | Verdict | Wall time | Commits | Hardware | Results |
|---|---|---|---|---|---|---|---|
| 2026-11-07T13:32Z | quantum | 10/10 consecutive | PASS | 1.0 s median, 1.2 s max | AIP-agent-identity-protocol- 7ccbd4d; overlay 3d63f95 | 4 vCPU, 15 GB RAM, no GPU | `demos/rehearsal-evidence/2026-11-07/quantum/` |
| 2026-11-07T13:32Z | security | 10/10 consecutive | PASS | 24.8 s median, 25.0 s max | AIP-agent-identity-protocol- 7ccbd4d | 4 vCPU, 15 GB RAM, no GPU | `demos/rehearsal-evidence/2026-11-07/security/` |
| 2026-11-07T13:37Z | pq | 10/10 consecutive | PASS | 35.4 s median, 35.6 s max | AIP-agent-identity-protocol- 7ccbd4d; overlay 3d63f95 | 4 vCPU, 15 GB RAM, no GPU | `demos/rehearsal-evidence/2026-11-07/pq/` |

Not rehearsed, because `launch.py check` reports them NOT READY: `customer-<sector>` and
`investor-3min` (need W1.4: real local models), `teach` (the teaching-demo loop has not
reported ready). OVERLAY `3d63f95` is local only; it is not pushed (no write access yet).
