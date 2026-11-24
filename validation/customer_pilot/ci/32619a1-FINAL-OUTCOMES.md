# Final implementation candidate CI outcomes

Source: 32619a16b102d14d9cca667699a3b64394ca644f. Tested PR merge checkout: e004eb0e49d39647c6e509909b0264c023416a9d.

All seven workflows and all 22 configured jobs finished: **16 successful, 3 failed, 3 gated/skipped**. The overall suite remains failed because strict security gates are open.

| Check | Result |
| --- | --- |
| Format and clippy with warnings denied | Pass |
| Workspace debug | 3,322 passed, 0 failed, 7 ignored |
| Workspace release | 3,324 passed, 0 failed, 5 ignored |
| Doctests, each profile | 2 passed, 0 failed, 2 ignored |
| Additional focused release g14_04 | 20/20 repetitions passed |
| Coverage execution | 3,322 passed, 0 failed, 7 ignored |
| Line coverage | 53,335 / 64,342 = 82.893% |
| Function coverage | 5,373 / 6,857 = 78.3579% |
| Genuine execution, interruption and recovery | All passed; public evidence preserved |
| RBI live rehearsal, offline verification, deleted-record rejection | Passed |

The relocated-executable and failed-build/stale-fallback regressions passed in debug, release and coverage. Coverage has no configured minimum-percentage gate. Two real-client tests ignored in the general workspace suite ran explicitly in enterprise integration. Regeneration helpers, observer throughput measurement and two doctest examples remain ignored. The RED ledger job has 43 reproduced/runnable cases, two notes and ten blocked cases.

Genuine same-run artifact 14711609978 belongs to run 44916522554; its SHA-256 is f0c35f0d2ef1239f0615f0b95d0128b778ca1cdab6a56d25a650e9f8d9b2c75e. RBI artifact 14711873252 belongs to run 44916522539: 85 signed batches, 3,696 kernel events and four health records verified; deleting one middle record was rejected. Coverage artifact 14712177239 belongs to run 44916522570. Independent local replay is recorded separately under validation/customer_pilot/evidence/32619a1.

Strict failures remain: gitleaks 217 findings; Trivy 4 HIGH misconfigurations; cargo deny rejects chrono 0.4.45 under RUSTSEC-2026-0543. Cargo audit passed with its pre-existing RUSTSEC-2026-0097 ignore, while retaining chrono and rustix informational advisories. No waiver was added.

Skipped jobs: local-evidence-agent-linux, local-evidence-agent-offline and Agent Zero genuine-task. The Agent Zero image/API component job does not establish a genuine Agent Zero workload. Package lifecycle testing used a staging root; the full sensor service and separately administered collector were not installed or accepted. No customer-pilot readiness or independent-custody claim is made.
