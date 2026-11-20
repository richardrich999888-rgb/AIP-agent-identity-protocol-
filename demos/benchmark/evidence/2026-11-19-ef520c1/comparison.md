# Benchmark rerun vs recorded

Model sha256 (baselines): recorded `d7efb072e772…`, fresh `d7efb072e772…` — same file

| System | Correct /40 (rec → fresh) | Decision /32 | False act. | CPU-s/task | Same label on |
|---|---|---|---|---|---|
| B1 | 11 → 11 | 3 → 3 | 0 → 0 | 3.24 → 3.84 | 40/40 |
| B2 | 12 → 12 | 4 → 4 | 0 → 0 | 9.11 → 10.30 | 40/40 |
| B3 | 13 → 13 | 5 → 5 | 0 → 0 | 15.92 → 17.46 | 40/40 |
| B4 | 8 → 8 | 0 → 0 | 0 → 0 | 4.19 → 3.91 | 40/40 |
| candidate | 37 → 37 | 29 → 29 | 0 → 0 | 3.05 → 3.35 | 40/40 |

Lifecycle: recorded [14, 14, 4, 4, True], fresh [14, 14, 4, 4, True] (expert_passed, expert_cases, counterexamples_passed, counterexamples, suite_signature_ok)

Phase E (Q4 → Q8): fresh Q8 labels equal fresh Q4 labels on 40/40; equal recorded Q8 on 40/40
  e2_balanced: recorded ran=8 refused_stale=0; fresh ran=8 refused_stale=0
  e2_speed: recorded ran=0 refused_stale=8; fresh ran=0 refused_stale=8

## Items whose label changed

None.
