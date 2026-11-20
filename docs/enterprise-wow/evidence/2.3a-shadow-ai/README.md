# 2.3a: heuristic shadow AI, live (adversarial #1 and #2)

Command, run three times: `python3 command-center/lab/live_shadow_ai.py OUT_DIR`.
Each run: **7 passed / 0 failed checks**.

| Run | HEURISTIC_AI_WORKLOAD | Processes observed | A's attribution_missing_reason |
|---|---|---|---|
| 1 | 1 (A only) | 13 | no binding |
| 2 | 1 (A only) | 16 | no binding |
| 3 | 1 (A only) | 13 | no binding |

The processes:

- **A** is a `python3` client of the mock model's port. It is classified
  HEURISTIC in every run.
- **B** is `python3 -m http.server` plus a `python3` client that fetches from
  it. **C** is `sort`. All three are observed and UNCLASSIFIED in every run,
  so the negative is not vacuous.

As a false-positive check on unrelated traffic, the three 3.4b archives
(collector-kill workload, no model traffic) were classified with 8900
declared as the model endpoint: **0 HEURISTIC** out of 154–160 processes
each (`false-positive-3.4b-archives.txt`).

**Port orientation was measured, not assumed.** A lab experiment connected a
known pid to a known port. Only CLOSE→SYN_SENT (7→2) carries the
connecting process's pid, with `remote` as the destination. On loopback,
the other transitions carry whichever pid the CPU was in (softirq). They are
ignored.

Limits:

- **"no binding" in every run.** The probe bound no start time for A's pid
  in these runs, so `pid_reuse_not_excluded` is true. That makes this a
  heuristic, not a confirmed identity.
- The registry is empty here. P0-059's registry, and the reasons
  "signature invalid" and "no gateway session", are 2.3b (blocked on 0.1).
- The model endpoint is declared by the operator. A workload that reaches a
  model through an undeclared address is not flagged.
- The mock model's replies are TEST DATA.
