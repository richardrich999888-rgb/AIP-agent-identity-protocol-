# Adaptive routing — when does model cooperation pay?

## Method

`tools/cascade.py` replays the per-item predictions System One iteration 2
recorded for each method (decision + measured latency) through a cascade. No
model is re-run, so cascade quality is exactly what the stages produced.
Rules were written before any cascade result was computed, **but both
hand-written sets (v3, v4) had already been seen**, so these results are
exploratory; a fresh held-out set is required before any claim.

| Rule | Behaviour |
|---|---|
| R1 | exact rules (equipment code + unit); if they abstain → encoder + gate |
| R2 | encoder + gate; reports naming ≥ 2 registered equipment codes → 1.5B SLM + gate |
| R3 | R1, then R2 |

## Results

| Strategy | v4 acc | v4 wrong rel. | v4 compute-s (39 items) | v3 acc | v3 wrong rel. | SLM calls (v4 / v3) |
|---|---|---|---|---|---|---|
| exact rules only | 0.538 | 0 | ~0 | 0.459 | 2 | 0 |
| TF-IDF + gate | 0.795 | 4 | 0.02 | 0.784 | 7 | 0 |
| encoder + gate | 0.821 | 4 | 1.84 | 0.824 | 7 | 0 |
| SLM + gate | 0.692 | 12 | 190.7 | 0.649 | 26 | 39 / 74 |
| R1 | 0.821 | 4 | 1.42 | **0.878** | 5 | 0 |
| R2 | **0.872** | 4 | 13.2 | 0.851 | 5 | 2 / 4 |
| R3 | **0.872** | 4 | 12.7 | **0.878** | 5 | 2 / 0 |

Correct decisions per compute-second on v4: SLM-only 0.14; R3 2.7 (19×);
encoder-only 17; TF-IDF 1,345.

## Economics, including memory

| Deployment | Resident memory | Per-escalation cost |
|---|---|---|
| encoder only | ~755 MB (process) | — |
| encoder + SLM both resident | ~755 + 2,076 = **~2.8 GB** | ~3.6 s (p50 native) |
| encoder resident, SLM loaded on demand | ~755 MB idle | +1.1–2.0 s load (warm/cold, measured) + 3.6 s |
| SLM only | ~2.1 GB | every item 3.6 s |

The cascade's memory cost is the second model. Keeping it resident costs
more than running the SLM alone (2.8 vs 2.1 GB) while serving 5 % of
traffic. Where escalations are rare (here 2–4 per 39–74 reports), **loading
the SLM on demand** keeps idle memory at the encoder's ~0.75 GB and adds
~1–2 s to the rare escalated request. That trade is favourable unless
escalations are frequent or latency-critical.

## Answers this supports (exploratory)

- Cooperation beats the single larger model when most requests are
  structured and a cheap, deterministic signal identifies the hard ones
  (multi-reading reports). It did here on both sets.
- It loses when the escalation signal is poor (every escalation costs ~250×
  an encoder call) or when both models must stay resident on a
  memory-limited host.
- Not tested: a learned router, concurrency, a genuinely harder task where
  the larger model is necessary, and a fresh held-out set.
