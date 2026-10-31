# System One — iteration 1 report

Branch `claude/vanian-system-one`. Host: 2 vCPU (x86-64, Firecracker VM),
7 GB RAM, no GPU, **no power instrumentation** (no RAPL/powercap): energy per
decision is not reported. LLMs: Qwen2.5-0.5B/1.5B-Instruct Q4_K_M (publisher
SHA-256 verified) on llama.cpp from the llama-cpp-python 0.3.16 sdist, all LLM
runs inside a loopback-only network namespace with an egress check that
refuses to start if an external route exists.

Dataset `maintenance-priority-v2` (seeded; hashes in MANIFEST.json): 4-class
priority decision from operator text + SOP thresholds. Splits: train 1200,
val 300, test_id 300, **test_para 300** (metric names replaced by paraphrases
absent from SOP and training), **test_ood 300** (unseen templates, 1–3
readings per report). Labels are computed by the SOP rule table, which is
itself a limitation (see §5). Raw predictions for every number below are in
`results/iter1/**/preds_*.jsonl`; all metrics are recomputed by
`harness/report.py`.

## 1. Results (1.5B unless noted; JSON variants on a class-balanced 60/split subset)

| Method | test_id | test_para | test_ood | p95 latency (per escalated / per item) | Peak RSS |
|---|---|---|---|---|---|
| Symbolic (SOP vocabulary + rules) | 1.000 | 0.293 (271 abstain) | 1.000 | 0.02 ms | 147 MB |
| TF-IDF + LR | 0.867 | 0.897 | 0.440 | 2.4–3.0 ms | 161 MB |
| LLM decision, single-token readout | 0.357 | 0.343 | 0.277 | 1.2–2.4 s | 1,821 MB |
| LLM decision, JSON decision-first (n=60) | 0.250 | 0.233 | 0.267 | 7.6–9.2 s | 1,830 MB |
| LLM decision, JSON reason-first (n=60) | 0.317 | 0.233 | 0.267 | 8.7–11.4 s | 1,869 MB |
| LLM **interprets** (quantity letter) + exact policy | 0.897 | 0.783 | 0.490 | 1.0–2.1 s | — |
| LLM **interprets** (JSON readings) + exact policy | — | **0.977** [0.957, 0.993] | 0.607 | 3.5 s / 8.5 s | 1,830 MB |
| **Cascade: rules → TF-IDF** | 1.000 | 0.903 [0.870, 0.937] | 1.000 | 2.7 ms on 271/300 para | 161 MB |
| **Cascade: rules → LLM JSON extraction** | 1.000 | **0.977** [0.957, 0.993] | 1.000 | 3.5 s on 271/300 para; 0 ms elsewhere | 1,830 MB when escalating |
| 0.5B, any LLM mode | ≤0.40 | ≤0.32 | ≤0.40 | — | 621–646 MB |

Majority-class rate: test_id 0.43, test_para 0.40, test_ood 0.24 (class
imbalance per split in MANIFEST.json; JSON subsets are balanced, chance 0.25).

Paired bootstrap (same items, 2,000 resamples):

- Cascade(rules→LLM extraction) − cascade(rules→TF-IDF), test_para: **+0.073 [+0.037, +0.113]**.
- LLM extraction JSON − LLM extraction single-token, test_para: **+0.193 [+0.143, +0.247]**.
- LLM decision readout − LLM decision JSON, every split and both JSON orders: |Δ| ≤ 0.05, every CI spans 0; readout p95 **75–87 % lower**, throughput **4.0–7.6×**.
- Prompt-prefix cache (shared SOP state), decision readout test_id: p95 **8,376 ms uncached → 1,194 ms cached (7.0×)**.

## 2. Hypotheses

| Hypothesis | Verdict | Evidence |
|---|---|---|
| A — decisions need no text generation | **Survives for cost only; falsified for interpretation.** Single-token decision readout matches JSON accuracy at 4–7.6× throughput, but at 1.5B both are near chance. For *interpretation*, generating structured JSON beat the single-token readout by +0.19. | §1 |
| B — conditional compute | **Survives.** Rules settle 600/900 test items exactly at ~0 ms; only 271 of 900 escalate. The cascade is never worse than either component on any split. | §1 |
| C — knowledge outside the weights | **Survives in its strong form.** The SOP in context did not let the LLM apply thresholds (reasoning traces assert "103 C is above 105 C"); the same SOP as executable rules is exact. | rationale samples in `json_reason_first/preds_*.jsonl` |
| D — shared representation amortises cost | **Survives.** 7.0× p95 reduction from reusing the cached SOP prefix. | §1 |
| E — memory bandwidth | Not tested. | — |

## 3. Main finding

The decisive variable is **what the model is asked to output, not the model.**
The same 1.5B weights score 0.343 when asked for the decision and 0.977 when
asked only for the policy's input variables, with exact code applying the
policy (IL-001). A 2 ms TF-IDF classifier is the strongest *cheap* learned
interpreter (0.903 in cascade); the LLM extractor is +7.3 points better on
paraphrase at ~1,300× the per-item latency on escalated items. Which to deploy
is a cost/accuracy choice per installation, and the cascade makes it explicit.

## 4. Measurement defects found and corrected (preserved, not deleted)

1. **Readout prompt v1** left ~95 % of next-token mass on words; digits were
   read from the tail. Kept as `readout_v1_invalid`.
2. **llama.cpp logprobs disagreed with emitted tokens** for the A–H letter
   readout (argmax agreed 31–68 %; emitted letters 15/16 correct vs logprob
   argmax 4/16 on a probe). Digit readouts agreed 300/300. All readouts are now
   scored on the emitted token; a regression test pins this
   (`tests/test_run_scoring.py`). Kept as `*_logprob_invalid`. The no-cache
   ablation directory carries that suffix, but its **latency** values are
   valid (scoring does not affect timing).
3. **JSON schema order** forced the decision before the rationale; a
   reason-first variant was added and reported.
4. **Symbolic baseline** read the "7" of "P-7" as a measurement; fixed with a
   regression test.
5. My own interim statement that "every readout result is an artifact" was
   over-broad; the decision readout was valid. Corrected here.

## 5. Threats to validity

- Labels come from the same rule table the symbolic method executes. Its
  1.000 scores show the method is exact *when the vocabulary matches*, not
  that real plant text is this regular.
- Paraphrase items keep in-distribution units (`s`, `drops/min`), which leak
  some identity to TF-IDF and the LLM.
- JSON methods ran on 60 items per split (balanced); their CIs are wide (±0.1).
- One host, one quantization, one seed for LLM decoding (greedy). No GPU numbers.
- Calibration is not evaluated for LLM methods: probabilities from this
  llama.cpp build are not trustworthy for letter tokens, and JSON gives none.
- Kev was **not run** (needs PyTorch + its serving stack; both reachable,
  scheduled for iteration 2). Jev was not called (hosted API; not used).

## 6. Against the brief's research targets

Reference = the generative baseline (1.5B JSON). Cascade(rules→LLM extraction):
quality +0.71 to +0.75 absolute on every split; p95 on escalated items −60 %
vs reason-first JSON (3.5 s vs 8.7 s), ~0 ms on non-escalated; throughput on
mixed traffic depends on the escalation rate (here 30 % of items) — not
reported as a single number. Peak memory is unchanged **when** the LLM is
loaded (1.8 GB); the rules→TF-IDF cascade uses 161 MB (−91 %). ECE ≤ 0.05:
rules→TF-IDF cascade 0.039 on test_para; LLM methods not calibratable here.
Zero external connections: every LLM run started only after the namespace
egress check passed. **Energy: not measured.**

## 7. Next

1. Iteration 2: run **Kev-0.5b** (same Qwen2.5-0.5B base) as the trained
   decision-head baseline, CPU fp32, through its own server.
2. Train a small **extraction head** (quantity + value span) instead of a
   decision head — the IL-001 direction — and compare with LLM JSON
   extraction at ~ms latency.
3. Replace the synthetic rule-derived labels with independently written
   paraphrase and noisy reports (human-style), so the symbolic baseline can no
   longer be exact by construction.
