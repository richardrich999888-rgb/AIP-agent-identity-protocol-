# Baseline comparison (iteration 2, held-out hard-reports-v4)

Strongest baselines by role: exact rules (rules_equnit: 0 wrong releases, 0.308
coverage); conventional classifier (TF-IDF+gate: 0.795, 0.9 ms); generative SLM
(Qwen2.5-1.5B+gate: 0.692, 6.1 s). Full table, CIs and paired tests:
REPORT_ITER2.md. Raw per-item predictions: results/iter2/*/hard_v4.jsonl.
Reproduce: `python3 -I datasets/hard_reports_v4.py data/hard-reports-v4`;
`SPLITS=hard_v4 python3 harness/extract_eval.py <method> OUT`;
`harness/run_extract_llm.sh LLAMA MODEL SHA OUT`; `python3 harness/extract_report.py results/iter2`.
