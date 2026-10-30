# VANIAN System One — research workspace

Isolated from production code. Branch `claude/vanian-system-one`.

```
datasets/maintenance_priority.py   seeded, versioned dataset generator (v2)
data/maintenance-priority-v2/      generated splits + MANIFEST.json (hashes, class counts, contamination checks)
methods/symbolic.py                SOP-vocabulary extraction + rule table (no learning)
methods/tfidf_lr.py                TF-IDF + logistic regression (train split only)
methods/llm.py                     llama-server: single-token logit readout | JSON generation
harness/run.py                     runs one method, writes raw per-item predictions
harness/run_llm.sh                 LLM methods inside a loopback-only namespace (egress-checked)
harness/report.py                  all metrics from raw predictions; cascade composition; paired bootstrap
harness/metrics.py                 accuracy, macro-F1, ECE, Brier, AURC, risk–coverage, bootstrap, temperature fit
tests/                             pytest: metrics and symbolic baseline
results/<iteration>/               raw predictions, run.json, summary.json, REPORT.md
```

Reproduce: `python3 -I datasets/maintenance_priority.py data/maintenance-priority-v2`,
`python3 -m pytest -q tests`, `python3 harness/run.py symbolic|tfidf DATA OUT`,
`harness/run_llm.sh LLAMA_SERVER MODEL SHA DATA OUT 60 readout-nocache`,
`python3 harness/report.py results/iter1`.

Energy is **not measured**: this host exposes no RAPL/powercap interface.
