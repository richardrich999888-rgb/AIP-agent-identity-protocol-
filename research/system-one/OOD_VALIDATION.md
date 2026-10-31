# Out-of-distribution validation

| Set | Why it is OOD | Built by | Used for |
|---|---|---|---|
| v2 test_para | metric names paraphrased | generator | **invalid as a language test**: (equipment, unit) rule = 1.000 |
| v2 test_ood | unseen templates, 1–3 readings | generator | reference |
| hard-reports-v3 | hand-written; no units, descriptive names, typos, mixed language, distractors, conversion, multi, must-abstain | builder | development (gate designed here) |
| hard-reports-v4 | as v3, new items, code-like non-equipment tokens | builder, frozen before iteration-2b methods | **held-out** |

Survives on held-out: compact interpreter ≥ SLM extraction at ~100× lower
latency; gate effect +0.128. Does not survive: iteration-1 claim of paraphrase
understanding. Still missing: text written by people other than the builder;
real plant reports.
