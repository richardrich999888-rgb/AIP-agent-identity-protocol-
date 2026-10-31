# System One — iteration 2: can a compact interpreter replace SLM extraction?

Branch `claude/syntriass-airgap-intelligence`. Baseline research head
`277136f` (claude/vanian-system-one). Host unchanged: 2 vCPU x86-64 VM, 7 GB
RAM, no GPU, no power instrumentation (energy not reported). All methods ran
in a user+net namespace with no external route; the compact encoder ran with
`HF_HUB_OFFLINE=1` from a local cache.

## P0 — reproduction of iteration 1

| Item | Result |
|---|---|
| Dataset regeneration (`maintenance_priority.py`) | 5/5 splits byte-identical |
| Symbolic and TF-IDF predictions + probabilities | identical on all 3 test splits |
| Metric recomputation from committed raw predictions | 0 differences |
| LLM runs | not re-run (cost); raw predictions committed and re-scored identically |
| **Methodology defect found** | test_para kept equipment codes and units; a 10-line (equipment, unit) lookup scores **1.000**. Iteration 1's 0.977 for LLM extraction therefore did **not** demonstrate paraphrase understanding. Measurements were correct; the test did not measure what was claimed. |

## New data (frozen before methods ran)

| Set | Role | n | Hash | Commit |
|---|---|---|---|---|
| hard-reports-v3 | development (from iteration 2b) | 74 (18 abstain) | `4ac54d2b…` | `7b53dd1` |
| hard-reports-v4 | **held-out**, written before the gate was designed | 39 (13 abstain) | `fba32fd2…` | `be3bda8` |

Hand-written item by item (no templates): missing units, descriptive equipment
names, typos, Hinglish/Telugu-English, distractor numbers and code-like tokens,
unit conversion, multiple readings, and items whose only correct output is
ABSTAIN (unknown equipment, no value, ambiguous). Gold = annotated readings;
decision = the SOP policy over them. Limitation: written by the system builder,
not by plant staff.

## Methods (all produce readings; one shared exact policy decides)

| ID | Interpreter | Size / runtime |
|---|---|---|
| rules_vocab | SOP metric names + number | none |
| rules_equnit | equipment code + exact unit | none |
| tfidf_clf | char TF-IDF + LR quantity classifier, v2 train only | 158 MB process |
| bge_clf | frozen BAAI/bge-small-en-v1.5 (ONNX, 33M) + LR head, v2 train only | 755 MB process |
| qwen{0.5,1.5}b_json_v2 | Qwen2.5 Q4_K_M constrained JSON extraction with explicit empty-list abstention | 628 / 1,827 MB server |
| `+gate` | deterministic equipment-registry gate (designed on v3, iteration 2b) | µs |

## Results

### Held-out (hard-reports-v4, n = 39) — the evidence that counts

| Method | Decision acc | Correct releases | Wrong releases | Correct abstain | Coverage | p95 | Peak RSS |
|---|---|---|---|---|---|---|---|
| **bge_clf+gate** | **0.821** | 22 | **4** | 10/13 | 0.846 | 57 ms | 755 MB |
| tfidf_clf+gate | 0.795 | 21 | 4 | 10/13 | 0.808 | 0.9 ms | 158 MB |
| qwen1.5b_json_v2+gate | 0.692 | 22 | 12 | 5/13 | 0.846 | 6,105 ms | 1,827 MB |
| qwen1.5b_json_v2 | 0.564 | 22 | 17 | **0/13** | 0.846 | 6,105 ms | 1,827 MB |
| rules_equnit | 0.538 | 8 | **0** | 13/13 | 0.308 | ~0 | 32 MB |
| bge_clf | 0.692 | 22 | 9 | 5/13 | 0.846 | 57 ms | 755 MB |
| tfidf_clf | 0.667 | 21 | 9 | 5/13 | 0.808 | 0.9 ms | 158 MB |
| qwen0.5b_json_v2 | 0.205 | 8 | 31 | 0/13 | 0.308 | 1,979 ms | 628 MB |

Paired bootstrap on identical held-out items (2,000 resamples):

| Comparison | Δ decision acc | 95 % CI | Verdict |
|---|---|---|---|
| gate effect (bge or Qwen-1.5B) | +0.128 | [+0.026, +0.231] | **significant** |
| bge+gate − Qwen-1.5B+gate | +0.128 | [−0.026, +0.256] | not significant (p ≈ 0.06) |
| bge+gate − TF-IDF+gate | +0.026 | [−0.051, +0.128] | not significant |
| bge+gate − rules_equnit | +0.282 | [+0.077, +0.462] | significant |

### Development (hard-reports-v3, n = 74) — gate designed here

bge+gate 0.824 / 7 wrong; TF-IDF+gate 0.784 / 7 wrong; Qwen-1.5B 0.568 / 32
wrong, **0/18 correct abstentions**; Qwen-1.5B+gate 0.649.

## What the failures show

- **The 1.5B extractor fabricates.** It never returned the empty list it was
  told to use: on the "no value" items ("P-7 sounds rough today") it emitted a
  reading with a number not in the text. Constrained decoding guarantees the
  JSON shape, not the truth of its contents.
- **Trained classifiers cannot say "not covered".** Trained only on positive
  single-reading text, they map "P-9 vibration 9.1" onto P-7. The gate fixes the
  case where an unregistered code is written; it does not fix uncoded unknown
  assets (held-out: "instrument air dryer", "BFP-2" → 2 wrong releases).
- **Multi-reading reports are the LLM's only clear advantage** (v4: Qwen 3/3,
  classifiers 1/3; v3: 5/6 vs 2/6).
- 0.5B is unusable for extraction (0.205, 31 wrong releases of 39).

## Cost

Correct releases per compute-second on v4 (wall time, single stream, 2 vCPU):
bge+gate ≈ 22 / (39 × 0.047 s) ≈ **12 /s**; TF-IDF+gate ≈ 21 / (39 × 0.0005 s)
≈ **1,000 /s**; Qwen-1.5B+gate ≈ 22 / (39 × 4.6 s) ≈ **0.12 /s**. Model
load: TF-IDF 1.2 s (train), bge 52 s (embedding the 1,200 training texts),
Qwen-1.5B server load not separated from run (see llama logs).

## Verdicts

| Hypothesis | Verdict |
|---|---|
| A compact interpreter approaches SLM extraction at much lower cost | **VALIDATED IN SCOPE** — matched or exceeded on held-out (not significant for accuracy, significant for wrong releases and cost) |
| The neural encoder beats a conventional classifier | **INCONCLUSIVE** — +0.026, CI spans 0; TF-IDF is 60× faster and 4.8× smaller |
| A deterministic asset-registry gate removes unknown-equipment errors | **VALIDATED IN SCOPE** (held-out +0.128) with stated blind spots |
| Constrained SLM extraction abstains when told to | **FALSIFIED** (0/31 abstain items across v3+v4 at 1.5B) |

## Limits

n = 39 held-out items: CIs are wide. Single author for all hand-written data.
One host, one quantization, greedy decoding. Classifiers trained on synthetic
template text. Kev not run (cost); larger local models not runnable here.
