# Reproducing the learning benchmark (W6)

The benchmark: `docs/intelligence-runtime/LEARNING_BENCHMARK.md`. Dataset
`research/capability-learning/data/ir-tasks-v1`, frozen at `46485eb`. Harness
and results live under `research/capability-learning/`, owned by the
teaching-demo session; this folder reads them and never writes there.

## 1. Check the published table against the recorded files — works now, no model

```sh
python3 demos/benchmark/summarize.py          # table with sources
python3 demos/benchmark/summarize.py --json   # machine-readable
python3 -m unittest discover -s demos/benchmark -p 'test_*.py'
```

Output on `feature/wow-demos`, 2026-11-07:

```
system     correct/40  dec/32  false CPU-s/task  delta [bootstrap 95% CI]
B1                 11       3      0       3.24  -0.650 [-0.800, -0.500]
B2                 12       4      0       9.11  -0.625 [-0.800, -0.450]
B3                 13       5      0      15.92  -0.600 [-0.775, -0.425]
B4                  8       0      0       4.19  -0.725 [-0.850, -0.575]
candidate          37      29      0       3.05  —
```

**Agrees with the published table:** correct /40, decision items /32, false
activations, CPU-s for B1–B3, every paired delta, and every 95 % CI. The
published CIs have no committed script; a paired bootstrap (10,000 resamples,
seed 0) reproduces all four to three decimals.

**Does not agree — the candidate's CPU-s per task.** The table says "≤ 0.01".
That is the capability path only: 30 items, 0 model calls, 0.03 CPU-s in total.
Averaged over all 40 items, as the baselines are, it is **3.05 CPU-s per task**.
The 8 false-activation probes are not decided by the capability. The runtime
sends them to the model (`GroundedQa`, 8 model calls, 121.8 CPU-s) and gets all
8 right. Also, one capability item recorded 0.02 CPU-s, above the stated
"bounded at 0.01". B4's CPU-s (shown as "—") is 4.19 on the same basis.

## 2. Full offline rerun — BLOCKED

Every phase starts a local model server, so nothing beyond §1 runs without
model weights. The harness commands are the teaching session's own
(`harness/run_learning.py`, `harness/baselines.py`, `harness/phase_e.py`,
`harness/economics.py`, each documents its usage). They run inside
`research/compute-memory/bench/offline.sh` (no route out).

A one-command wrapper (W6.1) waits for the model resolver
(`deploy/syntriass/resolve_model.py`, PR #14, open, not merged) and staged
weights (W0.3). Until then this folder ships no `run.sh`: it would have to
hard-code model paths and digests, which is exactly what PR #14 removes.

Recorded model: `qwen2.5-1.5b-instruct-q8_0.gguf`, sha256 `d7efb072e772…a63c8`
(from `results/baselines_q8/summary.json`).

## 3. What a rerun should reproduce

There is one recorded run per system, so **no variance has been measured** and
no range is invented here. What can be said from the design:

| Part | Depends on the model? | Expected on a rerun with the same weights and the same llama.cpp build |
|---|---|---|
| Capability path (30 items): 29 correct, 0 model calls | no | identical; phase E's Q8 run gave the same label as run 1 on 40/40 items (`results/phase_e/report.json` vs `results/run1/report.json`) |
| Lifecycle: 14/14 expert cases, 4/4 counterexamples, signature + independence checks | no | identical |
| Other tenant / lower clearance: capability used 0 of 18 | no | identical |
| The 8 probes answered by the model (8/8) | yes | same if greedy decoding is deterministic on that build; **not established** |
| B1–B3 (greedy, temperature 0, seed 0) | yes | same if deterministic; **not established** across machines or builds |
| CPU-s and wall time | hardware | will differ; label every figure with its machine |

On a different machine or llama.cpp build, record any change in a correct count
as a difference. Don't widen a "range" to absorb it. W6.3 is that rerun.

## 4. Must not say

- "The system learned the procedure by itself" — the 1.5B model drafted 0
  compiling candidates; an engineer's 7 corrections were required.
- "Fine-tuned model" — no weights were updated; say **taught capability**.
- "Costs ≤ 0.01 CPU-s per task" without "on the capability path". Across the
  benchmark it is 3.05 CPU-s per task, because probes go to the model.
- "37/40 with zero model calls" — 32 of 40 items had zero model calls; the 8
  probes used the model.
- Any claim about human effort or human cost — it was not measured.
- That it transfers to other procedures, units or operations the parser does
  not support — not shown.
- That it holds on data written by anyone other than the system's author — all
  data, the procedure and the system had one author.
- Variance, confidence over reruns, or "reproducible on any machine" — one run
  per system, on one machine; §3 is design expectation, not measurement.
- That two of the 32 unseen items were unseen in the strict sense — they were
  printed once to a terminal before evaluation (disclosure 3).
