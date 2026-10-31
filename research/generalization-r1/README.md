# SYNTRIASS generalization falsification, round 1

This is a research-only addition to base `2883da7bf5b8591a31bf24789c1d0722f83a6624`. Production runtime and seven-scene demonstration are unchanged. The dataset/protocol was committed as `d44a3ee` before methods. This round establishes no new foundation-model architecture or patentable invention.

## Reproduce

From repository root, with Rust dependencies available locally:

```sh
cargo build --release --locked -p syntriass-runtime
python3 -m venv .venv
.venv/bin/pip install pytest==8.4.2
.venv/bin/python -m pytest -q research/generalization-r1/test_methods.py
python3 research/generalization-r1/replay_records.py
python3 research/generalization-r1/benchmark.py independent-replay
```

The benchmark refuses to overwrite an existing result directory. Installation requires staged dependencies; the three experiment commands require no network or model. Replay verifies actual signatures using only public synthetic instrument keys. It executes the capability checker, not sandboxed tools. Do not describe the replay as independent kernel observation.

To regenerate historical baseline data, preserving original manifest hashes:

```sh
python3 research/capability-learning/datasets/ir_tasks_v1.py research/capability-learning/data/ir-tasks-v1
python3 research/capability-learning/datasets/bt_tasks_v1.py research/capability-learning/data/bt-tasks-v1
python3 research/capability-learning/datasets/tx_tasks_v1.py research/capability-learning/data/tx-tasks-v1
python3 research/capability-learning/harness/fp_resonance.py .local/new-resonance
python3 research/capability-learning/harness/fp_evidence.py .local/evidence-reproduction
```

`record_probe.py` generates fresh synthetic signed cases after the last command; remove nothing: change its output path for another run. Private test signing keys stay under ignored `.local`, never in committed results. `replay_records.py` is the simpler verification path.

## Measurement scope

`results/logistics` is the initial frozen evaluation. `results/logistics-control` adds conventional early-exit enumeration after the initial result; it reuses the consumed evaluation and is a diagnostic control, not fresh generalization evidence. Both runs and all per-example outputs are preserved. Timing is one host, repeated fixed workloads, warm batches and Python process CPU. Data generation, extraction, learning, human approval and model startup are excluded from deterministic timing. RSS is whole-process high-water RSS, not incremental method memory. Interval evaluation assumes monotone constraints and independent alternative sets; arbitrary relations or non-monotone procedures require a different sound abstraction or enumeration.

The conservative baseline is intentionally safe but weak: capacity and weight remain ambiguous even in the `exact` stock category, so it releases no answers. Do not compare only against that baseline. Eager binding is likewise unsafe; the meaningful conventional competitors are exhaustive, short-circuit and interval execution.

`llm_baseline.py` requires staged pinned Qwen3-4B and llama-server under `.local/runtime`. It performs only loopback requests. Its RAG arm supplies the sole relevant policy; retrieval cost/failure is excluded. Its 70-case subset is diagnostic, not a fresh independent holdout. Extrema compression is shared across LLM modes but was not used in the earlier full-list timing run: no cross-run compute-ratio claim is valid. The structured-skill arm explicitly supplies the conventional interval algorithm. Server CPU/RSS cover all modes together, not per-arm attribution. See results for exact model hash and settings.

Model staging is reproducible with `bash research/generalization-r1/stage_model.sh` (Python 3.12, C++ compiler and CMake 4.1.2 used here). This is explicitly an online preparation step; alternatively transfer the verified artifacts through your approved offline import process. Official Qwen model metadata declares Apache-2.0; deployment licence review remains the operator's responsibility. Revision and both source/model SHA256 checks are pinned in the script. No weights are committed.

Local diagnostic commands (each output directory must not already exist):

```sh
python3 research/generalization-r1/llm_baseline.py
python3 research/generalization-r1/score_llm.py
python3 research/generalization-r1/llm_baseline.py --fewshot --dev
python3 research/generalization-r1/score_llm.py llm-fewshot-dev
python3 research/generalization-r1/llm_baseline.py --fewshot
python3 research/generalization-r1/score_llm.py llm-fewshot
```
