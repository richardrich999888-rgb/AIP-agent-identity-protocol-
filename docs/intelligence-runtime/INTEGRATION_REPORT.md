# Integration report — `feature/syntriass-intelligence-runtime-v01`

## Lineage (no rewrite, no force-push, nothing merged to protected branches)

`claude/release-completion-loop` (104e191) → `claude/vanian-sovereign-slice1`
(60b75e9) → `claude/vanian-system-one` (277136f) →
`claude/syntriass-airgap-intelligence` (dd0bd4c … a04b864) and
`research/syntriass-compute-memory` (9f88335). The integration branch is
9f88335 plus a no-ff merge of a04b864 (80d4386); the merged commits touch
only `research/bittorrent-p2p/`, so there were no conflicts or duplicate
interfaces to resolve. All historical benchmarks and failed experiments are
preserved.

## Commits on this branch

| Commit | Content |
|---|---|
| 986a19e | baseline inventory |
| 46485eb | fresh held-out data frozen before runtime/learner code (ir-tasks-v1, hard-reports-v5) |
| 45b9614 | capability engine core (quantity parser, expression language, artifact, validation, lifecycle) |
| 80753ef | controller, adapters, orchestration, sidecar |
| c15c3f2 | **fix**: capabilities could certify themselves → signed expert suites; CLI |
| b54795a | **fix**: streamed model hash (838 MB RSS spike) |
| fc5334b | lifecycle CLI, proposer, corrections, Phases A/C/D |
| 35c2d26 | router fix, baselines, Phases E/F, fresh v5 routing test, integrated cache attack |
| 647cb8e | six-scene offline demo |

## What was integrated

| Component | How |
|---|---|
| Sovereign corpus ACL, grounded RAG, validator, egress policy | called unchanged through `rag::answer` with a scoped `InferencePort` |
| System One interpreters and exact policy | sidecar runs the reference Python code byte-for-byte; policy re-implemented in `domain::maintenance` and tested against it |
| Compute-memory profiles and cache isolation | `adapters::supervisor` profiles; `domain::scope` (Rust port of `cachescope`) + `ScopedLlama` |
| AIP crypto | Ed25519 signatures for approvals and suites, SHA-256 identities |
| BitTorrent research | present on the branch as an optional research subsystem; not in the runtime |

## Tests (all passing at 647cb8e)

| Suite | Command | Result |
|---|---|---|
| runtime (unit, capability engine, learning flow, orchestration attacks) | `cargo test --offline -p syntriass-runtime` | 66 passed |
| Sovereign + AIP authorize/core/reconcile | `cargo test --offline -p vanian-sovereign -p aip-authorize -p aip-core -p aip-reconcile` | 580 passed |
| lint | `cargo fmt --check`, `cargo clippy -p syntriass-runtime --all-targets -- -D warnings` | clean |
| Python | `pytest research/{system-one,compute-memory,bittorrent-p2p}/tests` | 18 + 32 + 9 passed |

Not run: the full 40+-crate workspace (needs SoftHSM2 and crates outside this
dependency set).

## Build and reproduce

```sh
cargo build --offline --release -p syntriass-runtime        # target/release/syntriass
# llama.cpp native build (from llama-cpp-python 0.3.16 sdist, sha 34ed0f9b…):
cmake -S <sdist>/vendor/llama.cpp -B build-llama-native -DCMAKE_BUILD_TYPE=Release -DGGML_NATIVE=ON -DLLAMA_CURL=OFF
cmake --build build-llama-native --target llama-server -j
research/intelligence-runtime/demo/run_demo.sh OUT            # six scenes, ~25 s warm
python3 -I research/capability-learning/harness/run_learning.py OUT research/capability-learning/results/corrected/capability.json
research/compute-memory/bench/offline.sh python3 -I research/capability-learning/harness/baselines.py OUT --model … --model-sha … --server …
python3 -I research/capability-learning/harness/phase_e.py OUT research/capability-learning/results/corrected/capability.json
python3 -I research/intelligence-runtime/harness/run_maintenance.py OUT.json CONFIG…
python3 -I research/intelligence-runtime/harness/run_cache_attack.py OUT.json CONFIG
python3 -I research/capability-learning/harness/economics.py research/capability-learning/results
```

## Model manifest (SHA-256 verified against Hugging Face LFS etags)

| File | SHA-256 |
|---|---|
| qwen2.5-0.5b-instruct-q4_k_m.gguf | 74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db |
| qwen2.5-0.5b-instruct-q8_0.gguf | ca59ca7f13d0e15a8cfa77bd17e65d24f6844b554a7b6c12e07a5f89ff76844e |
| qwen2.5-1.5b-instruct-q4_k_m.gguf | 6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e |
| qwen2.5-1.5b-instruct-q8_0.gguf | d7efb072e7724d25048a4fda0a3e10b04bdef5d06b1403a1c93bd9f1240a63c8 |

Weights are not in the repository. The runtime refuses to start a model
whose streamed hash differs.

## Dataset manifest

| Set | Role | SHA-256 / manifest | Frozen in |
|---|---|---|---|
| ir-tasks-v1 (6 demos, 14 validation, 32 unseen, 8 false-activation, 3 docs) | learning benchmark | `research/capability-learning/data/ir-tasks-v1/MANIFEST.json` | 46485eb |
| hard-reports-v5 (37) | fresh routing test | 3a1e9fdd… | 46485eb |
| hard-reports-v4 (39), v3 (74) | earlier held-out / dev (seen) | fba32fd2… / 4ac54d2b… | be3bda8 / 7b53dd1 |
| Sovereign eval corpus (16 docs) | grounded QA | `sovereign/eval/` | Phase A |

All hand-written data has one author, who also wrote the system.

## Unresolved blockers

1. **AIP action path not in the runtime.** Consequential actions still go
   through `vanian-sovereign::app::act` only; capability approvals record a
   `consequential` flag that nothing yet enforces differently.
2. **No independent observer** (Sniffer Dog not attached); `CannotProve` is
   the ceiling for every record.
3. **Role collapse**: institution, approver, expert and runtime keys live on
   one host and uid in the research setup.
4. **Autonomous capability proposal failed** at 1.5B; learning required 7
   engineer corrections.
5. **Quantity parser kinds were built for the target task family**; a new
   family with other units needs reviewed parser code.
6. **Single author** for all evaluation data; no customer data.
7. **No GPU, no model > 1.5B, no energy counters**; Strategy D untested.
8. **Real-disk cold load** is ~15 MB/s on this VM (75 s for 1.1 GB);
   on-demand loading economics depend on page-cache state.
9. **BitTorrent**: no signed release manifest, rollback or import procedure;
   no physical-LAN measurement.
10. **IP ownership**: no VANIAN → SYNTRIASS assignment recorded; founder/legal
    decision required.
11. The final-report question list in the brief is truncated after "16. What".
