# Baseline inventory — state before the intelligence runtime (2026-10-31)

Recorded from a full (unshallowed) fetch of `origin`. The clone was shallow
until this inventory; branch relationships below were computed only after
`git fetch --unshallow`.

## 1. Source commits

| Branch | Head | Relationship |
|---|---|---|
| `main` | `872dbf3` (2026-06-19) | protected; not modified |
| `claude/release-completion-loop` | `104e191` | 422 commits ahead of `main`; base of everything below |
| `claude/vanian-sovereign-slice1` | `60b75e9` | `104e191` + 3 commits (`b73e062`, `cc3fccf`, `60b75e9`) |
| `claude/vanian-system-one` | `277136f` | descends from `60b75e9` |
| `claude/syntriass-airgap-intelligence` | `a04b864` | descends from `277136f`; 4 BitTorrent commits not in compute-memory |
| `research/syntriass-compute-memory` | `9f88335` | descends from `dd0bd4c` (airgap); 5 compute-memory commits |
| **`feature/syntriass-intelligence-runtime-v01`** | `80d4386` | `9f88335` + no-ff merge of `a04b864`; both histories preserved; no conflicts (merged commits touch only `research/bittorrent-p2p/`) |

## 2. Existing capabilities (implemented and tested)

| Component | Location | What it does | Evidence |
|---|---|---|---|
| Grounded QA | `sovereign/vanian-sovereign` (`rag.rs`, `domain/{grounding,support,citation}.rs`) | ACL-filtered SQLite FTS5 retrieval → constrained-JSON answer → citation, numeric-claim and unit validation; withholds unsupported answers | 75 unit + 19 integration tests; Phase A: 0 wrong releases, 0 disclosures on 44 dev questions |
| Access-controlled corpus | `adapters/sqlite_corpus.rs` | tenant + clearance enforced inside the SQL query; injection-phrase quarantine; `PRAGMA quick_check` | tests |
| Loopback-only inference | `adapters/llama_http.rs`, `policy/egress.rs` | HTTP only to a loopback IP literal; JSON-schema response format | tests |
| Authorized tool execution | `app::act`, `agent/{tool,replay,evidence}.rs`, `adapters/sandbox.rs` | AIP `DecisionPoint` issues signed `ExpectedExecution`; runner re-derives parameter digest; user+net namespace sandbox; one-shot replay guard; runner-signed `RunRecord`; offline verifier | `tests/agent_execution.rs` |
| AIP authorization | `aip-standalone/aip-authorize` | `DecisionPoint`, `ExpectedExecution`, `DenialReason::ActionOutOfScope` | crate tests |
| AIP identity / tokens / binding | `aip-standalone/aip-core` | identities, scoped tokens, `execution_binding::collect_self_binding` | crate tests |
| Reconciliation | `aip-standalone/aip-reconcile` | expected vs observed; ceiling is `CANNOT_PROVE` without an independent observer; `VERIFIED_EXECUTION` unreachable from runner-only evidence | crate tests |
| Structured interpreters | `research/system-one/methods` (Python) | exact rules, TF-IDF+LR, bge-small+LR quantity classifiers, Qwen JSON extraction, equipment-registry gate | 18 tests; held-out v4 results |
| Exact maintenance policy | `research/system-one/datasets/maintenance_priority.py` (`METRICS`, priority) | deterministic SOP thresholds → priority 1–4 | dataset tests |
| Cache isolation policy | `research/compute-memory/cachescope` (Python) | scope key over model, tokenizer, policy, snapshot, principal scope, domain; erase on scope change | 25 tests; side-channel AUC 1.00 → 0.43 |
| Profiling harness | `research/compute-memory/bench` | `/proc`-based RSS/PSS/faults; offline namespace wrapper; load/throughput/prefix/side-channel/restore/shared/specdec | raw JSON |
| Routing simulation | `research/compute-memory/tools/cascade.py` | replays recorded predictions (not a live controller) | 7 tests |
| P2P distribution | `research/bittorrent-p2p/bench` (libtorrent 2.1.1) | private v2 torrents, SSL-torrent peer auth, corruption and resume tests on emulated LAN | 9 tests; GO_NO_GO conditional |

## 3. Missing integrations (what this branch must build)

1. No runtime connects Sovereign RAG, System One interpreters, the exact
   policy and model selection: they are separate programs (Rust CLI vs Python
   research code).
2. No live controller: routing exists only as an offline replay.
3. `cachescope` is Python research code; the Rust inference adapter
   (`LlamaHttp`) has no slot management, so the integrated path still uses a
   shared prompt cache.
4. No experience records, capability artifacts, lifecycle or validation.
5. No serving profiles in the runtime (native build, repack, mmap are
   measured but not selectable).
6. No per-request cost accounting.
7. No fresh held-out data for routing (v3 and v4 have both been inspected).
8. BitTorrent distribution has no signed release manifest.

## 4. Tests run for this inventory (integration branch `80d4386`)

| Suite | Command | Result |
|---|---|---|
| Rust: `vanian-sovereign`, `aip-authorize`, `aip-core`, `aip-reconcile` (+ their test targets) | `cargo test --offline -p … ` | **579 passed, 0 failed** |
| Rust format | `cargo fmt --check -p vanian-sovereign` | clean |
| Rust lint | `cargo clippy -p vanian-sovereign --all-targets -- -D warnings` | exit 0 |
| Python: System One | `pytest research/system-one/tests` | 18 passed |
| Python: compute-memory | `pytest research/compute-memory/tests` | 32 passed |
| Python: bittorrent-p2p | `pytest research/bittorrent-p2p/tests` | 9 passed |

**Not run**: the full 40+-crate workspace (includes `aip-hsm`, which needs
SoftHSM2, and other crates outside this runtime's dependency set).

## 5. Known defects and open failures

| # | Defect | Source |
|---|---|---|
| D1 | Phase A original-six gate **failed** (4/6; mis-citation correctly withheld) | `docs/sovereign/PHASE_A_EVIDENCE.md` |
| D2 | Role collapse: institution, decision-point, runner and agent keys on one host, one uid; decision point runs in the agent's process | `app.rs` header |
| D3 | No independent observer attached; every execution record is `CannotProve` | `lib.rs` |
| D4 | All hand-written evaluation data authored by the system builder | System One reports |
| D5 | Registry gate blind spots: codes outside known families (BFP-2), uncoded assets | `REPORT_ITER2.md` |
| D6 | Routing result (0.872) obtained after inspecting v3/v4 | `ADAPTIVE_ROUTING.md` |
| D7 | `cascade.py` normalises codes with `int(num)`; `extractors.unregistered_equipment` does not (`P-07` differs) | code comparison |
| D8 | Side-channel test: one slot, 20 trials; multi-slot behaviour unmeasured | `CACHE_SECURITY.md` |
| D9 | Enabling llama-server slot erase requires `--slot-save-path`, which also enables KV save/restore to disk | `server.cpp` |
| D10 | llama.cpp as originally built used AVX2 only; a native build differs in greedy text (task decisions identical on 39 items) | `LLM_EXPERIMENTS.md` |
| D11 | libtorrent defaults lose up to 100 MiB on crash; fixed by setting, not by default | `bittorrent-p2p/EXPERIMENT_RESULTS.md` |

## 6. Hardware limitations

2 vCPU Xeon (AVX-512, AMX-INT8), 8 GB RAM, no swap, **no GPU**, no power
counters, Firecracker VM. Largest runnable model: Qwen2.5-1.5B (Q8_0, 3.3 GB
serving). No result here validates GPU paths, ≥ 7B models or energy.

## 7. Dependencies (pinned)

| Dependency | Version | Use |
|---|---|---|
| Rust toolchain | 1.97.0 | workspace |
| rusqlite (bundled SQLite) | =0.32.1 | corpus |
| llama.cpp | vendored in llama-cpp-python 0.3.16 (sdist sha `34ed0f9b…`) | inference |
| Models | Qwen2.5-0.5B/1.5B-Instruct GGUF, Q4_K_M and Q8_0 (SHA-256 in `research/compute-memory/BASELINES.md`) | inference |
| Python | 3.13; scikit-learn, numpy, fastembed 0.9.1 (bge-small ONNX) | interpreters |
| libtorrent | 2.1.1 | optional distribution |
| pyroute2 | 0.9.7 | network emulation only |

## 8. Security limitations carried forward

- Prompt cache shared across principals in the Rust path (D-integration 3).
- No authentication beyond the OS uid → principal map.
- Keys are files (0600) on one host; no HSM in this path.
- Runner-signed evidence only; `CannotProve` is the ceiling.
- No signed release manifest for models; model hash is pinned by the operator.

## 9. Unresolved IP ownership

- `README.md`: "© 2025–2026 K. NAGA SRI GANESH"; crates, patents and earlier
  documents are named and attributed to VANIAN Technologies;
  `Cargo.toml` license `LicenseRef-Proprietary`.
- **No IP assignment between VANIAN Technologies and SYNTRIASS Labs is
  recorded in this repository.** The SYNTRIASS product name used in new
  documents does not establish ownership of any existing code or patent.
  Settlement requires founder/legal documentation; nothing in this branch
  changes existing notices or authorship.
