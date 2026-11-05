# Demo inventory (W0.1)

Taken 2026-11-05 from `git fetch --all` in both repositories. Static facts
(branches, files, test-function counts) are from git; nothing here has been
built or run yet unless it says so. Every later number must come from a run
on recorded hardware.

## Hardware this session can measure on

4 vCPU Intel Xeon @ 2.10 GHz, 15 GB RAM, 12 GB free disk, no GPU, no KVM,
kernel 6.18.44, Docker present, root, no NTP synchronization. This is **below
the target demo machine** (16 cores, 64 GB). Any figure measured here is
labelled with this hardware and is not a sizing claim. 12 GB free disk limits
how many local models fit at once (W0.3).

## AIP repository (`richardrich999888-rgb/AIP-agent-identity-protocol-`)

30 remote branches (20 at the 30 Oct inventory in `docs/release/BRANCH_INVENTORY.md`).

| Line | Head | Date | Relation |
|---|---|---|---|
| `feature/syntriass-runtime-v02` | `2883da7` | 10-31 | **Base of `feature/wow-demos`.** Contains `main` and all of `fix/vanian-end-to-end-green`; 92 commits not on the snifferdog line |
| `integration/snifferdog-complete-enterprise-validation` | `ab16159` | 11-03 | **Moved since the brief** (was `57ac0d1`). 20 commits not on the runtime line: mostly retained evidence (1,473 files under `validation/enterprise`), `examples/local-evidence-agent` (168 files), real-agent adapters, the 3 Nov Qwen observations (`6eb36fd`) |
| `fix/vanian-end-to-end-green` | `4d0ce1e` | 10-29 | Release-candidate line; fully contained in the runtime line |
| `main` | `872dbf3` | 06-19 | Stale |
| `codex/open-source-agents-nov1-validation`, `testing`, `research/*`, `claude/syntriass-*`, `claude/vanian-*`, `feature/syntriass-intelligence-runtime-v01` | 10-31…11-02 | New since 30 Oct; not yet classified (W0 follow-up if a demo needs them) |

### Claims in the brief, checked

| Claim | Result | Where |
|---|---|---|
| Runtime crate `sovereign/syntriass-runtime`, binary `syntriass` | Present on `2883da7` | `sovereign/syntriass-runtime/Cargo.toml` |
| Offline wrapper | Present. Runs the command in a fresh user+net namespace with only loopback; **refuses to start** if `1.1.1.1:443` is reachable | `research/compute-memory/bench/offline.sh` |
| Seven-scene demo | Present. Real binary, real models, every model call under `offline.sh`. **Scene 3 replays a recorded model draft and 7 recorded engineer corrections by default**; it re-drafts live only with `--propose` (~4 min on 2 vCPU, expected to fail validation on its own). Under rule 1 that scene must be shown as "recorded" unless `--propose` is used | `research/intelligence-runtime/demo/run_demo.sh` |
| Scripted Sniffer Dog run | Present on both lines | `validation/rbi_demo/run.sh` |
| LangGraph agent, 167 events signed and verified offline | Confirmed as **167 process exec/fork events** in the collector-signed archive | `integrations/agents/README.md` L14; `docs/pilot/WHAT_THE_TESTS_PROVE.md` L32 |
| bpftrace 113 agreed / 0 missing | Confirmed; the same record also lists **1 AIP-only** event | `validation/external/corroborate/README.md` L27 |
| auditd 112 agreed / 0 missing | Confirmed; also **2 AIP-only** | same file, L28 |
| Real Qwen agent observed (3 Nov) | Confirmed on the snifferdog line only (Qwen2.5-Coder-1.5B-Instruct via Agent Zero) | `6eb36fd`; `docs/enterprise/OPEN_SOURCE_AGENT_OBSERVATION.md` |

### Caveat that W2 must respect

The strategic validation work (`claude/strategic-validation-loop`, M1
correction) found that the M1 harness's single "lineage edge" was its own
`bash → /usr/bin/sleep`, not the agent's, and that short-lived agent children
are often recorded *unbound*. W2's "undeclared action" must therefore be
detected from signed kernel events tied to the agent, not from a lineage edge
that may not be derived.

## OVERLAY repository (`richardrich999888-rgb/OVERLAY`)

Cloned at `/home/user/overlay` (shallow; all 23 branch heads fetched).
**Attached read-only**: pushing `feature/wow-demos` there will need push
access.

| Claim | Result |
|---|---|
| Overlay (hybrid X25519 + ML-KEM-768 for unmodified TCP apps) | Repository present; demo packaging not yet inspected (W5.1) |
| `deploy/cbom/`, `docs/CBOM_ENGINE_PLAN.md` | Present on `main` (`bbfa36d`, 08-10) |
| "CBOM engine with ~2,540 tests" — where it lives | **In OVERLAY; no other repository needed.** The figure matches *whole-repository* Rust test-function counts on the 8 Sep `feature/*` branches (2,542–2,607, of which ~646 are under CBOM paths). `main` has only 408 tests (61 CBOM) |
| Most complete CBOM line | `claude/cbom-dashboard-ai-analysis-uujp2g` (`eccb668`, 10-17): 3,037 test functions, 875 under CBOM paths; `src/cbom` (84 files), `crates/cbom-{model,policy,ports}`, `deploy/cbom`, dashboard, source scan (incl. Solidity, crypto API use) — **W0 recommends it as the W4 base**, pending a build and real test run in W4.1 |

Counts are `#[test]` / `#[tokio::test]` occurrences from `git grep` on each
branch head, not executed results.

Reproduce:

```sh
git -C /home/user/overlay grep -cE '#\[(tokio::)?test' <branch> -- '*.rs' | awk -F: '{s+=$NF} END {print s}'
```

## Not yet established (later items)

- Whether the runtime builds and the seven-scene demo runs on this hardware (W0.2 / W1).
- Local models: **none present on this machine** (no `*.gguf`/`*.safetensors` over 50 MB, no `~/.ollama`). The bench harness pins four hash-verified Qwen2.5 GGUF builds (0.5B/1.5B, q4_k_m/q8_0) in `research/compute-memory/bench/run_all.sh`. All are Qwen; **no non-Chinese model is pinned yet** (rule 7). W0.3 needs one connected staging download, run by the user.
- The Overlay's runnable demo path (W5).
- A non-Chinese model option for every demo (rule 7; W0.3).
