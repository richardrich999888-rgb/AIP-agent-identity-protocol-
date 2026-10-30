# VANIAN Sovereign AI OS — slice 1 evidence report

Date: 2026-10-31. Branch: `claude/vanian-sovereign-slice1`, based on
`claude/release-completion-loop` @ `104e191`. Host: 2 vCPU, 7 GB RAM, no GPU,
Linux 6.18 (Firecracker VM), util-linux 2.39.3, rustc/cargo 1.97.0.

## 1. Baseline inventory (what existed before this slice)

Inspected, not assumed. `main` (`872dbf3`, 2026-06-19) is four months behind;
the active line is `claude/release-completion-loop` (20 remote branches,
inventoried in `docs/release/BRANCH_INVENTORY.md` on that branch).

| Capability | Present? | Where | Basis |
|---|---|---|---|
| Agent identity, scoped tokens, delegation | Yes | aip-core, aip-types | code read + used by this slice's tests |
| Authorization → signed `ExpectedExecution` | Yes | aip-authorize | code read + used, denial reasons exercised |
| Process-instance binding | Yes | aip-core::execution_binding | used (`collect_self_binding`) |
| eBPF observation, collector, offline observer verifier | Yes | aip-probe, aip-collector, aip-observe-verify | STATUS.md + code layout; **not run in this slice** |
| Reconciliation with CANNOT_PROVE semantics | Yes | aip-reconcile | code read; not integrated yet |
| seccomp execve enforcement | Yes | aip-enforce | code read; not integrated yet |
| Air-gap install procedure (observer stack) | Docs only | deploy/enterprise/airgap | read |
| Local LLM inference | **No** | — | `git ls-files` search: no llama/gguf/vllm/ollama code |
| Document retrieval / RAG | **No** | — | same search |
| Workspace UI | **No** | — | same search |

SYNTRIASS Edge, Overlay, AIRON–SIEPMU, ChainVanta repositories: **not
inspected** — not attached to this session (see Blocked).

## 2. What this slice built

| Component | Status |
|---|---|
| SQLite FTS5 corpus, ACL in SQL + defence-in-depth re-check, versioning | Implemented and tested |
| Loopback-only inference adapter (IP literal; hostnames never resolved) | Implemented and tested |
| Deterministic prompt, source fencing, citation gate (withhold unless grounded) | Implemented and tested |
| Tool manifests pinned by program SHA-256; canonical argv bound into AIP params | Implemented and tested |
| Runner: DP-anchor verify, window, process binding, param re-derivation, program hash, one-shot | Implemented and tested |
| Namespace sandbox (user, net, pid, mount), empty env, SIGKILL deadline | Implemented and tested |
| Runner-signed `RunRecord`, offline verifier, no "verified" verdict exists | Implemented and tested |
| `vanian` CLI: init / ingest / ask / act / verify | Implemented; exercised by demo |
| Offline demo in loopback-only namespace | Executed, exit 0 |
| Grounded-QA eval (8 questions) | Executed on 2 models |

## 3. Tests — exact commands and outcomes

```
cargo test -p vanian-sovereign --locked
  lib:                    43 passed, 0 failed
  tests/agent_execution:  19 passed, 0 failed   (~21 s; ~2 s/fixture is key generation)
cargo clippy -p vanian-sovereign --all-targets --locked -- -D warnings   clean
cargo fmt --all -- --check                                              clean
```

Attacks covered by `tests/agent_execution.rs` (real sandbox, not mocked):
ungranted tool → `ActionOutOfScope`; argument substitution after authorization
→ `ParameterMismatch` and decision **not** consumed; replay → refused; decision
moved to another process → `BindingMismatch`; program swapped on disk →
`ProgramDigestMismatch`; rogue decision point → refused; expired → refused;
missing `unshare` → refused before consumption (fail closed); sandbox sees only
`lo`; empty environment; 30 s sleep killed at 300 ms deadline; tampered exit
code, forged payload hash, foreign runner key, swapped expectation, tampered
expectation, stripped signature → each rejected with a named reason; JSON edit
`CannotProve`→`VerifiedExecution` fails to deserialize.

Unit-level: FTS5 operator / SQL injection strings neither error nor widen
results; stale index rows removed on re-ingest; IPv4-mapped `::ffff:8.8.8.8`
refused; malformed HTTP / chunk framing are errors not panics; citation parser
ignores overflow digits and non-ASCII safely.

## 4. Offline demonstration

`sovereign/demo/run_offline_demo.sh`, run with Qwen2.5-1.5B-Instruct Q4_K_M.
Transcript and artifacts: `sovereign/evidence/2026-10-31/demo-qwen2.5-1.5b/`.

| Step | Result |
|---|---|
| Disconnection | Namespace has only `lo`; TCP to 1.1.1.1:443 → no route |
| Model integrity | SHA-256 matched before load (also matches publisher LFS hash) |
| Retrieval | 2 internal docs retrieved; restricted + other-tenant docs absent |
| Answer | **Withheld** — model answered without a citation marker |
| Restricted question | Withheld; override code and plant-beta text absent |
| Non-loopback endpoints | `10.0.0.5:8080`, `api.example.com:443` refused |
| Authorized tool | `count-alarms` authorized, run in nested sandbox, stdout `2` |
| Offline verify | `AUTHORIZED_AND_RUNNER_ATTESTED`, observation `CannotProve` |
| Tampered evidence | `REJECTED: RunRecordPayloadMismatch` |
| Unauthorized tool | `DENIED … ActionOutOfScope`; no evidence file; nothing ran |

## 5. Measured AI quality (not a parity claim)

8 questions: 6 answerable from internal docs, 1 restricted, 1 cross-tenant.
Grading is substring fact-presence, which overstates correctness of long
answers. Raw outputs are in `results.jsonl` for review.

| Model (Q4_K_M, CPU) | Raw fact correct | Released | Released correct | Released wrong | Leaks | Median / max latency |
|---|---|---|---|---|---|---|
| Qwen2.5-0.5B-Instruct | 5/6 | 1/8 | 0 | 0 | 0 | 3.1 s / 4.1 s |
| Qwen2.5-1.5B-Instruct | 6/6 | 3/8 | 3 | 0 | 0 | 3.6 s / 8.3 s |

Observations: 0.5B confabulated an "override code" in the first (pre-gate)
demo run; the gate now withholds such output. 0.5B's one "grounded" release
echoed the source block — citation presence is not answer relevance. 1.5B
answered `INSUFFICIENT SOURCES` for both restricted and cross-tenant questions.

## 6. Failures found and fixed this slice

1. **Fail-open answer release.** First demo displayed ungrounded,
   confabulated text with only a label. Fixed: only `Grounded` text is
   released; raw output kept for audit behind `--show-withheld yes`.
   Regression test `uncited_answer_is_withheld_but_auditable`.
2. Loopback is down in a fresh network namespace and the host has no
   `iproute2`; demo brings `lo` up via `SIOCSIFFLAGS`.
3. clippy `large_enum_variant` on `ActOutcome`; boxed.

## 7. Residual risks (not solved, stated)

- **Roles collapsed:** institution, DP, runner, agent keys on one host/uid;
  DP and runner run in the agent's process. Keys plaintext at rest (0600).
- **No independent observation:** runner can lie about what ran.
- **TOCTOU** between program hash check and `execve` (aip-enforce closes it).
- **No filesystem isolation** in the tool sandbox; tool reads host FS as the
  runner's uid. No cgroup CPU/memory limits.
- **Citation ≠ entailment:** a cited answer can still misstate its source.
- **Prompt injection** inside an authorized document can steer answer text
  (cannot widen retrieval or authorize tools).
- **Authentication** is the OS login via uid map; no MFA, no session audit.
- **Network test scope:** the namespace proves no route for this process
  tree only. It says nothing about host-level telemetry, other processes, or
  covert channels. llama-server's own behavior was not audited.
- Single-writer replay log; concurrent runners per state dir unsupported.

## 8. Blocked

- SYNTRIASS Edge / Overlay / AIRON–SIEPMU / ChainVanta repos: not attached;
  repository names not provided. Inventory incomplete for them.
- Sniffer Dog live capture: requires the eBPF probe on a host where loading
  BPF is permitted; not attempted in this slice.
- GPU benchmarks: no GPU available.

## 9. Backlog, in priority order

1. Citation discipline: llama-server JSON-schema constrained output
   `{answer, citations:[int], insufficient:bool}` + deterministic numeric
   fidelity check (every number in the answer must occur in a cited passage).
   Acceptance: ≥5/6 released-correct, 0 released-wrong, 0 leaks on the eval,
   eval grown to ≥40 questions.
2. Attach Sniffer Dog: run `aip-probe` + `aip-collector` around the sandbox,
   reconcile via `aip-reconcile`; `Observation` gains a reconciled variant only
   when reconciliation succeeds.
3. Split runner and DP into separate processes/uids; keys via aip-hsm.
4. aip-enforce on tool execve; read-only bind mounts + cgroup limits.
5. Signed offline bundle (binary, llama-server, model manifest) verified
   against a customer trust root before install.
6. Workspace UI (local, no CDN) over the same app layer.
