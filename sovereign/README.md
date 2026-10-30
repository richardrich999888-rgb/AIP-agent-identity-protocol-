# VANIAN Sovereign AI OS — slice 1

One vertical path, fully local, with AIP accountability on the action side.

```
OS user ─► principal (uid map) ─► SQLite FTS5 retrieval, ACL inside the query
        ─► llama.cpp on a loopback IP literal ─► citation gate (fail closed)

agent ─► AIP DecisionPoint ─► ExpectedExecution (signed)
      ─► runner: verify, re-derive params, pin program hash, one-shot
      ─► unshare(user,net,pid,mount) sandbox, empty env, SIGKILL deadline
      ─► RunRecord (runner-signed) ─► offline verifier (public anchors only)
```

Verified scope, failures and residual risks: [`docs/sovereign/SLICE1_EVIDENCE.md`](../docs/sovereign/SLICE1_EVIDENCE.md).
Architecture choice: [`docs/sovereign/ARCHITECTURE_DECISION.md`](../docs/sovereign/ARCHITECTURE_DECISION.md).

## Layout

```
sovereign/
  vanian-sovereign/
    src/domain/      pure types: corpus, classification, citation parsing
    src/policy/      pure decisions: retrieval ACL, inference egress
    src/ports.rs     CorpusStore, InferencePort
    src/adapters/    sqlite_corpus, llama_http (std-only HTTP), sandbox runner
    src/agent/       tool manifests, replay guard, run record + verifier
    src/rag.rs       grounded answering over ports
    src/app.rs       composition root (state dir, keys, CLI operations)
    src/bin/vanian.rs  argument parsing and printing only
    tests/agent_execution.rs  19 sandbox + tamper + authorization attacks
  demo/run_offline_demo.sh   end-to-end demo in a loopback-only namespace
  eval/                      grounded-QA set, runner, grader
  evidence/2026-10-31/       sealed outputs of the runs cited in the evidence doc
```

## Run

```bash
cargo test -p vanian-sovereign --locked
cargo build --release --locked -p vanian-sovereign

export VANIAN_BIN=$PWD/target/release/vanian
export VANIAN_LLAMA_SERVER=/path/to/llama-server     # built from pinned source
export VANIAN_MODEL=/path/to/model.gguf
export VANIAN_MODEL_SHA256=<approved hash>
sovereign/demo/run_offline_demo.sh                   # exits non-zero on any failed check

sovereign/eval/run_eval.sh "$VANIAN_BIN" "$VANIAN_LLAMA_SERVER" "$VANIAN_MODEL" "$VANIAN_MODEL_SHA256" ./eval-out
```

Host requirements: Linux with unprivileged user namespaces, util-linux
`unshare` at `/usr/bin/unshare`, Python 3 (demo/eval scripts only).
The `vanian` binary links only libc/libm/libgcc_s; SQLite is compiled in.

## Not claimed

- Independent execution observation. Every run record says `CannotProve`.
- Parity with any hosted assistant. See the eval numbers.
- Accreditation, certification or production readiness of any kind.
