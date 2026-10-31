# SYNTRIASS intelligence runtime v0.1 — architecture

Crate `sovereign/syntriass-runtime` (Rust) + the System One interpretation
sidecar (Python, pipes only) + llama.cpp `llama-server` (loopback only).
Ownership of reused code is as recorded in the repository (VANIAN
attribution unchanged); the crate name establishes nothing.

## Request flow (as implemented)

```
request (text, principal)
 │  principal: OS uid → principal map (Sovereign `principal_for_uid`) for `ask`;
 │  `serve --eval` takes principals from input lines (evaluation harness only)
 ▼
candidates ← capability store: ACTIVE ∧ approval signed by a configured
 │            approver ∧ tenant/domain/clearance match ∧ applies(text)
 │            (+ staleness: evidence digests via the SQL ACL, policy version,
 │             execution model hash)
 ▼
features ← sidecar.interpret(text)   (only if no capability applies)
 │          rules_equnit readings · TF-IDF interpreter readings ·
 │          unregistered equipment codes · registered asset count
 ▼
controller::route(features)  — pure; model output never reaches it
 │  E capability (exactly one fresh) │ ambiguous / stale → refuse
 │  gate: unregistered equipment → refuse
 │  A exact rules (readings cover every named asset)
 │  C/D model extraction (≥ 2 assets; tier configured, else refuse)
 │  B compact interpreter
 │  C/D grounded QA (question form; Sovereign rag::answer, unchanged)
 │  otherwise refuse
 ▼
execute ── exact policy (domain::maintenance) decides every maintenance
 │         priority, whoever extracted the readings
 │         capability: restricted expression language, no IO, no calls
 │         models: through ScopedLlama (cache bound to CacheScope)
 ▼
validate ── grounded QA: Sovereign citation / numeric / unit / entity validator
 │           capability: Execution::{Decided, Ambiguous, Failed, NotApplicable}
 ▼
response + cost (wall, CPU and RSS per process, tokens, cached tokens,
 │               model load ms, model and interpreter calls)
 ▼
audit ── hash-chained JSONL: principal scope, SHA-256 of the request
          (never its text), strategy, outcome label, capability hash, cost,
          observation = "CannotProve"
```

## Layers

| Layer | Modules | Rule |
|---|---|---|
| Domain (pure) | `domain::{maintenance, scope}` | exact SOP policy; `CacheScope` key + slot table |
| Capability (pure) | `capability::{quantity, expr, artifact, suite, validate, lifecycle, experience}` | typed artifact, restricted language, signed expert suites, lifecycle table, signed approvals |
| Controller (pure) | `controller` | strategy from features only |
| Ports | `ports` | `InterpreterPort`, `ScopedGenerator`, `CapabilityStore`, `Meter` |
| Adapters (IO) | `adapters::{sidecar, llama_scoped, supervisor, pool, store, meter}` | pipes to the sidecar; loopback HTTP to llama-server; SHA-256-verified model start; on-demand pool; owner-only file store; /proc meter |
| Orchestration | `app`, `learning` | request handling; capability lifecycle IO (evidence binding from the corpus) |
| Interface | `bin/syntriass.rs` | argument parsing only |

Reused unchanged from `vanian-sovereign`: corpus with ACL in SQL, grounded
RAG and validator, loopback egress policy. Added to it (additive):
`SqliteCorpus::{document_digest, snapshot_digest}` behind the same ACL.

## Serving profiles (from the compute-memory measurements)

| Profile | Model | Flags | Measured trade-off (1.5B, 2 vCPU) |
|---|---|---|---|
| memory | Q4_K_M | `--no-repack` | peak ≈ 1.3 GB, prefill −24…−32 % |
| balanced (default) | Q4_K_M | repack on | peak ≈ 2.1–2.2 GB |
| speed | Q8_0 | repack on | peak ≈ 3.3–3.6 GB, fastest and best task quality on this CPU |

All profiles: native ISA llama.cpp build, 2 slots × 4,096 context,
`--slot-save-path` pointing at a private (0700) directory that must stay
empty (erase needs it; the runtime never saves or restores KV state and the
supervisor errors if a slot file appears). Speculative decoding is never
enabled (falsified on this host). Models load on demand and stop after the
batch; nothing is kept resident between `serve` invocations.

## Trust anchors (operator configuration)

| Anchor | Used for |
|---|---|
| `approvers` (id → Ed25519 public key) | capability approval signatures; checked on every request |
| `experts` (id → Ed25519 public key) | signed validation suites |
| model SHA-256 per profile | verified (streamed) before every model start |

## Not integrated (see INTEGRATION_REPORT blockers)

- AIP-authorized tool execution (`vanian-sovereign::app::act`) exists but the
  runtime does not route requests to actions; capabilities only decide.
- No independent execution observer: every audit record is `CannotProve`.
- Larger model tier (Strategy D) is a configuration slot; no model > 1.5B
  ran on this host.
- BitTorrent distribution is a separate research subsystem, not in any
  request path.
