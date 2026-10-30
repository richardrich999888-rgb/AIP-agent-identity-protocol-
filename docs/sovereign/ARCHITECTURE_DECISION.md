# ADR-SOV-001 — Architecture for VANIAN Sovereign AI OS

Status: accepted for slice 1. Date: 2026-10-31. Branch `claude/vanian-sovereign-slice1`.

## Decision

**C (hybrid intelligence) on B's process boundaries, delivered incrementally
as a single Rust crate with hexagonal internals first.**

- The model is one untrusted component behind `InferencePort`. It decides
  nothing about access or authority.
- Deterministic code owns every security decision: retrieval ACL (in SQL and
  re-checked), egress (IP-literal loopback only), citation gate, tool
  authorization (AIP `DecisionPoint`), parameter binding, replay, sandboxing.
- Process boundaries that exist **now**: inference server (llama.cpp), the
  `vanian` CLI, each sandboxed tool. Boundaries that are **designed but
  collapsed** in slice 1: decision point, runner, observer (see Consequences).

## Options evaluated

| Criterion | A Monolith | B Modular services | C Hybrid (chosen, on B boundaries) |
|---|---|---|---|
| Offline correctness | Good | Good | Good |
| Security isolation | Poor: model, policy, keys share a process | Strong | Strong where boundaries are real |
| AI quality per watt | Model does everything; needs largest model | Same as A unless routed | Deterministic parts are free; model only writes prose. Measured below |
| Install complexity | Lowest | Highest (many daemons) | Medium; grows only as boundaries are split |
| Reuse of AIP/Sniffer Dog | Awkward (AIP assumes separate DP/observer) | Natural | Natural |
| Failure recovery | One crash = everything | Per service | Per process |

A was rejected because it puts the decision-point and runner keys in the same
address space as model-controlled text, which contradicts the AIP design
(ADR-015 §5.1: claimant ≠ observer). B as a day-one target was rejected on
delivery cost: five daemons before one working answer. C keeps B's trust
boundaries as the target and only pays for each split when it is built.

## Evidence that drove it

- **Determinism carries the security weight.** In slice 1, all six refusal
  classes (cross-tenant, over-clearance, non-loopback endpoint, ungranted
  tool, argument substitution, tampered evidence) are enforced by code paths
  with no model input, and are covered by tests (`cargo test -p vanian-sovereign`).
- **Small models need a gate, not trust.** Measured on 8 questions
  (evidence/2026-10-31): Qwen2.5-0.5B had the right fact in 5/6 raw outputs
  but cited 0; it confabulated an "override code" when not gated. 1.5B: 6/6
  raw-correct, 3/6 cited and released, 0 wrong released, 0 leaks. The gate,
  not the model, is what prevents confabulation reaching the user.
- **Compute:** 1.5B Q4_K_M on 2 vCPU, no GPU: median 3.6 s, max 8.3 s per
  answer. A CPU-only deployment is viable for SOP-style QA; it is not viable
  for long-form coding assistance at this size.

## Rejected sub-choices

- vLLM: GPU-first, heavy Python runtime; llama.cpp builds to one static
  binary from a hash-pinned source tarball. Revisit for GPU deployments.
- Vector search in slice 1: needs a local embedding model and an ANN index;
  BM25 over FTS5 answered every eval question's retrieval correctly. Added
  when an eval shows lexical retrieval failing.
- A new database engine: no requirement found that SQLite does not meet.
- An HTTP client library: the only destination is a loopback IP literal; a
  std-only client removes DNS, proxies, redirects and TLS from the trust base.

## Consequences

- Slice 1 collapses roles: institution, decision point, runner and agent keys
  are distinct but on one host, one uid, and `act` runs DP + runner in the
  agent's process. **No separation-of-duties claim is valid until these are
  split into separately administered processes.**
- Run records are runner claims. Independent observation requires attaching
  `aip-probe`/`aip-collector` and reconciling via `aip-reconcile`.
