# OrbitalTrust — The Accountability Layer for AI Agents

Three integrated products. This document is the build plan's traceability
record: every component graded against what is **actually in this repository**,
with the module and test evidence that backs the grade — the same discipline
`docs/PS24_COMPLIANCE_MATRIX.md` applies to the SDA capabilities.

| Grade | Meaning |
|-------|---------|
| **Built** | Implemented and covered by passing tests in this repo. |
| **Partial** | The mechanism exists; a stated piece of it does not. |
| **Roadmap** | Not built. Interfaces may exist; the capability does not. |

Test totals at the time of writing: `ot-accountability-core` 45,
`ot-mcp-gateway` 80, `ot-sentinel` 114 (including the runtime), plus the
console's governance suites under `apps/ot-vis/tests/`.

---

## Product 1 — Agent ID
*Identity + authority + lifecycle for every agent.*

| Component | Grade | Where it lives | Evidence |
|-----------|-------|----------------|----------|
| DID issuance & use | **Built** | DIDs are the identity vocabulary across `ot-accountability-core`, `ot-mcp-gateway`; console side `apps/ot-vis/src/telemetry/agent-identity/persistent-identity.ts` (`toAgentDid`) | gateway registration/`ghost_hunt.rs` handshake scenarios |
| AGENT_GENESIS ledger | **Built** | `ot-accountability-core::lifecycle` (hash-chained anchors); console `NexoraAnchorChain` | anchor-chain suites in core and `apps/ot-vis/tests/nexora-lifecycle.test.ts` |
| Cryptographic credential binding | **Built** | `ot-accountability-core::identity::CredentialRegistry` (`AuthMethod::ProofOfPossession`), `ot-mcp-gateway::identity::PqcChallengeAttestor` — challenge/response over **ML-DSA-87** (hybrid `X25519MlKem1024MlDsa87`) | `a_governed_fleet_that_authenticates_raises_no_identity_findings`, gateway identity suite |
| DelegationEdge | **Built** | `ot-accountability-core::authority::DelegationEdge` — scope, clearance level, validity window, multi-sig tool list | authority suite (45 tests incl. revocation cascade) |
| Revocation registry | **Built** | `authority::…::revoke` (downstream loss of authority), credential revocation that is never silently reinstated, CRL checking | `an_agent_still_acting_after_its_kill_switch_is_caught` |
| Durable identity storage | **Partial** | Console identities persist; the Rust `MemoryAuthorityStore` is in-memory behind the `AuthorityStore` trait — the stated seam for a durable store | governance hub durability covers ingestion, not the authority store |

> Correction to the circulated plan: the credential suite is **ML-DSA-87**,
> not ML-DSA-65. ML-DSA-65 is the SSA engine's own signing suite in `ot-api`;
> agent credentials use the stronger parameter set.

## Product 2 — Agent Gateway
*The funnel every action must pass through.*

| Component | Grade | Where it lives | Evidence |
|-----------|-------|----------------|----------|
| AipFunnel choke point | **Built** | `ot-accountability-core::aip::AipFunnel`; `ot-mcp-gateway::gateway::McpGateway` drives it for real MCP traffic | the whole `ghost_hunt.rs` suite runs a live gateway, not fixtures |
| Tool manifest, fresh per call | **Built** | `authority::ToolManifest` / `ToolMandate` — resolved on every call | gateway refusal scenarios |
| Authority resolution | **Built** | funnel resolves the delegation graph per call | scope/clearance refusal tests |
| Co-sign for high-risk tools | **Built** | `aip::CoSignatureVerifier` (+ `DenyAllCoSignatures` fail-closed default), `multi_sig_tools` on edges | co-signature tests in core |
| Evidence sealing | **Built** | evidence packets: prompt, tool, arguments digest, pre-execution state, result — hash-chained | packet-chain suites; console `governed-dispatch.test.ts` asserts the sealed `rawPrompt` and viewport state |
| Hash chain | **Built** | `ot_accountability_core::seal_hash` / `chain_payload_bytes` / `verify_anchor_chain` — one construction everywhere | `editing_the_ledger_to_hide_an_action_breaks_the_chain_the_sentinel_checks` |
| Kill switch | **Built** | revocation removes authority immediately, end-to-end | `the_full_circuit_closes_detect_decide_contain_and_the_agent_really_loses_authority` |
| `governedDispatchTool` frontend seam | **Built** | `apps/ot-vis/src/agent/governed-dispatch.ts` — the single path for spoken *and* typed commands | `governed-dispatch.test.ts`, `copilot-turn.test.ts` |

## Product 3 — Agent Sentinel
*The out-of-band watchdog that catches bypasses.*

| Component | Grade | Where it lives | Evidence |
|-----------|-------|----------------|----------|
| Reconciliation engine | **Built** | `ot-sentinel::reconcile` — matched / unattributed / phantom, keyed on canonical-parameter digests, one-to-one | reconciliation suite + e2e escapes |
| The detector suite (11) | **Built** | `ot-sentinel::detector` — Reconciliation, EffectConformance, ChainIntegrity, Registration, ModelDrift, Liveness, Probing, Principal, SensorIntegrity, SensorLiveness, Continuity | each has unit + `ghost_hunt.rs` scenarios |
| Two axes (Severity ⊥ Strength) | **Built** | `ot-sentinel::finding` | policy tests |
| Proof threshold (warrant standard) | **Built** | `response::ResponsePolicy::decide` — containment requires `Proof`; advisory by default | `an_unvouched_sensor_can_raise_the_alarm_but_cannot_get_an_agent_quarantined` |
| Sensor attestation | **Built** | `attestation::SensorCheckpoint` + `deep_verify` — catches byte-length-preserving retroactive edits | same-length tamper e2e tests |
| Continuity hardening | **Built** | `state::PatrolState` / `verify_continuity` — amnesia, rollback, fork, truncated archive, at Proof strength; the finding deliberately names no subject so a forged state file is not a kill switch | six restart e2e scenarios |
| **Deployable process** | **Built** | `runtime::SentinelRuntime` + the `sentinel` binary — tails the logs, attests streams, deep-verifies on a cadence, patrols the ledger, persists state atomically, appends its own archive, audits continuity on start (`--strict-continuity` refuses to run past a break) | 7 runtime tests: escape caught from disk, chain verifies across restart, amnesia caught, offline edit caught after resume, corrupt state refused |
| Sensors beyond files | **Roadmap** | `JsonlAccessLog` / `JsonlEffectLog` read what servers/proxies write; no live eBPF/syscall/cloud-audit adapters exist in-repo (the sovereign overlay's eBPF module is a user-space policy model, no kernel loader) | — |

## Running the product line

```text
# Product 2+1: the governed gateway (library, driven by your MCP host)
#   see crates/ot-mcp-gateway — the ghost_hunt tests double as usage examples

# Product 3: the watchdog, as a process
cargo run -p ot-sentinel --bin sentinel -- \
  --ledger evidence.jsonl \
  --access-log /var/log/toolserver/access.jsonl \
  --effect-log /var/log/egress/effects.jsonl \
  --covers send_command --covers purge_archive \
  --trust-sensors --deep-verify-every 10 --interval 60
```

Advisory by default; add `--autonomous` for containment on Proof-strength
findings, `--allow-dest`/`--allow-cmd` to turn on fail-closed egress/spawn
conformance, and `--strict-continuity` to refuse startup over a broken
history rather than run and report it.

## What remains honestly open

1. **Durable Rust-side authority store** — `AuthorityStore` is the seam;
   only the in-memory implementation ships.
2. **Kernel-level sensors** — an eBPF `connect4`/exec loader feeding
   `JsonlEffectLog`'s schema. The schema and detector are ready; the
   kernel half is not in this repository.
3. **Cross-agent/swarm correlation** — detectors judge one window; no
   detector yet correlates coordinated activity across agents.
4. **Reconciliation scale** — O(observations × packets) per window, no
   index; fine at fleet-demo scale, unproven at 10⁴.
