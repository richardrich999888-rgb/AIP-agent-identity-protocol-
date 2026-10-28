# AUDIT CORRECTIONS

**Trust is a product feature.** This document records, plainly, what this
repository previously overstated, what actually exists, what is experimental,
and what is roadmap. It exists so that any engineer, auditor, or investor
doing diligence finds the truth here first — not by discovering it themselves.

Date: 2026-06-09

### Dated qualification — 2026-10-28 interoperability work

The sections below retain their historical context. Current enterprise and
interoperability implementation/evidence is indexed in
[`docs/interoperability/VALIDATION_REPORT.md`](docs/interoperability/VALIDATION_REPORT.md).
Real ADK/A2A/Microsoft-governed gateway traffic does not establish the complete
same-run institutional authorization and kernel-observation chain. The new
offline authority-reference verifier authenticates native signatures, exact
chain references, scope and validity at issuance; it does not establish
revocation, resource/spend policy, institutional key custody or execution.
Missing observations remain `CannotProve`, including with a valid authority
chain. Historical RBI evidence is preserved separately. Local host limitations,
the full-workspace test failures and unexecuted CI jobs remain disclosed.

---

## 1. What was overstated (now corrected)

| Previous claim | Reality | Correction |
|---|---|---|
| "Status: Production" badge; components marked "✅ Production" | The flagship Rust workspace **did not compile as committed** — `aip-standalone/Cargo.toml` referenced a `crates/` directory layout that did not exist. | Manifest fixed. All status claims downgraded to honest maturity levels (see §3). |
| `benchmark-results/aip_validation.json` reported "137 passed, 0 failed, pass_rate 1.0000" | Running the suite produced **2 failures**: a reputation-score bounds violation (integer overflow) and a throughput gate failing in debug builds. | Non-reproducing artifacts **deleted**. The overflow bug is **fixed** (`aip-core`, weighted-mean score no longer rescales by 10,000); the bounds property test now enforces 0..=1,000,000 across the full input range. Throughput gates now run only under `--release`, where they are meaningful. |
| "Provenance-bound identity cryptographically traces actions to a specific AI model" | The `ProvenanceTriple` is three caller-supplied SHA-256 commitments. Nothing verifies the model commitment corresponds to any actual model. | Documented as a **commitment scheme**, not model attestation. Verifying commitments against real artifacts is roadmap. |
| Hardware attestation ("TEE/PUF trust levels") | `evaluate_hardware_trust` performs structural checks and looks for a marker byte sequence. It does **not** verify Intel SGX/TDX, AMD SEV, Arm, or Apple attestation quotes against any vendor root of trust. | Marked **EXPERIMENTAL — not for production use** in `aip-core` docs. |
| "Cascade revocation… Verifiable Delegation Lattice" implied to be live in the HTTP service | The `aip-service` JWTs carry no scope lattice and no provenance; its own benchmark notes admitted "multi-hop via delegation_id not supported." The novel delegation/audit library (`aip-core`) was not wired into the service. | Service explicitly labeled a **reference prototype** (no authentication, single-node state). The lattice + evidence layer now lives in `aip-protocol`, verified end-to-end in code and tests. |
| Patent documents referenced `aegis/src/lib.rs`, `helix/`, `cortex/`, quantum/neuromorphic layers | **None of those files or systems exist in this repository.** | Retained under `reports_and_patents/` as attorney working documents only. Nothing in this repo should be read as implying those systems exist. The README no longer references them. |

## 2. What exists (verified by compiling code and passing tests)

- **`aip-protocol` — EvidencePacket v1, verification engine, accountability
  graph.** The primary artifact of the system: canonical serialization,
  deterministic hashing, agent packet signatures, per-action attestations
  bound to decisions, delegation/authority-chain verification, scope
  checking, revocation and temporal checks, trace/receipt bindings with
  counterparty countersignatures, and machine-derived trust floors.
  Exercised by integration tests in which **every tamper scenario must flip
  a specific named rule**.
- **`aip-core` — delegation chains, capability scopes, scoped audit.**
  N-hop delegation with per-hop Ed25519 signatures, lattice scope
  intersection (MEET), depth limits, cascade revocation, hash-chained
  scope-bound audit entries.
- **`aip-crypto` / `aip-types`** — Ed25519 sign/verify, SHA-256, Base58
  AIP-ID derivation with checksum, spec-aligned data structures.
- **`banking_demo`** — end-to-end design-partner demo: CFO → delegation →
  payment approval → countersigned ledger receipt → EvidencePacket →
  verification, then tamper-and-detect (including an attacker who recomputes
  the packet hash). Exits non-zero if any of that fails.
- **`aip-service`** — reference HTTP prototype (issue/verify/delegate/revoke
  + JWKS). **Not production**: no authentication on endpoints, file-backed
  single-node state, no key rotation.

## 3. Component maturity (honest)

| Component | Maturity |
|---|---|
| `aip-protocol` (EvidencePacket, verifier, graph) | **MVP** — new, tested, API unstable |
| `aip-core` delegation / capability / revocation / scoped_audit | **MVP** — well-tested library, not yet exposed as a service |
| `aip-crypto`, `aip-types` | **Stable library code** |
| `aip-service` | **Prototype / reference only** |
| `aip-cli` | **Prototype** |
| Reputation (BFT aggregation) | **EXPERIMENTAL** — overflow bug fixed, design unvalidated |
| Hardware attestation | **EXPERIMENTAL** — structural checks only, no vendor quote verification |
| Liveness challenge-response | **EXPERIMENTAL** |
| Multi-node simulation | **Test harness only** |

## 4. What is roadmap (does not exist yet — see ROADMAP.md)

- Enterprise Accountability Console (viewer / verification UI)
- TypeScript and Python SDKs
- Framework integrations (MCP, LangGraph, OpenAI Agents SDK, CrewAI)
- Evidence Vault (storage, search, retention, compliance export)
- Authenticated, multi-tenant, horizontally scalable verification service
- KMS/HSM-backed key management and rotation
- Real TEE quote verification; provenance commitment validation
- Transparency-log anchoring of packet hashes

## 5. Standing policy

1. No component is labeled "production" without CI-reproducible evidence.
2. No benchmark number is published without the command that reproduces it.
3. Experimental modules carry an explicit warning in their rustdoc.
4. Claims about capabilities live in `AIP_SPEC.md` and must reference
   implemented, tested code.
