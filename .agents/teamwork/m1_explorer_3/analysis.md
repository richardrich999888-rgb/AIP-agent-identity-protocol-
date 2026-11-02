# Milestone 1 Fixtures & Test Data Pipeline Specification (F2)

**Explorer 3: Fixtures & Test Data Specialist**  
**Milestone:** M1 — `aip-wasm` Core Engine & Fixtures Pipeline  
**Target:** AIP Enterprise Accountability Console (`aip-console`)  
**Date:** 2026-11-02  
**Status:** Complete Architectural Proposal  

---

## 1. Executive Summary & Architecture Goals

Feature **F2 (Test Fixture Generation Pipeline)** provides the foundational test artifacts for the entire AIP Enterprise Accountability Console ecosystem:
1. **Zero-JS Engine Validation**: Powers offline verification in WebAssembly (`aip-wasm`) and automated E2E suites (Tiers 1–5 per `TEST_INFRA.md`).
2. **Interactive Console Showcases**: Serves as pre-loaded sample records in `aip-console/public/fixtures/` for the Ingestion drop-zone, 14-Rule Ledger, Accountability DAG viewer, Adversarial Tamper Sandbox, and Evidence Vault offline fallback mode.
3. **Forensic Audit Compliance**: Generates realistic, fully signed 7-file audit ZIP bundles conforming to `AUDIT_EXPORT_SPEC.md` (`aip-bundle-1`).

### Primary Design Pillars
- **Strict Cryptographic Soundness**: Every signature, token, canonical hash, and countersignature is computed using real Ed25519 and SHA-256 cryptography (no fake or stubbed hashes).
- **14-Rule Ledger Alignment**: Every fixture maps to explicit expected outcomes across the 14 engine verification rules defined in `aip-protocol/src/verification_report.rs`.
- **Tamper Evidence Differentiation**: Clear separation between administrative invalidity (e.g. revoked token, untrusted root) and positive forensic tampering (`tamper_evidence = true`).
- **Reproducible Determinism**: Deterministic key generation from stable seeds ensures bit-exact reproducible fixtures across builds, eliminating spurious git diffs and test flakiness.
- **Self-Testing Generation Pipeline**: The generator validates every fixture through `aip_protocol::verify_packet` and `aip_protocol::verify_zip` before committing files to disk.

---

## 2. Existing Fixture Generators in the Codebase

The repository contains three primary reference implementations of fixture generators:

| Generator Location | Purpose | Key Artifacts | Reusable Patterns |
|---|---|---|---|
| `aip-standalone/aip-protocol/tests/evidence_packet.rs` | 17-case protocol verification test suite | `build_fixture()`: CFO $\to$ Treasury Orchestrator $\to$ Payments Agent $\to$ Bank Ledger receipt | `EvidencePacketBuilder`, `VerificationContext`, multi-hop delegation, tamper mutations (summary, hash fixing, action payload, scope escalation, revoked JTI) |
| `aip-standalone/aip-protocol/tests/bundle.rs` | 7-case audit export ZIP test suite | `build_zip("acme", &packet, &report, &seed, &pub)` | Unzipping/re-zipping, manifest edits, missing files, signature corruption, `verify_zip` assertion |
| `aip-standalone/banking_demo/src/main.rs` | End-to-end CFO pilot demonstration | $48,200 payment approval invoice `INV-2026-0142`, core banking ledger countersigned receipt `LEDGER-90211` | Realistic financial domain naming, rationale hashes, W3C OTel trace binding, console reporting |
| `aip-service/src/test_support.rs` | Axum test harness | `sample_packet()` and `sample_generate_request()` | Key extraction, map-to-hex formatting |

These existing generators provide the exact cryptographic templates needed. The generator pipeline consolidates and elevates them into a production CLI tool and library module.

---

## 3. Comprehensive Specification of the 10 Required Fixtures

### 3.1 Overview Matrix

| # | Fixture Name | Format | Claimed Floor | Derived Floor | Valid? | Tampered? | Target Failed Rules | Domain Scenario |
|---|---|---|---|---|---|---|---|---|
| 1 | `honest_counterparty.json` | JSON | `COUNTERPARTY_SIGNED` | `COUNTERPARTY_SIGNED` | **YES** | No | None (14/14 PASS) | CFO $\to$ Treasury $\to$ Payments Agent $\to$ Bank Ledger Receipt |
| 2 | `authority_bound.json` | JSON | `AUTHORITY_BOUND` | `AUTHORITY_BOUND` | **YES** | No | None (14/14 PASS) | VP Engineering $\to$ Infra Orchestrator $\to$ K8s Scaling Agent |
| 3 | `agent_signed.json` | JSON | `AGENT_SIGNED` | `AGENT_SIGNED` | **NO** | No | R5 (`ROOT_TOKEN_SIGNATURE`) | Autonomous Research Agent scraping SEC 10-K filings |
| 4 | `tampered_summary.json` | JSON | `COUNTERPARTY_SIGNED` | `UNVERIFIED` | **NO** | **YES** | R3 (`CANONICAL_HASH`), R14 (`TRUST_FLOOR`) | Payment amount altered from $48,200 to $4,820,000 |
| 5 | `tampered_hash.json` | JSON | `COUNTERPARTY_SIGNED` | `UNVERIFIED` | **NO** | **YES** | R4 (`AGENT_SIGNATURE`), R14 (`TRUST_FLOOR`) | Payment amount altered + packet hash recalculated |
| 6 | `tampered_signature.json` | JSON | `COUNTERPARTY_SIGNED` | `UNVERIFIED` | **NO** | **YES** | R4 (`AGENT_SIGNATURE`), R14 (`TRUST_FLOOR`) | Corrupted agent signature bytes (bit flip) |
| 7 | `scope_escalation.json` | JSON | `COUNTERPARTY_SIGNED` | `UNVERIFIED` | **NO** | **YES** | R6 (`DELEGATION_CHAIN`), R14 (`TRUST_FLOOR`) | Delegated Write-only scope illegally expanded to Admin/All |
| 8 | `revoked_token.json` | JSON | `COUNTERPARTY_SIGNED` | `UNVERIFIED` | **NO** | No | R9 (`REVOCATION`), R14 (`TRUST_FLOOR`) | Validly formed packet referencing revoked delegation JTI |
| 9 | `audit_bundle_valid.zip` | ZIP | N/A | N/A | **YES** | No | None (All 7 bundle checks PASS) | Certified 7-file audit export signed by Syntriass service |
| 10 | `audit_bundle_tampered.zip` | ZIP | N/A | N/A | **NO** | **YES** | `FILE_HASHES` FAIL | Audit ZIP bundle containing manipulated `evidence.json` |

---

### 3.2 Detailed Fixture Blueprints

#### Fixture 1: `honest_counterparty.json`
- **Domain Story**: Human CFO authorizes Treasury Orchestrator, which delegates Write-only payment authority to Payments Agent. Agent approves payment for invoice `INV-2026-0142` ($48,200.00) to Acme Industrial GmbH. External banking ledger posts entry `LEDGER-90211` and countersigns receipt.
- **Key Identifiers**:
  - Principal: `aip1cfo...` (Role: `"CFO"`)
  - Intermediary: `aip1orch...` (Role: `"Treasury Orchestrator"`)
  - Agent: `aip1paymentsagent...` (Role: `"Payments Agent"`)
  - Counterparty: `"ledger.example-bank.com"`
- **Cryptographic Elements**:
  - Root Token: Scoped to Read, Write, Execute, Delegate (Admin Denied), 1-hour TTL. Signed by CFO.
  - Delegation Hop: Depth 0, Scoped to Write only (attenuated via lattice meet $\sqcap$). Signed by Orchestrator.
  - Decision: `action_kind: ScopeAction::Standard(Action::Write)`, `summary`: `"Approve vendor payment INV-2026-0142 for $48,200.00 to Acme Industrial GmbH"`.
  - Action Attestation: Signed by Agent, bound to `decision_id`, description: `"POST /v1/ledger/payments {\"invoice\":\"INV-2026-0142\",\"amount\":\"$48,200.00\"}"`.
  - Trace Binding: W3C trace ID `"4bf92f3577b34da6a3ce929d0e0e4736"`, SHA-256 of OTel span payload.
  - Receipt Binding: `receipt_system: "ledger.example-bank.com"`, `receipt_id: "LEDGER-90211"`, countersigned by ledger private key over canonical receipt bytes.
  - Claimed Trust Floor: `COUNTERPARTY_SIGNED`.
- **Verification Result**: All 14 checks PASS, `derived_trust_floor == CounterpartySigned`, `valid == true`, `tampered == false`.

#### Fixture 2: `authority_bound.json`
- **Domain Story**: Autonomous cloud operations under VP of Engineering authority. VP Engineering grants infrastructure orchestration authority. Orchestrator delegates replica scaling rights to Autoscaling Agent. Agent executes Kubernetes deployment patch.
- **Key Identifiers**:
  - Principal: `aip1vpeng...` (Role: `"VP Engineering"`)
  - Intermediary: `aip1infraorch...` (Role: `"Cloud Infrastructure Orchestrator"`)
  - Agent: `aip1autoscale...` (Role: `"Kubernetes Autoscaling Agent"`)
- **Differences from Fixture 1**:
  - Decision: `"Scale Kubernetes cluster production-east from 12 to 18 worker nodes"`.
  - Receipt Binding: Internal cluster event receipt without counterparty countersignature (`counterparty_id: None`, `counterparty_sig: None`).
  - Claimed Trust Floor: `AUTHORITY_BOUND`.
- **Verification Result**: Rules 1–12 PASS, Rule 13 PASS ("receipt bound by hash (no countersignature)"), Rule 14 PASS (`derived floor AuthorityBound supports claimed floor AuthorityBound`). `valid == true`, `tampered == false`.

#### Fixture 3: `agent_signed.json`
- **Domain Story**: Autonomous web research agent initiating an uncoordinated SEC 10-K scrape. The agent seals the packet with its own identity and key, but possesses no enterprise principal delegation chain.
- **Key Identifiers**:
  - Agent: `aip1researchagent...` (Role: `"Autonomous Research Agent"`)
  - Root Authority: Self-asserted or ad-hoc unverified principal (not present in verifier's trust keys).
  - Delegation Chain: Empty (`[]`).
- **Differences from Fixture 1**:
  - Decision: `"Fetch and summarize SEC 10-K filings for Q3 2026 analysis"`.
  - Claimed Trust Floor: `AGENT_SIGNED`.
- **Verification Result**:
  - R1 (`STRUCTURE`): PASS
  - R2 (`AGENT_ID_BINDING`): PASS
  - R3 (`CANONICAL_HASH`): PASS
  - R4 (`AGENT_SIGNATURE`): PASS
  - R5 (`ROOT_TOKEN_SIGNATURE`): **FAIL** ("no trusted public key for root issuer")
  - R6 (`DELEGATION_CHAIN`): PASS (0 hops)
  - R7 (`AUTHORITY_CHAIN`): FAIL (root token not issued to agent or chain broken)
  - Derived Trust Floor: `AgentSigned`
  - R14 (`TRUST_FLOOR`): **PASS** (`derived floor AgentSigned supports claimed floor AgentSigned`)
  - `tampered == false` (key omission is verifiability gap, not tamper evidence).

#### Fixture 4: `tampered_summary.json`
- **Domain Story**: Naive man-in-the-middle attacker edits invoice approval amount from `$48,200.00` to `$4,820,000.00` in the serialized JSON without altering other fields.
- **Mutation**:
  - `packet.decision.summary = "Approve vendor payment INV-2026-0142 for $4,820,000.00 to Acme Industrial GmbH"`
  - `packet_hash` and `agent_sig` left intact.
- **Verification Result**:
  - R3 (`CANONICAL_HASH`): **FAIL** (`packet_hash mismatch: stored ... recomputed ... — packet modified after sealing`).
  - `tampered == true`.
  - Derived Trust Floor: `Unverified`.
  - R14 (`TRUST_FLOOR`): **FAIL** (claimed `CounterpartySigned` exceeds derived `Unverified`).

#### Fixture 5: `tampered_hash.json`
- **Domain Story**: Sophisticated attacker alters invoice amount to `$4,820,000.00` and recalculates `packet_hash = SHA-256(canonical_bytes)` to evade canonical hash checks.
- **Mutation**:
  - `packet.decision.summary = "Approve vendor payment INV-2026-0142 for $4,820,000.00 to Acme Industrial GmbH"`
  - `packet.packet_hash = packet.compute_hash()` (hash fixed).
  - `packet.agent_sig` left intact (attacker lacks agent private key).
- **Verification Result**:
  - R3 (`CANONICAL_HASH`): **PASS** (recomputed canonical hash matches updated packet_hash).
  - R4 (`AGENT_SIGNATURE`): **FAIL** (`signature payload hash does not cover current packet contents` or cryptographic signature verification fails).
  - `tampered == true`.
  - Derived Trust Floor: `Unverified`.
  - R14 (`TRUST_FLOOR`): **FAIL**.

#### Fixture 6: `tampered_signature.json`
- **Domain Story**: Bit-rot, storage corruption, or signature forgery: the agent signature bytes are modified in transit.
- **Mutation**:
  - `packet.agent_sig.signature_bytes[0] ^= 0xFF`.
- **Verification Result**:
  - R3 (`CANONICAL_HASH`): PASS.
  - R4 (`AGENT_SIGNATURE`): **FAIL** (`agent signature cryptographic verification failed`).
  - `tampered == true`.
  - Derived Trust Floor: `Unverified`.

#### Fixture 7: `scope_escalation.json`
- **Domain Story**: Rogue intermediary or malicious agent attempts privilege escalation by replacing the delegated Write-only scope with an all-permissive `CapabilityScope::all()` (granting Admin, Delete, Execute).
- **Mutation**:
  - `packet.delegation_chain[0].scope = CapabilityScope::all()`.
  - `packet.packet_hash = packet.compute_hash()`.
- **Verification Result**:
  - R6 (`DELEGATION_CHAIN`): **FAIL** (delegation token issuer signature does not match modified scope).
  - `tampered == true`.
  - Derived Trust Floor: `Unverified`.

#### Fixture 8: `revoked_token.json`
- **Domain Story**: Legitimate payment approval signed when active, but the Treasury Orchestrator's delegation token was subsequently revoked by compliance prior to verifier check.
- **Mutation**:
  - Packet is mathematically authentic and unaltered.
  - Companion verification context includes `delegation_chain[0].jti` in `revoked_jtis`.
- **Verification Result**:
  - R1–R8: PASS.
  - R9 (`REVOCATION`): **FAIL** (`revoked tokens in chain: delegation <hex_jti>`).
  - R10–R13: PASS.
  - `tampered == false` (CRITICAL: revocation is an administrative status update, NOT cryptographic tampering).
  - Derived Trust Floor: `Unverified` (drops below `AuthorityBound`).
  - R14 (`TRUST_FLOOR`): **FAIL**.

#### Fixture 9: `audit_bundle_valid.zip`
- **Domain Story**: Portable 7-file audit package exported by Syntriass compliance service for regulatory inspection.
- **Archive Contents**:
  1. `evidence.json`: Full canonical packet for `honest_counterparty`.
  2. `verification_report.json`: Machine-readable `VerificationReport` from `verify_packet`.
  3. `verification_report.md`: Auditor-readable Markdown narrative report.
  4. `authority_graph.json`: Serialized `AccountabilityGraph` (nodes and edges).
  5. `authority_graph.dot`: Graphviz DOT visualization.
  6. `manifest.json`: Schema `aip-bundle-1` with sorted per-file SHA-256 and `bundle_hash`.
  7. `bundle_signature.sig`: Detached Ed25519 signature over `manifest.json` bytes.
- **Verification Result via `verify_zip`**:
  - `BUNDLE_STRUCTURE`: PASS
  - `MANIFEST_PARSE`: PASS
  - `FILE_HASHES`: PASS
  - `BUNDLE_HASH`: PASS
  - `BUNDLE_SIGNATURE`: PASS
  - `EVIDENCE_INTEGRITY`: PASS
  - `PACKET_VERIFICATION`: PASS (with trust keys)
  - Overall status: `BundleStatus::Pass`.

#### Fixture 10: `audit_bundle_tampered.zip`
- **Domain Story**: Forensic tampering investigation: an adversary opened an exported audit ZIP bundle, edited `evidence.json` inside the archive, and re-compressed without updating `manifest.json` or `bundle_signature.sig`.
- **Archive Mutation**:
  - Generated from `audit_bundle_valid.zip`.
  - `evidence.json` byte stream modified (e.g. decision summary altered).
- **Verification Result via `verify_zip`**:
  - `BUNDLE_STRUCTURE`: PASS
  - `MANIFEST_PARSE`: PASS
  - `FILE_HASHES`: **FAIL** (`evidence.json: sha256 mismatch: manifest ... actual ...`).
  - Overall status: `BundleStatus::Fail`.

---

## 4. The 14-Rule Verification Ledger Mapping Matrix

Every UI verification check in `aip-console` maps 1:1 to an engine rule evaluated during verification:

| Rule ID | Engine Constant | Property Verified | Expected Behavior in Fixtures |
|---|---|---|---|
| **R1** | `STRUCTURE` | Magic bytes `b"AEP1"`, version `1`, non-empty agent/principal/decision, $\ge 1$ actions | PASS in all 8 JSON fixtures |
| **R2** | `AGENT_ID_BINDING` | Agent AIP-ID derives from embedded public key and provenance triple | PASS in all 8 JSON fixtures |
| **R3** | `CANONICAL_HASH` | SHA-256 over deterministic canonical bytes equals `packet.packet_hash` | **FAILS in `tampered_summary.json`**; PASS in all others |
| **R4** | `AGENT_SIGNATURE` | Agent's Ed25519 signature verifies over canonical packet hash | **FAILS in `tampered_hash.json` and `tampered_signature.json`** |
| **R5** | `ROOT_TOKEN_SIGNATURE` | Root authority scoped token is signed by trusted principal key | **FAILS in `agent_signed.json`** (no trusted root key); PASS in others |
| **R6** | `DELEGATION_CHAIN` | Per-hop signatures, JTI linkage, depth increment, scope attenuation | **FAILS in `scope_escalation.json`**; PASS in others |
| **R7** | `AUTHORITY_CHAIN` | End-to-end graph path from principal $\to$ hops $\to$ acting agent | PASS in `honest_counterparty` and `authority_bound` |
| **R8** | `SCOPE_AUTHORITY` | Decision and all action kinds fall within effective delegated scope | PASS in all valid fixtures |
| **R9** | `REVOCATION` | Neither root token nor any delegation hop is in `revoked_jtis` | **FAILS in `revoked_token.json`**; PASS in others |
| **R10** | `TEMPORAL_VALIDITY` | Decision $\ge$ token issuance, actions $\ge$ decision, all $\le$ expiry | PASS in all 8 JSON fixtures |
| **R11** | `ACTION_ATTESTATIONS` | Each action signed by agent and bound to `decision_id` | PASS in all 8 JSON fixtures |
| **R12** | `TRACE_BINDING` | Optional external trace hash verification against supplied trace data | PASS in `honest_counterparty` |
| **R13** | `RECEIPT_BINDING` | External receipt data hash and counterparty countersignature | PASS in `honest_counterparty` (Countersigned), PASS in `authority_bound` (Uncountersigned) |
| **R14** | `TRUST_FLOOR` | Derived floor meets or exceeds packet's claimed trust floor | PASS in `honest`, `authority_bound`, `agent_signed`; **FAILS in tampered/revoked fixtures** |

---

## 5. Companion Contexts & Manifest Specification

### 5.1 Verification Context Files (`*.context.json`)

To enable instant offline verification in both the UI and test suites, companion context files are generated alongside the packets.

Example: `honest_counterparty.context.json`:
```json
{
  "trusted_issuers": {
    "aip1cfo5910248...": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "aip1orch830182...": "3b248a719021...hex_pubkey..."
  },
  "trusted_counterparties": {
    "ledger.example-bank.com": "5f10a82910...hex_pubkey..."
  },
  "revoked_jtis": [],
  "trace_data": "OTel:trace_id=4bf92f3577b34da6a3ce929d0e0e4736;span_id=00f067aa0ba902b7;sampled=1",
  "receipt_data": "LEDGER-90211|INV-2026-0142|$48,200.00|POSTED"
}
```

Example: `revoked_token.context.json`:
```json
{
  "trusted_issuers": {
    "aip1cfo5910248...": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "aip1orch830182...": "3b248a719021...hex_pubkey..."
  },
  "trusted_counterparties": {
    "ledger.example-bank.com": "5f10a82910...hex_pubkey..."
  },
  "revoked_jtis": [
    "4a12b0e9c87f32104a12b0e9c87f3210"
  ]
}
```

### 5.2 Fixtures Catalog Index (`index.json`)

Written to `aip-console/public/fixtures/index.json`:
```json
{
  "version": "1.0.0",
  "generated_at": 1781769600000,
  "fixtures": [
    {
      "id": "honest_counterparty",
      "filename": "honest_counterparty.json",
      "context_filename": "honest_counterparty.context.json",
      "title": "Honest Counterparty-Signed Payment",
      "category": "valid",
      "description": "Full enterprise payment approval chain with bilateral bank ledger countersignature. Passes all 14 engine verification rules.",
      "claimed_trust_floor": "COUNTERPARTY_SIGNED",
      "expected_derived_floor": "COUNTERPARTY_SIGNED",
      "expected_valid": true,
      "expected_tampered": false,
      "expected_failed_rules": []
    },
    {
      "id": "authority_bound",
      "filename": "authority_bound.json",
      "context_filename": "authority_bound.context.json",
      "title": "Authority-Bound Cloud Scaling",
      "category": "valid",
      "description": "Autonomous infrastructure scaling action with attenuated delegation. Passes rules 1-12 without external countersignature.",
      "claimed_trust_floor": "AUTHORITY_BOUND",
      "expected_derived_floor": "AUTHORITY_BOUND",
      "expected_valid": true,
      "expected_tampered": false,
      "expected_failed_rules": []
    },
    {
      "id": "agent_signed",
      "filename": "agent_signed.json",
      "context_filename": "agent_signed.context.json",
      "title": "Agent-Signed Autonomous Task",
      "category": "unverified_authority",
      "description": "Self-signed web scraping task lacking enterprise principal delegation. Derives AgentSigned trust floor.",
      "claimed_trust_floor": "AGENT_SIGNED",
      "expected_derived_floor": "AGENT_SIGNED",
      "expected_valid": false,
      "expected_tampered": false,
      "expected_failed_rules": ["ROOT_TOKEN_SIGNATURE"]
    },
    {
      "id": "tampered_summary",
      "filename": "tampered_summary.json",
      "context_filename": "honest_counterparty.context.json",
      "title": "Tampered Decision Summary",
      "category": "adversarial",
      "description": "Payment amount modified in sealed packet without hash update. Violates CANONICAL_HASH.",
      "claimed_trust_floor": "COUNTERPARTY_SIGNED",
      "expected_derived_floor": "UNVERIFIED",
      "expected_valid": false,
      "expected_tampered": true,
      "expected_failed_rules": ["CANONICAL_HASH", "TRUST_FLOOR"]
    },
    {
      "id": "tampered_hash",
      "filename": "tampered_hash.json",
      "context_filename": "honest_counterparty.context.json",
      "title": "Tampered Payload with Recalculated Hash",
      "category": "adversarial",
      "description": "Attacker updated packet_hash after editing payload. Bypasses CANONICAL_HASH but caught by AGENT_SIGNATURE.",
      "claimed_trust_floor": "COUNTERPARTY_SIGNED",
      "expected_derived_floor": "UNVERIFIED",
      "expected_valid": false,
      "expected_tampered": true,
      "expected_failed_rules": ["AGENT_SIGNATURE", "TRUST_FLOOR"]
    },
    {
      "id": "tampered_signature",
      "filename": "tampered_signature.json",
      "context_filename": "honest_counterparty.context.json",
      "title": "Corrupted Agent Signature",
      "category": "adversarial",
      "description": "Corrupted signature bytes in transit. Violates AGENT_SIGNATURE.",
      "claimed_trust_floor": "COUNTERPARTY_SIGNED",
      "expected_derived_floor": "UNVERIFIED",
      "expected_valid": false,
      "expected_tampered": true,
      "expected_failed_rules": ["AGENT_SIGNATURE", "TRUST_FLOOR"]
    },
    {
      "id": "scope_escalation",
      "filename": "scope_escalation.json",
      "context_filename": "honest_counterparty.context.json",
      "title": "Privilege Scope Escalation",
      "category": "adversarial",
      "description": "Delegation hop claims wider scope than granted by root token. Violates DELEGATION_CHAIN.",
      "claimed_trust_floor": "COUNTERPARTY_SIGNED",
      "expected_derived_floor": "UNVERIFIED",
      "expected_valid": false,
      "expected_tampered": true,
      "expected_failed_rules": ["DELEGATION_CHAIN", "TRUST_FLOOR"]
    },
    {
      "id": "revoked_token",
      "filename": "revoked_token.json",
      "context_filename": "revoked_token.context.json",
      "title": "Revoked Delegation Token",
      "category": "revocation",
      "description": "Validly sealed packet whose delegation token was revoked after issuance. Violates REVOCATION (not tampered).",
      "claimed_trust_floor": "COUNTERPARTY_SIGNED",
      "expected_derived_floor": "UNVERIFIED",
      "expected_valid": false,
      "expected_tampered": false,
      "expected_failed_rules": ["REVOCATION", "TRUST_FLOOR"]
    },
    {
      "id": "audit_bundle_valid",
      "filename": "audit_bundle_valid.zip",
      "title": "Certified Audit Export Bundle",
      "category": "bundle",
      "format": "zip",
      "description": "Conforming 7-file ZIP archive signed by service key with valid manifest and file checksums.",
      "expected_valid": true,
      "expected_checks": ["BUNDLE_STRUCTURE", "MANIFEST_PARSE", "FILE_HASHES", "BUNDLE_HASH", "BUNDLE_SIGNATURE", "EVIDENCE_INTEGRITY", "PACKET_VERIFICATION"]
    },
    {
      "id": "audit_bundle_tampered",
      "filename": "audit_bundle_tampered.zip",
      "title": "Tampered Audit Export Bundle",
      "category": "bundle",
      "format": "zip",
      "description": "ZIP bundle with modified evidence.json. FILE_HASHES check detects content tampering.",
      "expected_valid": false,
      "expected_failed_checks": ["FILE_HASHES"]
    }
  ]
}
```

---

## 6. Generator Architecture & File Layout

### 6.1 Code Placement Recommendation

We recommend implementing the generator pipeline within the existing `aip-standalone` workspace:

1. **Library Module: `aip-standalone/aip-protocol/src/fixtures.rs`**
   - Implements the fixture generation logic, key derivations, tamper mutations, and bundle creation.
   - Exposes `pub fn generate_all_fixtures() -> FixtureCollection`.
   - Exposes `pub fn write_fixtures_to_dir(fixtures: &FixtureCollection, out_dir: &Path) -> Result<(), Box<dyn Error>>`.
   - Exposes `pub fn get_fixture_json(id: &str) -> Option<&'static str>`.
   - Allows both native binaries, tests, and `aip-wasm` to reuse fixture generation logic without code duplication.

2. **Binary Target: `aip-standalone/aip-protocol/src/bin/generate_fixtures.rs`**
   - Standard Cargo binary discovered automatically under `src/bin/`.
   - Command:
     ```bash
     cargo run --manifest-path aip-standalone/Cargo.toml -p aip-protocol --bin generate_fixtures -- --out-dir aip-console/public/fixtures
     ```
   - Automatically supports `--out-dir <PATH>` and `--also-e2e <PATH>` (to copy fixtures directly into `e2e/fixtures/`).
   - Runs self-verification checks on all 10 fixtures before writing to disk.

3. **Workspace Script Integration**
   - Add to repository root `package.json`:
     ```json
     "scripts": {
       "generate:fixtures": "cargo run --manifest-path aip-standalone/Cargo.toml -p aip-protocol --bin generate_fixtures -- --out-dir aip-console/public/fixtures --also-e2e e2e/fixtures"
     }
     ```

### 6.2 Generator Implementation Architecture

```
aip-standalone/aip-protocol/
├── src/
│   ├── lib.rs                       # Expose `pub mod fixtures;`
│   ├── fixtures.rs                  # Complete generator logic & self-verifier
│   └── bin/
│       └── generate_fixtures.rs     # CLI entrypoint with flag parsing & disk output
```

#### Deterministic Seed Strategy
To ensure bit-exact reproducible fixtures across runs:
- `CFO_SEED`: `sha256(b"syntriass:aip:seed:cfo:v1")`
- `ORCHESTRATOR_SEED`: `sha256(b"syntriass:aip:seed:orchestrator:v1")`
- `PAYMENTS_AGENT_SEED`: `sha256(b"syntriass:aip:seed:payments_agent:v1")`
- `VP_ENG_SEED`: `sha256(b"syntriass:aip:seed:vp_eng:v1")`
- `INFRA_ORCH_SEED`: `sha256(b"syntriass:aip:seed:infra_orch:v1")`
- `AUTOSCALE_AGENT_SEED`: `sha256(b"syntriass:aip:seed:autoscale_agent:v1")`
- `RESEARCH_AGENT_SEED`: `sha256(b"syntriass:aip:seed:research_agent:v1")`
- `COUNTERPARTY_SEED`: `sha256(b"syntriass:aip:seed:ledger_counterparty:v1")`
- `SERVICE_SIGNER_SEED`: `sha256(b"syntriass:aip:seed:audit_service_signer:v1")`
- Fixed base timestamp: `1781769600000` (e.g., 2026-06-15T08:00:00Z)

Using deterministic seeds guarantees that hashes, IDs, and signatures match across all developer machines, CI runners, and E2E test runs.

---

## 7. Actionable Implementation Plan for the Worker

The Worker can execute this plan sequentially with zero ambiguity:

### Phase 1: Implement `aip-protocol/src/fixtures.rs`
1. Define deterministic key generator helper:
   ```rust
   fn deterministic_keypair(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>);
   ```
2. Build generator for `honest_counterparty` (CFO $\to$ Orchestrator $\to$ Payments Agent $\to$ Ledger receipt).
3. Build generator for `authority_bound` (VP Eng $\to$ Infra Orchestrator $\to$ K8s Scaling Agent).
4. Build generator for `agent_signed` (Autonomous Research Agent with self-asserted root).
5. Build mutation functions for the 5 tamper/revocation variants:
   - `tamper_summary`: mutate `decision.summary`.
   - `tamper_hash`: mutate `decision.summary` + call `packet.compute_hash()`.
   - `tamper_signature`: mutate `packet.agent_sig.signature_bytes[0] ^= 0xFF`.
   - `scope_escalation`: set `delegation_chain[0].scope = CapabilityScope::all()`.
   - `revoked_token`: record hop JTI and add to revocation context.
6. Build ZIP bundle generators using `aip_protocol::bundle::build_zip`:
   - `audit_bundle_valid.zip`: clean export.
   - `audit_bundle_tampered.zip`: uncompressed, `evidence.json` mutated, re-compressed.
7. Implement self-verification routine `verify_all(&fixtures) -> Result<(), FixtureError>` asserting:
   - `honest_counterparty`: 14/14 PASS.
   - `authority_bound`: 14/14 PASS (uncountersigned).
   - `agent_signed`: derives `AgentSigned`, R5 fails.
   - `tampered_summary`: R3 fails, `tampered == true`.
   - `tampered_hash`: R4 fails, `tampered == true`.
   - `tampered_signature`: R4 fails, `tampered == true`.
   - `scope_escalation`: R6 fails, `tampered == true`.
   - `revoked_token`: R9 fails, `tampered == false`.
   - `audit_bundle_valid`: all 7 bundle checks PASS.
   - `audit_bundle_tampered`: `FILE_HASHES` fails.
8. Register `pub mod fixtures;` in `aip-standalone/aip-protocol/src/lib.rs`.

### Phase 2: Implement CLI Binary `aip-protocol/src/bin/generate_fixtures.rs`
1. Parse CLI arguments:
   - `--out-dir <PATH>` (defaults to `aip-console/public/fixtures`)
   - `--also-e2e <PATH>` (optional secondary directory, e.g. `e2e/fixtures`)
   - `--verify-only` (run self-verification without writing)
2. Ensure destination directories exist (`std::fs::create_dir_all`).
3. Generate all fixtures, execute self-verification, and write:
   - 8 `.json` EvidencePackets
   - Companion `*.context.json` files
   - 2 `.zip` audit export bundles
   - `index.json` catalog
4. Print colorized summary report to stdout.

### Phase 3: Integration & Build Verification
1. Run `cargo test -p aip-protocol` to ensure all existing tests pass.
2. Execute generator:
   ```bash
   cargo run --manifest-path aip-standalone/Cargo.toml -p aip-protocol --bin generate_fixtures -- --out-dir aip-console/public/fixtures
   ```
3. Verify that all 10 fixtures, 4 context files, and `index.json` are created in `aip-console/public/fixtures/`.
4. Run `aip-verify` on generated fixtures to confirm offline auditor CLI compatibility:
   ```bash
   cargo run --manifest-path aip-standalone/Cargo.toml -p aip-verify -- aip-console/public/fixtures/honest_counterparty.json --report
   cargo run --manifest-path aip-standalone/Cargo.toml -p aip-verify -- aip-console/public/fixtures/audit_bundle_valid.zip --report
   ```
