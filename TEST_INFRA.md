# TEST_INFRA.md: E2E Test Infrastructure Specification
**Project:** AIP Enterprise Accountability Console (`aip-console`)  
**Lead:** E2E Testing Lead (`e2e_test_writer`)  
**Standard:** High-Assurance Opaque-Box Automated Verification  
**Date:** 2026-11-02  

---

## 1. Executive Summary & Infrastructure Overview

The AIP Enterprise Accountability Console is a mission-critical cryptographic verification web application providing offline and connected verification of Agent Identity Protocol (AIP) EvidencePackets with Syntriass enterprise branding.

This document defines the authoritative, opaque-box End-to-End (E2E) Test Infrastructure for the entire system. In accordance with zero-JS verification and high-assurance cryptographic audit requirements, all test assertions, expected outputs, boundary conditions, and real-world scenarios are derived strictly from normative specifications (`ORIGINAL_REQUEST.md`, `PROJECT.md`, `AIP_SPEC.md`, `AUDIT_EXPORT_SPEC.md`), and never from ad-hoc internal implementation code.

### Core Testing Mandates
1. **Opaque-Box Verification**: Tests interact with system boundaries (WASM APIs, UI contracts, REST endpoints, and file artifacts) as an external auditor or verifier.
2. **Authoritative Output Derivation**: Expected test values are calculated from deterministic mathematical formulations (e.g. SHA-256 canonical hashing, lattice meet operator $\sqcap$, trust floor state machine, and Ed25519 signature semantics).
3. **Four-Tier Comprehensive Taxonomy**:
   - **Tier 1 (Feature Coverage)**: At least 5 distinct test cases for every one of the 22 features (minimum 110 tests).
   - **Tier 2 (Boundary & Corner Cases)**: At least 5 boundary/edge test cases for every feature covering corrupt payloads, empty inputs, malformed signatures, and extreme conditions (minimum 110 tests).
   - **Tier 3 (Cross-Feature Combinations)**: Pairwise and multi-stage pipeline interactions (e.g. Ingestion $\to$ WASM Verification $\to$ DAG Reconstruction; Tampering $\to$ Hash Recalculation $\to$ Rule Failure; Authority Matrix $\to$ Lattice Attenuation $\to$ Cascade Revocation; Vault Filtering $\to$ Offline Fallback $\to$ ZIP Export).
   - **Tier 4 (Real-World Application Scenarios)**: Full lifecycle enterprise workflows (enterprise loan approval, multi-hop delegation, tamper detection, and offline air-gapped verification).
4. **Zero Flakiness & Test Isolation**: Each test is strictly hermetic, self-contained, deterministic, and creates its own independent cryptographic fixtures without cross-test state leakage.

---

## 2. Authoritative Specification & Ground Truth Sources

All test inputs and expected outputs are derived from authoritative specification documents:

| Source Document | Path in Repository | Governed Subsystems & Normative Ground Truth |
|---|---|---|
| `ORIGINAL_REQUEST.md` | `.agents/teamwork/ORIGINAL_REQUEST.md` | Requirements R1–R6, core acceptance criteria, trust anchor rules, zero-JS verification. |
| `PROJECT.md` | `PROJECT.md` | 22-Feature inventory (F1–F22), milestone dependencies, interface contracts (`AipWasmExports`, `VerificationReport`, `RuleResult`, `IEvidenceVaultClient`). |
| `AIP_SPEC.md` | `AIP_SPEC.md` | Normative wire format `AEP1`, canonical byte serialization algorithm, AIP-ID Base58 checksum derivation, 14 engine verification rules, Trust Floor progression. |
| `AUDIT_EXPORT_SPEC.md` | `docs/AUDIT_EXPORT_SPEC.md` | 7-file audit ZIP bundle specification (`evidence.json`, `verification.json`, `audit_report.md`, `accountability_graph.json`, `accountability_graph.dot`, `manifest.json`, `bundle.sig`). |
| `aip-types` & `aip-core` | `aip-standalone/` | Capability lattice algebra ($P \sqcap C$), standard named scopes (`ADMIN`, `ORCHESTRATOR`, `AUDIT_READER`, `SUBMITTER`), delegation chain depth limit (8 hops), cascade revocation hash-chaining. |

---

## 3. Four-Tier Test Architecture & Taxonomy

```
+-------------------------------------------------------------------------------------------------------+
|                                    AIP E2E TEST ARCHITECTURE                                         |
+-------------------------------------------------------------------------------------------------------+
|  Tier 4: Real-World Scenarios (e2e/tier4-scenarios/)                                                  |
|  - Enterprise Loan Approval Workflow          - Multi-Hop Delegation Attenuation Workflow             |
|  - Adversarial Tamper Detection Workflow      - Air-Gapped Offline Audit & ZIP Export Workflow        |
+-------------------------------------------------------------------------------------------------------+
|  Tier 3: Cross-Feature Combinations (e2e/tier3-combinations/)                                         |
|  - Ingestion -> WASM Verification -> DAG Rendering                                                   |
|  - Tampering -> Hash Fixing -> Rule Failure Feedback                                                  |
|  - Authority Matrix -> Lattice Attenuation -> Cascade Revocation                                      |
|  - Vault Filtering -> Offline Fallback -> ZIP Export                                                  |
+-------------------------------------------------------------------------------------------------------+
|  Tier 2: Boundary & Corner Cases (e2e/tier2-boundary/)                                                |
|  - F1..F22 Boundary Suites: Malformed JSON, Empty Inputs, Expired Tokens, Hash Mismatches,           |
|    Out-of-Order Timestamps, Max Delegation Depth (8+), Cross-Tenant Injections, Corrupted ZIPs       |
|    (>= 5 boundary tests per feature = 110+ tests)                                                     |
+-------------------------------------------------------------------------------------------------------+
|  Tier 1: Feature Coverage (e2e/tier1-features/)                                                       |
|  - F1..F22 Feature Coverage Suites: Primary Happy Paths, Interface Adherence, Output Formats        |
|    (>= 5 tests per feature = 110+ tests)                                                              |
+-------------------------------------------------------------------------------------------------------+
|  Test Harness & Support Infrastructure (e2e/support/ & e2e/fixtures/)                                 |
|  - Cryptographic Reference Oracles: Canonical Bytes, SHA-256, Ed25519, AIP-ID Base58 Derivation       |
|  - Mathematical Capability Lattice Engine: Meet Operator (⊓), Named Scopes, Revocation Chain          |
|  - Fixture Repository: Valid, Tampered, Attenuated, Revoked, and Countersigned EvidencePackets        |
+-------------------------------------------------------------------------------------------------------+
```

### Tier 1: Feature Coverage (F1 to F22)
Tier 1 ensures every functional feature defined in `PROJECT.md` operates according to specification under valid, expected operating conditions.
- Target: 22 features $\times \ge 5$ test cases = **$\ge 110$ tests**.
- Subsystems:
  - F1: `aip-wasm` WebAssembly export interface and functional exports.
  - F2: Deterministic test fixture generation pipeline.
  - F3: Next.js 15 & React 19 app shell structure and page routes.
  - F4: Syntriass enterprise vector SVG branding, logo, wordmark, and cyber color palette.
  - F5: Drag-and-drop file ingestion zone (JSON packets and ZIP audit bundles).
  - F6: Verifier trust anchor configuration input panel (trusted issuers, counterparties, revoked JTIs).
  - F7: 14-rule verification ledger rendering 1:1 engine outputs with zero JS verification.
  - F8: Mathematical Trust Floor progression ladder (`UNVERIFIED` $\to$ `AGENT_SIGNED` $\to$ `AUTHORITY_BOUND` $\to$ `COUNTERPARTY_SIGNED`).
  - F9: React Flow DAG viewer rendering 7 node kinds and 6 edge relations.
  - F10: Interactive DAG node inspection sheet displaying signatures, hashes, scopes, and verification badges.
  - F11: Adversarial tamper sandbox simulating 14 attack vectors.
  - F12: Smart hash recalculation toggle demonstrating tamper detection with and without hash fixing.
  - F13: Instant real-time rule failure feedback ledger.
  - F14: Visual scope matrix editor for named and custom capability permissions.
  - F15: Capability lattice attenuation preview calculating meet operator ($\sqcap$) and $\bot$ detection.
  - F16: Cascade revocation tree visualizing recursive subtree token invalidation.
  - F17: Evidence Vault Explorer multi-tenant table with search, filter, and sort capabilities.
  - F18: Signed ZIP bundle export adhering to 7-file `AUDIT_EXPORT_SPEC.md`.
  - F19: Connected service REST API client (`/v1/evidence/verify`, `/v1/evidence/{id}`, `/v1/authority/{id}`, `/v1/evidence/{id}/export`).
  - F20: Offline mock fallback mode with IndexedDB repository and client-side verification/export.
  - F21: End-to-end test suite execution and test coverage validation.
  - F22: Adversarial coverage hardening and stress testing verification.

### Tier 2: Boundary & Corner Cases (F1 to F22)
Tier 2 subjects all 22 features to boundary conditions, invalid inputs, corrupted signatures, non-canonical encodings, and edge cases.
- Target: 22 features $\times \ge 5$ test cases = **$\ge 110$ tests**.
- Key Boundary Vectors:
  - Empty or null inputs, empty action arrays, empty decision summaries.
  - Malformed magic bytes (`b"BAD1"`), unsupported versions (`version: 2`).
  - Cryptographic payload mismatch, corrupted signatures, public key substitutions.
  - Sub-millisecond and inverted timestamps (`performed_at < decided_at`, expired tokens).
  - Maximum delegation depth boundary (chain length 7 vs 8 vs 9 hops).
  - Lattice meet resulting in empty intersection ($\bot$).
  - Circular delegation attempt, broken issuer/grantee handoffs.
  - ZIP bundles with corrupted CRC, missing manifest, or tampered member files.
  - Cross-tenant unauthorized access attempts returning strictly 404 Not Found.

### Tier 3: Cross-Feature Combinations
Tier 3 verifies the interaction boundaries between interdependent subsystems:
1. **Pipeline 1: Ingestion $\to$ WASM Verification $\to$ DAG Rendering**
   Raw file drop parsed, passed to WASM engine, 14 rules evaluated, Trust Floor computed, and 7-node DAG rendered with corresponding cryptographic badges.
2. **Pipeline 2: Tamper Simulation $\to$ Smart Hash Fixing $\to$ Real-Time Ledger Reaction**
   Adversarial modification of decision summary, triggering immediate `CANONICAL_HASH` and `AGENT_SIGNATURE` failure; toggling hash recalculation fixes `CANONICAL_HASH` while `AGENT_SIGNATURE` remains failed.
3. **Pipeline 3: Visual Scope Matrix $\to$ Lattice Meet Attenuation $\to$ Cascade Revocation**
   Permission reduction in scope matrix triggers live meet calculation; revoking a parent token recursively marks all child tokens revoked across the tree.
4. **Pipeline 4: Vault Search/Filter $\to$ Offline Fallback Failover $\to$ Signed Bundle ZIP Export**
   Evidence vault transitions from live REST API to offline fallback upon connection loss; filtering retains state; export produces valid 7-file ZIP bundle verifiable offline.

### Tier 4: Real-World Application Scenarios
Tier 4 executes complete end-to-end user workflows representative of production enterprise deployment:
1. **Scenario 1: Enterprise Loan Approval & Multi-Level Attenuation**
   Full enterprise flow from Chief Risk Officer principal down through Treasury Orchestrator to Loan Approval Agent, action execution, and bilateral core-banking countersigned receipt.
2. **Scenario 2: Multi-Hop Autonomous Agent Delegation Chain**
   Deep delegation across 4 tiers with monotonic scope attenuation, verifying depth monotonicity and handoff continuity.
3. **Scenario 3: Forensic Adversarial Tamper Investigation**
   Ingesting an apparently valid packet, detecting silent tampering via canonical hash and signature mismatch, locating the exact modified field, and validating engine tamper evidence flags.
4. **Scenario 4: Air-Gapped Offline Audit & Signed ZIP Verification**
   Operating in completely disconnected mode (no network, zero REST service), loading pre-compiled ZIP audit bundle, verifying all 7 internal bundle checks, and exporting cryptographically certified audit summary.

---

## 4. Test Topology & Code Layout

The test suite is structured within the standard `e2e/` directory per `PROJECT.md`:

```
e2e/
├── fixtures/                          # Canonical test packets and audit bundles
│   ├── evidence_packets.ts           # Deterministic valid, tampered, attenuated packets
│   └── audit_bundles.ts              # Canonical 7-file ZIP bundle fixtures
├── support/                           # Test harness, reference oracles & models
│   ├── reference_oracle.ts           # Authoritative 14-rule engine, hash, and crypto oracle
│   ├── lattice_oracle.ts             # Normative capability lattice meet (⊓) calculator
│   ├── dag_oracle.ts                 # Graph topology, node schemas, BFS chain validator
│   ├── types.ts                      # Protocol wire types & engine interface contracts
│   └── mock_vault_client.ts          # IEvidenceVaultClient test harness
├── tier1-features/                    # Tier 1: Feature Coverage (>= 110 tests)
│   ├── f01_wasm_bridge.spec.ts       # F1: aip-wasm export contract & execution
│   ├── f02_fixture_pipeline.spec.ts  # F2: Sample packet & bundle generators
│   ├── f03_app_shell.spec.ts         # F3: Next.js 15 / React 19 app shell routes
│   ├── f04_branding.spec.ts          # F4: Syntriass vector SVG logos & cyber palette
│   ├── f05_ingestion.spec.ts         # F5: Drag-and-drop JSON & ZIP ingestion
│   ├── f06_trust_anchor.spec.ts      # F6: Trust anchor configuration panel
│   ├── f07_rule_ledger.spec.ts       # F7: 14-rule verification ledger (1:1 mapping)
│   ├── f08_trust_floor.spec.ts       # F8: Mathematical Trust Floor ladder
│   ├── f09_dag_viewer.spec.ts        # F9: React Flow DAG viewer (7 nodes, 6 edges)
│   ├── f10_inspection_sheet.spec.ts  # F10: DAG node inspection sheet
│   ├── f11_tamper_sandbox.spec.ts    # F11: 14-vector adversarial tamper sandbox
│   ├── f12_hash_toggle.spec.ts       # F12: Smart hash recalculation toggle
│   ├── f13_failure_feedback.spec.ts  # F13: Instant rule failure feedback
│   ├── f14_scope_matrix.spec.ts      # F14: Visual scope matrix editor
│   ├── f15_lattice_preview.spec.ts   # F15: Capability lattice meet preview (⊓)
│   ├── f16_revocation_tree.spec.ts   # F16: Cascade revocation tree
│   ├── f17_vault_table.spec.ts       # F17: Evidence Vault Explorer table
│   ├── f18_bundle_export.spec.ts     # F18: 7-file signed ZIP bundle export
│   ├── f19_service_client.spec.ts    # F19: Connected REST client (/v1/evidence/*)
│   ├── f20_offline_mode.spec.ts      # F20: Offline mock fallback mode
│   ├── f21_e2e_suite.spec.ts         # F21: End-to-end test suite coverage
│   └── f22_hardening.spec.ts         # F22: Adversarial coverage hardening
├── tier2-boundary/                    # Tier 2: Boundary & Corner Cases (>= 110 tests)
│   ├── f01_wasm_boundary.spec.ts
│   ├── f02_fixtures_boundary.spec.ts
│   ├── f03_app_shell_boundary.spec.ts
│   ├── f04_branding_boundary.spec.ts
│   ├── f05_ingestion_boundary.spec.ts
│   ├── f06_trust_anchor_boundary.spec.ts
│   ├── f07_ledger_boundary.spec.ts
│   ├── f08_trust_floor_boundary.spec.ts
│   ├── f09_dag_boundary.spec.ts
│   ├── f10_inspection_boundary.spec.ts
│   ├── f11_tamper_boundary.spec.ts
│   ├── f12_hash_toggle_boundary.spec.ts
│   ├── f13_failure_boundary.spec.ts
│   ├── f14_scope_matrix_boundary.spec.ts
│   ├── f15_lattice_boundary.spec.ts
│   ├── f16_revocation_boundary.spec.ts
│   ├── f17_vault_boundary.spec.ts
│   ├── f18_bundle_export_boundary.spec.ts
│   ├── f19_service_boundary.spec.ts
│   ├── f20_offline_boundary.spec.ts
│   ├── f21_e2e_boundary.spec.ts
│   └── f22_hardening_boundary.spec.ts
├── tier3-combinations/                # Tier 3: Cross-Feature Interactions
│   ├── pipeline1_ingest_verify_dag.spec.ts
│   ├── pipeline2_tamper_hash_ledger.spec.ts
│   ├── pipeline3_matrix_lattice_revoke.spec.ts
│   └── pipeline4_vault_offline_export.spec.ts
└── tier4-scenarios/                   # Tier 4: Real-World Production Scenarios
    ├── scenario1_enterprise_loan.spec.ts
    ├── scenario2_delegation_chain.spec.ts
    ├── scenario3_forensic_tamper.spec.ts
    └── scenario4_airgapped_audit.spec.ts
```

---

## 5. Test Oracle & Expected Value Derivation Strategy

To uphold the principle that tests must be opaque-box and derived strictly from requirements, the test infrastructure embeds mathematical reference oracles.

### 5.1 The 14-Rule Verification Ledger Oracle
The verification oracle (`e2e/support/reference_oracle.ts`) executes the exact normative verification algorithm specified in `AIP_SPEC.md`:
1. `STRUCTURE`: Evaluates magic bytes `0x41 0x45 0x50 0x31` (`"AEP1"`), version `1`, non-empty strings, and `actions.length >= 1`.
2. `AGENT_ID_BINDING`: Validates Base58 checksum format and checks $AIP\_ID == \text{derive}(pubkey, provenance)$.
3. `CANONICAL_HASH`: Computes SHA-256 over deterministic canonical bytes; checks equality with `packet.packet_hash`. Sets `tamper_evidence = true` if mismatched.
4. `AGENT_SIGNATURE`: Checks `sig.signer_id == agent.aip_id`, `sig.payload_hash == recomputed_hash`, and verifies Ed25519 signature. Sets `tamper_evidence = true` if invalid.
5. `ROOT_TOKEN_SIGNATURE`: Looks up root issuer key in trust context; verifies root token Ed25519 signature. Sets `tamper_evidence = true` if trusted key present but signature fails.
6. `DELEGATION_CHAIN`: Checks JTI linkage, depth monotonicity ($d_{i} = d_{i-1} + 1$), chain length $< 8$, attenuation ($Scope_i \subseteq Scope_{i-1}$), and verifies per-hop signatures.
7. `AUTHORITY_CHAIN`: Verifies continuity from root token grantee to acting agent through consecutive hops ($hop[i].issuer == hop[i-1].grantee$).
8. `SCOPE_AUTHORITY`: Computes effective scope; verifies decision and all action kinds are permitted.
9. `REVOCATION`: Verifies neither root token JTI nor any delegation JTI exists in `context.revoked_jtis`.
10. `TEMPORAL_VALIDITY`: Verifies $decided\_at \ge issued\_at$, $performed\_at \ge decided\_at$, and both $\le expires\_at$.
11. `ACTION_ATTESTATIONS`: Verifies each action's Ed25519 signature bound to `decision_id` and action canonical bytes.
12. `TRACE_BINDING`: If present and trace data supplied, verifies $SHA256(data) == trace\_hash$.
13. `RECEIPT_BINDING`: If present, verifies receipt system, receipt ID, and countersignature over canonical receipt payload.
14. `TRUST_FLOOR`: Derives mathematical floor ($0 \dots 3$) and asserts $derived\_floor \ge claimed\_floor$.

### 5.2 Mathematical Capability Lattice Meet ($\sqcap$) Oracle
The capability lattice oracle (`e2e/support/lattice_oracle.ts`) computes:
$$Allowed(P \sqcap C) = C.Allowed \cap (P.Allowed \setminus P.Denied)$$
$$Denied(P \sqcap C) = P.Denied \cup C.Denied$$
If $Allowed(P \sqcap C) = \emptyset$, the operator returns $\bot$ (bottom), signifying illegal capability expansion.

### 5.3 Accountability DAG Reachability Oracle
The DAG oracle (`e2e/support/dag_oracle.ts`) constructs graph nodes and edges per `PROJECT.md` contracts and performs Breadth-First Search (BFS) starting from the single `Principal` node. It verifies:
- Exactly 1 `Principal` node.
- All 7 node kinds adhere to schema (`principal`, `authority_grant`, `delegation`, `agent`, `decision`, `action`, `receipt`).
- All 6 edge kinds adhere to directional semantics (`Issues`, `Delegates`, `ActsUnder`, `Decides`, `Performs`, `Produces`).
- $100\%$ of graph nodes are reachable from the Principal root.

---

## 6. Execution Harness & Toolchain Configuration

### Toolchain Specification
- **Runtime**: Node.js v24.17.0+
- **Package Manager**: npm 11.13.0+
- **Test Runner**: Vitest 5.0+ / Node native test runner (`node --test`)
- **Language**: TypeScript 5.0+

### Execution Commands
- **Full E2E Suite**: `npm run test:e2e` (or `npx vitest run`)
- **Tier 1 Only**: `npx vitest run e2e/tier1-features/`
- **Tier 2 Only**: `npx vitest run e2e/tier2-boundary/`
- **Tier 3 Only**: `npx vitest run e2e/tier3-combinations/`
- **Tier 4 Only**: `npx vitest run e2e/tier4-scenarios/`
- **Single Feature Verification**: `npx vitest run e2e/tier1-features/f07_rule_ledger.spec.ts`

---

## 7. Traceability Matrix

| Requirement | Governed Features | Primary Test Suites | Boundary Test Suites | Combinations / Scenarios |
|---|---|---|---|---|
| **R1: Ingestion & 14-Rule Ledger** | F1, F2, F5, F6, F7, F8 | `f01_wasm_bridge`, `f02_fixture_pipeline`, `f05_ingestion`, `f06_trust_anchor`, `f07_rule_ledger`, `f08_trust_floor` | `f01`, `f02`, `f05`, `f06`, `f07`, `f08_boundary` | `pipeline1_ingest_verify_dag`, `scenario4_airgapped_audit` |
| **R2: Accountability DAG** | F9, F10 | `f09_dag_viewer`, `f10_inspection_sheet` | `f09_dag_boundary`, `f10_inspection_boundary` | `pipeline1_ingest_verify_dag`, `scenario2_delegation_chain` |
| **R3: Adversarial Tamper Sandbox**| F11, F12, F13 | `f11_tamper_sandbox`, `f12_hash_toggle`, `f13_failure_feedback` | `f11`, `f12`, `f13_boundary` | `pipeline2_tamper_hash_ledger`, `scenario3_forensic_tamper` |
| **R4: Authority & Lattice Builder**| F14, F15, F16 | `f14_scope_matrix`, `f15_lattice_preview`, `f16_revocation_tree` | `f14`, `f15`, `f16_boundary` | `pipeline3_matrix_lattice_revoke`, `scenario1_enterprise_loan` |
| **R5: Evidence Vault Explorer** | F17, F18, F19, F20 | `f17_vault_table`, `f18_bundle_export`, `f19_service_client`, `f20_offline_mode` | `f17`, `f18`, `f19`, `f20_boundary` | `pipeline4_vault_offline_export`, `scenario4_airgapped_audit` |
| **R6: Architecture & Branding** | F3, F4, F21, F22 | `f03_app_shell`, `f04_branding`, `f21_e2e_suite`, `f22_hardening` | `f03`, `f04`, `f21`, `f22_boundary` | All pipelines and scenarios |

---

## 8. Pass/Fail Criteria & Quality Gates

The test suite enforces zero-tolerance quality gates:
1. **100% Pass Rate**: Zero test failures tolerated across all 4 tiers.
2. **Strict Non-Short-Circuiting**: Every rule check in the 14-rule ledger must be explicitly tested for independent evaluation.
3. **Tamper Evidence Accuracy**: Any mutation to sealed packets must assert both `overall_valid == false` and `tamper_evidence == true` (with the exception of configuration/revocation gaps).
4. **Coverage Density**: Minimum 5 test cases per feature in Tier 1, minimum 5 boundary test cases per feature in Tier 2, multi-stage interaction tests in Tier 3, and full lifecycle workflows in Tier 4.

Upon completion of test suite implementation and verification pass, `TEST_READY.md` is published at the project root to certify readiness.
