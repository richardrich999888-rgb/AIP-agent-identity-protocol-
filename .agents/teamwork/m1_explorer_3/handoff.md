# Handoff Report: Milestone 1 Fixtures & Test Data Pipeline Specialist (F2)

**Agent ID:** `m1_explorer_3`  
**Milestone:** M1 — `aip-wasm` Core Engine & Fixtures Pipeline  
**Target:** Feature F2 (Test Fixture Generation Pipeline)  
**Date:** 2026-11-02  
**Handoff Type:** Hard Handoff (Investigation & Specification Complete)  

---

## 1. Observation

Direct observations from repository files and tool inspections:

1. **Existing Protocol Generators**:
   - `aip-standalone/aip-protocol/tests/evidence_packet.rs` lines 45–161 implement `build_fixture()` producing a 3-party chain: Human CFO (`cfo_kp`), Treasury Orchestrator (`orch_kp`), Payments Agent (`agent_kp`), and external Ledger system (`ledger_kp`).
   - `aip-standalone/aip-protocol/tests/evidence_packet.rs` lines 223–440 implement 12 distinct tamper attack vectors:
     - `test_tamper_decision_summary_detected` (lines 223–233): mutates `p.decision.summary`, triggers `rules::CANONICAL_HASH`.
     - `test_tamper_recompute_hash_still_caught_by_signature` (lines 235–246): mutates summary and calls `p.packet_hash = p.compute_hash()`, triggers `rules::AGENT_SIGNATURE`.
     - `test_scope_escalation_in_chain_detected` (lines 262–273): mutates `p.delegation_chain[0].scope = CapabilityScope::all()`, triggers `rules::DELEGATION_CHAIN`.
     - `test_revoked_delegation_invalidates_packet` (lines 310–322): adds hop JTI to `ctx.revoked_jtis`, triggers `rules::REVOCATION`. Note lines 318–319 explicitly assert: `assert!(!report.revocation_clear); assert!(!report.tampered);`.
   - `aip-standalone/aip-protocol/tests/bundle.rs` lines 109–144 implement `build_zip("acme", &packet, &report, &seed, &public)`.
   - `aip-standalone/aip-protocol/tests/bundle.rs` lines 173–189 demonstrate tampering `evidence.json` inside a ZIP archive, asserting failure of `FILE_HASHES` (`fh.status == BundleStatus::Fail`).
   - `aip-standalone/banking_demo/src/main.rs` lines 56–268 implement a realistic enterprise pilot workflow with payment approval for invoice `INV-2026-0142` ($48,200.00), W3C OTel trace binding, and bilateral bank ledger receipt `LEDGER-90211` from `ledger.example-bank.com`.

2. **Verification Engine Rule Constants**:
   - In `aip-standalone/aip-protocol/src/verification_report.rs` lines 15–30, the 14 stable rule identifiers are:
     ```rust
     pub const STRUCTURE: &str = "STRUCTURE";
     pub const AGENT_ID_BINDING: &str = "AGENT_ID_BINDING";
     pub const CANONICAL_HASH: &str = "CANONICAL_HASH";
     pub const AGENT_SIGNATURE: &str = "AGENT_SIGNATURE";
     pub const ROOT_TOKEN_SIGNATURE: &str = "ROOT_TOKEN_SIGNATURE";
     pub const DELEGATION_CHAIN: &str = "DELEGATION_CHAIN";
     pub const AUTHORITY_CHAIN: &str = "AUTHORITY_CHAIN";
     pub const SCOPE_AUTHORITY: &str = "SCOPE_AUTHORITY";
     pub const REVOCATION: &str = "REVOCATION";
     pub const TEMPORAL_VALIDITY: &str = "TEMPORAL_VALIDITY";
     pub const ACTION_ATTESTATIONS: &str = "ACTION_ATTESTATIONS";
     pub const TRACE_BINDING: &str = "TRACE_BINDING";
     pub const RECEIPT_BINDING: &str = "RECEIPT_BINDING";
     pub const TRUST_FLOOR: &str = "TRUST_FLOOR";
     ```
   - In `aip-standalone/aip-protocol/src/evidence_packet.rs` lines 44–58:
     `TrustFloor` enum: `Unverified = 0`, `AgentSigned = 1`, `AuthorityBound = 2`, `CounterpartySigned = 3`.

3. **Workspace Configuration & Dependency Graph**:
   - `aip-standalone/Cargo.toml` lines 1–13 show the workspace members: `aip-types`, `aip-crypto`, `aip-core`, `aip-protocol`, `aip-test`, `aip-cli`, `aip-verify`, `aip-real-tests`, `banking_demo`.
   - `aip-protocol/Cargo.toml` lines 8–16 include `aip-types`, `aip-crypto`, `aip-core`, `serde`, `serde_json`, `hex`, and `zip = { version = "2", default-features = false, features = ["deflate"] }`.
   - Adding a binary to `aip-protocol/src/bin/generate_fixtures.rs` requires zero changes to `aip-standalone/Cargo.toml` or `aip-protocol/Cargo.toml` because Cargo natively recognizes all files under `src/bin/*.rs` as executable targets.

4. **Directory Structure**:
   - `aip-console/public/` does not yet exist. It will be created to house `aip-console/public/fixtures/` and `aip-console/public/wasm/`.
   - `docs/AUDIT_EXPORT_SPEC.md` lines 12–23 specify the 7 mandatory entries of `aip-bundle-1`: `evidence.json`, `verification_report.json`, `verification_report.md`, `authority_graph.json`, `authority_graph.dot`, `manifest.json`, and `bundle_signature.sig`.

---

## 2. Logic Chain

1. **Step 1: Test and UI Dependability**:
   - Both the Next.js 15 Console (`aip-console/`) and the automated opaque-box test suites (`e2e/`) require static, pre-compiled, cryptographically valid and tampered EvidencePackets and ZIP bundles.
   - Relying on dynamic runtime key generation inside client-side TypeScript would violate the architectural requirement of "zero verification/generation logic reimplemented in JS" and introduce non-deterministic state.
   - Therefore, a dedicated Rust pipeline must generate deterministic, bit-exact fixtures and write them to `aip-console/public/fixtures/` and `e2e/fixtures/`.

2. **Step 2: 1:1 Coverage of the 14 Verification Rules**:
   - The UI verification ledger displays 14 engine checks. To test and demonstrate all ledger states in the console:
     - `honest_counterparty.json` proves complete validity (all 14 rules pass, floor: `CounterpartySigned`).
     - `authority_bound.json` proves valid internal enterprise delegation without external counterparty countersignature (rules 1–12 pass, receipt rule reports uncountersigned, floor: `AuthorityBound`).
     - `agent_signed.json` proves agent identity commitment without backing corporate delegation (rules 1–4 pass, rule 5 fails on missing root issuer key, floor: `AgentSigned`).
     - `tampered_summary.json` proves detection of field modification (rule 3 `CANONICAL_HASH` fails, `tamper_evidence = true`).
     - `tampered_hash.json` proves detection of hash-recalculating attackers (rule 3 passes, rule 4 `AGENT_SIGNATURE` fails, `tamper_evidence = true`).
     - `tampered_signature.json` proves detection of signature corruption (rule 4 fails, `tamper_evidence = true`).
     - `scope_escalation.json` proves enforcement of capability attenuation (rule 6 `DELEGATION_CHAIN` fails, `tamper_evidence = true`).
     - `revoked_token.json` proves token lifecycle invalidation without flagging post-sealing tampering (rule 9 `REVOCATION` fails, `tamper_evidence = false`).
     - `audit_bundle_valid.zip` proves offline multi-file verification (all 7 bundle checks pass).
     - `audit_bundle_tampered.zip` proves detection of manipulated archive members (`FILE_HASHES` fails).

3. **Step 3: Verification Context Binding**:
   - EvidencePacket verification is functional: $f(\text{packet}, \text{context}) \to \text{report}$.
   - Without the corresponding `VerificationContext` (trusted root issuer keys and counterparty public keys), an auditor or the UI cannot verify `ROOT_TOKEN_SIGNATURE`, `DELEGATION_CHAIN`, or `RECEIPT_BINDING`.
   - Therefore, each fixture must be accompanied by its matching `*.context.json` file and indexed in `index.json`.

4. **Step 4: Location and Pipeline Architecture**:
   - `aip-protocol` is already the crate where `EvidencePacketBuilder`, `VerificationContext`, `verify_packet`, `build_zip`, and `verify_zip` live.
   - Placing the reusable generator logic in `aip-protocol/src/fixtures.rs` and the CLI binary in `aip-protocol/src/bin/generate_fixtures.rs`:
     - Keeps dependencies minimal (zero new crates or workspace edits).
     - Provides an automated self-test before disk writes.
     - Enables a single standard command: `cargo run -p aip-protocol --bin generate_fixtures -- --out-dir aip-console/public/fixtures`.

---

## 3. Caveats

1. **Console Directory Creation**:
   - `aip-console/public/fixtures/` does not exist yet. The generator must call `std::fs::create_dir_all` to automatically create parent directories.
2. **Determinism vs SystemTime**:
   - If `std::time::SystemTime::now()` is used, timestamp fields will change on every execution.
   - To make fixtures strictly deterministic and prevent noisy git diffs, the generator should use fixed base timestamps (e.g. `1781769600000`, 2026-06-15T08:00:00Z) and deterministic seeds for Ed25519 signing keys.
3. **WASM Crate Coordination**:
   - `aip-wasm` (designed by Explorer 1 and Explorer 2) includes `get_sample_packet(sampleType: string)`.
   - It can either read from the generated JSON files or link to `aip_protocol::fixtures::get_sample(name)`.

---

## 4. Conclusion

1. Implement the fixture generation engine in `aip-standalone/aip-protocol/src/fixtures.rs`.
2. Implement the CLI generation binary in `aip-standalone/aip-protocol/src/bin/generate_fixtures.rs`.
3. Support exporting all 10 required fixtures (8 JSONs + 2 ZIPs), 4 context files, and `index.json` to `aip-console/public/fixtures/` and optionally `e2e/fixtures/`.
4. The generation pipeline executes self-verification before writing, ensuring 100% adherence to expected rule outcomes.

---

## 5. Verification Method

To independently verify the implementation:

1. **Build and Test Protocol Crate**:
   ```bash
   cargo test --manifest-path "c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\aip-standalone\Cargo.toml" -p aip-protocol
   ```
2. **Execute the Generator Binary**:
   ```bash
   cargo run --manifest-path "c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\aip-standalone\Cargo.toml" -p aip-protocol --bin generate_fixtures -- --out-dir "c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\aip-console\public\fixtures"
   ```
3. **Verify File Outputs**:
   Confirm the presence of all 15 files in `aip-console/public/fixtures/`:
   - `honest_counterparty.json`, `honest_counterparty.context.json`
   - `authority_bound.json`, `authority_bound.context.json`
   - `agent_signed.json`, `agent_signed.context.json`
   - `tampered_summary.json`
   - `tampered_hash.json`
   - `tampered_signature.json`
   - `scope_escalation.json`
   - `revoked_token.json`, `revoked_token.context.json`
   - `audit_bundle_valid.zip`
   - `audit_bundle_tampered.zip`
   - `index.json`
4. **Offline Auditor CLI Verification**:
   ```bash
   cargo run --manifest-path "c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\aip-standalone\Cargo.toml" -p aip-verify -- "c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\aip-console\public\fixtures\honest_counterparty.json" --report
   cargo run --manifest-path "c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\aip-standalone\Cargo.toml" -p aip-verify -- "c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\aip-console\public\fixtures\audit_bundle_valid.zip" --report
   ```
5. **Invalidation Condition**:
   The implementation is invalid if any fixture fails to elicit its exact specified rule pass/fail status, if `tampered_summary.json` does not set `tamper_evidence = true`, if `revoked_token.json` incorrectly sets `tamper_evidence = true`, or if `audit_bundle_valid.zip` fails `verify_zip`.
