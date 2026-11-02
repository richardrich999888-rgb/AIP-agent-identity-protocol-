# Milestone 1 Challenger 2 Empirical Handoff Report

**Agent**: Milestone 1 Challenger 2 (`teamwork_challenger`)  
**Roles**: `critic`, `specialist`  
**Milestone**: M1 — `aip-wasm` Core Engine & Fixtures Pipeline  
**Date**: 2026-11-02  
**Handoff Type**: Hard (Challenge Complete)  
**Verdict**: **REJECT** (Blocking WebAssembly Runtime Panic in Exported Function `get_sample_packet`)

---

## 1. Observation

### 1.1 Core Verification Target Results
Challenger 2 developed and executed two comprehensive empirical test harnesses:
1. `aip-standalone/aip-wasm/tests/challenge_tests.rs` (Native integration stress test suite)
2. `aip-standalone/aip-wasm/tests/wasm_binary_empirical.mjs` (Direct WebAssembly binary execution harness against `aip-console/public/wasm/aip_wasm_bg.wasm`)

#### Target 1: Bundle ZIP Verification & 7-File Extraction
- **File Extraction (`extract_bundle_files`)**:
  Extracted all 7 required files from `aip-console/public/fixtures/audit_bundle_valid.zip`:
  1. `evidence.json` (SHA-256: `a75d5b404f738b441735564728103d9e9817b10514c257bfdff24abe460b6e95`)
  2. `verification_report.json` (SHA-256: `c44a2f2d68d3a9531ddb2ec0f63da259bbe205507bcc6eb7c06d04cdd934ccb8`)
  3. `verification_report.md` (SHA-256: `4941dadd75754087ac423930c2c18cbe944b302eaa3323b4b55932f859da584c`)
  4. `authority_graph.json` (SHA-256: `bdaf2c31cbc8b1dbdf4d16b2ea607b549d401f5a5493c7fb06c34710910da8e4`)
  5. `authority_graph.dot` (SHA-256: `5d755a27cf8f8f27f494d35bae9ebf88822803e0a79afc5b2d8e3215b3df54ce`)
  6. `manifest.json` (Schema: `aip-bundle-1`)
  7. `bundle_signature.sig` (128-char hex Ed25519 signature)
  Every content file matches bit-for-bit the SHA-256 hash recorded in `manifest.json`.
- **Bundle Verification (`verify_bundle_zip`)**:
  - Valid bundle + context yields `overall: "PASS"`, `overall_pass: true`, with 7/7 checks passed (`BUNDLE_STRUCTURE`, `MANIFEST_PARSE`, `FILE_HASHES`, `BUNDLE_HASH`, `BUNDLE_SIGNATURE`, `EVIDENCE_INTEGRITY`, `PACKET_VERIFICATION`).
  - Valid bundle without context yields `overall: "WARNING"` with warning on unanchored authority chain (does not falsely fail).
  - Tampered bundle (`audit_bundle_tampered.zip`) yields `overall: "FAIL"`, `overall_pass: false`.
  - Adversarial mutations (missing files, tampered `manifest.json`, tampered `evidence.json`, corrupt `bundle_signature.sig`, empty bytes, corrupt non-ZIP data) all cleanly fail verification with specific rule breakdown.

#### Target 2: React Flow DAG Formatting in `get_accountability_graph`
- Emits valid React Flow DAG structure:
  - Nodes have `id`, `kind`, and `label`.
  - Edges have `from`, `to`, `source`, `target`, and `relation`, with invariant `source === from` and `target === to` required by React Flow (`@xyflow/react`).
  - Graph connectivity: BFS traversal from root `principal` visits 100% of nodes in the graph (zero orphan or unreachable nodes).
  - Correctly renders graph variants: `agent_signed` (no receipt, no delegation hops), `authority_bound` (no receipt counterparty signature), and `honest_counterparty` (full multi-hop delegation and receipt chain).
  - Correctly binds `derived_trust_floor` when attached verification report matches `packet_id`, and sets `null` on ID mismatch.

#### Target 3: Capability Lattice Algebra (`check_scope_permits` & `meet_capability_scopes`)
- `check_scope_permits` correctly evaluates permissions against standard named scopes (`ADMIN`, `ORCHESTRATOR`, `AUDIT_READER`, `SUBMITTER`) and custom domain scopes.
- `meet_capability_scopes` accurately performs lattice intersection ($\sqcap$):
  - `ADMIN ⊓ ORCHESTRATOR`: non-empty, `is_bottom: false`.
  - `ORCHESTRATOR ⊓ AUDIT_READER`: retains `["read"]`, `is_bottom: false`.
  - `AUDIT_READER ⊓ SUBMITTER`: disjoint intersection flags `is_bottom: true` ($\bot$) with `allowed: []`.
  - Custom disjoint domains (`finance:transfer` vs `k8s:deploy`): flags `is_bottom: true` with `allowed: []`.
  - Attenuation non-expansion invariant verified: child scope cannot escalate privileges beyond parent.

---

### 1.2 Critical Defect Observed: WebAssembly Runtime Panic in `get_sample_packet`

When executing `aip_wasm.js` / `aip_wasm_bg.wasm` inside the WebAssembly runtime via `node aip-standalone/aip-wasm/tests/wasm_binary_empirical.mjs`:
```text
panicked at /rustc/88d9e12ae178fab0fb5cc050a94da85685d449ea/library/std/src/sys/time/unsupported.rs:35:9:
time not implemented on this platform

Stack:
Error
    at __wbg_new_bb74001155cb8ca8 (aip-console/public/wasm/aip_wasm.js:360:25)
    at wasm://wasm/0040aa8a:wasm-function[1025]:0xddc5f
    at wasm://wasm/0040aa8a:wasm-function[513]:0x9aa96
    at wasm://wasm/0040aa8a:wasm-function[787]:0xa9158
    at wasm://wasm/0040aa8a:wasm-function[954]:0xdd243
    at wasm://wasm/0040aa8a:wasm-function[166]:0x5b817
    at wasm://wasm/0040aa8a:wasm-function[835]:0xc0427
    at Module.get_sample_packet (aip-console/public/wasm/aip_wasm.js:152:26)

RuntimeError: unreachable
```

**Root Cause Code Inspection**:
1. In `aip-standalone/aip-wasm/src/lib.rs` (line 272):
   ```rust
   #[wasm_bindgen]
   pub fn get_sample_packet(sample_type: &str) -> Result<String, JsValue> {
       let fixtures = samples::generate_all_fixtures();
       ...
   ```
2. In `aip-standalone/aip-wasm/src/samples.rs` (lines 35, 95):
   `generate_all_fixtures()` calls `build_honest_counterparty()`, which calls:
   ```rust
   let root_token = issue_scoped_token(
       &vp_id,
       &vp_sk,
       &infra_id,
       scope_admin(),
       Some(7_200_000),
   ).expect("issue root token");
   ```
3. In `aip-standalone/aip-core/src/capability.rs` (lines 137, 191-196):
   `issue_scoped_token` calls local helper `now_ms()`:
   ```rust
   fn now_ms() -> u64 {
       SystemTime::now()
           .duration_since(UNIX_EPOCH)
           .unwrap()
           .as_millis() as u64
   }
   ```
4. On `wasm32-unknown-unknown`, `std::time::SystemTime::now()` is not implemented and unconditionally panics. This triggers `RuntimeError: unreachable`, crashing the WebAssembly engine.
5. In addition, identical unhandled `SystemTime::now()` calls exist in:
   - `aip-standalone/aip-core/src/delegation.rs` (line 362)
   - `aip-standalone/aip-core/src/revocation.rs` (line 278)
   - `aip-standalone/aip-protocol/src/bundle.rs` (line 97)

---

## 2. Logic Chain

1. **Premise 1 (`PROJECT.md` Feature Contract F1)**: `aip-wasm` must compile to `wasm32-unknown-unknown` and export 10 functions with full runtime compatibility in browser environments without runtime panics.
2. **Premise 2 (Worker Claim in `m1_worker/handoff.md`)**: The worker claimed: *"Step 1 (WASM Time Safety): Direct observation showed SystemTime::now() panics on wasm32-unknown-unknown at runtime. Introducing aip_crypto::now_ms() ... eliminates runtime panic on browser targets"*.
3. **Observation 3 (Omission in Core Crates)**: While `aip_crypto` and `aip_protocol::verification` were updated, `aip-core/src/capability.rs` (line 191) still calls `SystemTime::now()`.
4. **Observation 4 (WASM Runtime Panic)**: Direct execution of the compiled `aip_wasm_bg.wasm` via `node wasm_binary_empirical.mjs` confirmed that calling `get_sample_packet('honest_counterparty')` immediately panics with `time not implemented on this platform`, triggering an unrecoverable `RuntimeError: unreachable`.
5. **Deduction 5 (Verdict Requirement)**: Because an exported WebAssembly function crashes the browser runtime upon invocation, Feature F1 is broken in production WebAssembly execution. Milestone 1 cannot be approved in this state.

---

## 3. Caveats

- The 4 core verification targets assigned to Challenger 2 (`verify_bundle_zip`, `extract_bundle_files`, `get_accountability_graph`, `meet_capability_scopes`) are mathematically correct and pass 100% of both native and WebAssembly tests.
- 9 of the 10 exported WASM functions operate flawlessly in WebAssembly. Only `get_sample_packet` panics due to the unmigrated `SystemTime::now()` call in `aip-core::capability`.
- Pre-generated static fixture files in `aip-console/public/fixtures/` are valid and uncorrupted.

---

## 4. Conclusion

**Verdict: REJECT**

Milestone 1 is **REJECTED** pending resolution of the WebAssembly runtime panic in `get_sample_packet`.

### Required Remediation for Worker:
1. **Fix `aip-core` time calls**:
   Replace local `SystemTime::now()` calls in `aip-standalone/aip-core/src/capability.rs` (line 191), `delegation.rs` (line 362), and `revocation.rs` (line 278) with `aip_crypto::now_ms()`.
2. **Optimize `get_sample_packet` in `aip-standalone/aip-wasm/src/lib.rs`**:
   Rather than dynamically computing deterministic Ed25519 signatures and generating ZIP archives from scratch on every call in the browser, `get_sample_packet` should directly serve the static pre-generated JSON strings via `include_str!("../../../aip-console/public/fixtures/...")` (or use `aip_crypto::now_ms()`).
3. **Rebuild WebAssembly package**:
   Re-run `npx wasm-pack build aip-standalone/aip-wasm --target web --out-dir ../../aip-console/public/wasm --out-name aip_wasm --no-gitignore`.
4. **Verify fix**:
   Run `node aip-standalone/aip-wasm/tests/wasm_binary_empirical.mjs` and ensure all 5 sections exit cleanly with 0 errors.

---

## 5. Verification Method

To independently reproduce this finding and verify the test harness:

1. **Run the WebAssembly binary empirical test harness (Demonstrates the WASM defect)**:
   ```powershell
   node aip-standalone/aip-wasm/tests/wasm_binary_empirical.mjs
   ```
   *Outcome*: Shows 87/87 checks passed for bundle ZIP, React Flow DAG, and capability lattice meet, followed by:
   `❌ CONFIRMED CRITICAL DEFECT: get_sample_packet panicked in WebAssembly runtime! Error caught: RuntimeError: unreachable`

2. **Run native challenge integration test suite**:
   ```powershell
   cargo test --manifest-path aip-standalone/Cargo.toml -p aip-wasm --test challenge_tests
   ```
   *Outcome*: `test result: ok. 7 passed; 0 failed`.

3. **Run all `aip-wasm` native tests**:
   ```powershell
   cargo test --manifest-path aip-standalone/Cargo.toml -p aip-wasm
   ```
   *Outcome*: `test result: ok. 26 passed; 0 failed`.

4. **Invalidation condition**:
   The rejection is invalidated once `node aip-standalone/aip-wasm/tests/wasm_binary_empirical.mjs` runs with `get_sample_packet` returning genuine JSON packets in WASM without panicking.
