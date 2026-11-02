# Milestone 1 Quality & Adversarial Review Report

**Agent**: Milestone 1 Reviewer 1 (`teamwork_reviewer` / `critic`)  
**Milestone**: M1 — `aip-wasm` Core Engine & Fixtures Pipeline  
**Date**: 2026-11-02  
**Verdict**: **REQUEST_CHANGES**

---

## 1. Observation

### 1.1 Test & Build Execution Results
1. **WASM crate unit tests**:
   - Command: `cargo test --manifest-path aip-standalone/Cargo.toml -p aip-wasm`
   - Result: Exit code 0, 10 passed, 0 failed (0.38s).
2. **Protocol crate unit tests**:
   - Command: `cargo test --manifest-path aip-standalone/Cargo.toml -p aip-protocol`
   - Result: Exit code 0, 27 passed, 0 failed, 1 ignored (`emit_sample_bundle`) (0.17s).
3. **WASM compilation check**:
   - Command: `cargo check --target wasm32-unknown-unknown -p aip-wasm --manifest-path aip-standalone/Cargo.toml`
   - Result: Exit code 0, 0 errors, 0 warnings.
4. **End-to-End test suite**:
   - Command: `npm run test:e2e`
   - Result: Exit code 0, 52 test files passed, 260 tests passed, 0 failed (2.16s).

### 1.2 WebAssembly Runtime Execution Observation
Direct execution of the compiled WebAssembly package (`aip-console/public/wasm/aip_wasm_bg.wasm` via `aip-console/public/wasm/aip_wasm.js`) in Node.js revealed:

- Functions that execute cleanly without error:
  - `verify_evidence_packet(honestJson, contextJson)` -> `overall_valid: true`, `derived_trust_floor: "COUNTERPARTY_SIGNED"`, `checks: 14`
  - `recompute_packet_hash(honestJson)` -> `06e842d481e967b91d295b2da91ad927b263e0be2871306222ff121bd4f11a59`
  - `get_canonical_bytes_hex(honestJson)` -> 3532 hex characters
  - `verify_bundle_zip(zipBytes, contextJson)` -> `overall_pass: true`, 7 checks passed
  - `get_accountability_graph(honestJson, reportJson)` -> 7 nodes, 6 edges (with both `from`/`to` and `source`/`target`)
  - `check_scope_permits(metScope, "\"Write\"")` -> `true`
  - `meet_capability_scopes(parentJson, childJson)` -> valid intersection with `"is_bottom": false`
  - `extract_bundle_files(zipBytes)` -> extracts all 7 files from the audit zip
  - `generate_keypair()` -> returns valid Ed25519 keypair and `aip1...` AIP-ID

- **CRITICAL FAILURE in `get_sample_packet`**:
  Executing `get_sample_packet("honest_counterparty")` or any other parameter in WebAssembly triggers an unhandled WebAssembly trap:
  ```text
  panicked at /rustc/88d9e12ae178fab0fb5cc050a94da85685d449ea/library/std/src/sys/time/unsupported.rs:35:9:
  time not implemented on this platform

  Stack:
  Error
      at __wbg_new_bb74001155cb8ca8 (aip-console/public/wasm/aip_wasm.js:360:25)
      at Module.get_sample_packet (aip-console/public/wasm/aip_wasm.js:152:26)
  RuntimeError: unreachable
  ```

### 1.3 Code Inspection Findings
1. In `aip-standalone/aip-wasm/src/lib.rs` (lines 271-274):
   ```rust
   #[wasm_bindgen]
   pub fn get_sample_packet(sample_type: &str) -> Result<String, JsValue> {
       let fixtures = samples::generate_all_fixtures();
   ```
   `get_sample_packet` unconditionally calls `samples::generate_all_fixtures()` at runtime on every invocation.

2. In `aip-standalone/aip-wasm/src/samples.rs` (lines 97, 106, 125, 532):
   `generate_all_fixtures()` calls:
   - `aip_core::capability::issue_scoped_token`
   - `aip_core::delegation::create_delegation`
   - `aip_protocol::ActionAttestation::create`
   - `aip_protocol::bundle::build_zip`

3. In `aip-standalone/aip-core/src/capability.rs` (lines 191-196):
   ```rust
   fn now_ms() -> u64 {
       SystemTime::now()
           .duration_since(UNIX_EPOCH)
           .unwrap()
           .as_millis() as u64
   }
   ```
   Directly calls `std::time::SystemTime::now()`.

4. In `aip-standalone/aip-core/src/delegation.rs` (lines 362-367):
   ```rust
   fn now_ms() -> u64 {
       std::time::SystemTime::now()
           .duration_since(std::time::UNIX_EPOCH)
           .unwrap()
           .as_millis() as u64
   }
   ```
   Directly calls `std::time::SystemTime::now()`.

5. In `aip-standalone/aip-core/src/revocation.rs` (lines 278-283) and `aip-standalone/aip-core/src/nonce.rs` (lines 66-71):
   Both functions directly call `SystemTime::now()`.

6. In `aip-standalone/aip-protocol/src/evidence_packet.rs` (lines 467-472) and `aip-standalone/aip-protocol/src/bundle.rs` (lines 97-102):
   Both functions directly call `std::time::SystemTime::now()`.

7. In `aip-standalone/aip-crypto/src/lib.rs` (lines 126-143):
   `pub fn now_ms() -> u64` is already implemented with target-conditional compilation (`js_sys::Date::now() as u64` on `wasm32`, `SystemTime::now()` on native). However, the upstream crates (`aip-core` and parts of `aip-protocol`) were not updated to use it.

8. In `aip-console/public/fixtures/`:
   All 15 fixture files exist and have genuine cryptographic signatures and hashes:
   - 8 EvidencePackets (`honest_counterparty.json`, `authority_bound.json`, `agent_signed.json`, `tampered_summary.json`, `tampered_hash.json`, `tampered_signature.json`, `scope_escalation.json`, `revoked_token.json`)
   - 4 Context files (`honest_counterparty.context.json`, `authority_bound.context.json`, `agent_signed.context.json`, `revoked_token.context.json`)
   - 2 ZIP bundles (`audit_bundle_valid.zip`, `audit_bundle_tampered.zip`)
   - 1 Catalog index (`index.json`)

---

## 2. Logic Chain

1. **Step 1 (Root Cause of WASM Runtime Panic)**: On the `wasm32-unknown-unknown` target, standard Rust library time facilities (`std::time::SystemTime::now()`) panic at runtime with `time not implemented on this platform` because WebAssembly has no operating system clock without host environment bindings.
2. **Step 2 (Incomplete Time Patching)**: The worker patched `aip-crypto/src/lib.rs` and `aip-protocol/src/verification.rs`, but did not patch `aip-core/src/capability.rs`, `aip-core/src/delegation.rs`, `aip-core/src/revocation.rs`, `aip-core/src/nonce.rs`, `aip-protocol/src/evidence_packet.rs`, or `aip-protocol/src/bundle.rs`.
3. **Step 3 (Trigger Path)**: In `aip-wasm/src/lib.rs`, `get_sample_packet` calls `samples::generate_all_fixtures()`, which invokes token issuance, delegation hop creation, action attestation, and bundle creation. This immediately hits unpatched `SystemTime::now()` calls, causing an uncatchable WebAssembly trap in the browser/Node.js runtime.
4. **Step 4 (Design Inefficiency)**: Calling `generate_all_fixtures()` on every invocation of `get_sample_packet` re-generates all 10 cryptographic structures and re-compresses 2 ZIP archives on every button click in the UI. Because the 15 fixtures have already been generated into `aip-console/public/fixtures/`, embedding them via `include_str!` is instantaneous, uses zero crypto compute cycles, and completely avoids runtime generation overhead.
5. **Step 5 (Assessment of Other Exports)**: Independent stress testing confirmed that all 9 other WASM exports (`verify_evidence_packet`, `verify_bundle_zip`, `recompute_packet_hash`, `get_canonical_bytes_hex`, `get_accountability_graph`, `check_scope_permits`, `meet_capability_scopes`, `extract_bundle_files`, `generate_keypair`) are functional, memory safe, and conformant with interface contracts.

---

## 3. Caveats

- Native tests (`cargo test -p aip-wasm` and `cargo test -p aip-protocol`) pass because the host OS provides system time on native platforms.
- `cargo check --target wasm32-unknown-unknown` passed because `SystemTime::now()` exists in the standard library for wasm32, but traps only at runtime when executed.
- `npm run test:e2e` passed because `reference_oracle.js` was written in TypeScript/JS prior to WASM compilation.
- There are no integrity violations (no hardcoded test outputs, no facade implementations, no fake crypto signatures). The implementation logic and fixtures are genuine, but require the fix below to work in WebAssembly.

---

## 4. Conclusion & Required Actions

**Verdict**: **REQUEST_CHANGES**

### Required Changes for M1 Worker:

1. **Fix `now_ms()` across all workspace crates**:
   - In `aip-core/src/capability.rs:191-196`: replace `SystemTime::now()` with `aip_crypto::now_ms()`.
   - In `aip-core/src/delegation.rs:362-367`: replace `SystemTime::now()` with `aip_crypto::now_ms()`.
   - In `aip-core/src/revocation.rs:278-283`: replace `SystemTime::now()` with `aip_crypto::now_ms()`.
   - In `aip-core/src/nonce.rs:66-71`: replace `SystemTime::now()` with `aip_crypto::now_ms()`.
   - In `aip-protocol/src/evidence_packet.rs:467-472`: replace `SystemTime::now()` with `aip_crypto::now_ms()`.
   - In `aip-protocol/src/bundle.rs:97-102`: replace `SystemTime::now()` with `aip_crypto::now_ms()`.

2. **Optimize `get_sample_packet` in `aip-standalone/aip-wasm/src/lib.rs`**:
   - Replace the runtime invocation of `samples::generate_all_fixtures()` in `get_sample_packet` with direct inclusion of pre-generated fixture files via `include_str!("../../../aip-console/public/fixtures/...")` (or static strings in `samples.rs`). This eliminates runtime generation latency and memory pressure in the browser.

3. **Rebuild WebAssembly package and verify in Node**:
   - Recompile: `npx wasm-pack build aip-standalone/aip-wasm --target web --out-dir ../../aip-console/public/wasm --out-name aip_wasm --no-gitignore`
   - Run a Node.js verification script to ensure `get_sample_packet("honest_counterparty")` executes cleanly without trapping.

---

## 5. Verification Method

To independently verify the resolution of this finding:

1. **Test `get_sample_packet` in Node.js WebAssembly runtime**:
   ```powershell
   @'
   import fs from "node:fs";
   import path from "node:path";
   const wasmBytes = fs.readFileSync(path.resolve("aip-console/public/wasm/aip_wasm_bg.wasm"));
   const wasmModule = await import("./aip-console/public/wasm/aip_wasm.js");
   wasmModule.initSync({ module: wasmBytes });
   const honest = wasmModule.get_sample_packet("honest_counterparty");
   console.log("Success! Length:", honest.length);
   '@ | node --input-type=module
   ```
   *Expected outcome*: Exits code 0 and prints sample packet length without trapping.

2. **Run native test suites**:
   ```powershell
   cargo test --manifest-path aip-standalone/Cargo.toml -p aip-wasm
   cargo test --manifest-path aip-standalone/Cargo.toml -p aip-protocol
   ```
   *Expected outcome*: 10 passed in `aip-wasm`, 27 passed in `aip-protocol`.

3. **Run E2E test suite**:
   ```powershell
   npm run test:e2e
   ```
   *Expected outcome*: 260 passed (100%).
