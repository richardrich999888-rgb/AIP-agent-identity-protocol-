# Milestone 1 Review & Adversarial Evaluation Report

**Reviewer**: Milestone 1 Reviewer 2 (`teamwork_reviewer` / critic)  
**Milestone**: M1 — `aip-wasm` Core Engine & Fixtures Pipeline  
**Date**: 2026-11-02  
**Verdict**: **REQUEST_CHANGES**

---

## 1. Observation

### 1.1 Test & Build Execution Results
1. `cargo test --manifest-path aip-standalone/Cargo.toml -p aip-wasm`
   - Command result: Exit code 0.
   - Verbatim output:
     ```text
     running 10 tests
     test tests::test_scope_permits_and_meet ... ok
     test tests::test_keypair_generation ... ok
     test tests::test_hash_and_canonical_bytes ... ok
     test tests::test_extract_bundle_files ... ok
     test tests::test_verify_evidence_packet_tampered_summary ... ok
     test tests::test_accountability_graph ... ok
     test tests::test_verify_evidence_packet_honest ... ok
     test tests::test_verify_bundle_zip ... ok
     test tests::test_get_sample_packet ... ok
     test tests::test_self_verify_fixtures_all ... ok

     test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.39s
     ```

2. `cargo test --manifest-path aip-standalone/Cargo.toml -p aip-protocol`
   - Command result: Exit code 0.
   - Verbatim output:
     ```text
     running 4 tests (lib) ... 4 passed
     running 7 tests (bundle) ... 6 passed; 1 ignored
     running 17 tests (evidence_packet) ... 17 passed
     test result: ok. 27 passed; 0 failed; 1 ignored
     ```

3. `npm run test:e2e`
   - Command result: Exit code 0.
   - Verbatim output:
     ```text
     Test Files  52 passed (52)
          Tests  260 passed (260)
       Start at  14:51:06
       Duration  2.16s
     ```

### 1.2 WebAssembly Runtime Execution & Critical Crash Observation
When the compiled WebAssembly package (`aip-console/public/wasm/aip_wasm_bg.wasm` + `aip_wasm.js`) was loaded in an actual JavaScript runtime (Node.js v24.17.0 via `initSync`), the following behavior was observed:

```javascript
import fs from 'node:fs';
import { initSync, get_sample_packet } from './aip-console/public/wasm/aip_wasm.js';

const wasmBytes = fs.readFileSync('./aip-console/public/wasm/aip_wasm_bg.wasm');
initSync(wasmBytes);
get_sample_packet('honest_counterparty');
```

- **Verbatim Runtime Failure**:
  ```text
  panicked at /rustc/88d9e12ae178fab0fb5cc050a94da85685d449ea/library/std/src/sys/time/unsupported.rs:35:9:
  time not implemented on this platform

  Stack:
  Error
      at __wbg_new_bb74001155cb8ca8 (file:///C:/Users/shrey/Desktop/Internship/Sniffer%20Dog/AIP-agent-identity-protocol-/aip-console/public/wasm/aip_wasm.js:360:25)
      at wasm://wasm/0040aa8a:wasm-function[1025]:0xddc5f
      at wasm://wasm/0040aa8a:wasm-function[513]:0x9aa96
      at wasm://wasm/0040aa8a:wasm-function[787]:0xa9158
      at wasm://wasm/0040aa8a:wasm-function[954]:0xdd243
      at wasm://wasm/0040aa8a:wasm-function[166]:0x5b817
      at wasm://wasm/0040aa8a:wasm-function[835]:0xc0427
      at get_sample_packet (file:///C:/Users/shrey/Desktop/Internship/Sniffer%20Dog/AIP-agent-identity-protocol-/aip-console/public/wasm/aip_wasm.js:152:26)
  RuntimeError: unreachable
  ```

### 1.3 Codebase Inspections
- In `aip-standalone/aip-wasm/src/lib.rs` (line 273):
  `get_sample_packet` invokes `samples::generate_all_fixtures()`.
- In `aip-standalone/aip-wasm/src/samples.rs`:
  - Line 97, 208, 301: calls `issue_scoped_token`
  - Line 106, 216: calls `create_delegation`
  - Line 532: calls `build_zip`
- In `aip-standalone/aip-protocol/src/bundle.rs` (lines 97-102):
  ```rust
  fn now_ms() -> u64 {
      std::time::SystemTime::now()
          .duration_since(std::time::UNIX_EPOCH)
          .unwrap()
          .as_millis() as u64
  }
  ```
- In `aip-standalone/aip-core/src/capability.rs` (lines 191-196):
  ```rust
  fn now_ms() -> u64 {
      SystemTime::now()
          .duration_since(UNIX_EPOCH)
          .unwrap()
          .as_millis() as u64
  }
  ```
- In `aip-standalone/aip-core/src/delegation.rs` (lines 362-367):
  ```rust
  fn now_ms() -> u64 {
      std::time::SystemTime::now()
          .duration_since(std::time::UNIX_EPOCH)
          .unwrap()
          .as_millis() as u64
  }
  ```
  On `wasm32-unknown-unknown`, `std::time::SystemTime::now()` is not implemented in the standard library and panics unconditionally.

### 1.4 Fixture Catalog Discrepancy in `index.json`
Direct execution of `verify_evidence_packet` against `revoked_token.json` with `revoked_token.context.json`:
- `aip-console/public/fixtures/index.json` lines 109-123:
  ```json
  "id": "revoked_token",
  "expected_derived_floor": "UNVERIFIED"
  ```
- Actual engine output via WASM `verify_evidence_packet`:
  ```json
  "claimed_trust_floor": "COUNTERPARTY_SIGNED",
  "derived_trust_floor": "AGENT_SIGNED",
  "overall_valid": false,
  "tamper_evidence": false
  ```
  Rule 14 (`TRUST_FLOOR`) logs: `claimed floor CounterpartySigned exceeds what the evidence supports (AgentSigned)`.
  The engine derived floor is `AGENT_SIGNED` (because structure, agent id, canonical hash, and agent signature are valid; only the delegation token revocation fails, which drops the packet to `AgentSigned`). `index.json` erroneously specifies `"expected_derived_floor": "UNVERIFIED"`.

### 1.5 Contract & Integrity Check
- **Integrity Check**:
  - No hardcoded test outputs or facades detected in `aip-wasm/src/lib.rs`.
  - Cryptographic verification executes real 14-rule verification via `aip_protocol::verify_packet`.
  - Bundle ZIP verification executes real manifest, checksum, and signature checks via `aip_protocol::bundle::verify_zip`.
  - Dual-key compatibility keys are correctly emitted:
    - `overall_valid` & `valid` (both boolean)
    - `derived_trust_floor` & `trust_floor` (both string)
    - `tamper_evidence` & `tampered` (both boolean)
  - AccountabilityGraph edges correctly emit both `from`/`to` and `source`/`target`.
  - `check_scope_permits` and `meet_capability_scopes` correctly handle lattice operations and bottom ($\bot$).
  - `extract_bundle_files` extracts all 7 files in-memory without filesystem writes (preventing Zip-Slip).

---

## 2. Logic Chain

1. **Step 1 (False Negative in Tests)**:
   - `cargo test -p aip-wasm` compiles to native x86_64 Windows (`target\debug\deps\aip_wasm-*.exe`). On Windows native targets, `std::time::SystemTime::now()` functions without error, so `test_get_sample_packet` passes natively.
   - `npm run test:e2e` executes against `e2e/support/reference_oracle.ts`, which is a pure TypeScript reference oracle, never invoking the WebAssembly binary directly.
   - Consequently, neither the Rust native tests nor the E2E test suite ever executed `get_sample_packet` inside a WebAssembly runtime.
2. **Step 2 (Root Cause of WASM Panic)**:
   - When compiled to `wasm32-unknown-unknown`, `std::time::SystemTime::now()` calls `unsupported.rs` line 35 in the Rust standard library, which immediately panics with `time not implemented on this platform`.
   - The M1 Worker attempted to fix this in `aip-crypto/src/lib.rs` and `aip-protocol/src/verification.rs`, but left unpatched `SystemTime::now()` calls in `aip-core/src/capability.rs` (line 192), `aip-core/src/delegation.rs` (line 363), and `aip-protocol/src/bundle.rs` (line 98).
   - In `aip-wasm/src/lib.rs`, `get_sample_packet` calls `samples::generate_all_fixtures()`, which invokes `issue_scoped_token`, `create_delegation`, and `build_zip` at runtime.
   - Every invocation of `get_sample_packet` in the browser or Node.js crashes the WASM runtime with an unrecoverable `RuntimeError: unreachable` trap.
3. **Step 3 (Fixture Catalog Inconsistency)**:
   - In `samples.rs` line 518 and `index.json` line 113, `expected_derived_floor` was hardcoded as `"UNVERIFIED"`.
   - However, in `aip-protocol/src/verification.rs` (lines 266-285), when a delegation token is revoked, `revocation_ok` is false (failing `AuthorityBound` and `CounterpartySigned`), but `agent_signed` remains true (structure, id, hash, and agent signature are valid).
   - The engine correctly derives `AGENT_SIGNED`. The fixture catalog metadata in `index.json` contradicts the engine's mathematical derivation.
4. **Step 4 (Conclusion Formulation)**:
   - A core exported WebAssembly function crashes at runtime on the target architecture (`wasm32-unknown-unknown`).
   - A fixture catalog entry has contradictory metadata.
   - Therefore, the milestone cannot be approved in its current state.

---

## 3. Findings

### [Critical] Finding 1: `get_sample_packet` Panics in WebAssembly (`wasm32-unknown-unknown`)
- **What**: Invoking `get_sample_packet` crashes with `time not implemented on this platform` and fatal `RuntimeError: unreachable`.
- **Where**:
  - `aip-standalone/aip-wasm/src/lib.rs`: line 273 (`get_sample_packet`)
  - `aip-standalone/aip-protocol/src/bundle.rs`: lines 97-102 (`now_ms()`)
  - `aip-standalone/aip-core/src/capability.rs`: lines 191-196 (`now_ms()`)
  - `aip-standalone/aip-core/src/delegation.rs`: lines 362-367 (`now_ms()`)
- **Why**: `get_sample_packet` regenerates all fixtures and builds ZIP archives dynamically at runtime on every call, triggering unpatched `SystemTime::now()` calls in `aip-core` and `aip-protocol`.
- **Suggestion**:
  1. In `aip-wasm/src/lib.rs`, embed the pre-generated static fixture JSON strings directly using `include_str!` (e.g. `include_str!("../../../aip-console/public/fixtures/honest_counterparty.json")`), making `get_sample_packet` instantaneous, zero-alloc, and free of runtime cryptographic/time dependencies.
  2. Replace `SystemTime::now()` in `aip-protocol/src/bundle.rs`, `aip-core/src/capability.rs`, and `aip-core/src/delegation.rs` with `aip_crypto::now_ms()`.
  3. Rebuild the WASM package via `wasm-pack`.

### [Major] Finding 2: `revoked_token` Derived Floor Discrepancy in `index.json`
- **What**: `index.json` lists `expected_derived_floor: "UNVERIFIED"`, but the engine derives `"AGENT_SIGNED"`.
- **Where**: `aip-console/public/fixtures/index.json`: line 113; `aip-standalone/aip-wasm/src/samples.rs`: line 518.
- **Why**: When a validly signed packet has a revoked delegation hop, it fails `AUTHORITY_BOUND` and `COUNTERPARTY_SIGNED`, but fulfills all conditions for `AGENT_SIGNED`. The engine derivation is correct, but the metadata and fixture record claim `UNVERIFIED`.
- **Suggestion**: Update `samples.rs` (line 518) and `index.json` to specify `expected_derived_floor: "AGENT_SIGNED"` and regenerate the fixtures.

### [Minor] Finding 3: In-Memory ZIP Extraction Lacks Size Bounds (Zip-Bomb Hardening)
- **What**: `extract_bundle_files` reads ZIP entries into memory with `read_to_end` without an upper bound.
- **Where**: `aip-standalone/aip-wasm/src/lib.rs`: line 237.
- **Why**: Maliciously crafted ZIP files with excessive compression ratio could exhaust WebAssembly linear memory.
- **Suggestion**: Introduce a maximum extracted entry size check (e.g., limit each file to 10MB or total to 50MB) and return a clean `JsValue` error if exceeded.

---

## 4. Caveats

- All other 9 exported WASM functions (`verify_evidence_packet`, `verify_bundle_zip`, `get_accountability_graph`, `recompute_packet_hash`, `get_canonical_bytes_hex`, `check_scope_permits`, `meet_capability_scopes`, `extract_bundle_files`, `generate_keypair`) were executed directly in Node.js and verified to function correctly in WebAssembly.
- The dual-key compatibility contract (`overall_valid` & `valid`, `derived_trust_floor` & `trust_floor`, `tamper_evidence` & `tampered`) is fully implemented and verified.
- The cryptographic implementation in `aip-protocol` and `aip-wasm` is genuine, with zero hardcoding or facading.

---

## 5. Conclusion

**Verdict: REQUEST_CHANGES**

Milestone 1 is well-architected and 90% solid, but cannot be approved until Finding 1 (`get_sample_packet` WASM runtime panic) and Finding 2 (`revoked_token` floor metadata mismatch) are resolved.

---

## 6. Verification Method

To independently verify the failure and the subsequent fix:

1. **Reproduce the WebAssembly runtime panic**:
   ```powershell
   node -e "
   import fs from 'node:fs';
   import { initSync, get_sample_packet } from './aip-console/public/wasm/aip_wasm.js';
   const wasmBytes = fs.readFileSync('./aip-console/public/wasm/aip_wasm_bg.wasm');
   initSync(wasmBytes);
   console.log(get_sample_packet('honest_counterparty'));
   "
   ```
   *Current result*: Panics with `time not implemented on this platform` and `RuntimeError: unreachable`.  
   *Invalidation condition*: Returns the valid JSON string of the honest counterparty packet.

2. **Verify all 10 fixtures in WebAssembly**:
   ```powershell
   node -e "
   import fs from 'node:fs';
   import { initSync, verify_evidence_packet, verify_bundle_zip } from './aip-console/public/wasm/aip_wasm.js';
   const wasmBytes = fs.readFileSync('./aip-console/public/wasm/aip_wasm_bg.wasm');
   initSync(wasmBytes);
   const index = JSON.parse(fs.readFileSync('./aip-console/public/fixtures/index.json', 'utf8'));
   for (const fix of index.fixtures) {
     if (fix.format === 'zip') {
       const res = JSON.parse(verify_bundle_zip(fs.readFileSync('./aip-console/public/fixtures/' + fix.filename), null));
       console.log(fix.id, res.overall_pass === fix.expected_valid ? 'PASS' : 'FAIL');
     } else {
       const pkt = fs.readFileSync('./aip-console/public/fixtures/' + fix.filename, 'utf8');
       const ctx = fix.context_filename ? fs.readFileSync('./aip-console/public/fixtures/' + fix.context_filename, 'utf8') : null;
       const res = JSON.parse(verify_evidence_packet(pkt, ctx));
       console.log(fix.id, (res.overall_valid === fix.expected_valid && res.derived_trust_floor === fix.expected_derived_floor) ? 'PASS' : 'FAIL');
     }
   }
   "
   ```
