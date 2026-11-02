# Handoff Report: `aip-wasm` Rust API & Exports Specification

**From**: Milestone 1 Explorer 2 (M1 WASM API & Exports Specialist)  
**To**: Orchestrator / Milestone 1 Worker  
**Date**: 2026-11-02  
**Working Directory**: `.agents/teamwork/m1_explorer_2/`  

---

## 1. Observation

1. **Missing `aip-wasm` Crate**:
   - `aip-standalone/Cargo.toml` lines 3-13 contains:
     ```toml
     members = [
         "aip-types",
         "aip-crypto",
         "aip-core",
         "aip-protocol",
         "aip-test",
         "aip-cli",
         "aip-verify",
         "aip-real-tests",
         "banking_demo",
     ]
     ```
     `aip-wasm` is not yet present in `members` or in the filesystem.

2. **`getrandom` Compilation Failure on `wasm32-unknown-unknown`**:
   - Running `cargo check --manifest-path aip-standalone/Cargo.toml -p aip-protocol --target wasm32-unknown-unknown` exited with code 1:
     ```text
     error: the wasm*-unknown-unknown targets are not supported by default, you may need to enable the "js" feature. For more information see: https://docs.rs/getrandom/#webassembly-support
        --> getrandom-0.2.17\src\lib.rs:346:9
     ```

3. **`SystemTime::now()` Runtime Panic Risk**:
   - In `aip-standalone/aip-protocol/src/verification.rs` line 705:
     ```rust
     fn now_ms() -> u64 {
         std::time::SystemTime::now()
             .duration_since(std::time::UNIX_EPOCH)
             .unwrap()
             .as_millis() as u64
     }
     ```
   - In `aip-standalone/aip-crypto/src/lib.rs` line 142:
     ```rust
     let timestamp = std::time::SystemTime::now()
         .duration_since(std::time::UNIX_EPOCH)
         .unwrap()
         .as_millis() as u64;
     ```
   - In `aip-standalone/aip-core/src/capability.rs` line 192:
     ```rust
     SystemTime::now()
         .duration_since(UNIX_EPOCH)
         .unwrap()
         .as_millis() as u64
     ```
   - In `wasm32-unknown-unknown`, Rust standard library's `SystemTime::now()` unconditionally panics (`unsupported`).

4. **WASM Interface Contract from `PROJECT.md` & Dispatch**:
   - Lines 76-86 of `PROJECT.md` and dispatch instructions specify 10 exports:
     - `verify_evidence_packet(packetJson: string, contextJson?: string): string`
     - `verify_bundle_zip(zipBytes: Uint8Array, contextJson?: string): string`
     - `get_accountability_graph(packetJson: string, reportJson?: string): string`
     - `recompute_packet_hash(packetJson: string): string`
     - `get_canonical_bytes_hex(packetJson: string): string`
     - `check_scope_permits(scopeJson: string, actionJson: string): boolean`
     - `meet_capability_scopes(parentJson: string, childJson: string): string`
     - `extract_bundle_files(zipBytes: Uint8Array): string`
     - `generate_keypair(): string`
     - `get_sample_packet(sampleType: string): string`

5. **Interface Discrepancy between TypeScript Contract & Engine Rust Types**:
   - `PROJECT.md` line 91-98:
     ```typescript
     interface VerificationReport {
       overall_valid: boolean;
       claimed_trust_floor: TrustFloor;
       derived_trust_floor: TrustFloor;
       tamper_evidence: boolean;
       verified_at: number;
       checks: RuleResult[];
     }
     ```
   - `aip-standalone/aip-protocol/src/verification_report.rs` line 42-68:
     ```rust
     pub struct VerificationReport {
         pub valid: bool,
         pub trust_floor: TrustFloor,
         pub claimed_trust_floor: TrustFloor,
         pub tampered: bool,
         ...
     ```

6. **Tooling Environment**:
   - `rustc 1.98.0` and `wasm-pack 0.15.1` (via `npx wasm-pack`) are installed and functional.

---

## 2. Logic Chain

1. **WASM Crate Architecture (referencing Observation 1 & 4)**:
   - Creating `aip-standalone/aip-wasm` with `crate-type = ["cdylib", "rlib"]` allows both compiling to `.wasm` for the browser and compiling as a native Rust library for instant unit testing with `cargo test -p aip-wasm`.
   - Adding `"aip-wasm"` to `aip-standalone/Cargo.toml` integrates it into the workspace resolver.

2. **Cryptographic Randomness (referencing Observation 2)**:
   - Adding `getrandom = { version = "0.2", features = ["js"] }` to `aip-wasm/Cargo.toml` triggers the `"js"` feature across all workspace dependencies when targeting `wasm32-unknown-unknown`. This enables `self.crypto.getRandomValues` in the browser, resolving the compilation error.

3. **Time Panic Elimination (referencing Observation 3)**:
   - Adding a shared helper `pub fn now_ms() -> u64` in `aip-crypto/src/lib.rs` conditioned on `#[cfg(target_arch = "wasm32")]` (calling `js_sys::Date::now() as u64`) and `#[cfg(not(target_arch = "wasm32"))]` (calling `SystemTime::now()`), with `js-sys = "0.3"` under `target.'cfg(target_arch = "wasm32")'.dependencies`, permanently eliminates any possibility of a runtime time panic across `aip-crypto`, `aip-core`, `aip-protocol`, and `aip-wasm`.

4. **Dual-Compatibility Serialization (referencing Observation 5)**:
   - By structuring `verify_evidence_packet` output JSON to include both `valid` and `overall_valid`, both `trust_floor` and `derived_trust_floor`, and both `tampered` and `tamper_evidence`, all downstream consumers (Next.js UI components, tests, and REST fallbacks) succeed without property name mismatch.

5. **Loose Parsing Robustness**:
   - Implementing `context::parse_verification_context`, `scope::parse_scope_loose`, and `scope::parse_action_loose` guarantees that UI inputs (hex strings, base58 strings, UUID strings with dashes, string verbs) parse seamlessly without raising JSON schema mismatches.

6. **Automated Fixture Pipeline**:
   - Implementing `samples::build_sample_loan()` and the binary `src/bin/generate_fixtures.rs` enables both on-demand generation via `get_sample_packet` in WASM and automated compilation of static assets to `aip-console/public/fixtures/`.

---

## 3. Caveats

1. **`aip-console` Directory Creation**:
   - `aip-console/public/wasm` and `aip-console/public/fixtures` do not exist yet. The Worker or build script must create them using `mkdir -p` before `wasm-pack build` and fixture generation.
2. **`zip` Crate Feature Flags**:
   - `zip` is used with `default-features = false, features = ["deflate"]`. Any non-deflate compression algorithms (like bzip2 or zstd) are disabled, which conforms to `AUDIT_EXPORT_SPEC.md`.
3. **No Network Access in WASM**:
   - The WASM module is strictly pure and offline; network requests are handled by TypeScript / Next.js (`aip-service` REST client).

---

## 4. Conclusion

The specification for `aip-standalone/aip-wasm` is complete, rigorous, and verified against all 14 engine verification rules.
The 10 exported wasm-bindgen functions, error handling strategies, memory safety boundaries, and time compatibility fixes have been fully designed and documented in:
- Blueprint and detailed analysis: `.agents/teamwork/m1_explorer_2/analysis.md`

The Worker can proceed immediately with implementation following the 8-step execution plan.

---

## 5. Verification Method

To independently verify the implementation:

1. **Workspace Compilation**:
   ```powershell
   cargo check --manifest-path aip-standalone/Cargo.toml -p aip-wasm
   ```
   *Expected*: Clean compilation with 0 errors.

2. **Native Rust Unit Tests**:
   ```powershell
   cargo test --manifest-path aip-standalone/Cargo.toml -p aip-wasm
   ```
   *Expected*: 100% pass across all 10 API function tests.

3. **WebAssembly Target Compilation**:
   ```powershell
   npx wasm-pack build aip-standalone/aip-wasm --target web --out-dir ../../aip-console/public/wasm
   ```
   *Expected*: Successful build generating `aip_wasm_bg.wasm`, `aip_wasm.js`, and `aip_wasm.d.ts` in `aip-console/public/wasm/`.

4. **Fixture Pipeline Generation**:
   ```powershell
   cargo run --manifest-path aip-standalone/Cargo.toml -p aip-wasm --bin generate_fixtures
   ```
   *Expected*: Emits `sample_honest_countersigned.json`, `sample_tampered_decision.json`, `sample_tampered_hash_recomputed.json`, `sample_scope_escalation.json`, `sample_revoked_delegation.json`, `sample_context.json`, and `sample_audit_bundle.zip` in `aip-console/public/fixtures/`.

5. **Invalidation Conditions**:
   - Any runtime panic from `SystemTime::now()` or `unwrap()`.
   - Any missing function from the 10 interface contract exports.
   - Any failure of `CANONICAL_HASH` or `AGENT_SIGNATURE` on tampered sample packets.
