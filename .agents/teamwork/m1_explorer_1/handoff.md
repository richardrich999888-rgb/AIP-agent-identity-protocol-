# Handoff Report: `aip-wasm` Crate Configuration & WASM Build Strategy

**Agent**: Milestone 1 Explorer 1 (M1 Crate & WASM Build Specialist)  
**Milestone**: Milestone 1 (`aip-wasm` Core Engine & Fixtures Pipeline)  
**Recipient**: Orchestrator (Conversation ID: `675111aa-04e8-493f-9811-dbfc1935a77b`) and Milestone 1 Worker(s)  
**Status**: Task Complete (Hard Handoff)

---

## 1. Observation

1. **Toolchain Environment**:
   - Command `rustc --version; cargo --version; rustup target list --installed; npx wasm-pack --version`:
     ```text
     rustc 1.98.0 (88d9e12ae 2026-08-18)
     cargo 1.98.0 (797e8a9bc 2026-08-05)
     wasm32-unknown-unknown
     x86_64-pc-windows-gnu
     wasm-pack 0.15.1
     ```
2. **`getrandom` Compilation Failure on `wasm32-unknown-unknown`**:
   - Command `cargo check --target wasm32-unknown-unknown -p aip-crypto --manifest-path aip-standalone/Cargo.toml`:
     ```text
     error: the wasm*-unknown-unknown targets are not supported by default, you may need to enable the "js" feature. For more information see: https://docs.rs/getrandom/#webassembly-support
        --> C:\Users\shrey\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f\getrandom-0.2.17\src\lib.rs:346:9
         |
     346 | /         compile_error!("the wasm*-unknown-unknown targets are not supported by \
     347 | |                         default, you may need to enable the \"js\" feature. \
     ```
   - In `aip-standalone/Cargo.lock`: `rand_core` 0.6.4 (depended on by `rand 0.8` and `ed25519-dalek 2.1`) depends on `getrandom 0.2.17`.
3. **`SystemTime::now()` Invocations in `aip-protocol`**:
   - `aip-standalone/aip-protocol/src/verification.rs`:
     - Line 319: `verified_at: now_ms(),`
     - Line 704-709:
       ```rust
       fn now_ms() -> u64 {
           std::time::SystemTime::now()
               .duration_since(std::time::UNIX_EPOCH)
               .unwrap()
               .as_millis() as u64
       }
       ```
   - `aip-standalone/aip-protocol/src/bundle.rs`:
     - Line 97-102: identical `fn now_ms()` called at line 151 (`exported_at: now_ms(),`).
   - `aip-standalone/aip-protocol/src/evidence_packet.rs`:
     - Line 467-472: identical `fn now_ms()` called at line 439 (`let created_at = self.created_at.unwrap_or_else(now_ms);`).
   - Verification of `check_temporal_validity` in `verification.rs` (lines 471-521): All rule temporal checks compare packet timestamps (`decided_at`, `issued_at`, `expires_at`, `performed_at`) relative to each other; none invoke the current system wall clock.
4. **Current Workspace Registration**:
   - `aip-standalone/Cargo.toml` lines 1-13:
     ```toml
     [workspace]
     resolver = "2"
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
   - `"aip-wasm"` is not yet listed. Directory `aip-standalone/aip-wasm` does not exist yet.
5. **Specification & Contract DTO Keys**:
   - `PROJECT.md` lines 90-98 and `e2e/support/types.ts` lines 30-37 define `VerificationReport` with:
     ```typescript
     overall_valid: boolean;
     claimed_trust_floor: TrustFloor;
     derived_trust_floor: TrustFloor;
     tamper_evidence: boolean;
     verified_at: number;
     checks: RuleResult[];
     ```
   - `aip-standalone/aip-protocol/src/verification_report.rs` lines 42-68 define fields:
     `valid: bool`, `trust_floor: TrustFloor`, `claimed_trust_floor: TrustFloor`, `tampered: bool`.
6. **WASM-Pack Build Flags**:
   - Command `npx wasm-pack build --help` confirms flags:
     - `--target web`: generates ES module loader and wasm binary.
     - `--out-dir <OUT_DIR>`: relative to crate directory or absolute path.
     - `--out-name <OUT_NAME>`: sets base filename.
     - `--no-gitignore`: skips `.gitignore` generation containing `*` in the output directory.
     - `--no-opt`: skips `wasm-opt` binary execution if Binaryen is missing.

---

## 2. Logic Chain

1. **Resolving `getrandom` compilation error (Observation 1 & 2)**:
   - Observation 2 demonstrates that `cargo check --target wasm32-unknown-unknown` fails because `getrandom 0.2.17` requires the `"js"` feature on wasm targets.
   - In Cargo workspaces, feature unification activates features declared by any root package.
   - Therefore, specifying `getrandom = { version = "0.2", features = ["js"] }` in `aip-wasm/Cargo.toml` satisfies the requirement for `aip-crypto`, `ed25519-dalek`, and `rand`, resolving the compile error without breaking native builds.
2. **Eliminating the `SystemTime::now()` Runtime Panic (Observation 3)**:
   - On `wasm32-unknown-unknown`, Rust standard library `SystemTime::now()` panics at runtime with `unsupported`.
   - Observation 3 shows that `SystemTime::now()` is executed in `verification.rs` line 319 solely to populate `verified_at: now_ms()`. Temporal rule validation does not use `SystemTime`.
   - Adding `[target.'cfg(target_arch = "wasm32")'.dependencies] js-sys = "0.3"` to `aip-protocol/Cargo.toml` and gating `now_ms()` with `#[cfg(target_arch = "wasm32")] js_sys::Date::now() as u64` and `#[cfg(not(target_arch = "wasm32"))] SystemTime::now()` ensures:
     a) 100% native compatibility and zero overhead during native unit tests.
     b) Panic-free, millisecond-accurate timestamp reporting in browser WebAssembly.
3. **Ensuring Seamless Next.js 15 Integration (Observations 1 & 6)**:
   - Building with `--target web` into `aip-console/public/wasm/` places the compiled assets where Next.js serves them statically (`/wasm/aip_wasm_bg.wasm`).
   - Loading the WebAssembly module via `fetch('/wasm/aip_wasm_bg.wasm')` inside a client-side singleton avoids Turbopack/Webpack compilation hooks that frequently fail on WebAssembly bundles.
   - Adding `--no-gitignore` prevents wasm-pack from hiding the compiled assets from version control.
4. **Guaranteeing 100% Consumer Compatibility (Observation 5)**:
   - Due to the discrepancy between `e2e/support/types.ts` (`overall_valid`, `derived_trust_floor`, `tamper_evidence`) and `aip-protocol` (`valid`, `trust_floor`, `tampered`), `aip-wasm`'s JSON serializer will emit both sets of keys.
   - This ensures both E2E test suites and internal protocol consumers deserialize the verification report without field-missing errors.

---

## 3. Caveats

1. **`wasm-opt` Availability on Windows**: If Binaryen (`wasm-opt`) is not present in PATH and wasm-pack cannot download it, the worker must pass `--no-opt` to prevent a build abort. The resulting WASM binary is slightly larger (~10-15%) but operates with identical correctness.
2. **Browser Environment for WASM**: The compiled WASM module requires browser Web Crypto (`crypto.getRandomValues`) and standard ES6 module support. If executed in Node.js for tests, global polyfills (`globalThis.crypto`) or Node 19+ is required.

---

## 4. Conclusion

1. `aip-wasm` should be created as a `cdylib`/`rlib` crate in `aip-standalone/aip-wasm/` and added to `aip-standalone/Cargo.toml`.
2. `aip-standalone/aip-wasm/Cargo.toml` must depend on:
   - `aip-protocol`, `aip-types`, `aip-crypto`, `aip-core`
   - `wasm-bindgen = "0.2"`
   - `serde-wasm-bindgen = "0.6"`
   - `getrandom = { version = "0.2", features = ["js"] }`
   - `js-sys = "0.3"`
   - `console_error_panic_hook = "0.1"`
3. `aip-standalone/aip-protocol` must be updated with:
   - `[target.'cfg(target_arch = "wasm32")'.dependencies] js-sys = "0.3"`
   - Target-conditional `now_ms()` (`js_sys::Date::now() as u64` for wasm32).
4. The exact build command is:
   ```bash
   npx wasm-pack build aip-standalone/aip-wasm --target web --out-dir ../../aip-console/public/wasm --out-name aip_wasm --no-gitignore
   ```
5. All 10 interface exports from `PROJECT.md` must be implemented in `aip-standalone/aip-wasm/src/lib.rs` with dual-field mapping for JSON reports.

---

## 5. Verification Method

To independently verify the implementation:
1. **Native Protocol Tests**:
   ```bash
   cargo test -p aip-protocol --manifest-path aip-standalone/Cargo.toml
   # Invalidation condition: any of the 27 tests fails.
   ```
2. **WASM Compilation Check**:
   ```bash
   cargo check --target wasm32-unknown-unknown -p aip-wasm --manifest-path aip-standalone/Cargo.toml
   # Invalidation condition: getrandom compile error or unresolved symbol.
   ```
3. **WASM Build Command**:
   ```bash
   npx wasm-pack build aip-standalone/aip-wasm --target web --out-dir ../../aip-console/public/wasm --out-name aip_wasm --no-gitignore
   # Invalidation condition: build fails or files missing in aip-console/public/wasm/.
   ```
4. **File Inspection**:
   Inspect that the following files exist and have non-zero size:
   - `aip-console/public/wasm/aip_wasm.js`
   - `aip-console/public/wasm/aip_wasm_bg.wasm`
   - `aip-console/public/wasm/aip_wasm.d.ts`
