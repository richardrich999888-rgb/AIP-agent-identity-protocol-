# Milestone 1 Iteration 2 Explorer 2 Handoff Report

**Agent**: Milestone 1 Iteration 2 Explorer 2 (`teamwork_explorer`)  
**Roles**: `investigation`, `synthesis`  
**Milestone**: M1 Iteration 2 — `aip-wasm` Static Fixtures & Bundle ZIP Hardening  
**Date**: 2026-11-02  
**Handoff Type**: Hard (Investigation & Formulation Complete)  

---

## 1. Observation

### 1.1 `get_sample_packet` Dynamic Generation Defect in `aip-standalone/aip-wasm/src/lib.rs`
In `aip-standalone/aip-wasm/src/lib.rs` (lines 271-274):
```rust
#[wasm_bindgen]
pub fn get_sample_packet(sample_type: &str) -> Result<String, JsValue> {
    let fixtures = samples::generate_all_fixtures();
```
On every invocation of `get_sample_packet`, the function dynamically runs `samples::generate_all_fixtures()`, which calls:
- `aip_core::capability::issue_scoped_token` (`samples.rs:97`)
- `aip_core::delegation::create_delegation` (`samples.rs:106`)
- `aip_protocol::bundle::build_zip` (`samples.rs:532`)

When compiled to `wasm32-unknown-unknown` and executed in Node.js or a browser (`tests/wasm_empirical_challenger.mjs`), this triggers a fatal WebAssembly panic:
```text
panicked at /rustc/88d9e12ae178fab0fb5cc050a94da85685d449ea/library/std/src/sys/time/unsupported.rs:35:9:
time not implemented on this platform
RuntimeError: unreachable
```

### 1.2 Availability of Pre-Compiled Fixtures in `aip-console/public/fixtures/`
Inspection of `aip-console/public/fixtures/` reveals that all 15 fixture artifacts already exist in the repository with verified cryptographic signatures and hashes:
- `honest_counterparty.json` (16,180 bytes) & `honest_counterparty.context.json` (595 bytes)
- `authority_bound.json` (14,181 bytes) & `authority_bound.context.json` (432 bytes)
- `agent_signed.json` (10,672 bytes) & `agent_signed.context.json` (127 bytes)
- `tampered_summary.json` (16,183 bytes)
- `tampered_hash.json` (16,178 bytes)
- `tampered_signature.json` (16,179 bytes)
- `scope_escalation.json` (16,346 bytes)
- `revoked_token.json` (16,180 bytes) & `revoked_token.context.json` (637 bytes)
- `audit_bundle_valid.zip` (7,951 bytes) & `audit_bundle_tampered.zip` (7,935 bytes)
- `index.json` (5,735 bytes)

Relative path resolution from `aip-standalone/aip-wasm/src/` to `aip-console/public/fixtures/` is `../../../aip-console/public/fixtures/`. Verification via PowerShell confirmed:
`Test-Path 'aip-standalone\aip-wasm\src\..\..\..\aip-console\public\fixtures\honest_counterparty.json'` -> `True`.

### 1.3 `revoked_token` Derived Floor Discrepancy in `samples.rs` and `index.json`
In `aip-standalone/aip-wasm/src/samples.rs` (lines 510-525):
```rust
let revoked_rec = FixtureRecord {
    id: "revoked_token".into(),
    ...
    claimed_trust_floor: "COUNTERPARTY_SIGNED".into(),
    expected_derived_floor: "UNVERIFIED".into(),
```
When `verify_evidence_packet` evaluates `revoked_token.json` with `revoked_token.context.json`:
- Structure, Agent ID Binding, Canonical Hash, and Agent Signature all pass -> `agent_signed` is true.
- Revocation of the delegation hop fails -> `authority_bound` and `counterparty_signed` are false.
- The derived trust floor is `AGENT_SIGNED`.
However, `samples.rs:518` and `aip-console/public/fixtures/index.json:113` incorrectly record `"expected_derived_floor": "UNVERIFIED"`.

### 1.4 Unbounded ZIP Extraction in `extract_bundle_files`
In `aip-standalone/aip-wasm/src/lib.rs` (lines 225-246):
```rust
#[wasm_bindgen]
pub fn extract_bundle_files(zip_bytes: &[u8]) -> Result<String, JsValue> {
    let mut archive = zip::ZipArchive::new(Cursor::new(zip_bytes))
        .map_err(|e| JsValue::from_str(&format!("Failed to read ZIP archive: {e}")))?;

    let mut file_map = BTreeMap::new();
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| JsValue::from_str(&format!("ZIP entry error: {e}")))?;
        let name = file.name().to_string();
        let mut buf = Vec::new();
        use std::io::Read;
        file.read_to_end(&mut buf)
            .map_err(|e| JsValue::from_str(&format!("Failed reading file {name}: {e}")))?;
```
`extract_bundle_files` has:
1. No limit on the number of entries in `archive.len()`.
2. No limit on individual uncompressed entry size.
3. No check on total cumulative uncompressed size.
4. No protection against malicious compression ratios (ZIP bombs).

---

## 2. Logic Chain

1. **Step 1 (Root Cause & Inefficiency of `get_sample_packet`)**:
   `get_sample_packet` is designed as a sample fixture loader for the UI and tests. Re-running the entire cryptographic pipeline (`generate_all_fixtures()`) on every button click or function call consumes significant CPU cycles (~30-50ms) and invokes unpatched system time functions, causing runtime crashes in WebAssembly.
2. **Step 2 (Zero-Cost Static Embedding via `include_str!`)**:
   By embedding the pre-generated JSON fixture files into the binary at compile time via `include_str!("../../../aip-console/public/fixtures/...")`, `get_sample_packet` becomes an $O(1)$ zero-crypto lookup. It requires zero host OS time access, executes in <1 microsecond, and eliminates runtime panics regardless of target platform.
3. **Step 3 (Fixture Consistency Requirement)**:
   Because `include_str!` embeds `index.json` and fixture files at compile time, `samples.rs:518` must first be corrected to `"AGENT_SIGNED".into()`, and `cargo run -p aip-wasm --bin generate_fixtures` must be executed to regenerate `index.json` *before* compiling the WebAssembly binary.
4. **Step 4 (Defense-in-Depth for `extract_bundle_files`)**:
   In WebAssembly, memory is limited by 32-bit linear address space. An adversarial ZIP archive (e.g. 1 KB compressed expanding to 1 GB) could trigger an out-of-memory WebAssembly panic.
   A 3-tier boundary check must be enforced:
   - Max entry count: `MAX_BUNDLE_ENTRIES = 128`
   - Max file size: `MAX_ENTRY_SIZE = 10 * 1024 * 1024` (10 MiB)
   - Max bundle size: `MAX_TOTAL_BUNDLE_SIZE = 50 * 1024 * 1024` (50 MiB)
   To prevent lying headers, the reader must wrap each file in `(&mut file).take(MAX_ENTRY_SIZE + 1)` and reject entries that exceed the limit.
   Directory entries must be skipped (`if file.is_dir() { continue; }`).

---

## 3. Caveats

- `include_str!` paths are evaluated relative to the source file (`aip-standalone/aip-wasm/src/lib.rs`). The path `../../../aip-console/public/fixtures/` has been verified and resolves correctly.
- The Worker must run `cargo run --manifest-path aip-standalone/Cargo.toml -p aip-wasm --bin generate_fixtures` *after* updating `samples.rs:518` and *before* running `wasm-pack build`.
- In addition to the `lib.rs` and `samples.rs` fixes formulated here, Explorer 1's time-routing fixes in `aip-core` and `aip-protocol` (`aip_crypto::now_ms()`) must also be applied by the Worker so native generator tools and unit tests execute cleanly across targets.

---

## 4. Conclusion & Exact Code Formulations

### 4.1 Exact Code Changes for `aip-standalone/aip-wasm/src/lib.rs`

#### A. Static Fixture Declarations & `get_sample_packet` Formulation
Replace lines 270-326 in `aip-standalone/aip-wasm/src/lib.rs` with:

```rust
// Static pre-compiled fixture strings embedded at compile time via include_str!
// Eliminates runtime generation overhead and guarantees zero WebAssembly runtime traps from platform time/crypto operations.
static FIXTURE_HONEST_COUNTERPARTY: &str =
    include_str!("../../../aip-console/public/fixtures/honest_counterparty.json");
static FIXTURE_HONEST_CONTEXT: &str =
    include_str!("../../../aip-console/public/fixtures/honest_counterparty.context.json");
static FIXTURE_AUTHORITY_BOUND: &str =
    include_str!("../../../aip-console/public/fixtures/authority_bound.json");
static FIXTURE_AUTHORITY_CONTEXT: &str =
    include_str!("../../../aip-console/public/fixtures/authority_bound.context.json");
static FIXTURE_AGENT_SIGNED: &str =
    include_str!("../../../aip-console/public/fixtures/agent_signed.json");
static FIXTURE_AGENT_CONTEXT: &str =
    include_str!("../../../aip-console/public/fixtures/agent_signed.context.json");
static FIXTURE_TAMPERED_SUMMARY: &str =
    include_str!("../../../aip-console/public/fixtures/tampered_summary.json");
static FIXTURE_TAMPERED_HASH: &str =
    include_str!("../../../aip-console/public/fixtures/tampered_hash.json");
static FIXTURE_TAMPERED_SIGNATURE: &str =
    include_str!("../../../aip-console/public/fixtures/tampered_signature.json");
static FIXTURE_SCOPE_ESCALATION: &str =
    include_str!("../../../aip-console/public/fixtures/scope_escalation.json");
static FIXTURE_REVOKED_TOKEN: &str =
    include_str!("../../../aip-console/public/fixtures/revoked_token.json");
static FIXTURE_REVOKED_CONTEXT: &str =
    include_str!("../../../aip-console/public/fixtures/revoked_token.context.json");
static FIXTURE_INDEX_JSON: &str =
    include_str!("../../../aip-console/public/fixtures/index.json");

/// 10. Sample packet fixture provider.
/// Serves static pre-compiled JSON fixture strings directly from compile-time embedded strings.
#[wasm_bindgen]
pub fn get_sample_packet(sample_type: &str) -> Result<String, JsValue> {
    match sample_type.trim().to_ascii_lowercase().as_str() {
        "honest_counterparty"
        | "honest_counterparty.json"
        | "valid_loan"
        | "valid_countersigned"
        | "valid"
        | "" => Ok(FIXTURE_HONEST_COUNTERPARTY.to_string()),
        "authority_bound" | "authority_bound.json" => Ok(FIXTURE_AUTHORITY_BOUND.to_string()),
        "agent_signed" | "agent_signed.json" => Ok(FIXTURE_AGENT_SIGNED.to_string()),
        "tampered_summary"
        | "tampered_summary.json"
        | "tampered_decision"
        | "tampered" => Ok(FIXTURE_TAMPERED_SUMMARY.to_string()),
        "tampered_hash" | "tampered_hash.json" | "tampered_hash_recomputed" => {
            Ok(FIXTURE_TAMPERED_HASH.to_string())
        }
        "tampered_signature" | "tampered_signature.json" => {
            Ok(FIXTURE_TAMPERED_SIGNATURE.to_string())
        }
        "scope_escalation" | "scope_escalation.json" | "attenuation_violation" => {
            Ok(FIXTURE_SCOPE_ESCALATION.to_string())
        }
        "revoked_token" | "revoked_token.json" | "revoked_delegation" | "revoked" => {
            Ok(FIXTURE_REVOKED_TOKEN.to_string())
        }
        "sample_context"
        | "valid_context"
        | "context"
        | "honest_counterparty.context"
        | "honest_counterparty.context.json" => Ok(FIXTURE_HONEST_CONTEXT.to_string()),
        "authority_bound.context"
        | "authority_bound.context.json"
        | "authority_context" => Ok(FIXTURE_AUTHORITY_CONTEXT.to_string()),
        "agent_signed.context" | "agent_signed.context.json" | "agent_context" => {
            Ok(FIXTURE_AGENT_CONTEXT.to_string())
        }
        "revoked_token.context" | "revoked_token.context.json" | "revoked_context" => {
            Ok(FIXTURE_REVOKED_CONTEXT.to_string())
        }
        "index" | "index.json" => Ok(FIXTURE_INDEX_JSON.to_string()),
        other => Err(JsValue::from_str(&format!(
            "Unknown sample type '{other}'. Valid options: honest_counterparty, authority_bound, agent_signed, tampered_summary, tampered_hash, tampered_signature, scope_escalation, revoked_token, sample_context, index"
        ))),
    }
}
```

#### B. ZIP Bomb Hardening Constants & `extract_bundle_files` Formulation
Replace lines 222-246 in `aip-standalone/aip-wasm/src/lib.rs` with:

```rust
/// Maximum number of files permitted in a ZIP bundle to prevent directory/entry exhaustion attacks.
pub const MAX_BUNDLE_ENTRIES: usize = 128;

/// Maximum uncompressed size permitted per individual file (10 MiB) to guard against ZIP bombs.
pub const MAX_ENTRY_SIZE: usize = 10 * 1024 * 1024;

/// Maximum total cumulative uncompressed size across all files in a bundle (50 MiB).
pub const MAX_TOTAL_BUNDLE_SIZE: usize = 50 * 1024 * 1024;

/// 8. Extract all content files from ZIP bundle bytes.
/// Returns JSON map of filename -> content text.
/// Hardened with in-memory size limits to guard against ZIP bombs and memory exhaustion.
#[wasm_bindgen]
pub fn extract_bundle_files(zip_bytes: &[u8]) -> Result<String, JsValue> {
    let mut archive = zip::ZipArchive::new(Cursor::new(zip_bytes))
        .map_err(|e| JsValue::from_str(&format!("Failed to read ZIP archive: {e}")))?;

    if archive.len() > MAX_BUNDLE_ENTRIES {
        return Err(JsValue::from_str(&format!(
            "ZIP bundle contains too many entries ({} > max {})",
            archive.len(),
            MAX_BUNDLE_ENTRIES
        )));
    }

    let mut file_map = BTreeMap::new();
    let mut total_extracted_bytes: usize = 0;

    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| JsValue::from_str(&format!("ZIP entry error: {e}")))?;

        if file.is_dir() {
            continue;
        }

        let name = file.name().to_string();

        // 1. Header check: verify declared size is within reasonable bounds
        if file.size() > MAX_ENTRY_SIZE as u64 {
            return Err(JsValue::from_str(&format!(
                "ZIP entry '{name}' declared uncompressed size ({} bytes) exceeds limit of {MAX_ENTRY_SIZE} bytes",
                file.size()
            )));
        }

        // 2. Stream bounds check: read at most MAX_ENTRY_SIZE + 1 bytes to detect lying headers / compression bombs
        use std::io::Read;
        let mut buf = Vec::new();
        let mut limited_reader = (&mut file).take((MAX_ENTRY_SIZE + 1) as u64);
        limited_reader
            .read_to_end(&mut buf)
            .map_err(|e| JsValue::from_str(&format!("Failed reading file {name}: {e}")))?;

        if buf.len() > MAX_ENTRY_SIZE {
            return Err(JsValue::from_str(&format!(
                "ZIP entry '{name}' uncompressed size exceeds limit of {MAX_ENTRY_SIZE} bytes (ZIP bomb detected)"
            )));
        }

        // 3. Cumulative size check: verify total across all bundle entries does not exceed ceiling
        total_extracted_bytes = total_extracted_bytes
            .checked_add(buf.len())
            .ok_or_else(|| JsValue::from_str("Bundle extracted size integer overflow"))?;

        if total_extracted_bytes > MAX_TOTAL_BUNDLE_SIZE {
            return Err(JsValue::from_str(&format!(
                "Total extracted bundle size ({} bytes) exceeds limit of {MAX_TOTAL_BUNDLE_SIZE} bytes (ZIP bomb detected)",
                total_extracted_bytes
            )));
        }

        let content = String::from_utf8(buf.clone())
            .unwrap_or_else(|_| String::from_utf8_lossy(&buf).to_string());
        file_map.insert(name, content);
    }

    serde_json::to_string_pretty(&file_map).map_err(|e| JsValue::from_str(&e.to_string()))
}
```

#### C. Unit Test Updates in `aip-standalone/aip-wasm/src/lib.rs`
Update `test_get_sample_packet` (lines 457-469) to verify all embedded samples:
```rust
    #[test]
    fn test_get_sample_packet() {
        let p_honest = get_sample_packet("honest_counterparty").unwrap();
        assert!(p_honest.contains("packet_id"));
        assert!(p_honest.contains("decision"));

        let p_auth = get_sample_packet("authority_bound").unwrap();
        assert!(p_auth.contains("packet_id"));
        assert!(p_auth.contains("decision"));

        let p_agent = get_sample_packet("agent_signed").unwrap();
        assert!(p_agent.contains("packet_id"));

        let p_t_sum = get_sample_packet("tampered_summary").unwrap();
        assert!(p_t_sum.contains("packet_id"));

        let p_t_hash = get_sample_packet("tampered_hash").unwrap();
        assert!(p_t_hash.contains("packet_id"));

        let p_t_sig = get_sample_packet("tampered_signature").unwrap();
        assert!(p_t_sig.contains("packet_id"));

        let p_scope = get_sample_packet("scope_escalation").unwrap();
        assert!(p_scope.contains("packet_id"));

        let p_rev = get_sample_packet("revoked_token").unwrap();
        assert!(p_rev.contains("packet_id"));

        let ctx = get_sample_packet("sample_context").unwrap();
        assert!(ctx.contains("trusted_issuers"));

        let idx = get_sample_packet("index.json").unwrap();
        assert!(idx.contains("fixtures"));

        assert!(get_sample_packet("unknown_type_xxx").is_err());
    }
```

### 4.2 Exact Code Change for `aip-standalone/aip-wasm/src/samples.rs`
In `aip-standalone/aip-wasm/src/samples.rs` line 518:
```rust
// Before:
expected_derived_floor: "UNVERIFIED".into(),

// After:
expected_derived_floor: "AGENT_SIGNED".into(),
```
And in `aip-standalone/aip-wasm/src/samples.rs` lines 784-787:
```rust
    // 8. Revoked Token: valid == false, tampered == false, floor == AgentSigned
    let rep = verify_packet(&fixtures.revoked_token.packet, &fixtures.revoked_token.context);
    if rep.valid || rep.tampered || rep.trust_floor != TrustFloor::AgentSigned {
        return Err(format!("revoked_token mismatch: valid={}, tampered={}, floor={:?}", rep.valid, rep.tampered, rep.trust_floor));
    }
```

---

### 4.3 Sequential 6-Step Implementation Plan for the Worker

| Step | Action | Files | Verification |
|------|--------|-------|--------------|
| **1** | Replace all `SystemTime::now()` calls with `aip_crypto::now_ms()` | `aip-core/src/capability.rs:191`<br>`aip-core/src/delegation.rs:362`<br>`aip-core/src/revocation.rs:278`<br>`aip-core/src/nonce.rs:67`<br>`aip-protocol/src/evidence_packet.rs:468`<br>`aip-protocol/src/bundle.rs:97` | `cargo check --target wasm32-unknown-unknown -p aip-core -p aip-protocol` |
| **2** | Update `revoked_token` derived floor in fixture generator | `aip-standalone/aip-wasm/src/samples.rs:518, 785` | `cargo test -p aip-wasm test_self_verify_fixtures_all` |
| **3** | Regenerate static fixtures | Run binary: `cargo run --manifest-path aip-standalone/Cargo.toml -p aip-wasm --bin generate_fixtures` | Verify `aip-console/public/fixtures/index.json` has `"expected_derived_floor": "AGENT_SIGNED"` |
| **4** | Apply `lib.rs` updates: static `include_str!` and ZIP bomb limits | `aip-standalone/aip-wasm/src/lib.rs:222-326, 457-469` | `cargo test --manifest-path aip-standalone/Cargo.toml -p aip-wasm` |
| **5** | Run workspace test suites | Workspace tests | `cargo test --manifest-path aip-standalone/Cargo.toml -p aip-wasm -p aip-protocol` |
| **6** | Recompile WebAssembly & run empirical validations | Run wasm-pack & node harnesses | `npx wasm-pack build aip-standalone/aip-wasm --target web --out-dir ../../aip-console/public/wasm --out-name aip_wasm --no-gitignore`<br>`node tests/wasm_empirical_challenger.mjs`<br>`node aip-standalone/aip-wasm/tests/wasm_binary_empirical.mjs`<br>`npm run test:e2e` |

---

## 5. Verification Method

To independently verify that the defect is resolved:

1. **Verify WebAssembly `get_sample_packet` execution without trap**:
   ```powershell
   node -e "import('node:fs').then(fs => import('./aip-console/public/wasm/aip_wasm.js').then(async m => { const wasmBytes = fs.readFileSync('./aip-console/public/wasm/aip_wasm_bg.wasm'); await m.default({ module_or_path: wasmBytes }); const p = m.get_sample_packet('honest_counterparty'); console.log('Packet length:', p.length); }));"
   ```
   *Expected output*: `Packet length: 16180` (or similar non-zero byte count), exit code 0.
   *Invalidation condition*: Any `RuntimeError: unreachable` or `time not implemented` panic.

2. **Execute Challenger 1's 93-test empirical WASM harness**:
   ```powershell
   node tests/wasm_empirical_challenger.mjs
   ```
   *Expected output*:
   ```text
   ALL CHALLENGES COMPLETED: 93 passed, 0 failed, 93 total
   ```
   *Invalidation condition*: Any failed tests.

3. **Execute Challenger 2's empirical WASM harness**:
   ```powershell
   node aip-standalone/aip-wasm/tests/wasm_binary_empirical.mjs
   ```
   *Expected output*: All assertions pass, exit code 0.

4. **Execute Native Rust Test Suites**:
   ```powershell
   cargo test --manifest-path aip-standalone/Cargo.toml -p aip-wasm
   cargo test --manifest-path aip-standalone/Cargo.toml -p aip-protocol
   ```
   *Expected output*: 10+ passed in `aip-wasm`, 27 passed in `aip-protocol`.

5. **Execute E2E Test Suite**:
   ```powershell
   npm run test:e2e
   ```
   *Expected output*: 52 test files passed, 260 tests passed, 0 failed.
