# `aip-wasm` Crate Configuration & WebAssembly Build Strategy

**Explorer**: Milestone 1 Explorer 1 (M1 Crate & WASM Build Specialist)  
**Date**: 2026-11-02  
**Target Working Directory**: `.agents/teamwork/m1_explorer_1/`  
**Milestone**: Milestone 1 (`aip-wasm` Core Engine & Fixtures Pipeline)

---

## 1. Executive Summary

This report establishes the complete specification, crate manifest, build commands, and runtime compatibility strategy for compiling the AIP Rust verification engine into WebAssembly (`aip-wasm`).

### Core Findings & Architectural Decisions:
1. **Host Toolchain Ready**: The environment has `rustc 1.98.0`, `cargo 1.98.0`, `wasm32-unknown-unknown` pre-installed, and `wasm-pack 0.15.1` accessible via `npx wasm-pack`.
2. **`getrandom` 0.2 Web Crypto Activation**: Cargo fails on `wasm32-unknown-unknown` by default because `ed25519-dalek 2.1` and `rand 0.8` depend on `getrandom 0.2.17`. Declaring `getrandom = { version = "0.2", features = ["js"] }` in `aip-wasm/Cargo.toml` activates the Web Crypto API (`crypto.getRandomValues`) workspace-wide for the WASM target.
3. **`SystemTime::now()` Runtime Panic Mitigation**: In Rust on `wasm32-unknown-unknown`, `std::time::SystemTime::now()` panics at runtime (`unsupported`). In `aip-protocol`, this is called only to record `verified_at: now_ms()` (line 319 in `verification.rs`), `exported_at` (line 151 in `bundle.rs`), and default `created_at` (line 439 in `evidence_packet.rs`). We provide a zero-cost target-conditional implementation using `js_sys::Date::now() as u64` when `target_arch = "wasm32"`.
4. **Target Strategy (`--target web`)**: Compiling with `--target web` into `aip-console/public/wasm/` generates an ES module (`aip_wasm.js`) and binary (`aip_wasm_bg.wasm`) served statically by Next.js 15. This avoids Turbopack/Webpack WebAssembly bundling conflicts and guarantees 100% offline client-side verification with zero verification logic in JavaScript.
5. **Contract Field Dual-Mapping**: Discovered that `PROJECT.md` and `e2e/support/types.ts` use `overall_valid`, `derived_trust_floor`, and `tamper_evidence`, whereas `aip-protocol` historically named these fields `valid`, `trust_floor`, and `tampered`. `aip-wasm` emits both sets of keys in its JSON output to guarantee seamless compatibility with all consumers.

---

## 2. Workspace Registration

In `aip-standalone/Cargo.toml`, register `"aip-wasm"` as a workspace member:

```toml
[workspace]
resolver = "2"
members = [
    "aip-types",
    "aip-crypto",
    "aip-core",
    "aip-protocol",
    "aip-wasm",         # WebAssembly bindings crate
    "aip-test",
    "aip-cli",
    "aip-verify",
    "aip-real-tests",
    "banking_demo",
]

[workspace.package]
version = "0.4.0"
edition = "2021"
license = "LicenseRef-Proprietary"
```

---

## 3. Crate Manifest: `aip-standalone/aip-wasm/Cargo.toml`

Create `aip-standalone/aip-wasm/Cargo.toml`:

```toml
[package]
name = "aip-wasm"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "WebAssembly bindings for AIP verification engine & accountability console"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
# Local workspace crates
aip-protocol = { path = "../aip-protocol" }
aip-types = { path = "../aip-types" }
aip-crypto = { path = "../aip-crypto" }
aip-core = { path = "../aip-core" }

# WebAssembly & JS interop
wasm-bindgen = "0.2"
js-sys = "0.3"
serde-wasm-bindgen = "0.6"

# Serialization & Cryptographic utilities
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
hex = "0.4"

# Critical for WASM randomness (activates browser Web Crypto crypto.getRandomValues)
getrandom = { version = "0.2", features = ["js"] }

# Better browser console panic backtraces
console_error_panic_hook = { version = "0.1", optional = true }

[features]
default = ["console_error_panic_hook"]
```

---

## 4. WASM-Safe Timestamp Strategy (`SystemTime::now()` Fix)

### The Problem:
On `wasm32-unknown-unknown`, `std::time::SystemTime::now()` compiles without error, but at runtime in the browser it throws an uncatchable panic:
```text
RuntimeError: unreachable (or panicked at 'unsupported')
```
In `aip-protocol/src/verification.rs` (line 705):
```rust
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
```
If called without adaptation, any call to `verify_packet` immediately crashes when populating `verified_at: now_ms()`.

### The Solution:
1. In `aip-standalone/aip-protocol/Cargo.toml`, add target-conditional `js-sys`:
   ```toml
   [target.'cfg(target_arch = "wasm32")'.dependencies]
   js-sys = "0.3"
   ```

2. In `aip-standalone/aip-protocol/src/lib.rs`, define a shared `now_ms` helper:
   ```rust
   #[cfg(not(target_arch = "wasm32"))]
   pub(crate) fn now_ms() -> u64 {
       std::time::SystemTime::now()
           .duration_since(std::time::UNIX_EPOCH)
           .unwrap()
           .as_millis() as u64
   }

   #[cfg(target_arch = "wasm32")]
   pub(crate) fn now_ms() -> u64 {
       js_sys::Date::now() as u64
   }
   ```

3. In `verification.rs`, `bundle.rs`, and `evidence_packet.rs`:
   Replace local `fn now_ms()` with `crate::now_ms()`.

4. Furthermore, allow deterministic timestamp overrides in `VerificationContext` for tests and audit replays:
   In `aip-protocol/src/verification.rs`:
   ```rust
   pub struct VerificationContext {
       ...
       pub now_override: Option<u64>,
   }
   ```
   And in `verify_packet`:
   ```rust
   verified_at: ctx.now_override.unwrap_or_else(crate::now_ms),
   ```

### Verification of Native Non-Regression:
When compiling on native targets (e.g. Windows/Linux x86_64), `cfg(not(target_arch = "wasm32"))` triggers, `js-sys` is not included in the native build, and `cargo test -p aip-protocol` runs with 100% native behavior.

---

## 5. WebAssembly Export API Specification (`aip-wasm/src/lib.rs`)

`aip-wasm` exposes the 10 interface contract functions defined in `PROJECT.md` (§ Interface Contracts):

```rust
use wasm_bindgen::prelude::*;
use std::collections::HashMap;
use std::io::Cursor;

use aip_protocol::{
    verify_packet, verify_zip, AccountabilityGraph, EvidencePacket,
    VerificationContext, TrustFloor,
};
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_types::{CapabilityScope, ScopeAction, ProvenanceTriple};

#[wasm_bindgen(start)]
pub fn init_wasm() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// 1. Verify EvidencePacket JSON against optional VerificationContext JSON
#[wasm_bindgen]
pub fn verify_evidence_packet(packet_json: &str, context_json: Option<String>) -> Result<String, JsValue> {
    let packet = EvidencePacket::from_json(packet_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid EvidencePacket JSON: {e}")))?;

    let ctx = match context_json {
        Some(s) if !s.trim().is_empty() => parse_verification_context(&s)
            .map_err(|e| JsValue::from_str(&format!("Invalid VerificationContext JSON: {e}")))?,
        _ => VerificationContext::new(),
    };

    let report = verify_packet(&packet, &ctx);

    // Emits JSON supporting both PROJECT.md / e2e (overall_valid, derived_trust_floor, tamper_evidence)
    // and aip-protocol internal keys (valid, trust_floor, tampered).
    let val = serde_json::json!({
        "valid": report.valid,
        "overall_valid": report.valid,
        "trust_floor": report.trust_floor,
        "derived_trust_floor": report.trust_floor,
        "claimed_trust_floor": report.claimed_trust_floor,
        "tampered": report.tampered,
        "tamper_evidence": report.tampered,
        "authority_chain_verified": report.authority_chain_verified,
        "delegation_chain_verified": report.delegation_chain_verified,
        "scope_verified": report.scope_verified,
        "receipt_verified": report.receipt_verified,
        "trace_verified": report.trace_verified,
        "revocation_clear": report.revocation_clear,
        "packet_id": report.packet_id,
        "agent_id": report.agent_id,
        "verified_at": report.verified_at,
        "checks": report.checks,
    });

    serde_json::to_string_pretty(&val).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// 2. Verify ZIP audit bundle bytes against optional context
#[wasm_bindgen]
pub fn verify_bundle_zip(zip_bytes: &[u8], context_json: Option<String>) -> Result<String, JsValue> {
    let ctx = match context_json {
        Some(s) if !s.trim().is_empty() => parse_verification_context(&s)
            .map_err(|e| JsValue::from_str(&format!("Invalid context JSON: {e}")))?,
        _ => VerificationContext::new(),
    };

    let result = verify_zip(zip_bytes, &ctx);
    
    // Formats result conforming to BundleVerificationResult
    let checks: Vec<serde_json::Value> = result.checks.iter().map(|c| {
        serde_json::json!({
            "name": c.name,
            "status": c.status,
            "pass": c.status == aip_protocol::BundleStatus::Pass,
            "detail": c.detail,
        })
    }).collect();

    let val = serde_json::json!({
        "overall": result.overall,
        "bundle_id": result.bundle_id,
        "packet_id": result.packet_id,
        "signer_fingerprint": result.signer_fingerprint,
        "checks": checks,
    });

    serde_json::to_string_pretty(&val).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// 3. Extract all content files from ZIP bundle bytes
#[wasm_bindgen]
pub fn extract_bundle_files(zip_bytes: &[u8]) -> Result<String, JsValue> {
    let mut archive = zip::ZipArchive::new(Cursor::new(zip_bytes))
        .map_err(|e| JsValue::from_str(&format!("Failed to parse ZIP archive: {e}")))?;
    
    let mut map: HashMap<String, String> = HashMap::new();
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)
            .map_err(|e| JsValue::from_str(&format!("Failed to read ZIP entry: {e}")))?;
        let name = file.name().to_string();
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut buf)
            .map_err(|e| JsValue::from_str(&format!("Failed to read file {name}: {e}")))?;
        
        let text = String::from_utf8(buf)
            .map_err(|e| JsValue::from_str(&format!("File {name} is not valid UTF-8: {e}")))?;
        map.insert(name, text);
    }

    serde_json::to_string_pretty(&map).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// 4. Reconstruct AccountabilityGraph from EvidencePacket JSON & optional VerificationReport JSON
#[wasm_bindgen]
pub fn get_accountability_graph(packet_json: &str, report_json: Option<String>) -> Result<String, JsValue> {
    let packet = EvidencePacket::from_json(packet_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mut graph = AccountabilityGraph::from_packet(&packet);
    if let Some(r) = report_json {
        if !r.trim().is_empty() {
            if let Ok(report) = serde_json::from_str(&r) {
                graph = graph.with_report(&report);
            }
        }
    }

    // Adapt edges to include both from/to and source/target for React Flow
    let nodes: Vec<serde_json::Value> = graph.nodes.iter().map(|n| {
        serde_json::json!({
            "id": n.id,
            "kind": n.kind,
            "label": n.label,
        })
    }).collect();

    let edges: Vec<serde_json::Value> = graph.edges.iter().map(|e| {
        serde_json::json!({
            "from": e.from,
            "to": e.to,
            "source": e.from,
            "target": e.to,
            "relation": e.relation,
        })
    }).collect();

    let val = serde_json::json!({
        "packet_id": graph.packet_id,
        "claimed_trust_floor": graph.claimed_trust_floor,
        "derived_trust_floor": graph.derived_trust_floor,
        "nodes": nodes,
        "edges": edges,
    });

    serde_json::to_string_pretty(&val).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// 5. Recompute packet hash over canonical bytes
#[wasm_bindgen]
pub fn recompute_packet_hash(packet_json: &str) -> Result<String, JsValue> {
    let packet = EvidencePacket::from_json(packet_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(hex::encode(packet.compute_hash()))
}

/// 6. Get canonical encoding bytes as hex string
#[wasm_bindgen]
pub fn get_canonical_bytes_hex(packet_json: &str) -> Result<String, JsValue> {
    let packet = EvidencePacket::from_json(packet_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(hex::encode(packet.canonical_bytes()))
}

/// 7. Check if CapabilityScope permits a ScopeAction
#[wasm_bindgen]
pub fn check_scope_permits(scope_json: &str, action_json: &str) -> Result<bool, JsValue> {
    let scope: CapabilityScope = serde_json::from_str(scope_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let action: ScopeAction = serde_json::from_str(action_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(aip_core::capability::scope_permits(&scope, &action))
}

/// 8. Compute Capability Lattice intersection (MEET operator ⊓)
#[wasm_bindgen]
pub fn meet_capability_scopes(parent_json: &str, child_json: &str) -> Result<String, JsValue> {
    let parent: CapabilityScope = serde_json::from_str(parent_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let child: CapabilityScope = serde_json::from_str(child_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    match aip_core::capability::scope_intersection(&parent, &child) {
        Some(met) => serde_json::to_string_pretty(&met).map_err(|e| JsValue::from_str(&e.to_string())),
        None => Ok("null".to_string()), // ⊥ bottom element
    }
}

/// 9. Generate Ed25519 keypair and derive AIP-ID with provenance
#[wasm_bindgen]
pub fn generate_keypair() -> Result<String, JsValue> {
    let kp = generate_ed25519_keypair();
    let prov = ProvenanceTriple {
        model_commitment: sha256(b"syntriass-console-model"),
        environment_commitment: sha256(b"syntriass-console-env"),
        toolchain_commitment: sha256(b"syntriass-console-toolchain"),
    };
    let aip_id = derive_aip_id(&kp.public_key, &prov);
    let val = serde_json::json!({
        "aip_id": aip_id,
        "public_key_hex": hex::encode(&kp.public_key),
        "private_key_hex": hex::encode(&kp.private_key),
    });
    Ok(val.to_string())
}

/// 10. Built-in sample packet fixture provider
#[wasm_bindgen]
pub fn get_sample_packet(sample_type: &str) -> Result<String, JsValue> {
    // Return embedded normative JSON fixtures:
    // "valid_loan", "tampered_summary", "tampered_hash", "revoked_delegation", "attenuation_violation", "countersigned"
    ...
}
```

---

## 6. Build Command & Strategy

### 6.1 The Build Command
From the project root:
```bash
npx wasm-pack build aip-standalone/aip-wasm --target web --out-dir ../../aip-console/public/wasm --out-name aip_wasm --no-gitignore
```
Or from within `aip-standalone/aip-wasm/`:
```bash
npx wasm-pack build --target web --out-dir ../../aip-console/public/wasm --out-name aip_wasm --no-gitignore
```

### 6.2 Key Flags Explained:
- `--target web`: Compiles to standard WebAssembly ES module suitable for direct browser consumption via `fetch()` and `WebAssembly.instantiateStreaming()`.
- `--out-dir ../../aip-console/public/wasm`: Directs output files into Next.js static asset folder.
- `--out-name aip_wasm`: Generates predictable file names:
  - `aip_wasm.js` (ES module loader)
  - `aip_wasm_bg.wasm` (Compiled WebAssembly bytecode)
  - `aip_wasm.d.ts` (TypeScript definitions)
- `--no-gitignore`: **CRITICAL**. Without this flag, wasm-pack generates a `.gitignore` containing `*` in the output directory, causing git to ignore all compiled WASM artifacts.
- `--no-opt` (fallback flag): If the local Windows environment does not have `binaryen` / `wasm-opt` installed and cannot download it, pass `--no-opt` to complete compilation without post-processing.

### 6.3 NPM Script Integration:
In repository root `package.json`:
```json
"scripts": {
  "build:wasm": "npx wasm-pack build aip-standalone/aip-wasm --target web --out-dir ../../aip-console/public/wasm --out-name aip_wasm --no-gitignore"
}
```

---

## 7. Next.js 15 & React 19 Client Integration Architecture

To ensure zero Turbopack/Webpack bundling issues, safe React 19 SSR hydration, and zero verification logic in UI code:

### 7.1 Static Asset Serving
Because files are placed in `aip-console/public/wasm/`, Next.js automatically serves them at `/wasm/aip_wasm.js` and `/wasm/aip_wasm_bg.wasm`.

### 7.2 Singleton WASM Loader (`aip-console/src/lib/wasm/aip-wasm-client.ts`)
```typescript
'use client';

// Dynamically import the loader module from public directory or static path
let wasmModule: typeof import('../../../public/wasm/aip_wasm') | null = null;
let initPromise: Promise<typeof import('../../../public/wasm/aip_wasm')> | null = null;

export async function getAipWasm() {
  if (typeof window === 'undefined') {
    throw new Error('aip-wasm can only execute client-side in the browser');
  }
  if (wasmModule) return wasmModule;
  if (!initPromise) {
    initPromise = (async () => {
      const wasm = await import('../../../public/wasm/aip_wasm');
      await wasm.default('/wasm/aip_wasm_bg.wasm');
      wasmModule = wasm;
      return wasm;
    })();
  }
  return initPromise;
}
```

### 7.3 React Hook (`useAipVerifier`)
Provides instant, responsive verification with zero UI calculation:
```typescript
'use client';

import { useState, useEffect, useCallback } from 'react';
import { getAipWasm } from './aip-wasm-client';
import type { VerificationReport, AccountabilityGraph } from '@/types/aip';

export function useAipVerifier() {
  const [ready, setReady] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getAipWasm()
      .then(() => setReady(true))
      .catch((err) => setError(String(err)));
  }, []);

  const verifyPacket = useCallback(async (
    packetJson: string,
    contextJson?: string
  ): Promise<VerificationReport> => {
    const wasm = await getAipWasm();
    const raw = wasm.verify_evidence_packet(packetJson, contextJson);
    return JSON.parse(raw);
  }, []);

  const getGraph = useCallback(async (
    packetJson: string,
    reportJson?: string
  ): Promise<AccountabilityGraph> => {
    const wasm = await getAipWasm();
    const raw = wasm.get_accountability_graph(packetJson, reportJson);
    return JSON.parse(raw);
  }, []);

  return { ready, error, verifyPacket, getGraph };
}
```

---

## 8. Actionable Step-by-Step Implementation Plan for Worker 1

| Step | Action | Files Modified / Created | Verification Command |
|---|---|---|---|
| **Step 1** | Register `aip-wasm` in workspace | `aip-standalone/Cargo.toml` | `cargo check --manifest-path aip-standalone/Cargo.toml` |
| **Step 2** | Add WASM target dependency in `aip-protocol` | `aip-standalone/aip-protocol/Cargo.toml` | View file |
| **Step 3** | Implement WASM-safe `now_ms()` and make `read_zip` public | `aip-standalone/aip-protocol/src/lib.rs`, `verification.rs`, `bundle.rs`, `evidence_packet.rs` | `cargo test -p aip-protocol --manifest-path aip-standalone/Cargo.toml` |
| **Step 4** | Scaffold `aip-standalone/aip-wasm/Cargo.toml` | `aip-standalone/aip-wasm/Cargo.toml` | View file |
| **Step 5** | Implement WASM export functions in `src/lib.rs` | `aip-standalone/aip-wasm/src/lib.rs` | `cargo check --target wasm32-unknown-unknown -p aip-wasm --manifest-path aip-standalone/Cargo.toml` |
| **Step 6** | Add `"build:wasm"` script to `package.json` | `package.json` | `npm run build:wasm` |
| **Step 7** | Compile WASM to `aip-console/public/wasm/` | `aip-console/public/wasm/aip_wasm_bg.wasm`, `aip_wasm.js`, `aip_wasm.d.ts` | File inspection |
| **Step 8** | Verify WASM loading and verification | Temporary Node.js verification test | `node -e "..."` or Vitest test |
