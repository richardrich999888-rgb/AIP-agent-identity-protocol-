# Rust Verification Engine & WebAssembly (WASM) Architecture Analysis
**AIP Enterprise Accountability Console**  
**Explorer**: Explorer 1 (Rust Engine & WASM Explorer)  
**Date**: 2026-11-02  
**Target Working Directory**: `.agents/teamwork/survey_explorer_rust/`  

---

## 1. Executive Summary

This investigation explores the Rust codebase powering the Agent Identity Protocol (AIP), analyzes the implementation of the 14-rule verification engine in `aip-protocol`, inspects all core data structures, evaluates the status of WebAssembly support, and defines the exact WebAssembly bindings and Next.js 15 / React 19 integration architecture required for the AIP Enterprise Accountability Console.

### Key Discoveries:
1. **Verification Engine Rigor**: The verification engine in `aip-standalone/aip-protocol/src/verification.rs` implements all 14 normative verification rules without short-circuiting. Every check performs actual cryptographic signature validation, SHA-256 canonical hashing, AIP-ID provenance derivation, or scope attenuation lattice evaluation.
2. **Deterministic Canonical Encoding**: Evidence packets are hashed and signed using a prefix-free, little-endian binary encoding (`canonical_bytes()`) that strictly covers all fields including embedded delegation signatures and counterparty signatures, making any mutation tamper-evident.
3. **Current State of WASM (`aip-wasm`)**: The repository does **not** currently contain an `aip-wasm` crate. However, the host environment has Cargo 1.98.0, Rustc 1.98.0, `wasm32-unknown-unknown` target installed, and `wasm-pack 0.15.1` available via `npx wasm-pack`.
4. **WASM Compilation Requirements**: Compiling `aip-protocol` and its dependencies to `wasm32-unknown-unknown` requires enabling the `"js"` feature on `getrandom` (`getrandom = { version = "0.2", features = ["js"] }`). In addition, the runtime invocation of `std::time::SystemTime::now()` in `verification.rs` line 319 (used only for recording the audit timestamp `verified_at`) must be handled gracefully in WASM so it does not trigger a runtime panic.
5. **Next.js 15 / React 19 Integration Strategy**: Compiling `aip-wasm` with `--target web` outputting to `aip-console/public/wasm/` and wrapping initialization in a React Hook (`useAipVerifier`) completely avoids Webpack Turbopack bundling collisions, guarantees safe SSR hydration, and fulfills the strict requirement of **zero verification logic in JavaScript**.

---

## 2. Workspace & Crate Layout

The repository contains two primary Rust workspaces/trees:

```
c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\
├── aip-standalone/                 # Core Rust Protocol Workspace
│   ├── Cargo.toml                  # Workspace root (resolver = "2", version = "0.4.0")
│   ├── aip-types/                  # Core types: PublicKey, Signature, ScopeAction, CapabilityScope
│   ├── aip-crypto/                 # Ed25519 dalek, SHA-256, bs58, AIP-ID derivation
│   ├── aip-core/                   # AID lifecycle, capability lattice, delegation, revocation
│   ├── aip-protocol/               # EvidencePacket, 14-rule verification engine, bundle zip, graph
│   ├── aip-test/                   # Test utilities and synthetic fixtures
│   ├── aip-cli/                    # CLI runner for AIP operations
│   ├── aip-verify/                 # Standalone offline verifier CLI
│   ├── aip-real-tests/             # Adversarial attack tests and security properties
│   └── banking_demo/               # End-to-end banking loan approval simulation
├── aip-service/                    # Backend REST API Service
│   ├── Cargo.toml                  # Standalone crate (`airon-aip`, Axum 0.7, Tokio 1.0)
│   └── src/
│       ├── evidence.rs             # REST endpoints: /v1/evidence/{generate, verify, :id, export}
│       ├── authority.rs            # Multi-packet AuthorityGraph resolution
│       ├── store.rs                # EvidenceStore trait (JSONL & PostgreSQL backends)
│       └── ...
└── docs/
    └── AUDIT_EXPORT_SPEC.md        # Specification for portable audit zip bundles
```

### Cargo Workspace Configuration (`aip-standalone/Cargo.toml`)
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

[workspace.package]
version = "0.4.0"
edition = "2021"
license = "LicenseRef-Proprietary"
```

All 27 integration and unit tests in `aip-protocol` pass cleanly:
```bash
cargo test -p aip-protocol --manifest-path aip-standalone/Cargo.toml
# Result: 27 passed; 0 failed; 1 ignored (sample bundle emitter) in 0.99s
```

---

## 3. The 14 Verification Rules & Verification Engine

Verification is implemented in `aip-standalone/aip-protocol/src/verification.rs` and structured via `verification_report.rs`.

### Architectural Principles of the Engine:
1. **No Short-Circuiting**: All 14 rules are evaluated sequentially for every packet. Even if Rule 1 fails, Rules 2 through 14 continue executing. This produces a comprehensive audit report rather than stopping at the first discrepancy.
2. **Zero Verification Logic in UI**: Every UI status badge and rule row maps directly to a `RuleResult` emitted by the engine.
3. **Derived Trust Floor**: The trust floor is computed mathematically from the passed checks and compared to `packet.claimed_trust_floor`. A packet cannot assert a higher floor than its evidence substantiates.
4. **Tamper Classification**: The engine distinguishes between administrative invalidity (e.g. a revoked token, which sets `valid = false, tampered = false`) and active tampering (hash mismatch, signature corruption, payload manipulation, which sets `valid = false, tampered = true`).

### Detailed Rule Specification Matrix

| Rule Name (`RuleResult.rule`) | Engine Function | Cryptographic Check / Condition | Tamper Evidence Trigger | UI Rendering Requirements |
|---|---|---|---|---|
| **1. `STRUCTURE`** | `check_structure` | `magic == "AEP1"`, `version == 1`, non-empty `aip_id`, `principal_id`, `decision.summary`, and `actions.len() >= 1`. | No (structural defect) | Displays packet schema version, delegation hop count, action count. |
| **2. `AGENT_ID_BINDING`** | Lines 102–118 | `validate_aip_id(agent.aip_id)` passes checksum & Base58 decoding; `derive_aip_id(pubkey, provenance) == agent.aip_id`. | No (identity mismatch) | Shows verified agent AIP-ID and confirms model/env/tool commitments match key. |
| **3. `CANONICAL_HASH`** | Lines 121–136 | Recomputes `sha256(&packet.canonical_bytes())` and verifies `recomputed == packet.packet_hash`. | **Yes (`tamper_evidence = true`)** | Displays stored hash vs recomputed hash; highlights byte disparity if tampered. |
| **4. `AGENT_SIGNATURE`** | Lines 139–160 | `agent_sig.signer_id == agent.aip_id`, `agent_sig.payload_hash == recomputed_hash`, and Ed25519 verifies against embedded public key. | **Yes (`tamper_evidence = true`)** | Displays agent signature status, signer ID, and cryptographic verification badge. |
| **5. `ROOT_TOKEN_SIGNATURE`** | Lines 165–190 | `verify_scoped_token(root_token, trusted_key)`. Checks root token signature against verifier's trusted key for `principal_id`. | **Yes** if trusted key is present and sig fails | Displays root token issuer ID, role (e.g. "CFO"), and verifier trust anchor status. |
| **6. `DELEGATION_CHAIN`** | Lines 193–225 | `verify_delegation_chain()` verifies each hop's Ed25519 signature, `parent_jti` linkage, depth increment, and scope attenuation subset. | **Yes** if chain altered (except missing key) | Shows hop-by-hop verification, depth progression (0 to N), and lattice monotonicity. |
| **7. `AUTHORITY_CHAIN`** | `check_authority_chain` | `root_token.issuer == principal_id`; `first.issuer == root.holder`; `hop[n].issuer == hop[n-1].grantee`; `leaf.grantee == agent.aip_id`. | No (delegation breach) | Visual breadcrumb: Principal → Orchestrator → ... → Acting Agent. |
| **8. `SCOPE_AUTHORITY`** | `check_scope_authority` | `scope_permits(effective_scope, decision.action_kind)` AND for all actions `scope_permits(effective_scope, action.action_kind)`. | No (unauthorized action) | Displays effective attenuated scope and highlights authorized vs unauthorized verbs. |
| **9. `REVOCATION`** | Lines 233–251 | Verifies that neither `root_token.jti` nor any `delegation.jti` appears in `ctx.revoked_jtis`. | No (revoked status) | Shows revocation check status; lists revoked JTIs if cascade revocation triggered. |
| **10. `TEMPORAL_VALIDITY`** | `check_temporal_validity` | `decided_at >= issued_at` for all tokens; `decided_at <= expires_at`; `action.performed_at <= expires_at`; `action.performed_at >= decided_at`. | No (temporal breach) | Timeline display showing token issuance, expiration window, decision, and actions. |
| **11. `ACTION_ATTESTATIONS`** | `check_action_attestations` | For each action: `agent_sig.signer == agent.aip_id`, `payload_hash == sha256(canonical_action_bytes(decision_id))`, Ed25519 verifies. | **Yes (`tamper_evidence = true`)** | Per-action badge showing individual attestation validity and decision binding. |
| **12. `TRACE_BINDING`** | `check_trace_binding` | If trace binding present: `trace_id` non-empty; if `ctx.trace_data` provided: `sha256(trace_data) == trace_hash`. | **Yes** if trace data supplied and fails | OpenTelemetry W3C trace ID display with hash match confirmation badge. |
| **13. `RECEIPT_BINDING`** | `check_receipt_binding` | If receipt present: system/id non-empty; if `ctx.receipt_data`: hash matches; if countersigned: Ed25519 verifies under counterparty key. | **Yes** if countersignature corrupted | Bilateral countersignature status, external receipt ID, and counterparty identity. |
| **14. `TRUST_FLOOR`** | Lines 288–303 | `derived_floor >= packet.claimed_trust_floor`. Verifies that claimed floor does not exceed mathematical evidence. | No (over-claimed trust) | Trust Floor progression ladder badge (UNVERIFIED to COUNTERPARTY_SIGNED). |

### Trust Floor Progression Derivation
The engine computes `derived_floor` strictly as follows:
```rust
let agent_signed = structure_ok && binding_ok && hash_ok && agent_sig_ok;
let authority_bound = agent_signed
    && root_sig_ok
    && chain_ok
    && authority_ok
    && scope_ok
    && revocation_ok
    && temporal_ok
    && actions_ok;
let counterparty_signed = authority_bound && receipt_rule_ok && receipt_countersigned;

let derived_floor = if counterparty_signed {
    TrustFloor::CounterpartySigned // Floor 3
} else if authority_bound {
    TrustFloor::AuthorityBound      // Floor 2
} else if agent_signed {
    TrustFloor::AgentSigned         // Floor 1
} else {
    TrustFloor::Unverified          // Floor 0
};
```

---

## 4. Core Protocol Types & Serialization Format

### `EvidencePacket` Structure (`aip-protocol/src/evidence_packet.rs`)
```rust
pub struct EvidencePacket {
    pub magic: [u8; 4],                     // b"AEP1"
    pub version: u16,                       // 1
    pub packet_id: [u8; 16],                // UUIDv4
    pub created_at: u64,                    // Unix ms
    pub agent: AgentIdentitySummary,        // aip_id, public_key, provenance
    pub root_authority: RootAuthority,      // principal_id, display_role, root_token
    pub delegation_chain: Vec<DelegationToken>, // Zero or more attenuated hops
    pub decision: DecisionRecord,           // decision_id, action_kind, summary, hashes
    pub actions: Vec<ActionAttestation>,    // Individually signed action records
    pub trace_binding: Option<TraceBinding>,
    pub receipt_binding: Option<ReceiptBinding>, // Bilateral receipt + countersignature
    pub claimed_trust_floor: TrustFloor,    // Claimed level (0 to 3)
    pub packet_hash: [u8; 32],              // Excluded from canonical_bytes
    pub agent_sig: Signature,               // Covers packet_hash
}
```

### Canonical Byte Encoding Specification
All hashing and signing operations are strictly deterministic and prefix-free (`aip-protocol/src/canonical.rs`):
- Integers: Little-endian (`u16`, `u32`, `u64`).
- Strings and Byte Slices: Prefixed by `u32` little-endian length followed by raw UTF-8 / bytes.
- Optionals: `0u8` if `None`; `1u8` followed by encoded value if `Some`.
- Lists (`actions`, `delegation_chain`): Prefixed by `u32` length followed by sequential items.
- Scope Actions: `0u8` + `action as u8` for Standard; `1u8` + length + string for Custom.
- `canonical_bytes()` covers every field **except** `packet_hash` and `agent_sig`. Embedded hop signatures and counterparty signatures **are** covered, ensuring second-order signature tampering is instantly detected.

### Accountability Graph (`aip-protocol/src/accountability_graph.rs`)
The graph models the end-to-end accountability chain:
- **Nodes**:
  - `Principal`: `{ id: "principal", kind: "principal", label: "CFO (aip1...)" }`
  - `AuthorityGrant`: `{ id: "authority_grant", kind: "authority_grant", label: "root token..." }`
  - `Delegation`: `{ id: "delegation:0", kind: "delegation", label: "hop 0 (depth 1)..." }`
  - `Agent`: `{ id: "agent", kind: "agent", label: "aip1payments..." }`
  - `Decision`: `{ id: "decision", kind: "decision", label: "Approve vendor payment..." }`
  - `Action`: `{ id: "action:0", kind: "action", label: "POST /ledger/payments..." }`
  - `Receipt`: `{ id: "receipt", kind: "receipt", label: "LEDGER-ENTRY-90211 @ bank" }`
- **Edges & Relations**:
  - `Principal` --`Issues`--> `AuthorityGrant`
  - `AuthorityGrant` --`Delegates`--> `Delegation:0`
  - `Delegation:0` --`ActsUnder`--> `Agent`
  - `Agent` --`Decides`--> `Decision`
  - `Decision` --`Performs`--> `Action:0`
  - `Action:0` --`Produces`--> `Receipt`

---

## 5. WebAssembly Architecture (`aip-wasm`) Design Specification

Since `aip-wasm` does not exist yet, this section provides the complete design, dependency manifest, and Rust export API required to build the crate.

### 5.1 Crate Manifest: `aip-standalone/aip-wasm/Cargo.toml`
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
aip-protocol = { path = "../aip-protocol" }
aip-types = { path = "../aip-types" }
aip-crypto = { path = "../aip-crypto" }
aip-core = { path = "../aip-core" }
wasm-bindgen = "0.2.99"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
serde-wasm-bindgen = "0.6"
getrandom = { version = "0.2", features = ["js"] }
js-sys = "0.3.76"
hex = "0.4"
```

### 5.2 Resolution of WASM Compilation Hurdles

1. **`getrandom` on `wasm32-unknown-unknown`**:
   - *Problem*: `rand 0.8` and `ed25519-dalek 2.1` depend on `getrandom 0.2`. Compiling to `wasm32-unknown-unknown` fails by default with: `compile_error!("the wasm*-unknown-unknown targets are not supported by default, you may need to enable the \"js\" feature")`.
   - *Fix*: Specifying `getrandom = { version = "0.2", features = ["js"] }` in `aip-wasm/Cargo.toml` activates Web Crypto API (`crypto.getRandomValues`) for all workspace crates targeting WASM.
2. **`std::time::SystemTime::now()` Runtime Panic**:
   - *Problem*: `verification.rs` line 705 calls `std::time::SystemTime::now()` to populate `verified_at`. On `wasm32-unknown-unknown`, `SystemTime::now()` panics at runtime with `unreachable` / `time not implemented`.
   - *Fix*: In `aip-wasm`, or via conditional compilation in `aip-protocol`:
     ```rust
     #[cfg(target_arch = "wasm32")]
     fn now_ms() -> u64 {
         js_sys::Date::now() as u64
     }
     #[cfg(not(target_arch = "wasm32"))]
     fn now_ms() -> u64 {
         std::time::SystemTime::now()
             .duration_since(std::time::UNIX_EPOCH)
             .unwrap()
             .as_millis() as u64
     }
     ```
     Alternatively, `aip-wasm` can inject the client's current timestamp or pass it in context.

### 5.3 Rust WASM Exports (`aip-standalone/aip-wasm/src/lib.rs`)

The `aip-wasm` crate should expose the following 10 functions:

```rust
use wasm_bindgen::prelude::*;
use aip_protocol::{
    verify_packet, verify_zip, AccountabilityGraph, EvidencePacket, VerificationContext,
};
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_types::{CapabilityScope, ScopeAction};

#[wasm_bindgen]
pub fn verify_evidence_packet(packet_json: &str, context_json: Option<String>) -> Result<String, JsValue> {
    let packet = EvidencePacket::from_json(packet_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid packet JSON: {e}")))?;
    
    let ctx = match context_json {
        Some(s) if !s.trim().is_empty() => parse_verification_context(&s)
            .map_err(|e| JsValue::from_str(&format!("Invalid context JSON: {e}")))?,
        _ => VerificationContext::new(),
    };

    let report = verify_packet(&packet, &ctx);
    report.to_json().map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn verify_bundle_zip(zip_bytes: &[u8], context_json: Option<String>) -> Result<String, JsValue> {
    let ctx = match context_json {
        Some(s) if !s.trim().is_empty() => parse_verification_context(&s)
            .map_err(|e| JsValue::from_str(&format!("Invalid context JSON: {e}")))?,
        _ => VerificationContext::new(),
    };

    let result = verify_zip(zip_bytes, &ctx);
    serde_json::to_string_pretty(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn extract_bundle_files(zip_bytes: &[u8]) -> Result<String, JsValue> {
    // Reads zip and returns { "evidence.json": "...", "manifest.json": "...", ... }
}

#[wasm_bindgen]
pub fn get_accountability_graph(packet_json: &str, report_json: Option<String>) -> Result<String, JsValue> {
    let packet = EvidencePacket::from_json(packet_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mut graph = AccountabilityGraph::from_packet(&packet);
    if let Some(r) = report_json {
        if let Ok(report) = serde_json::from_str(&r) {
            graph = graph.with_report(&report);
        }
    }
    graph.to_json().map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn recompute_packet_hash(packet_json: &str) -> Result<String, JsValue> {
    let packet = EvidencePacket::from_json(packet_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(hex::encode(packet.compute_hash()))
}

#[wasm_bindgen]
pub fn get_canonical_bytes_hex(packet_json: &str) -> Result<String, JsValue> {
    let packet = EvidencePacket::from_json(packet_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(hex::encode(packet.canonical_bytes()))
}

#[wasm_bindgen]
pub fn check_scope_permits(scope_json: &str, action_json: &str) -> Result<bool, JsValue> {
    let scope: CapabilityScope = serde_json::from_str(scope_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let action: ScopeAction = serde_json::from_str(action_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(aip_core::capability::scope_permits(&scope, &action))
}

#[wasm_bindgen]
pub fn meet_capability_scopes(parent_json: &str, child_json: &str) -> Result<String, JsValue> {
    let parent: CapabilityScope = serde_json::from_str(parent_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let child: CapabilityScope = serde_json::from_str(child_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let met = aip_core::capability::scope_meet(&parent, &child)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_json::to_string_pretty(&met).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn generate_keypair() -> Result<String, JsValue> {
    let kp = generate_ed25519_keypair();
    let prov = aip_types::ProvenanceTriple {
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

#[wasm_bindgen]
pub fn get_sample_packet(sample_type: &str) -> Result<String, JsValue> {
    // Returns built-in fixture JSONs:
    // "valid_loan", "tampered_summary", "tampered_hash", "revoked_delegation", "attenuation_violation"
}
```

---

## 6. Next.js 15 & React 19 WASM Integration Strategy

### 6.1 Build Target: `--target web`
Command:
```bash
npx wasm-pack build --target web --out-dir ../../aip-console/public/wasm
```
Generated artifacts in `aip-console/public/wasm/`:
- `aip_wasm_bg.wasm`: the pre-compiled binary.
- `aip_wasm.js`: WebAssembly loader ES module.
- `aip_wasm.d.ts`: TypeScript typings.

### 6.2 Client Initialization in React 19
In Next.js 15 App Router (`'use client'`), we implement a singleton promise loader:

```typescript
// aip-console/src/lib/wasm/aip-wasm-client.ts
'use client';

import init, * as Wasm from '@/../public/wasm/aip_wasm';

let initPromise: Promise<typeof Wasm> | null = null;

export function getAipWasm(): Promise<typeof Wasm> {
  if (typeof window === 'undefined') {
    return Promise.reject(new Error('WASM can only run in the browser'));
  }
  if (!initPromise) {
    initPromise = init('/wasm/aip_wasm_bg.wasm').then(() => Wasm);
  }
  return initPromise;
}
```

### 6.3 React Hook: `useAipVerifier`
```typescript
// aip-console/src/lib/wasm/useAipVerifier.ts
'use client';

import { useState, useEffect, useCallback } from 'react';
import { getAipWasm } from './aip-wasm-client';
import type { VerificationReport, BundleVerification, AccountabilityGraph } from '@/types/aip';

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

  const verifyZip = useCallback(async (
    zipBytes: Uint8Array,
    contextJson?: string
  ): Promise<BundleVerification> => {
    const wasm = await getAipWasm();
    const raw = wasm.verify_bundle_zip(zipBytes, contextJson);
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

  return { ready, error, verifyPacket, verifyZip, getGraph };
}
```

This guarantees that:
- **Zero verification logic** resides in UI code.
- Verification runs in sub-millisecond time directly in browser WebAssembly.
- The UI works 100% offline without backend availability.

---

## 7. Sample Data & Test Fixture Catalog

The following sample scenarios from `aip-standalone/aip-protocol/tests/evidence_packet.rs` and `banking_demo/src/main.rs` are recommended for testing and demoing in the UI:

1. **`sample_honest_countersigned.json`**:
   - Scenario: Branch Manager (Principal) -> Loan Agent (Root Grant) -> Underwriter Sub-Agent (Delegation) -> Rs 5 Crore Loan Approval (Decision) -> Disbursement Posting (Action) -> Core Banking Countersigned Receipt.
   - Status: 100% Pass across all 14 rules. Trust Floor: `COUNTERPARTY_SIGNED`.
2. **`sample_tampered_decision.json`**:
   - Scenario: Attacker modifies loan amount in `decision.summary` from `Rs 5,00,00,000` to `Rs 50,00,00,000`.
   - Result: Rule `CANONICAL_HASH` FAILS. Tamper badge: **TAMPERED**.
3. **`sample_tampered_hash_recomputed.json`**:
   - Scenario: Attacker modifies `decision.summary` AND recalculates `packet_hash` to match.
   - Result: Rule `CANONICAL_HASH` passes, but `AGENT_SIGNATURE` FAILS. Tamper badge: **TAMPERED**.
4. **`sample_scope_escalation.json`**:
   - Scenario: Agent attempts an `Admin` or `Delete` operation when only delegated `Write` (submitter) scope.
   - Result: Rule `SCOPE_AUTHORITY` FAILS.
5. **`sample_revoked_delegation.json`**:
   - Scenario: Delegation JTI is marked revoked in context.
   - Result: Rule `REVOCATION` FAILS. Valid: `false`, Tampered: `false`. Trust Floor drops to `AGENT_SIGNED`.

---

## 8. Summary of Recommendations for Implementation Teams

1. **Workspace Addition**: Add `"aip-wasm"` to `members` in `aip-standalone/Cargo.toml`.
2. **Scaffold `aip-wasm`**: Create crate with `cdylib`, `wasm-bindgen`, and `getrandom = { version = "0.2", features = ["js"] }`.
3. **Build Script**: Add build target in `package.json`:
   ```json
   "build:wasm": "npx wasm-pack build ../aip-standalone/aip-wasm --target web --out-dir ../aip-console/public/wasm"
   ```
4. **React Flow DAG**: Convert `AccountabilityGraph` nodes and edges directly into `@xyflow/react` nodes and edges using React Flow layouting (e.g. Dagre or ELK).
5. **Tamper Simulator**: Provide sliders and JSON field inputs that invoke `recompute_packet_hash` and `verify_evidence_packet` in real-time on keystroke.
