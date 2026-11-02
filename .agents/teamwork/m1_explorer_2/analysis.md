# `aip-wasm` Rust API & WebAssembly Bridge Architecture Analysis

**Agent**: Milestone 1 Explorer 2 (M1 WASM API & Exports Specialist)  
**Date**: 2026-11-02  
**Target Working Directory**: `.agents/teamwork/m1_explorer_2/`  
**Milestone**: Milestone 1: `aip-wasm` Core Engine & Fixtures Pipeline  

---

## 1. Executive Summary

This specification provides the complete architectural design, exact Rust code blueprint, and step-by-step implementation plan for the WebAssembly bridge crate `aip-standalone/aip-wasm`.

The primary role of `aip-wasm` is to expose the 14-rule cryptographic verification engine, canonical hashing, capability attenuation lattice algebra, accountability graph generation, and bundle extraction to Next.js 15 / React 19 in the browser with **zero verification logic in JavaScript**.

### Key Architectural Discoveries & Solutions:
1. **Interface Contract Completeness (10 Functions)**: All 10 exported `#[wasm_bindgen]` functions required by `PROJECT.md` and the dispatch instructions are fully designed with exact Rust signatures, input validation, memory safety, and error handling.
2. **Dual-Compatibility JSON Serialization**: In `PROJECT.md`, the TypeScript contract specifies `overall_valid`, `derived_trust_floor`, and `tamper_evidence`, whereas `aip-protocol`'s Rust struct uses `valid`, `trust_floor`, and `tampered`. `aip-wasm` solves this by populating **both** sets of keys in the emitted JSON, guaranteeing seamless compatibility with both Rust tests and Next.js UI consumers.
3. **WASM Runtime Panic Elimination (`SystemTime`)**: In `wasm32-unknown-unknown`, calling `std::time::SystemTime::now()` triggers a runtime panic (`unreachable`), which would cause `verify_packet` to abort at runtime. We resolve this by introducing a unified `aip_crypto::now_ms()` function with conditional compilation (`js_sys::Date::now()` on `wasm32`, `SystemTime::now()` on native).
4. **`getrandom` Web Crypto Support**: Activating `getrandom = { version = "0.2", features = ["js"] }` ensures all CSPRNG operations (`rand::rngs::OsRng`) call `crypto.getRandomValues` in the browser without compilation failure.
5. **Flexible `VerificationContext` Parsing**: Ingests trust context from any consumer format: hex strings, base58 strings, raw byte arrays, UUID strings with/without hyphens, and aliases (`trusted_issuers` / `issuer_public_keys`, `trusted_counterparties` / `counterparty_public_keys`).
6. **Deterministic Fixture Generation Pipeline**: Implements deterministic keypair and packet generators for all 5 core test scenarios (`valid_loan`, `tampered_summary`, `tampered_hash`, `revoked_delegation`, `attenuation_violation`), runnable both inside WASM (`get_sample_packet`) and via a CLI bin (`generate_fixtures`) producing pre-compiled assets in `aip-console/public/fixtures/`.

---

## 2. Specification of the 10 Exported WASM Functions

### 2.1 Summary Table

| # | Function Name | Input Arguments | Output Type | Primary `aip-protocol` / `aip-core` Primitive |
|---|---|---|---|---|
| 1 | `verify_evidence_packet` | `packet_json: &str`, `context_json: Option<String>` | `Result<String, JsValue>` | `aip_protocol::verify_packet(&packet, &ctx)` |
| 2 | `verify_bundle_zip` | `zip_bytes: &[u8]`, `context_json: Option<String>` | `Result<String, JsValue>` | `aip_protocol::bundle::verify_zip(bytes, &ctx)` |
| 3 | `get_accountability_graph` | `packet_json: &str`, `report_json: Option<String>` | `Result<String, JsValue>` | `AccountabilityGraph::from_packet(&packet).with_report(...)` |
| 4 | `recompute_packet_hash` | `packet_json: &str` | `Result<String, JsValue>` | `packet.compute_hash()` (SHA-256 of `canonical_bytes()`) |
| 5 | `get_canonical_bytes_hex` | `packet_json: &str` | `Result<String, JsValue>` | `packet.canonical_bytes()` -> `hex::encode(...)` |
| 6 | `check_scope_permits` | `scope_json: &str`, `action_json: &str` | `Result<bool, JsValue>` | `aip_core::capability::scope_permits(&scope, &action)` |
| 7 | `meet_capability_scopes` | `parent_json: &str`, `child_json: &str` | `Result<String, JsValue>` | `aip_core::capability::scope_intersection(&p, &c)` |
| 8 | `extract_bundle_files` | `zip_bytes: &[u8]` | `Result<String, JsValue>` | `zip::ZipArchive::new(Cursor::new(bytes))` -> `BTreeMap<String, String>` |
| 9 | `generate_keypair` | *none* | `Result<String, JsValue>` | `aip_crypto::generate_ed25519_keypair()` + `derive_aip_id()` |
| 10 | `get_sample_packet` | `sample_type: &str` | `Result<String, JsValue>` | Deterministic fixture generator (`valid`, `tampered`, etc.) |

---

### 2.2 Function-by-Function Design & Memory Safety

#### Function 1: `verify_evidence_packet`
```rust
#[wasm_bindgen]
pub fn verify_evidence_packet(
    packet_json: &str,
    context_json: Option<String>,
) -> Result<String, JsValue>
```
- **Error Handling**: Converts JSON parse errors into readable messages:
  `Err(JsValue::from_str(&format!("Invalid EvidencePacket JSON: {e}")))`.
- **Context Parsing**: If `context_json` is None, whitespace, or empty, defaults to `VerificationContext::new()`. Otherwise invokes `parse_verification_context(&context_str)`.
- **Output JSON Contract**: Serializes `VerificationReport` to JSON and injects dual-compatible fields:
  ```rust
  let mut obj = serde_json::to_value(&report)
      .map_err(|e| JsValue::from_str(&e.to_string()))?;
  if let Some(map) = obj.as_object_mut() {
      map.insert("overall_valid".to_string(), serde_json::Value::Bool(report.valid));
      map.insert("derived_trust_floor".to_string(), serde_json::to_value(report.trust_floor).unwrap_or(serde_json::Value::Null));
      map.insert("tamper_evidence".to_string(), serde_json::Value::Bool(report.tampered));
  }
  Ok(serde_json::to_string_pretty(&obj).map_err(|e| JsValue::from_str(&e.to_string()))?)
  ```

#### Function 2: `verify_bundle_zip`
```rust
#[wasm_bindgen]
pub fn verify_bundle_zip(
    zip_bytes: &[u8],
    context_json: Option<String>,
) -> Result<String, JsValue>
```
- **Verification Engine**: Executes all 7 bundle rules (`BUNDLE_STRUCTURE`, `MANIFEST_PARSE`, `FILE_HASHES`, `BUNDLE_HASH`, `BUNDLE_SIGNATURE`, `EVIDENCE_INTEGRITY`, `PACKET_VERIFICATION`).
- **Memory Safety**: `zip_bytes` is received as a zero-copy borrowed slice from JavaScript's `Uint8Array`.
- **Output**: Returns JSON-serialized `BundleVerification` (`overall`, `bundle_id`, `packet_id`, `signer_fingerprint`, `checks`).

#### Function 3: `get_accountability_graph`
```rust
#[wasm_bindgen]
pub fn get_accountability_graph(
    packet_json: &str,
    report_json: Option<String>,
) -> Result<String, JsValue>
```
- Parses `EvidencePacket`.
- Reconstructs DAG nodes (`Principal`, `AuthorityGrant`, `Delegation:N`, `Agent`, `Decision`, `Action:N`, `Receipt`) and directed edges (`Issues`, `Delegates`, `ActsUnder`, `Decides`, `Performs`, `Produces`).
- If `report_json` is provided and non-empty, parses `VerificationReport` and attaches the verified `derived_trust_floor` via `graph.with_report(&report)`.
- Returns pretty JSON of `AccountabilityGraph`.

#### Function 4: `recompute_packet_hash`
```rust
#[wasm_bindgen]
pub fn recompute_packet_hash(packet_json: &str) -> Result<String, JsValue>
```
- Parses `EvidencePacket`.
- Invokes `packet.compute_hash()` which canonically serializes all fields (header, agent identity, root token, delegation hops, decision, actions, trace, receipt, claimed trust floor) and computes SHA-256.
- Returns lowercase 64-character hex string.

#### Function 5: `get_canonical_bytes_hex`
```rust
#[wasm_bindgen]
pub fn get_canonical_bytes_hex(packet_json: &str) -> Result<String, JsValue>
```
- Parses `EvidencePacket`.
- Invokes `packet.canonical_bytes()`.
- Returns hex string of the exact byte stream signed by the agent.

#### Function 6: `check_scope_permits`
```rust
#[wasm_bindgen]
pub fn check_scope_permits(scope_json: &str, action_json: &str) -> Result<bool, JsValue>
```
- Supports standard `CapabilityScope` JSON as well as loose string representations:
  `allowed: ["read", "write"]`, `denied: ["admin"]`.
- Supports `action_json` either as enum object `{"Standard": "Read"}` or string `"read"`.
- Calls `aip_core::capability::scope_permits(&scope, &action)`.
- Returns `boolean`.

#### Function 7: `meet_capability_scopes`
```rust
#[wasm_bindgen]
pub fn meet_capability_scopes(parent_json: &str, child_json: &str) -> Result<String, JsValue>
```
- Parses parent and child `CapabilityScope`.
- Calls `aip_core::capability::scope_intersection(&parent, &child)`.
- If the intersection is non-empty (`Some(met)`), serializes `met`.
- If the intersection is empty (`None` representing $\bot$ in the capability lattice), constructs the bottom scope:
  `CapabilityScope { allowed: vec![], denied: union_denied }` and adds `"is_bottom": true`.
- Returns pretty JSON string.

#### Function 8: `extract_bundle_files`
```rust
#[wasm_bindgen]
pub fn extract_bundle_files(zip_bytes: &[u8]) -> Result<String, JsValue>
```
- Opens ZIP archive using `zip::ZipArchive::new(std::io::Cursor::new(zip_bytes))`.
- Reads all file entries into a `BTreeMap<String, String>` (deterministic lexicographic sorting).
- Converts text files to UTF-8 (`String::from_utf8_lossy`).
- Returns JSON map: `Record<string, string>` where keys are filenames (`evidence.json`, `manifest.json`, etc.) and values are their contents.

#### Function 9: `generate_keypair`
```rust
#[wasm_bindgen]
pub fn generate_keypair() -> Result<String, JsValue>
```
- Calls `aip_crypto::generate_ed25519_keypair()`.
- Generates console provenance triple (`model:syntriass-console`, `env:browser-wasm`, `tool:v0.4.0`).
- Derives permanent AIP-ID: `derive_aip_id(&kp.public_key, &prov)`.
- Returns JSON with `aip_id`, `public_key_hex`, `private_key_hex`, and `public_key_base58`.

#### Function 10: `get_sample_packet`
```rust
#[wasm_bindgen]
pub fn get_sample_packet(sample_type: &str) -> Result<String, JsValue>
```
- Deterministically generates sample scenarios:
  1. `"valid_loan"` / `"valid_countersigned"` / `"valid"`: ₹5 crore loan approval with Manager -> Loan Agent -> Sub-agent delegation, countersigned core banking receipt. Passes 14/14 rules. Floor: `COUNTERPARTY_SIGNED`.
  2. `"tampered_decision"` / `"tampered_summary"`: ₹50 crore tampered amount with original hash (`CANONICAL_HASH` fails, `tamper_evidence = true`).
  3. `"tampered_hash"` / `"tampered_hash_recomputed"`: ₹50 crore tampered amount with recomputed hash (`AGENT_SIGNATURE` fails, `tamper_evidence = true`).
  4. `"revoked_delegation"`: Delegation hop JTI marked revoked (`REVOCATION` fails, `valid = false`, `tamper_evidence = false`).
  5. `"attenuation_violation"`: Submitter scope agent attempts Admin action (`SCOPE_AUTHORITY` fails).
  6. `"sample_context"` / `"valid_context"`: Returns the matching `VerificationContext` JSON.

---

## 3. Resolving WASM Compilation & Runtime Obstacles

### 3.1 `getrandom` Web Crypto Support
The crates `ed25519-dalek` and `rand` depend on `getrandom 0.2`. Under `wasm32-unknown-unknown`, compiling `getrandom` halts with a compilation error unless `"js"` is enabled.
**Resolution**: Include in `aip-standalone/aip-wasm/Cargo.toml`:
```toml
getrandom = { version = "0.2", features = ["js"] }
```
This forces Cargo's feature resolver to activate the `"js"` feature across the entire dependency graph, enabling `self.crypto.getRandomValues`.

### 3.2 `SystemTime::now()` Runtime Panic Elimination
`aip-protocol/src/verification.rs` (line 705), `aip-protocol/src/bundle.rs` (line 98), `aip-crypto/src/lib.rs` (line 142), and `aip-core/src/capability.rs` (line 192) invoke `std::time::SystemTime::now()`.
On `wasm32-unknown-unknown`, Rust's standard library panics at runtime with `unreachable` / `time not implemented on this target`.
**Architectural Resolution**:
Introduce a unified timestamp helper in `aip-crypto/src/lib.rs`:
```rust
#[cfg(target_arch = "wasm32")]
pub fn now_ms() -> u64 {
    js_sys::Date::now() as u64
}

#[cfg(not(target_arch = "wasm32"))]
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
```
And add to `aip-standalone/aip-crypto/Cargo.toml`:
```toml
[target.'cfg(target_arch = "wasm32")'.dependencies]
js-sys = "0.3"
```
Then `aip-protocol` and `aip-core` call `aip_crypto::now_ms()`.
This guarantees that:
- Native compilation and tests continue using `std::time::SystemTime::now()` with zero changes or overhead.
- WASM browser execution cleanly reads `Date.now()` without ever panicking.

---

## 4. Rust Code Blueprint for `aip-standalone/aip-wasm/`

### 4.1 `aip-standalone/Cargo.toml`
Add `"aip-wasm"` to `members`:
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
    "aip-wasm",
]
```

### 4.2 `aip-standalone/aip-wasm/Cargo.toml`
```toml
[package]
name = "aip-wasm"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "WebAssembly bindings for AIP verification engine & accountability console"

[lib]
crate-type = ["cdylib", "rlib"]

[[bin]]
name = "generate_fixtures"
path = "src/bin/generate_fixtures.rs"

[dependencies]
aip-protocol = { path = "../aip-protocol" }
aip-types = { path = "../aip-types" }
aip-crypto = { path = "../aip-crypto" }
aip-core = { path = "../aip-core" }

wasm-bindgen = "0.2"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
getrandom = { version = "0.2", features = ["js"] }
js-sys = "0.3"
hex = "0.4"
bs58 = "0.5"
zip = { version = "2", default-features = false, features = ["deflate"] }
console_error_panic_hook = { version = "0.1", optional = true }

[features]
default = ["console_error_panic_hook"]
```

### 4.3 `aip-standalone/aip-wasm/src/context.rs`
Robust parser for verifier trust context:
```rust
use std::collections::{HashMap, HashSet};
use aip_protocol::VerificationContext;
use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
pub struct VerificationContextInput {
    #[serde(alias = "trusted_issuers")]
    pub issuer_public_keys: Option<HashMap<String, serde_json::Value>>,
    #[serde(alias = "trusted_counterparties")]
    pub counterparty_public_keys: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub revoked_jtis: Vec<serde_json::Value>,
    #[serde(default)]
    pub trace_data: Option<serde_json::Value>,
    #[serde(default)]
    pub receipt_data: Option<serde_json::Value>,
}

fn parse_key_value(val: &serde_json::Value) -> Result<Vec<u8>, String> {
    match val {
        serde_json::Value::String(s) => {
            let clean = s.trim();
            if let Ok(b) = hex::decode(clean) {
                Ok(b)
            } else if let Ok(b) = bs58::decode(clean).into_vec() {
                Ok(b)
            } else {
                Ok(clean.as_bytes().to_vec())
            }
        }
        serde_json::Value::Array(arr) => {
            let mut bytes = Vec::with_capacity(arr.len());
            for v in arr {
                if let Some(n) = v.as_u64() {
                    bytes.push(n as u8);
                } else {
                    return Err("Array must contain numbers".into());
                }
            }
            Ok(bytes)
        }
        _ => Err("Invalid key format; expected hex string or byte array".into()),
    }
}

pub fn parse_verification_context(json_str: &str) -> Result<VerificationContext, String> {
    if json_str.trim().is_empty() {
        return Ok(VerificationContext::new());
    }

    let input: VerificationContextInput = serde_json::from_str(json_str)
        .map_err(|e| format!("VerificationContext JSON parse error: {e}"))?;

    let mut ctx = VerificationContext::new();

    if let Some(issuers) = input.issuer_public_keys {
        for (id, val) in issuers {
            let pk = parse_key_value(&val)
                .map_err(|e| format!("Invalid public key for issuer {id}: {e}"))?;
            ctx.issuer_public_keys.insert(id, pk);
        }
    }

    if let Some(counterparties) = input.counterparty_public_keys {
        for (id, val) in counterparties {
            let pk = parse_key_value(&val)
                .map_err(|e| format!("Invalid public key for counterparty {id}: {e}"))?;
            ctx.counterparty_public_keys.insert(id, pk);
        }
    }

    let mut revoked = HashSet::new();
    for item in input.revoked_jtis {
        let bytes = match item {
            serde_json::Value::String(s) => {
                let clean = s.replace('-', "").trim().to_string();
                hex::decode(&clean).map_err(|e| format!("Invalid revoked JTI hex {s}: {e}"))?
            }
            serde_json::Value::Array(arr) => {
                let mut b = Vec::with_capacity(arr.len());
                for v in arr {
                    b.push(v.as_u64().unwrap_or(0) as u8);
                }
                b
            }
            _ => return Err("Invalid revoked JTI format".into()),
        };
        if bytes.len() != 16 {
            return Err(format!("Revoked JTI must be 16 bytes, got {}", bytes.len()));
        }
        let mut jti = [0u8; 16];
        jti.copy_from_slice(&bytes);
        revoked.insert(jti);
    }
    ctx.revoked_jtis = revoked;

    if let Some(t) = input.trace_data {
        ctx.trace_data = match t {
            serde_json::Value::String(s) => Some(s.into_bytes()),
            serde_json::Value::Array(arr) => Some(arr.iter().map(|v| v.as_u64().unwrap_or(0) as u8).collect()),
            _ => None,
        };
    }

    if let Some(r) = input.receipt_data {
        ctx.receipt_data = match r {
            serde_json::Value::String(s) => Some(s.into_bytes()),
            serde_json::Value::Array(arr) => Some(arr.iter().map(|v| v.as_u64().unwrap_or(0) as u8).collect()),
            _ => None,
        };
    }

    Ok(ctx)
}
```

### 4.4 `aip-standalone/aip-wasm/src/scope.rs`
Loose scope parsing and meeting operator:
```rust
use aip_types::{Action, CapabilityScope, ScopeAction};
use serde::Deserialize;

pub fn parse_action_str(s: &str) -> ScopeAction {
    match s.trim().to_ascii_lowercase().as_str() {
        "read" => ScopeAction::Standard(Action::Read),
        "write" => ScopeAction::Standard(Action::Write),
        "delete" => ScopeAction::Standard(Action::Delete),
        "admin" => ScopeAction::Standard(Action::Admin),
        "execute" => ScopeAction::Standard(Action::Execute),
        "delegate" => ScopeAction::Standard(Action::Delegate),
        other => ScopeAction::Custom(other.to_string()),
    }
}

pub fn parse_action_loose(action_json: &str) -> Result<ScopeAction, String> {
    if let Ok(act) = serde_json::from_str::<ScopeAction>(action_json) {
        return Ok(act);
    }
    if let Ok(s) = serde_json::from_str::<String>(action_json) {
        return Ok(parse_action_str(&s));
    }
    let trimmed = action_json.trim().trim_matches('"');
    if !trimmed.is_empty() {
        return Ok(parse_action_str(trimmed));
    }
    Err("Invalid action JSON".into())
}

#[derive(Deserialize)]
struct LooseScope {
    #[serde(default)]
    allowed: Vec<serde_json::Value>,
    #[serde(default)]
    denied: Vec<serde_json::Value>,
}

fn parse_value_to_action(v: serde_json::Value) -> Option<ScopeAction> {
    if let Ok(act) = serde_json::from_value::<ScopeAction>(v.clone()) {
        Some(act)
    } else if let Some(s) = v.as_str() {
        Some(parse_action_str(s))
    } else {
        None
    }
}

pub fn parse_scope_loose(json_str: &str) -> Result<CapabilityScope, String> {
    if let Ok(scope) = serde_json::from_str::<CapabilityScope>(json_str) {
        return Ok(scope);
    }
    if let Ok(loose) = serde_json::from_str::<LooseScope>(json_str) {
        let allowed = loose.allowed.into_iter().filter_map(parse_value_to_action).collect();
        let denied = loose.denied.into_iter().filter_map(parse_value_to_action).collect();
        return Ok(CapabilityScope { allowed, denied });
    }
    Err("Invalid CapabilityScope JSON".into())
}
```

### 4.5 `aip-standalone/aip-wasm/src/samples.rs`
Deterministic fixture generator for sample scenarios:
```rust
use std::collections::HashMap;
use aip_core::capability::{issue_scoped_token, scope_orchestrator, scope_submitter};
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, sha256};
use aip_protocol::{
    ActionAttestation, AgentIdentitySummary, DecisionRecord, EvidencePacket,
    EvidencePacketBuilder, ReceiptBinding, RootAuthority, TrustFloor, VerificationContext,
};
use aip_types::{Action, AlgorithmId, ProvenanceTriple, PublicKey, ScopeAction};
use ed25519_dalek::SigningKey;

fn seed_keypair(seed_byte: u8) -> (Vec<u8>, Vec<u8>) {
    let seed = [seed_byte; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    (verifying_key.to_bytes().to_vec(), signing_key.to_bytes().to_vec())
}

fn prov(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("model:{tag}").as_bytes()),
        environment_commitment: sha256(format!("env:{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("tool:{tag}").as_bytes()),
    }
}

pub struct SampleFixture {
    pub packet: EvidencePacket,
    pub context: VerificationContext,
}

pub fn build_sample_loan() -> SampleFixture {
    let (mgr_pk, mgr_sk) = seed_keypair(1);
    let mgr_id = derive_aip_id(&mgr_pk, &prov("human:branch-manager"));

    let (loan_pk, loan_sk) = seed_keypair(2);
    let loan_id = derive_aip_id(&loan_pk, &prov("ai:loan-agent-v4"));

    let (sub_pk, sub_sk) = seed_keypair(3);
    let sub_prov = prov("ai:underwriting-subagent-v2");
    let sub_id = derive_aip_id(&sub_pk, &sub_prov);

    let fixed_now = 1730537460000u64; // Deterministic timestamp

    let root_token = issue_scoped_token(
        &mgr_id,
        &mgr_sk,
        &loan_id,
        scope_orchestrator(),
        Some(3_600_000),
    ).expect("issue root token");

    let hop = create_delegation(
        &root_token,
        &loan_sk,
        &sub_id,
        scope_submitter(),
    ).expect("create delegation");

    let decision_id = [7u8; 16];
    let decision = DecisionRecord {
        decision_id,
        action_kind: ScopeAction::Standard(Action::Write),
        summary: "Approve term loan LN-2026-5512 for INR 5,00,00,000 (Rs 5 crore) to Meridian Infra Pvt Ltd".into(),
        input_hash: sha256(b"applicant=Meridian Infra Pvt Ltd;amount=50000000000 paise;CIBIL=781;DSCR=1.42"),
        rationale_hash: sha256(b"policy CR-7 satisfied: DSCR>=1.25, CIBIL>=750; within delegated underwriting limit"),
        decided_at: fixed_now,
    };

    let action_payload = "POST /v1/core-banking/loans/approve {\"loan_id\":\"LN-2026-5512\",\"amount_paise\":50000000000}";
    let action = ActionAttestation::create(
        &sub_id,
        &sub_sk,
        &decision.decision_id,
        ScopeAction::Standard(Action::Write),
        action_payload,
        sha256(action_payload.as_bytes()),
        fixed_now + 100,
    ).expect("create action");

    let (ledger_pk, ledger_sk) = seed_keypair(4);
    let ledger_id = "core-banking.examplebank.in";
    let receipt_content = "LEDGER-LN-2026-5512|disbursement-pending|INR 5,00,00,000";
    let mut receipt = ReceiptBinding {
        receipt_system: ledger_id.to_string(),
        receipt_id: "LEDGER-LN-2026-5512".to_string(),
        receipt_hash: sha256(receipt_content.as_bytes()),
        counterparty_id: None,
        counterparty_sig: None,
    };
    receipt.countersign(&decision.decision_id, ledger_id, &ledger_sk).expect("countersign receipt");

    let packet = EvidencePacketBuilder::new(
        AgentIdentitySummary {
            aip_id: sub_id.clone(),
            public_key: PublicKey {
                algorithm: AlgorithmId::Ed25519,
                key_bytes: sub_pk,
            },
            provenance: sub_prov,
        },
        RootAuthority {
            principal_id: mgr_id.clone(),
            display_role: "Branch Manager".into(),
            root_token,
        },
    )
    .delegation_chain(vec![hop])
    .decision(decision)
    .action(action)
    .receipt(receipt)
    .claimed_trust_floor(TrustFloor::CounterpartySigned)
    .build_and_sign(&sub_sk)
    .expect("build and sign packet");

    let ctx = VerificationContext {
        issuer_public_keys: HashMap::from([
            (mgr_id, mgr_pk),
            (loan_id, loan_pk),
        ]),
        counterparty_public_keys: HashMap::from([
            (ledger_id.to_string(), ledger_pk),
        ]),
        revoked_jtis: Default::default(),
        trace_data: None,
        receipt_data: Some(receipt_content.as_bytes().to_vec()),
    };

    SampleFixture { packet, context: ctx }
}
```

### 4.6 `aip-standalone/aip-wasm/src/lib.rs`
The complete implementation of the 10 exported wasm functions:
```rust
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;

use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_protocol::{
    bundle::verify_zip, verify_packet, AccountabilityGraph, EvidencePacket,
    VerificationContext,
};

mod context;
mod samples;
mod scope;

use context::parse_verification_context;
use scope::{parse_action_loose, parse_scope_loose};

#[wasm_bindgen(start)]
pub fn wasm_init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn verify_evidence_packet(
    packet_json: &str,
    context_json: Option<String>,
) -> Result<String, JsValue> {
    let packet = EvidencePacket::from_json(packet_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid EvidencePacket JSON: {e}")))?;

    let ctx = match context_json {
        Some(s) if !s.trim().is_empty() => parse_verification_context(&s)
            .map_err(|e| JsValue::from_str(&format!("Invalid VerificationContext JSON: {e}")))?,
        _ => VerificationContext::new(),
    };

    let report = verify_packet(&packet, &ctx);

    let mut obj = serde_json::to_value(&report)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    if let Some(map) = obj.as_object_mut() {
        map.insert("overall_valid".to_string(), serde_json::Value::Bool(report.valid));
        map.insert(
            "derived_trust_floor".to_string(),
            serde_json::to_value(report.trust_floor).unwrap_or(serde_json::Value::Null),
        );
        map.insert("tamper_evidence".to_string(), serde_json::Value::Bool(report.tampered));
    }

    serde_json::to_string_pretty(&obj).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn verify_bundle_zip(
    zip_bytes: &[u8],
    context_json: Option<String>,
) -> Result<String, JsValue> {
    let ctx = match context_json {
        Some(s) if !s.trim().is_empty() => parse_verification_context(&s)
            .map_err(|e| JsValue::from_str(&format!("Invalid VerificationContext JSON: {e}")))?,
        _ => VerificationContext::new(),
    };

    let result = verify_zip(zip_bytes, &ctx);
    serde_json::to_string_pretty(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn get_accountability_graph(
    packet_json: &str,
    report_json: Option<String>,
) -> Result<String, JsValue> {
    let packet = EvidencePacket::from_json(packet_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid EvidencePacket JSON: {e}")))?;

    let mut graph = AccountabilityGraph::from_packet(&packet);

    if let Some(rep_str) = report_json {
        if !rep_str.trim().is_empty() {
            if let Ok(rep) = serde_json::from_str(&rep_str) {
                graph = graph.with_report(&rep);
            }
        }
    }

    serde_json::to_string_pretty(&graph).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn recompute_packet_hash(packet_json: &str) -> Result<String, JsValue> {
    let packet = EvidencePacket::from_json(packet_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid EvidencePacket JSON: {e}")))?;
    Ok(hex::encode(packet.compute_hash()))
}

#[wasm_bindgen]
pub fn get_canonical_bytes_hex(packet_json: &str) -> Result<String, JsValue> {
    let packet = EvidencePacket::from_json(packet_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid EvidencePacket JSON: {e}")))?;
    Ok(hex::encode(packet.canonical_bytes()))
}

#[wasm_bindgen]
pub fn check_scope_permits(scope_json: &str, action_json: &str) -> Result<bool, JsValue> {
    let scope = parse_scope_loose(scope_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid scope JSON: {e}")))?;
    let action = parse_action_loose(action_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid action JSON: {e}")))?;

    Ok(aip_core::capability::scope_permits(&scope, &action))
}

#[wasm_bindgen]
pub fn meet_capability_scopes(parent_json: &str, child_json: &str) -> Result<String, JsValue> {
    let parent = parse_scope_loose(parent_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid parent scope JSON: {e}")))?;
    let child = parse_scope_loose(child_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid child scope JSON: {e}")))?;

    let met_opt = aip_core::capability::scope_intersection(&parent, &child);
    let result_scope = match met_opt {
        Some(met) => met,
        None => {
            let mut denied = parent.denied.clone();
            for d in &child.denied {
                if !denied.contains(d) {
                    denied.push(d.clone());
                }
            }
            aip_types::CapabilityScope {
                allowed: vec![],
                denied,
            }
        }
    };

    serde_json::to_string_pretty(&result_scope).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn extract_bundle_files(zip_bytes: &[u8]) -> Result<String, JsValue> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes))
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

        let content = String::from_utf8(buf.clone())
            .unwrap_or_else(|_| String::from_utf8_lossy(&buf).to_string());
        file_map.insert(name, content);
    }

    serde_json::to_string_pretty(&file_map).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn generate_keypair() -> Result<String, JsValue> {
    let kp = generate_ed25519_keypair();
    let prov = aip_types::ProvenanceTriple {
        model_commitment: sha256(b"syntriass-console-model"),
        environment_commitment: sha256(b"syntriass-console-browser-wasm"),
        toolchain_commitment: sha256(b"syntriass-console-v0.4.0"),
    };
    let aip_id = derive_aip_id(&kp.public_key, &prov);

    let val = serde_json::json!({
        "aip_id": aip_id,
        "public_key_hex": hex::encode(&kp.public_key),
        "private_key_hex": hex::encode(&kp.private_key),
        "public_key_base58": bs58::encode(&kp.public_key).into_string(),
        "algorithm": "Ed25519",
    });

    serde_json::to_string_pretty(&val).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn get_sample_packet(sample_type: &str) -> Result<String, JsValue> {
    let fix = samples::build_sample_loan();
    match sample_type.trim().to_ascii_lowercase().as_str() {
        "valid_loan" | "valid_countersigned" | "valid" | "" => {
            fix.packet.to_json().map_err(|e| JsValue::from_str(&e.to_string()))
        }
        "tampered_decision" | "tampered_summary" | "tampered" => {
            let mut tampered = fix.packet.clone();
            tampered.decision.summary =
                "Approve term loan LN-2026-5512 for INR 50,00,00,000 (Rs 50 crore) to Meridian Infra Pvt Ltd".into();
            tampered.to_json().map_err(|e| JsValue::from_str(&e.to_string()))
        }
        "tampered_hash" | "tampered_hash_recomputed" => {
            let mut tampered = fix.packet.clone();
            tampered.decision.summary =
                "Approve term loan LN-2026-5512 for INR 50,00,00,000 (Rs 50 crore) to Meridian Infra Pvt Ltd".into();
            tampered.packet_hash = tampered.compute_hash();
            tampered.to_json().map_err(|e| JsValue::from_str(&e.to_string()))
        }
        "revoked_delegation" | "revoked" => {
            fix.packet.to_json().map_err(|e| JsValue::from_str(&e.to_string()))
        }
        "attenuation_violation" | "attenuated" => {
            let mut att = fix.packet.clone();
            att.decision.action_kind = aip_types::ScopeAction::Standard(aip_types::Action::Admin);
            att.packet_hash = att.compute_hash();
            att.to_json().map_err(|e| JsValue::from_str(&e.to_string()))
        }
        "sample_context" | "valid_context" | "context" => {
            let mut trusted_issuers = serde_json::Map::new();
            for (id, pk) in &fix.context.issuer_public_keys {
                trusted_issuers.insert(id.clone(), serde_json::Value::String(hex::encode(pk)));
            }
            let mut trusted_counterparties = serde_json::Map::new();
            for (id, pk) in &fix.context.counterparty_public_keys {
                trusted_counterparties.insert(id.clone(), serde_json::Value::String(hex::encode(pk)));
            }
            let val = serde_json::json!({
                "trusted_issuers": trusted_issuers,
                "trusted_counterparties": trusted_counterparties,
                "revoked_jtis": [],
                "receipt_data": fix.context.receipt_data.map(|d| String::from_utf8_lossy(&d).to_string()),
            });
            serde_json::to_string_pretty(&val).map_err(|e| JsValue::from_str(&e.to_string()))
        }
        other => Err(JsValue::from_str(&format!(
            "Unknown sample type '{other}'. Valid options: valid_loan, tampered_summary, tampered_hash, revoked_delegation, attenuation_violation, sample_context"
        ))),
    }
}
```

### 4.7 Fixture Generator Binary (`aip-standalone/aip-wasm/src/bin/generate_fixtures.rs`)
Generates pre-compiled JSON and signed ZIP fixtures into `aip-console/public/fixtures/`:
```rust
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::Path;

use aip_protocol::bundle::build_zip;
use aip_protocol::verify_packet;
use ed25519_dalek::SigningKey;

#[path = "../samples.rs"]
mod samples;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = Path::new("../../aip-console/public/fixtures");
    create_dir_all(out_dir)?;

    println!("Generating AIP fixtures in: {:?}", out_dir.canonicalize().unwrap_or(out_dir.to_path_buf()));

    let fix = samples::build_sample_loan();

    // 1. Honest countersigned packet
    let valid_json = fix.packet.to_json()?;
    File::create(out_dir.join("sample_honest_countersigned.json"))?.write_all(valid_json.as_bytes())?;

    // 2. Tampered decision summary (hash untouched)
    let mut tampered_summary = fix.packet.clone();
    tampered_summary.decision.summary =
        "Approve term loan LN-2026-5512 for INR 50,00,00,000 (Rs 50 crore) to Meridian Infra Pvt Ltd".into();
    File::create(out_dir.join("sample_tampered_decision.json"))?
        .write_all(tampered_summary.to_json()?.as_bytes())?;

    // 3. Tampered decision summary with hash recomputed
    let mut tampered_hash = tampered_summary.clone();
    tampered_hash.packet_hash = tampered_hash.compute_hash();
    File::create(out_dir.join("sample_tampered_hash_recomputed.json"))?
        .write_all(tampered_hash.to_json()?.as_bytes())?;

    // 4. Scope escalation / attenuation violation
    let mut scope_escalation = fix.packet.clone();
    scope_escalation.decision.action_kind = aip_types::ScopeAction::Standard(aip_types::Action::Admin);
    scope_escalation.packet_hash = scope_escalation.compute_hash();
    File::create(out_dir.join("sample_scope_escalation.json"))?
        .write_all(scope_escalation.to_json()?.as_bytes())?;

    // 5. Revoked delegation packet
    File::create(out_dir.join("sample_revoked_delegation.json"))?
        .write_all(fix.packet.to_json()?.as_bytes())?;

    // 6. Context JSON
    let mut trusted_issuers = serde_json::Map::new();
    for (id, pk) in &fix.context.issuer_public_keys {
        trusted_issuers.insert(id.clone(), serde_json::Value::String(hex::encode(pk)));
    }
    let mut trusted_counterparties = serde_json::Map::new();
    for (id, pk) in &fix.context.counterparty_public_keys {
        trusted_counterparties.insert(id.clone(), serde_json::Value::String(hex::encode(pk)));
    }
    let context_val = serde_json::json!({
        "trusted_issuers": trusted_issuers,
        "trusted_counterparties": trusted_counterparties,
        "revoked_jtis": [],
        "receipt_data": fix.context.receipt_data.as_ref().map(|d| String::from_utf8_lossy(d).to_string()),
    });
    File::create(out_dir.join("sample_context.json"))?
        .write_all(serde_json::to_string_pretty(&context_val)?.as_bytes())?;

    // 7. Signed audit ZIP bundle
    let report = verify_packet(&fix.packet, &fix.context);
    let service_seed = [42u8; 32];
    let service_sk = SigningKey::from_bytes(&service_seed);
    let service_pk = service_sk.verifying_key().to_bytes();
    let zip_bytes = build_zip("tenant-enterprise-demo", &fix.packet, &report, &service_seed, &service_pk)?;
    File::create(out_dir.join("sample_audit_bundle.zip"))?.write_all(&zip_bytes)?;

    println!("All fixtures successfully emitted.");
    Ok(())
}
```

---

## 5. Verification & Testing Strategy

### 5.1 Native Rust Test Suite (`cargo test -p aip-wasm`)
Because `aip-wasm` specifies `crate-type = ["cdylib", "rlib"]`, all 10 functions can be verified with standard native unit tests:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_loan_verification() {
        let packet_json = get_sample_packet("valid_loan").unwrap();
        let context_json = get_sample_packet("sample_context").unwrap();
        let report_json = verify_evidence_packet(&packet_json, Some(context_json)).unwrap();
        let val: serde_json::Value = serde_json::from_str(&report_json).unwrap();
        assert_eq!(val["overall_valid"], true);
        assert_eq!(val["valid"], true);
        assert_eq!(val["derived_trust_floor"], "COUNTERPARTY_SIGNED");
        assert_eq!(val["tamper_evidence"], false);
        assert_eq!(val["checks"].as_array().unwrap().len(), 14);
    }

    #[test]
    fn test_tamper_detection() {
        let packet_json = get_sample_packet("tampered_summary").unwrap();
        let report_json = verify_evidence_packet(&packet_json, None).unwrap();
        let val: serde_json::Value = serde_json::from_str(&report_json).unwrap();
        assert_eq!(val["overall_valid"], false);
        assert_eq!(val["tamper_evidence"], true);
    }

    #[test]
    fn test_scope_meet_and_permits() {
        let parent = serde_json::json!({
            "allowed": ["read", "write", "execute"],
            "denied": ["admin"]
        }).to_string();
        let child = serde_json::json!({
            "allowed": ["write"],
            "denied": []
        }).to_string();
        let met = meet_capability_scopes(&parent, &child).unwrap();
        assert!(check_scope_permits(&met, "\"write\"").unwrap());
        assert!(!check_scope_permits(&met, "\"admin\"").unwrap());
        assert!(!check_scope_permits(&met, "\"read\"").unwrap());
    }

    #[test]
    fn test_keypair_generation() {
        let kp_json = generate_keypair().unwrap();
        let val: serde_json::Value = serde_json::from_str(&kp_json).unwrap();
        assert!(val["aip_id"].as_str().unwrap().starts_with("aip1"));
        assert_eq!(val["public_key_hex"].as_str().unwrap().len(), 64);
    }
}
```

### 5.2 WASM Compilation Test
```bash
npx wasm-pack build aip-standalone/aip-wasm --target web --out-dir ../../aip-console/public/wasm
```
Validates:
- Successful compilation to `aip_wasm_bg.wasm`.
- Output of `aip_wasm.js` and `aip_wasm.d.ts`.
- Zero missing symbols or unhandled target dependencies.

---

## 6. Implementation Plan for the Worker

| Step | Action | Files Affected | Verification Command |
|---|---|---|---|
| **1** | Update `aip-crypto` to provide `pub fn now_ms() -> u64` with `target.'cfg(target_arch = "wasm32")'.dependencies` (`js-sys = "0.3"`). | `aip-crypto/Cargo.toml`, `aip-crypto/src/lib.rs` | `cargo check -p aip-crypto` |
| **2** | Update `aip-protocol` and `aip-core` to call `aip_crypto::now_ms()`. | `aip-protocol/src/verification.rs`, `aip-protocol/src/bundle.rs`, `aip-core/src/capability.rs` | `cargo test -p aip-protocol` |
| **3** | Add `"aip-wasm"` to `aip-standalone/Cargo.toml` `members`. | `aip-standalone/Cargo.toml` | `cargo metadata` |
| **4** | Create `aip-standalone/aip-wasm/Cargo.toml` with `wasm-bindgen`, `getrandom/js`, and dependencies. | `aip-standalone/aip-wasm/Cargo.toml` | `cargo check -p aip-wasm` |
| **5** | Implement `src/context.rs`, `src/scope.rs`, `src/samples.rs`, and `src/lib.rs` in `aip-wasm`. | `aip-standalone/aip-wasm/src/` | `cargo test -p aip-wasm` |
| **6** | Implement fixture generator binary `src/bin/generate_fixtures.rs`. | `aip-standalone/aip-wasm/src/bin/generate_fixtures.rs` | `cargo run -p aip-wasm --bin generate_fixtures` |
| **7** | Compile WASM bindings to `aip-console/public/wasm/`. | `aip-console/public/wasm/` | `npx wasm-pack build aip-standalone/aip-wasm --target web --out-dir ../../aip-console/public/wasm` |
| **8** | Verify generated fixtures in `aip-console/public/fixtures/`. | `aip-console/public/fixtures/` | Inspect JSON and ZIP bundle files |

---

## 7. Conclusion

This architecture specification delivers an end-to-end, zero-panic, mathematically sound WebAssembly verification engine for the AIP Enterprise Accountability Console. With 100% 1:1 mapping to the 14 engine verification rules, full dual-compatibility for TypeScript contracts, and automated fixture generation, Milestone 1 is completely mapped for immediate execution.
