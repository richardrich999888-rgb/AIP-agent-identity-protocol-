use std::collections::BTreeMap;
use std::io::Cursor;
use wasm_bindgen::prelude::*;

use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_protocol::bundle::{verify_zip, BundleStatus};
use aip_protocol::{
    verify_packet, AccountabilityGraph, EvidencePacket, VerificationContext, VerificationReport,
};

pub mod context;
pub mod samples;
pub mod scope;

use context::parse_verification_context;
use scope::{parse_action_loose, parse_scope_loose};

#[wasm_bindgen(start)]
pub fn wasm_init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// 1. Verify EvidencePacket JSON against optional VerificationContext JSON.
/// Returns JSON VerificationReport with dual-compatibility keys.
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
        // Dual compatibility keys for PROJECT.md / e2e / Next.js UI
        map.insert("overall_valid".to_string(), serde_json::Value::Bool(report.valid));
        map.insert("valid".to_string(), serde_json::Value::Bool(report.valid));

        let tf_val = serde_json::to_value(report.trust_floor).unwrap_or(serde_json::Value::Null);
        map.insert("derived_trust_floor".to_string(), tf_val.clone());
        map.insert("trust_floor".to_string(), tf_val);

        map.insert("tamper_evidence".to_string(), serde_json::Value::Bool(report.tampered));
        map.insert("tampered".to_string(), serde_json::Value::Bool(report.tampered));
    }

    serde_json::to_string_pretty(&obj).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// 2. Verify audit export ZIP bundle bytes against optional context.
/// Returns JSON BundleVerificationResult.
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

    let checks: Vec<serde_json::Value> = result
        .checks
        .iter()
        .map(|c| {
            serde_json::json!({
                "name": c.name,
                "status": c.status,
                "pass": c.status == BundleStatus::Pass,
                "detail": c.detail,
            })
        })
        .collect();

    let val = serde_json::json!({
        "overall": result.overall,
        "overall_pass": result.overall == BundleStatus::Pass,
        "bundle_id": result.bundle_id,
        "packet_id": result.packet_id,
        "signer_fingerprint": result.signer_fingerprint,
        "checks": checks,
    });

    serde_json::to_string_pretty(&val).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// 3. Reconstruct AccountabilityGraph from EvidencePacket JSON & optional VerificationReport JSON.
/// Returns JSON graph with React Flow dual edge support (from/to and source/target).
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
            if let Ok(report) = serde_json::from_str::<VerificationReport>(&rep_str) {
                graph = graph.with_report(&report);
            }
        }
    }

    let nodes: Vec<serde_json::Value> = graph
        .nodes
        .iter()
        .map(|n| {
            serde_json::json!({
                "id": n.id,
                "kind": n.kind,
                "label": n.label,
            })
        })
        .collect();

    let edges: Vec<serde_json::Value> = graph
        .edges
        .iter()
        .map(|e| {
            serde_json::json!({
                "from": e.from,
                "to": e.to,
                "source": e.from,
                "target": e.to,
                "relation": e.relation,
            })
        })
        .collect();

    let val = serde_json::json!({
        "packet_id": graph.packet_id,
        "claimed_trust_floor": graph.claimed_trust_floor,
        "derived_trust_floor": graph.derived_trust_floor,
        "nodes": nodes,
        "edges": edges,
    });

    serde_json::to_string_pretty(&val).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// 4. Recompute SHA-256 packet hash over canonical bytes.
#[wasm_bindgen]
pub fn recompute_packet_hash(packet_json: &str) -> Result<String, JsValue> {
    let packet = EvidencePacket::from_json(packet_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid EvidencePacket JSON: {e}")))?;
    Ok(hex::encode(packet.compute_hash()))
}

/// 5. Get canonical encoding bytes as lowercase hex string.
#[wasm_bindgen]
pub fn get_canonical_bytes_hex(packet_json: &str) -> Result<String, JsValue> {
    let packet = EvidencePacket::from_json(packet_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid EvidencePacket JSON: {e}")))?;
    Ok(hex::encode(packet.canonical_bytes()))
}

/// 6. Check if CapabilityScope permits a ScopeAction.
#[wasm_bindgen]
pub fn check_scope_permits(scope_json: &str, action_json: &str) -> Result<bool, JsValue> {
    let scope = parse_scope_loose(scope_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid scope JSON: {e}")))?;
    let action = parse_action_loose(action_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid action JSON: {e}")))?;

    Ok(aip_core::capability::scope_permits(&scope, &action))
}

/// 7. Compute Capability Lattice intersection (MEET operator ⊓).
#[wasm_bindgen]
pub fn meet_capability_scopes(parent_json: &str, child_json: &str) -> Result<String, JsValue> {
    let parent = parse_scope_loose(parent_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid parent scope JSON: {e}")))?;
    let child = parse_scope_loose(child_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid child scope JSON: {e}")))?;

    let met_opt = aip_core::capability::scope_intersection(&parent, &child);
    let (result_scope, is_bottom) = match met_opt {
        Some(met) => (met, false),
        None => {
            let mut denied = parent.denied.clone();
            for d in &child.denied {
                if !denied.contains(d) {
                    denied.push(d.clone());
                }
            }
            (
                aip_types::CapabilityScope {
                    allowed: vec![],
                    denied,
                },
                true,
            )
        }
    };

    let mut val = serde_json::to_value(&result_scope)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    if let Some(obj) = val.as_object_mut() {
        obj.insert("is_bottom".to_string(), serde_json::Value::Bool(is_bottom));
    }

    serde_json::to_string_pretty(&val).map_err(|e| JsValue::from_str(&e.to_string()))
}

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

/// 9. Generate Ed25519 keypair and derive AIP-ID with provenance.
#[wasm_bindgen]
pub fn generate_keypair() -> Result<String, JsValue> {
    let kp = generate_ed25519_keypair();
    let prov = aip_types::ProvenanceTriple {
        model_commitment: sha256(b"syntriass:console:model:v1"),
        environment_commitment: sha256(b"syntriass:console:browser-wasm"),
        toolchain_commitment: sha256(b"syntriass:console:toolchain:v0.4.0"),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_evidence_packet_honest() {
        let fixtures = samples::generate_all_fixtures();
        let packet_json = fixtures.honest_counterparty.packet.to_json().unwrap();
        let context_json = fixtures.honest_counterparty.context_json;

        let res = verify_evidence_packet(&packet_json, Some(context_json)).unwrap();
        let val: serde_json::Value = serde_json::from_str(&res).unwrap();

        assert_eq!(val["overall_valid"], true);
        assert_eq!(val["valid"], true);
        assert_eq!(val["derived_trust_floor"], "COUNTERPARTY_SIGNED");
        assert_eq!(val["trust_floor"], "COUNTERPARTY_SIGNED");
        assert_eq!(val["tamper_evidence"], false);
        assert_eq!(val["tampered"], false);
        assert_eq!(val["checks"].as_array().unwrap().len(), 14);
    }

    #[test]
    fn test_verify_evidence_packet_tampered_summary() {
        let fixtures = samples::generate_all_fixtures();
        let packet_json = fixtures.tampered_summary.packet.to_json().unwrap();
        let context_json = fixtures.honest_counterparty.context_json;

        let res = verify_evidence_packet(&packet_json, Some(context_json)).unwrap();
        let val: serde_json::Value = serde_json::from_str(&res).unwrap();

        assert_eq!(val["overall_valid"], false);
        assert_eq!(val["valid"], false);
        assert_eq!(val["tamper_evidence"], true);
        assert_eq!(val["tampered"], true);
    }

    #[test]
    fn test_verify_bundle_zip() {
        let fixtures = samples::generate_all_fixtures();
        let context_json = fixtures.honest_counterparty.context_json;

        // Valid zip
        let res_valid = verify_bundle_zip(&fixtures.valid_bundle_zip, Some(context_json.clone())).unwrap();
        let val_valid: serde_json::Value = serde_json::from_str(&res_valid).unwrap();
        assert_eq!(val_valid["overall"], "PASS");
        assert_eq!(val_valid["overall_pass"], true);

        // Tampered zip
        let res_tampered = verify_bundle_zip(&fixtures.tampered_bundle_zip, Some(context_json)).unwrap();
        let val_tampered: serde_json::Value = serde_json::from_str(&res_tampered).unwrap();
        assert_eq!(val_tampered["overall"], "FAIL");
        assert_eq!(val_tampered["overall_pass"], false);
    }

    #[test]
    fn test_accountability_graph() {
        let fixtures = samples::generate_all_fixtures();
        let packet_json = fixtures.honest_counterparty.packet.to_json().unwrap();
        let report_json = verify_evidence_packet(&packet_json, Some(fixtures.honest_counterparty.context_json)).unwrap();

        let graph_res = get_accountability_graph(&packet_json, Some(report_json)).unwrap();
        let graph: serde_json::Value = serde_json::from_str(&graph_res).unwrap();

        assert!(graph["nodes"].as_array().unwrap().len() >= 5);
        assert!(graph["edges"].as_array().unwrap().len() >= 4);

        // React Flow compatibility checks
        let first_edge = &graph["edges"][0];
        assert!(first_edge.get("source").is_some());
        assert!(first_edge.get("target").is_some());
        assert!(first_edge.get("from").is_some());
        assert!(first_edge.get("to").is_some());
    }

    #[test]
    fn test_hash_and_canonical_bytes() {
        let fixtures = samples::generate_all_fixtures();
        let packet_json = fixtures.honest_counterparty.packet.to_json().unwrap();

        let hash_hex = recompute_packet_hash(&packet_json).unwrap();
        assert_eq!(hash_hex.len(), 64);
        assert_eq!(hash_hex, hex::encode(fixtures.honest_counterparty.packet.packet_hash));

        let canon_hex = get_canonical_bytes_hex(&packet_json).unwrap();
        assert!(!canon_hex.is_empty());
    }

    #[test]
    fn test_scope_permits_and_meet() {
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
    fn test_extract_bundle_files() {
        let fixtures = samples::generate_all_fixtures();
        let json_map = extract_bundle_files(&fixtures.valid_bundle_zip).unwrap();
        let map: serde_json::Value = serde_json::from_str(&json_map).unwrap();

        assert!(map.get("evidence.json").is_some());
        assert!(map.get("manifest.json").is_some());
        assert!(map.get("bundle_signature.sig").is_some());
    }

    #[test]
    fn test_keypair_generation() {
        let kp_json = generate_keypair().unwrap();
        let val: serde_json::Value = serde_json::from_str(&kp_json).unwrap();

        assert!(val["aip_id"].as_str().unwrap().starts_with("aip1"));
        assert_eq!(val["public_key_hex"].as_str().unwrap().len(), 64);
        assert_eq!(val["private_key_hex"].as_str().unwrap().len(), 64);
        assert!(!val["public_key_base58"].as_str().unwrap().is_empty());
    }

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
    }

    #[test]
    fn test_self_verify_fixtures_all() {
        let fixtures = samples::generate_all_fixtures();
        samples::self_verify_fixtures(&fixtures).expect("All fixtures must pass self-verification");
    }
}
