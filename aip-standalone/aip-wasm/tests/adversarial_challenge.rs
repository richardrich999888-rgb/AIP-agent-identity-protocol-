//! Milestone 1 Adversarial Challenge & Stress Harness
//! Validates the 14-rule verification engine, canonical hashing,
//! tamper detection accuracy, and boundary edge cases.

use aip_crypto::sha256;
use aip_protocol::EvidencePacket;
use aip_wasm::samples::{build_honest_counterparty, generate_all_fixtures, serialize_context};
use aip_wasm::*;
use serde_json::Value;

// ─── Challenge 1: Canonical Bytes and Recomputed Hash Cryptographic Invariant ───

#[test]
fn challenge_recompute_packet_hash_matches_sha256_canonical_bytes() {
    let fixtures = generate_all_fixtures();
    let packets = [
        ("honest_counterparty", fixtures.honest_counterparty.packet),
        ("authority_bound", fixtures.authority_bound.packet),
        ("agent_signed", fixtures.agent_signed.packet),
        ("tampered_summary", fixtures.tampered_summary.packet),
    ];

    for (name, packet) in packets {
        let packet_json = packet.to_json().expect("serialize packet");

        // 1. Get canonical bytes hex via aip-wasm export
        let canonical_hex = get_canonical_bytes_hex(&packet_json)
            .unwrap_or_else(|e| panic!("get_canonical_bytes_hex failed for {name}: {e:?}"));
        let canonical_bytes = hex::decode(&canonical_hex).expect("valid hex");

        // 2. Independently compute SHA-256 over canonical bytes
        let direct_hash = sha256(&canonical_bytes);
        let direct_hash_hex = hex::encode(direct_hash);

        // 3. Get recomputed packet hash via aip-wasm export
        let recomputed_hex = recompute_packet_hash(&packet_json)
            .unwrap_or_else(|e| panic!("recompute_packet_hash failed for {name}: {e:?}"));

        // 4. Assert cryptographic equivalence
        assert_eq!(
            recomputed_hex, direct_hash_hex,
            "Recomputed hash must match SHA-256 of canonical bytes for {name}"
        );
        assert_eq!(
            recomputed_hex.len(),
            64,
            "SHA-256 hex must be exactly 64 characters for {name}"
        );
        assert_eq!(
            recomputed_hex,
            hex::encode(packet.compute_hash()),
            "Exported recomputed hash must match internal compute_hash for {name}"
        );
    }
}

// ─── Challenge 2: Complete 14-Rule Verification Ledger Mapping ───────────────────

#[test]
fn challenge_14_rules_complete_verification_mapping() {
    let fixtures = generate_all_fixtures();
    let packet_json = fixtures.honest_counterparty.packet.to_json().unwrap();
    let context_json = fixtures.honest_counterparty.context_json;

    let rep_str = verify_evidence_packet(&packet_json, Some(context_json))
        .expect("verify honest packet");
    let rep: Value = serde_json::from_str(&rep_str).expect("parse JSON report");

    // Dual compatibility checks
    assert_eq!(rep["overall_valid"], true);
    assert_eq!(rep["valid"], true);
    assert_eq!(rep["tamper_evidence"], false);
    assert_eq!(rep["tampered"], false);
    assert_eq!(rep["derived_trust_floor"], "COUNTERPARTY_SIGNED");
    assert_eq!(rep["trust_floor"], "COUNTERPARTY_SIGNED");

    let checks = rep["checks"].as_array().expect("checks array");
    assert_eq!(checks.len(), 14, "Exactly 14 rules must be evaluated");

    let expected_rules = [
        "STRUCTURE",
        "AGENT_ID_BINDING",
        "CANONICAL_HASH",
        "AGENT_SIGNATURE",
        "ROOT_TOKEN_SIGNATURE",
        "DELEGATION_CHAIN",
        "AUTHORITY_CHAIN",
        "SCOPE_AUTHORITY",
        "REVOCATION",
        "TEMPORAL_VALIDITY",
        "ACTION_ATTESTATIONS",
        "TRACE_BINDING",
        "RECEIPT_BINDING",
        "TRUST_FLOOR",
    ];

    for expected in expected_rules {
        let found = checks.iter().find(|c| c["rule"] == expected);
        assert!(
            found.is_some(),
            "Rule '{expected}' must exist in checks ledger"
        );
        let check = found.unwrap();
        assert_eq!(
            check["pass"], true,
            "Rule '{expected}' must pass for honest packet"
        );
        assert!(
            !check["detail"].as_str().unwrap().is_empty(),
            "Rule '{expected}' must have detailed explanation"
        );
    }
}

// ─── Challenge 3: Tamper Detection Accuracy — Hash and Signature Mutants ────────

#[test]
fn challenge_tamper_evidence_triggered_on_hash_and_signature_mutation() {
    let (honest_packet, honest_ctx) = build_honest_counterparty();
    let ctx_json = serialize_context(&honest_ctx);

    // Case A: Mutate decision summary without updating hash
    let mut tampered_a = honest_packet.clone();
    tampered_a.decision.summary = "Malicious transfer of $10,000,000.00 to Off-shore Corp".into();
    let rep_a_str = verify_evidence_packet(
        &tampered_a.to_json().unwrap(),
        Some(ctx_json.clone()),
    ).unwrap();
    let rep_a: Value = serde_json::from_str(&rep_a_str).unwrap();

    assert_eq!(rep_a["overall_valid"], false);
    assert_eq!(
        rep_a["tamper_evidence"], true,
        "tamper_evidence must be true when payload is mutated"
    );
    let hash_check = rep_a["checks"].as_array().unwrap().iter().find(|c| c["rule"] == "CANONICAL_HASH").unwrap();
    assert_eq!(hash_check["pass"], false);

    // Case B: Mutate payload AND recalculate packet_hash to bypass CANONICAL_HASH
    let mut tampered_b = honest_packet.clone();
    tampered_b.decision.summary = "Malicious transfer of $10,000,000.00 to Off-shore Corp".into();
    tampered_b.packet_hash = tampered_b.compute_hash(); // bypass rule 3
    let rep_b_str = verify_evidence_packet(
        &tampered_b.to_json().unwrap(),
        Some(ctx_json.clone()),
    ).unwrap();
    let rep_b: Value = serde_json::from_str(&rep_b_str).unwrap();

    assert_eq!(rep_b["overall_valid"], false);
    assert_eq!(
        rep_b["tamper_evidence"], true,
        "tamper_evidence must be true when hash was faked but signature fails"
    );
    let hash_check_b = rep_b["checks"].as_array().unwrap().iter().find(|c| c["rule"] == "CANONICAL_HASH").unwrap();
    assert_eq!(hash_check_b["pass"], true, "CANONICAL_HASH passes because hash was recalculated");
    let sig_check_b = rep_b["checks"].as_array().unwrap().iter().find(|c| c["rule"] == "AGENT_SIGNATURE").unwrap();
    assert_eq!(sig_check_b["pass"], false, "AGENT_SIGNATURE must catch tampered hash");

    // Case C: Corrupt agent signature bytes directly
    let mut tampered_c = honest_packet.clone();
    tampered_c.agent_sig.signature_bytes[0] ^= 0xAA;
    let rep_c_str = verify_evidence_packet(
        &tampered_c.to_json().unwrap(),
        Some(ctx_json.clone()),
    ).unwrap();
    let rep_c: Value = serde_json::from_str(&rep_c_str).unwrap();

    assert_eq!(rep_c["overall_valid"], false);
    assert_eq!(
        rep_c["tamper_evidence"], true,
        "tamper_evidence must be true when agent signature is corrupted"
    );
    let sig_check_c = rep_c["checks"].as_array().unwrap().iter().find(|c| c["rule"] == "AGENT_SIGNATURE").unwrap();
    assert_eq!(sig_check_c["pass"], false);
}

// ─── Challenge 4: Administrative Revocation vs. Forensic Tampering ───────────────

#[test]
fn challenge_tamper_evidence_false_on_token_revocation() {
    let (honest_packet, honest_ctx) = build_honest_counterparty();

    // 1. Revoke the delegation hop JTI
    let mut revoked_ctx_hop = honest_ctx.clone();
    let hop_jti = honest_packet.delegation_chain[0].jti;
    revoked_ctx_hop.revoked_jtis.insert(hop_jti);
    let ctx_hop_json = serialize_context(&revoked_ctx_hop);

    let rep_str = verify_evidence_packet(
        &honest_packet.to_json().unwrap(),
        Some(ctx_hop_json),
    ).unwrap();
    let rep: Value = serde_json::from_str(&rep_str).unwrap();

    assert_eq!(rep["overall_valid"], false, "Revoked token must fail overall verification");
    assert_eq!(
        rep["tamper_evidence"], false,
        "Administrative revocation must NOT trigger tamper_evidence"
    );
    assert_eq!(
        rep["tampered"], false,
        "tampered flag must be false on revocation"
    );
    let rev_check = rep["checks"].as_array().unwrap().iter().find(|c| c["rule"] == "REVOCATION").unwrap();
    assert_eq!(rev_check["pass"], false, "REVOCATION check must fail");
    assert!(rev_check["detail"].as_str().unwrap().contains("revoked"));

    // 2. Revoke the root token JTI
    let mut revoked_ctx_root = honest_ctx.clone();
    let root_jti = honest_packet.root_authority.root_token.jti;
    revoked_ctx_root.revoked_jtis.insert(root_jti);
    let ctx_root_json = serialize_context(&revoked_ctx_root);

    let rep_root_str = verify_evidence_packet(
        &honest_packet.to_json().unwrap(),
        Some(ctx_root_json),
    ).unwrap();
    let rep_root: Value = serde_json::from_str(&rep_root_str).unwrap();

    assert_eq!(rep_root["overall_valid"], false);
    assert_eq!(
        rep_root["tamper_evidence"], false,
        "Root token revocation must NOT trigger tamper_evidence"
    );
}

// ─── Challenge 5: Trust Anchor Absence vs. Tampered Root Signature ──────────────

#[test]
fn challenge_untrusted_issuer_is_not_tampered_but_bad_signature_is() {
    let (honest_packet, _) = build_honest_counterparty();

    // Context without CFO issuer key (verifiability gap)
    let empty_ctx = "{}";
    let rep_empty_str = verify_evidence_packet(
        &honest_packet.to_json().unwrap(),
        Some(empty_ctx.to_string()),
    ).unwrap();
    let rep_empty: Value = serde_json::from_str(&rep_empty_str).unwrap();

    assert_eq!(rep_empty["overall_valid"], false);
    assert_eq!(
        rep_empty["tamper_evidence"], false,
        "Missing trusted issuer key is an anchor gap, NOT tamper evidence"
    );
    let root_check = rep_empty["checks"].as_array().unwrap().iter().find(|c| c["rule"] == "ROOT_TOKEN_SIGNATURE").unwrap();
    assert_eq!(root_check["pass"], false);
    assert!(root_check["detail"].as_str().unwrap().contains("no trusted public key"));

    // Known CFO key in context, but root token signature corrupted
    let (_, honest_ctx) = build_honest_counterparty();
    let mut tampered_root_packet = honest_packet.clone();
    tampered_root_packet.root_authority.root_token.issuer_sig.signature_bytes[0] ^= 0x55;
    let rep_corrupt_str = verify_evidence_packet(
        &tampered_root_packet.to_json().unwrap(),
        Some(serialize_context(&honest_ctx)),
    ).unwrap();
    let rep_corrupt: Value = serde_json::from_str(&rep_corrupt_str).unwrap();

    assert_eq!(rep_corrupt["overall_valid"], false);
    assert_eq!(
        rep_corrupt["tamper_evidence"], true,
        "Forged or corrupted root signature under trusted issuer key MUST trigger tamper_evidence"
    );
}

// ─── Challenge 6: Structural and Schema Validation via Rust Deserializer ─────────

#[test]
fn challenge_structural_schema_validation() {
    // 1. Completely empty string
    let res_empty = EvidencePacket::from_json("");
    assert!(res_empty.is_err(), "Empty packet JSON must return Err");

    // 2. Malformed JSON syntax
    let res_syntax = EvidencePacket::from_json("{\"magic\": [65, 69, 80, 49], incomplete...");
    assert!(res_syntax.is_err(), "Invalid JSON syntax must return Err");

    // 3. Null bytes in input
    let res_null = EvidencePacket::from_json("{\x00\"packet_id\": 123}");
    assert!(res_null.is_err(), "Null bytes must return Err");

    // 4. Missing required structure fields
    let res_empty_obj = EvidencePacket::from_json("{}");
    assert!(res_empty_obj.is_err(), "Empty object must fail deserialization cleanly");

    // 5. Structure rule evaluation when magic bytes corrupted
    let (mut bad_magic_packet, honest_ctx) = build_honest_counterparty();
    bad_magic_packet.magic = [0, 0, 0, 0];
    let rep_str = verify_evidence_packet(
        &bad_magic_packet.to_json().unwrap(),
        Some(serialize_context(&honest_ctx)),
    ).unwrap();
    let rep: Value = serde_json::from_str(&rep_str).unwrap();
    assert_eq!(rep["overall_valid"], false);
    let struct_check = rep["checks"].as_array().unwrap().iter().find(|c| c["rule"] == "STRUCTURE").unwrap();
    assert_eq!(struct_check["pass"], false);
    assert!(struct_check["detail"].as_str().unwrap().contains("bad magic"));

    // 6. Structure rule evaluation when version is invalid
    let (mut bad_ver_packet, _) = build_honest_counterparty();
    bad_ver_packet.version = 99;
    let rep_ver_str = verify_evidence_packet(
        &bad_ver_packet.to_json().unwrap(),
        Some(serialize_context(&honest_ctx)),
    ).unwrap();
    let rep_ver: Value = serde_json::from_str(&rep_ver_str).unwrap();
    let struct_ver_check = rep_ver["checks"].as_array().unwrap().iter().find(|c| c["rule"] == "STRUCTURE").unwrap();
    assert_eq!(struct_ver_check["pass"], false);
    assert!(struct_ver_check["detail"].as_str().unwrap().contains("unsupported version"));
}

// ─── Challenge 7: Large Payload & Multibyte UTF-8 Boundary ───────────────────────

#[test]
fn challenge_large_payload_and_multibyte_utf8() {
    let (mut honest_packet, _) = build_honest_counterparty();

    // Large 100 KB payload string
    honest_packet.decision.summary = "Large audit payload: ".to_string() + &"Z".repeat(100_000);
    let packet_json = honest_packet.to_json().unwrap();

    let hash_hex = recompute_packet_hash(&packet_json).expect("hash 100KB payload");
    assert_eq!(hash_hex.len(), 64);

    let canon_hex = get_canonical_bytes_hex(&packet_json).expect("canon 100KB payload");
    assert!(canon_hex.len() > 100_000);

    // Multi-byte Unicode (Japanese, Arabic, Cyrillic, Emoji)
    let (mut utf8_packet, _) = build_honest_counterparty();
    utf8_packet.decision.summary = "送金承認: $50,000 — تأكيد التحويل — Подтверждение платежа 🛡️⚡".into();
    let utf8_json = utf8_packet.to_json().unwrap();

    let utf8_hash = recompute_packet_hash(&utf8_json).expect("hash utf8 payload");
    assert_eq!(utf8_hash.len(), 64);
}

// ─── Challenge 8: Capability Lattice Meet Operator Invariants ───────────────────

#[test]
fn challenge_lattice_meet_invariants() {
    // 1. Compatible subset intersection
    let parent = serde_json::json!({
        "allowed": ["Read", "Write", "Execute"],
        "denied": ["Admin"]
    }).to_string();

    let child = serde_json::json!({
        "allowed": ["Write", "Execute"],
        "denied": []
    }).to_string();

    let met_str = meet_capability_scopes(&parent, &child).expect("meet compatible");
    let met: Value = serde_json::from_str(&met_str).unwrap();

    assert_eq!(met["is_bottom"], false);
    assert!(check_scope_permits(&met_str, "\"Write\"").unwrap());
    assert!(check_scope_permits(&met_str, "\"Execute\"").unwrap());
    assert!(!check_scope_permits(&met_str, "\"Read\"").unwrap());
    assert!(!check_scope_permits(&met_str, "\"Admin\"").unwrap());

    // 2. Disjoint intersection produces bottom (is_bottom == true)
    let p_disjoint = serde_json::json!({
        "allowed": ["Read"],
        "denied": []
    }).to_string();

    let c_disjoint = serde_json::json!({
        "allowed": ["Write"],
        "denied": []
    }).to_string();

    let met_disjoint_str = meet_capability_scopes(&p_disjoint, &c_disjoint).expect("meet disjoint");
    let met_disjoint: Value = serde_json::from_str(&met_disjoint_str).unwrap();
    assert_eq!(met_disjoint["is_bottom"], true, "Disjoint meet must produce is_bottom = true");
    assert_eq!(met_disjoint["allowed"].as_array().unwrap().len(), 0);
}

// ─── Challenge 9: ZIP Bundle Verification & Extraction Resilience ────────────────

#[test]
fn challenge_bundle_zip_verification_and_extraction() {
    let fixtures = generate_all_fixtures();
    let ctx_json = fixtures.honest_counterparty.context_json;

    // 1. Valid bundle passes with 7 files extracted
    let rep_valid_str = verify_bundle_zip(&fixtures.valid_bundle_zip, Some(ctx_json.clone()))
        .expect("verify valid bundle");
    let rep_valid: Value = serde_json::from_str(&rep_valid_str).unwrap();
    assert_eq!(rep_valid["overall"], "PASS");
    assert_eq!(rep_valid["overall_pass"], true);

    let extracted_str = extract_bundle_files(&fixtures.valid_bundle_zip)
        .expect("extract valid bundle");
    let extracted: Value = serde_json::from_str(&extracted_str).unwrap();
    let map = extracted.as_object().unwrap();
    assert!(map.contains_key("evidence.json"));
    assert!(map.contains_key("manifest.json"));
    assert!(map.contains_key("bundle_signature.sig"));

    // 2. Tampered bundle fails bundle verification
    let rep_tampered_str = verify_bundle_zip(&fixtures.tampered_bundle_zip, Some(ctx_json))
        .expect("verify tampered bundle");
    let rep_tampered: Value = serde_json::from_str(&rep_tampered_str).unwrap();
    assert_eq!(rep_tampered["overall"], "FAIL");
    assert_eq!(rep_tampered["overall_pass"], false);
}
