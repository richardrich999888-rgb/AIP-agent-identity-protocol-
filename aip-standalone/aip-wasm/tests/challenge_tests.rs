//! Challenger 2 Empirical Stress & Adversarial Test Suite
//!
//! Validates:
//! 1. Bundle ZIP verification (`verify_bundle_zip`, `extract_bundle_files`)
//! 2. React Flow DAG formatting in `get_accountability_graph`
//! 3. Capability lattice algebra (`check_scope_permits`, `meet_capability_scopes`)

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Cursor, Write};

use aip_crypto::sha256;
use aip_wasm::samples;
use aip_wasm::{
    check_scope_permits, extract_bundle_files, get_accountability_graph, meet_capability_scopes,
    verify_bundle_zip, verify_evidence_packet,
};

// ============================================================================
// 1. BUNDLE ZIP VERIFICATION & EXTRACTION CHALLENGES
// ============================================================================

const EXPECTED_BUNDLE_FILES: [&str; 7] = [
    "evidence.json",
    "verification_report.json",
    "verification_report.md",
    "authority_graph.json",
    "authority_graph.dot",
    "manifest.json",
    "bundle_signature.sig",
];

#[test]
fn test_challenge_bundle_zip_extraction_all_7_files() {
    let fixtures = samples::generate_all_fixtures();

    // 1. Extract from valid bundle
    let files_json = extract_bundle_files(&fixtures.valid_bundle_zip)
        .expect("extract_bundle_files should succeed on valid bundle");
    let file_map: HashMap<String, String> =
        serde_json::from_str(&files_json).expect("Extracted JSON must parse into a map");

    // Verify all 7 files are present
    assert_eq!(file_map.len(), 7, "Bundle must contain exactly 7 files");
    for expected_file in EXPECTED_BUNDLE_FILES {
        assert!(
            file_map.contains_key(expected_file),
            "Extracted bundle missing expected file: {}",
            expected_file
        );
        let content = &file_map[expected_file];
        assert!(
            !content.is_empty(),
            "Extracted file {} is unexpectedly empty",
            expected_file
        );
    }

    // 2. Validate manifest.json integrity & exact match against extracted files
    let manifest_str = &file_map["manifest.json"];
    let manifest: serde_json::Value =
        serde_json::from_str(manifest_str).expect("manifest.json must be valid JSON");

    assert_eq!(manifest["schema_version"], "aip-bundle-1");
    let manifest_files = manifest["files"]
        .as_array()
        .expect("manifest must have files array");

    // The 5 content files are listed in manifest.files
    for file_entry in manifest_files {
        let name = file_entry["name"].as_str().unwrap();
        let expected_sha256 = file_entry["sha256"].as_str().unwrap();

        assert!(
            file_map.contains_key(name),
            "Manifest references file not extracted: {}",
            name
        );
        let content_bytes = file_map[name].as_bytes();
        let actual_sha256 = hex::encode(sha256(content_bytes));
        assert_eq!(
            actual_sha256, expected_sha256,
            "SHA-256 mismatch for extracted file {}",
            name
        );
    }

    // 3. Verify bundle_signature.sig format and length
    let sig_str = file_map["bundle_signature.sig"].trim();
    assert_eq!(
        sig_str.len(),
        128,
        "bundle_signature.sig must be a 128-char hex string (64 bytes Ed25519)"
    );
    assert!(
        hex::decode(sig_str).is_ok(),
        "bundle_signature.sig must be valid hex"
    );
}

#[test]
fn test_challenge_bundle_zip_verification_valid_and_tampered() {
    let fixtures = samples::generate_all_fixtures();
    let ctx_json = fixtures.honest_counterparty.context_json;

    // 1. Valid bundle with trusted context
    let res_valid = verify_bundle_zip(&fixtures.valid_bundle_zip, Some(ctx_json.clone()))
        .expect("verify_bundle_zip should succeed");
    let val_valid: serde_json::Value = serde_json::from_str(&res_valid).unwrap();

    assert_eq!(val_valid["overall"], "PASS");
    assert_eq!(val_valid["overall_pass"], true);
    let checks = val_valid["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 7, "Must contain all 7 verification checks");
    for check in checks {
        assert_eq!(
            check["status"], "PASS",
            "Check {} failed: {}",
            check["name"], check["detail"]
        );
        assert_eq!(check["pass"], true);
    }

    // 2. Valid bundle without context -> WARNING on PACKET_VERIFICATION
    let res_no_ctx = verify_bundle_zip(&fixtures.valid_bundle_zip, None)
        .expect("verify_bundle_zip without context should succeed");
    let val_no_ctx: serde_json::Value = serde_json::from_str(&res_no_ctx).unwrap();
    assert_eq!(val_no_ctx["overall"], "WARNING");
    assert_eq!(val_no_ctx["overall_pass"], false);

    // 3. Tampered bundle from fixtures
    let res_tampered = verify_bundle_zip(&fixtures.tampered_bundle_zip, Some(ctx_json))
        .expect("verify_bundle_zip should complete for tampered bundle");
    let val_tampered: serde_json::Value = serde_json::from_str(&res_tampered).unwrap();
    assert_eq!(val_tampered["overall"], "FAIL");
    assert_eq!(val_tampered["overall_pass"], false);
}

#[test]
fn test_challenge_bundle_zip_adversarial_tampering() {
    let fixtures = samples::generate_all_fixtures();
    let ctx_json = fixtures.honest_counterparty.context_json;

    // Helper to extract raw zip entries as a map
    let extract_raw_entries = |zip_bytes: &[u8]| -> HashMap<String, Vec<u8>> {
        let mut archive = zip::ZipArchive::new(Cursor::new(zip_bytes)).unwrap();
        let mut map = HashMap::new();
        for i in 0..archive.len() {
            let mut file = archive.by_index(i).unwrap();
            let mut buf = Vec::new();
            use std::io::Read;
            file.read_to_end(&mut buf).unwrap();
            map.insert(file.name().to_string(), buf);
        }
        map
    };

    // Helper to re-assemble zip from entries
    let build_zip_from_entries = |entries: &HashMap<String, Vec<u8>>| -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut zw = zip::ZipWriter::new(&mut cursor);
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            for (name, bytes) in entries {
                zw.start_file(name.clone(), opts).unwrap();
                zw.write_all(bytes).unwrap();
            }
            zw.finish().unwrap();
        }
        cursor.into_inner()
    };

    let base_entries = extract_raw_entries(&fixtures.valid_bundle_zip);

    // Challenge A: Missing manifest.json
    {
        let mut entries = base_entries.clone();
        entries.remove("manifest.json");
        let zip_bytes = build_zip_from_entries(&entries);
        let res = verify_bundle_zip(&zip_bytes, Some(ctx_json.clone())).unwrap();
        let val: serde_json::Value = serde_json::from_str(&res).unwrap();
        assert_eq!(val["overall"], "FAIL");
        let structure_check = val["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "BUNDLE_STRUCTURE")
            .unwrap();
        assert_eq!(structure_check["status"], "FAIL");
        assert!(structure_check["detail"]
            .as_str()
            .unwrap()
            .contains("manifest.json"));
    }

    // Challenge B: Missing bundle_signature.sig
    {
        let mut entries = base_entries.clone();
        entries.remove("bundle_signature.sig");
        let zip_bytes = build_zip_from_entries(&entries);
        let res = verify_bundle_zip(&zip_bytes, Some(ctx_json.clone())).unwrap();
        let val: serde_json::Value = serde_json::from_str(&res).unwrap();
        assert_eq!(val["overall"], "FAIL");
    }

    // Challenge C: Tampered evidence.json content
    {
        let mut entries = base_entries.clone();
        let mut ev_str = String::from_utf8(entries["evidence.json"].clone()).unwrap();
        assert!(ev_str.contains("INV-2026-0142"), "evidence.json must contain invoice ID");
        ev_str = ev_str.replace("INV-2026-0142", "INV-HACKED-9999");
        entries.insert("evidence.json".to_string(), ev_str.into_bytes());
        let zip_bytes = build_zip_from_entries(&entries);
        let res = verify_bundle_zip(&zip_bytes, Some(ctx_json.clone())).unwrap();
        let val: serde_json::Value = serde_json::from_str(&res).unwrap();
        assert_eq!(val["overall"], "FAIL");
        let file_hashes_check = val["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "FILE_HASHES")
            .unwrap();
        assert_eq!(file_hashes_check["status"], "FAIL");
    }

    // Challenge D: Tampered manifest (altered bundle_hash)
    {
        let mut entries = base_entries.clone();
        let mut manifest_str = String::from_utf8(entries["manifest.json"].clone()).unwrap();
        manifest_str = manifest_str.replace(
            "\"schema_version\": \"aip-bundle-1\"",
            "\"schema_version\": \"aip-bundle-tampered\"",
        );
        entries.insert("manifest.json".to_string(), manifest_str.into_bytes());
        let zip_bytes = build_zip_from_entries(&entries);
        let res = verify_bundle_zip(&zip_bytes, Some(ctx_json.clone())).unwrap();
        let val: serde_json::Value = serde_json::from_str(&res).unwrap();
        assert_eq!(val["overall"], "FAIL");
        let sig_check = val["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "BUNDLE_SIGNATURE")
            .unwrap();
        assert_eq!(sig_check["status"], "FAIL");
    }

    // Challenge E: Corrupt signature in bundle_signature.sig
    {
        let mut entries = base_entries.clone();
        let corrupted_sig = "deadbeef".repeat(16);
        entries.insert(
            "bundle_signature.sig".to_string(),
            corrupted_sig.into_bytes(),
        );
        let zip_bytes = build_zip_from_entries(&entries);
        let res = verify_bundle_zip(&zip_bytes, Some(ctx_json)).unwrap();
        let val: serde_json::Value = serde_json::from_str(&res).unwrap();
        assert_eq!(val["overall"], "FAIL");
        let sig_check = val["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "BUNDLE_SIGNATURE")
            .unwrap();
        assert_eq!(sig_check["status"], "FAIL");
    }

    // Challenge F: Completely invalid non-ZIP bytes
    {
        let bad_bytes = b"NOT_A_ZIP_FILE_AT_ALL_JUST_GARBAGE";
        let res = verify_bundle_zip(bad_bytes, None).unwrap();
        let val: serde_json::Value = serde_json::from_str(&res).unwrap();
        assert_eq!(val["overall"], "FAIL");
        assert_eq!(val["overall_pass"], false);
        assert_eq!(val["checks"][0]["name"], "BUNDLE_READABLE");
        assert_eq!(val["checks"][0]["status"], "FAIL");
    }

    // Challenge G: Empty bytes slice
    {
        let empty_bytes = b"";
        let res = verify_bundle_zip(empty_bytes, None).unwrap();
        let val: serde_json::Value = serde_json::from_str(&res).unwrap();
        assert_eq!(val["overall"], "FAIL");
        assert_eq!(val["overall_pass"], false);
        assert_eq!(val["checks"][0]["name"], "BUNDLE_READABLE");
        assert_eq!(val["checks"][0]["status"], "FAIL");
    }
}

// ============================================================================
// 2. REACT FLOW DAG FORMATTING & REACHABILITY CHALLENGES
// ============================================================================

#[test]
fn test_challenge_react_flow_dag_structure_and_reachability() {
    let fixtures = samples::generate_all_fixtures();

    // 1. Honest Counterparty Packet DAG
    let packet_json = fixtures.honest_counterparty.packet.to_json().unwrap();
    let report_json = verify_evidence_packet(
        &packet_json,
        Some(fixtures.honest_counterparty.context_json.clone()),
    )
    .unwrap();

    let graph_json = get_accountability_graph(&packet_json, Some(report_json.clone())).unwrap();
    let graph: serde_json::Value = serde_json::from_str(&graph_json).unwrap();

    // Verify top-level properties
    assert_eq!(
        graph["packet_id"],
        fixtures.honest_counterparty.packet.packet_id_hex()
    );
    assert_eq!(
        graph["claimed_trust_floor"],
        "COUNTERPARTY_SIGNED"
    );
    assert_eq!(
        graph["derived_trust_floor"],
        "COUNTERPARTY_SIGNED"
    );

    let nodes = graph["nodes"].as_array().expect("nodes must be array");
    let edges = graph["edges"].as_array().expect("edges must be array");

    // Must contain nodes for Principal, AuthorityGrant, Delegation, Agent, Decision, Action, Receipt
    let mut node_ids: HashSet<String> = HashSet::new();
    let mut node_kinds: HashSet<String> = HashSet::new();

    for node in nodes {
        let id = node["id"].as_str().expect("node id must be string");
        let kind = node["kind"].as_str().expect("node kind must be string");
        let label = node["label"].as_str().expect("node label must be string");

        assert!(!id.is_empty());
        assert!(!label.is_empty());

        node_ids.insert(id.to_string());
        node_kinds.insert(kind.to_string());
    }

    assert!(node_kinds.contains("principal"), "Missing principal node");
    assert!(node_kinds.contains("authority_grant"), "Missing authority_grant node");
    assert!(node_kinds.contains("delegation"), "Missing delegation node");
    assert!(node_kinds.contains("agent"), "Missing agent node");
    assert!(node_kinds.contains("decision"), "Missing decision node");
    assert!(node_kinds.contains("action"), "Missing action node");
    assert!(node_kinds.contains("receipt"), "Missing receipt node");

    // Check React Flow Edge properties: source, target, from, to, relation
    let mut adj: HashMap<String, Vec<String>> = HashMap::new();
    for edge in edges {
        let from = edge["from"].as_str().expect("edge from must be string");
        let to = edge["to"].as_str().expect("edge to must be string");
        let source = edge["source"].as_str().expect("edge source must be string");
        let target = edge["target"].as_str().expect("edge target must be string");
        let relation = edge["relation"].as_str().expect("edge relation must be string");

        // React Flow compatibility invariants
        assert_eq!(from, source, "React Flow edge.source must equal edge.from");
        assert_eq!(to, target, "React Flow edge.target must equal edge.to");
        assert!(!relation.is_empty());

        assert!(node_ids.contains(from), "Edge from non-existent node: {}", from);
        assert!(node_ids.contains(to), "Edge to non-existent node: {}", to);

        adj.entry(from.to_string()).or_default().push(to.to_string());
    }

    // Reachability Challenge:
    // Every node in the accountability graph MUST be reachable from "principal"
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    let root = "principal".to_string();
    visited.insert(root.clone());
    queue.push_back(root);

    while let Some(curr) = queue.pop_front() {
        if let Some(neighbors) = adj.get(&curr) {
            for neighbor in neighbors {
                if visited.insert(neighbor.clone()) {
                    queue.push_back(neighbor.clone());
                }
            }
        }
    }

    for id in &node_ids {
        assert!(
            visited.contains(id),
            "Accountability node '{}' is not reachable from root principal! Broken DAG.",
            id
        );
    }
}

#[test]
fn test_challenge_react_flow_dag_variants_and_error_handling() {
    let fixtures = samples::generate_all_fixtures();

    // 1. Agent Signed Packet (No receipt node, no delegation hops)
    let agent_json = fixtures.agent_signed.packet.to_json().unwrap();
    let agent_graph_json = get_accountability_graph(&agent_json, None).unwrap();
    let agent_graph: serde_json::Value = serde_json::from_str(&agent_graph_json).unwrap();
    let agent_kinds: HashSet<String> = agent_graph["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["kind"].as_str().unwrap().to_string())
        .collect();

    assert!(agent_kinds.contains("principal"));
    assert!(agent_kinds.contains("authority_grant"));
    assert!(agent_kinds.contains("agent"));
    assert!(agent_kinds.contains("decision"));
    assert!(agent_kinds.contains("action"));
    assert!(!agent_kinds.contains("receipt"), "AgentSigned packet should have no receipt node");
    assert!(!agent_kinds.contains("delegation"), "AgentSigned packet should have no delegation node");

    // 2. Report Mismatch: Report for a different packet does not populate derived_trust_floor
    let different_report = serde_json::json!({
        "packet_id": "0000000000000000000000000000000000000000000000000000000000000000",
        "valid": true,
        "trust_floor": "COUNTERPARTY_SIGNED",
        "tampered": false,
        "checks": []
    }).to_string();

    let mismatched_graph_json = get_accountability_graph(&agent_json, Some(different_report)).unwrap();
    let mismatched_graph: serde_json::Value = serde_json::from_str(&mismatched_graph_json).unwrap();
    assert!(
        mismatched_graph["derived_trust_floor"].is_null(),
        "Mismatched report packet_id should NOT populate derived_trust_floor"
    );
}

// ============================================================================
// 3. CAPABILITY LATTICE ALGEBRA CHALLENGES
// ============================================================================

#[test]
fn test_challenge_capability_lattice_meet_and_bottom_flag() {
    // Standard named scopes:
    // ADMIN = allowed: all, denied: none
    // ORCHESTRATOR = allowed: [read, write, execute, delegate], denied: [admin]
    // AUDIT_READER = allowed: [read], denied: [write, admin, delete]
    // SUBMITTER = allowed: [write], denied: [admin, delete]

    let admin_scope = serde_json::json!({
        "allowed": ["read", "write", "execute", "delegate", "admin", "delete"],
        "denied": []
    }).to_string();

    let orchestrator_scope = serde_json::json!({
        "allowed": ["read", "write", "execute", "delegate"],
        "denied": ["admin"]
    }).to_string();

    let audit_reader_scope = serde_json::json!({
        "allowed": ["read"],
        "denied": ["write", "admin", "delete"]
    }).to_string();

    let submitter_scope = serde_json::json!({
        "allowed": ["write"],
        "denied": ["admin", "delete"]
    }).to_string();

    // Case 1: ADMIN ⊓ ORCHESTRATOR = ORCHESTRATOR (is_bottom = false)
    {
        let res = meet_capability_scopes(&admin_scope, &orchestrator_scope)
            .expect("meet_capability_scopes should succeed");
        let val: serde_json::Value = serde_json::from_str(&res).unwrap();
        assert_eq!(val["is_bottom"], false, "ADMIN ⊓ ORCHESTRATOR is not bottom");

        assert!(check_scope_permits(&res, "\"read\"").unwrap());
        assert!(check_scope_permits(&res, "\"write\"").unwrap());
        assert!(check_scope_permits(&res, "\"execute\"").unwrap());
        assert!(check_scope_permits(&res, "\"delegate\"").unwrap());
        assert!(!check_scope_permits(&res, "\"admin\"").unwrap());
    }

    // Case 2: ORCHESTRATOR ⊓ AUDIT_READER = { allowed: ["read"] } (is_bottom = false)
    {
        let res = meet_capability_scopes(&orchestrator_scope, &audit_reader_scope).unwrap();
        let val: serde_json::Value = serde_json::from_str(&res).unwrap();
        assert_eq!(val["is_bottom"], false);

        assert!(check_scope_permits(&res, "\"read\"").unwrap());
        assert!(!check_scope_permits(&res, "\"write\"").unwrap());
        assert!(!check_scope_permits(&res, "\"execute\"").unwrap());
        assert!(!check_scope_permits(&res, "\"admin\"").unwrap());
    }

    // Case 3: AUDIT_READER ⊓ SUBMITTER = ⊥ (is_bottom = true, allowed = [])
    // AUDIT_READER allows only read; SUBMITTER allows only write. Intersection is EMPTY!
    {
        let res = meet_capability_scopes(&audit_reader_scope, &submitter_scope).unwrap();
        let val: serde_json::Value = serde_json::from_str(&res).unwrap();
        assert_eq!(
            val["is_bottom"], true,
            "Disjoint scopes AUDIT_READER and SUBMITTER MUST yield is_bottom: true"
        );
        let allowed = val["allowed"].as_array().unwrap();
        assert!(
            allowed.is_empty(),
            "Empty intersection ⊥ must have empty allowed array"
        );

        // Neither read nor write should be permitted
        assert!(!check_scope_permits(&res, "\"read\"").unwrap());
        assert!(!check_scope_permits(&res, "\"write\"").unwrap());
    }

    // Case 4: Completely disjoint custom domains
    {
        let scope_finance = serde_json::json!({
            "allowed": ["finance:transfer", "finance:view_balance"],
            "denied": []
        }).to_string();

        let scope_infra = serde_json::json!({
            "allowed": ["k8s:deploy", "k8s:restart_pod"],
            "denied": []
        }).to_string();

        let res = meet_capability_scopes(&scope_finance, &scope_infra).unwrap();
        let val: serde_json::Value = serde_json::from_str(&res).unwrap();
        assert_eq!(val["is_bottom"], true);
        assert!(val["allowed"].as_array().unwrap().is_empty());
        assert!(!check_scope_permits(&res, "\"finance:transfer\"").unwrap());
        assert!(!check_scope_permits(&res, "\"k8s:deploy\"").unwrap());
    }

    // Case 5: Attenuation non-expansion invariant
    // Child tries to escalate by adding "admin" privilege that parent does not have
    {
        let parent = serde_json::json!({
            "allowed": ["read"],
            "denied": ["admin"]
        }).to_string();

        let malicious_child = serde_json::json!({
            "allowed": ["read", "admin"],
            "denied": []
        }).to_string();

        let res = meet_capability_scopes(&parent, &malicious_child).unwrap();
        let val: serde_json::Value = serde_json::from_str(&res).unwrap();
        assert_eq!(val["is_bottom"], false);

        assert!(check_scope_permits(&res, "\"read\"").unwrap());
        assert!(
            !check_scope_permits(&res, "\"admin\"").unwrap(),
            "Child cannot escalate to admin beyond parent's scope"
        );
    }
}

#[test]
fn test_challenge_scope_permits_loose_formats() {
    let scope_json = serde_json::json!({
        "allowed": ["read", "write", "custom:audit"],
        "denied": ["admin", "custom:forbidden"]
    }).to_string();

    // 1. Quoted string format
    assert!(check_scope_permits(&scope_json, "\"read\"").unwrap());
    assert!(check_scope_permits(&scope_json, "\"write\"").unwrap());
    assert!(check_scope_permits(&scope_json, "\"custom:audit\"").unwrap());
    assert!(!check_scope_permits(&scope_json, "\"admin\"").unwrap());
    assert!(!check_scope_permits(&scope_json, "\"custom:forbidden\"").unwrap());
    assert!(!check_scope_permits(&scope_json, "\"execute\"").unwrap());

    // 2. Unquoted string format
    assert!(check_scope_permits(&scope_json, "read").unwrap());
    assert!(check_scope_permits(&scope_json, "custom:audit").unwrap());
    assert!(!check_scope_permits(&scope_json, "admin").unwrap());

    // 3. Case insensitivity for standard actions
    assert!(check_scope_permits(&scope_json, "\"READ\"").unwrap());
    assert!(check_scope_permits(&scope_json, "\"Write\"").unwrap());

    // 4. Action object format: {"Standard": "Read"}
    let std_read_obj = serde_json::json!({"Standard": "Read"}).to_string();
    assert!(check_scope_permits(&scope_json, &std_read_obj).unwrap());
}
