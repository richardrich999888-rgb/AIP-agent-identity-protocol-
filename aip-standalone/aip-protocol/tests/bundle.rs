//! Audit-export bundle tests: build → verify, and every tamper scenario.

use std::collections::HashMap;
use std::io::{Cursor, Read, Write};

use aip_core::capability::{issue_scoped_token, scope_orchestrator, scope_submitter};
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_protocol::bundle::{build_zip, verify_zip, BundleStatus, F_EVIDENCE, F_MANIFEST, F_SIG};
use aip_protocol::{
    verify_packet, ActionAttestation, AgentIdentitySummary, DecisionRecord, EvidencePacket,
    EvidencePacketBuilder, RootAuthority, TrustFloor, VerificationContext, VerificationReport,
};
use aip_types::{Action, AlgorithmId, ProvenanceTriple, PublicKey, ScopeAction};

fn prov(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("m:{tag}").as_bytes()),
        environment_commitment: sha256(format!("e:{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("t:{tag}").as_bytes()),
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Returns (packet, report, trust ctx, signer custodian).
fn fixture() -> (
    EvidencePacket,
    VerificationReport,
    VerificationContext,
    aip_custody::DevCustodian,
) {
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo_kp.public_key, &prov("cfo"));
    let (orch_aid, orch_kp) = create_identity(prov("orch"), None).unwrap();
    let (agent_aid, agent_kp) = create_identity(prov("agent"), None).unwrap();

    let root_token = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &orch_aid.id,
        scope_orchestrator(),
        Some(3_600_000),
    )
    .unwrap();
    let hop = create_delegation(
        &root_token,
        &orch_kp.private_key,
        &agent_aid.id,
        scope_submitter(),
    )
    .unwrap();

    let now = now_ms();
    let decision = DecisionRecord {
        decision_id: aip_core::capability::random_jti(),
        action_kind: ScopeAction::Standard(Action::Write),
        summary: "Approve payment INV-9 for $1,000".into(),
        input_hash: sha256(b"inv-9"),
        rationale_hash: sha256(b"ok"),
        decided_at: now,
    };
    let action = ActionAttestation::create(
        &agent_aid.id,
        &agent_kp.private_key,
        &decision.decision_id,
        ScopeAction::Standard(Action::Write),
        "POST /ledger/payments",
        sha256(b"payload"),
        now + 1,
    )
    .unwrap();

    let packet = EvidencePacketBuilder::new(
        AgentIdentitySummary {
            aip_id: agent_aid.id.clone(),
            public_key: PublicKey {
                algorithm: AlgorithmId::Ed25519,
                key_bytes: agent_kp.public_key.clone(),
            },
            provenance: agent_aid.provenance.clone(),
        },
        RootAuthority {
            principal_id: cfo_id.clone(),
            display_role: "CFO".into(),
            root_token,
        },
    )
    .delegation_chain(vec![hop])
    .decision(decision)
    .action(action)
    .claimed_trust_floor(TrustFloor::AuthorityBound)
    .build_and_sign(&agent_kp.private_key)
    .unwrap();

    let ctx = VerificationContext::new()
        .trust_issuer(&cfo_id, &cfo_kp.public_key)
        .trust_issuer(&orch_aid.id, &orch_kp.public_key);
    let report = verify_packet(&packet, &ctx);
    assert!(report.valid);

    // Service signer key (distinct from agent/principal), held by a
    // development custodian: these are tests, and the class says so.
    let kp = generate_ed25519_keypair();
    let signer = aip_custody::DevCustodian::from_bytes(
        "bundle-test-signer",
        0,
        &kp.private_key,
        &kp.public_key,
    );

    (packet, report, ctx, signer)
}

/// Read a zip into a name→bytes map.
fn unzip(bytes: &[u8]) -> HashMap<String, Vec<u8>> {
    let mut a = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut m = HashMap::new();
    for i in 0..a.len() {
        let mut f = a.by_index(i).unwrap();
        let name = f.name().to_string();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        m.insert(name, buf);
    }
    m
}

/// Rebuild a zip from a name→bytes map (for crafting tampered bundles).
fn rezip(files: &HashMap<String, Vec<u8>>) -> Vec<u8> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zw = zip::ZipWriter::new(&mut cursor);
        let opts = zip::write::SimpleFileOptions::default();
        for (name, bytes) in files {
            zw.start_file(name, opts).unwrap();
            zw.write_all(bytes).unwrap();
        }
        zw.finish().unwrap();
    }
    cursor.into_inner()
}

#[test]
fn test_bundle_build_and_verify_ok() {
    let (packet, report, ctx, signer) = fixture();
    let zip = build_zip("acme", &packet, &report, &signer).unwrap();

    // With trust keys → full PASS.
    let v = verify_zip(&zip, &ctx);
    for c in &v.checks {
        assert_ne!(c.status, BundleStatus::Fail, "{}: {}", c.name, c.detail);
    }
    assert_eq!(v.overall, BundleStatus::Pass, "checks: {:?}", v.checks);
    assert_eq!(v.packet_id, packet.packet_id_hex());
}

#[test]
fn test_bundle_no_trust_keys_is_warning_not_fail() {
    let (packet, report, _ctx, signer) = fixture();
    let zip = build_zip("acme", &packet, &report, &signer).unwrap();

    // No trust keys: integrity + signature pass, authority unverifiable → WARNING.
    let v = verify_zip(&zip, &VerificationContext::new());
    assert_eq!(v.overall, BundleStatus::Warning, "checks: {:?}", v.checks);
    // No FAILs.
    assert!(v.checks.iter().all(|c| c.status != BundleStatus::Fail));
}

#[test]
fn test_bundle_tampered_content_detected() {
    let (packet, report, ctx, signer) = fixture();
    let zip = build_zip("acme", &packet, &report, &signer).unwrap();

    // Tamper a content file (the evidence) without updating the manifest hash.
    let mut files = unzip(&zip);
    let mut ev = files.get(F_EVIDENCE).unwrap().clone();
    ev.extend_from_slice(b" ");
    files.insert(F_EVIDENCE.to_string(), ev);
    let tampered = rezip(&files);

    let v = verify_zip(&tampered, &ctx);
    assert_eq!(v.overall, BundleStatus::Fail);
    let fh = v.checks.iter().find(|c| c.name == "FILE_HASHES").unwrap();
    assert_eq!(fh.status, BundleStatus::Fail);
}

#[test]
fn test_bundle_missing_file_detected() {
    let (packet, report, ctx, signer) = fixture();
    let zip = build_zip("acme", &packet, &report, &signer).unwrap();

    let mut files = unzip(&zip);
    files.remove(F_EVIDENCE);
    let broken = rezip(&files);

    let v = verify_zip(&broken, &ctx);
    assert_eq!(v.overall, BundleStatus::Fail);
    let st = v
        .checks
        .iter()
        .find(|c| c.name == "BUNDLE_STRUCTURE")
        .unwrap();
    assert_eq!(st.status, BundleStatus::Fail);
}

#[test]
fn test_bundle_signature_mismatch_detected() {
    let (packet, report, ctx, signer) = fixture();
    let zip = build_zip("acme", &packet, &report, &signer).unwrap();

    // Replace the signature with a valid-length but wrong signature.
    let mut files = unzip(&zip);
    files.insert(F_SIG.to_string(), hex::encode([0u8; 64]).into_bytes());
    let tampered = rezip(&files);

    let v = verify_zip(&tampered, &ctx);
    assert_eq!(v.overall, BundleStatus::Fail);
    let sig = v
        .checks
        .iter()
        .find(|c| c.name == "BUNDLE_SIGNATURE")
        .unwrap();
    assert_eq!(sig.status, BundleStatus::Fail);
}

#[test]
fn test_bundle_manifest_edit_breaks_signature() {
    let (packet, report, ctx, signer) = fixture();
    let zip = build_zip("acme", &packet, &report, &signer).unwrap();

    // Edit the manifest (e.g. change tenant) — the signature no longer matches.
    let mut files = unzip(&zip);
    let manifest = String::from_utf8(files.get(F_MANIFEST).unwrap().clone()).unwrap();
    let edited = manifest.replace("\"acme\"", "\"evil-tenant\"");
    assert_ne!(edited, manifest, "manifest should contain the tenant id");
    files.insert(F_MANIFEST.to_string(), edited.into_bytes());
    let tampered = rezip(&files);

    let v = verify_zip(&tampered, &ctx);
    assert_eq!(v.overall, BundleStatus::Fail);
    assert_eq!(
        v.checks
            .iter()
            .find(|c| c.name == "BUNDLE_SIGNATURE")
            .unwrap()
            .status,
        BundleStatus::Fail
    );
}

#[test]
#[ignore = "emits a sample bundle for CLI smoke testing"]
fn emit_sample_bundle() {
    let (packet, report, _ctx, signer) = fixture();
    let zip = build_zip("acme", &packet, &report, &signer).unwrap();
    let out =
        std::env::var("AIP_BUNDLE_OUT").unwrap_or_else(|_| "/tmp/aip_sample_bundle.zip".into());
    std::fs::write(&out, zip).unwrap();
    eprintln!("wrote bundle to {out}");
}
