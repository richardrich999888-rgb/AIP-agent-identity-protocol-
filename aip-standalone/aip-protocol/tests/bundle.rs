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

/// Returns (packet, report, trust ctx, signer_seed, signer_public).
fn fixture() -> (
    EvidencePacket,
    VerificationReport,
    VerificationContext,
    [u8; 32],
    [u8; 32],
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

    // Service signer key (distinct from agent/principal).
    let signer = generate_ed25519_keypair();
    let seed: [u8; 32] = signer.private_key.clone().try_into().unwrap();
    let public: [u8; 32] = signer.public_key.clone().try_into().unwrap();

    (packet, report, ctx, seed, public)
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
    let (packet, report, ctx, seed, public) = fixture();
    let zip = build_zip("acme", &packet, &report, &seed, &public).unwrap();

    // With issuer trust keys *and* an anchored bundle signer → full PASS.
    //
    // The signer anchor is required as of AUDIT B-4: a verification that did
    // not establish who exported the bundle is a warning, never a pass. This
    // test previously reached Pass with issuer keys alone, which is precisely
    // the state B-4 says a caller must not be able to mistake for
    // attribution.
    let ctx = ctx.trust_bundle_signer(&public);
    let v = verify_zip(&zip, &ctx);
    for c in &v.checks {
        assert_ne!(c.status, BundleStatus::Fail, "{}: {}", c.name, c.detail);
    }
    assert_eq!(v.overall, BundleStatus::Pass, "checks: {:?}", v.checks);
    assert_eq!(v.packet_id, packet.packet_id_hex());
}

#[test]
fn test_bundle_no_trust_keys_is_warning_not_fail() {
    let (packet, report, _ctx, seed, public) = fixture();
    let zip = build_zip("acme", &packet, &report, &seed, &public).unwrap();

    // No trust keys: integrity and signature pass; authority is unverifiable
    // and the bundle is unattributed → WARNING, still no failures.
    let v = verify_zip(&zip, &VerificationContext::new());
    assert_eq!(v.overall, BundleStatus::Warning, "checks: {:?}", v.checks);
    // No FAILs.
    assert!(v.checks.iter().all(|c| c.status != BundleStatus::Fail));
}

#[test]
fn test_bundle_tampered_content_detected() {
    let (packet, report, ctx, seed, public) = fixture();
    let zip = build_zip("acme", &packet, &report, &seed, &public).unwrap();

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
    let (packet, report, ctx, seed, public) = fixture();
    let zip = build_zip("acme", &packet, &report, &seed, &public).unwrap();

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
    let (packet, report, ctx, seed, public) = fixture();
    let zip = build_zip("acme", &packet, &report, &seed, &public).unwrap();

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
    let (packet, report, ctx, seed, public) = fixture();
    let zip = build_zip("acme", &packet, &report, &seed, &public).unwrap();

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
    let (packet, report, _ctx, seed, public) = fixture();
    let zip = build_zip("acme", &packet, &report, &seed, &public).unwrap();
    let out =
        std::env::var("AIP_BUNDLE_OUT").unwrap_or_else(|_| "/tmp/aip_sample_bundle.zip".into());
    std::fs::write(&out, zip).unwrap();
    eprintln!("wrote bundle to {out}");
}

// ═══ B-4 — the bundle signer must be anchored by the verifier ═══════════════
//
// The finding: `verify_bundle_signature` checks the manifest signature
// against `manifest.signer_public_key` — a key that arrives *inside the
// bundle*. That establishes internal consistency and nothing else. An
// attacker who fabricates an evidence bundle, signs it with a key they
// generated, and writes that key into the manifest produces a bundle on which
// every integrity check passes.
//
// These tests pin the separation: BUNDLE_SIGNATURE answers "is this manifest
// signed by the key it names", BUNDLE_SIGNER_TRUSTED answers "is that a key
// the verifier trusts", and only the second is attribution.

/// The R5a check from a verification, which every test below inspects.
fn signer_trust(
    v: &aip_protocol::bundle::BundleVerification,
) -> &aip_protocol::bundle::BundleCheck {
    v.checks
        .iter()
        .find(|c| c.name == "BUNDLE_SIGNER_TRUSTED")
        .expect("BUNDLE_SIGNER_TRUSTED must appear in every bundle verification")
}

/// A bundle built by an attacker: real structure, real hashes, real
/// signature — under a key of the attacker's own making. Returns the bundle
/// and the legitimate signer's public key, which the attacker does not hold.
fn forged_bundle() -> (Vec<u8>, [u8; 32]) {
    let (packet, report, _ctx, _real_seed, real_public) = fixture();
    let forger = generate_ed25519_keypair();
    let forger_seed: [u8; 32] = forger.private_key.clone().try_into().unwrap();
    let forger_public: [u8; 32] = forger.public_key.clone().try_into().unwrap();
    let zip = build_zip(
        "attacker-tenant",
        &packet,
        &report,
        &forger_seed,
        &forger_public,
    )
    .expect("a forger can build a well-formed bundle");
    (zip, real_public)
}

#[test]
fn a_forged_bundle_passes_the_signature_check_by_design() {
    // Not a defect being asserted as acceptable — a boundary being stated.
    // R5 is a consistency check. If this ever stops passing, R5 has quietly
    // changed meaning and the tests below are measuring something else.
    let (zip, _) = forged_bundle();
    let v = verify_zip(&zip, &VerificationContext::new());
    let sig = v
        .checks
        .iter()
        .find(|c| c.name == "BUNDLE_SIGNATURE")
        .expect("R5 present");
    assert_eq!(sig.status, BundleStatus::Pass);
    assert!(
        sig.detail.contains("does not establish who"),
        "R5's detail must not let a reader mistake it for attribution: {}",
        sig.detail
    );
}

#[test]
fn a_forged_bundle_is_refused_when_a_signer_is_anchored() {
    // The attack, closed. The verifier knows the real exporter's key; the
    // forged bundle names a different one.
    let (zip, legitimate_public) = forged_bundle();
    let ctx = VerificationContext::new().trust_bundle_signer(&legitimate_public);

    let v = verify_zip(&zip, &ctx);
    assert_eq!(
        signer_trust(&v).status,
        BundleStatus::Fail,
        "SECURITY (B-4): a bundle signed by an unanchored key was accepted"
    );
    assert_eq!(
        v.overall,
        BundleStatus::Fail,
        "SECURITY (B-4): the bundle verified overall despite an untrusted signer"
    );
}

#[test]
fn an_unanchored_verification_never_reports_pass() {
    // The epistemic rule. A verifier that did not ask who signed the bundle
    // must not return a clean result, because a caller reading
    // `overall == Pass` would take it as attribution.
    let (packet, report, _ctx, seed, public) = fixture();
    let zip = build_zip("acme", &packet, &report, &seed, &public).unwrap();

    let v = verify_zip(&zip, &VerificationContext::new());
    let trust = signer_trust(&v);
    assert_eq!(
        trust.status,
        BundleStatus::Warning,
        "an unanchored signer check must be a warning, not a pass"
    );
    assert_ne!(
        v.overall,
        BundleStatus::Pass,
        "SECURITY (B-4): a bundle verified clean with no signer anchor. A \
         caller cannot distinguish this from an attributed bundle."
    );
    assert!(
        trust
            .detail
            .contains("not that it came from anyone in particular"),
        "the warning must say what was not established: {}",
        trust.detail
    );
}

#[test]
fn a_genuine_bundle_passes_when_its_signer_is_anchored() {
    // The counterweight: anchoring must make attribution possible, not merely
    // make everything fail. Without this the tests above are satisfied by a
    // check that always refuses.
    let (packet, report, _ctx, seed, public) = fixture();
    let zip = build_zip("acme", &packet, &report, &seed, &public).unwrap();

    let v = verify_zip(
        &zip,
        &VerificationContext::new().trust_bundle_signer(&public),
    );
    let trust = signer_trust(&v);
    assert_eq!(trust.status, BundleStatus::Pass, "{}", trust.detail);
}

#[test]
fn anchoring_one_signer_does_not_anchor_another() {
    // Set membership, asserted rather than assumed: two anchored keys, a
    // third signer, still refused.
    let (packet, report, _ctx, seed, public) = fixture();
    let zip = build_zip("acme", &packet, &report, &seed, &public).unwrap();

    let other_a = generate_ed25519_keypair().public_key;
    let other_b = generate_ed25519_keypair().public_key;
    assert_ne!(other_a, public.to_vec());
    let ctx = VerificationContext::new()
        .trust_bundle_signer(&other_a)
        .trust_bundle_signer(&other_b);

    let v = verify_zip(&zip, &ctx);
    let trust = signer_trust(&v);
    assert_eq!(trust.status, BundleStatus::Fail);
    assert!(
        trust.detail.contains("2 anchored"),
        "the refusal must say how many anchors were consulted: {}",
        trust.detail
    );
}

#[test]
fn a_malformed_anchor_is_ignored_rather_than_trusted() {
    // A caller that passes a truncated key must not end up with a context
    // that trusts something unintended. The wrong-length key is dropped,
    // leaving no anchors — which is a warning, not a pass.
    let ctx = VerificationContext::new()
        .trust_bundle_signer(&[0u8; 31])
        .trust_bundle_signer(&[0u8; 33])
        .trust_bundle_signer(&[]);
    assert!(
        ctx.trusted_bundle_signers.is_empty(),
        "SECURITY (B-4): a malformed key became a trust anchor"
    );
}

#[test]
fn a_manifest_naming_a_malformed_signer_key_is_refused() {
    // The other direction: the bundle, not the caller, supplies nonsense.
    // With anchors present this must fail rather than warn — a manifest whose
    // signer field cannot be parsed is not merely unattributed.
    let (packet, report, _ctx, seed, public) = fixture();
    let zip = build_zip("acme", &packet, &report, &seed, &public).unwrap();

    let mut files = unzip(&zip);
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&files[F_MANIFEST]).expect("manifest parses");
    manifest["signer_public_key"] = serde_json::Value::String("not-hex".into());
    files.insert(
        F_MANIFEST.to_string(),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    );
    let tampered = rezip(&files);

    let v = verify_zip(
        &tampered,
        &VerificationContext::new().trust_bundle_signer(&public),
    );
    assert_eq!(
        signer_trust(&v).status,
        BundleStatus::Fail,
        "{}",
        signer_trust(&v).detail
    );
}
