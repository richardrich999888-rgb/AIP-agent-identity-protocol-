//! Audit-export bundle tests: build → verify, and every tamper scenario.

mod common;
use common::*;

use aip_crypto::generate_ed25519_keypair;
use aip_protocol::bundle::{build_zip, verify_zip, BundleStatus, F_EVIDENCE, F_MANIFEST, F_SIG};
use aip_protocol::VerificationContext;

#[test]
fn test_bundle_build_and_verify_ok() {
    let (packet, report, ctx, seed, public) = fixture();
    let zip = build_zip("acme", &packet, &report, &signer_custodian(&seed, &public)).unwrap();

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
    let zip = build_zip("acme", &packet, &report, &signer_custodian(&seed, &public)).unwrap();

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
    let zip = build_zip("acme", &packet, &report, &signer_custodian(&seed, &public)).unwrap();

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
    let zip = build_zip("acme", &packet, &report, &signer_custodian(&seed, &public)).unwrap();

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
    let zip = build_zip("acme", &packet, &report, &signer_custodian(&seed, &public)).unwrap();

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
    let zip = build_zip("acme", &packet, &report, &signer_custodian(&seed, &public)).unwrap();

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
    let zip = build_zip("acme", &packet, &report, &signer_custodian(&seed, &public)).unwrap();
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
        &signer_custodian(&forger_seed, &forger_public),
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
    let zip = build_zip("acme", &packet, &report, &signer_custodian(&seed, &public)).unwrap();

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
    let zip = build_zip("acme", &packet, &report, &signer_custodian(&seed, &public)).unwrap();

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
    let zip = build_zip("acme", &packet, &report, &signer_custodian(&seed, &public)).unwrap();

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
    let zip = build_zip("acme", &packet, &report, &signer_custodian(&seed, &public)).unwrap();

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
