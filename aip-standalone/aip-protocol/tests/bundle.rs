//! Audit-export bundle tests: build → verify, and every tamper scenario.

mod common;
use common::*;

use aip_protocol::bundle::{build_zip, verify_zip, BundleStatus, F_EVIDENCE, F_MANIFEST, F_SIG};
use aip_protocol::VerificationContext;

#[test]
fn test_bundle_build_and_verify_ok() {
    let (packet, report, ctx, seed, public) = fixture();
    let zip = build_zip("acme", &packet, &report, &seed, &public).unwrap();

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
    let (packet, report, _ctx, seed, public) = fixture();
    let zip = build_zip("acme", &packet, &report, &seed, &public).unwrap();

    // No trust keys: integrity + signature pass, authority unverifiable → WARNING.
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
