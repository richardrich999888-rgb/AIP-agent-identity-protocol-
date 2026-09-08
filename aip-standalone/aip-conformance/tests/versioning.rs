//! Version and compatibility (Skill 28, R4).
//!
//! Two questions. Can an adapter's version change without a verifier
//! noticing? Can a proof package's? The answer must be no in both cases, and
//! the way to keep it no is to pin the constants here — so a bump shows up as
//! a failing conformance test rather than as a silent wire change.
//!
//! These are deliberately brittle. That is their job: a version constant that
//! can change without any test noticing is a version constant that is not
//! doing anything.

use aip_conformance::{Domain, CONFORMANCE_SCHEMA_VERSION};

/// Every wire-bearing constant, pinned. A change here is a wire change and
/// must be a deliberate, reviewed one.
#[test]
fn v1_the_wire_constants_are_what_they_were() {
    assert_eq!(aip_types::AIP_VERSION, 0x0004, "AIP identity/token version");
    assert_eq!(
        aip_types::EXECUTION_BINDING_VERSION,
        1,
        "execution binding structure version"
    );
    assert_eq!(
        aip_nexora::merkle::LeafKind::ALL.len(),
        9,
        "the proof tree's leaf kinds are frozen at nine; a tenth is a wire change"
    );
}

/// Every realising crate declares a version, and every profile's domain tag
/// carries one. A profile whose tag has no version cannot be superseded
/// without ambiguity.
#[test]
fn v2_every_profile_is_versioned_and_domain_separated() {
    for d in Domain::ALL {
        let r = d.realisation();
        assert!(
            r.profile_domain.starts_with("SYNTRIASS/AUTONOMY/"),
            "{}: {} is outside the reserved namespace",
            d.as_str(),
            r.profile_domain
        );
        assert!(
            r.profile_domain.ends_with("/v1"),
            "{}: {} carries no version",
            d.as_str(),
            r.profile_domain
        );
        assert!(
            r.profile_id.starts_with("vanian.") && r.profile_id.ends_with(".v1"),
            "{}: {} is not a versioned vanian id",
            d.as_str(),
            r.profile_id
        );
    }
}

/// The five profile version constants, pinned individually. Bumping one is a
/// compatibility event for that domain's consumers.
#[test]
fn v3_the_profile_versions_are_pinned() {
    assert_eq!(aip_uas::UAS_PROFILE_VERSION, 1);
    assert_eq!(aip_robotics::ROBOTICS_PROFILE_VERSION, 1);
    assert_eq!(aip_industrial::INDUSTRIAL_PROFILE_VERSION, 1);
    assert_eq!(aip_space::SPACE_PROFILE_VERSION, 1);
    assert_eq!(aip_enterprise::ENTERPRISE_PROFILE_VERSION, 1);
}

/// A proof package declaring a version the verifier does not implement is
/// refused before its key is consulted — the compatibility rule that matters,
/// because a newer package may commit to fields today's parser never reads.
#[test]
fn v4_a_head_at_an_unknown_version_is_refused_on_the_version() {
    use aip_crypto::generate_ed25519_keypair;
    use aip_nexora::commitment::*;
    use aip_nexora::merkle::LeafKind;

    let kp = generate_ed25519_keypair();
    let signer = NexoraSigner::new("conformance-v4", 1, &kp.private_key, &kp.public_key).unwrap();
    let anchors = NexoraTrustAnchors::new().trust("conformance-v4", 1, &kp.public_key);
    let mut log = CommitmentLog::new([0x44; 16]);
    log.append(LeafKind::Reconciliation, b"v4");
    let head = log.head(&signer, 1_700_000_000_000).unwrap();
    verify_signed_head(&head, &anchors).unwrap();

    // Validly signed at a version this build does not implement.
    let mut t = head.clone();
    t.version = NEXORA_VERSION + 1;
    let t = signer.resign(t).unwrap();
    assert!(
        matches!(
            verify_signed_head(&t, &anchors),
            Err(NexoraError::UnsupportedVersion(v)) if v == NEXORA_VERSION + 1
        ),
        "an unknown version is refused on the version, not on the signature"
    );
}

/// The conformance artifact's own schema is versioned, so a reviewer diffing
/// two artifacts can tell a semantic change from a schema change.
#[test]
fn v5_the_conformance_artifact_carries_its_own_schema_version() {
    assert_eq!(CONFORMANCE_SCHEMA_VERSION, 1);
    let m = aip_conformance::ConformanceMatrix::build();
    assert_eq!(m.schema_version, CONFORMANCE_SCHEMA_VERSION);
    assert!(
        m.to_json().contains("\"schema_version\": 1"),
        "the emitted artifact must carry its schema version"
    );
}
