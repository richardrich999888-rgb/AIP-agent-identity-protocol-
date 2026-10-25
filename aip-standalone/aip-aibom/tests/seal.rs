//! The detached seal: authorship, never truth.

mod common;

use aip_aibom::seal::{verify_seal, Publisher, SealError};
use common::*;
use std::collections::BTreeMap;

fn setup() -> (Publisher, BTreeMap<String, Vec<u8>>) {
    let kp = aip_crypto::generate_ed25519_keypair();
    let p = Publisher::new("platform-team", &kp.private_key, &kp.public_key).unwrap();
    let mut anchors = BTreeMap::new();
    anchors.insert("platform-team".to_string(), kp.public_key.clone());
    (p, anchors)
}

#[test]
fn a_seal_verifies_over_the_manifest_it_was_made_for() {
    let (p, anchors) = setup();
    let m = manifest("agent");
    let s = p.seal(&m, 10).unwrap();
    assert_eq!(verify_seal(&s, &m, &anchors), Ok(()));
}

#[test]
fn a_seal_over_a_different_manifest_is_refused() {
    let (p, anchors) = setup();
    let m = manifest("agent");
    let s = p.seal(&m, 10).unwrap();
    let mut changed = m.clone();
    changed.permissions.allowed.push(custom("wire_transfer"));
    assert_eq!(
        verify_seal(&s, &changed, &anchors),
        Err(SealError::DigestMismatch)
    );
}

/// The key comes from the assessor's anchors. A seal cannot name its own.
#[test]
fn a_seal_from_an_unanchored_publisher_is_refused() {
    let (p, _) = setup();
    let m = manifest("agent");
    let s = p.seal(&m, 10).unwrap();
    assert_eq!(
        verify_seal(&s, &m, &BTreeMap::new()),
        Err(SealError::PublisherNotAnchored("platform-team".into()))
    );
}

#[test]
fn a_seal_under_the_wrong_key_is_refused() {
    let (p, _) = setup();
    let other = aip_crypto::generate_ed25519_keypair();
    let mut anchors = BTreeMap::new();
    anchors.insert("platform-team".to_string(), other.public_key);
    let m = manifest("agent");
    let s = p.seal(&m, 10).unwrap();
    assert_eq!(
        verify_seal(&s, &m, &anchors),
        Err(SealError::SignatureInvalid)
    );
}

#[test]
fn every_sealed_field_is_covered_by_the_signature() {
    let (p, anchors) = setup();
    let m = manifest("agent");
    let s = p.seal(&m, 10).unwrap();

    let mut t = s.clone();
    t.sealed_at_ms += 1;
    assert_eq!(
        verify_seal(&t, &m, &anchors),
        Err(SealError::PayloadHashMismatch)
    );

    let mut t = s.clone();
    t.publisher_id = "someone-else".into();
    let mut a2 = anchors.clone();
    a2.insert("someone-else".into(), anchors["platform-team"].clone());
    assert_eq!(verify_seal(&t, &m, &a2), Err(SealError::SignerMismatch));

    let mut t = s.clone();
    t.version = 2;
    assert_eq!(
        verify_seal(&t, &m, &anchors),
        Err(SealError::UnsupportedVersion(2))
    );
}

#[test]
fn a_publisher_with_a_mismatched_key_pair_is_refused_at_construction() {
    let a = aip_crypto::generate_ed25519_keypair();
    let b = aip_crypto::generate_ed25519_keypair();
    assert_eq!(
        Publisher::new("x", &a.private_key, &b.public_key).unwrap_err(),
        SealError::KeyPairMismatch
    );
}

#[test]
fn a_publishers_debug_output_never_contains_its_key() {
    let kp = aip_crypto::generate_ed25519_keypair();
    let p = Publisher::new("platform-team", &kp.private_key, &kp.public_key).unwrap();
    let shown = format!("{p:?}");
    assert!(!shown.contains(&format!("{:?}", kp.private_key)));
    assert!(!shown.contains(&hex::encode(&kp.private_key)));
}
