//! Exit gate for the hybrid Ed25519 + ML-DSA-65 signature path.
//!
//! Four properties define it, and every one of them is a way the migration
//! could go wrong rather than a way it could go right:
//!
//!   1. **Both halves must verify.** If either alone sufficed, the second
//!      algorithm would be decoration and a break in one would forge.
//!   2. **The two eras cannot be confused.** The `AlgorithmId` is inside the
//!      signed bytes, so neither half can be lifted out of a hybrid signature
//!      and presented standalone, and no standalone signature can be
//!      relabelled `Hybrid`.
//!   3. **Nothing already sealed changes.** Every existing Ed25519 artefact
//!      verifies byte-identically, because the Ed25519 path is untouched.
//!   4. **The policy is the verifier's.** An institution decides what it
//!      accepts; an artefact cannot declare itself sufficient.

use aip_crypto::hybrid::*;
use aip_crypto::{generate_ed25519_keypair, sign_ed25519, verify_ed25519};
use aip_types::AlgorithmId;

const SIGNER: &str = "did:aip:collector:C1";
const PAYLOAD: &[u8] = b"an attested batch the institution will hold for seven years";

/// An Ed25519 keypair and an independent ML-DSA seed. Separate by design:
/// one compromised key must not yield both halves.
fn keys() -> (Vec<u8>, Vec<u8>, [u8; 32], Vec<u8>) {
    let ed = generate_ed25519_keypair();
    let mut seed = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let ml_public = ml_dsa_public_key_from_seed(&seed).expect("seed is 32 bytes");
    (
        ed.private_key.to_vec(),
        ed.public_key.to_vec(),
        seed,
        ml_public,
    )
}

// ── 1. Both halves, or refuse ─────────────────────────────────────────────

#[test]
fn h01_a_hybrid_signature_verifies_under_both_keys() {
    let (ed_priv, ed_pub, seed, ml_pub) = keys();
    let sig = sign_hybrid(&ed_priv, &seed, SIGNER, PAYLOAD).unwrap();

    assert_eq!(sig.algorithm, AlgorithmId::Hybrid);
    assert_eq!(sig.signer_id, SIGNER);
    assert_eq!(
        sig.signature_bytes.len(),
        4 + ED25519_SIGNATURE_LEN + 4 + ML_DSA_65_SIGNATURE_LEN,
        "the encoding is length-prefixed and exactly sized"
    );
    verify_hybrid(&ed_pub, &ml_pub, &sig).expect("both halves verify");
}

#[test]
fn h02_a_wrong_ed25519_key_fails_even_though_the_ml_dsa_half_is_good() {
    // The whole point: one good half is not enough.
    let (ed_priv, _ed_pub, seed, ml_pub) = keys();
    let sig = sign_hybrid(&ed_priv, &seed, SIGNER, PAYLOAD).unwrap();
    let other = generate_ed25519_keypair();
    assert_eq!(
        verify_hybrid(&other.public_key, &ml_pub, &sig),
        Err(HybridError::Ed25519ComponentInvalid)
    );
}

#[test]
fn h03_a_wrong_ml_dsa_key_fails_even_though_the_ed25519_half_is_good() {
    // The direction that matters most for the migration's purpose: if
    // Ed25519 is one day broken, this is the check that still has to hold.
    let (ed_priv, ed_pub, seed, _ml_pub) = keys();
    let sig = sign_hybrid(&ed_priv, &seed, SIGNER, PAYLOAD).unwrap();
    let (_, _, _other_seed, other_ml_pub) = keys();
    assert_eq!(
        verify_hybrid(&ed_pub, &other_ml_pub, &sig),
        Err(HybridError::MlDsaComponentInvalid)
    );
}

#[test]
fn h04_tampering_with_either_component_is_caught_and_named() {
    let (ed_priv, ed_pub, seed, ml_pub) = keys();
    let good = sign_hybrid(&ed_priv, &seed, SIGNER, PAYLOAD).unwrap();

    let mut ed_flipped = good.clone();
    ed_flipped.signature_bytes[10] ^= 0x01; // inside the Ed25519 half
    assert_eq!(
        verify_hybrid(&ed_pub, &ml_pub, &ed_flipped),
        Err(HybridError::Ed25519ComponentInvalid)
    );

    let mut ml_flipped = good.clone();
    let ml_offset = 4 + ED25519_SIGNATURE_LEN + 4 + 100;
    ml_flipped.signature_bytes[ml_offset] ^= 0x01; // inside the ML-DSA half
    assert!(matches!(
        verify_hybrid(&ed_pub, &ml_pub, &ml_flipped),
        Err(HybridError::MlDsaComponentInvalid)
    ));

    // And the signed metadata is covered too, not only the payload hash.
    let mut relabelled = good.clone();
    relabelled.signer_id = "did:aip:collector:IMPOSTOR".into();
    assert_eq!(
        verify_hybrid(&ed_pub, &ml_pub, &relabelled),
        Err(HybridError::Ed25519ComponentInvalid)
    );
}

// ── 2. The two eras cannot be confused ────────────────────────────────────

#[test]
fn h05_the_ed25519_half_cannot_be_lifted_out_and_passed_off_as_standalone() {
    // `signature_signed_bytes` puts the AlgorithmId inside the signed bytes,
    // so the Ed25519 half of a hybrid signature is over a `Hybrid`-tagged
    // preimage and does not verify against the `Ed25519`-tagged one.
    let (ed_priv, ed_pub, seed, _ml_pub) = keys();
    let hybrid = sign_hybrid(&ed_priv, &seed, SIGNER, PAYLOAD).unwrap();
    let (ed_half, _) = decode_hybrid(&hybrid.signature_bytes).unwrap();

    let mut forged = hybrid.clone();
    forged.algorithm = AlgorithmId::Ed25519;
    forged.signature_bytes = ed_half.to_vec();

    assert!(
        !matches!(verify_ed25519(&ed_pub, &forged), Ok(true)),
        "the Ed25519 half of a hybrid signature must not verify as a standalone one"
    );
}

#[test]
fn h06_a_standalone_ed25519_signature_cannot_be_relabelled_hybrid() {
    // The other direction: padding a real Ed25519 signature with arbitrary
    // ML-DSA-shaped bytes and calling it hybrid.
    let (ed_priv, ed_pub, _seed, ml_pub) = keys();
    let plain = sign_ed25519(&ed_priv, SIGNER, PAYLOAD).unwrap();
    assert!(verify_ed25519(&ed_pub, &plain).unwrap());

    let mut forged = plain.clone();
    forged.algorithm = AlgorithmId::Hybrid;
    forged.signature_bytes = encode_hybrid(&plain.signature_bytes, &[0u8; ML_DSA_65_SIGNATURE_LEN]);

    // It fails on the Ed25519 half first, because that half was made over the
    // Ed25519-tagged preimage — the relabelling is caught by the mature
    // algorithm, not only by the new one.
    assert_eq!(
        verify_hybrid(&ed_pub, &ml_pub, &forged),
        Err(HybridError::Ed25519ComponentInvalid)
    );
}

#[test]
fn h07_the_encoding_is_strict_so_one_signature_has_one_form() {
    let (ed_priv, ed_pub, seed, ml_pub) = keys();
    let good = sign_hybrid(&ed_priv, &seed, SIGNER, PAYLOAD).unwrap();

    for (mutate, why) in [
        (
            Box::new(|b: &mut Vec<u8>| b.push(0)) as Box<dyn Fn(&mut Vec<u8>)>,
            "trailing byte",
        ),
        (
            Box::new(|b: &mut Vec<u8>| {
                b.pop();
            }),
            "truncated",
        ),
        (
            Box::new(|b: &mut Vec<u8>| b[0..4].copy_from_slice(&63u32.to_be_bytes())),
            "lying Ed25519 length prefix",
        ),
        (
            Box::new(|b: &mut Vec<u8>| {
                let at = 4 + ED25519_SIGNATURE_LEN;
                b[at..at + 4].copy_from_slice(&3308u32.to_be_bytes())
            }),
            "lying ML-DSA length prefix",
        ),
    ] {
        let mut bad = good.clone();
        mutate(&mut bad.signature_bytes);
        assert!(
            matches!(
                verify_hybrid(&ed_pub, &ml_pub, &bad),
                Err(HybridError::MalformedEncoding(_))
            ),
            "{why} must be refused as malformed, not interpreted"
        );
    }
}

#[test]
fn h08_a_non_hybrid_signature_is_refused_by_name() {
    let (ed_priv, ed_pub, _seed, ml_pub) = keys();
    let plain = sign_ed25519(&ed_priv, SIGNER, PAYLOAD).unwrap();
    assert_eq!(
        verify_hybrid(&ed_pub, &ml_pub, &plain),
        Err(HybridError::NotHybrid(AlgorithmId::Ed25519))
    );
}

// ── 3. Nothing already sealed changes ─────────────────────────────────────

#[test]
fn h09_the_ed25519_path_is_untouched_by_the_existence_of_the_hybrid_one() {
    // The non-negotiable property. Every artefact sealed before this module
    // existed must verify exactly as it did, or the migration has invalidated
    // the history it was meant to protect.
    let (ed_priv, ed_pub, _seed, _ml_pub) = keys();
    let sig = sign_ed25519(&ed_priv, SIGNER, PAYLOAD).unwrap();

    assert_eq!(sig.algorithm, AlgorithmId::Ed25519);
    assert_eq!(sig.signature_bytes.len(), ED25519_SIGNATURE_LEN);
    assert!(verify_ed25519(&ed_pub, &sig).unwrap());

    // And a transitional verifier accepts it without knowing any ML-DSA key.
    verify_under_policy(SignaturePolicy::Transitional, &ed_pub, None, &sig)
        .expect("an Ed25519 artefact still verifies during the transition");
}

// ── 4. The policy belongs to the verifier ─────────────────────────────────

#[test]
fn h10_a_strict_verifier_refuses_an_ed25519_artefact_as_insufficient_not_invalid() {
    // The distinction matters operationally: "correctly signed with an
    // algorithm we no longer accept" must not be logged as "bad signature",
    // or an estate mid-migration reads as if it were under attack.
    let (ed_priv, ed_pub, _seed, ml_pub) = keys();
    let sig = sign_ed25519(&ed_priv, SIGNER, PAYLOAD).unwrap();

    assert_eq!(
        verify_under_policy(
            SignaturePolicy::HybridRequired,
            &ed_pub,
            Some(&ml_pub),
            &sig
        ),
        Err(HybridError::PolicyRequiresHybrid)
    );
    assert!(
        verify_ed25519(&ed_pub, &sig).unwrap(),
        "and the signature itself is still perfectly valid"
    );
}

#[test]
fn h11_a_strict_verifier_accepts_a_hybrid_artefact() {
    let (ed_priv, ed_pub, seed, ml_pub) = keys();
    let sig = sign_hybrid(&ed_priv, &seed, SIGNER, PAYLOAD).unwrap();
    verify_under_policy(
        SignaturePolicy::HybridRequired,
        &ed_pub,
        Some(&ml_pub),
        &sig,
    )
    .expect("a hybrid artefact satisfies a strict verifier");
}

#[test]
fn h12_a_hybrid_artefact_without_an_ml_dsa_key_is_refused_not_half_checked() {
    // A verifier that has not been provisioned with the second key must not
    // fall back to checking only the half it can.
    let (ed_priv, ed_pub, seed, _ml_pub) = keys();
    let sig = sign_hybrid(&ed_priv, &seed, SIGNER, PAYLOAD).unwrap();
    assert!(matches!(
        verify_under_policy(SignaturePolicy::Transitional, &ed_pub, None, &sig),
        Err(HybridError::BadKeyLength { .. })
    ));
}

#[test]
fn h13_ml_dsa_65_alone_remains_a_reserved_identifier() {
    // A label never becomes a capability. This module implements `Hybrid`;
    // it deliberately does not implement standalone ML-DSA, because that
    // would trade a mature implementation for an unaudited one rather than
    // adding to it.
    let (ed_priv, ed_pub, seed, ml_pub) = keys();
    let mut sig = sign_hybrid(&ed_priv, &seed, SIGNER, PAYLOAD).unwrap();
    sig.algorithm = AlgorithmId::MlDsa65;
    assert_eq!(
        verify_under_policy(SignaturePolicy::Transitional, &ed_pub, Some(&ml_pub), &sig),
        Err(HybridError::NotHybrid(AlgorithmId::MlDsa65))
    );
}

// ── Determinism and key handling ──────────────────────────────────────────

#[test]
fn h14_the_ml_dsa_key_is_derived_from_its_seed_deterministically() {
    // Custody of a post-quantum key is then the same shape as custody of an
    // Ed25519 one: 32 bytes, and an HSM or wrapped file holds no more.
    let seed = [7u8; 32];
    let a = ml_dsa_public_key_from_seed(&seed).unwrap();
    let b = ml_dsa_public_key_from_seed(&seed).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.len(), ML_DSA_65_PUBLIC_KEY_LEN);
    assert_ne!(a, ml_dsa_public_key_from_seed(&[8u8; 32]).unwrap());
}

#[test]
fn h15_a_wrong_length_seed_or_key_is_refused_by_name() {
    assert!(matches!(
        ml_dsa_public_key_from_seed(&[0u8; 31]),
        Err(HybridError::BadKeyLength { .. })
    ));
    let (ed_priv, ed_pub, seed, _) = keys();
    let sig = sign_hybrid(&ed_priv, &seed, SIGNER, PAYLOAD).unwrap();
    assert!(matches!(
        verify_hybrid(&ed_pub, &[0u8; 10], &sig),
        Err(HybridError::BadKeyLength { .. })
    ));
    assert!(sign_hybrid(&ed_priv, &[0u8; 16], SIGNER, PAYLOAD).is_err());
}
