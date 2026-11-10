//! Hybrid Ed25519 + ML-DSA-65 signatures — the migration path for evidence
//! that must stay verifiable after Ed25519 does not.
//!
//! # Why this exists
//!
//! This system asks an institution to treat signed artefacts as evidence it
//! can re-verify later, and its storage controls enforce a 180-day retention
//! floor with a legal hold that outlives retention. An artefact held for a
//! proceeding may need to verify years after it was signed. Every signature
//! today is Ed25519, so **the non-repudiation of retained evidence has a
//! horizon**, and unlike confidentiality that cannot be repaired afterwards:
//! re-signing old artefacts under a new algorithm would mean the re-signer
//! vouching for bytes it did not witness. Only artefacts signed *after* a
//! migration benefit from one, which is why the path has to exist before it
//! is needed rather than when it is.
//!
//! # Both, or refuse — never either
//!
//! A hybrid signature is verified by checking **both** component signatures.
//! Accepting either would defeat the entire construction: a break in Ed25519
//! alone would then forge a hybrid signature, and the second algorithm would
//! be decoration. [`verify_hybrid`] returns an error naming *which* component
//! failed rather than a bare `false`, on the same principle as the rest of
//! this crate — a verifier that cannot answer says so.
//!
//! # The domain separation is free, and load-bearing
//!
//! [`crate::signature_signed_bytes`] puts the [`AlgorithmId`] **inside the
//! signed bytes**. A hybrid signature therefore signs a preimage tagged
//! `Hybrid`, which is a different message from the one a standalone Ed25519
//! signature over the same payload signs. Two consequences, both tested:
//!
//! * The Ed25519 half of a hybrid signature **cannot be lifted out** and
//!   presented as a standalone Ed25519 signature — it does not verify against
//!   the Ed25519-tagged preimage.
//! * A standalone Ed25519 signature **cannot be relabelled** `Hybrid` and
//!   padded with any ML-DSA bytes — its Ed25519 half was made over the
//!   Ed25519-tagged preimage and fails against the hybrid one.
//!
//! So the two eras cannot be confused for one another in either direction,
//! which is what makes a transition window safe to operate.
//!
//! # Encoding: length-prefixed, because concatenation is ambiguous
//!
//! `signature_bytes` for a hybrid signature is
//!
//! ```text
//! u32be(64) || ed25519_signature || u32be(3309) || ml_dsa_65_signature
//! ```
//!
//! Lengths are written even though both components are fixed-size today,
//! because a bare concatenation has no way to say where one ends if a
//! parameter set ever changes, and a decoder that infers a boundary from
//! total length is a decoder that can be tricked by a future size collision.
//! [`decode_hybrid`] requires the exact expected lengths and refuses trailing
//! bytes, so one signature has one encoding.
//!
//! # Maturity disclosure, which this dependency obliges
//!
//! The ML-DSA implementation is [`ml_dsa`] `0.1.1` from RustCrypto: pure Rust,
//! FIPS-204 final, Apache-2.0 OR MIT. It is **pre-1.0 and not independently
//! audited**, and this crate's own test vectors exercise it only through this
//! API. Ed25519 here is `ed25519-dalek` 2.1, which is mature and widely
//! reviewed. That asymmetry is the reason this construction is **hybrid and
//! verifies both halves**: a defect in the newer implementation cannot, on its
//! own, produce a signature that verifies, because the mature half must verify
//! too. It is also the reason nothing in this repository signs hybrid by
//! default — see `docs/adr/` and the technical brief's section 9a for where
//! that decision sits.
//!
//! # What this module does not do
//!
//! It does not implement standalone ML-DSA-65 signing. [`AlgorithmId::MlDsa65`]
//! remains a reserved identifier that every verifier refuses, because a
//! post-quantum-only signature would trade a mature implementation for an
//! unaudited one rather than adding to it. It does not touch
//! [`crate::sign_ed25519`] or [`crate::verify_ed25519`], so every artefact
//! already sealed verifies byte-identically to before.

use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Keypair as _, MlDsa65, Signature as MlDsaSignature,
    Signer as _, SigningKey as MlDsaSigningKey, Verifier as _, VerifyingKey as MlDsaVerifyingKey,
    B32,
};

use aip_types::{AipError, AlgorithmId, Signature};

use crate::{sha256, signature_signed_bytes};

/// Bytes in an Ed25519 signature.
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// Bytes in an ML-DSA-65 signature (FIPS 204, parameter set 65).
pub const ML_DSA_65_SIGNATURE_LEN: usize = 3309;
/// Bytes in an ML-DSA-65 verifying key.
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;
/// Bytes in the seed an ML-DSA-65 signing key is derived from.
pub const ML_DSA_65_SEED_LEN: usize = 32;

/// What a verifier requires of an artefact's signature.
///
/// This is the knob a migration turns. It belongs to the *verifier*, not to
/// the artefact: the institution decides what it will accept, and an artefact
/// cannot declare itself acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignaturePolicy {
    /// Accept Ed25519 or hybrid. The behaviour of every verifier shipped
    /// today, and what a transition window runs so that artefacts sealed
    /// before the migration keep verifying.
    Transitional,
    /// Require hybrid. An Ed25519-only artefact is **refused**, not reported
    /// invalid — it is a well-formed signature of an algorithm this verifier
    /// has been told is no longer sufficient, which is a different statement
    /// from a bad signature and must not be logged as one.
    HybridRequired,
}

/// Why a hybrid operation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HybridError {
    /// The signature is not tagged `Hybrid`.
    NotHybrid(AlgorithmId),
    /// `signature_bytes` is not a well-formed hybrid encoding.
    MalformedEncoding(&'static str),
    /// The Ed25519 half did not verify. The mature half failing is the
    /// stronger signal of the two and is named separately for that reason.
    Ed25519ComponentInvalid,
    /// The ML-DSA-65 half did not verify.
    MlDsaComponentInvalid,
    /// A key was the wrong length for its algorithm.
    BadKeyLength { algorithm: &'static str, len: usize },
    /// The policy required a hybrid signature and the artefact carried an
    /// Ed25519-only one. Not an invalid signature — an insufficient one.
    PolicyRequiresHybrid,
}

impl From<HybridError> for AipError {
    fn from(_: HybridError) -> Self {
        AipError::SignatureInvalid
    }
}

/// Derive an ML-DSA-65 verifying key from its 32-byte seed.
///
/// Seed-derived rather than stored expanded, so custody of a post-quantum key
/// is the same shape as custody of an Ed25519 one: 32 bytes, and an HSM or a
/// wrapped file holds the same amount of secret material.
pub fn ml_dsa_public_key_from_seed(seed: &[u8]) -> Result<Vec<u8>, HybridError> {
    let seed: &[u8; ML_DSA_65_SEED_LEN] =
        seed.try_into().map_err(|_| HybridError::BadKeyLength {
            algorithm: "ml-dsa-65 seed",
            len: seed.len(),
        })?;
    let sk = MlDsaSigningKey::<MlDsa65>::from_seed(&B32::from(*seed));
    Ok(sk.verifying_key().encode().to_vec())
}

/// Encode the two component signatures into one `signature_bytes`.
pub fn encode_hybrid(ed25519: &[u8], ml_dsa: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + ed25519.len() + ml_dsa.len());
    out.extend_from_slice(&(ed25519.len() as u32).to_be_bytes());
    out.extend_from_slice(ed25519);
    out.extend_from_slice(&(ml_dsa.len() as u32).to_be_bytes());
    out.extend_from_slice(ml_dsa);
    out
}

/// Split a hybrid `signature_bytes` back into its two components.
///
/// Strict: exact expected lengths, and no trailing bytes. A decoder that
/// tolerated either would let one signature have several encodings, and a
/// canonical form that is not canonical is not one.
pub fn decode_hybrid(bytes: &[u8]) -> Result<(&[u8], &[u8]), HybridError> {
    const HEADER: usize = 4;
    let expected = HEADER + ED25519_SIGNATURE_LEN + HEADER + ML_DSA_65_SIGNATURE_LEN;
    if bytes.len() != expected {
        return Err(HybridError::MalformedEncoding(
            "hybrid signature is not exactly 4+64+4+3309 bytes",
        ));
    }
    let ed_len = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
    if ed_len != ED25519_SIGNATURE_LEN {
        return Err(HybridError::MalformedEncoding(
            "the Ed25519 length prefix is not 64",
        ));
    }
    let ed = &bytes[4..4 + ED25519_SIGNATURE_LEN];
    let rest = &bytes[4 + ED25519_SIGNATURE_LEN..];
    let ml_len = u32::from_be_bytes(rest[0..4].try_into().unwrap()) as usize;
    if ml_len != ML_DSA_65_SIGNATURE_LEN {
        return Err(HybridError::MalformedEncoding(
            "the ML-DSA length prefix is not 3309",
        ));
    }
    Ok((ed, &rest[4..]))
}

/// Sign a payload under **both** algorithms.
///
/// `ed25519_private` is the 32-byte Ed25519 key; `ml_dsa_seed` is the 32-byte
/// seed the ML-DSA-65 key is derived from. The two are separate keys by
/// design: one compromised key must not yield both halves.
pub fn sign_hybrid(
    ed25519_private: &[u8],
    ml_dsa_seed: &[u8],
    signer_id: &str,
    payload: &[u8],
) -> Result<Signature, AipError> {
    let ed_key: &[u8; 32] = ed25519_private
        .try_into()
        .map_err(|_| AipError::InvalidPublicKey)?;
    let seed: &[u8; ML_DSA_65_SEED_LEN] = ml_dsa_seed
        .try_into()
        .map_err(|_| AipError::InvalidPublicKey)?;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| AipError::SignatureInvalid)?
        .as_millis() as u64;

    let mut nonce = [0u8; 16];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let payload_hash = sha256(payload);

    // Tagged `Hybrid`, so neither half can be confused with a standalone
    // signature over the same payload. This is the whole domain separation.
    let signed_bytes = signature_signed_bytes(
        AlgorithmId::Hybrid,
        signer_id,
        timestamp,
        &nonce,
        &payload_hash,
    );

    let ed_sig = SigningKey::from_bytes(ed_key).sign(&signed_bytes);
    let ml_sig = MlDsaSigningKey::<MlDsa65>::from_seed(&B32::from(*seed)).sign(&signed_bytes);

    Ok(Signature {
        algorithm: AlgorithmId::Hybrid,
        signer_id: signer_id.to_string(),
        timestamp,
        nonce,
        payload_hash,
        signature_bytes: encode_hybrid(&ed_sig.to_bytes(), &ml_sig.encode()),
    })
}

/// Verify a hybrid signature. **Both** components must verify.
pub fn verify_hybrid(
    ed25519_public: &[u8],
    ml_dsa_public: &[u8],
    signature: &Signature,
) -> Result<(), HybridError> {
    if signature.algorithm != AlgorithmId::Hybrid {
        return Err(HybridError::NotHybrid(signature.algorithm));
    }
    let (ed_sig, ml_sig) = decode_hybrid(&signature.signature_bytes)?;

    let signed_bytes = signature_signed_bytes(
        AlgorithmId::Hybrid,
        &signature.signer_id,
        signature.timestamp,
        &signature.nonce,
        &signature.payload_hash,
    );

    let ed_key: &[u8; 32] = ed25519_public
        .try_into()
        .map_err(|_| HybridError::BadKeyLength {
            algorithm: "ed25519",
            len: ed25519_public.len(),
        })?;
    let ed_verifier = VerifyingKey::from_bytes(ed_key).map_err(|_| HybridError::BadKeyLength {
        algorithm: "ed25519",
        len: 32,
    })?;
    let ed_sig_array: [u8; ED25519_SIGNATURE_LEN] = ed_sig.try_into().expect("decode checked");
    ed_verifier
        .verify(
            &signed_bytes,
            &ed25519_dalek::Signature::from_bytes(&ed_sig_array),
        )
        .map_err(|_| HybridError::Ed25519ComponentInvalid)?;

    let ml_key_bytes: &[u8; ML_DSA_65_PUBLIC_KEY_LEN] =
        ml_dsa_public
            .try_into()
            .map_err(|_| HybridError::BadKeyLength {
                algorithm: "ml-dsa-65",
                len: ml_dsa_public.len(),
            })?;
    let ml_verifier =
        MlDsaVerifyingKey::<MlDsa65>::decode(&EncodedVerifyingKey::<MlDsa65>::from(*ml_key_bytes));
    let ml_sig_array: [u8; ML_DSA_65_SIGNATURE_LEN] = ml_sig.try_into().expect("decode checked");
    let ml_signature =
        MlDsaSignature::<MlDsa65>::decode(&EncodedSignature::<MlDsa65>::from(ml_sig_array))
            .ok_or(HybridError::MlDsaComponentInvalid)?;
    ml_verifier
        .verify(&signed_bytes, &ml_signature)
        .map_err(|_| HybridError::MlDsaComponentInvalid)?;

    Ok(())
}

/// Verify under a policy, where the artefact may be Ed25519 or hybrid.
///
/// This is the function a migrating verifier calls. `ml_dsa_public` may be
/// `None` while an institution is still Ed25519-only; a hybrid artefact
/// presented without one is refused rather than half-checked.
pub fn verify_under_policy(
    policy: SignaturePolicy,
    ed25519_public: &[u8],
    ml_dsa_public: Option<&[u8]>,
    signature: &Signature,
) -> Result<(), HybridError> {
    match signature.algorithm {
        AlgorithmId::Hybrid => {
            let ml = ml_dsa_public.ok_or(HybridError::BadKeyLength {
                algorithm: "ml-dsa-65",
                len: 0,
            })?;
            verify_hybrid(ed25519_public, ml, signature)
        }
        AlgorithmId::Ed25519 => {
            if policy == SignaturePolicy::HybridRequired {
                // Well formed, correctly signed, and no longer sufficient.
                return Err(HybridError::PolicyRequiresHybrid);
            }
            match crate::verify_ed25519(ed25519_public, signature) {
                Ok(true) => Ok(()),
                _ => Err(HybridError::Ed25519ComponentInvalid),
            }
        }
        // Still reserved. A label never becomes a capability.
        other => Err(HybridError::NotHybrid(other)),
    }
}
