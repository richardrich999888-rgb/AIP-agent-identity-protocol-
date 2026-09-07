//! The signing interface.
//!
//! # The invariant, and where it lives
//!
//! ```text
//! private key
//!     ↓  never casually serialized
//!     ↓  never returned to a caller
//!     ↓  used through a controlled signing operation
//! signature returned
//!     ↓
//! verification remains independent
//! ```
//!
//! [`SigningCustodian`] has **no method that returns key material**. Not
//! `private_key()`, not `export()`, not `seed()`, not `to_bytes()`. A caller
//! holding a `&dyn SigningCustodian` can obtain a public key, an identity and
//! a signature, and nothing else.
//!
//! That is the difference between an invariant and a convention. Six types in
//! this workspace — the collector, the decision point, the warrant and
//! containment authorities, the NEXORA signer — already keep a private field
//! and expose only `sign()`. They were each correct and each unnamed; this is
//! the name, so a seventh cannot be written differently by accident.
//!
//! # What this interface does not do
//!
//! It does not verify. Verification takes a **public** key and stays entirely
//! independent of how the private key was held — a verifier must not need to
//! know, and must not care, whether a signature came from a file, a TPM, or a
//! test fixture. Custody is a property of the signer; it is not evidence.

use crate::error::CustodyError;
use crate::policy::CustodyClass;

/// Something that holds a private key: identifiable, versioned, and honest
/// about how the key is protected.
///
/// Deliberately **cannot sign**. Most key holders in this workspace already
/// have exactly one signing operation, and it is domain-specific: a
/// `WarrantAuthority` signs a warrant preimage, a `ContainmentAuthority` signs a
/// containment record, a `CollectorSigner` signs an observation batch. Each is
/// a narrow surface with a fixed, domain-separated input.
///
/// Giving those types a general `sign(&[u8])` — which is what implementing
/// [`SigningCustodian`] would do — would hand every one of them a raw-signing
/// oracle. A caller could then ask the warrant authority to sign bytes that
/// happen to be a valid containment-record preimage, and the containment
/// verifier would accept the result: cross-protocol signature confusion,
/// introduced by the very abstraction meant to tighten key handling. So the
/// trait splits.
///
/// `KeyCustody` is what a key holder needs to be inventoried and
/// policy-checked. [`SigningCustodian`] adds general signing, and only the
/// backends whose whole purpose is general signing implement it.
pub trait KeyCustody: Send + Sync {
    /// A stable label for the key this holder has — an observer id, an AIP-ID,
    /// a service fingerprint. Used to select an anchor, never to grant one.
    fn key_id(&self) -> &str;

    /// Which version of that key this is.
    ///
    /// Rotation is `(key_id, key_version)`, matching the observer anchor model
    /// exactly rather than introducing a second scheme: two rotation schemes
    /// in one system is two schemes to get wrong.
    fn key_version(&self) -> u32;

    /// The public key. Safe to publish; this is what a verifier anchors.
    fn public_key(&self) -> &[u8];

    /// How the private key is protected.
    ///
    /// Reported so a caller can refuse a holder that does not meet its policy,
    /// and so an operator can see what protection is actually in force rather
    /// than what was intended.
    fn custody_class(&self) -> CustodyClass;
}

/// A key holder that can sign arbitrary bytes, without being able to hand over
/// what it signs with.
///
/// Implemented only by the general-purpose backends — [`crate::DevCustodian`],
/// [`crate::FileCustodian`], and the service key — where signing arbitrary
/// bytes *is* the purpose. The domain authorities deliberately implement
/// [`KeyCustody`] alone; see its documentation for why.
///
/// The trait is deliberately small: widening it is how key accessors get added.
pub trait SigningCustodian: KeyCustody {
    /// Sign `message`, returning the raw Ed25519 signature.
    ///
    /// The only operation that touches the private key, and the only way to
    /// obtain anything derived from it.
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], CustodyError>;
}

/// Whether this key holder meets `policy`, as a check a caller can make before
/// relying on it.
///
/// A free function rather than a trait method: a trait method could be
/// overridden by an implementation to report a class it does not have, which
/// is precisely the thing the policy exists to catch.
///
/// Generic over `?Sized` so it accepts `&dyn KeyCustody`, `&dyn
/// SigningCustodian` and concrete types alike, without depending on trait
/// upcasting.
pub fn admits<C: KeyCustody + ?Sized>(
    policy: crate::policy::CustodyPolicy,
    custodian: &C,
) -> Result<(), CustodyError> {
    if policy.admits(custodian.custody_class()) {
        Ok(())
    } else {
        Err(CustodyError::PolicyRefused {
            policy,
            class: custodian.custody_class(),
        })
    }
}

/// Produce an AIP [`Signature`] envelope using `custodian`, without the
/// caller ever holding the key.
///
/// This is the custodian-backed counterpart to `aip_crypto::sign_ed25519`. It
/// builds the identical envelope and covers the identical bytes — both call
/// `aip_crypto::signature_signed_bytes` — so a signature produced here and one
/// produced by the key-taking function are indistinguishable to a verifier.
/// That equivalence is what makes migrating a call site to a custodian a
/// no-op for every relying party.
///
/// # Randomness
///
/// The envelope carries a 16-byte nonce from the OS CSPRNG, so this function
/// is not deterministic. That is pre-existing envelope semantics, not a new
/// choice: the nonce is what stops a captured signature being replayed as a
/// signature over the same payload at a different moment. Everything else in
/// the envelope is a pure function of its inputs, and verification is fully
/// deterministic given the envelope.
pub fn sign_envelope(
    custodian: &dyn SigningCustodian,
    signer_id: &str,
    payload: &[u8],
) -> Result<aip_types::Signature, CustodyError> {
    use rand::RngCore;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| CustodyError::SigningFailed(format!("system clock is before the epoch: {e}")))?
        .as_millis() as u64;

    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let payload_hash = aip_crypto::sha256(payload);
    let signed_bytes = aip_crypto::signature_signed_bytes(
        aip_types::AlgorithmId::Ed25519,
        signer_id,
        timestamp,
        &nonce,
        &payload_hash,
    );

    let signature_bytes = custodian.sign(&signed_bytes)?.to_vec();

    Ok(aip_types::Signature {
        algorithm: aip_types::AlgorithmId::Ed25519,
        signer_id: signer_id.to_string(),
        timestamp,
        nonce,
        payload_hash,
        signature_bytes,
    })
}
