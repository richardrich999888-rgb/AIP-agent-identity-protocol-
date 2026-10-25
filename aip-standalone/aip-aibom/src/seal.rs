//! A detached seal over a manifest's canonical digest.
//!
//! # What a seal means, and only that
//!
//! *"This publisher issued this exact inventory at this time."* It is the
//! publisher putting their name to the manifest. It is **not** a statement
//! that any field is true, it never raises any field's standing, and a sealed
//! manifest whose permissions nothing backs is assessed exactly as an unsealed
//! one — except that the report can now say who made the unbacked claims.
//! `aip_nexora::ProofAssembler` follows the same rule for the same reason.
//!
//! # Why detached
//!
//! A manifest that contained its own digest could not be canonically encoded
//! without an exclusion rule, and every such rule is a place for two
//! implementations to disagree. The seal is a separate object over
//! `canonical::manifest_digest`.

use crate::canonical::manifest_digest;
use crate::model::Manifest;
use aip_crypto::{sha256, sign_ed25519, verify_ed25519};
use aip_types::canonical::{put_domain, put_str, put_u16, put_u64};
use aip_types::Signature;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Domain tag for a seal's signing preimage.
pub const SEAL_DOMAIN: &str = "AIP-AIBOM-SEAL-v1";

/// The seal format this build reads and writes.
pub const SEAL_VERSION: u16 = 1;

/// A publisher's signature over one manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seal {
    pub version: u16,
    pub publisher_id: String,
    pub sealed_at_ms: u64,
    /// `canonical::manifest_digest`, lowercase hex.
    pub manifest_sha256: String,
    pub signature: Signature,
}

impl Seal {
    /// Every field but the signature, domain-tagged and length-prefixed.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut b = Vec::new();
        put_domain(&mut b, SEAL_DOMAIN);
        put_u16(&mut b, self.version);
        put_str(&mut b, &self.publisher_id);
        put_u64(&mut b, self.sealed_at_ms);
        put_str(&mut b, &self.manifest_sha256);
        b
    }
}

/// Why a seal was refused, or could not be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealError {
    UnsupportedVersion(u16),
    /// The seal is over a different manifest.
    DigestMismatch,
    PublisherNotAnchored(String),
    SignerMismatch,
    PayloadHashMismatch,
    SignatureInvalid,
    /// The publisher's private and public keys are not a pair.
    KeyPairMismatch,
    Crypto(String),
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SealError {}

/// A party that seals manifests. Holds a key; `Debug` never prints it.
pub struct Publisher {
    id: String,
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl std::fmt::Debug for Publisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Publisher")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Publisher {
    /// A publisher under a key pair, checked to be a pair before it is
    /// accepted: a publisher whose seals could never verify is refused at
    /// construction rather than discovered at assessment.
    pub fn new(id: &str, private_key: &[u8], public_key: &[u8]) -> Result<Self, SealError> {
        let probe = sign_ed25519(private_key, id, SEAL_DOMAIN.as_bytes())
            .map_err(|e| SealError::Crypto(format!("{e:?}")))?;
        match verify_ed25519(public_key, &probe) {
            Ok(true) => Ok(Self {
                id: id.to_string(),
                private_key: private_key.to_vec(),
                public_key: public_key.to_vec(),
            }),
            Ok(false) => Err(SealError::KeyPairMismatch),
            Err(e) => Err(SealError::Crypto(format!("{e:?}"))),
        }
    }

    /// The key a verifier anchors for this publisher.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Seal `m` as issued at `sealed_at_ms`.
    pub fn seal(&self, m: &Manifest, sealed_at_ms: u64) -> Result<Seal, SealError> {
        let mut s = Seal {
            version: SEAL_VERSION,
            publisher_id: self.id.clone(),
            sealed_at_ms,
            manifest_sha256: hex::encode(manifest_digest(m)),
            signature: placeholder(&self.id),
        };
        s.signature = sign_ed25519(&self.private_key, &self.id, &s.signing_preimage())
            .map_err(|e| SealError::Crypto(format!("{e:?}")))?;
        Ok(s)
    }
}

fn placeholder(signer_id: &str) -> Signature {
    Signature {
        algorithm: aip_types::AlgorithmId::Ed25519,
        signer_id: signer_id.to_string(),
        timestamp: 0,
        nonce: [0; 16],
        payload_hash: [0; 32],
        signature_bytes: Vec::new(),
    }
}

/// Verify `seal` over `m` against the publishers the assessor anchors.
///
/// The publisher's key comes from `publishers`, never from the seal: a seal
/// that could name its own key would verify under any key its author chose.
pub fn verify_seal(
    seal: &Seal,
    m: &Manifest,
    publishers: &BTreeMap<String, Vec<u8>>,
) -> Result<(), SealError> {
    if seal.version != SEAL_VERSION {
        return Err(SealError::UnsupportedVersion(seal.version));
    }
    if seal.manifest_sha256 != hex::encode(manifest_digest(m)) {
        return Err(SealError::DigestMismatch);
    }
    let key = publishers
        .get(&seal.publisher_id)
        .ok_or_else(|| SealError::PublisherNotAnchored(seal.publisher_id.clone()))?;
    if seal.signature.signer_id != seal.publisher_id {
        return Err(SealError::SignerMismatch);
    }
    if seal.signature.payload_hash != sha256(&seal.signing_preimage()) {
        return Err(SealError::PayloadHashMismatch);
    }
    match verify_ed25519(key, &seal.signature) {
        Ok(true) => Ok(()),
        Ok(false) => Err(SealError::SignatureInvalid),
        Err(e) => Err(SealError::Crypto(format!("{e:?}"))),
    }
}
