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
use aip_crypto::custody::{Backend, Custodian, InMemoryCustodian};
use aip_crypto::{sha256, verify_ed25519};
use aip_types::canonical::{put_domain, put_str, put_u16, put_u64};
use aip_types::{AlgorithmId, Signature};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

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

/// A party that seals manifests through a signing custodian.
/// The private key is never stored or exposed by Publisher.
pub struct Publisher {
    id: String,
    custodian: Arc<dyn Custodian>,
}

impl std::fmt::Debug for Publisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Publisher")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Publisher {
    /// Backward-compatible software-key constructor.
    ///
    /// The key is moved into an in-memory custodian, which wipes its
    /// private-key buffer on drop. Prefer `from_custodian` when using
    /// wrapped-file or hardware-backed custody.
    pub fn new(id: &str, private_key: &[u8], public_key: &[u8]) -> Result<Self, SealError> {
        let custodian = InMemoryCustodian::new(private_key, public_key)
            .map_err(|e| SealError::Crypto(format!("{e:?}")))?;
        Self::from_custodian(id, Arc::new(custodian))
    }

    /// Construct a publisher using any AIP signing custodian.
    ///
    /// A probe signature is verified before the custodian is accepted.
    /// This checks that its public key corresponds to the signing key and
    /// that it returns the expected AIP signature envelope.
    pub fn from_custodian(
        id: &str,
        custodian: Arc<dyn Custodian>,
    ) -> Result<Self, SealError> {
        let probe_payload = SEAL_DOMAIN.as_bytes();
        let probe = custodian
            .sign(id, probe_payload)
            .map_err(|e| SealError::Crypto(format!("{e:?}")))?;

        if probe.algorithm != AlgorithmId::Ed25519 {
            return Err(SealError::SignatureInvalid);
        }
        if probe.signer_id != id {
            return Err(SealError::SignerMismatch);
        }
        if probe.payload_hash != sha256(probe_payload) {
            return Err(SealError::PayloadHashMismatch);
        }

        match verify_ed25519(custodian.public_key(), &probe) {
            Ok(true) => Ok(Self {
                id: id.to_string(),
                custodian,
            }),
            Ok(false) => Err(SealError::KeyPairMismatch),
            Err(e) => Err(SealError::Crypto(format!("{e:?}"))),
        }
    }

    /// The key a verifier anchors for this publisher.
    pub fn public_key(&self) -> &[u8] {
        self.custodian.public_key()
    }

    /// The custody backend used by this publisher.
    ///
    /// This is descriptive metadata, not evidence that a manifest is true.
    pub fn backend(&self) -> Backend {
        self.custodian.backend()
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

        let preimage = s.signing_preimage();
        let signature = self
            .custodian
            .sign(&self.id, &preimage)
            .map_err(|e| SealError::Crypto(format!("{e:?}")))?;

        if signature.algorithm != AlgorithmId::Ed25519 {
            return Err(SealError::SignatureInvalid);
        }
        if signature.signer_id != self.id {
            return Err(SealError::SignerMismatch);
        }
        if signature.payload_hash != sha256(&preimage) {
            return Err(SealError::PayloadHashMismatch);
        }

        match verify_ed25519(self.custodian.public_key(), &signature) {
            Ok(true) => {
                s.signature = signature;
                Ok(s)
            }
            Ok(false) => Err(SealError::SignatureInvalid),
            Err(e) => Err(SealError::Crypto(format!("{e:?}"))),
        }
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
