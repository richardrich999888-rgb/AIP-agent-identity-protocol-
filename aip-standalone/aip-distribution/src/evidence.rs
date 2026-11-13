//! Signed, versioned claims about a package transfer and subsequent staging.
//!
//! The receiver signs this record with its AIP identity key. It binds evidence
//! claims to independently verifiable package, AIBOM, transfer and peer-binding
//! digests; it does not turn those claims into proof of execution or business
//! effects. Verifiers must still supply all trust anchors separately.

use aip_crypto::{custody::Custodian, sha256, verify_ed25519};
use aip_types::{AlgorithmId, Signature};
use serde::{Deserialize, Serialize};

pub const DISTRIBUTION_EVIDENCE_VERSION: u16 = 1;
const SIGN_DOMAIN: &[u8] = b"AIP/DISTRIBUTION/EVIDENCE/SIGN/v1\0";
const DIGEST_DOMAIN: &[u8] = b"AIP/DISTRIBUTION/EVIDENCE/DIGEST/v1\0";
const CORRELATION_DOMAIN: &[u8] = b"AIP/DISTRIBUTION/CORRELATION/v1\0";

/// Deterministic correlation identifier bound to the signed transfer ID.
pub fn correlation_id_for_transfer(transfer_id: &str) -> Result<[u8; 16], EvidenceError> {
    let bytes = hex::decode(transfer_id)
        .map_err(|_| EvidenceError::Invalid("malformed transfer ID".into()))?;
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| EvidenceError::Invalid("malformed transfer ID".into()))?;
    let mut input = CORRELATION_DOMAIN.to_vec();
    input.extend_from_slice(&raw);
    let digest = sha256(&input);
    let mut correlation = [0u8; 16];
    correlation.copy_from_slice(&digest[..16]);
    Ok(correlation)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceOperation {
    Serve,
    Receive,
    Resume,
    ServeResume,
    Stage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransferOutcome {
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StagingOutcome {
    NotAttempted,
    Staged,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceTimestampKind {
    LocalSystemClock,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DistributionEvidencePayload {
    pub version: u16,
    pub correlation_id: [u8; 16],
    pub sender_aid_id: String,
    pub receiver_aid_id: String,
    pub sender_peer_id: String,
    pub receiver_peer_id: String,
    pub sender_binding_digest: [u8; 32],
    pub receiver_binding_digest: [u8; 32],
    /// SHA-256 of the exact portable package-export bytes.
    pub package_export_digest: [u8; 32],
    /// SHA-256 of the existing package archive bytes.
    pub package_archive_digest: [u8; 32],
    /// SHA-256 of the signed embedded package manifest bytes.
    pub package_manifest_digest: [u8; 32],
    /// SHA-256 of the signed transfer manifest's canonical signing bytes.
    pub transfer_manifest_digest: [u8; 32],
    pub aibom_manifest_digest: [u8; 32],
    pub aibom_seal_digest: [u8; 32],
    pub aibom_seal_verified: bool,
    pub authorization_operations: Vec<EvidenceOperation>,
    pub transfer_outcome: TransferOutcome,
    pub resume_count: u32,
    pub cancellation_count: u32,
    pub staging_outcome: StagingOutcome,
    /// Digest of the canonical staged-file inventory; present only when the
    /// record reports a successful staging operation.
    pub staged_artifact_digest: Option<[u8; 32]>,
    pub timestamp_ms: u64,
    pub timestamp_kind: EvidenceTimestampKind,
    /// The receiver identity whose private key signs the evidence record.
    pub signer_aid_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DistributionEvidenceRecord {
    pub payload: DistributionEvidencePayload,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceError {
    Invalid(String),
    Untrusted(String),
}

impl std::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for EvidenceError {}

impl DistributionEvidencePayload {
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if self.version != DISTRIBUTION_EVIDENCE_VERSION
            || self.correlation_id == [0; 16]
            || self.sender_binding_digest == [0; 32]
            || self.receiver_binding_digest == [0; 32]
            || self.package_export_digest == [0; 32]
            || self.package_archive_digest == [0; 32]
            || self.package_manifest_digest == [0; 32]
            || self.transfer_manifest_digest == [0; 32]
            || self.aibom_manifest_digest == [0; 32]
            || self.aibom_seal_digest == [0; 32]
            || self.timestamp_ms == 0
        {
            return Err(EvidenceError::Invalid(
                "missing or unsupported evidence fields".into(),
            ));
        }
        for (field, value) in [
            ("sender AID", &self.sender_aid_id),
            ("receiver AID", &self.receiver_aid_id),
            ("sender PeerId", &self.sender_peer_id),
            ("receiver PeerId", &self.receiver_peer_id),
            ("signer AID", &self.signer_aid_id),
        ] {
            if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                return Err(EvidenceError::Invalid(format!("invalid {field}")));
            }
        }
        if self.signer_aid_id != self.receiver_aid_id {
            return Err(EvidenceError::Invalid(
                "evidence signer must be the receiver".into(),
            ));
        }
        if self
            .authorization_operations
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(EvidenceError::Invalid(
                "authorization operations must be sorted and unique".into(),
            ));
        }
        if self.transfer_outcome == TransferOutcome::Completed
            && (!self
                .authorization_operations
                .contains(&EvidenceOperation::Serve)
                || !self
                    .authorization_operations
                    .contains(&EvidenceOperation::Receive))
        {
            return Err(EvidenceError::Invalid(
                "completed transfer requires Serve and Receive decisions".into(),
            ));
        }
        match (self.staging_outcome, self.staged_artifact_digest) {
            (StagingOutcome::Staged, Some(digest))
                if self.transfer_outcome == TransferOutcome::Completed
                    && self.aibom_seal_verified
                    && digest != [0; 32]
                    && self
                        .authorization_operations
                        .contains(&EvidenceOperation::Stage) => {}
            (StagingOutcome::Staged, _) => {
                return Err(EvidenceError::Invalid(
                    "staged outcome requires verified completed inputs, Stage authorization and inventory digest".into(),
                ));
            }
            (_, Some(_)) => {
                return Err(EvidenceError::Invalid(
                    "staged digest is only valid for a staged outcome".into(),
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

impl DistributionEvidenceRecord {
    pub fn sign(
        payload: DistributionEvidencePayload,
        custodian: &dyn Custodian,
    ) -> Result<Self, EvidenceError> {
        payload.validate()?;
        let signer = payload.signer_aid_id.clone();
        let preimage = signing_preimage(&payload)?;
        let signature = custodian
            .sign(&signer, &preimage)
            .map_err(|error| EvidenceError::Invalid(error.to_string()))?;
        Ok(Self { payload, signature })
    }

    pub fn verify(&self, trusted_receiver_public_key: &[u8]) -> Result<(), EvidenceError> {
        self.payload.validate()?;
        if trusted_receiver_public_key.len() != 32
            || self.signature.algorithm != AlgorithmId::Ed25519
            || self.signature.signer_id != self.payload.receiver_aid_id
        {
            return Err(EvidenceError::Untrusted(
                "invalid evidence signer anchor".into(),
            ));
        }
        let preimage = signing_preimage(&self.payload)?;
        if self.signature.payload_hash != sha256(&preimage)
            || !verify_ed25519(trusted_receiver_public_key, &self.signature)
                .map_err(|error| EvidenceError::Untrusted(error.to_string()))?
        {
            return Err(EvidenceError::Untrusted(
                "evidence signature is invalid".into(),
            ));
        }
        Ok(())
    }

    /// Domain-separated digest over the canonical payload and complete
    /// signature envelope. It is computed, never trusted from the bundle.
    pub fn digest(&self) -> Result<[u8; 32], EvidenceError> {
        let mut bytes = DIGEST_DOMAIN.to_vec();
        let preimage = signing_preimage(&self.payload)?;
        bytes.extend_from_slice(&preimage);
        bytes.extend_from_slice(
            &serde_json::to_vec(&self.signature)
                .map_err(|error| EvidenceError::Invalid(error.to_string()))?,
        );
        Ok(sha256(&bytes))
    }

    pub fn to_json(&self) -> Result<Vec<u8>, EvidenceError> {
        serde_json::to_vec(self).map_err(|error| EvidenceError::Invalid(error.to_string()))
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, EvidenceError> {
        if bytes.len() > 64 * 1024 {
            return Err(EvidenceError::Invalid(
                "distribution evidence exceeds size limit".into(),
            ));
        }
        serde_json::from_slice(bytes).map_err(|error| EvidenceError::Invalid(error.to_string()))
    }
}

fn signing_preimage(payload: &DistributionEvidencePayload) -> Result<Vec<u8>, EvidenceError> {
    let canonical =
        serde_json::to_vec(payload).map_err(|error| EvidenceError::Invalid(error.to_string()))?;
    let length = u64::try_from(canonical.len())
        .map_err(|_| EvidenceError::Invalid("canonical evidence length overflow".into()))?;
    let mut bytes = SIGN_DOMAIN.to_vec();
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}
