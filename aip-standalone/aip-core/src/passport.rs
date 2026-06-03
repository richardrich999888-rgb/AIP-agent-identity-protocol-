//! AIP Agent Passport schema and validation helpers.
//!
//! Phase 1 intentionally defines the portable wire document without binding it
//! to one transport. The AIP service issues this structure, `airon-passport`
//! verifies it offline, and SDKs persist/forward it.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const PASSPORT_VERSION: &str = "1.0.0";
pub const PASSPORT_TYPE: &str = "AIP-PASSPORT";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentPassport {
    pub header: PassportHeader,
    pub body: PassportBody,
    pub proof: PassportProof,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PassportHeader {
    pub version: String,
    pub typ: String,
    pub alg: String,
}

impl Default for PassportHeader {
    fn default() -> Self {
        Self {
            version: PASSPORT_VERSION.to_string(),
            typ: PASSPORT_TYPE.to_string(),
            alg: "Ed25519".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PassportBody {
    pub passport_id: String,
    pub subject: PassportSubject,
    pub issuer: PassportIssuer,
    pub constraints: PassportConstraints,
    pub lineage: Vec<LineageEntry>,
    pub environmental_lock: EnvironmentalLock,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PassportSubject {
    pub agent_id: String,
    pub friendly_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pqc_pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classical_pubkey: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PassportIssuer {
    pub name: String,
    pub id: String,
    pub registry_url: String,
    pub public_key_fingerprint: String,
    /// Raw 32-byte Ed25519 public key, base64url without padding.
    pub classical_pubkey: String,
    /// Raw ML-DSA-65 public key, base64url without padding, once enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pqc_pubkey: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PassportConstraints {
    pub issued_at: u64,
    pub expires_at: u64,
    pub capabilities: Vec<String>,
    pub max_delegation_depth: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LineageEntry {
    pub actor: String,
    pub action: String,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvironmentalLock {
    pub runtime: String,
    pub image_hash: String,
}

impl Default for EnvironmentalLock {
    fn default() -> Self {
        Self {
            runtime: "unknown".to_string(),
            image_hash: "sha256:unknown".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PassportProof {
    /// Ed25519 signature over canonical PassportBody bytes.
    pub signature: String,
    /// ML-DSA-65 signature over canonical PassportBody bytes, once enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pqc_signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PassportValidationError {
    UnsupportedVersion,
    WrongType,
    MissingPassportId,
    MissingAgentId,
    MissingIssuer,
    MissingIssuerKey,
    MissingSignature,
    EmptyCapability,
    DuplicateCapability(String),
    Expired,
    InvalidTimeWindow,
}

impl std::fmt::Display for PassportValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion => write!(f, "unsupported passport version"),
            Self::WrongType => write!(f, "wrong passport document type"),
            Self::MissingPassportId => write!(f, "passport_id is required"),
            Self::MissingAgentId => write!(f, "subject.agent_id is required"),
            Self::MissingIssuer => write!(f, "issuer id/name is required"),
            Self::MissingIssuerKey => write!(f, "issuer classical public key is required"),
            Self::MissingSignature => write!(f, "passport proof signature is required"),
            Self::EmptyCapability => write!(f, "capabilities must not contain empty values"),
            Self::DuplicateCapability(capability) => {
                write!(f, "duplicate capability: {capability}")
            }
            Self::Expired => write!(f, "passport has expired"),
            Self::InvalidTimeWindow => write!(f, "passport expires before it is issued"),
        }
    }
}

impl std::error::Error for PassportValidationError {}

impl AgentPassport {
    pub fn structural_check(&self) -> Result<(), PassportValidationError> {
        if self.header.version != PASSPORT_VERSION {
            return Err(PassportValidationError::UnsupportedVersion);
        }
        if self.header.typ != PASSPORT_TYPE {
            return Err(PassportValidationError::WrongType);
        }
        if self.body.passport_id.trim().is_empty() {
            return Err(PassportValidationError::MissingPassportId);
        }
        if self.body.subject.agent_id.trim().is_empty() {
            return Err(PassportValidationError::MissingAgentId);
        }
        if self.body.issuer.id.trim().is_empty() || self.body.issuer.name.trim().is_empty() {
            return Err(PassportValidationError::MissingIssuer);
        }
        if self.body.issuer.classical_pubkey.trim().is_empty() {
            return Err(PassportValidationError::MissingIssuerKey);
        }
        if self.proof.signature.trim().is_empty() {
            return Err(PassportValidationError::MissingSignature);
        }
        if self.body.constraints.expires_at <= self.body.constraints.issued_at {
            return Err(PassportValidationError::InvalidTimeWindow);
        }

        let mut seen = HashSet::new();
        for capability in &self.body.constraints.capabilities {
            let trimmed = capability.trim();
            if trimmed.is_empty() {
                return Err(PassportValidationError::EmptyCapability);
            }
            if !seen.insert(trimmed.to_string()) {
                return Err(PassportValidationError::DuplicateCapability(
                    trimmed.to_string(),
                ));
            }
        }

        Ok(())
    }

    pub fn temporal_check(&self, now_unix_seconds: u64) -> Result<(), PassportValidationError> {
        if now_unix_seconds >= self.body.constraints.expires_at {
            return Err(PassportValidationError::Expired);
        }
        Ok(())
    }
}

pub fn canonical_passport_body_bytes(body: &PassportBody) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passport() -> AgentPassport {
        AgentPassport {
            header: PassportHeader::default(),
            body: PassportBody {
                passport_id: "urn:aip:passport:550e8400-e29b-41d4-a716-446655440000".to_string(),
                subject: PassportSubject {
                    agent_id: "aip-agent-inv-9921".to_string(),
                    friendly_name: "Invoice-Automation-Bot".to_string(),
                    pqc_pubkey: None,
                    classical_pubkey: None,
                },
                issuer: PassportIssuer {
                    name: "Syntriass Labs Root".to_string(),
                    id: "syntriass.labs.root".to_string(),
                    registry_url: "https://trust.syntriass.io".to_string(),
                    public_key_fingerprint: "abc123".to_string(),
                    classical_pubkey: "issuer-public-key".to_string(),
                    pqc_pubkey: None,
                },
                constraints: PassportConstraints {
                    issued_at: 1_717_441_200,
                    expires_at: 1_720_033_200,
                    capabilities: vec!["invoice.read".to_string(), "ledger.post".to_string()],
                    max_delegation_depth: 3,
                },
                lineage: vec![LineageEntry {
                    actor: "manager-ganesh".to_string(),
                    action: "AUTHORIZE".to_string(),
                    timestamp: 1_717_441_000,
                    signature: "lineage-sig".to_string(),
                }],
                environmental_lock: EnvironmentalLock {
                    runtime: "python-3.11".to_string(),
                    image_hash: "sha256:e3b0c442".to_string(),
                },
            },
            proof: PassportProof {
                signature: "sig".to_string(),
                pqc_signature: None,
            },
        }
    }

    #[test]
    fn passport_structural_check_accepts_valid_document() {
        passport().structural_check().unwrap();
    }

    #[test]
    fn passport_structural_check_rejects_duplicate_capabilities() {
        let mut passport = passport();
        passport
            .body
            .constraints
            .capabilities
            .push("invoice.read".to_string());
        let err = passport.structural_check().unwrap_err();
        assert_eq!(
            err,
            PassportValidationError::DuplicateCapability("invoice.read".to_string())
        );
    }

    #[test]
    fn passport_temporal_check_rejects_expired_document() {
        let err = passport().temporal_check(1_800_000_000).unwrap_err();
        assert_eq!(err, PassportValidationError::Expired);
    }

    #[test]
    fn canonical_body_bytes_are_stable_for_same_document() {
        let first = canonical_passport_body_bytes(&passport().body).unwrap();
        let second = canonical_passport_body_bytes(&passport().body).unwrap();
        assert_eq!(first, second);
    }
}
