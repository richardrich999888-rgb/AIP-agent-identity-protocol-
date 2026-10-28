//! The decision point's signed records of what spend authority decided.
//!
//! Formats live here; signing happens in the decision point, with its own key
//! passed in for the duration of one call. Verification takes the
//! verifier's decision-point anchors through [`DecisionPointKeys`], which
//! `aip-authorize` implements for its own anchor type.
//!
//! # What each record carries
//!
//! A [`SpendAttestation`] — an authorised decision — names the policy by
//! digest, the verdict and the limit applied, and binds to the expectation by
//! its digest. It carries **no amount**: the gateway receipt's rule that
//! arguments never appear in evidence is kept one layer up.
//!
//! A [`SpendRefusal`] carries the **requested amount**. A refused request
//! never executes, and the number is the evidence a supervisor needs.

use aip_crypto::{sha256, sign_ed25519, verify_ed25519};
use aip_types::canonical::{
    encode_scope_action, put_domain, put_opt_u64, put_str, put_u16, put_u64, put_u8,
};
use aip_types::{ScopeAction, Signature};
use serde::{Deserialize, Serialize};

/// Domain tag for a spend attestation.
pub const SPEND_ATTESTATION_DOMAIN: &str = "AIP-SPEND-ATTESTATION-v1";
/// Domain tag for a spend refusal.
pub const SPEND_REFUSAL_DOMAIN: &str = "AIP-SPEND-REFUSAL-v1";
/// The record format this build reads and writes.
pub const SPEND_RECORD_VERSION: u16 = 1;

/// The decision point's key, by its id. Supplied by the verifier.
pub trait DecisionPointKeys {
    fn key(&self, decision_point_id: &str) -> Option<&[u8]>;
}

/// Which policy governed a decision: enough to fetch it and to check it is
/// the one the verifier holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyCitation {
    pub issuer_id: String,
    pub policy_id: String,
    pub revision: u64,
    pub digest: [u8; 32],
}

impl PolicyCitation {
    fn encode(&self, b: &mut Vec<u8>) {
        put_str(b, &self.issuer_id);
        put_str(b, &self.policy_id);
        put_u64(b, self.revision);
        b.extend_from_slice(&self.digest);
    }
}

/// The verdict on an authorised decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpendVerdict {
    Within,
    /// Authorised on condition of human approval above the threshold.
    ApprovalRequired,
}

impl SpendVerdict {
    fn code(self) -> u8 {
        match self {
            Self::Within => 0x01,
            Self::ApprovalRequired => 0x02,
        }
    }
}

/// An authorised decision, and the policy it was authorised under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendAttestation {
    pub version: u16,
    pub decision_point_id: String,
    pub decision_id: [u8; 16],
    pub agent_id: String,
    /// `SHA-256(ExpectedExecution::signing_preimage())`.
    pub expectation_digest: [u8; 32],
    pub policy: PolicyCitation,
    pub action: ScopeAction,
    pub verdict: SpendVerdict,
    pub limit_minor_units: u64,
    pub approval_threshold: Option<u64>,
    pub currency: String,
    pub exponent: u8,
    pub attested_at_ms: u64,
}

/// Why a request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefusalReason {
    LimitExceeded,
    AmountMissing,
    AmountNotDecimal,
    AmountOutOfRange,
}

impl RefusalReason {
    fn code(self) -> u8 {
        match self {
            Self::LimitExceeded => 0x01,
            Self::AmountMissing => 0x02,
            Self::AmountNotDecimal => 0x03,
            Self::AmountOutOfRange => 0x04,
        }
    }
}

/// A request the decision point refused on spend authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendRefusal {
    pub version: u16,
    pub decision_point_id: String,
    pub agent_id: String,
    /// `ActionParameters::digest()` of the refused request — binds the record
    /// to exactly what was asked without restating the other parameters.
    pub request_digest: [u8; 32],
    pub policy: PolicyCitation,
    pub action: ScopeAction,
    pub reason: RefusalReason,
    /// The amount asked for, when it could be read.
    pub requested_minor_units: Option<u64>,
    pub limit_minor_units: u64,
    pub currency: String,
    pub exponent: u8,
    pub refused_at_ms: u64,
}

impl SpendAttestation {
    /// Every field, domain-tagged and length-prefixed.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut b = Vec::new();
        put_domain(&mut b, SPEND_ATTESTATION_DOMAIN);
        put_u16(&mut b, self.version);
        put_str(&mut b, &self.decision_point_id);
        b.extend_from_slice(&self.decision_id);
        put_str(&mut b, &self.agent_id);
        b.extend_from_slice(&self.expectation_digest);
        self.policy.encode(&mut b);
        encode_scope_action(&mut b, &self.action);
        put_u8(&mut b, self.verdict.code());
        put_u64(&mut b, self.limit_minor_units);
        put_opt_u64(&mut b, &self.approval_threshold);
        put_str(&mut b, &self.currency);
        put_u8(&mut b, self.exponent);
        put_u64(&mut b, self.attested_at_ms);
        b
    }
}

impl SpendRefusal {
    /// Every field, domain-tagged and length-prefixed.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut b = Vec::new();
        put_domain(&mut b, SPEND_REFUSAL_DOMAIN);
        put_u16(&mut b, self.version);
        put_str(&mut b, &self.decision_point_id);
        put_str(&mut b, &self.agent_id);
        b.extend_from_slice(&self.request_digest);
        self.policy.encode(&mut b);
        encode_scope_action(&mut b, &self.action);
        put_u8(&mut b, self.reason.code());
        put_opt_u64(&mut b, &self.requested_minor_units);
        put_u64(&mut b, self.limit_minor_units);
        put_str(&mut b, &self.currency);
        put_u8(&mut b, self.exponent);
        put_u64(&mut b, self.refused_at_ms);
        b
    }
}

/// Why a record did not verify or could not be signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    UnsupportedVersion(u16),
    DecisionPointNotAnchored(String),
    SignerMismatch,
    PayloadHashMismatch,
    SignatureInvalid,
    Crypto(String),
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for RecordError {}

fn sign(preimage: &[u8], signer: &str, key: &[u8]) -> Result<Signature, RecordError> {
    sign_ed25519(key, signer, preimage).map_err(|e| RecordError::Crypto(format!("{e:?}")))
}

fn verify(
    version: u16,
    preimage: &[u8],
    signer: &str,
    signature: &Signature,
    keys: &dyn DecisionPointKeys,
) -> Result<(), RecordError> {
    if version != SPEND_RECORD_VERSION {
        return Err(RecordError::UnsupportedVersion(version));
    }
    let key = keys
        .key(signer)
        .ok_or_else(|| RecordError::DecisionPointNotAnchored(signer.to_string()))?;
    if signature.signer_id != signer {
        return Err(RecordError::SignerMismatch);
    }
    if signature.payload_hash != sha256(preimage) {
        return Err(RecordError::PayloadHashMismatch);
    }
    match verify_ed25519(key, signature) {
        Ok(true) => Ok(()),
        Ok(false) => Err(RecordError::SignatureInvalid),
        Err(e) => Err(RecordError::Crypto(format!("{e:?}"))),
    }
}

/// An attestation and the decision point's signature over it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSpendAttestation {
    pub attestation: SpendAttestation,
    pub signature: Signature,
}

/// A refusal and the decision point's signature over it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSpendRefusal {
    pub refusal: SpendRefusal,
    pub signature: Signature,
}

impl SignedSpendAttestation {
    /// Sign as `attestation.decision_point_id` with that decision point's key.
    pub fn sign(
        attestation: SpendAttestation,
        decision_point_key: &[u8],
    ) -> Result<Self, RecordError> {
        let signature = sign(
            &attestation.signing_preimage(),
            &attestation.decision_point_id,
            decision_point_key,
        )?;
        Ok(Self {
            attestation,
            signature,
        })
    }

    /// Verify under the verifier's decision-point anchors.
    pub fn verify(&self, keys: &dyn DecisionPointKeys) -> Result<(), RecordError> {
        let a = &self.attestation;
        verify(
            a.version,
            &a.signing_preimage(),
            &a.decision_point_id,
            &self.signature,
            keys,
        )
    }
}

impl SignedSpendRefusal {
    /// Sign as `refusal.decision_point_id` with that decision point's key.
    pub fn sign(refusal: SpendRefusal, decision_point_key: &[u8]) -> Result<Self, RecordError> {
        let signature = sign(
            &refusal.signing_preimage(),
            &refusal.decision_point_id,
            decision_point_key,
        )?;
        Ok(Self { refusal, signature })
    }

    /// Verify under the verifier's decision-point anchors.
    pub fn verify(&self, keys: &dyn DecisionPointKeys) -> Result<(), RecordError> {
        let r = &self.refusal;
        verify(
            r.version,
            &r.signing_preimage(),
            &r.decision_point_id,
            &self.signature,
            keys,
        )
    }
}
