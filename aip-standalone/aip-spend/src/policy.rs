//! The institution-signed spend policy.
//!
//! Per agent, one rule per governed action: which request parameter carries
//! the amount, in which currency and scale, the most a single action may
//! move, and the amount above which a human must approve. Signed by the
//! institution's policy authority and verified under anchors the verifier
//! holds — a policy cannot name the key it is judged by.

use crate::limits::*;
use aip_crypto::{sha256, sign_ed25519, verify_ed25519};
use aip_types::canonical::{
    encode_scope_action, put_bytes, put_domain, put_str, put_u16, put_u32, put_u64, put_u8,
};
use aip_types::{ScopeAction, Signature};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Domain tag for a policy's signing preimage.
pub const SPEND_POLICY_DOMAIN: &str = "AIP-SPEND-POLICY-v1";

/// The policy format this build reads and writes.
pub const SPEND_POLICY_VERSION: u16 = 1;

/// How one governed action is limited. Amounts are integer minor units.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendRule {
    pub action: ScopeAction,
    /// The request parameter whose value is the amount, as ASCII decimal
    /// minor units, e.g. `amount_cents`.
    pub amount_parameter: String,
    pub currency: String,
    pub exponent: u8,
    /// A request above this is refused.
    pub max_per_action: u64,
    /// A request above this, and within the maximum, needs human approval.
    #[serde(default)]
    pub approval_above: Option<u64>,
}

/// What an institution permits one agent to spend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendPolicy {
    pub version: u16,
    pub policy_id: String,
    /// The policy authority that signs. Maps to an anchor.
    pub issuer_id: String,
    /// Monotonic per `policy_id`; a later revision supersedes an earlier one.
    pub revision: u64,
    pub issued_at_ms: u64,
    /// The one agent this policy governs.
    pub agent_id: String,
    pub rules: Vec<SpendRule>,
}

/// A policy and its issuer's signature over its canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSpendPolicy {
    pub policy: SpendPolicy,
    pub signature: Signature,
}

/// Why a policy was refused or could not be signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendError {
    UnsupportedVersion(u16),
    Empty(&'static str),
    TooLong(&'static str),
    TooManyRules,
    DuplicateRule,
    BadCurrency,
    ExponentTooLarge,
    /// The approval threshold is above the maximum, so it could never apply.
    ThresholdAboveMaximum,
    IssuerNotAnchored(String),
    SignerMismatch,
    PayloadHashMismatch,
    SignatureInvalid,
    Crypto(String),
}

impl std::fmt::Display for SpendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SpendError {}

fn id(field: &'static str, s: &str) -> Result<(), SpendError> {
    if s.is_empty() {
        return Err(SpendError::Empty(field));
    }
    if s.len() > MAX_ID_LEN {
        return Err(SpendError::TooLong(field));
    }
    Ok(())
}

impl SpendRule {
    fn validate(&self) -> Result<(), SpendError> {
        id("amount_parameter", &self.amount_parameter)?;
        if let ScopeAction::Custom(c) = &self.action {
            id("action", c)?;
        }
        let ok = self.currency.len() == CURRENCY_CODE_LEN
            && self.currency.bytes().all(|b| b.is_ascii_uppercase());
        if !ok {
            return Err(SpendError::BadCurrency);
        }
        if self.exponent > MAX_AMOUNT_EXPONENT {
            return Err(SpendError::ExponentTooLarge);
        }
        if self.approval_above.is_some_and(|t| t > self.max_per_action) {
            return Err(SpendError::ThresholdAboveMaximum);
        }
        Ok(())
    }

    fn encode(&self, b: &mut Vec<u8>) {
        encode_scope_action(b, &self.action);
        put_str(b, &self.amount_parameter);
        put_str(b, &self.currency);
        put_u8(b, self.exponent);
        put_u64(b, self.max_per_action);
        match self.approval_above {
            None => put_u8(b, 0),
            Some(t) => {
                put_u8(b, 1);
                put_u64(b, t);
            }
        }
    }
}

/// The action's canonical bytes, used as a set key so duplicates are judged
/// exactly as the core distinguishes actions.
pub(crate) fn action_key(a: &ScopeAction) -> Vec<u8> {
    let mut b = Vec::new();
    encode_scope_action(&mut b, a);
    b
}

impl SpendPolicy {
    /// Every bound, every format, and one rule per action.
    pub fn validate(&self) -> Result<(), SpendError> {
        if self.version != SPEND_POLICY_VERSION {
            return Err(SpendError::UnsupportedVersion(self.version));
        }
        id("policy_id", &self.policy_id)?;
        id("issuer_id", &self.issuer_id)?;
        id("agent_id", &self.agent_id)?;
        if self.rules.len() > MAX_RULES {
            return Err(SpendError::TooManyRules);
        }
        let mut seen = BTreeSet::new();
        for r in &self.rules {
            r.validate()?;
            if !seen.insert(action_key(&r.action)) {
                return Err(SpendError::DuplicateRule);
            }
        }
        Ok(())
    }

    /// Canonical bytes: domain-tagged, length-prefixed, rules sorted by their
    /// own encoding so authoring order is not a change to the policy.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        put_domain(&mut b, SPEND_POLICY_DOMAIN);
        put_u16(&mut b, self.version);
        put_str(&mut b, &self.policy_id);
        put_str(&mut b, &self.issuer_id);
        put_u64(&mut b, self.revision);
        put_u64(&mut b, self.issued_at_ms);
        put_str(&mut b, &self.agent_id);
        let mut rules: Vec<Vec<u8>> = self
            .rules
            .iter()
            .map(|r| {
                let mut e = Vec::new();
                r.encode(&mut e);
                e
            })
            .collect();
        rules.sort();
        put_u32(&mut b, rules.len() as u32);
        for r in &rules {
            put_bytes(&mut b, r);
        }
        b
    }

    /// SHA-256 of the canonical bytes. What every record cites.
    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }
}

impl SignedSpendPolicy {
    /// Validate and sign as `policy.issuer_id`.
    pub fn sign(policy: SpendPolicy, issuer_private_key: &[u8]) -> Result<Self, SpendError> {
        policy.validate()?;
        let signature = sign_ed25519(
            issuer_private_key,
            &policy.issuer_id,
            &policy.canonical_bytes(),
        )
        .map_err(|e| SpendError::Crypto(format!("{e:?}")))?;
        Ok(Self { policy, signature })
    }

    /// Verify under the verifier's anchors. The only way to obtain a
    /// [`VerifiedSpendPolicy`].
    pub fn verify(&self, anchors: &SpendPolicyAnchors) -> Result<VerifiedSpendPolicy, SpendError> {
        let p = &self.policy;
        p.validate()?;
        let key = anchors
            .get(&p.issuer_id)
            .ok_or_else(|| SpendError::IssuerNotAnchored(p.issuer_id.clone()))?;
        if self.signature.signer_id != p.issuer_id {
            return Err(SpendError::SignerMismatch);
        }
        if self.signature.payload_hash != sha256(&p.canonical_bytes()) {
            return Err(SpendError::PayloadHashMismatch);
        }
        match verify_ed25519(key, &self.signature) {
            Ok(true) => Ok(VerifiedSpendPolicy(p.clone())),
            Ok(false) => Err(SpendError::SignatureInvalid),
            Err(e) => Err(SpendError::Crypto(format!("{e:?}"))),
        }
    }
}

/// A policy whose signature has been checked under the verifier's anchors.
/// Constructible only by [`SignedSpendPolicy::verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSpendPolicy(SpendPolicy);

impl VerifiedSpendPolicy {
    pub fn policy(&self) -> &SpendPolicy {
        &self.0
    }

    /// The rule governing `action`, if any.
    pub fn rule_for(&self, action: &ScopeAction) -> Option<&SpendRule> {
        let k = action_key(action);
        self.0.rules.iter().find(|r| action_key(&r.action) == k)
    }
}

/// Policy issuers the verifier trusts, by issuer id. The verifier's own.
#[derive(Debug, Clone, Default)]
pub struct SpendPolicyAnchors {
    keys: BTreeMap<String, Vec<u8>>,
}

impl SpendPolicyAnchors {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn trust(mut self, issuer_id: &str, public_key: &[u8]) -> Self {
        self.keys.insert(issuer_id.to_string(), public_key.to_vec());
        self
    }

    pub fn get(&self, issuer_id: &str) -> Option<&[u8]> {
        self.keys.get(issuer_id).map(Vec::as_slice)
    }
}
