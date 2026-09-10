//! `ExpectedExecution` — the signed output of a decision point — plus its
//! canonical preimage, offline verification, and temporal semantics.
//!
//! ## Signing preimage (deterministic, injective, domain-tagged)
//!
//! ```text
//! put_domain("GHOST/ExpectedExecution/v1")
//! put_u16(version)
//! decision_id            (16 bytes, fixed)
//! put_str(decision_point_id)
//! put_str(agent_id)
//! authority.root_jti     (16 bytes, fixed)
//! put_u32(len) ‖ chain_jtis…   (16 bytes each, fixed)
//! encode_scope_action(action_kind)
//! parameter_digest       (32 bytes, fixed)
//! put_bytes(execution_binding.canonical_bytes())
//! put_u64(issued_at)
//! put_u64(valid_until)
//! ```
//!
//! `decision_sig = sign_ed25519(decision_point_key, decision_point_id, preimage)`.
//! Every security-sensitive field is inside the preimage; nothing is implicit.
//!
//! ## Temporal contract
//!
//! Unix milliseconds, matching every other timestamp in AIP. The window is
//! **inclusive at both ends**, `[issued_at, valid_until]`, following the R10
//! convention established in Skill 3 (`decided_at == expires_at` is inside).
//! The verifier supplies `T` explicitly; this module never reads a clock.

use std::collections::{BTreeMap, HashMap};

use aip_crypto::{sha256, verify_ed25519};
use aip_types::canonical::*;
use aip_types::{AipError, ExecutionBinding, ScopeAction, Signature, EXECUTION_BINDING_VERSION};
use serde::{Deserialize, Serialize};

/// Domain tag leading the `ExpectedExecution` signing preimage.
pub const EXPECTED_EXECUTION_DOMAIN: &str = "GHOST/ExpectedExecution/v1";
/// Domain tag leading the canonical action-parameter encoding.
pub const ACTION_PARAMETERS_DOMAIN: &str = "GHOST/ActionParameters/v1";
/// Structure version of `ExpectedExecution`.
pub const EXPECTED_EXECUTION_VERSION: u16 = 1;

// ─── Authority reference ───

/// Which authority chain the decision was made under — by token identity,
/// not by copying the tokens. The tokens themselves live in the packet and
/// are verified there (R5/R6); here they are named so the expectation cannot
/// be re-attached to a different chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityRef {
    pub root_jti: [u8; 16],
    pub chain_jtis: Vec<[u8; 16]>,
}

// ─── Action parameters ───

/// Canonical, order-independent action parameters.
///
/// Keys are unique; entries are encoded in byte order of the key so two
/// callers supplying the same map in different insertion orders produce the
/// same digest, while any difference in a key or value produces a different
/// digest.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ActionParameters {
    entries: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParameterError {
    DuplicateKey(String),
}

impl std::fmt::Display for ParameterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParameterError::DuplicateKey(k) => write!(f, "duplicate parameter key `{k}`"),
        }
    }
}

impl std::error::Error for ParameterError {}

impl ActionParameters {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build from `(key, value)` pairs. A repeated key is an error, never a
    /// silent overwrite — the digest must represent one unambiguous set.
    pub fn from_pairs<I, K, V>(pairs: I) -> Result<Self, ParameterError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<Vec<u8>>,
    {
        let mut entries = BTreeMap::new();
        for (k, v) in pairs {
            let k = k.into();
            if entries.contains_key(&k) {
                return Err(ParameterError::DuplicateKey(k));
            }
            entries.insert(k, v.into());
        }
        Ok(Self { entries })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.entries.get(key).map(|v| v.as_slice())
    }

    /// Domain-tagged, length-prefixed, key-sorted encoding.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, ACTION_PARAMETERS_DOMAIN);
        put_u32(&mut buf, self.entries.len() as u32);
        for (k, v) in &self.entries {
            put_str(&mut buf, k);
            put_bytes(&mut buf, v);
        }
        buf
    }

    /// `parameter_digest = SHA-256(canonical_bytes)`.
    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }
}

// ─── ExpectedExecution ───

/// A signed statement by a decision point that a specific execution is
/// authorized within a bounded window.
///
/// It proves that the named decision point signed this expectation. It does
/// **not** prove that the process ran, that the action happened, that the
/// parameters were used, or that anyone observed anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedExecution {
    pub version: u16,
    /// Fresh per decision; the reconciliation join key shared with
    /// `DecisionRecord.decision_id`.
    pub decision_id: [u8; 16],
    /// Identifier of the signing decision point; verifiers map it to a
    /// trusted public key.
    pub decision_point_id: String,
    /// The agent the expectation is issued for.
    pub agent_id: String,
    /// The authority chain the decision was made under.
    pub authority: AuthorityRef,
    /// The authorized action kind.
    pub action_kind: ScopeAction,
    /// Digest of the authorized parameter set ([`ActionParameters::digest`]).
    pub parameter_digest: [u8; 32],
    /// The process instance the authorization is bound to (Stage 1).
    pub execution_binding: ExecutionBinding,
    /// Start of the validity window (inclusive), Unix ms.
    pub issued_at: u64,
    /// End of the validity window (inclusive), Unix ms. Mandatory: an
    /// expectation is always bounded.
    pub valid_until: u64,
    /// Decision-point signature over [`ExpectedExecution::signing_preimage`].
    pub decision_sig: Signature,
}

/// Where `T` sits relative to the expectation's window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemporalStatus {
    /// `T < issued_at`
    NotYetValid,
    /// `issued_at <= T <= valid_until`
    Valid,
    /// `T > valid_until`
    Expired,
}

impl ExpectedExecution {
    /// The exact bytes that are hashed into `decision_sig.payload_hash`.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, EXPECTED_EXECUTION_DOMAIN);
        put_u16(&mut buf, self.version);
        buf.extend_from_slice(&self.decision_id);
        put_str(&mut buf, &self.decision_point_id);
        put_str(&mut buf, &self.agent_id);
        buf.extend_from_slice(&self.authority.root_jti);
        put_u32(&mut buf, self.authority.chain_jtis.len() as u32);
        for jti in &self.authority.chain_jtis {
            buf.extend_from_slice(jti);
        }
        encode_scope_action(&mut buf, &self.action_kind);
        buf.extend_from_slice(&self.parameter_digest);
        put_bytes(&mut buf, &self.execution_binding.canonical_bytes());
        put_u64(&mut buf, self.issued_at);
        put_u64(&mut buf, self.valid_until);
        buf
    }

    /// Is the expectation in force at `t_ms`? Purely arithmetic; the caller
    /// chooses `T` (e.g. an action's signed `performed_at`).
    pub fn temporal_status_at(&self, t_ms: u64) -> TemporalStatus {
        if t_ms < self.issued_at {
            TemporalStatus::NotYetValid
        } else if t_ms > self.valid_until {
            TemporalStatus::Expired
        } else {
            TemporalStatus::Valid
        }
    }

    /// Does this expectation refer to exactly this decision, agent and
    /// execution identity? Compares `identity_bytes` of the binding (agent +
    /// process instance + executable contents), never PID alone.
    pub fn covers(
        &self,
        decision_id: &[u8; 16],
        agent_id: &str,
        binding: &ExecutionBinding,
    ) -> bool {
        self.decision_id == *decision_id
            && self.agent_id == agent_id
            && self.execution_binding.same_execution(binding)
    }
}

// ─── Offline verification ───

/// The verifier's trust decision: which decision-point identifiers map to
/// which public keys. Supplied by the verifier, never by the packet or agent.
#[derive(Debug, Clone, Default)]
pub struct DecisionPointTrustAnchors {
    keys: HashMap<String, Vec<u8>>,
}

impl DecisionPointTrustAnchors {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn trust(mut self, decision_point_id: &str, public_key: &[u8]) -> Self {
        self.keys
            .insert(decision_point_id.to_string(), public_key.to_vec());
        self
    }

    pub fn get(&self, decision_point_id: &str) -> Option<&[u8]> {
        self.keys.get(decision_point_id).map(|k| k.as_slice())
    }

    /// Every anchor, in a deterministic order, so a written file is stable.
    pub fn entries(&self) -> Vec<(String, Vec<u8>)> {
        let mut v: Vec<(String, Vec<u8>)> = self
            .keys
            .iter()
            .map(|(id, key)| (id.clone(), key.clone()))
            .collect();
        v.sort();
        v
    }
}

/// Why an `ExpectedExecution` failed verification. The variants distinguish
/// "cryptographically invalid" from "not trusted" from "structurally wrong";
/// callers must not flatten them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedVerifyError {
    UnsupportedVersion(u16),
    /// `decision_point_id == agent_id`: the agent is naming itself as its
    /// own decision point.
    SelfAuthorization,
    /// The anchor key for the decision point equals the agent's own public
    /// key: the agent holds the decision key.
    DecisionKeyIsAgentKey,
    /// `valid_until < issued_at`.
    InvalidWindow {
        issued_at: u64,
        valid_until: u64,
    },
    /// The embedded binding names a different agent.
    BindingAgentMismatch,
    /// The embedded binding is degenerate (see Stage 1 R15 rules).
    BindingMalformed(&'static str),
    /// No trust anchor for this decision point id. The signature may be
    /// perfectly valid — the verifier simply does not trust the signer.
    UntrustedDecisionPoint(String),
    /// `decision_sig.signer_id != decision_point_id`.
    SignerMismatch,
    /// `decision_sig.payload_hash != sha256(signing_preimage)`.
    PayloadHashMismatch,
    /// Ed25519 verification failed under the anchored key.
    SignatureInvalid,
    Crypto(AipError),
}

impl std::fmt::Display for ExpectedVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ExpectedVerifyError {}

fn check_structure(ee: &ExpectedExecution) -> Result<(), ExpectedVerifyError> {
    if ee.version != EXPECTED_EXECUTION_VERSION {
        return Err(ExpectedVerifyError::UnsupportedVersion(ee.version));
    }
    if ee.decision_point_id == ee.agent_id {
        return Err(ExpectedVerifyError::SelfAuthorization);
    }
    if ee.valid_until < ee.issued_at {
        return Err(ExpectedVerifyError::InvalidWindow {
            issued_at: ee.issued_at,
            valid_until: ee.valid_until,
        });
    }
    let b = &ee.execution_binding;
    if b.agent_id != ee.agent_id {
        return Err(ExpectedVerifyError::BindingAgentMismatch);
    }
    if b.version != EXECUTION_BINDING_VERSION {
        return Err(ExpectedVerifyError::BindingMalformed("version"));
    }
    if b.process.pid == 0 {
        return Err(ExpectedVerifyError::BindingMalformed("pid"));
    }
    if b.process.pid_start_time_ticks == 0 {
        return Err(ExpectedVerifyError::BindingMalformed(
            "pid_start_time_ticks",
        ));
    }
    if b.process.boot_id == [0u8; 16] {
        return Err(ExpectedVerifyError::BindingMalformed("boot_id"));
    }
    if b.exe_content_sha256 == [0u8; 32] {
        return Err(ExpectedVerifyError::BindingMalformed("exe_content_sha256"));
    }
    Ok(())
}

/// Verify an `ExpectedExecution` offline against the verifier's trust
/// anchors. Succeeds iff the structure is sound, the decision point is
/// trusted, and its signature covers exactly this record.
///
/// Success means: *the trusted decision point signed this expectation*. It
/// does not mean the execution happened.
pub fn verify_expected_execution(
    ee: &ExpectedExecution,
    anchors: &DecisionPointTrustAnchors,
) -> Result<(), ExpectedVerifyError> {
    check_structure(ee)?;
    let key = anchors
        .get(&ee.decision_point_id)
        .ok_or_else(|| ExpectedVerifyError::UntrustedDecisionPoint(ee.decision_point_id.clone()))?;
    if ee.decision_sig.signer_id != ee.decision_point_id {
        return Err(ExpectedVerifyError::SignerMismatch);
    }
    if ee.decision_sig.payload_hash != sha256(&ee.signing_preimage()) {
        return Err(ExpectedVerifyError::PayloadHashMismatch);
    }
    match verify_ed25519(key, &ee.decision_sig) {
        Ok(true) => Ok(()),
        Ok(false) => Err(ExpectedVerifyError::SignatureInvalid),
        Err(e) => Err(ExpectedVerifyError::Crypto(e)),
    }
}

/// As [`verify_expected_execution`], additionally rejecting an anchor whose
/// key is the agent's own public key (the agent would hold the decision key).
/// Use this whenever the agent's public key is known — e.g. from the
/// `EvidencePacket` it produced.
pub fn verify_expected_execution_for_agent(
    ee: &ExpectedExecution,
    anchors: &DecisionPointTrustAnchors,
    agent_public_key: &[u8],
) -> Result<(), ExpectedVerifyError> {
    if let Some(key) = anchors.get(&ee.decision_point_id) {
        if key == agent_public_key {
            return Err(ExpectedVerifyError::DecisionKeyIsAgentKey);
        }
    }
    verify_expected_execution(ee, anchors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameters_are_order_independent_and_content_sensitive() {
        let a = ActionParameters::from_pairs([
            ("amount", b"48200".to_vec()),
            ("invoice", b"INV-1".to_vec()),
        ])
        .unwrap();
        let b = ActionParameters::from_pairs([
            ("invoice", b"INV-1".to_vec()),
            ("amount", b"48200".to_vec()),
        ])
        .unwrap();
        assert_eq!(a.digest(), b.digest());
        let c = ActionParameters::from_pairs([
            ("amount", b"48201".to_vec()),
            ("invoice", b"INV-1".to_vec()),
        ])
        .unwrap();
        assert_ne!(a.digest(), c.digest());
        // key/value boundary collisions
        let d = ActionParameters::from_pairs([("ab", b"c".to_vec())]).unwrap();
        let e = ActionParameters::from_pairs([("a", b"bc".to_vec())]).unwrap();
        assert_ne!(d.digest(), e.digest());
        // splitting one entry into two
        let f = ActionParameters::from_pairs([("a", b"".to_vec()), ("b", b"c".to_vec())]).unwrap();
        assert_ne!(d.digest(), f.digest());
        assert_ne!(ActionParameters::empty().digest(), f.digest());
    }

    #[test]
    fn duplicate_parameter_key_is_an_error_not_an_overwrite() {
        let r = ActionParameters::from_pairs([("k", b"1".to_vec()), ("k", b"2".to_vec())]);
        assert_eq!(r, Err(ParameterError::DuplicateKey("k".into())));
    }

    #[test]
    fn parameter_encoding_leads_with_domain() {
        let p = ActionParameters::empty().canonical_bytes();
        let tag = ACTION_PARAMETERS_DOMAIN.as_bytes();
        assert_eq!(&p[4..4 + tag.len()], tag);
    }
}
