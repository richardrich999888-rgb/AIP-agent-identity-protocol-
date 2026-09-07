//! Policy, decision, outcome and the signed record. Everything a third
//! party needs to answer *why was containment attempted, on what authority,
//! against whom, and what happened* (Skill 9 §18, §19, §21).

use aip_crypto::{sha256, sign_ed25519, verify_ed25519};
use aip_observe::ObserverState;
use aip_reconcile::{EvidenceRef, EvidenceStrength, ReconciliationResult};
use aip_types::canonical::*;
use aip_types::{AipError, ProcessInstance, Signature};
use aip_warrant::ProtectedIdentitySet;
use serde::{Deserialize, Serialize};

use crate::actuator::{ActuationFailure, Mechanism};
use crate::attribution::AttributionFailure;

/// Domain tag leading the canonical encoding of [`ContainmentRecord`].
pub const CONTAINMENT_DOMAIN: &str = "SYNTRIASS/GHOST/CONTAINMENT/v1";
pub const CONTAINMENT_VERSION: u16 = 1;

// ─── Policy ───

/// Whether the boundary may act at all (Skill 9 §10). Absence of
/// configuration is `Advisory`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ContainmentMode {
    /// Decide, record, never actuate. The default.
    #[default]
    Advisory,
    /// Actuate only when an operator acknowledgement names the warrant.
    OperatorEnabled,
    /// Actuate on a valid warrant the engine issued as autonomous.
    AutonomousEnabled,
}

impl ContainmentMode {
    pub fn code(self) -> u8 {
        match self {
            ContainmentMode::Advisory => 0x01,
            ContainmentMode::OperatorEnabled => 0x02,
            ContainmentMode::AutonomousEnabled => 0x03,
        }
    }
}

/// The closed set of actions (Skill 9 §16). No string, path or command
/// line is representable here; the only actuation the product supports is
/// a cgroup v2 freeze of the attributed process instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainmentAction {
    AdvisoryOnly,
    FreezeProcess,
}

impl ContainmentAction {
    pub const ALL: [ContainmentAction; 2] = [
        ContainmentAction::AdvisoryOnly,
        ContainmentAction::FreezeProcess,
    ];

    pub fn code(self) -> u8 {
        match self {
            ContainmentAction::AdvisoryOnly => 0x01,
            ContainmentAction::FreezeProcess => 0x02,
        }
    }
}

/// Operator policy for the boundary. Advisory, no action, nothing
/// protected, health no older than thirty seconds — by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContainmentPolicy {
    pub version: u32,
    pub mode: ContainmentMode,
    pub action: ContainmentAction,
    /// Reused from the warrant engine: one protected-identity model, not
    /// two.
    pub protected: ProtectedIdentitySet,
    /// The cited observer's newest signed health must be no older than this
    /// at decision time.
    pub max_health_age_ms: u64,
}

impl Default for ContainmentPolicy {
    fn default() -> Self {
        Self {
            version: 1,
            mode: ContainmentMode::Advisory,
            action: ContainmentAction::AdvisoryOnly,
            protected: ProtectedIdentitySet::default(),
            max_health_age_ms: 30_000,
        }
    }
}

/// An operator's acknowledgement of one warrant, required under
/// `OperatorEnabled`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorAcknowledgement {
    pub operator_id: String,
    pub warrant_id: [u8; 16],
    pub acknowledged_at_ms: u64,
}

// ─── Refusal ───

/// Why the boundary did not act. A refusal never enables anything and is
/// itself recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Refusal {
    /// Not authenticated under the warrant trust root, or mutated.
    WarrantInvalid(String),
    NoValidityBound,
    WarrantNotYetValid {
        issued_at: u64,
        now: u64,
    },
    WarrantExpired {
        valid_until: u64,
        now: u64,
    },
    ResponseNotContain(String),
    TargetNotWorkload,
    /// Explicit match: anything but `Proven`.
    StrengthBelowProven(EvidenceStrength),
    ResultNotWorkloadViolation(ReconciliationResult),
    ObservationUnavailable,
    NoEvidenceReference,
    WarrantNotAutonomous,
    WarrantMarkedProtected,
    SubjectUnbound,
    SubjectMismatch {
        warrant_subject: String,
        target_agent: String,
    },
    Protected {
        identity: String,
    },
    OperatorAcknowledgementMissing,
    OperatorAcknowledgementMismatch,
    ObserverHealthMissing,
    ObserverHealthUntrusted(String),
    ObserverNotActive(ObserverState),
    ObserverHealthStale {
        emitted_at_ms: u64,
        now: u64,
    },
    ObserverNotCited {
        observer_id: String,
    },
    Replayed {
        warrant_id: [u8; 16],
    },
    Attribution(AttributionFailure),
}

impl Refusal {
    pub fn code(&self) -> u8 {
        match self {
            Refusal::WarrantInvalid(_) => 0x01,
            Refusal::NoValidityBound => 0x02,
            Refusal::WarrantNotYetValid { .. } => 0x03,
            Refusal::WarrantExpired { .. } => 0x04,
            Refusal::ResponseNotContain(_) => 0x05,
            Refusal::TargetNotWorkload => 0x06,
            Refusal::StrengthBelowProven(_) => 0x07,
            Refusal::ResultNotWorkloadViolation(_) => 0x08,
            Refusal::ObservationUnavailable => 0x09,
            Refusal::NoEvidenceReference => 0x0a,
            Refusal::WarrantNotAutonomous => 0x0b,
            Refusal::WarrantMarkedProtected => 0x0c,
            Refusal::SubjectUnbound => 0x0d,
            Refusal::SubjectMismatch { .. } => 0x0e,
            Refusal::Protected { .. } => 0x0f,
            Refusal::OperatorAcknowledgementMissing => 0x10,
            Refusal::OperatorAcknowledgementMismatch => 0x11,
            Refusal::ObserverHealthMissing => 0x12,
            Refusal::ObserverHealthUntrusted(_) => 0x13,
            Refusal::ObserverNotActive(_) => 0x14,
            Refusal::ObserverHealthStale { .. } => 0x15,
            Refusal::ObserverNotCited { .. } => 0x16,
            Refusal::Replayed { .. } => 0x17,
            Refusal::Attribution(_) => 0x18,
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── Decision ───

/// The execution identity the decision is about: agent, process instance
/// and executable contents — never a pid, path or name alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetIdentity {
    pub agent_id: String,
    pub process: ProcessInstance,
    pub exe_content_sha256: [u8; 32],
}

impl TargetIdentity {
    fn encode(&self, buf: &mut Vec<u8>) {
        put_str(buf, &self.agent_id);
        put_u32(buf, self.process.pid);
        put_u64(buf, self.process.pid_start_time_ticks);
        buf.extend_from_slice(&self.process.boot_id);
        buf.extend_from_slice(&self.exe_content_sha256);
    }
}

/// What the boundary decided, before anything was done (Skill 9 §18).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentDecision {
    pub version: u16,
    /// Deterministic: derived from warrant id, target, policy version and
    /// time.
    pub decision_id: [u8; 16],
    pub warrant_id: [u8; 16],
    /// SHA-256 of the warrant's signing preimage.
    pub warrant_digest: [u8; 32],
    /// The reconciliation record the warrant rests on, as the warrant
    /// carried it.
    pub reconciliation_digest: [u8; 32],
    pub reconciliation_result: ReconciliationResult,
    /// Verbatim from the warrant. Never raised or lowered here.
    pub evidence_strength: EvidenceStrength,
    pub evidence_refs: Vec<EvidenceRef>,
    /// What the request named. Whether it was established live is stated
    /// by the outcome (`Refused(Attribution(..))` when it was not).
    pub target: TargetIdentity,
    pub action: ContainmentAction,
    pub mode: ContainmentMode,
    pub policy_version: u32,
    /// The warrant engine issued this warrant under autonomous policy.
    pub warrant_autonomous: bool,
    pub decided_at_ms: u64,
    /// The warrant's bound, carried so the record shows the window the
    /// decision was inside.
    pub valid_until: Option<u64>,
}

impl ContainmentDecision {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_u16(&mut buf, self.version);
        buf.extend_from_slice(&self.decision_id);
        buf.extend_from_slice(&self.warrant_id);
        buf.extend_from_slice(&self.warrant_digest);
        buf.extend_from_slice(&self.reconciliation_digest);
        put_u8(&mut buf, self.reconciliation_result.code());
        put_u8(&mut buf, self.evidence_strength.code());
        put_u32(&mut buf, self.evidence_refs.len() as u32);
        for r in &self.evidence_refs {
            put_bytes(&mut buf, &r.canonical_bytes());
        }
        self.target.encode(&mut buf);
        put_u8(&mut buf, self.action.code());
        put_u8(&mut buf, self.mode.code());
        put_u32(&mut buf, self.policy_version);
        put_u8(&mut buf, u8::from(self.warrant_autonomous));
        put_u64(&mut buf, self.decided_at_ms);
        put_opt_u64(&mut buf, &self.valid_until);
        buf
    }
}

// ─── Outcome and record ───

/// What happened. `Applied` is written only after the actuator confirmed
/// the effect; `Failed` is fail-open — nothing is contained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Refused(Refusal),
    /// Every gate passed; the policy is advisory; nothing was done.
    Advisory,
    Applied {
        mechanism: Mechanism,
        handle: String,
    },
    Failed(ActuationFailure),
    Released {
        mechanism: Mechanism,
        handle: String,
    },
}

impl Outcome {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Outcome::Refused(r) => {
                put_u8(buf, 0x01);
                put_u8(buf, r.code());
                put_str(buf, &format!("{r:?}"));
            }
            Outcome::Advisory => put_u8(buf, 0x02),
            Outcome::Applied { mechanism, handle } => {
                put_u8(buf, 0x03);
                put_u8(buf, mechanism.code());
                put_str(buf, handle);
            }
            Outcome::Failed(f) => {
                put_u8(buf, 0x04);
                put_u8(buf, f.code());
                put_str(buf, &format!("{f:?}"));
            }
            Outcome::Released { mechanism, handle } => {
                put_u8(buf, 0x05);
                put_u8(buf, mechanism.code());
                put_str(buf, handle);
            }
        }
    }
}

/// One attempt, accountable (Skill 9 §19).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentRecord {
    pub version: u16,
    pub decision: ContainmentDecision,
    pub outcome: Outcome,
    pub recorded_at_ms: u64,
}

impl ContainmentRecord {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, CONTAINMENT_DOMAIN);
        put_u16(&mut buf, self.version);
        put_bytes(&mut buf, &self.decision.canonical_bytes());
        self.outcome.encode(&mut buf);
        put_u64(&mut buf, self.recorded_at_ms);
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }
}

/// [`ContainmentRecord`] plus the containment authority's signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedContainmentRecord {
    pub record: ContainmentRecord,
    pub signature: Signature,
}

// ─── Authority and verification ───

/// The containment authority: a distinct key holder. Not the warrant
/// authority, not the decision point, not an observer, not the agent.
pub struct ContainmentAuthority {
    id: String,
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl std::fmt::Debug for ContainmentAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContainmentAuthority")
            .field("id", &self.id)
            .field("public_key", &self.public_key)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

impl ContainmentAuthority {
    pub fn new(id: &str, private_key: &[u8], public_key: &[u8]) -> Result<Self, AipError> {
        if private_key.len() != 32 || public_key.len() != 32 {
            return Err(AipError::InvalidPublicKey);
        }
        Ok(Self {
            id: id.to_string(),
            private_key: private_key.to_vec(),
            public_key: public_key.to_vec(),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Sign a record. Proves origin, not that the action was right.
    pub fn sign(&self, record: ContainmentRecord) -> Result<SignedContainmentRecord, AipError> {
        let signature = sign_ed25519(&self.private_key, &self.id, &record.canonical_bytes())?;
        Ok(SignedContainmentRecord { record, signature })
    }
}

/// Verifier-supplied containment authority keys, by id.
#[derive(Debug, Clone, Default)]
pub struct ContainmentTrustAnchors {
    keys: Vec<(String, Vec<u8>)>,
}

impl ContainmentTrustAnchors {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn trust(mut self, authority_id: &str, public_key: &[u8]) -> Self {
        self.keys
            .push((authority_id.to_string(), public_key.to_vec()));
        self
    }

    pub fn get(&self, authority_id: &str) -> Option<&[u8]> {
        self.keys
            .iter()
            .find(|(id, _)| id == authority_id)
            .map(|(_, k)| k.as_slice())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordVerifyError {
    UnsupportedVersion(u16),
    UntrustedAuthority(String),
    /// The anchored key equals another authority's key.
    KeyIsAnotherAuthority,
    SignatureInvalid,
    Crypto(AipError),
}

impl std::fmt::Display for RecordVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for RecordVerifyError {}

/// Verify a record offline: version, trusted signer, payload hash over the
/// canonical bytes, Ed25519 envelope.
pub fn verify_containment_record(
    r: &SignedContainmentRecord,
    anchors: &ContainmentTrustAnchors,
) -> Result<(), RecordVerifyError> {
    if r.record.version != CONTAINMENT_VERSION {
        return Err(RecordVerifyError::UnsupportedVersion(r.record.version));
    }
    let key = anchors
        .get(&r.signature.signer_id)
        .ok_or_else(|| RecordVerifyError::UntrustedAuthority(r.signature.signer_id.clone()))?;
    if r.signature.payload_hash != r.record.digest() {
        return Err(RecordVerifyError::SignatureInvalid);
    }
    match verify_ed25519(key, &r.signature) {
        Ok(true) => Ok(()),
        Ok(false) => Err(RecordVerifyError::SignatureInvalid),
        Err(e) => Err(RecordVerifyError::Crypto(e)),
    }
}

/// As [`verify_containment_record`], additionally refusing an anchor whose
/// key equals any of `other_authority_keys` (warrant authority, decision
/// point, observer, agent).
pub fn verify_containment_record_distinct(
    r: &SignedContainmentRecord,
    anchors: &ContainmentTrustAnchors,
    other_authority_keys: &[&[u8]],
) -> Result<(), RecordVerifyError> {
    if let Some(key) = anchors.get(&r.signature.signer_id) {
        if other_authority_keys.contains(&key) {
            return Err(RecordVerifyError::KeyIsAnotherAuthority);
        }
    }
    verify_containment_record(r, anchors)
}
