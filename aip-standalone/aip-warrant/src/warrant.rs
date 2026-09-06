//! The warrant: what response a reconciliation result permits, and why.
//!
//! The gate is structural (§7, §25): the response ceiling is a `match` on
//! `EvidenceStrength`, then on the result class, then on severity; policy,
//! protection, citation and availability can only lower it. Nothing here
//! computes a product of the two axes, and nothing here actuates (§20).

use aip_crypto::{sha256, sign_ed25519, verify_ed25519};
use aip_observe::ObservationAvailability;
use aip_reconcile::{
    EvidenceRef, EvidenceStrength, Reconciliation, ReconciliationResult, RECONCILIATION_VERSION,
};
use aip_types::canonical::{put_domain, put_opt_u64, put_str, put_u16, put_u32, put_u64, put_u8};
use aip_types::{AipError, Signature};
use serde::{Deserialize, Serialize};

use crate::policy::{Severity, WarrantPolicy};

pub const WARRANT_DOMAIN: &str = "SYNTRIASS/GHOST/WARRANT/v1";
pub const WARRANT_VERSION: u16 = 1;

/// The response a warrant permits. Ordered: nothing may exceed `Contain`,
/// and every cap in the engine is a `min` against this order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ResponseClass {
    /// Record only; no operator attention required.
    Observe,
    /// Bring to an operator; take no action.
    Alert,
    /// Limit, under explicit policy; never terminate or isolate.
    Constrain,
    /// Containment is *permitted* (Skill 9 decides whether to act).
    Contain,
}

impl ResponseClass {
    pub fn code(self) -> u8 {
        match self {
            ResponseClass::Observe => 0x01,
            ResponseClass::Alert => 0x02,
            ResponseClass::Constrain => 0x03,
            ResponseClass::Contain => 0x04,
        }
    }
}

/// What the response is about. A sensor finding is about the observer, never
/// authority over the workload (§12, §13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResponseTarget {
    Workload,
    Observer,
}

impl ResponseTarget {
    pub fn code(self) -> u8 {
        match self {
            ResponseTarget::Workload => 0x01,
            ResponseTarget::Observer => 0x02,
        }
    }
}

/// The engine's input: an identified reconciliation record and, when the
/// caller knows it from the expectation, the agent it concerns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub finding_id: [u8; 16],
    pub reconciliation: Reconciliation,
    pub subject_agent: Option<String>,
}

/// Why no warrant was produced. A refusal never enables any action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    UnsupportedReconciliationVersion(u16),
    InvalidPolicy(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::UnsupportedReconciliationVersion(v) => {
                write!(f, "unsupported reconciliation record version {v}")
            }
            Refusal::InvalidPolicy(why) => write!(f, "invalid policy: {why}"),
        }
    }
}

impl std::error::Error for Refusal {}

/// Permission to respond, traceable to the record it rests on (§16, §21).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Warrant {
    pub version: u16,
    /// Deterministic: derived from finding, record digest, policy and time.
    pub warrant_id: [u8; 16],
    pub finding_id: [u8; 16],
    pub reconciliation_result: ReconciliationResult,
    /// `Reconciliation::digest()` of the record this warrant rests on.
    pub reconciliation_digest: [u8; 32],
    /// The record carried `ObservationAvailability::Unavailable`.
    pub observation_unavailable: bool,
    pub severity: Severity,
    pub evidence_strength: EvidenceStrength,
    pub response: ResponseClass,
    pub target: ResponseTarget,
    pub policy_version: u32,
    /// The policy had autonomous containment enabled.
    pub autonomous: bool,
    /// The subject, decision point or observer was protected by policy.
    pub protected: bool,
    pub issued_at: u64,
    pub valid_until: Option<u64>,
    /// The record's evidence references, verbatim.
    pub evidence_refs: Vec<EvidenceRef>,
    pub subject_agent: Option<String>,
    pub signature: Option<Signature>,
}

impl Warrant {
    /// Canonical, domain-tagged, injective bytes over every security-relevant
    /// field (everything but the signature).
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, WARRANT_DOMAIN);
        put_u16(&mut buf, self.version);
        buf.extend_from_slice(&self.warrant_id);
        buf.extend_from_slice(&self.finding_id);
        put_u8(&mut buf, self.reconciliation_result.code());
        buf.extend_from_slice(&self.reconciliation_digest);
        put_u8(&mut buf, u8::from(self.observation_unavailable));
        put_u8(&mut buf, self.severity.code());
        put_u8(&mut buf, self.evidence_strength.code());
        put_u8(&mut buf, self.response.code());
        put_u8(&mut buf, self.target.code());
        put_u32(&mut buf, self.policy_version);
        put_u8(&mut buf, u8::from(self.autonomous));
        put_u8(&mut buf, u8::from(self.protected));
        put_u64(&mut buf, self.issued_at);
        put_opt_u64(&mut buf, &self.valid_until);
        put_u32(&mut buf, self.evidence_refs.len() as u32);
        for r in &self.evidence_refs {
            let bytes = r.canonical_bytes();
            put_u32(&mut buf, bytes.len() as u32);
            buf.extend_from_slice(&bytes);
        }
        match &self.subject_agent {
            Some(s) => {
                put_u8(&mut buf, 1);
                put_str(&mut buf, s);
            }
            None => put_u8(&mut buf, 0),
        }
        buf
    }

    /// Inside `[issued_at, valid_until]`.
    pub fn is_valid_at(&self, t_ms: u64) -> bool {
        t_ms >= self.issued_at && self.valid_until.is_none_or(|v| t_ms <= v)
    }
}

fn min3(a: ResponseClass, b: ResponseClass, c: ResponseClass) -> ResponseClass {
    a.min(b).min(c)
}

/// The engine. Reads the record, the policy and the clock; writes a warrant
/// or a refusal. Never reads process ids, addresses, or anything upstream of
/// the reconciler (§5).
pub fn evaluate(f: &Finding, p: &WarrantPolicy, now_ms: u64) -> Result<Warrant, Refusal> {
    let rec = &f.reconciliation;
    if rec.version != RECONCILIATION_VERSION {
        return Err(Refusal::UnsupportedReconciliationVersion(rec.version));
    }
    if p.version == 0 {
        return Err(Refusal::InvalidPolicy("version must be positive".into()));
    }
    if p.validity_ms == 0 {
        return Err(Refusal::InvalidPolicy(
            "validity_ms must be positive".into(),
        ));
    }

    let severity = p.severity.severity_of(rec.result);
    let unavailable = matches!(
        rec.availability,
        ObservationAvailability::Unavailable { .. }
    );
    let cited = !rec.evidence.is_empty();
    let protected = is_protected(f, p);

    // 1. What the result class is about, and the most it can ever warrant.
    let (target, result_cap) = match rec.result {
        ReconciliationResult::VerifiedExecution => {
            (ResponseTarget::Workload, ResponseClass::Observe)
        }
        ReconciliationResult::CannotProve => (ResponseTarget::Workload, ResponseClass::Alert),
        ReconciliationResult::ContinuityFailure => (ResponseTarget::Observer, ResponseClass::Alert),
        ReconciliationResult::SensorIntegrityFailure => {
            (ResponseTarget::Observer, ResponseClass::Constrain)
        }
        ReconciliationResult::UnattributedEffect
        | ReconciliationResult::PhantomClaim
        | ReconciliationResult::IdentityDivergence
        | ReconciliationResult::LineageViolation => {
            (ResponseTarget::Workload, ResponseClass::Contain)
        }
    };

    // 2. The evidence-strength gate (§7, §25): explicit match, no arithmetic.
    let strength_cap = match rec.strength {
        EvidenceStrength::Heuristic | EvidenceStrength::Correlated => ResponseClass::Alert,
        EvidenceStrength::Attested => {
            if p.allow_constrain_on_attested {
                ResponseClass::Constrain
            } else {
                ResponseClass::Alert
            }
        }
        EvidenceStrength::Proven => ResponseClass::Contain,
    };

    // 3. Severity proposes; it can only lower.
    let severity_cap = match severity {
        Severity::Low => ResponseClass::Observe,
        Severity::Medium => ResponseClass::Alert,
        Severity::High => ResponseClass::Constrain,
        Severity::Critical => ResponseClass::Contain,
    };

    let mut response = min3(result_cap, strength_cap, severity_cap);

    // 4. Absence, silence, protection and missing citations never escalate.
    if unavailable || !cited || protected {
        response = response.min(ResponseClass::Alert);
    }
    // 5. Containment requires the operator to have enabled it.
    if response == ResponseClass::Contain && !p.autonomous_containment {
        response = ResponseClass::Alert;
    }

    let digest = rec.digest();
    let valid_until = now_ms.checked_add(p.validity_ms);
    let warrant_id = {
        let mut b = Vec::new();
        put_domain(&mut b, WARRANT_DOMAIN);
        b.extend_from_slice(&f.finding_id);
        b.extend_from_slice(&digest);
        put_u32(&mut b, p.version);
        put_u64(&mut b, now_ms);
        let h = sha256(&b);
        let mut id = [0u8; 16];
        id.copy_from_slice(&h[..16]);
        id
    };

    Ok(Warrant {
        version: WARRANT_VERSION,
        warrant_id,
        finding_id: f.finding_id,
        reconciliation_result: rec.result,
        reconciliation_digest: digest,
        observation_unavailable: unavailable,
        severity,
        evidence_strength: rec.strength,
        response,
        target,
        policy_version: p.version,
        autonomous: p.autonomous_containment,
        protected,
        issued_at: now_ms,
        valid_until,
        evidence_refs: rec.evidence.clone(),
        subject_agent: f.subject_agent.clone(),
        signature: None,
    })
}

fn is_protected(f: &Finding, p: &WarrantPolicy) -> bool {
    if f.subject_agent
        .as_deref()
        .is_some_and(|a| p.protected.contains_agent(a))
    {
        return true;
    }
    f.reconciliation.evidence.iter().any(|e| match e {
        EvidenceRef::Expected {
            decision_point_id, ..
        }
        | EvidenceRef::CoverageStatement {
            decision_point_id, ..
        } => p.protected.contains_decision_point(&decision_point_id.0),
        EvidenceRef::Batch { observer_id, .. } | EvidenceRef::Health { observer_id, .. } => {
            p.protected.contains_observer(&observer_id.0)
        }
        EvidenceRef::Observation { .. } | EvidenceRef::KernelEvent { .. } => false,
    })
}

// ─── authenticity (§17–§19) ───

/// The warrant authority: a distinct key holder. Not the agent, not the
/// decision point, not an observer.
pub struct WarrantAuthority {
    id: String,
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl std::fmt::Debug for WarrantAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WarrantAuthority")
            .field("id", &self.id)
            .field("public_key", &self.public_key)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

impl WarrantAuthority {
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

    /// Sign the warrant's canonical preimage. Signing changes nothing about
    /// the response: it proves origin, not correctness.
    pub fn sign(&self, mut w: Warrant) -> Result<Warrant, AipError> {
        let sig = sign_ed25519(&self.private_key, &self.id, &w.signing_preimage())?;
        w.signature = Some(sig);
        Ok(w)
    }
}

/// Verifier-supplied warrant authority keys, by id.
#[derive(Debug, Clone, Default)]
pub struct WarrantTrustAnchors {
    keys: Vec<(String, Vec<u8>)>,
}

impl WarrantTrustAnchors {
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
pub enum WarrantVerifyError {
    Unsigned,
    UnsupportedVersion(u16),
    InvalidWindow {
        issued_at: u64,
        valid_until: u64,
    },
    UntrustedAuthority(String),
    /// The anchor key for this authority equals another authority's key.
    KeyIsAnotherAuthority,
    SignatureInvalid,
    Crypto(AipError),
}

/// Verify a warrant against the anchors: structure, trusted signer, payload
/// hash over the canonical preimage, Ed25519 envelope.
pub fn verify_warrant(
    w: &Warrant,
    anchors: &WarrantTrustAnchors,
) -> Result<(), WarrantVerifyError> {
    if w.version != WARRANT_VERSION {
        return Err(WarrantVerifyError::UnsupportedVersion(w.version));
    }
    if let Some(v) = w.valid_until {
        if v < w.issued_at {
            return Err(WarrantVerifyError::InvalidWindow {
                issued_at: w.issued_at,
                valid_until: v,
            });
        }
    }
    let sig = w.signature.as_ref().ok_or(WarrantVerifyError::Unsigned)?;
    let key = anchors
        .get(&sig.signer_id)
        .ok_or_else(|| WarrantVerifyError::UntrustedAuthority(sig.signer_id.clone()))?;
    if sig.payload_hash != sha256(&w.signing_preimage()) {
        return Err(WarrantVerifyError::SignatureInvalid);
    }
    match verify_ed25519(key, sig) {
        Ok(true) => Ok(()),
        Ok(false) => Err(WarrantVerifyError::SignatureInvalid),
        Err(e) => Err(WarrantVerifyError::Crypto(e)),
    }
}

/// As [`verify_warrant`], additionally refusing an anchor whose key equals
/// any of `other_authority_keys` (decision point, observer, agent).
pub fn verify_warrant_distinct(
    w: &Warrant,
    anchors: &WarrantTrustAnchors,
    other_authority_keys: &[&[u8]],
) -> Result<(), WarrantVerifyError> {
    if let Some(sig) = &w.signature {
        if let Some(key) = anchors.get(&sig.signer_id) {
            if other_authority_keys.contains(&key) {
                return Err(WarrantVerifyError::KeyIsAnotherAuthority);
            }
        }
    }
    verify_warrant(w, anchors)
}
