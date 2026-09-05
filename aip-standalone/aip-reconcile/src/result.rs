//! Closed, typed reconciliation output.
//!
//! No booleans stand in for states, no scalar score exists, and severity is
//! not a concept in this crate at all: `EvidenceStrength` is the only
//! confidence-like axis, it is an enum, and it is assigned by result kind
//! (§ `reconcile`), never computed from a number.

use aip_observe::ObservationAvailability;
use aip_types::canonical::*;
use serde::{Deserialize, Serialize};

use crate::ids::DecisionId;

/// Domain tag leading the canonical encoding of a [`Reconciliation`] record.
pub const RECONCILIATION_DOMAIN: &str = "SYNTRIASS/GHOST/RECONCILIATION/v1";
/// Structure version.
pub const RECONCILIATION_VERSION: u16 = 1;

/// The eight result classes from `RECONCILIATION_MODEL.md` §4. The
/// `Default` is `CannotProve`: absence of evidence is absence of a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum ReconciliationResult {
    /// Expected ∧ observed ∧ identity ∧ action ∧ parameters ∧ window ∧
    /// attested continuity. **Unreachable with the current observer**: no
    /// observation carries action-level evidence (see `ActionComparison`).
    VerifiedExecution,
    /// An attested effect for which a decision point has attested that no
    /// expectation exists. Requires `ExpectedSideCoverage::Attested`.
    UnattributedEffect,
    /// An expectation with no observation of its instance, under signed
    /// kernel-pushed coverage of the exact window by a contiguous chain.
    PhantomClaim,
    /// The instance the observer measured under this decision claim differs
    /// from the instance the decision point authorized.
    IdentityDivergence,
    /// Observed ancestry contradicts the authority chain. Requires both fork
    /// ends bound; unreachable today.
    LineageViolation,
    /// Observer signature or chain arithmetic failed.
    SensorIntegrityFailure,
    /// The observer explicitly attests a continuity break over the window.
    ContinuityFailure,
    /// The default. Evidence insufficient for any other class.
    #[default]
    CannotProve,
}

impl ReconciliationResult {
    pub fn code(&self) -> u8 {
        match self {
            Self::VerifiedExecution => 0x01,
            Self::UnattributedEffect => 0x02,
            Self::PhantomClaim => 0x03,
            Self::IdentityDivergence => 0x04,
            Self::LineageViolation => 0x05,
            Self::SensorIntegrityFailure => 0x06,
            Self::ContinuityFailure => 0x07,
            Self::CannotProve => 0x00,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::VerifiedExecution => "VERIFIED_EXECUTION",
            Self::UnattributedEffect => "UNATTRIBUTED_EFFECT",
            Self::PhantomClaim => "PHANTOM_CLAIM",
            Self::IdentityDivergence => "IDENTITY_DIVERGENCE",
            Self::LineageViolation => "LINEAGE_VIOLATION",
            Self::SensorIntegrityFailure => "SENSOR_INTEGRITY_FAILURE",
            Self::ContinuityFailure => "CONTINUITY_FAILURE",
            Self::CannotProve => "CANNOT_PROVE",
        }
    }
}

/// How certain, as an epistemic category — not how bad, and not a number.
/// `Proven` is reserved for facts a third party can recompute from held
/// bytes (signature and chain arithmetic). Anything that depends on the
/// *content* of an observation is capped at `Attested`, because content is
/// procfs-derived and root-forgeable (Skill 6 A4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EvidenceStrength {
    Heuristic,
    Correlated,
    Attested,
    Proven,
}

impl EvidenceStrength {
    pub fn code(&self) -> u8 {
        match self {
            Self::Heuristic => 0x01,
            Self::Correlated => 0x02,
            Self::Attested => 0x03,
            Self::Proven => 0x04,
        }
    }
}

/// Why the result is what it is. Closed list; every variant names an
/// epistemic condition, never a moral one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReasonCode {
    // ── expected side ──
    ExpectedSignatureInvalid,
    ExpectedUntrustedDecisionPoint,
    ExpectedStructurallyInvalid,
    ExpectedSideCompletenessUnknown,
    ExpectedSideStatementInvalid,
    ExpectedSideStatementDoesNotCover,
    ExpectationExistsForObservation,
    // ── observer side ──
    NoObserverEvidence,
    ObserverUntrusted,
    ObserverSignatureInvalid,
    ObserverChainBroken,
    ObserverQuarantined,
    ObservationSetIncomplete,
    MixedObservers,
    HealthStale,
    ObserverDegraded,
    ObserverRecovering,
    ObserverContinuityUnverified,
    ProvenanceUnverifiedOpenPolicy,
    // ── matching ──
    ActionEvidenceUnavailable,
    IdentityDiverged,
    AmbiguousObservations,
    UnboundReferencesOnly,
    ObservationOutsideWindow,
    AttributionNotEstablished,
    // ── coverage ──
    WindowNotCovered,
    CoverageNotKernelPushed,
    KernelCoverageWithNoReference,
    // ── target ──
    TargetNotFound,
    NoExpectationAttested,
}

impl ReasonCode {
    pub fn code(&self) -> u8 {
        *self as u8
    }
}

/// Outcome of comparing expected and observed process identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IdentityComparison {
    /// No observation or kernel event refers to the expected instance or pid.
    NoReference,
    /// Only bare-pid references exist (unbound kernel events); identity is
    /// `CANNOT_PROVE`.
    UnboundReferencesOnly { references: u32 },
    /// At least one measured instance matches the expected binding
    /// structurally (process tuple + executable hash), none diverge.
    Match { observations: u32 },
    /// A measured instance carrying this decision claim differs from the
    /// expected binding; none match.
    Divergent { observations: u32 },
    /// Both matching and divergent measured instances exist.
    Ambiguous { matching: u32, divergent: u32 },
}

impl IdentityComparison {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::NoReference => put_u8(buf, 0x00),
            Self::UnboundReferencesOnly { references } => {
                put_u8(buf, 0x01);
                put_u32(buf, *references);
            }
            Self::Match { observations } => {
                put_u8(buf, 0x02);
                put_u32(buf, *observations);
            }
            Self::Divergent { observations } => {
                put_u8(buf, 0x03);
                put_u32(buf, *observations);
            }
            Self::Ambiguous {
                matching,
                divergent,
            } => {
                put_u8(buf, 0x04);
                put_u32(buf, *matching);
                put_u32(buf, *divergent);
            }
        }
    }
}

/// Outcome of comparing expected action/parameters with observation.
///
/// Only `Unobservable` can currently be produced: no `ObservedEffect` carries
/// an action kind or parameter digest. `Match`/`Mismatch` are defined so the
/// contract is complete, but nothing in this crate constructs them — which is
/// exactly why `VerifiedExecution` is unreachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionComparison {
    Unobservable,
    Match,
    Mismatch,
}

impl ActionComparison {
    fn code(&self) -> u8 {
        match self {
            Self::Unobservable => 0x00,
            Self::Match => 0x01,
            Self::Mismatch => 0x02,
        }
    }
}

/// Where the observation's claimed window sits relative to the expectation's
/// authorized window (plus verifier tolerance). Batch windows are probe
/// claims, so this is a consistency filter, never evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TemporalComparison {
    WithinWindow,
    OutsideWindow,
    Indeterminate,
}

impl TemporalComparison {
    fn code(&self) -> u8 {
        match self {
            Self::WithinWindow => 0x01,
            Self::OutsideWindow => 0x02,
            Self::Indeterminate => 0x00,
        }
    }
}

/// A pointer to an input the result rests on, so a third party can fetch it
/// and recompute.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceRef {
    Expected {
        decision_point_id: String,
        decision_id: DecisionId,
    },
    Batch {
        observer_id: String,
        key_version: u32,
        sequence: u64,
        head: [u8; 32],
    },
    Health {
        observer_id: String,
        sequence: u64,
        emitted_at_ms: u64,
    },
    Observation {
        batch_sequence: u64,
        index: u32,
    },
    KernelEvent {
        batch_sequence: u64,
        index: u32,
    },
    CoverageStatement {
        decision_point_id: String,
        issued_at_ms: u64,
    },
}

impl EvidenceRef {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Expected {
                decision_point_id,
                decision_id,
            } => {
                put_u8(buf, 0x01);
                put_str(buf, decision_point_id);
                buf.extend_from_slice(decision_id.as_bytes());
            }
            Self::Batch {
                observer_id,
                key_version,
                sequence,
                head,
            } => {
                put_u8(buf, 0x02);
                put_str(buf, observer_id);
                put_u32(buf, *key_version);
                put_u64(buf, *sequence);
                buf.extend_from_slice(head);
            }
            Self::Health {
                observer_id,
                sequence,
                emitted_at_ms,
            } => {
                put_u8(buf, 0x03);
                put_str(buf, observer_id);
                put_u64(buf, *sequence);
                put_u64(buf, *emitted_at_ms);
            }
            Self::Observation {
                batch_sequence,
                index,
            } => {
                put_u8(buf, 0x04);
                put_u64(buf, *batch_sequence);
                put_u32(buf, *index);
            }
            Self::KernelEvent {
                batch_sequence,
                index,
            } => {
                put_u8(buf, 0x05);
                put_u64(buf, *batch_sequence);
                put_u32(buf, *index);
            }
            Self::CoverageStatement {
                decision_point_id,
                issued_at_ms,
            } => {
                put_u8(buf, 0x06);
                put_str(buf, decision_point_id);
                put_u64(buf, *issued_at_ms);
            }
        }
    }
}

/// The complete, auditable output of one reconciliation.
///
/// Carries the result **and** every intermediate comparison and reference, so
/// a reader sees not just the verdict but what was and was not established.
/// `availability` is the observer's coverage state for the window — the
/// `OBSERVATION_UNAVAILABLE` input state — carried alongside the result so a
/// later layer can refuse to act on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reconciliation {
    pub version: u16,
    pub result: ReconciliationResult,
    pub strength: EvidenceStrength,
    pub reason: ReasonCode,
    pub decision_id: Option<DecisionId>,
    pub availability: ObservationAvailability,
    pub identity: IdentityComparison,
    pub action: ActionComparison,
    pub temporal: TemporalComparison,
    /// Duplicate attested batches were supplied and collapsed.
    pub replay_detected: bool,
    pub evidence: Vec<EvidenceRef>,
    /// The verifier-supplied time the reconciliation was computed at.
    pub verification_time_ms: u64,
}

fn encode_availability(buf: &mut Vec<u8>, a: &ObservationAvailability) {
    use aip_observe::UnavailableReason as R;
    match a {
        ObservationAvailability::Covered { window } => {
            put_u8(buf, 0x01);
            put_u64(buf, window.from_ms);
            put_u64(buf, window.to_ms);
        }
        ObservationAvailability::Unavailable { reason } => {
            put_u8(buf, 0x00);
            match reason {
                R::NoObserver => put_u8(buf, 0x01),
                R::ObserverDegraded => put_u8(buf, 0x02),
                R::ObserverRecovering => put_u8(buf, 0x03),
                R::ContinuityUnverified => put_u8(buf, 0x04),
                R::ObserverQuarantined => put_u8(buf, 0x05),
                R::WindowNotCovered => put_u8(buf, 0x06),
                R::HealthStale {
                    newest_ms,
                    required_ms,
                } => {
                    put_u8(buf, 0x07);
                    put_u64(buf, *newest_ms);
                    put_u64(buf, *required_ms);
                }
            }
        }
    }
}

impl Reconciliation {
    /// Canonical, domain-tagged, injective encoding for audit and any later
    /// signing by a party that is one. This crate signs nothing.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, RECONCILIATION_DOMAIN);
        put_u16(&mut buf, self.version);
        put_u8(&mut buf, self.result.code());
        put_u8(&mut buf, self.strength.code());
        put_u8(&mut buf, self.reason.code());
        match &self.decision_id {
            Some(d) => {
                put_u8(&mut buf, 1);
                buf.extend_from_slice(d.as_bytes());
            }
            None => put_u8(&mut buf, 0),
        }
        encode_availability(&mut buf, &self.availability);
        self.identity.encode(&mut buf);
        put_u8(&mut buf, self.action.code());
        put_u8(&mut buf, self.temporal.code());
        put_u8(&mut buf, u8::from(self.replay_detected));
        put_u32(&mut buf, self.evidence.len() as u32);
        for e in &self.evidence {
            e.encode(&mut buf);
        }
        put_u64(&mut buf, self.verification_time_ms);
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        aip_crypto::sha256(&self.canonical_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_result_is_cannot_prove() {
        assert_eq!(
            ReconciliationResult::default(),
            ReconciliationResult::CannotProve
        );
    }

    #[test]
    fn result_and_strength_codes_are_distinct() {
        let results = [
            ReconciliationResult::VerifiedExecution,
            ReconciliationResult::UnattributedEffect,
            ReconciliationResult::PhantomClaim,
            ReconciliationResult::IdentityDivergence,
            ReconciliationResult::LineageViolation,
            ReconciliationResult::SensorIntegrityFailure,
            ReconciliationResult::ContinuityFailure,
            ReconciliationResult::CannotProve,
        ];
        let mut codes: Vec<u8> = results.iter().map(|r| r.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), results.len());
        assert!(EvidenceStrength::Proven > EvidenceStrength::Attested);
        assert!(EvidenceStrength::Attested > EvidenceStrength::Correlated);
        assert!(EvidenceStrength::Correlated > EvidenceStrength::Heuristic);
    }

    #[test]
    fn no_severity_or_score_exists_in_output() {
        let r = Reconciliation {
            version: RECONCILIATION_VERSION,
            result: ReconciliationResult::CannotProve,
            strength: EvidenceStrength::Heuristic,
            reason: ReasonCode::NoObserverEvidence,
            decision_id: None,
            availability: aip_observe::no_observer(),
            identity: IdentityComparison::NoReference,
            action: ActionComparison::Unobservable,
            temporal: TemporalComparison::Indeterminate,
            replay_detected: false,
            evidence: vec![],
            verification_time_ms: 0,
        };
        let json = serde_json::to_string(&r).unwrap().to_lowercase();
        for forbidden in [
            "severity",
            "confidence",
            "score",
            "risk",
            "malicious",
            "permitted",
            "authorized",
            "allowed",
            "trusted\":true",
        ] {
            assert!(!json.contains(forbidden), "`{forbidden}` in {json}");
        }
        assert_eq!(r.digest().len(), 32);
    }
}
