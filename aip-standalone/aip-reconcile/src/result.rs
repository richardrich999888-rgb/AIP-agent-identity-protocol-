//! Closed, typed reconciliation output.
//!
//! No booleans stand in for states, no scalar score exists, and severity is
//! not a concept in this crate at all: `EvidenceStrength` is the only
//! confidence-like axis, it is an enum, and it is assigned by result kind
//! (§ `reconcile`), never computed from a number.

use aip_observe::{ObservationAvailability, SourceMechanism};
use aip_types::canonical::*;
use serde::{Deserialize, Serialize};

use crate::ids::{BatchId, DecisionId, DecisionPointId, ObserverId, ObserverSequence, ProbeRunId};

/// Domain tag leading the canonical encoding of a [`Reconciliation`] record.
pub const RECONCILIATION_DOMAIN: &str = "SYNTRIASS/GHOST/RECONCILIATION/v1";
/// Structure version.
///
/// v3 (Stage 7b): `ActionEvidenceSeal` records the evidence *kind* (presence
/// vs transition), `TemporalComparison` distinguishes before/after/unanchored,
/// and batch references carry the collector's `attested_at_ms`.
///
/// v2 (Skill 7 corrective pass): evidence references carry the probe-level
/// identifiers needed to re-derive coverage (`batch_id`, `probe_run_id`),
/// `IdentityComparison` gained `ClaimInconsistent`, and `ActionComparison`'s
/// positive variants became unconstructible outside this module. No consumer
/// had persisted a v1 record — the crate has no producer of signed
/// reconciliation records and no storage.
pub const RECONCILIATION_VERSION: u16 = 3;

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
#[repr(u8)]
pub enum ReasonCode {
    // ── expected side ──
    ExpectedSignatureInvalid = 0x10,
    ExpectedUntrustedDecisionPoint = 0x11,
    ExpectedStructurallyInvalid = 0x12,
    /// The agent is named as its own decision point, or the anchored
    /// decision key is the agent's own key (I1). A trust failure, never a
    /// verdict about execution.
    ExpectedSelfAuthorization = 0x13,
    ExpectedSideCompletenessUnknown = 0x14,
    ExpectedSideStatementInvalid = 0x15,
    ExpectedSideStatementDoesNotCover = 0x16,
    ExpectationExistsForObservation = 0x17,
    // ── observer side ──
    NoObserverEvidence = 0x20,
    ObserverUntrusted = 0x21,
    ObserverSignatureInvalid = 0x22,
    ObserverChainBroken = 0x23,
    ObserverQuarantined = 0x24,
    ObservationSetIncomplete = 0x25,
    MixedObservers = 0x26,
    HealthStale = 0x27,
    ObserverDegraded = 0x28,
    ObserverRecovering = 0x29,
    ObserverContinuityUnverified = 0x2a,
    ProvenanceUnverifiedOpenPolicy = 0x2b,
    /// The observer protocol version is not one this reconciler verifies.
    ObserverProtocolUnsupported = 0x2c,
    /// The anchored observer key is the observed agent's own key: the
    /// "observation" is a second self-report (I10), not independent evidence.
    ObserverKeyIsAgentKey = 0x2d,
    /// The health record is dated after the verifier's own verification
    /// time, so the verifier cannot place it in time at all.
    HealthNotYetEmitted = 0x2e,
    // ── matching ──
    ActionEvidenceUnavailable = 0x40,
    IdentityDiverged = 0x41,
    AmbiguousObservations = 0x42,
    UnboundReferencesOnly = 0x43,
    ObservationOutsideWindow = 0x44,
    AttributionNotEstablished = 0x45,
    /// A reference claims this decision while naming a different agent. The
    /// claim pair is internally inconsistent and supports no verdict about
    /// either party.
    AttributionInconsistent = 0x46,
    /// An observation of the authorized instance evidences the expected
    /// action kind with exactly the expected parameter digest, inside the
    /// window, claimed under this decision. The reason of a
    /// `VerifiedExecution`.
    ActionEvidenceMatches = 0x47,
    /// Action evidence of the expected kind exists for the instance, but its
    /// parameter digest differs. Says nothing about whether the authorized
    /// action also happened.
    ActionEvidenceDoesNotMatch = 0x48,
    /// Action evidence matching the expected kind and digest exists for the
    /// instance, but is not claimed under this decision (no claim, another
    /// decision, or another agent), so it cannot be tied to *this*
    /// expectation.
    ActionEvidenceUnclaimed = 0x49,
    /// Matching action evidence exists, but the batch that carries it is not
    /// placed wholly inside the authorized window.
    ActionEvidenceOutsideWindow = 0x4a,
    /// Matching action evidence exists, but the batch that carries it lies
    /// outside the collector's attested coverage epoch, so its continuity is
    /// not vouched for.
    ActionEvidenceNotCovered = 0x4b,
    /// A kernel-reported connection transition matching the expected action
    /// is placed **before** the decision was issued — by the collector's
    /// signed attestation clock (two off-host clocks) or by the probe's
    /// boot-clock anchor. The connection predates the authorization; it is
    /// not the authorized action. Also overrides presence evidence of the
    /// same connection.
    ActionPrecedesAuthorization = 0x4c,
    /// The kernel reported the `connect()` initiation for the expected
    /// endpoint on the authorized instance, but no matching completion
    /// (`SYN_SENT → ESTABLISHED`) for that socket was recorded. An attempt
    /// is not a connection.
    ActionTransitionIncomplete = 0x4d,
    /// A matching kernel transition exists but the batch carrying it has no
    /// boot-clock anchor, so its kernel timestamp cannot be placed on the
    /// wall clock the authorization is expressed in.
    KernelTimeUnanchored = 0x4e,
    // ── coverage ──
    WindowNotCovered = 0x50,
    CoverageNotKernelPushed = 0x51,
    KernelCoverageWithNoReference = 0x52,
    /// The supplied batches' claimed intervals leave a hole inside the
    /// window: part of it was claimed by no batch at all.
    CoverageGapInWindow = 0x53,
    /// A batch claims to have sampled past the moment the collector signed
    /// its health record — an attestation about the future.
    CoverageEndsAfterHealth = 0x54,
    /// The probe restarted inside the window: `probe_run_id` is not constant
    /// across the batches that claim to cover it.
    CoverageProbeRunChanged = 0x55,
    // ── target ──
    TargetNotFound = 0x60,
    NoExpectationAttested = 0x61,
    /// A positive class was assembled whose evidence precondition is not
    /// visible in the record. The central guard in `reconcile` downgraded it;
    /// reaching this reason means a caller or a future edit tried to emit a
    /// verdict the record does not support.
    InvariantNotSatisfied = 0x62,
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
    /// A reference claims this decision but names a different agent than the
    /// expectation was issued for. `claimed_decision_id` and the claimed
    /// `agent_id` come from the same unauthenticated claim; when they
    /// disagree the pair supports no statement about either party.
    ClaimInconsistent { references: u32 },
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
            Self::ClaimInconsistent { references } => {
                put_u8(buf, 0x05);
                put_u32(buf, *references);
            }
        }
    }
}

/// Witness that an observation was interpreted as action-level evidence, and
/// how that observation was obtained.
///
/// The field is private and the only constructors are `pub(crate)`, so a
/// value can be built **only by this crate's engine** — specifically by the
/// action-derivation step in `reconcile`, after an observation has passed
/// signature, provenance, identity and window checks. No caller can hand the
/// reconciler a `Match`. Extending the set of observable action classes means
/// extending `action::derive_action`; that is the deliberate, reviewable act,
/// and there is no other way in.
///
/// `mechanism` is recorded so a reader of the result sees *what kind* of
/// evidence carried the action — today always `ProcNetTable`, i.e. polled
/// socket-table metadata, never a kernel-pushed event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActionEvidenceSeal {
    mechanism: SourceMechanism,
    kind: ActionEvidenceKind,
}

/// What kind of fact the action evidence is. The two are not the same
/// statement and a consumer must not treat them as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionEvidenceKind {
    /// A socket **existed** in the relevant state at the moment the polled
    /// table was read. Says nothing about when it came to exist.
    Presence,
    /// The kernel reported the socket **transitioning** into the relevant
    /// state (`CLOSE → SYN_SENT → ESTABLISHED`), bound to the acting
    /// instance at the initiating transition, with kernel timestamps.
    Transition,
}

impl ActionEvidenceKind {
    fn code(&self) -> u8 {
        match self {
            ActionEvidenceKind::Presence => 0x01,
            ActionEvidenceKind::Transition => 0x02,
        }
    }
}

impl ActionEvidenceSeal {
    pub(crate) fn new(mechanism: SourceMechanism, kind: ActionEvidenceKind) -> Self {
        Self { mechanism, kind }
    }

    pub fn mechanism(&self) -> SourceMechanism {
        self.mechanism
    }

    pub fn kind(&self) -> ActionEvidenceKind {
        self.kind
    }
}

/// Outcome of comparing expected action/parameters with observation.
///
/// `Unobservable` is the default and the answer whenever no observation of
/// the authorized instance is an instance of an observable action class of
/// the expected `action_kind`. The positive variants require an
/// [`ActionEvidenceSeal`], which only the engine can construct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionComparison {
    Unobservable,
    /// An observation of the authorized instance evidences the expected
    /// action kind with exactly the expected parameter digest.
    Match(ActionEvidenceSeal),
    /// An observation of the authorized instance evidences the expected
    /// action kind with a different parameter digest. Not proof that the
    /// authorized action did not also happen.
    Mismatch(ActionEvidenceSeal),
}

impl ActionComparison {
    pub(crate) fn matched(mechanism: SourceMechanism, kind: ActionEvidenceKind) -> Self {
        Self::Match(ActionEvidenceSeal::new(mechanism, kind))
    }

    pub(crate) fn mismatched(mechanism: SourceMechanism, kind: ActionEvidenceKind) -> Self {
        Self::Mismatch(ActionEvidenceSeal::new(mechanism, kind))
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Unobservable => put_u8(buf, 0x00),
            Self::Match(s) => {
                put_u8(buf, 0x01);
                put_u8(buf, s.mechanism.code());
                put_u8(buf, s.kind.code());
            }
            Self::Mismatch(s) => {
                put_u8(buf, 0x02);
                put_u8(buf, s.mechanism.code());
                put_u8(buf, s.kind.code());
            }
        }
    }

    /// The evidence kind, if any action evidence exists.
    pub fn evidence_kind(&self) -> Option<ActionEvidenceKind> {
        match self {
            Self::Unobservable => None,
            Self::Match(s) | Self::Mismatch(s) => Some(s.kind),
        }
    }

    /// Did some observation carry action evidence of the expected kind?
    pub fn is_observable(&self) -> bool {
        !matches!(self, Self::Unobservable)
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
    /// A kernel-timestamped transition is placed **before** the authorized
    /// window — by the collector's signed clock, or by the probe's boot-clock
    /// anchor.
    BeforeWindow,
    /// A kernel-timestamped transition is placed **after** the window.
    AfterWindow,
    /// Kernel timestamps exist but no clock anchor lets them be placed on
    /// the decision point's wall clock; the two clock domains are not
    /// compared.
    Unanchored,
}

impl TemporalComparison {
    fn code(&self) -> u8 {
        match self {
            Self::WithinWindow => 0x01,
            Self::OutsideWindow => 0x02,
            Self::Indeterminate => 0x00,
            Self::BeforeWindow => 0x03,
            Self::AfterWindow => 0x04,
            Self::Unanchored => 0x05,
        }
    }
}

/// A pointer to an input the result rests on, so a third party can fetch it
/// and recompute.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceRef {
    Expected {
        decision_point_id: DecisionPointId,
        decision_id: DecisionId,
    },
    Batch {
        observer_id: ObserverId,
        key_version: u32,
        sequence: ObserverSequence,
        /// The probe-chosen batch id, and the probe run it belongs to. Both
        /// are recorded so a reader can re-derive the coverage argument —
        /// in particular that one probe run spanned the window.
        batch_id: BatchId,
        probe_run_id: ProbeRunId,
        /// The collector's clock when it signed the batch.
        attested_at_ms: u64,
        head: [u8; 32],
    },
    Health {
        observer_id: ObserverId,
        sequence: ObserverSequence,
        emitted_at_ms: u64,
    },
    Observation {
        batch_sequence: ObserverSequence,
        index: u32,
    },
    KernelEvent {
        batch_sequence: ObserverSequence,
        index: u32,
    },
    CoverageStatement {
        decision_point_id: DecisionPointId,
        issued_at_ms: u64,
    },
}

impl EvidenceRef {
    /// Canonical, injective bytes of one reference, for embedding in another
    /// signed object's preimage (the warrant). Same encoding the record uses.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Expected {
                decision_point_id,
                decision_id,
            } => {
                put_u8(buf, 0x01);
                put_str(buf, &decision_point_id.0);
                buf.extend_from_slice(decision_id.as_bytes());
            }
            Self::Batch {
                observer_id,
                key_version,
                sequence,
                batch_id,
                probe_run_id,
                attested_at_ms,
                head,
            } => {
                put_u8(buf, 0x02);
                put_str(buf, &observer_id.0);
                put_u32(buf, *key_version);
                put_u64(buf, sequence.0);
                buf.extend_from_slice(batch_id.as_bytes());
                buf.extend_from_slice(probe_run_id.as_bytes());
                put_u64(buf, *attested_at_ms);
                buf.extend_from_slice(head);
            }
            Self::Health {
                observer_id,
                sequence,
                emitted_at_ms,
            } => {
                put_u8(buf, 0x03);
                put_str(buf, &observer_id.0);
                put_u64(buf, sequence.0);
                put_u64(buf, *emitted_at_ms);
            }
            Self::Observation {
                batch_sequence,
                index,
            } => {
                put_u8(buf, 0x04);
                put_u64(buf, batch_sequence.0);
                put_u32(buf, *index);
            }
            Self::KernelEvent {
                batch_sequence,
                index,
            } => {
                put_u8(buf, 0x05);
                put_u64(buf, batch_sequence.0);
                put_u32(buf, *index);
            }
            Self::CoverageStatement {
                decision_point_id,
                issued_at_ms,
            } => {
                put_u8(buf, 0x06);
                put_str(buf, &decision_point_id.0);
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
        self.action.encode(&mut buf);
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
