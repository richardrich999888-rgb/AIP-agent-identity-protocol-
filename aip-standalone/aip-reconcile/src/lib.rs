//! aip-reconcile — Ghost Stage 4: compare what a decision point authorized
//! with what an independent observer recorded, and say exactly how far the
//! evidence goes.
//!
//! ```text
//! ExpectedExecution  (aip-authorize, decision-point-signed)
//!         +
//! AttestedBatch* + SignedSensorHealth  (aip-observe, collector-signed)
//!         ↓
//! Reconciliation { result, strength, reason, identity, action, temporal,
//!                  availability, evidence refs }
//! ```
//!
//! # What this crate never does
//!
//! It holds no key and signs nothing. It grants, revokes, permits or denies
//! nothing. It never kills, freezes, filters or isolates anything. It never
//! infers from silence: `ReconciliationResult::default()` is `CannotProve`,
//! and every positive class has a precondition that must be met from signed
//! evidence the verifier supplied.
//!
//! # The ceiling of the current evidence
//!
//! `VERIFIED_EXECUTION` is unreachable: no observation produced by
//! `aip-observe` carries an action kind or parameter digest, so
//! [`ActionComparison`] is always `Unobservable`. The strongest positive
//! statement about an expectation is *identity corroborated* — reported as
//! `CANNOT_PROVE` with `reason = ActionEvidenceUnavailable` and
//! `identity = Match`. `UNATTRIBUTED_EFFECT` is unreachable in production
//! until a decision point emits [`DecisionPointCoverageStatement`]s.
//! `LINEAGE_VIOLATION` is unreachable until both ends of a kernel fork are
//! bound. These are stated, not worked around.

pub mod action;
pub mod ids;
pub mod inputs;
pub mod reconcile;
pub mod result;

pub use action::{
    derive_action, derive_executions, derive_transition_evidence, derive_transitions,
    DerivedAction, EventPosition, ExecutedImage, ProcessExecution, SocketTransition,
    TransitionEvidence, TCP_ESTABLISHED,
};
pub use ids::{BatchId, DecisionId, DecisionPointId, ObserverId, ObserverSequence, ProbeRunId};
pub use inputs::{
    CoverageStatementError, DecisionPointCoverageStatement, ExpectedSideCoverage,
    ObservationTarget, ObserverEvidence, ReconciliationContext, DECISION_POINT_COVERAGE_DOMAIN,
    DECISION_POINT_COVERAGE_VERSION,
};
pub use reconcile::{reconcile_expectation, reconcile_observation};
pub use result::{
    ActionComparison, ActionEvidenceKind, ActionEvidenceSeal, EvidenceRef, EvidenceStrength,
    IdentityComparison, ReasonCode, Reconciliation, ReconciliationResult, TemporalComparison,
    RECONCILIATION_DOMAIN, RECONCILIATION_VERSION,
};
