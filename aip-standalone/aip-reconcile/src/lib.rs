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
//! `identity = Match`. `UNATTRIBUTED_EFFECT` requires a
//! [`DecisionPointCoverageStatement`] the decision point derived from its own
//! ledger (`aip_authorize::DecisionPoint::coverage_statement`); without one
//! the expected side's completeness is unknown and the verdict stays
//! `CANNOT_PROVE`.
//! `LINEAGE_VIOLATION` is unreachable until both ends of a kernel fork are
//! bound. These are stated, not worked around.

pub mod action;
pub mod attest;
pub mod ids;
pub mod inputs;
pub mod lineage_report;
pub mod reconcile;
pub mod result;

pub use action::{
    derive_action, derive_executions, derive_file_writes, derive_lineage_edges, derive_sends,
    derive_transition_evidence, derive_transitions, DerivedAction, EventPosition, ExecutedImage,
    FileWrite, LineageEdge, ProcessExecution, SocketSend, SocketTransition, TransitionEvidence,
    TCP_ESTABLISHED,
};
pub use attest::{
    ReconcilerSigner, ReconcilerTrustAnchors, ReconciliationAttestationError, SignedReconciliation,
    RECONCILIATION_ATTESTATION_DOMAIN, RECONCILIATION_ATTESTATION_VERSION,
    SIGNED_RECONCILIATION_DOMAIN,
};
pub use ids::{BatchId, DecisionId, DecisionPointId, ObserverId, ObserverSequence, ProbeRunId};
pub use inputs::{
    CoverageStatementError, DecisionAuthority, DecisionPointCoverageStatement,
    ExpectedSideCoverage, IdentityLineageInput, LineageInputs, ObservationTarget, ObserverEvidence,
    ReconciliationContext, DECISION_POINT_COVERAGE_DOMAIN, DECISION_POINT_COVERAGE_VERSION,
};
pub use lineage_report::{distinct_parents, render_edge, render_report, sort_edges};
pub use reconcile::{reconcile_expectation, reconcile_lineage, reconcile_observation};
pub use result::{
    ActionComparison, ActionEvidenceKind, ActionEvidenceSeal, EvidenceRef, EvidenceStrength,
    IdentityComparison, LineageComparison, LineageLink, Provenance, ReasonCode, Reconciliation,
    ReconciliationResult, TemporalComparison, WireCorroboration, RECONCILIATION_DOMAIN,
    RECONCILIATION_VERSION,
};
