//! Strongly typed inputs. Authorization evidence, observation evidence and
//! the verifier's context stay distinct types; nothing here merges them into
//! a generic "execution".

use aip_authorize::DecisionPointTrustAnchors;
use aip_observe::{AttestedBatch, ObserverTrustAnchors, SignedSensorHealth};
use aip_types::{AgentIdentityDocument, DelegationToken, ScopedToken};

use crate::ids::ObserverSequence;

/// The decision point's expected-side completeness statement and its
/// verifier. Defined by the producer crate (`aip_authorize::coverage`), where
/// the ledger it is derived from lives; re-exported here so the reconciler's
/// input contract names it unchanged. Domain and version are the ones fixed
/// when this contract was written.
pub use aip_authorize::{
    CoverageStatementError, DecisionPointCoverageStatement, DECISION_POINT_COVERAGE_DOMAIN,
    DECISION_POINT_COVERAGE_VERSION,
};

/// Everything the observer side contributes: the attested batches the caller
/// holds for the subject and the newest signed health record. The batches
/// must form a contiguous chain ending at the health record's head; otherwise
/// the reconciler cannot know whether an observation was omitted and returns
/// `ObservationSetIncomplete` rather than a verdict.
#[derive(Debug, Clone)]
pub struct ObserverEvidence {
    pub batches: Vec<AttestedBatch>,
    pub health: SignedSensorHealth,
}

/// What the reconciler knows about the expected side's completeness.
#[derive(Debug, Clone)]
pub enum ExpectedSideCoverage {
    /// Nothing attests that the set of expectations the caller holds is
    /// complete. Absence of an expectation is then just absence.
    Unknown,
    /// A decision point attests the complete set for an agent and window
    /// (produced by `aip_authorize::DecisionPoint::coverage_statement` from
    /// its own ledger).
    Attested(Box<DecisionPointCoverageStatement>),
}

/// The verifier's context. Every trust decision and every time reference
/// enters here explicitly; the reconciler reads no clock and holds no
/// anchors of its own.
#[derive(Debug, Clone)]
pub struct ReconciliationContext {
    pub decision_point_anchors: DecisionPointTrustAnchors,
    pub observer_anchors: ObserverTrustAnchors,
    /// The time the verifier is reconciling at. Used only for health
    /// freshness and for the expectation's `TemporalStatus` annotation;
    /// never to place an event in time.
    pub verification_time_ms: u64,
    /// Health older than this is `HealthStale` → unavailable.
    pub health_max_age_ms: u64,
    /// Slack applied when comparing a probe-claimed batch window with the
    /// expectation's authorized window, and when comparing the collector's
    /// clock with the verifier's. A filter, not evidence.
    pub window_tolerance_ms: u64,
    pub expected_side: ExpectedSideCoverage,
    /// The observed agent's public key, when the verifier knows it (e.g.
    /// from the `EvidencePacket` the agent produced).
    ///
    /// Supplying it lets the reconciler check the two independence
    /// invariants it otherwise cannot see: that the anchored decision key is
    /// not the agent's own (I1) and that the anchored observer key is not
    /// the agent's own (I10). `None` means the verifier did not supply it and
    /// those checks are skipped — a documented limitation, not a pass.
    pub agent_public_key: Option<Vec<u8>>,
}

/// Which observation an observed-only reconciliation is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationTarget {
    Observation {
        batch_sequence: ObserverSequence,
        index: u32,
    },
    KernelEvent {
        batch_sequence: ObserverSequence,
        index: u32,
    },
}

// ─── Lineage inputs (Phase C2) ───

/// The tokens a decision rests on, supplied by the verifier so the
/// reconciler can check them against the expectation's `AuthorityRef` and
/// verify them through `aip_core`. Never trusted from the record itself.
#[derive(Debug, Clone)]
pub struct DecisionAuthority {
    pub root: ScopedToken,
    pub chain: Vec<DelegationToken>,
}

/// The agent's identity document and the parent document its lineage proof
/// names, both validated before use.
#[derive(Debug, Clone, Copy)]
pub struct IdentityLineageInput<'a> {
    pub child: &'a AgentIdentityDocument,
    pub parent: &'a AgentIdentityDocument,
}

/// Everything `reconcile_lineage` needs beyond the expectation and the
/// observer evidence. Each piece is verified inside the reconciler; an
/// absent or unverifiable piece makes the corresponding side incomplete.
#[derive(Debug, Clone, Copy)]
pub struct LineageInputs<'a> {
    /// Decision-point-signed expectations of other agents, used to attribute
    /// the spawning instance (and to detect a second claim on the child).
    pub peer_expectations: &'a [aip_authorize::ExpectedExecution],
    pub authority: Option<&'a DecisionAuthority>,
    /// Issuer public keys by AIP-ID, the verifier's own.
    pub issuer_keys: &'a std::collections::HashMap<String, Vec<u8>>,
    /// Verifier-supplied revoked token ids.
    pub revoked_jtis: &'a [[u8; 16]],
    pub identity: Option<IdentityLineageInput<'a>>,
}
