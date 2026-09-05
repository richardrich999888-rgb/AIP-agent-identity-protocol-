//! Strongly typed inputs. Authorization evidence, observation evidence and
//! the verifier's context stay distinct types; nothing here merges them into
//! a generic "execution".

use aip_authorize::DecisionPointTrustAnchors;
use aip_crypto::{sha256, verify_ed25519};
use aip_observe::{AttestedBatch, CoverageWindow, ObserverTrustAnchors, SignedSensorHealth};
use aip_types::canonical::*;
use aip_types::Signature;
use serde::{Deserialize, Serialize};

use crate::ids::ObserverSequence;

/// Domain tag of a decision point's expected-side completeness statement.
pub const DECISION_POINT_COVERAGE_DOMAIN: &str = "GHOST/DecisionPointCoverage/v1";
pub const DECISION_POINT_COVERAGE_VERSION: u16 = 1;

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

/// A decision point's signed statement of *every* decision it issued for an
/// agent over a window. This is the only thing that can turn "no expectation
/// found" into "no expectation exists" (`UNATTRIBUTED_EFFECT`). Database
/// absence never can.
///
/// **No producer exists yet.** `aip-authorize` does not emit these; until it
/// does, the reconciler only ever sees [`ExpectedSideCoverage::Unknown`] in
/// production and `UNATTRIBUTED_EFFECT` is unreachable. The type is defined
/// here so the input contract — and the signature the reconciler demands — is
/// fixed before any producer is written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionPointCoverageStatement {
    pub version: u16,
    pub decision_point_id: String,
    pub agent_id: String,
    pub window: CoverageWindow,
    /// Every decision id issued for `agent_id` whose validity window
    /// intersects `window`. May be empty.
    pub decision_ids: Vec<[u8; 16]>,
    pub issued_at_ms: u64,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoverageStatementError {
    UnsupportedVersion(u16),
    UntrustedDecisionPoint(String),
    SignerMismatch,
    PayloadHashMismatch,
    SignatureInvalid,
    InvalidWindow,
}

impl DecisionPointCoverageStatement {
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, DECISION_POINT_COVERAGE_DOMAIN);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, &self.decision_point_id);
        put_str(&mut buf, &self.agent_id);
        put_u64(&mut buf, self.window.from_ms);
        put_u64(&mut buf, self.window.to_ms);
        put_u32(&mut buf, self.decision_ids.len() as u32);
        for d in &self.decision_ids {
            buf.extend_from_slice(d);
        }
        put_u64(&mut buf, self.issued_at_ms);
        buf
    }

    pub fn verify(
        &self,
        anchors: &DecisionPointTrustAnchors,
    ) -> Result<(), CoverageStatementError> {
        if self.version != DECISION_POINT_COVERAGE_VERSION {
            return Err(CoverageStatementError::UnsupportedVersion(self.version));
        }
        if self.window.to_ms < self.window.from_ms {
            return Err(CoverageStatementError::InvalidWindow);
        }
        let key = anchors.get(&self.decision_point_id).ok_or_else(|| {
            CoverageStatementError::UntrustedDecisionPoint(self.decision_point_id.clone())
        })?;
        if self.signature.signer_id != self.decision_point_id {
            return Err(CoverageStatementError::SignerMismatch);
        }
        if self.signature.payload_hash != sha256(&self.signing_preimage()) {
            return Err(CoverageStatementError::PayloadHashMismatch);
        }
        match verify_ed25519(key, &self.signature) {
            Ok(true) => Ok(()),
            _ => Err(CoverageStatementError::SignatureInvalid),
        }
    }
}

/// What the reconciler knows about the expected side's completeness.
#[derive(Debug, Clone)]
pub enum ExpectedSideCoverage {
    /// Nothing attests that the set of expectations the caller holds is
    /// complete. Absence of an expectation is then just absence.
    Unknown,
    /// A decision point attests the complete set for an agent and window.
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
