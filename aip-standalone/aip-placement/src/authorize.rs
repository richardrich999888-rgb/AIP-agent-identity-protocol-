//! Whether a decision may be placed: the supervisor's only judgement, and a
//! pure one — no cgroup, no clock read, no IO.
//!
//! The supervisor places work for a decision only if a decision point it
//! trusts signed that decision, the decision point is not anchored under
//! the agent's own key, and the decision is valid at the supervisor's
//! present. It does not re-decide authority: that is the decision point's,
//! and the signature is the decision point's own verifier's to check.

use aip_authorize::{
    verify_expected_execution, verify_expected_execution_for_agent, DecisionPointTrustAnchors,
    ExpectedExecution, TemporalStatus,
};

/// The supervisor's trust: which decision points it places work for, and
/// the agent's key, so an anchor under it is refused.
#[derive(Debug, Clone)]
pub struct PlacementAuthority {
    anchors: DecisionPointTrustAnchors,
    agent_public_key: Option<Vec<u8>>,
}

impl PlacementAuthority {
    pub fn new(anchors: DecisionPointTrustAnchors, agent_public_key: Option<Vec<u8>>) -> Self {
        Self {
            anchors,
            agent_public_key,
        }
    }
}

/// Why a decision was not placed — returned by [`authorize_placement`].
pub use crate::cgroup::PlacementError;

/// The decision id to place, if `ee` may be placed at `now_ms`.
pub fn authorize_placement(
    ee: &ExpectedExecution,
    authority: &PlacementAuthority,
    now_ms: u64,
) -> Result<[u8; 16], PlacementError> {
    let verified = match &authority.agent_public_key {
        Some(agent) => verify_expected_execution_for_agent(ee, &authority.anchors, agent),
        None => verify_expected_execution(ee, &authority.anchors),
    };
    verified.map_err(PlacementError::NotAuthorized)?;
    match ee.temporal_status_at(now_ms) {
        TemporalStatus::Valid => Ok(ee.decision_id),
        other => Err(PlacementError::NotValidAt(other)),
    }
}
