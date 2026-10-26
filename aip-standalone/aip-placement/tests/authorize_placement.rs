//! A placement is made only for a decision a trusted decision point signed,
//! and only while that decision is valid. Pure: no cgroup, no kernel.

mod common;

use aip_authorize::{DecisionPointTrustAnchors, ExpectedVerifyError, TemporalStatus};
use aip_placement::{authorize_placement, PlacementAuthority, PlacementError};
use common::*;

#[test]
fn a_verified_valid_decision_is_placed_under_its_own_id() {
    let a = authorised();
    let ee = a.expectation();
    assert_eq!(
        authorize_placement(&ee, &a.authority(), a.now).unwrap(),
        ee.decision_id
    );
}

#[test]
fn a_rewritten_decision_is_not_placed() {
    let a = authorised();
    let mut ee = a.expectation();
    ee.valid_until += 1;
    assert!(matches!(
        authorize_placement(&ee, &a.authority(), a.now),
        Err(PlacementError::NotAuthorized(
            ExpectedVerifyError::PayloadHashMismatch
        ))
    ));
}

#[test]
fn a_decision_from_an_untrusted_decision_point_is_not_placed() {
    let a = authorised();
    let none = PlacementAuthority::new(DecisionPointTrustAnchors::new(), None);
    assert!(matches!(
        authorize_placement(&a.expectation(), &none, a.now),
        Err(PlacementError::NotAuthorized(
            ExpectedVerifyError::UntrustedDecisionPoint(_)
        ))
    ));
}

/// A supervisor configured to trust the agent's own key as a decision point
/// would let the agent place itself: refused.
#[test]
fn a_decision_point_anchored_under_the_agents_key_is_refused() {
    let a = authorised();
    let ee = a.expectation();
    let self_trust = PlacementAuthority::new(
        DecisionPointTrustAnchors::new().trust(&ee.decision_point_id, &a.agent_kp.public_key),
        Some(a.agent_kp.public_key.clone()),
    );
    assert!(matches!(
        authorize_placement(&ee, &self_trust, a.now),
        Err(PlacementError::NotAuthorized(
            ExpectedVerifyError::DecisionKeyIsAgentKey
        ))
    ));
}

#[test]
fn a_decision_outside_its_window_is_not_placed() {
    let a = authorised();
    let ee = a.expectation();
    assert!(matches!(
        authorize_placement(&ee, &a.authority(), ee.issued_at - 1),
        Err(PlacementError::NotValidAt(TemporalStatus::NotYetValid))
    ));
    assert!(matches!(
        authorize_placement(&ee, &a.authority(), ee.valid_until + 1),
        Err(PlacementError::NotValidAt(TemporalStatus::Expired))
    ));
    // Both ends inclusive, as the decision point signs them.
    assert!(authorize_placement(&ee, &a.authority(), ee.issued_at).is_ok());
    assert!(authorize_placement(&ee, &a.authority(), ee.valid_until).is_ok());
}
