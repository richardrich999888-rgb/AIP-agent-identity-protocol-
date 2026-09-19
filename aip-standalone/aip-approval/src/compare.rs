//! The comparison. Pure, deterministic, clock-free, and — when both sides
//! verified — recomputable by anyone holding the two artifacts.

use aip_authorize::{verify_expected_execution, DecisionPointTrustAnchors, ExpectedExecution};
use aip_crypto::sha256;
use aip_types::ScopeAction;
use serde::{Deserialize, Serialize};

use crate::artifact::VerifiedApprovalArtifact;

/// What kind of fact the comparison produced.
///
/// This is the load-bearing distinction in the crate. `Recomputable` means
/// the answer follows from two signed artifacts and two anchors, with no
/// input read from the observed host — the same property that lets
/// `classify_observer_error` grant `Proven` for signature arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Basis {
    /// Both sides verified under anchors the verifier chose; the comparison
    /// is arithmetic over held bytes. A third party recomputes it offline.
    Recomputable,
    /// The comparison ran, but at least one side was not independently
    /// verified, so the result describes the inputs it was handed rather
    /// than anything a third party could re-derive.
    Unverified,
}

/// A way the shown and the authorized can differ. Every variant is a
/// statement about **two documents**, never about the world.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Divergence {
    /// The human was shown parameters whose digest is not the digest the
    /// decision point sealed. **This is the Replit class**: a genuine
    /// approval of something other than what was authorized.
    ParametersDiffer {
        shown: [u8; 32],
        authorized: [u8; 32],
    },
    /// The action kind shown is not the action kind sealed.
    ActionDiffers {
        shown: ScopeAction,
        authorized: ScopeAction,
    },
    /// The artifact commits to an expectation digest that is not this
    /// expectation's. The approval is for a different document — possibly a
    /// replay of an earlier decision that shared a decision id.
    ExpectationDiffers {
        committed: [u8; 32],
        actual: [u8; 32],
    },
}

/// Why no comparison was made. **None of these is a finding about the
/// agent**, and none may be read as one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotEvaluatedReason {
    /// No artifact was supplied. Most decisions are never shown to a human;
    /// this is the ordinary case, not a gap.
    NoApprovalArtifact,
    /// The artifact is for a different decision entirely.
    DifferentDecision {
        artifact_decision: [u8; 16],
        expectation_decision: [u8; 16],
    },
    /// The expectation did not verify under the anchors supplied, so there is
    /// no authorized side to compare against.
    ExpectationNotVerified,
}

/// The result. `Agrees` and `Diverges` both carry a [`Basis`]; a caller that
/// ignores it is reading more into the answer than it contains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShownVsAuthorized {
    /// Shown and authorized commit to the same action and parameters.
    ///
    /// This does **not** mean the agent then did that. It means the human
    /// approved the thing that was sealed. What executed is the observer's
    /// question, and this crate never asks it.
    Agrees { basis: Basis },
    /// They differ, in the named way.
    Diverges {
        divergence: Divergence,
        basis: Basis,
    },
    /// Nothing was compared.
    NotEvaluated { reason: NotEvaluatedReason },
}

impl ShownVsAuthorized {
    /// Is this a divergence whose basis is arithmetic over verified,
    /// held bytes?
    ///
    /// This is the predicate a future reconciler entry point would gate on —
    /// see the crate docs, "The gate". It exists here so that when such an
    /// entry point is written, the precondition is one already-tested
    /// function rather than a condition re-derived at the call site and got
    /// subtly wrong.
    pub fn is_recomputable_divergence(&self) -> bool {
        matches!(
            self,
            ShownVsAuthorized::Diverges {
                basis: Basis::Recomputable,
                ..
            }
        )
    }

    pub fn divergence(&self) -> Option<&Divergence> {
        match self {
            ShownVsAuthorized::Diverges { divergence, .. } => Some(divergence),
            _ => None,
        }
    }
}

/// Compare what was shown against what was sealed.
///
/// `artifact` is `None` for the ordinary case of a decision no human saw.
/// The expectation is verified here rather than trusted: an unverified
/// expectation yields [`NotEvaluatedReason::ExpectationNotVerified`], because
/// comparing against bytes nobody checked would produce an answer that looks
/// arithmetic and is not.
///
/// Order of checks, each failing toward "cannot say":
/// 1. Is there an artifact at all?
/// 2. Does the expectation verify under the verifier's anchors?
/// 3. Do the two refer to the same decision?
/// 4. Does the artifact commit to *this* expectation's digest?
/// 5. Do the action kind and the parameter digest agree?
pub fn compare_shown_to_authorized(
    artifact: Option<&VerifiedApprovalArtifact>,
    expectation: &ExpectedExecution,
    anchors: &DecisionPointTrustAnchors,
) -> ShownVsAuthorized {
    let Some(verified) = artifact else {
        return ShownVsAuthorized::NotEvaluated {
            reason: NotEvaluatedReason::NoApprovalArtifact,
        };
    };
    if verify_expected_execution(expectation, anchors).is_err() {
        return ShownVsAuthorized::NotEvaluated {
            reason: NotEvaluatedReason::ExpectationNotVerified,
        };
    }
    // Both sides are now verified under anchors the caller chose, so every
    // answer below follows from held bytes alone.
    let basis = Basis::Recomputable;
    let a = verified.artifact();

    if a.decision_id != expectation.decision_id {
        return ShownVsAuthorized::NotEvaluated {
            reason: NotEvaluatedReason::DifferentDecision {
                artifact_decision: a.decision_id,
                expectation_decision: expectation.decision_id,
            },
        };
    }

    // The artifact names which expectation it approved. A decision id alone
    // is not enough: two expectations can share one if a decision point
    // reissues, and the approval belongs to exactly one of them.
    let actual = sha256(&expectation.signing_preimage());
    if a.expectation_digest != actual {
        return ShownVsAuthorized::Diverges {
            divergence: Divergence::ExpectationDiffers {
                committed: a.expectation_digest,
                actual,
            },
            basis,
        };
    }

    if a.shown_action != expectation.action_kind {
        return ShownVsAuthorized::Diverges {
            divergence: Divergence::ActionDiffers {
                shown: a.shown_action.clone(),
                authorized: expectation.action_kind.clone(),
            },
            basis,
        };
    }

    if a.shown_parameter_digest != expectation.parameter_digest {
        return ShownVsAuthorized::Diverges {
            divergence: Divergence::ParametersDiffer {
                shown: a.shown_parameter_digest,
                authorized: expectation.parameter_digest,
            },
            basis,
        };
    }

    ShownVsAuthorized::Agrees { basis }
}
