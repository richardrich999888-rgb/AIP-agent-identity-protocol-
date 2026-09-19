//! The tool-boundary comparison (R4): **authorized versus received**.
//!
//! Three documents can describe one tool invocation:
//!
//! | Document | Signer | Says |
//! |---|---|---|
//! | `ExpectedExecution` (`ghost.tool.invoke.v1`) | decision point | what was authorized: a tool id and a parameter commitment |
//! | `AiriEvent` / `ToolInvocationRequested` | the agent | what the agent says it asked for |
//! | [`ToolReceipt`](crate::ToolReceipt) | the tool gateway | what the gateway actually received, recomputed by the gateway |
//!
//! [`compare_tool_boundary`] recomputes the decision point's parameter
//! digest from the receipt's `(tool_id, parameter_commitment)` through the
//! same `tool_invoke_parameters` function the decision point used, and
//! compares. Both inputs are signed artefacts verified under anchors the
//! verifier chose, so every evaluated answer is arithmetic over held bytes:
//! a third party with the two documents and the two anchors recomputes it
//! offline, with no clock and no access to the observed host.
//!
//! The agent's own claim, when supplied, is compared too, but it can only
//! add a **third** kind of disagreement. It can never turn a receipt that
//! matches the authorization into a divergence, and it can never turn a
//! receipt that does not match into agreement: the agent is the party under
//! scrutiny.
//!
//! # What this is not
//!
//! - **Not a verdict.** No `ReconciliationResult` and no `EvidenceStrength`
//!   is produced or named here. The finding is surfaced beside a
//!   reconciliation, in the shape [`crate::AiriAnnotation`] established.
//!   Wiring a tool-boundary divergence into the engine's accusation path is
//!   a separate, gated decision (`docs/architecture/ADR-016-APPROVAL-TIER.md`
//!   lists the gate; the same four conditions apply here).
//! - **Not proof of effect.** A receipt says what reached the gateway. What
//!   the tool then did is the tool's business and is not claimed.
//! - **Not an accusation when nothing was received.** A decision with no
//!   receipt is [`ToolBoundary::NotEvaluated`] with a reason, never a
//!   divergence. A gateway that emits no receipts is a coverage gap, and a
//!   coverage gap is stated, not scored.

use aip_authorize::{
    tool_invoke_action, tool_invoke_parameters, verify_expected_execution,
    DecisionPointTrustAnchors, ExpectedExecution,
};
use aip_types::ScopeAction;
use serde::{Deserialize, Serialize};

use crate::event::{AiriEvent, AiriPayload};
use crate::receipt::VerifiedToolReceipt;

/// A way the documents can disagree. Every variant is a statement about
/// **documents**, never about the world.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolBoundaryDivergence {
    /// The gateway received a request whose `(tool_id, commitment)` digest
    /// is not the digest the decision point sealed. **This is the disputed
    /// transaction class**: what reached the system is not what was
    /// authorized, whatever the agent said about it.
    ReceiptDoesNotMatchAuthorization {
        received: [u8; 32],
        authorized: [u8; 32],
    },
    /// The gateway received what was authorized, but the agent's own signed
    /// claim names a different `(tool_id, commitment)`. The agent misreported
    /// its request; the request itself was in order.
    ClaimDoesNotMatchAuthorization {
        claimed: [u8; 32],
        authorized: [u8; 32],
    },
}

/// Why no comparison was made. **None of these is a finding about the
/// agent**, and none may be read as one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolBoundaryNotEvaluated {
    /// The expectation is not a `ghost.tool.invoke.v1` authorization; the
    /// tool boundary has nothing to say about a socket or an exec.
    NotAToolInvocation { action_kind: ScopeAction },
    /// The expectation did not verify under the verifier's anchors.
    /// Comparing against bytes nobody checked would produce an answer that
    /// looks arithmetic and is not.
    ExpectationNotVerified,
    /// No receipt was supplied. A coverage statement, not a finding.
    NoReceipt,
    /// The receipt cites a different decision.
    DifferentDecision {
        receipt_decision: [u8; 16],
        expectation_decision: [u8; 16],
    },
    /// The receipt names a different agent than the expectation authorizes.
    /// The pair is internally inconsistent and supports no comparison.
    DifferentAgent {
        receipt_agent: String,
        expectation_agent: String,
    },
    /// The receipt's tool id is not one `tool_invoke_parameters` accepts, so
    /// no digest can be recomputed from it.
    ReceiptToolIdMalformed { tool_id: String },
}

/// How the agent's own claim was treated, recorded so a reader can tell
/// "the claim agreed" from "no claim was supplied".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimStanding {
    /// No `AiriEvent` was supplied.
    NotSupplied,
    /// The supplied event is not a `ToolInvocationRequested`, or cites a
    /// different decision; it was not compared.
    NotComparable,
    /// The claim's `(tool_id, commitment)` digest equals the authorization.
    Agrees,
}

/// The outcome of one comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolBoundary {
    /// The gateway received exactly what was authorized. `claim` says
    /// whether the agent's account agreed too.
    Agrees { claim: ClaimStanding },
    /// The documents disagree in the named way.
    Diverges { divergence: ToolBoundaryDivergence },
    /// No comparison was made, for the stated reason.
    NotEvaluated { reason: ToolBoundaryNotEvaluated },
}

impl ToolBoundary {
    pub fn is_divergence(&self) -> bool {
        matches!(self, Self::Diverges { .. })
    }

    pub fn divergence(&self) -> Option<&ToolBoundaryDivergence> {
        match self {
            Self::Diverges { divergence } => Some(divergence),
            _ => None,
        }
    }
}

/// Compare what was authorized against what the gateway received, and
/// against what the agent claimed.
///
/// `receipt` is `None` for a decision no gateway reported on. `claim` is the
/// agent's `ToolInvocationRequested` event, when the verifier holds one; the
/// caller must have verified its signature with
/// [`crate::verify_airi_event`], as with [`crate::corroborate`].
///
/// Order of checks, each failing toward "cannot say":
/// 1. Is the expectation a tool invocation at all?
/// 2. Does the expectation verify under the verifier's anchors?
/// 3. Is there a receipt?
/// 4. Do receipt and expectation cite the same decision and the same agent?
/// 5. Does the receipt's recomputed digest equal the sealed one?
/// 6. Only then: does the agent's claim, if comparable, agree as well?
pub fn compare_tool_boundary(
    expectation: &ExpectedExecution,
    anchors: &DecisionPointTrustAnchors,
    receipt: Option<&VerifiedToolReceipt>,
    claim: Option<&AiriEvent>,
) -> ToolBoundary {
    use ToolBoundaryNotEvaluated as N;

    if expectation.action_kind != tool_invoke_action() {
        return ToolBoundary::NotEvaluated {
            reason: N::NotAToolInvocation {
                action_kind: expectation.action_kind.clone(),
            },
        };
    }
    if verify_expected_execution(expectation, anchors).is_err() {
        return ToolBoundary::NotEvaluated {
            reason: N::ExpectationNotVerified,
        };
    }
    let Some(verified) = receipt else {
        return ToolBoundary::NotEvaluated {
            reason: N::NoReceipt,
        };
    };
    let r = verified.receipt();
    if r.decision_id != expectation.decision_id {
        return ToolBoundary::NotEvaluated {
            reason: N::DifferentDecision {
                receipt_decision: r.decision_id,
                expectation_decision: expectation.decision_id,
            },
        };
    }
    if r.agent_id != expectation.agent_id {
        return ToolBoundary::NotEvaluated {
            reason: N::DifferentAgent {
                receipt_agent: r.agent_id.clone(),
                expectation_agent: expectation.agent_id.clone(),
            },
        };
    }
    let Ok(received_params) = tool_invoke_parameters(&r.tool_id, r.parameter_commitment) else {
        return ToolBoundary::NotEvaluated {
            reason: N::ReceiptToolIdMalformed {
                tool_id: r.tool_id.clone(),
            },
        };
    };
    let received = received_params.digest();
    let authorized = expectation.parameter_digest;
    if received != authorized {
        return ToolBoundary::Diverges {
            divergence: ToolBoundaryDivergence::ReceiptDoesNotMatchAuthorization {
                received,
                authorized,
            },
        };
    }

    // The independent side agrees. The agent's own account can now only add
    // a misreport; it cannot change what the gateway received.
    let claim_standing = match claim {
        None => ClaimStanding::NotSupplied,
        Some(ev) => match claimed_digest(ev, &expectation.decision_id) {
            None => ClaimStanding::NotComparable,
            Some(claimed) if claimed == authorized => ClaimStanding::Agrees,
            Some(claimed) => {
                return ToolBoundary::Diverges {
                    divergence: ToolBoundaryDivergence::ClaimDoesNotMatchAuthorization {
                        claimed,
                        authorized,
                    },
                }
            }
        },
    };
    ToolBoundary::Agrees {
        claim: claim_standing,
    }
}

/// The decision-point digest the agent's claim corresponds to, when the
/// event is a `ToolInvocationRequested` citing this decision and its tool
/// id is well formed. `None` means "not comparable", never "disagrees".
fn claimed_digest(ev: &AiriEvent, decision_id: &[u8; 16]) -> Option<[u8; 32]> {
    if ev.decision_id.as_ref() != Some(decision_id) {
        return None;
    }
    let AiriPayload::ToolInvocationRequested(t) = &ev.payload else {
        return None;
    };
    tool_invoke_parameters(&t.tool_id, t.parameter_commitment)
        .ok()
        .map(|p| p.digest())
}
