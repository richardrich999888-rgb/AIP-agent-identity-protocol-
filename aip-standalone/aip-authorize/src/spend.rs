//! Spend authority at the decision point (ADR-018, step 5c).
//!
//! The decision point holds at most one verified [`VerifiedSpendPolicy`] per
//! agent. When a policy governs the requested action, the amount is read from
//! the same parameter bytes the expectation will seal and the request is:
//!
//! - **refused** above the maximum, or when the amount cannot be read — and
//!   the decision point signs a [`SignedSpendRefusal`] carrying the amount;
//! - **authorised** within the maximum — and the decision point signs a
//!   [`SignedSpendAttestation`] (no amount) bound to the expectation by
//!   digest, marked `ApprovalRequired` above the approval threshold.
//!
//! `ExpectedExecution` is unchanged: the spend record is a separate signed
//! object, so every existing verifier and wire format is untouched.
//!
//! This module holds the record construction only; the enforcement decision
//! itself is [`aip_spend::evaluate`], a pure function.

use std::collections::HashMap;

use aip_crypto::sha256;
use aip_spend::{
    DecisionPointKeys, PolicyCitation, RecordError, RefusalReason, SignedSpendAttestation,
    SignedSpendRefusal, SpendAttestation, SpendOutcome, SpendRefusal, SpendRule, SpendVerdict,
    Unreadable, VerifiedSpendPolicy, SPEND_RECORD_VERSION,
};

use crate::decision::Decision;
use crate::expected::{DecisionPointTrustAnchors, ExpectedExecution};

/// The verifier's decision-point anchors also verify spend records.
impl DecisionPointKeys for DecisionPointTrustAnchors {
    fn key(&self, decision_point_id: &str) -> Option<&[u8]> {
        self.get(decision_point_id)
    }
}

/// The signed spend record a decision produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendRecord {
    /// The request was authorised under a governing rule.
    Attested(SignedSpendAttestation),
    /// The request was refused on spend authority.
    Refused(SignedSpendRefusal),
}

/// A decision together with its spend record, if one was produced.
///
/// `record` is `None` when no policy governs the request, when the request
/// was denied before spend authority was reached, or when it passed spend
/// authority and was denied by a later step (no expectation exists to bind
/// an attestation to). A refusal whose own signature failed also leaves it
/// `None`; the decision is still a denial and its detail says so.
#[derive(Debug, Clone)]
pub struct SpendDecision {
    pub decision: Decision,
    pub record: Option<SpendRecord>,
}

/// Why a spend policy could not be adopted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendConfigError {
    /// A policy for this agent is already held at the same or a later
    /// revision. Adopting it would roll a limit back.
    RevisionNotNewer {
        agent_id: String,
        held: u64,
        offered: u64,
    },
}

impl std::fmt::Display for SpendConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RevisionNotNewer {
                agent_id,
                held,
                offered,
            } => write!(
                f,
                "spend policy for {agent_id}: revision {offered} is not newer than held revision {held}"
            ),
        }
    }
}

impl std::error::Error for SpendConfigError {}

/// The verified policies a decision point enforces, one per agent.
#[derive(Debug, Clone, Default)]
pub(crate) struct SpendPolicies(HashMap<String, VerifiedSpendPolicy>);

impl SpendPolicies {
    /// Adopt `policy` for its agent. Refuses a revision that is not strictly
    /// newer than the one held, so configuration cannot roll a limit back.
    pub(crate) fn adopt(&mut self, policy: VerifiedSpendPolicy) -> Result<(), SpendConfigError> {
        let agent_id = policy.policy().agent_id.clone();
        if let Some(held) = self.0.get(&agent_id) {
            let (held, offered) = (held.policy().revision, policy.policy().revision);
            if offered <= held {
                return Err(SpendConfigError::RevisionNotNewer {
                    agent_id,
                    held,
                    offered,
                });
            }
        }
        self.0.insert(agent_id, policy);
        Ok(())
    }

    pub(crate) fn get(&self, agent_id: &str) -> Option<&VerifiedSpendPolicy> {
        self.0.get(agent_id)
    }

    /// Policy ids, for `Debug`, in a stable order.
    pub(crate) fn citations(&self) -> Vec<(String, u64)> {
        let mut v: Vec<(String, u64)> = self
            .0
            .values()
            .map(|p| (p.policy().policy_id.clone(), p.policy().revision))
            .collect();
        v.sort();
        v
    }
}

/// Which policy and rule governed a request, and what they said.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SpendCheck<'a> {
    pub(crate) policy: &'a VerifiedSpendPolicy,
    pub(crate) rule: &'a SpendRule,
    pub(crate) outcome: SpendOutcome,
}

/// The citation a record carries for `policy`.
pub(crate) fn citation(policy: &VerifiedSpendPolicy) -> PolicyCitation {
    let p = policy.policy();
    PolicyCitation {
        issuer_id: p.issuer_id.clone(),
        policy_id: p.policy_id.clone(),
        revision: p.revision,
        digest: p.digest(),
    }
}

/// The refusal reason and requested amount for a refusing outcome; `None`
/// for an outcome that authorises.
pub(crate) fn refusal_terms(outcome: SpendOutcome) -> Option<(RefusalReason, Option<u64>)> {
    match outcome {
        SpendOutcome::Exceeded { amount, .. } => Some((RefusalReason::LimitExceeded, Some(amount))),
        SpendOutcome::Unreadable { reason, .. } => Some((
            match reason {
                Unreadable::Missing => RefusalReason::AmountMissing,
                Unreadable::NotDecimal => RefusalReason::AmountNotDecimal,
                Unreadable::OutOfRange => RefusalReason::AmountOutOfRange,
            },
            None,
        )),
        SpendOutcome::NotGoverned
        | SpendOutcome::Within { .. }
        | SpendOutcome::ApprovalRequired { .. } => None,
    }
}

/// The attestation verdict for an authorising outcome; `None` otherwise.
pub(crate) fn verdict(outcome: SpendOutcome) -> Option<SpendVerdict> {
    match outcome {
        SpendOutcome::Within { .. } => Some(SpendVerdict::Within),
        SpendOutcome::ApprovalRequired { .. } => Some(SpendVerdict::ApprovalRequired),
        SpendOutcome::NotGoverned
        | SpendOutcome::Exceeded { .. }
        | SpendOutcome::Unreadable { .. } => None,
    }
}

/// Everything a refusal record needs that is not in the check itself.
pub(crate) struct RefusalContext<'a> {
    pub(crate) decision_point_id: &'a str,
    pub(crate) agent_id: &'a str,
    pub(crate) request_digest: [u8; 32],
    pub(crate) refused_at_ms: u64,
}

/// Sign a refusal for a refusing check. `None` if the check authorises.
pub(crate) fn sign_refusal(
    check: &SpendCheck<'_>,
    ctx: &RefusalContext<'_>,
    decision_point_key: &[u8],
) -> Option<Result<SignedSpendRefusal, RecordError>> {
    let (reason, requested) = refusal_terms(check.outcome)?;
    let refusal = SpendRefusal {
        version: SPEND_RECORD_VERSION,
        decision_point_id: ctx.decision_point_id.to_string(),
        agent_id: ctx.agent_id.to_string(),
        request_digest: ctx.request_digest,
        policy: citation(check.policy),
        action: check.rule.action.clone(),
        reason,
        requested_minor_units: requested,
        limit_minor_units: check.rule.max_per_action,
        currency: check.rule.currency.clone(),
        exponent: check.rule.exponent,
        refused_at_ms: ctx.refused_at_ms,
    };
    Some(SignedSpendRefusal::sign(refusal, decision_point_key))
}

/// Sign an attestation binding an authorising check to the signed
/// expectation `ee`. `None` if the check refuses.
pub(crate) fn sign_attestation(
    check: &SpendCheck<'_>,
    ee: &ExpectedExecution,
    decision_point_key: &[u8],
) -> Option<Result<SignedSpendAttestation, RecordError>> {
    let verdict = verdict(check.outcome)?;
    let attestation = SpendAttestation {
        version: SPEND_RECORD_VERSION,
        decision_point_id: ee.decision_point_id.clone(),
        decision_id: ee.decision_id,
        agent_id: ee.agent_id.clone(),
        expectation_digest: expectation_digest(ee),
        policy: citation(check.policy),
        action: check.rule.action.clone(),
        verdict,
        limit_minor_units: check.rule.max_per_action,
        approval_threshold: check.rule.approval_above,
        currency: check.rule.currency.clone(),
        exponent: check.rule.exponent,
        attested_at_ms: ee.issued_at,
    };
    Some(SignedSpendAttestation::sign(
        attestation,
        decision_point_key,
    ))
}

/// `SHA-256(ExpectedExecution::signing_preimage())` — the digest a
/// [`SpendAttestation`] binds to. The preimage excludes the signature, so the
/// digest names exactly the signed content.
pub fn expectation_digest(ee: &ExpectedExecution) -> [u8; 32] {
    sha256(&ee.signing_preimage())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each outcome maps to exactly one of: refusal terms, a verdict, or
    /// neither (not governed). No outcome both refuses and authorises.
    #[test]
    fn every_outcome_maps_to_exactly_one_record_kind() {
        let cases = [
            (SpendOutcome::NotGoverned, None, None),
            (
                SpendOutcome::Within {
                    amount: 1,
                    limit: 2,
                },
                None,
                Some(SpendVerdict::Within),
            ),
            (
                SpendOutcome::ApprovalRequired {
                    amount: 2,
                    limit: 3,
                    threshold: 1,
                },
                None,
                Some(SpendVerdict::ApprovalRequired),
            ),
            (
                SpendOutcome::Exceeded {
                    amount: 5,
                    limit: 1,
                },
                Some((RefusalReason::LimitExceeded, Some(5))),
                None,
            ),
            (
                SpendOutcome::Unreadable {
                    reason: Unreadable::Missing,
                    limit: 1,
                },
                Some((RefusalReason::AmountMissing, None)),
                None,
            ),
            (
                SpendOutcome::Unreadable {
                    reason: Unreadable::NotDecimal,
                    limit: 1,
                },
                Some((RefusalReason::AmountNotDecimal, None)),
                None,
            ),
            (
                SpendOutcome::Unreadable {
                    reason: Unreadable::OutOfRange,
                    limit: 1,
                },
                Some((RefusalReason::AmountOutOfRange, None)),
                None,
            ),
        ];
        for (outcome, refusal, attest) in cases {
            assert_eq!(refusal_terms(outcome), refusal, "{outcome:?}");
            assert_eq!(verdict(outcome), attest, "{outcome:?}");
            assert_eq!(outcome.refuses(), refusal.is_some(), "{outcome:?}");
        }
    }
}
