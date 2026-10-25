//! Pure evaluation of one request against a verified policy.
//!
//! No clock, no IO, no key. The decision point calls this with a lookup into
//! the request's own parameters — the same bytes the expectation will seal —
//! and acts on the answer.

use crate::limits::MAX_AMOUNT_DIGITS;
use crate::policy::{SpendRule, VerifiedSpendPolicy};
use aip_types::ScopeAction;

/// Why an amount could not be read. Every case is refused by the decision
/// point: an amount that cannot be read is not read permissively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreadable {
    /// The governed parameter is absent from the request.
    Missing,
    /// Not a run of ASCII digits: a sign, a decimal point, whitespace, an
    /// empty value, or anything else.
    NotDecimal,
    /// More digits than any `u64` has, or a value that overflows one.
    OutOfRange,
}

/// What the policy says about one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendOutcome {
    /// The policy governs a different agent, or has no rule for this action.
    NotGoverned,
    Within {
        amount: u64,
        limit: u64,
    },
    /// Within the maximum and above the approval threshold.
    ApprovalRequired {
        amount: u64,
        limit: u64,
        threshold: u64,
    },
    Exceeded {
        amount: u64,
        limit: u64,
    },
    Unreadable {
        reason: Unreadable,
        limit: u64,
    },
}

impl SpendOutcome {
    /// True for the outcomes the decision point refuses.
    pub fn refuses(&self) -> bool {
        matches!(self, Self::Exceeded { .. } | Self::Unreadable { .. })
    }
}

/// Parse ASCII decimal minor units. Strict: digits only, at most
/// [`MAX_AMOUNT_DIGITS`], no overflow.
pub fn parse_amount(bytes: &[u8]) -> Result<u64, Unreadable> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(Unreadable::NotDecimal);
    }
    if bytes.len() > MAX_AMOUNT_DIGITS {
        return Err(Unreadable::OutOfRange);
    }
    bytes.iter().try_fold(0u64, |acc, d| {
        acc.checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(d - b'0')))
            .ok_or(Unreadable::OutOfRange)
    })
}

/// Classify an amount against a rule. Boundaries are inclusive: an amount
/// equal to the maximum is within it, and one equal to the threshold does
/// not yet need approval — "above $500" means more than $500.
pub fn classify(rule: &SpendRule, amount: u64) -> SpendOutcome {
    let limit = rule.max_per_action;
    if amount > limit {
        return SpendOutcome::Exceeded { amount, limit };
    }
    match rule.approval_above {
        Some(threshold) if amount > threshold => SpendOutcome::ApprovalRequired {
            amount,
            limit,
            threshold,
        },
        _ => SpendOutcome::Within { amount, limit },
    }
}

/// Evaluate a request by `agent_id` for `action` whose parameters are read
/// through `param`.
pub fn evaluate<'p>(
    policy: &VerifiedSpendPolicy,
    agent_id: &str,
    action: &ScopeAction,
    param: impl Fn(&str) -> Option<&'p [u8]>,
) -> SpendOutcome {
    if policy.policy().agent_id != agent_id {
        return SpendOutcome::NotGoverned;
    }
    let Some(rule) = policy.rule_for(action) else {
        return SpendOutcome::NotGoverned;
    };
    let limit = rule.max_per_action;
    match param(&rule.amount_parameter) {
        None => SpendOutcome::Unreadable {
            reason: Unreadable::Missing,
            limit,
        },
        Some(bytes) => match parse_amount(bytes) {
            Ok(amount) => classify(rule, amount),
            Err(reason) => SpendOutcome::Unreadable { reason, limit },
        },
    }
}
