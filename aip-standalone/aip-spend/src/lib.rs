//! # Spend authority
//!
//! Makes a spending limit a signed, enforced, provable control instead of a
//! line in somebody's inventory (ADR-018).
//!
//! - [`policy`]: the institution-signed [`SpendPolicy`] — per agent, per
//!   action, a maximum and an approval threshold, in integer minor units.
//! - [`evaluate`]: a pure function of a verified policy and a request's own
//!   parameters. No clock, no IO, no key.
//! - [`record`]: what the decision point signs about each decision — a
//!   [`SpendAttestation`] when it authorises, a [`SpendRefusal`] when it
//!   refuses.
//!
//! The decision point in `aip-authorize` enforces the policy and signs the
//! records. This crate decides nothing and holds no decision-point key.

pub mod evaluate;
pub mod limits;
pub mod policy;
pub mod record;

pub use evaluate::{classify, evaluate, parse_amount, SpendOutcome, Unreadable};
pub use policy::{
    SignedSpendPolicy, SpendError, SpendPolicy, SpendPolicyAnchors, SpendRule, VerifiedSpendPolicy,
    SPEND_POLICY_VERSION,
};
pub use record::{
    DecisionPointKeys, PolicyCitation, RecordError, RefusalReason, SignedSpendAttestation,
    SignedSpendRefusal, SpendAttestation, SpendRefusal, SpendVerdict, SPEND_RECORD_VERSION,
};
