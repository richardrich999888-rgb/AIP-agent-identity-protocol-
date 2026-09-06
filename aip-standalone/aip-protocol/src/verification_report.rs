//! Structured verification results.
//!
//! Every check the engine runs is recorded as a [`RuleResult`] — there are
//! no silent checks and no hardcoded passes. `valid` is true iff every rule
//! passed; `tampered` is true iff at least one failure is positive evidence
//! of post-signing modification (hash or signature-payload mismatch), as
//! opposed to e.g. a revoked token, which makes a packet invalid but not
//! tampered.

use serde::{Deserialize, Serialize};

use crate::evidence_packet::TrustFloor;

/// Stable rule identifiers — referenced by tests, the spec, and consumers.
pub mod rules {
    pub const STRUCTURE: &str = "STRUCTURE";
    pub const AGENT_ID_BINDING: &str = "AGENT_ID_BINDING";
    pub const CANONICAL_HASH: &str = "CANONICAL_HASH";
    pub const AGENT_SIGNATURE: &str = "AGENT_SIGNATURE";
    pub const ROOT_TOKEN_SIGNATURE: &str = "ROOT_TOKEN_SIGNATURE";
    pub const DELEGATION_CHAIN: &str = "DELEGATION_CHAIN";
    pub const AUTHORITY_CHAIN: &str = "AUTHORITY_CHAIN";
    pub const SCOPE_AUTHORITY: &str = "SCOPE_AUTHORITY";
    pub const REVOCATION: &str = "REVOCATION";
    pub const TEMPORAL_VALIDITY: &str = "TEMPORAL_VALIDITY";
    pub const ACTION_ATTESTATIONS: &str = "ACTION_ATTESTATIONS";
    pub const TRACE_BINDING: &str = "TRACE_BINDING";
    pub const RECEIPT_BINDING: &str = "RECEIPT_BINDING";
    pub const TRUST_FLOOR: &str = "TRUST_FLOOR";
    /// R15 — structural/consistency check of the (self-reported) execution
    /// binding, when present. Passing this rule never means the execution
    /// was independently observed.
    pub const EXECUTION_BINDING: &str = "EXECUTION_BINDING";
}

/// Outcome of one verification rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleResult {
    pub rule: String,
    pub pass: bool,
    pub detail: String,
}

/// The verification engine's full output for one EvidencePacket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    /// True iff every verification rule passed.
    pub valid: bool,
    /// The trust floor *derived* by the verifier from the evidence.
    pub trust_floor: TrustFloor,
    /// The floor the packet producer claimed.
    pub claimed_trust_floor: TrustFloor,
    /// True iff a failure is positive evidence of post-signing modification.
    pub tampered: bool,

    pub authority_chain_verified: bool,
    pub delegation_chain_verified: bool,
    pub scope_verified: bool,
    pub receipt_verified: bool,
    pub trace_verified: bool,
    pub revocation_clear: bool,

    /// Hex packet ID this report refers to.
    pub packet_id: String,
    /// AIP-ID of the acting agent.
    pub agent_id: String,
    /// Unix ms when verification ran.
    pub verified_at: u64,

    /// Every rule that was evaluated, in order, with pass/fail and detail.
    pub checks: Vec<RuleResult>,
}

impl VerificationReport {
    /// Export as pretty-printed JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// All failed rules (empty when `valid`).
    pub fn failures(&self) -> Vec<&RuleResult> {
        self.checks.iter().filter(|c| !c.pass).collect()
    }

    /// Look up a specific rule's result by its stable identifier.
    pub fn rule(&self, rule: &str) -> Option<&RuleResult> {
        self.checks.iter().find(|c| c.rule == rule)
    }
}
