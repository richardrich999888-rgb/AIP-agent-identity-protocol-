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
    /// R16 — nothing in the packet is dated after the verification time the
    /// *verifier* supplied. Recorded as not evaluated when the verifier
    /// supplied none; never as a pass (AUDIT P0-1).
    pub const VERIFICATION_TIME_BOUND: &str = "VERIFICATION_TIME_BOUND";
    /// R17 — no two action attestations inside one packet share an
    /// `action_id`. Always evaluable: it is a property of the packet alone
    /// (AUDIT B-8).
    pub const ACTION_UNIQUENESS: &str = "ACTION_UNIQUENESS";
    /// R18 — this packet does not reuse a decision or action identity that a
    /// *different* packet already established. Requires the verifier to
    /// supply what it has observed; recorded as not evaluated when it does
    /// not, never as a pass (AUDIT B-8).
    pub const REPLAY_SCOPE: &str = "REPLAY_SCOPE";
}

/// Outcome of one verification rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleResult {
    pub rule: String,
    pub pass: bool,
    pub detail: String,
    /// Whether the rule was actually evaluated. A rule the verifier could
    /// not run — because the input it needs was not supplied — is recorded
    /// with `evaluated: false` and never counted as a pass. Defaults to
    /// true so reports written before this field existed still parse.
    #[serde(default = "default_true")]
    pub evaluated: bool,
}

fn default_true() -> bool {
    true
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
    /// Unix ms when verification ran. Read from the local clock and used
    /// for nothing but this field — it is not a bound (see
    /// `verification_time_ms`).
    pub verified_at: u64,
    /// The verification time the *verifier* supplied, if any. When present,
    /// nothing in the packet may be dated after it.
    #[serde(default)]
    pub verification_time_ms: Option<u64>,
    /// Whether the verification-time bound was evaluated at all. False
    /// means the verifier supplied no time; it does not mean the packet
    /// passed the bound (AUDIT P0-1).
    #[serde(default)]
    pub verification_time_checked: bool,

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
        self.checks
            .iter()
            .filter(|c| c.evaluated && !c.pass)
            .collect()
    }

    /// Rules the verifier declined to run because it was not given what
    /// they need. Neither passes nor failures — a consumer that requires
    /// one of them must look here rather than at `valid` (AUDIT P0-1).
    pub fn not_evaluated(&self) -> Vec<&RuleResult> {
        self.checks.iter().filter(|c| !c.evaluated).collect()
    }

    /// Look up a specific rule's result by its stable identifier.
    pub fn rule(&self, rule: &str) -> Option<&RuleResult> {
        self.checks.iter().find(|c| c.rule == rule)
    }
}
