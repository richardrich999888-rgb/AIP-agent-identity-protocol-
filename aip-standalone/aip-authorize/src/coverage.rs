//! Expected-side completeness: the decision point's signed statement of
//! *every* decision it issued for an agent over a window.
//!
//! This is the only object that can turn "no expectation found" into "no
//! expectation exists". Database absence never can: a missing row says
//! nothing about whether a decision was issued elsewhere, lost, or withheld.
//! The reconciler (`aip-reconcile`) refuses to name `UNATTRIBUTED_EFFECT`
//! without one of these, verified against decision-point anchors the
//! verifier supplies.
//!
//! # Where the list comes from
//!
//! The statement is **computed, never supplied**. A producer that signed a
//! caller-provided list would be a forgery oracle: the caller could omit a
//! decision and have the decision point swear to its absence. Instead the
//! decision point keeps a [`DecisionLedger`] of every expectation it signed
//! and derives the list from it. The caller chooses only the agent, the
//! window and the issue time; the decision point refuses windows it cannot
//! vouch for (before its ledger began, or not yet closed at issue time).
//!
//! # What a statement does not say
//!
//! It says nothing about execution. It does not say the agent acted or did
//! not act; it says which decisions *this* decision point issued. A verifier
//! that trusts several decision points needs a statement from each.

use std::collections::HashMap;

use aip_crypto::{sha256, verify_ed25519};
use aip_types::canonical::*;
use aip_types::{CoverageWindow, Signature};
use serde::{Deserialize, Serialize};

use crate::expected::DecisionPointTrustAnchors;

/// Domain tag of a decision point's expected-side completeness statement.
/// Fixed since the consumer contract was written; unchanged by the producer.
pub const DECISION_POINT_COVERAGE_DOMAIN: &str = "GHOST/DecisionPointCoverage/v1";
pub const DECISION_POINT_COVERAGE_VERSION: u16 = 1;

/// A decision point's signed statement of every decision it issued for an
/// agent whose validity window intersects `window`. Produced by
/// [`crate::DecisionPoint::coverage_statement`]; verified offline with
/// [`DecisionPointCoverageStatement::verify`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionPointCoverageStatement {
    pub version: u16,
    pub decision_point_id: String,
    pub agent_id: String,
    pub window: CoverageWindow,
    /// Every decision id issued for `agent_id` whose validity window
    /// intersects `window`, sorted ascending by id bytes, no duplicates. May
    /// be empty.
    pub decision_ids: Vec<[u8; 16]>,
    pub issued_at_ms: u64,
    pub signature: Signature,
}

/// Why a statement failed verification. Each is a refusal.
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
    /// The exact bytes hashed into `signature.payload_hash`: domain,
    /// version, both identifiers, the window, the length-prefixed id list,
    /// and the issue time. Injective: every field is fixed-width or
    /// length-prefixed.
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

    /// Verify against the verifier's own decision-point anchors. Checks the
    /// version, the window's shape, that the named decision point is
    /// anchored, that the signature names it, that the payload hash is this
    /// struct's preimage, and the Ed25519 signature — in that order.
    pub fn verify(
        &self,
        anchors: &DecisionPointTrustAnchors,
    ) -> Result<(), CoverageStatementError> {
        if self.version != DECISION_POINT_COVERAGE_VERSION {
            return Err(CoverageStatementError::UnsupportedVersion(self.version));
        }
        if !self.window.is_well_formed() {
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

// ─── Producer side ───

/// Why the decision point refused to issue a statement. Each is a refusal
/// to claim completeness it cannot vouch for; none is a statement about the
/// agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoverageIssueError {
    /// The decision point was built without a ledger epoch
    /// ([`crate::DecisionPoint::with_coverage_ledger`]); it records nothing
    /// it could attest from.
    LedgerNotEnabled,
    /// `agent_id` is empty.
    EmptyAgentId,
    /// `window.to_ms < window.from_ms`.
    InvalidWindow,
    /// The window starts before the ledger's declared epoch: the decision
    /// point cannot vouch for decisions it did not record.
    WindowPrecedesLedger { since_ms: u64 },
    /// `window.to_ms > issued_at_ms`: completeness cannot be claimed for
    /// instants that have not yet passed at issue time.
    WindowNotClosed { issued_at_ms: u64 },
    /// The decision point could not produce its signature.
    SigningFailed(String),
}

impl std::fmt::Display for CoverageIssueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LedgerNotEnabled => write!(f, "decision point has no coverage ledger"),
            Self::EmptyAgentId => write!(f, "agent id is empty"),
            Self::InvalidWindow => write!(f, "window end precedes window start"),
            Self::WindowPrecedesLedger { since_ms } => {
                write!(f, "window starts before the ledger epoch {since_ms}")
            }
            Self::WindowNotClosed { issued_at_ms } => {
                write!(f, "window extends past issue time {issued_at_ms}")
            }
            Self::SigningFailed(e) => write!(f, "signing failed: {e}"),
        }
    }
}

impl std::error::Error for CoverageIssueError {}

/// One issued expectation as the ledger remembers it: enough to answer
/// "does its validity window intersect this one, for this agent?" and
/// nothing more. The full `ExpectedExecution` is the caller's to keep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LedgerEntry {
    pub agent_id: String,
    pub decision_id: [u8; 16],
    /// `ExpectedExecution::issued_at ..= valid_until`, inclusive.
    pub validity: CoverageWindow,
}

/// The decision point's own record of what it signed. In-process and
/// append-only; it starts empty when the decision point is constructed.
///
/// # Restart caveat (operator contract)
///
/// The ledger lives in memory. A restarted decision point holds an empty
/// ledger and **must** be given a fresh `since_ms` no earlier than its
/// restart; declaring an earlier epoch would let it swear to the absence of
/// decisions a previous incarnation issued. This crate cannot check a wall
/// clock deterministically, so the epoch is the operator's assertion,
/// documented here and in `docs/architecture/DECISION_POINT.md`.
#[derive(Debug, Default)]
pub(crate) struct DecisionLedger {
    /// Instant from which the ledger vouches for completeness. `None`
    /// until the operator enables it; no statement can be issued before.
    since_ms: Option<u64>,
    entries: Vec<LedgerEntry>,
    /// agent id → the latest `to_ms` this decision point has attested
    /// completeness for. A decision issued at or before that instant would
    /// falsify an already-signed statement, so it is refused.
    closed_until: HashMap<String, u64>,
}

impl DecisionLedger {
    pub fn enable(&mut self, since_ms: u64) {
        self.since_ms = Some(since_ms);
    }

    pub fn since_ms(&self) -> Option<u64> {
        self.since_ms
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `Some(to_ms)` if a decision for `agent_id` issued at `now_ms` would
    /// contradict a statement already signed for that agent.
    pub fn closed_at(&self, agent_id: &str, now_ms: u64) -> Option<u64> {
        self.closed_until
            .get(agent_id)
            .copied()
            .filter(|&closed| now_ms <= closed)
    }

    pub fn record(&mut self, entry: LedgerEntry) {
        self.entries.push(entry);
    }

    /// Every decision id for `agent_id` whose validity intersects `window`,
    /// sorted ascending and de-duplicated, so two statements over the same
    /// ledger state have byte-identical preimages.
    pub fn decisions_for(&self, agent_id: &str, window: &CoverageWindow) -> Vec<[u8; 16]> {
        let mut ids: Vec<[u8; 16]> = self
            .entries
            .iter()
            .filter(|e| e.agent_id == agent_id && e.validity.intersects(window))
            .map(|e| e.decision_id)
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    /// Mark `[.., to_ms]` as attested for `agent_id`. Monotone: an earlier
    /// `to_ms` never reopens a later one.
    pub fn close(&mut self, agent_id: &str, to_ms: u64) {
        let slot = self.closed_until.entry(agent_id.to_string()).or_insert(0);
        *slot = (*slot).max(to_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(agent: &str, id: u8, from: u64, to: u64) -> LedgerEntry {
        LedgerEntry {
            agent_id: agent.into(),
            decision_id: [id; 16],
            validity: CoverageWindow {
                from_ms: from,
                to_ms: to,
            },
        }
    }

    #[test]
    fn decisions_for_filters_by_agent_and_intersection_and_sorts() {
        let mut l = DecisionLedger::default();
        l.record(entry("a", 9, 100, 200));
        l.record(entry("a", 3, 250, 300)); // disjoint: after the window
        l.record(entry("a", 5, 0, 100)); // touches at from_ms: intersects
        l.record(entry("b", 1, 100, 200)); // other agent
        l.record(entry("a", 9, 150, 160)); // duplicate id
        let w = CoverageWindow {
            from_ms: 100,
            to_ms: 200,
        };
        assert_eq!(l.decisions_for("a", &w), vec![[5; 16], [9; 16]]);
        assert_eq!(l.decisions_for("b", &w), vec![[1; 16]]);
        assert!(l.decisions_for("c", &w).is_empty());
    }

    #[test]
    fn close_is_monotone_and_per_agent() {
        let mut l = DecisionLedger::default();
        l.close("a", 500);
        l.close("a", 400);
        assert_eq!(l.closed_at("a", 500), Some(500));
        assert_eq!(l.closed_at("a", 501), None);
        assert_eq!(l.closed_at("b", 0), None);
    }
}
