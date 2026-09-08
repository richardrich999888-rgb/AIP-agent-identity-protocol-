//! The universal invariant set.
//!
//! Twelve invariants, the twelve the specification names. Each carries a
//! stable code so an emitted matrix is diffable, a statement of what it
//! requires, and — the part that matters most — the boundary at which it
//! stops. An invariant without a stated boundary invites the reader to
//! assume it covers more than it does.

use serde::{Deserialize, Serialize};

/// Stable identifier for one universal invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum InvariantCode {
    Identity,
    Authority,
    ExpectedExecution,
    ExecutionBinding,
    AiriClaim,
    Observation,
    Attribution,
    Continuity,
    Reconciliation,
    Warrant,
    Containment,
    Proof,
}

/// One invariant, as it is written into the artifact. `Serialize` only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Invariant {
    pub code: InvariantCode,
    /// `I01` … `I12`. Stable across reorderings.
    pub id: &'static str,
    /// What a conforming domain must do.
    pub requires: &'static str,
    /// Where the invariant stops. Never omitted.
    pub stops_at: &'static str,
}

impl InvariantCode {
    pub const ALL: [InvariantCode; 12] = [
        Self::Identity,
        Self::Authority,
        Self::ExpectedExecution,
        Self::ExecutionBinding,
        Self::AiriClaim,
        Self::Observation,
        Self::Attribution,
        Self::Continuity,
        Self::Reconciliation,
        Self::Warrant,
        Self::Containment,
        Self::Proof,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Self::Identity => "I01",
            Self::Authority => "I02",
            Self::ExpectedExecution => "I03",
            Self::ExecutionBinding => "I04",
            Self::AiriClaim => "I05",
            Self::Observation => "I06",
            Self::Attribution => "I07",
            Self::Continuity => "I08",
            Self::Reconciliation => "I09",
            Self::Warrant => "I10",
            Self::Containment => "I11",
            Self::Proof => "I12",
        }
    }

    pub fn describe(self) -> Invariant {
        let (requires, stops_at) = match self {
            Self::Identity => (
                "an AIP-ID is derived from a key and provenance and validates; a malformed id is refused rather than panicking a consumer",
                "says nothing about who holds the key",
            ),
            Self::Authority => (
                "a delegation chain verifies under the verifier's own issuer anchors, and a parent-child relation confers nothing by itself",
                "says nothing about whether the authority should have been granted",
            ),
            Self::ExpectedExecution => (
                "an expectation is decision-point signed, its expiry is inside the signature, and the agent may not be its own decision point",
                "is never evidence that anything executed",
            ),
            Self::ExecutionBinding => (
                "execution identity is the process instance and the executable's content, not a PID; a binding does not transplant to another host or execution",
                "says nothing about what the process did",
            ),
            Self::AiriClaim => (
                "a framework event is a claim bound to an agent and an execution, and no framework name grants anything",
                "a claim is never independent observation",
            ),
            Self::Observation => (
                "an observation carries its class, and a class's evidence ceiling is declared rather than computed from the record",
                "a profile may not raise a ceiling",
            ),
            Self::Attribution => (
                "an effect is attributed only through an attested, authentic, in-scope complete expected side",
                "insufficient evidence is CANNOT_PROVE, never an accusation",
            ),
            Self::Continuity => (
                "a gap, fork, rollback or replay in the observer's own record is explicit and sticky",
                "later well-formed traffic never erases a recorded gap",
            ),
            Self::Reconciliation => (
                "one engine draws every verdict and CANNOT_PROVE is the default",
                "strength is fixed by result kind, never by severity or a score",
            ),
            Self::Warrant => (
                "a warrant is a decision boundary; containment is never granted to CANNOT_PROVE, nor automatically to Attested",
                "a warrant is permission to act on proof, not proof",
            ),
            Self::Containment => (
                "containment consumes an independently produced warrant and manufactures no evidence",
                "fails closed; an actuation error does not become a verdict",
            ),
            Self::Proof => (
                "a proof package is re-derived by the verifier and never trusted on its own word; a refused package establishes nothing",
                "NEXORA is provenance and continuity, not authority",
            ),
        };
        Invariant {
            code: self,
            id: self.id(),
            requires,
            stops_at,
        }
    }
}
