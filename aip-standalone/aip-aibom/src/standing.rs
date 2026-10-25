//! Standing: what an assessment found to back one field.
//!
//! **Output only.** Every type here is `Serialize` and none is `Deserialize`.
//! A standing is computed by `crate::assess` from evidence a core verifier
//! accepted; one read back from bytes would be one an author could write
//! (ADR-017, decision 4).
//!
//! There is no `Assumed`, `Trusted`, `Compliant` or `Mitigated`. The way to
//! guarantee a report never overclaims is to leave its vocabulary no word to
//! do it with — the rule `aip-conformance` applies to `Waived` and
//! `Mitigated`.

use aip_reconcile::{EvidenceStrength, ReconciliationResult};
use serde::Serialize;

/// Which existing core verifier accepted the evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verifier {
    /// `aip_core::validate_aid`: the document derives to its own AIP-ID, and
    /// its required self-signature over identity, key, provenance and
    /// lifecycle status verifies.
    ///
    /// **Self-certifying**, so it needs no anchor from the assessor — and
    /// establishes correspondingly little: that this id is bound to this key.
    /// Not who holds the key, and not that the owner named in the manifest
    /// is the party in control.
    IdentityDocument,
    /// `aip_core::validate_aid_with_parent`.
    IdentityLineage,
    /// `aip_core::delegation::verify_delegation_chain`.
    DelegationChain,
    /// `aip_authorize::verify_expected_execution`.
    DecisionPoint,
    /// `aip_airi::verify_tool_receipt`: the institution's gateway, not the
    /// agent, signed that it received a call for this tool from this agent.
    /// Says what the gateway received, never that the effect landed.
    ToolGateway,
    /// `aip_ledger::AccessLedger::verify`: a signed ledger, built from
    /// attested observation and the institution's signed registry, records
    /// the agent reaching this resource. Says nothing about read or write.
    AccessLedger,
}

/// A limit recorded in `docs/architecture/AIRI_LIMITATIONS.md` that no
/// evidence can discharge. Cited, not restated: `tests/no_second_architecture`
/// checks each statement against that file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum NonEstablishment {
    #[serde(rename = "N-2")]
    N2,
    #[serde(rename = "N-3")]
    N3,
    #[serde(rename = "N-4")]
    N4,
    #[serde(rename = "N-10")]
    N10,
}

impl NonEstablishment {
    /// The identifier used in `AIRI_LIMITATIONS.md`.
    pub fn code(self) -> &'static str {
        match self {
            Self::N2 => "N-2",
            Self::N3 => "N-3",
            Self::N4 => "N-4",
            Self::N10 => "N-10",
        }
    }

    /// What cannot be established, verbatim from `AIRI_LIMITATIONS.md`.
    pub fn statement(self) -> &'static str {
        match self {
            Self::N2 => "That a claimed external effect landed",
            Self::N3 => "That a provider served the model requested",
            Self::N4 => "That specific weights were loaded",
            Self::N10 => "Any post-quantum property",
        }
    }
}

/// Why verified authority is not live at the assessor's present time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "lapse", rename_all = "snake_case")]
pub enum Lapse {
    /// An artifact in the chain, or the manifest itself, carried this signed
    /// expiry and the present is past it.
    Expired { valid_until_ms: u64 },
    /// The present is before the latest issuance in the chain.
    NotYetValid { valid_from_ms: u64 },
    /// A token in the chain appears in the assessor's revocation set.
    Revoked,
    /// The identity document's signed lifecycle status is not `Active`.
    IdentityNotActive { status: String },
}

/// Where a discovery came from: what kind of source, which file, and the
/// SHA-256 of the exact bytes the assessor read.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct SourceRef {
    pub kind: SourceKind,
    pub path: String,
    pub sha256: String,
}

/// A kind of discovery source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    McpClientConfig,
}

/// What backs one field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "standing", rename_all = "snake_case")]
pub enum Standing {
    /// A core verifier accepted a carried artifact, and that artifact supports
    /// the field as declared. Says the authority or identity is genuine — not
    /// that the agent used only that.
    Verified { verifier: Verifier },
    /// NEXORA accepted a proof whose re-derived identity comparison matched.
    /// `verdict` and `strength` are NEXORA's, read verbatim and never raised.
    Observed {
        verdict: ReconciliationResult,
        strength: EvidenceStrength,
    },
    /// Found by a discovery the assessor itself ran. Not verified.
    Discovered { source: SourceRef },
    /// The manifest author's word, and nothing else.
    SelfReported,
    /// No mechanism this system has can establish it.
    Unknowable { non_establishment: NonEstablishment },
    /// Verified, and not live at the assessor's present time.
    Lapsed { lapse: Lapse },
    /// Verified evidence that positively disagrees with the declaration.
    /// Absence of supporting evidence is never a contradiction.
    Contradicted { reason: String },
    /// Evidence offered for this field failed its core verifier.
    EvidenceRejected { reason: String },
}

impl Standing {
    /// Precedence when several artifacts bear on one field. Higher wins.
    ///
    /// Fail-closed at the top: a rejected artifact is never outvoted by a
    /// valid one, and a contradiction is never outvoted by a corroboration.
    ///
    /// `Lapsed` sits *below* `Verified`, deliberately. Two grants are two
    /// independent facts, not two accounts of one: an expired grant beside a
    /// live one is no evidence against the live one, and one live grant is
    /// enough to establish the field.
    ///
    /// `Unknowable` is assigned by field type and never competes; it ranks
    /// lowest so that combining it with anything cannot hide the other value.
    pub fn precedence(&self) -> u8 {
        match self {
            Self::Unknowable { .. } => 0,
            Self::SelfReported => 1,
            Self::Discovered { .. } => 2,
            Self::Lapsed { .. } => 3,
            Self::Verified { .. } => 4,
            Self::Observed { .. } => 5,
            Self::Contradicted { .. } => 6,
            Self::EvidenceRejected { .. } => 7,
        }
    }

    /// True for the two standings an independent party produced.
    pub fn is_independent(&self) -> bool {
        matches!(self, Self::Verified { .. } | Self::Observed { .. })
    }

    /// Stable label for tables.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Verified { .. } => "VERIFIED",
            Self::Observed { .. } => "OBSERVED",
            Self::Discovered { .. } => "DISCOVERED",
            Self::SelfReported => "SELF-REPORTED",
            Self::Unknowable { .. } => "UNKNOWABLE",
            Self::Lapsed { .. } => "LAPSED",
            Self::Contradicted { .. } => "CONTRADICTED",
            Self::EvidenceRejected { .. } => "EVIDENCE-REJECTED",
        }
    }

    /// One-line explanation, in stable terms.
    pub fn detail(&self) -> String {
        match self {
            Self::Verified { verifier } => format!("accepted by {verifier:?}"),
            Self::Observed { verdict, strength } => format!(
                "NEXORA re-derived {} at {strength:?} with the instance matched",
                verdict.as_str()
            ),
            Self::Discovered { source } => format!("found in {}", source.path),
            Self::SelfReported => "the manifest author's word only".into(),
            Self::Unknowable { non_establishment } => format!(
                "{}: {}",
                non_establishment.code(),
                non_establishment.statement()
            ),
            Self::Lapsed { lapse } => format!("{lapse:?}"),
            Self::Contradicted { reason } | Self::EvidenceRejected { reason } => reason.clone(),
        }
    }
}

/// Combine every standing that bears on one field. Fail-closed by
/// [`Standing::precedence`]; ties keep the earliest, so the result is a pure
/// function of the order evidence was supplied in.
pub fn combine(candidates: impl IntoIterator<Item = Standing>) -> Standing {
    let mut best = Standing::SelfReported;
    for c in candidates {
        if c.precedence() > best.precedence() {
            best = c;
        }
    }
    best
}
