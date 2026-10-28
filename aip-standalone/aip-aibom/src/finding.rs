//! Findings: the evidence gaps an assessment reports, each with a fixed
//! priority.
//!
//! Priority is a total function of the finding's kind — an explicit match, no
//! scoring and no arithmetic. It ranks gaps in an *inventory*; it says nothing
//! about the severity of anything an agent did, which is not a question this
//! crate answers.

use crate::model::Component;
use crate::standing::NonEstablishment;
use serde::Serialize;

/// How urgently a gap needs attention. Ordered: `Critical` sorts first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Critical,
    High,
    Medium,
    Info,
}

impl Priority {
    /// Stable label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Info => "INFO",
        }
    }
}

/// Where in an MCP configuration a credential was found inline. The value
/// itself is never carried — there is no field for it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "at", rename_all = "snake_case")]
pub enum SecretLocation {
    Env { name: String },
    Arg { index: usize },
    UrlUserinfo,
    UrlQuery { key: String },
    Header { name: String },
    Command,
}

/// What made the value look like a credential. A heuristic, labelled as one:
/// a secret under an innocuous name with no recognisable prefix is missed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretIndicator {
    CredentialName,
    KnownTokenPrefix,
    UrlUserinfo,
}

/// A kind of evidence gap.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FindingKind {
    /// Evidence offered for a field failed its core verifier.
    EvidenceRejected { reason: String },
    /// Verified evidence positively disagrees with the declaration.
    Contradicted { reason: String },
    /// A credential sits inline in a tool configuration the assessor read.
    SecretInConfig {
        server: String,
        location: SecretLocation,
        indicator: SecretIndicator,
    },
    /// The manifest's seal did not verify.
    SealRejected { reason: String },
    /// A verified approval artifact shows the human was shown something other
    /// than what was authorised. Signature arithmetic, not inference.
    ApprovalDiverged { divergence: String },
    /// A verified access ledger's own standing for a resource the agent
    /// reached is `Adverse`: a cited reconciliation verdict is adverse.
    AdverseAccess { resource: String },
    /// The agent holds verified, live authority its manifest does not declare.
    UndeclaredAuthority { action: String },
    /// A tool the assessor discovered is absent from the manifest.
    UndeclaredTool { server: String },
    /// A verified gateway receipt shows the agent calling a tool the manifest
    /// does not declare.
    UndeclaredToolUsed { tool_id: String },
    /// A verified access ledger shows the agent reaching a named resource the
    /// manifest does not declare.
    UndeclaredResourceReached { resource: String },
    /// A declared field rests on authority that has expired or been revoked.
    LapsedAuthority,
    /// A monetary or rate limit no authority artifact carries.
    LimitNotEnforceable,
    /// A verified decision-point refusal: the agent asked to spend beyond its
    /// signed per-action limit, or with an amount that could not be read.
    /// Ranked with undeclared authority: the agent's requests and its
    /// declared envelope disagree, whatever the refusal prevented.
    SpendRefused {
        action: String,
        reason: String,
        requested_minor_units: Option<u64>,
        limit_minor_units: u64,
        currency: String,
        exponent: u8,
    },
    /// A verified decision-point record cites a spend policy other than the
    /// current signed one: the decision point enforced different terms.
    SpendPolicyMismatch {
        cited_revision: u64,
        current_revision: u64,
    },
    /// The decision point marked a decision approval-required and no
    /// approval agreeing with that decision was offered.
    RequiredApprovalNotEvidenced { decision_id: String },
    /// The limit is signed; no verified decision-point record shows it being
    /// enforced.
    SpendEnforcementNotEvidenced,
    /// A human-approval requirement with no evidence that approvals occur.
    ApprovalGateNotEvidenced,
    /// Approvals were verified and agree with what was authorised, but that
    /// every action above the threshold was approved is not establishable: an
    /// expectation carries a parameter digest, not an amount.
    ApprovalGateNotEnforceable { approvals: usize },
    /// An approval artifact was offered and could not be compared.
    ApprovalNotEvaluated { reason: String },
    /// A verified gateway refused calls the agent made to this tool.
    GatewayRefusals { tool_id: String, count: usize },
    /// A verified access ledger shows endpoints the institution's registry
    /// never named. A question for the infrastructure owner first.
    UnregisteredEndpointReached { count: usize },
    /// A security control claimed and not evidenced.
    ControlNotEvidenced,
    /// A declared permission no offered authority grants.
    PermissionNotBacked,
    /// The agent's identifier is an AIP-ID, but no identity document backs it.
    NoIdentityEvidence,
    /// The agent's identifier is not a cryptographic identity at all.
    NotACryptographicIdentity,
    /// The identity document carries an expiry outside its self-signed bytes.
    UnsignedIdentityExpiry,
    /// The manifest's own validity window excludes the present.
    ManifestLapsed,
    /// A principal in a verified chain is absent from `delegated_from`.
    UndeclaredDelegator { issuer: String },
    /// A declared MCP tool was not in any configuration the assessor read.
    DeclaredToolNotFound,
    /// Verified authority that never expires.
    UnboundedAuthority,
    /// The manifest has no expiry.
    ManifestNeverExpires,
    /// The manifest is not sealed by any publisher.
    NotSealed,
    /// An executable was authorised or observed, and the manifest declares none.
    UndeclaredBinary,
    /// NEXORA proofs were offered and the assessor supplied no verifier anchors.
    ProofsNotEvaluated { count: usize },
    /// Artifacts about other agents were offered and ignored.
    ForeignEvidence { count: usize },
    /// A field no mechanism can establish.
    Unknowable { non_establishment: NonEstablishment },
}

impl FindingKind {
    /// The fixed priority of this kind of gap.
    pub fn priority(&self) -> Priority {
        use FindingKind::*;
        match self {
            EvidenceRejected { .. }
            | Contradicted { .. }
            | SecretInConfig { .. }
            | SealRejected { .. }
            | ApprovalDiverged { .. }
            | AdverseAccess { .. } => Priority::Critical,
            UndeclaredAuthority { .. }
            | UndeclaredTool { .. }
            | UndeclaredToolUsed { .. }
            | UndeclaredResourceReached { .. }
            | LapsedAuthority
            | LimitNotEnforceable
            | SpendRefused { .. }
            | SpendPolicyMismatch { .. }
            | RequiredApprovalNotEvidenced { .. }
            | ApprovalGateNotEvidenced
            | ControlNotEvidenced
            | NoIdentityEvidence
            | NotACryptographicIdentity
            | ManifestLapsed => Priority::High,
            PermissionNotBacked
            | UndeclaredDelegator { .. }
            | DeclaredToolNotFound
            | UnboundedAuthority
            | ManifestNeverExpires
            | NotSealed
            | UndeclaredBinary
            | UnsignedIdentityExpiry
            | ApprovalGateNotEnforceable { .. }
            | SpendEnforcementNotEvidenced
            | ApprovalNotEvaluated { .. }
            | GatewayRefusals { .. }
            | UnregisteredEndpointReached { .. }
            | ProofsNotEvaluated { .. } => Priority::Medium,
            ForeignEvidence { .. } | Unknowable { .. } => Priority::Info,
        }
    }

    /// One sentence, in stable terms. Never contains a secret: the kinds that
    /// concern secrets carry none.
    pub fn message(&self) -> String {
        use FindingKind::*;
        match self {
            EvidenceRejected { reason } => format!("evidence failed verification: {reason}"),
            Contradicted { reason } => format!("verified evidence contradicts the manifest: {reason}"),
            SecretInConfig { server, location, indicator } => format!(
                "credential inline in MCP server '{server}' at {location:?} ({indicator:?}); value withheld"
            ),
            SealRejected { reason } => format!("manifest seal rejected: {reason}"),
            ApprovalDiverged { divergence } => format!(
                "the human approver was shown something other than what was authorised ({divergence})"
            ),
            AdverseAccess { resource } => format!(
                "the signed access ledger's standing for {resource} is Adverse: a cited reconciliation verdict is adverse"
            ),
            UndeclaredToolUsed { tool_id } => format!(
                "a verified gateway receipt shows the agent calling '{tool_id}', which the manifest does not declare"
            ),
            UndeclaredResourceReached { resource } => format!(
                "the signed access ledger shows the agent reaching {resource}, which the manifest does not declare"
            ),
            ApprovalGateNotEnforceable { approvals } => format!(
                "{approvals} approval(s) verified as agreeing with what was authorised; that every action above the threshold was approved is not establishable"
            ),
            ApprovalNotEvaluated { reason } => format!("approval artifact could not be compared: {reason}"),
            GatewayRefusals { tool_id, count } => format!(
                "the gateway refused {count} call(s) the agent made to '{tool_id}'"
            ),
            UnregisteredEndpointReached { count } => format!(
                "the signed access ledger shows {count} endpoint(s) the institution's registry does not name"
            ),
            UndeclaredAuthority { action } => format!(
                "the agent holds live verified authority for {action}, which the manifest does not declare"
            ),
            UndeclaredTool { server } => format!(
                "MCP server '{server}' is configured for the agent and absent from the manifest"
            ),
            LapsedAuthority => "declared on authority that has expired or been revoked".into(),
            LimitNotEnforceable => "no signed spend policy carries this limit; enforcement, if any, happens where this assessment cannot see".into(),
            SpendRefused { action, reason, requested_minor_units, limit_minor_units, currency, exponent } => match requested_minor_units {
                Some(n) => format!(
                    "the decision point refused {action} for {n} minor units ({currency}, exponent {exponent}) against a per-action limit of {limit_minor_units} ({reason})"
                ),
                None => format!(
                    "the decision point refused {action}: the amount could not be read ({reason}); limit {limit_minor_units} minor units ({currency}, exponent {exponent})"
                ),
            },
            SpendPolicyMismatch { cited_revision, current_revision } => format!(
                "the decision point enforced spend policy revision {cited_revision}, not the current signed revision {current_revision}"
            ),
            RequiredApprovalNotEvidenced { decision_id } => format!(
                "decision {decision_id} was authorised on condition of human approval and no agreeing approval was offered"
            ),
            SpendEnforcementNotEvidenced => "the limit is signed by the institution; no verified decision-point record shows it enforced".into(),
            ApprovalGateNotEvidenced => "no evidence that approvals above this threshold occur".into(),
            ControlNotEvidenced => "security control claimed; nothing here can establish it exists".into(),
            PermissionNotBacked => "declared permission is not granted by any authority offered".into(),
            NoIdentityEvidence => "the agent's AIP-ID is declared and no identity document backs it".into(),
            NotACryptographicIdentity => "the agent's identifier is not a cryptographic identity".into(),
            UnsignedIdentityExpiry => "the identity document's expiry is not covered by its self-signature and was not relied on".into(),
            ManifestLapsed => "the manifest's validity window excludes the present".into(),
            UndeclaredDelegator { issuer } => format!(
                "{issuer} issued authority in a verified chain and is not declared in delegated_from"
            ),
            DeclaredToolNotFound => "declared MCP tool not found in any configuration read".into(),
            UnboundedAuthority => "verified authority with no expiry at any link".into(),
            ManifestNeverExpires => "the manifest has no expiry and will age silently".into(),
            NotSealed => "the manifest is not sealed; nobody has put their name to it".into(),
            UndeclaredBinary => "an executable was authorised or observed and the manifest declares none".into(),
            ProofsNotEvaluated { count } => format!(
                "{count} NEXORA proof(s) offered; the assessor supplied no verifier anchors, so none was evaluated"
            ),
            ForeignEvidence { count } => format!("{count} artifact(s) concern other agents and were ignored"),
            Unknowable { non_establishment } => format!(
                "{}: {}",
                non_establishment.code(),
                non_establishment.statement()
            ),
        }
    }
}

/// One gap, located.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub priority: Priority,
    pub component: Component,
    /// A manifest path (`$.…`) or a bundle path (`bundle.…`).
    pub path: String,
    pub kind: FindingKind,
    pub message: String,
}

impl Finding {
    /// Build a finding; priority and message follow from the kind.
    pub fn new(component: Component, path: impl Into<String>, kind: FindingKind) -> Self {
        Self {
            priority: kind.priority(),
            component,
            path: path.into(),
            message: kind.message(),
            kind,
        }
    }

    /// Deterministic report order.
    pub fn sort_key(&self) -> (Priority, Component, String, FindingKind) {
        (
            self.priority,
            self.component,
            self.path.clone(),
            self.kind.clone(),
        )
    }
}
