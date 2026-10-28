//! What the assessor is given, split by who it trusts.
//!
//! [`EvidenceBundle`] comes from the party being assessed and is **untrusted**:
//! every artifact in it is re-verified by a core verifier before it counts for
//! anything. It has no field for a key, an anchor, a revocation or a clock, so
//! a bundle cannot supply the terms it is judged by.
//!
//! [`AssessorContext`] is the assessor's own and is **trusted**: issuer keys,
//! decision-point anchors, NEXORA verifier anchors, publisher keys, the
//! revocation set and the present time (ADR-017, decision 3).

use crate::model::limits::MAX_ITEMS;
use aip_airi::{GatewayTrustAnchors, SignedToolReceipt};
use aip_approval::{ApprovalSurfaceAnchors, SignedApprovalArtifact};
use aip_authorize::{DecisionPointTrustAnchors, ExpectedExecution};
use aip_ledger::{AccessLedger, LedgerTrustAnchors};
use aip_nexora::{NexoraProof, VerifierAnchors};
use aip_spend::{
    SignedSpendAttestation, SignedSpendPolicy, SignedSpendRefusal, SpendPolicyAnchors,
};
use aip_types::{AgentIdentityDocument, DelegationToken, ScopedToken};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// A root grant and the delegation hops below it, as the core verifies them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityChain {
    pub root: ScopedToken,
    #[serde(default)]
    pub delegations: Vec<DelegationToken>,
}

impl AuthorityChain {
    /// The party the chain ends at. Read from unauthenticated fields, so it is
    /// used only to decide which agent the evidence was *offered* for.
    pub fn holder(&self) -> &str {
        match self.delegations.last() {
            Some(hop) => &hop.grantee_id,
            None => &self.root.agent_id,
        }
    }

    /// Every principal that issued a link in the chain.
    pub fn issuers(&self) -> Vec<&str> {
        let mut v = vec![self.root.issuer_id.as_str()];
        v.extend(self.delegations.iter().map(|h| h.issuer_id.as_str()));
        v
    }

    /// Every token id in the chain, root first.
    pub fn jtis(&self) -> Vec<[u8; 16]> {
        let mut v = vec![self.root.jti];
        v.extend(self.delegations.iter().map(|h| h.jti));
        v
    }

    /// The window over which every link is live: the latest issuance to the
    /// earliest expiry. `None` as the upper bound means no link expires.
    ///
    /// Only meaningful after `verify_delegation_chain` has accepted the chain;
    /// before that, these are unauthenticated numbers.
    pub fn window(&self) -> (u64, Option<u64>) {
        let from = self
            .delegations
            .iter()
            .map(|h| h.issued_at)
            .fold(self.root.issued_at, u64::max);
        let until = std::iter::once(self.root.expires_at)
            .chain(self.delegations.iter().map(|h| h.expires_at))
            .flatten()
            .min();
        (from, until)
    }
}

/// Evidence offered by the assessed party. Untrusted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundle {
    /// The agent's identity document.
    #[serde(default)]
    pub identity: Option<AgentIdentityDocument>,
    /// The identity it claims lineage from.
    #[serde(default)]
    pub parent_identity: Option<AgentIdentityDocument>,
    #[serde(default)]
    pub authority: Vec<AuthorityChain>,
    #[serde(default)]
    pub expectations: Vec<ExpectedExecution>,
    #[serde(default)]
    pub proofs: Vec<NexoraProof>,
    /// Gateway-countersigned receipts for tool calls (C4).
    #[serde(default)]
    pub tool_receipts: Vec<SignedToolReceipt>,
    /// What an approval surface showed a human, per decision (C5).
    #[serde(default)]
    pub approvals: Vec<SignedApprovalArtifact>,
    /// Signed per-agent access ledgers: resources the agent was observed
    /// reaching, as the institution's registry names them (C6).
    #[serde(default)]
    pub access_ledgers: Vec<AccessLedger>,
    /// Institution-signed spend policies for the agent (C5 limits).
    #[serde(default)]
    pub spend_policies: Vec<SignedSpendPolicy>,
    /// Decision-point attestations of authorised, spend-governed decisions.
    #[serde(default)]
    pub spend_attestations: Vec<SignedSpendAttestation>,
    /// Decision-point refusals on spend authority, each with the amount.
    #[serde(default)]
    pub spend_refusals: Vec<SignedSpendRefusal>,
}

/// Why a bundle or context file was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputError {
    Malformed(String),
    TooMany { field: &'static str, max: usize },
    BadHex { field: String },
}

impl std::fmt::Display for InputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for InputError {}

impl EvidenceBundle {
    /// Parse a bundle from JSON and bound its size. Content is verified later,
    /// artifact by artifact, by the core.
    pub fn from_json(bytes: &[u8]) -> Result<Self, InputError> {
        let b: Self =
            serde_json::from_slice(bytes).map_err(|e| InputError::Malformed(e.to_string()))?;
        for (field, n) in [
            ("authority", b.authority.len()),
            ("expectations", b.expectations.len()),
            ("proofs", b.proofs.len()),
            ("tool_receipts", b.tool_receipts.len()),
            ("approvals", b.approvals.len()),
            ("access_ledgers", b.access_ledgers.len()),
            ("spend_policies", b.spend_policies.len()),
            ("spend_attestations", b.spend_attestations.len()),
            ("spend_refusals", b.spend_refusals.len()),
        ] {
            if n > MAX_ITEMS {
                return Err(InputError::TooMany {
                    field,
                    max: MAX_ITEMS,
                });
            }
        }
        Ok(b)
    }
}

/// The assessor's trust inputs. Built by the caller; never deserialised from
/// anything the assessed party supplied.
#[derive(Debug, Clone)]
pub struct AssessorContext {
    /// The assessor's view of now. The engine reads no clock.
    pub present_time_ms: u64,
    /// Issuer public keys by AIP-ID, for delegation chains.
    pub issuer_keys: HashMap<String, Vec<u8>>,
    pub decision_points: DecisionPointTrustAnchors,
    /// `None` means NEXORA proofs are not evaluated, and are reported as such.
    pub nexora: Option<VerifierAnchors>,
    /// Token ids the assessor knows to be revoked.
    pub revoked_jtis: BTreeSet<[u8; 16]>,
    /// Manifest publishers' public keys, for seals.
    pub publishers: BTreeMap<String, Vec<u8>>,
    /// Tool gateways whose receipts the assessor accepts.
    pub gateways: GatewayTrustAnchors,
    /// Approval surfaces whose artifacts the assessor accepts.
    pub approval_surfaces: ApprovalSurfaceAnchors,
    /// Access-ledger signers the assessor accepts.
    pub ledger_signers: LedgerTrustAnchors,
    /// Spend-policy issuers the assessor accepts.
    pub spend_policy_anchors: SpendPolicyAnchors,
    /// The assessed agent's public key, when the assessor knows it. Used to
    /// refuse any gateway, surface or observer anchored under the agent's own
    /// key — a receipt the agent could sign is its self-report under another
    /// name.
    pub agent_public_key: Option<Vec<u8>>,
}

impl AssessorContext {
    /// A context that trusts nothing. Every artifact will fail to verify, and
    /// the report will say so rather than crediting it.
    pub fn trusting_nothing(present_time_ms: u64) -> Self {
        Self {
            present_time_ms,
            issuer_keys: HashMap::new(),
            decision_points: DecisionPointTrustAnchors::new(),
            nexora: None,
            revoked_jtis: BTreeSet::new(),
            publishers: BTreeMap::new(),
            gateways: GatewayTrustAnchors::new(),
            approval_surfaces: ApprovalSurfaceAnchors::new(),
            ledger_signers: LedgerTrustAnchors::new(),
            spend_policy_anchors: SpendPolicyAnchors::new(),
            agent_public_key: None,
        }
    }
}

/// One versioned key in a context file: an observer, a gateway or a ledger
/// signer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionedKey {
    pub id: String,
    pub key_version: u32,
    pub public_key: String,
}

/// The on-disk form of an [`AssessorContext`], written by the assessor.
///
/// Keys are lowercase hex. This is the CLI's input; the library takes an
/// `AssessorContext` and never reads this file itself.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextFile {
    #[serde(default)]
    pub issuers: BTreeMap<String, String>,
    #[serde(default)]
    pub decision_points: BTreeMap<String, String>,
    #[serde(default)]
    pub publishers: BTreeMap<String, String>,
    #[serde(default)]
    pub revoked_jtis: Vec<String>,
    /// Evaluate NEXORA proofs. Requires `observers`.
    #[serde(default)]
    pub evaluate_proofs: bool,
    #[serde(default)]
    pub observers: Vec<VersionedKey>,
    #[serde(default)]
    pub gateways: Vec<VersionedKey>,
    #[serde(default)]
    pub ledger_signers: Vec<VersionedKey>,
    /// Approval surface id → public key.
    #[serde(default)]
    pub approval_surfaces: BTreeMap<String, String>,
    /// Spend-policy issuer id → public key.
    #[serde(default)]
    pub spend_policy_issuers: BTreeMap<String, String>,
    /// The assessed agent's public key, for every independence check.
    #[serde(default)]
    pub agent_public_key: Option<String>,
}

fn decode(field: String, hex_str: &str) -> Result<Vec<u8>, InputError> {
    hex::decode(hex_str).map_err(|_| InputError::BadHex { field })
}

impl ContextFile {
    /// Parse a context file.
    pub fn from_json(bytes: &[u8]) -> Result<Self, InputError> {
        serde_json::from_slice(bytes).map_err(|e| InputError::Malformed(e.to_string()))
    }

    /// Build the assessor context at `present_time_ms`.
    pub fn into_context(self, present_time_ms: u64) -> Result<AssessorContext, InputError> {
        let mut ctx = AssessorContext::trusting_nothing(present_time_ms);
        for (id, k) in &self.issuers {
            ctx.issuer_keys
                .insert(id.clone(), decode(format!("issuers.{id}"), k)?);
        }
        for (id, k) in &self.decision_points {
            let key = decode(format!("decision_points.{id}"), k)?;
            ctx.decision_points = ctx.decision_points.trust(id, &key);
        }
        for (id, k) in &self.publishers {
            ctx.publishers
                .insert(id.clone(), decode(format!("publishers.{id}"), k)?);
        }
        for (i, j) in self.revoked_jtis.iter().enumerate() {
            let bytes = decode(format!("revoked_jtis[{i}]"), j)?;
            let jti: [u8; 16] = bytes.try_into().map_err(|_| InputError::BadHex {
                field: format!("revoked_jtis[{i}]"),
            })?;
            ctx.revoked_jtis.insert(jti);
        }
        for (i, g) in self.gateways.iter().enumerate() {
            let key = decode(format!("gateways[{i}].public_key"), &g.public_key)?;
            ctx.gateways = ctx.gateways.trust(&g.id, g.key_version, &key);
        }
        for (i, l) in self.ledger_signers.iter().enumerate() {
            let key = decode(format!("ledger_signers[{i}].public_key"), &l.public_key)?;
            ctx.ledger_signers = ctx.ledger_signers.trust(&l.id, l.key_version, &key);
        }
        for (id, k) in &self.approval_surfaces {
            let key = decode(format!("approval_surfaces.{id}"), k)?;
            ctx.approval_surfaces = ctx.approval_surfaces.trust(id, &key);
        }
        for (id, k) in &self.spend_policy_issuers {
            let key = decode(format!("spend_policy_issuers.{id}"), k)?;
            ctx.spend_policy_anchors = ctx.spend_policy_anchors.trust(id, &key);
        }
        if let Some(k) = &self.agent_public_key {
            ctx.agent_public_key = Some(decode("agent_public_key".into(), k)?);
        }
        if self.evaluate_proofs {
            let mut observer = aip_observe::ObserverTrustAnchors::new();
            for (i, o) in self.observers.iter().enumerate() {
                let key = decode(format!("observers[{i}].public_key"), &o.public_key)?;
                observer = observer.trust(&o.id, o.key_version, &key);
            }
            let agent_public_key = ctx.agent_public_key.clone();
            ctx.nexora = Some(VerifierAnchors {
                decision_point: ctx.decision_points.clone(),
                observer,
                warrant: aip_warrant::WarrantTrustAnchors::new(),
                nexora: aip_nexora::NexoraTrustAnchors::new(),
                issuers: ctx.issuer_keys.clone(),
                agent_public_key,
                capability: aip_nexora::VerifierCapability::strict(),
                present_time_ms: Some(present_time_ms),
            });
        }
        Ok(ctx)
    }
}
