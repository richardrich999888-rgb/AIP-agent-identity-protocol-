//! SD-05 — a read-only projection of the agent's authority.
//!
//! The projection applies exactly the checks the decision point applies to a
//! chain before it will sign an expectation (`aip_authorize::DecisionPoint`,
//! steps 1–4 and 7) and reports the outcome per chain. It introduces no
//! capability object of its own (I18): every field is read from a
//! `ScopedToken` or `DelegationToken` whose signature has just been verified
//! by `aip_core`.

use std::collections::HashMap;

use aip_core::capability::verify_scoped_token;
use aip_core::delegation::verify_delegation_chain;
use aip_types::{AipError, CapabilityScope, DelegationToken, ScopedToken};
use serde::{Serialize, Serializer};

/// Verifier-supplied issuer public keys, by AIP-ID. Supplied by the party
/// building the profile, never read from the tokens themselves.
#[derive(Debug, Clone, Default)]
pub struct IssuerKeys(HashMap<String, Vec<u8>>);

impl IssuerKeys {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn trust(mut self, issuer_id: &str, public_key: &[u8]) -> Self {
        self.0.insert(issuer_id.to_string(), public_key.to_vec());
        self
    }

    pub fn get(&self, issuer_id: &str) -> Option<&[u8]> {
        self.0.get(issuer_id).map(|k| k.as_slice())
    }

    pub fn as_map(&self) -> &HashMap<String, Vec<u8>> {
        &self.0
    }
}

/// One authority path: a root token and the delegation hops below it.
#[derive(Debug, Clone, Serialize)]
pub struct AuthorityChain {
    pub root: ScopedToken,
    pub chain: Vec<DelegationToken>,
}

/// Temporal standing of a verified chain at the profile's `as_of` time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Standing {
    Valid,
    Expired { at_ms: u64 },
    NotYetValid { from_ms: u64 },
}

/// A verified authority path and the scope it confers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorizedCapability {
    pub root_jti: [u8; 16],
    pub chain_jtis: Vec<[u8; 16]>,
    /// The principal who issued the root token.
    pub root_issuer: String,
    /// The issuer of the last hop (the root issuer when there are no hops).
    pub leaf_issuer: String,
    /// The most-attenuated scope, as `verify_delegation_chain` returns it.
    pub effective_scope: CapabilityScope,
    /// Latest `issued_at` along the path.
    pub issued_at: u64,
    /// Earliest expiry along the path; `None` only if every token is unbounded.
    pub expires_at: Option<u64>,
    pub standing: Standing,
}

/// Why a chain contributes no authority. Mirrors the decision point's
/// denial reasons for the same conditions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExclusionReason {
    /// The root token's issuer is the agent itself (I1).
    SelfIssuedRoot,
    /// No key is trusted for this issuer.
    UntrustedIssuer(String),
    /// The root token's signature does not verify against the trusted key.
    RootSignatureInvalid,
    /// `aip_core::verify_delegation_chain` refused the chain.
    ChainInvalid(AipError),
    /// The chain is valid but ends at another agent.
    LeafNotAgent { leaf: String },
}

impl Serialize for ExclusionReason {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{self:?}"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExcludedAuthority {
    pub root_jti: [u8; 16],
    pub reason: ExclusionReason,
}

/// The issuer partition of a profile: a principal who signed a root token
/// that verifiably reaches this agent. Derived, never declared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IssuerAssertion {
    pub issuer_id: String,
    pub root_jti: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct AuthorityProjection {
    /// Verified and in standing at `as_of`.
    pub authorized: Vec<AuthorizedCapability>,
    /// Verified, but expired or not yet valid at `as_of`. Real authority,
    /// just not now; kept apart from both `authorized` and `excluded`.
    pub not_in_standing: Vec<AuthorizedCapability>,
    /// Chains that contribute nothing, each with its reason.
    pub excluded: Vec<ExcludedAuthority>,
}

impl AuthorityProjection {
    /// Issuers of every *verified* chain (in standing or not). An excluded
    /// chain contributes no issuer, because nothing about it was verified.
    pub fn issuers(&self) -> Vec<IssuerAssertion> {
        let mut out: Vec<IssuerAssertion> = Vec::new();
        for c in self.authorized.iter().chain(self.not_in_standing.iter()) {
            let a = IssuerAssertion {
                issuer_id: c.root_issuer.clone(),
                root_jti: c.root_jti,
            };
            if !out.contains(&a) {
                out.push(a);
            }
        }
        out
    }
}

/// Project the authority reaching `agent_id` from `chains`, using the
/// decision point's rules, at `as_of_ms`.
pub fn project_authority(
    agent_id: &str,
    chains: &[AuthorityChain],
    keys: &IssuerKeys,
    as_of_ms: u64,
) -> AuthorityProjection {
    let mut p = AuthorityProjection::default();
    for c in chains {
        match verify_chain(agent_id, c, keys, as_of_ms) {
            Ok(cap) if cap.standing == Standing::Valid => p.authorized.push(cap),
            Ok(cap) => p.not_in_standing.push(cap),
            Err(reason) => p.excluded.push(ExcludedAuthority {
                root_jti: c.root.jti,
                reason,
            }),
        }
    }
    p
}

fn verify_chain(
    agent_id: &str,
    c: &AuthorityChain,
    keys: &IssuerKeys,
    as_of_ms: u64,
) -> Result<AuthorizedCapability, ExclusionReason> {
    let root = &c.root;

    // 1. The agent did not issue its own root authority.
    if root.issuer_id == agent_id {
        return Err(ExclusionReason::SelfIssuedRoot);
    }

    // 2. Root issuer trusted, root signature verifies.
    let root_key = keys
        .get(&root.issuer_id)
        .ok_or_else(|| ExclusionReason::UntrustedIssuer(root.issuer_id.clone()))?;
    match verify_scoped_token(root, root_key) {
        Ok(true) => {}
        Ok(false) | Err(_) => return Err(ExclusionReason::RootSignatureInvalid),
    }

    // 3. Delegation chain: aip_core owns the semantics.
    let effective_scope =
        verify_delegation_chain(root, &c.chain, keys.as_map()).map_err(|e| match e {
            AipError::InvalidPublicKey => {
                let missing = c
                    .chain
                    .iter()
                    .find(|h| keys.get(&h.issuer_id).is_none())
                    .map(|h| h.issuer_id.clone())
                    .unwrap_or_default();
                ExclusionReason::UntrustedIssuer(missing)
            }
            other => ExclusionReason::ChainInvalid(other),
        })?;

    // 4. The chain ends at this agent.
    let leaf = c
        .chain
        .last()
        .map(|h| h.grantee_id.as_str())
        .unwrap_or(root.agent_id.as_str());
    if leaf != agent_id {
        return Err(ExclusionReason::LeafNotAgent {
            leaf: leaf.to_string(),
        });
    }

    // 7. Temporal standing at `as_of_ms`, as the decision point computes it.
    let mut issued_at = root.issued_at;
    let mut expires_at = root.expires_at;
    for hop in &c.chain {
        issued_at = issued_at.max(hop.issued_at);
        expires_at = match (expires_at, hop.expires_at) {
            (Some(a), Some(h)) => Some(a.min(h)),
            (None, h) => h,
            (a, None) => a,
        };
    }
    let standing = if as_of_ms < issued_at {
        Standing::NotYetValid { from_ms: issued_at }
    } else if expires_at.is_some_and(|e| as_of_ms > e) {
        Standing::Expired {
            at_ms: expires_at.unwrap_or_default(),
        }
    } else {
        Standing::Valid
    };

    Ok(AuthorizedCapability {
        root_jti: root.jti,
        chain_jtis: c.chain.iter().map(|h| h.jti).collect(),
        root_issuer: root.issuer_id.clone(),
        leaf_issuer: c
            .chain
            .last()
            .map(|h| h.issuer_id.clone())
            .unwrap_or_else(|| root.issuer_id.clone()),
        effective_scope,
        issued_at,
        expires_at,
        standing,
    })
}
