//! Offline authentication of the native authority referenced by an expectation.
//!
//! This checks scope at issuance, not current revocation, resource/spend policy,
//! institutional key custody, identity mapping or execution. Canonical token
//! signatures and delegation attenuation remain owned by `aip_core`.
use std::collections::HashMap;

use aip_core::{capability::scope_permits, delegation::verify_delegation_chain};
use aip_types::{DelegationToken, ScopedToken};
use serde::Serialize;

use crate::{verify_expected_execution_for_agent, DecisionPointTrustAnchors, ExpectedExecution};

/// Assessor-provisioned roots are deliberately separate from delegator keys.
/// Knowing a delegator's public key does not permit it to issue root authority.
#[derive(Debug, Clone, Default)]
pub struct AuthorityTrustAnchors {
    roots: HashMap<String, Vec<u8>>,
    delegators: HashMap<String, Vec<u8>>,
}

impl AuthorityTrustAnchors {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn trust_root(mut self, id: &str, key: &[u8]) -> Self {
        self.roots.insert(id.into(), key.to_vec());
        self
    }

    pub fn trust_delegator(mut self, id: &str, key: &[u8]) -> Self {
        self.delegators.insert(id.into(), key.to_vec());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityReferenceError {
    InvalidExpectation,
    UnknownRoot,
    InvalidTrustAnchor,
    ConflictingIssuerKeys,
    SelfIssuedRoot,
    ReferenceMismatch,
    InvalidChain,
    LeafMismatch,
    ActionOutOfScope,
    AuthorityNotYetValid,
    ExpectationOutlivesAuthority,
}

/// A limited verification result, constructible only through the verifier.
/// This does not deserialize into an admission credential or grant authority.
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedAuthorityReference {
    root_issuer: String,
    agent_id: String,
    decision_id: [u8; 16],
    root_jti: [u8; 16],
    chain_jtis: Vec<[u8; 16]>,
    evaluated_at_ms: u64,
    expectation_valid_until_ms: u64,
}

/// Verify an expectation and the exact chain it names under external anchors.
/// Validity is evaluated at the signed issuance time, with native inclusive
/// expiry semantics. Later expiry does not erase historical signature validity.
pub fn verify_authority_reference(
    expectation: &ExpectedExecution,
    root: &ScopedToken,
    chain: &[DelegationToken],
    decisions: &DecisionPointTrustAnchors,
    agent_public_key: &[u8],
    authority: &AuthorityTrustAnchors,
) -> Result<VerifiedAuthorityReference, AuthorityReferenceError> {
    use AuthorityReferenceError::*;
    if agent_public_key.len() != 32 {
        return Err(InvalidTrustAnchor);
    }
    verify_expected_execution_for_agent(expectation, decisions, agent_public_key)
        .map_err(|_| InvalidExpectation)?;
    let root_key = authority.roots.get(&root.issuer_id).ok_or(UnknownRoot)?;
    if root.issuer_id == expectation.agent_id || root_key == agent_public_key {
        return Err(SelfIssuedRoot);
    }
    if root.issuer_id.is_empty()
        || authority
            .roots
            .iter()
            .chain(authority.delegators.iter())
            .any(|(id, key)| id.is_empty() || key.len() != 32)
    {
        return Err(InvalidTrustAnchor);
    }
    let mut keys = authority.delegators.clone();
    for (id, key) in &authority.roots {
        if keys.get(id).is_some_and(|other| other != key) {
            return Err(ConflictingIssuerKeys);
        }
        keys.insert(id.clone(), key.clone());
    }
    if expectation.authority.root_jti != root.jti
        || expectation.authority.chain_jtis != chain.iter().map(|hop| hop.jti).collect::<Vec<_>>()
    {
        return Err(ReferenceMismatch);
    }
    let scope = verify_delegation_chain(root, chain, &keys).map_err(|_| InvalidChain)?;
    let leaf = chain
        .last()
        .map(|hop| &hop.grantee_id)
        .unwrap_or(&root.agent_id);
    if leaf != &expectation.agent_id {
        return Err(LeafMismatch);
    }
    if !scope_permits(&scope, &expectation.action_kind) {
        return Err(ActionOutOfScope);
    }
    for (issued_at, expires_at) in std::iter::once((root.issued_at, root.expires_at))
        .chain(chain.iter().map(|hop| (hop.issued_at, hop.expires_at)))
    {
        if issued_at > expectation.issued_at {
            return Err(AuthorityNotYetValid);
        }
        if expires_at.is_some_and(|end| expectation.valid_until > end) {
            return Err(ExpectationOutlivesAuthority);
        }
    }
    Ok(VerifiedAuthorityReference {
        root_issuer: root.issuer_id.clone(),
        agent_id: expectation.agent_id.clone(),
        decision_id: expectation.decision_id,
        root_jti: root.jti,
        chain_jtis: expectation.authority.chain_jtis.clone(),
        evaluated_at_ms: expectation.issued_at,
        expectation_valid_until_ms: expectation.valid_until,
    })
}
