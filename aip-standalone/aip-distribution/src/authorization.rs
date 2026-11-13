//! Fail-closed package-operation authorization over existing AIP capabilities.
//!
//! Package operations use an exact resource-bound `ScopeAction::Custom`.
//! No broad Read/Write action is interpreted as package authority. Callers
//! must provide issuer keys and a revocation log from their trusted policy
//! source, together with that source's freshness deadline.

use crate::peer_binding::{
    verify_authenticated_peer, PeerBindingError, PeerBindingStatement, PeerBindingTrustAnchors,
    PeerStatusSnapshot,
};
use crate::revocation_snapshot::VerifiedRevocationSnapshot;
use aip_core::{
    capability::{scope_permits, verify_scoped_token},
    delegation::verify_delegation_chain,
    SignatureVerifier,
};
use aip_types::AgentIdentityDocument;
use aip_types::{CapabilityScope, DelegationToken, ScopeAction, ScopedToken};
use libp2p::PeerId;
use std::collections::HashMap;

const RESOURCE_ACTION_PREFIX: &str = "aip.pkg:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PackageOperation {
    Serve,
    Receive,
    Resume,
    /// Permission for a package server to continue a receiver's transfer.
    /// Distinct from `Resume`, which authorizes the receiver side.
    ServeResume,
    /// Permission to materialize a verified package into a staging directory.
    /// This does not mean activation, installation, or execution.
    Stage,
    Install,
}

impl PackageOperation {
    fn code(self) -> &'static str {
        match self {
            Self::Serve => "serve",
            Self::Receive => "receive",
            Self::Resume => "resume",
            Self::ServeResume => "serve_resume",
            Self::Stage => "stage",
            Self::Install => "install",
        }
    }
}

/// Exact package resource covered by the capability action.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageResource {
    pub package_id: String,
    pub publisher_id: String,
    pub release_digest: [u8; 32],
    /// Required for every operation so the grant cannot be reused for a
    /// different destination. For serve, this is the requesting/receiving AIP.
    pub recipient_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationError {
    Invalid(String),
    Untrusted(String),
    Denied(String),
}

impl std::fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for AuthorizationError {}

/// Result includes the exact action string callers should audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationDecision {
    pub subject_id: String,
    pub operation: PackageOperation,
    pub resource_action: String,
    pub effective_scope: CapabilityScope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionError {
    PeerBinding(PeerBindingError),
    Operation(AuthorizationError),
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for AdmissionError {}

/// One fail-closed application admission decision, bound first to the
/// transport-authenticated PeerId and then to an exact package operation.
/// Binding evidence/anchors are local policy inputs; only the capability and
/// delegation are portable signed credentials. Call this again on every
/// request, resume, and install transition.
#[allow(clippy::too_many_arguments)]
pub fn authorize_authenticated_peer_operation(
    authenticated_peer: &PeerId,
    statement: &PeerBindingStatement,
    aid: &AgentIdentityDocument,
    peer_status: &PeerStatusSnapshot,
    peer_anchors: &PeerBindingTrustAnchors,
    audience: &str,
    aid_signature_verifier: Option<&dyn SignatureVerifier>,
    operation: PackageOperation,
    resource: &PackageResource,
    capability: &ScopedToken,
    delegation_chain: &[DelegationToken],
    capability_issuer_keys: &HashMap<String, Vec<u8>>,
    revocations: &VerifiedRevocationSnapshot,
    now_ms: u64,
) -> Result<(String, AuthorizationDecision), AdmissionError> {
    let subject = verify_authenticated_peer(
        authenticated_peer,
        statement,
        aid,
        peer_status,
        peer_anchors,
        audience,
        now_ms,
        aid_signature_verifier,
    )
    .map_err(AdmissionError::PeerBinding)?;
    let decision = authorize_package_operation(
        operation,
        resource,
        &subject,
        capability,
        delegation_chain,
        capability_issuer_keys,
        revocations,
        now_ms,
    )
    .map_err(AdmissionError::Operation)?;
    Ok((subject, decision))
}

/// Authorize one operation for one exact package resource.
///
/// `revocations` can only be created by verifying a signed snapshot against
/// an independently provisioned authority anchor. The checkpoint returned by
/// its verifier must be persisted in rollback-resistant trusted policy storage.
pub fn authorize_package_operation(
    operation: PackageOperation,
    resource: &PackageResource,
    subject_id: &str,
    root_token: &ScopedToken,
    delegation_chain: &[DelegationToken],
    issuer_public_keys: &HashMap<String, Vec<u8>>,
    revocations: &VerifiedRevocationSnapshot,
    now_ms: u64,
) -> Result<AuthorizationDecision, AuthorizationError> {
    validate_resource(resource)?;
    validate_id(subject_id, "subject_id")?;
    revocations
        .ensure_fresh("/aip/distribution/1.0.0", now_ms)
        .map_err(|e| AuthorizationError::Untrusted(e.to_string()))?;
    check_time(
        root_token.issued_at,
        root_token.expires_at,
        now_ms,
        "root token",
    )?;
    if revocations.is_revoked(&root_token.jti) {
        return Err(AuthorizationError::Denied(
            "root capability is revoked".into(),
        ));
    }

    let (effective_scope, effective_holder) = if delegation_chain.is_empty() {
        let key = issuer_public_keys
            .get(&root_token.issuer_id)
            .ok_or_else(|| {
                AuthorizationError::Untrusted("root token issuer is not trusted".into())
            })?;
        if !verify_scoped_token(root_token, key)
            .map_err(|e| AuthorizationError::Invalid(e.to_string()))?
        {
            return Err(AuthorizationError::Invalid(
                "root token signature is invalid".into(),
            ));
        }
        (root_token.scope.clone(), root_token.agent_id.as_str())
    } else {
        for hop in delegation_chain {
            check_time(hop.issued_at, hop.expires_at, now_ms, "delegation")?;
            if revocations.is_revoked(&hop.jti) || revocations.is_revoked(&hop.parent_jti) {
                return Err(AuthorizationError::Denied(
                    "delegation or parent capability is revoked".into(),
                ));
            }
        }
        let scope = verify_delegation_chain(root_token, delegation_chain, issuer_public_keys)
            .map_err(|e| AuthorizationError::Invalid(e.to_string()))?;
        let holder = delegation_chain
            .last()
            .expect("non-empty delegation chain")
            .grantee_id
            .as_str();
        (scope, holder)
    };
    if effective_holder != subject_id {
        return Err(AuthorizationError::Denied(
            "capability holder does not match authenticated AIP subject".into(),
        ));
    }
    if matches!(
        operation,
        PackageOperation::Receive
            | PackageOperation::Resume
            | PackageOperation::Stage
            | PackageOperation::Install
    ) && resource.recipient_id != subject_id
    {
        return Err(AuthorizationError::Denied(
            "recipient does not match the receiving or installing subject".into(),
        ));
    }

    let action = package_resource_action(operation, resource);
    let scope_action = ScopeAction::Custom(action.clone());
    if !scope_permits(&effective_scope, &scope_action) {
        return Err(AuthorizationError::Denied(
            "capability does not grant this operation for this exact package resource".into(),
        ));
    }
    Ok(AuthorizationDecision {
        subject_id: subject_id.to_string(),
        operation,
        resource_action: action,
        effective_scope,
    })
}

/// Deterministic action encoding. The domain-separated digest commits to
/// operation, package ID, publisher ID, release digest, and recipient ID.
/// Its 192-bit truncation fits the documented 64-byte custom-action limit.
pub fn package_resource_action(operation: PackageOperation, resource: &PackageResource) -> String {
    let mut bytes = b"AIP/DISTRIBUTION/PACKAGE_AUTHORIZATION/v1".to_vec();
    put_field(&mut bytes, operation.code().as_bytes());
    put_field(&mut bytes, resource.package_id.as_bytes());
    put_field(&mut bytes, resource.publisher_id.as_bytes());
    bytes.extend_from_slice(&resource.release_digest);
    put_field(&mut bytes, resource.recipient_id.as_bytes());
    let digest = aip_crypto::sha256(&bytes);
    format!("{RESOURCE_ACTION_PREFIX}{}", hex::encode(&digest[..24]))
}

fn validate_resource(resource: &PackageResource) -> Result<(), AuthorizationError> {
    validate_id(&resource.package_id, "package_id")?;
    validate_id(&resource.publisher_id, "publisher_id")?;
    validate_id(&resource.recipient_id, "recipient_id")?;
    Ok(())
}

fn validate_id(value: &str, field: &str) -> Result<(), AuthorizationError> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(AuthorizationError::Invalid(format!("invalid {field}")));
    }
    Ok(())
}

fn check_time(
    issued_at: u64,
    expires_at: Option<u64>,
    now_ms: u64,
    label: &str,
) -> Result<(), AuthorizationError> {
    if issued_at > now_ms || expires_at.is_some_and(|expiry| now_ms > expiry) {
        return Err(AuthorizationError::Denied(format!(
            "{label} is not currently valid"
        )));
    }
    Ok(())
}

fn put_field(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u64).to_be_bytes());
    out.extend_from_slice(field);
}
