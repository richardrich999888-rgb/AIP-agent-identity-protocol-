//! Tenant-authenticated verification of signed AIP delegation chains.
//! Trust anchors are loaded by the institution, never accepted from requests.

use std::collections::HashMap;
use std::sync::Arc;

use aip_core::delegation::verify_delegation_chain;
use aip_types::{CapabilityScope, DelegationToken, ScopedToken};
use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::{auth::Principal, models::ErrorBody, revocation, AppState};

type ApiError = (StatusCode, Json<ErrorBody>);
pub const MAX_CHAIN_BODY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyDelegationRequest {
    pub root_token: ScopedToken,
    #[serde(default)]
    pub chain: Vec<DelegationToken>,
}

#[derive(Debug, Serialize)]
pub struct VerifyDelegationResponse {
    pub valid: bool,
    pub tenant_id: String,
    pub leaf_agent_id: String,
    pub chain_depth: usize,
    pub effective_scope: CapabilityScope,
    pub checked_at_ms: u64,
    pub trust_config_sha256: Option<String>,
}

fn error(status: StatusCode, message: impl Into<String>) -> ApiError {
    (
        status,
        Json(ErrorBody {
            error: message.into(),
        }),
    )
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub async fn verify(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Json(req): Json<VerifyDelegationRequest>,
) -> Result<Json<VerifyDelegationResponse>, ApiError> {
    let now = now_ms();

    // Resolve every issuer exclusively through institution-configured,
    // tenant-bound anchors. No request-supplied public keys are trusted.
    let mut issuer_keys: HashMap<String, Vec<u8>> = HashMap::new();

    for issuer_id in
        std::iter::once(&req.root_token.issuer_id).chain(req.chain.iter().map(|hop| &hop.issuer_id))
    {
        if !issuer_keys.contains_key(issuer_id) {
            let key = state.agent_trust.key(&principal.tenant_id, issuer_id)?;
            issuer_keys.insert(issuer_id.clone(), key.to_vec());
        }
    }

    let effective_scope = verify_delegation_chain(&req.root_token, &req.chain, &issuer_keys)
        .map_err(|e| {
            tracing::info!(
                tenant = %principal.tenant_id,
                error = ?e,
                "delegation chain verification rejected"
            );
            error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "delegation chain verification failed",
            )
        })?;

    // A valid signature does not make a future-issued credential valid now.
    // Check the root and every hop against the service clock.
    if req.root_token.issued_at > now || req.chain.iter().any(|hop| hop.issued_at > now) {
        return Err(error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "delegation chain contains a future-issued credential",
        ));
    }

    // The core verifier checks temporal attenuation between parent and child.
    // The service additionally checks whether every credential is valid now.
    if req
        .root_token
        .expires_at
        .is_some_and(|expiry| expiry <= now)
        || req
            .chain
            .iter()
            .any(|hop| hop.expires_at.is_some_and(|expiry| expiry <= now))
    {
        return Err(error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "delegation chain contains an expired credential",
        ));
    }

    // Revocation is always evaluated against the authenticated tenant.
    let root_jti = hex::encode(req.root_token.jti);
    if revocation::is_revoked(&state.revocation_set, &principal.tenant_id, &root_jti) {
        return Err(error(
            StatusCode::FORBIDDEN,
            "delegation chain contains a revoked credential",
        ));
    }

    for hop in &req.chain {
        let jti = hex::encode(hop.jti);
        if revocation::is_revoked(&state.revocation_set, &principal.tenant_id, &jti) {
            return Err(error(
                StatusCode::FORBIDDEN,
                "delegation chain contains a revoked credential",
            ));
        }
    }

    let leaf_agent_id = req
        .chain
        .last()
        .map(|hop| hop.grantee_id.clone())
        .unwrap_or_else(|| req.root_token.agent_id.clone());

    Ok(Json(VerifyDelegationResponse {
        valid: true,
        tenant_id: principal.tenant_id.clone(),
        leaf_agent_id,
        chain_depth: req.chain.len(),
        effective_scope,
        checked_at_ms: now,
        trust_config_sha256: state.agent_trust.source_sha256().map(str::to_owned),
    }))
}
