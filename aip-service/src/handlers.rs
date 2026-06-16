//! Axum route handlers for all AIP endpoints.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use std::sync::Arc;

use crate::{
    auth::{AdminPrincipal, Principal},
    delegation,
    models::{
        DelegateRequest, DelegateResponse, ErrorBody, HealthResponse, IssueRequest, IssueResponse,
        PublicKeyResponse, RevocationStatusResponse, RevokeRequest, RevokeResponse,
        VerifyChainRequest, VerifyChainResponse, VerifyRequest, VerifyResponse,
    },
    revocation, tokens, AppState,
};

type ApiError = (StatusCode, Json<ErrorBody>);

fn bad_request(msg: impl Into<String>) -> ApiError {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorBody { error: msg.into() }),
    )
}

fn internal_error(msg: impl Into<String>) -> ApiError {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorBody { error: msg.into() }),
    )
}

// ── GET /health ───────────────────────────────────────────────────────────────

pub async fn health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "aip",
        version: env!("CARGO_PKG_VERSION"),
        key_fingerprint: state.fingerprint.clone(),
    })
}

// ── POST /v1/identity/issue ───────────────────────────────────────────────────

pub async fn issue(
    State(state): State<Arc<AppState>>,
    _principal: Principal, // authenticated: minting tokens is not public
    Json(req): Json<IssueRequest>,
) -> Result<Json<IssueResponse>, ApiError> {
    // Validate: agent_id must be a UUID v4
    if uuid::Uuid::parse_str(&req.agent_id).is_err() {
        return Err(bad_request("agent_id must be a valid UUID v4"));
    }

    // Validate: ttl_seconds in range 1..=86400
    if req.ttl_seconds == 0 || req.ttl_seconds > 86_400 {
        return Err(bad_request("ttl_seconds must be between 1 and 86400"));
    }

    // Validate: metadata at most 10 keys
    if let Some(ref meta) = req.metadata {
        if meta.len() > 10 {
            return Err(bad_request(format!(
                "metadata may contain at most 10 keys, got {}",
                meta.len()
            )));
        }
    }

    tracing::debug!(
        agent_id = %req.agent_id,
        agent_type = %req.agent_type.as_str(),
        ttl = req.ttl_seconds,
        "issuing token"
    );

    let result = tokens::issue(
        &req.agent_id,
        req.agent_type.as_str(),
        req.metadata,
        req.ttl_seconds,
        &state.encoding_key,
    )
    .map_err(|e| {
        // Log the real error internally; return a generic message to the client
        // to avoid leaking signing key details or internal token structure.
        tracing::error!(agent_id = %req.agent_id, error = %e, "token issuance failed");
        internal_error("token issuance failed")
    })?;

    tracing::info!(
        agent_id = %req.agent_id,
        agent_type = %req.agent_type.as_str(),
        issued_at = %result.issued_at,
        expires_at = %result.expires_at,
        "token issued"
    );

    Ok(Json(IssueResponse {
        token: result.token,
        issued_at: result.issued_at,
        expires_at: result.expires_at,
        public_key_fingerprint: state.fingerprint.clone(),
    }))
}

// ── POST /v1/identity/verify ──────────────────────────────────────────────────
//
// Hot path: called by the gateway on every inbound request.
// Target: p99 < 10 ms.  No I/O, no allocation on the happy path beyond the
// JWT decode (signature verification + base64 decoding).

pub async fn verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyRequest>,
) -> Json<VerifyResponse> {
    let result = tokens::verify(&req.token, &state.decoding_key);

    // Check revocation set — a valid signature on a revoked JTI must be rejected.
    let (valid, reason) = if result.valid
        && !result.jti.is_empty()
        && revocation::is_revoked(&state.revocation_set, &result.jti)
    {
        tracing::debug!(jti = %result.jti, "token rejected: revoked");
        (false, Some("token has been revoked".to_owned()))
    } else {
        if result.valid {
            tracing::debug!(agent_id = %result.agent_id, jti = %result.jti, "token verified OK");
        } else {
            tracing::debug!(
                reason = result.reason.as_deref().unwrap_or(""),
                "token rejected"
            );
        }
        (result.valid, result.reason)
    };

    Json(VerifyResponse {
        valid,
        agent_id: result.agent_id,
        agent_type: result.agent_type,
        expired: result.expired,
        reason,
    })
}

// ── GET /v1/identity/public-key ───────────────────────────────────────────────

pub async fn public_key(State(state): State<Arc<AppState>>) -> Json<PublicKeyResponse> {
    Json(PublicKeyResponse {
        public_key_pem: state.public_pem.clone(),
        algorithm: "Ed25519",
        fingerprint: state.fingerprint.clone(),
    })
}

// ── POST /v1/identity/delegate ────────────────────────────────────────────────

pub async fn delegate(
    State(state): State<Arc<AppState>>,
    _principal: Principal, // authenticated: delegating authority is not public
    Json(req): Json<DelegateRequest>,
) -> Result<Json<DelegateResponse>, ApiError> {
    // Validate delegatee_id is a UUID
    if uuid::Uuid::parse_str(&req.delegatee_id).is_err() {
        return Err(bad_request("delegatee_id must be a valid UUID v4"));
    }

    // Validate ttl
    if req.ttl_seconds == 0 || req.ttl_seconds > 86_400 {
        return Err(bad_request("ttl_seconds must be between 1 and 86400"));
    }

    // Verify the parent token to get its JTI and check revocation
    let parent_result = tokens::verify(&req.parent_token, &state.decoding_key);
    if !parent_result.valid {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: format!(
                    "parent_token invalid: {}",
                    parent_result.reason.unwrap_or_default()
                ),
            }),
        ));
    }
    if revocation::is_revoked(&state.revocation_set, &parent_result.jti) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "parent_token has been revoked".to_owned(),
            }),
        ));
    }

    // Determine parent depth — root token (AIP JWT) has depth 0
    let parent_depth: u32 = {
        let log = state.delegation_log.lock().unwrap();
        log.iter()
            .find(|t| t.delegation_id == parent_result.jti)
            .map(|t| t.depth)
            .unwrap_or(0) // root AIP JWT → depth 0
    };

    let new_depth = parent_depth + 1;
    if new_depth > delegation::MAX_DEPTH {
        return Err(bad_request(format!(
            "delegation chain depth {} exceeds maximum {}",
            new_depth,
            delegation::MAX_DEPTH
        )));
    }

    let token = delegation::DelegationToken::new(
        &parent_result.jti,
        &req.delegatee_id,
        req.scope,
        new_depth,
        req.ttl_seconds,
    );

    delegation::append_delegation(&state.delegation_log_path, &state.delegation_log, &token)
        .map_err(|e| internal_error(format!("delegation log write error: {e}")))?;

    tracing::info!(
        delegation_id = %token.delegation_id,
        parent_jti = %token.parent_jti,
        delegatee_id = %token.delegatee_id,
        depth = token.depth,
        "delegation issued"
    );

    Ok(Json(DelegateResponse { delegation: token }))
}

// ── POST /v1/identity/verify-chain ───────────────────────────────────────────

pub async fn verify_chain(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyChainRequest>,
) -> Json<VerifyChainResponse> {
    // Verify root token
    let root_result = tokens::verify(&req.root_token, &state.decoding_key);
    if !root_result.valid {
        return Json(VerifyChainResponse {
            valid: false,
            effective_scope: None,
            chain_depth: 0,
            reason: Some(format!(
                "root_token invalid: {}",
                root_result.reason.unwrap_or_default()
            )),
        });
    }
    if revocation::is_revoked(&state.revocation_set, &root_result.jti) {
        return Json(VerifyChainResponse {
            valid: false,
            effective_scope: None,
            chain_depth: 0,
            reason: Some("root_token has been revoked".to_owned()),
        });
    }

    if req.delegation_ids.is_empty() {
        // Root-only chain — valid, no scope constraint from delegations
        return Json(VerifyChainResponse {
            valid: true,
            effective_scope: Some(crate::capability::CapabilityScope::admin()),
            chain_depth: 0,
            reason: None,
        });
    }

    let log = state.delegation_log.lock().unwrap();

    let mut expected_parent = root_result.jti.clone();
    let mut effective_scope: Option<crate::capability::CapabilityScope> = None;

    for (i, del_id) in req.delegation_ids.iter().enumerate() {
        // Find delegation entry
        let entry = match delegation::find_by_id(&log, del_id) {
            Some(e) => e,
            None => {
                return Json(VerifyChainResponse {
                    valid: false,
                    effective_scope: None,
                    chain_depth: i as u32,
                    reason: Some(format!("delegation_id {del_id} not found")),
                })
            }
        };

        // Check parent linkage
        if entry.parent_jti != expected_parent {
            return Json(VerifyChainResponse {
                valid: false,
                effective_scope: None,
                chain_depth: i as u32,
                reason: Some(format!("chain broken at index {i}: parent_jti mismatch")),
            });
        }

        // Check revocation
        if revocation::is_revoked(&state.revocation_set, &entry.delegation_id) {
            return Json(VerifyChainResponse {
                valid: false,
                effective_scope: None,
                chain_depth: i as u32,
                reason: Some(format!("delegation {del_id} has been revoked")),
            });
        }

        // Narrow effective scope
        effective_scope = Some(match effective_scope {
            None => entry.scope.clone(),
            Some(prev) => match prev.meet(&entry.scope) {
                Some(s) => s,
                None => {
                    return Json(VerifyChainResponse {
                        valid: false,
                        effective_scope: None,
                        chain_depth: i as u32,
                        reason: Some(format!("scope intersection empty at chain index {i}")),
                    })
                }
            },
        });

        expected_parent = entry.delegation_id.clone();
    }

    Json(VerifyChainResponse {
        valid: true,
        effective_scope,
        chain_depth: req.delegation_ids.len() as u32,
        reason: None,
    })
}

// ── POST /v1/identity/revoke ──────────────────────────────────────────────────

pub async fn revoke(
    State(state): State<Arc<AppState>>,
    admin: AdminPrincipal, // admin-only: revocation is a privileged authority action
    Json(req): Json<RevokeRequest>,
) -> Result<Json<RevokeResponse>, ApiError> {
    if req.jti.is_empty() {
        return Err(bad_request("jti must not be empty"));
    }
    if req.revoked_by.is_empty() {
        return Err(bad_request("revoked_by must not be empty"));
    }

    let revoked_jtis = if req.cascade {
        let parent_to_children = delegation::build_parent_to_children(&state.delegation_log);
        revocation::cascade_revoke(
            &state.revocation_log_path,
            &state.revocation_set,
            &req.jti,
            &req.revoked_by,
            &req.reason,
            &parent_to_children,
        )
        .map_err(|e| internal_error(format!("cascade revoke error: {e}")))?
    } else {
        let entry = revocation::RevocationEntry::new(&req.jti, &req.revoked_by, &req.reason);
        revocation::revoke(&state.revocation_log_path, &state.revocation_set, &entry)
            .map_err(|e| internal_error(format!("revoke error: {e}")))?;
        vec![req.jti.clone()]
    };

    tracing::info!(
        count = revoked_jtis.len(),
        cascade = req.cascade,
        revoked_by = %req.revoked_by,
        admin_key = %admin.0.key_id,
        admin_tenant = %admin.0.tenant_id,
        "tokens revoked"
    );

    Ok(Json(RevokeResponse {
        revoked_count: revoked_jtis.len(),
        revoked_jtis,
    }))
}

// ── GET /v1/identity/revocation-status/{jti} ─────────────────────────────────

pub async fn revocation_status(
    State(state): State<Arc<AppState>>,
    Path(jti): Path<String>,
) -> Json<RevocationStatusResponse> {
    let revoked = revocation::is_revoked(&state.revocation_set, &jti);
    Json(RevocationStatusResponse { jti, revoked })
}
