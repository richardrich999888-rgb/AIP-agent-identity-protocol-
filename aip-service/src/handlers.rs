//! Axum route handlers for all AIP endpoints.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use std::sync::Arc;

use crate::{
    auth::{AdminPrincipal, Principal},
    models::{
        ErrorBody, HealthResponse, IssueRequest, IssueResponse, PublicKeyResponse,
        RevocationStatusResponse, RevokeRequest, RevokeResponse, VerifyRequest, VerifyResponse,
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
    principal: Principal, // authenticated: minting tokens is not public
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
        &principal.tenant_id,
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

    // Check revocation set — a valid signature on a revoked JTI must be
    // rejected. The lookup is scoped to the tenant that minted the token (its
    // `tid` claim; pre-tenancy tokens belong to the legacy tenant), so no
    // other tenant's revocation log can invalidate it.
    let token_tenant = result
        .tenant_id
        .clone()
        .unwrap_or_else(|| revocation::LEGACY_TENANT.to_owned());
    let (valid, reason) = if result.valid
        && !result.jti.is_empty()
        && revocation::is_revoked(&state.revocation_set, &token_tenant, &result.jti)
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

// ── POST /v1/identity/revoke ──────────────────────────────────────────────────
//
// Admin-only, and scoped to the administrator's own tenant: the entry is
// written under `admin.0.tenant_id`, which comes from the API key and never
// from the body. A JTI that belongs to another tenant is unaffected — the
// call succeeds and records a revocation in the caller's namespace, which is
// inert there, rather than returning a distinguishable error that would tell
// the caller whether the JTI exists elsewhere.

pub async fn revoke(
    State(state): State<Arc<AppState>>,
    admin: AdminPrincipal, // admin-only: revocation is a privileged authority action
    Json(req): Json<RevokeRequest>,
) -> Result<Json<RevokeResponse>, ApiError> {
    let jti = revocation::normalize_jti(&req.jti).map_err(bad_request)?;
    if req.revoked_by.is_empty() || req.revoked_by.len() > revocation::MAX_TEXT_FIELD_LEN {
        return Err(bad_request(format!(
            "revoked_by must be 1..={} bytes",
            revocation::MAX_TEXT_FIELD_LEN
        )));
    }
    if req.reason.len() > revocation::MAX_TEXT_FIELD_LEN {
        return Err(bad_request(format!(
            "reason must be at most {} bytes",
            revocation::MAX_TEXT_FIELD_LEN
        )));
    }
    if req.cascade {
        // Refused, not ignored: a caller that asked for descendants to be
        // revoked and received a 200 would believe they were.
        return Err(bad_request(
            "cascade revocation is not available: the service no longer keeps a \
             delegation log. Revoke each descendant JTI explicitly; signed \
             aip-core delegation chains name them.",
        ));
    }

    let tenant = admin.0.tenant_id.as_str();
    let entry = revocation::RevocationEntry::new(tenant, &jti, &req.revoked_by, &req.reason);
    revocation::revoke(&state.revocation_log_path, &state.revocation_set, &entry).map_err(|e| {
        tracing::error!(error = %e, "revocation log write failed");
        internal_error("revocation could not be recorded")
    })?;

    tracing::info!(
        jti = %jti,
        revoked_by = %req.revoked_by,
        admin_key = %admin.0.key_id,
        tenant = %tenant,
        "token revoked"
    );

    Ok(Json(RevokeResponse {
        revoked_count: 1,
        revoked_jtis: vec![jti],
    }))
}

// ── GET /v1/identity/revocation-status/{jti} ─────────────────────────────────
//
// Authenticated and answered for the caller's tenant only. Unauthenticated,
// this was an oracle over every tenant's revocation log.

pub async fn revocation_status(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(jti): Path<String>,
) -> Json<RevocationStatusResponse> {
    let revoked = revocation::is_revoked(&state.revocation_set, &principal.tenant_id, &jti);
    Json(RevocationStatusResponse { jti, revoked })
}
