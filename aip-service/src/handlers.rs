//! Axum route handlers for all AIP endpoints.

use aip_core::passport::{
    canonical_passport_body_bytes, AgentPassport, EnvironmentalLock, LineageEntry, PassportBody,
    PassportConstraints, PassportHeader, PassportIssuer, PassportProof, PassportSubject,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use std::sync::Arc;

use crate::{
    delegation,
    models::{
        DelegateRequest, DelegateResponse, ErrorBody, HealthResponse, IssueRequest, IssueResponse,
        PassportIssueRequest, PassportIssueResponse, PassportVerifyRequest, PassportVerifyResponse,
        PublicKeyResponse, RevocationStatusResponse, RevokeRequest, RevokeResponse,
        VerifyChainRequest, VerifyChainResponse, VerifyRequest, VerifyResponse,
    },
    passport as passport_store, revocation, tokens, AppState,
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

fn unauthorized(msg: impl Into<String>) -> ApiError {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorBody { error: msg.into() }),
    )
}

fn now_unix_seconds() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

fn token_from_headers_or_body(
    headers: &HeaderMap,
    body_token: &Option<String>,
) -> Result<String, ApiError> {
    if let Some(token) = body_token
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        return Ok(token.to_owned());
    }

    if let Some(value) = headers.get("aip-token") {
        let token = value
            .to_str()
            .map_err(|_| bad_request("AIP-Token header must be valid UTF-8"))?
            .trim();
        if !token.is_empty() {
            return Ok(token.to_owned());
        }
    }

    if let Some(value) = headers.get("authorization") {
        let header = value
            .to_str()
            .map_err(|_| bad_request("Authorization header must be valid UTF-8"))?
            .trim();
        if let Some(token) = header.strip_prefix("Bearer ") {
            let token = token.trim();
            if !token.is_empty() {
                return Ok(token.to_owned());
            }
        }
    }

    Err(unauthorized(
        "AIP token required in aip_token, AIP-Token, or Authorization: Bearer",
    ))
}

fn metadata_string(
    metadata: &Option<serde_json::Map<String, serde_json::Value>>,
    key: &str,
) -> Option<String> {
    metadata
        .as_ref()
        .and_then(|meta| meta.get(key))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
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

// ── POST /v1/passports/issue ─────────────────────────────────────────────────

pub async fn issue_passport(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<PassportIssueRequest>,
) -> Result<Json<PassportIssueResponse>, ApiError> {
    if req.friendly_name.trim().is_empty() {
        return Err(bad_request("friendly_name must not be empty"));
    }
    if req.capabilities.is_empty() {
        return Err(bad_request("capabilities must not be empty"));
    }
    if req.capabilities.len() > 64 {
        return Err(bad_request("capabilities may contain at most 64 entries"));
    }

    let ttl_seconds = req.ttl_seconds.unwrap_or(3_600);
    if ttl_seconds == 0 || ttl_seconds > 86_400 {
        return Err(bad_request("ttl_seconds must be between 1 and 86400"));
    }

    let aip_token = token_from_headers_or_body(&headers, &req.aip_token)?;
    let parent_result = tokens::verify(&aip_token, &state.decoding_key);
    if !parent_result.valid {
        return Err(unauthorized(format!(
            "aip_token invalid: {}",
            parent_result.reason.unwrap_or_default()
        )));
    }
    if revocation::is_revoked(&state.revocation_set, &parent_result.jti) {
        return Err(unauthorized("aip_token has been revoked"));
    }

    let issued_at = now_unix_seconds();
    let expires_at = issued_at + ttl_seconds;
    let passport_id = format!("urn:aip:passport:{}", uuid::Uuid::new_v4());

    let environmental_lock = req.environmental_lock.unwrap_or_else(|| EnvironmentalLock {
        runtime: metadata_string(&req.metadata, "runtime")
            .unwrap_or_else(|| format!("airon-aip-service-{}", env!("CARGO_PKG_VERSION"))),
        image_hash: metadata_string(&req.metadata, "image_hash")
            .unwrap_or_else(|| "sha256:unknown".to_owned()),
    });

    let lineage_payload = serde_json::json!({
        "actor": parent_result.agent_id.clone(),
        "action": "AUTHORIZE_PASSPORT",
        "passport_id": passport_id,
        "parent_jti": parent_result.jti.clone(),
        "timestamp": issued_at,
    });
    let lineage_bytes = serde_json::to_vec(&lineage_payload)
        .map_err(|e| internal_error(format!("lineage encoding failed: {e}")))?;
    let lineage_signature = state.passport_keypair.sign_bytes_b64url(&lineage_bytes);

    let body = PassportBody {
        passport_id,
        subject: PassportSubject {
            agent_id: parent_result.agent_id,
            friendly_name: req.friendly_name.trim().to_owned(),
            pqc_pubkey: req.subject_pqc_pubkey,
            classical_pubkey: req.subject_classical_pubkey,
        },
        issuer: PassportIssuer {
            name: state.issuer_name.clone(),
            id: state.issuer_id.clone(),
            registry_url: state.registry_url.clone(),
            public_key_fingerprint: state.fingerprint.clone(),
            classical_pubkey: state.issuer_public_key_b64url.clone(),
            pqc_pubkey: None,
        },
        constraints: PassportConstraints {
            issued_at,
            expires_at,
            capabilities: req.capabilities,
            max_delegation_depth: req.max_delegation_depth.unwrap_or(delegation::MAX_DEPTH),
        },
        lineage: vec![LineageEntry {
            actor: lineage_payload["actor"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            action: "AUTHORIZE".to_owned(),
            timestamp: issued_at,
            signature: lineage_signature,
        }],
        environmental_lock,
    };

    let body_bytes = canonical_passport_body_bytes(&body)
        .map_err(|e| internal_error(format!("passport canonical encoding failed: {e}")))?;
    let signature = state.passport_keypair.sign_bytes_b64url(&body_bytes);
    let passport = AgentPassport {
        header: PassportHeader::default(),
        body,
        proof: PassportProof {
            signature,
            pqc_signature: None,
        },
    };

    passport
        .structural_check()
        .map_err(|e| bad_request(format!("passport validation failed: {e}")))?;

    let passport_hash = passport_store::passport_hash(&passport)
        .map_err(|e| internal_error(format!("passport hash failed: {e}")))?;
    passport_store::append_passport_record(
        &state.passport_log_path,
        &passport_store::PassportRecord {
            passport_id: passport.body.passport_id.clone(),
            agent_id: passport.body.subject.agent_id.clone(),
            passport_hash: passport_hash.clone(),
            issued_at,
            expires_at,
        },
    )
    .map_err(|e| internal_error(format!("passport log write error: {e}")))?;

    tracing::info!(
        passport_id = %passport.body.passport_id,
        agent_id = %passport.body.subject.agent_id,
        passport_hash = %passport_hash,
        "passport issued"
    );

    Ok(Json(PassportIssueResponse {
        passport,
        passport_hash,
    }))
}

// ── POST /v1/passports/verify ────────────────────────────────────────────────

pub async fn verify_passport(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<PassportVerifyRequest>,
) -> Json<PassportVerifyResponse> {
    let passport = req.passport;
    match passport_store::verify_passport_ed25519(&passport, now_unix_seconds()) {
        Ok(()) => Json(PassportVerifyResponse {
            valid: true,
            status: "PASS",
            reason: None,
            passport_id: Some(passport.body.passport_id),
            agent_id: Some(passport.body.subject.agent_id),
            capabilities: passport.body.constraints.capabilities,
            expires_at: Some(passport.body.constraints.expires_at),
        }),
        Err(reason) => Json(PassportVerifyResponse {
            valid: false,
            status: "TOXIC",
            reason: Some(reason),
            passport_id: Some(passport.body.passport_id),
            agent_id: Some(passport.body.subject.agent_id),
            capabilities: passport.body.constraints.capabilities,
            expires_at: Some(passport.body.constraints.expires_at),
        }),
    }
}

// ── GET /viewer ──────────────────────────────────────────────────────────────

pub async fn viewer() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("viewer.html"))
}
