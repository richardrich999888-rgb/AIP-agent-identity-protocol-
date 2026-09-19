//! HTTP routes for signed verdicts and access ledgers (R10).
//!
//! Four routes, one rule: **verify before storing, and return the bytes that
//! were verified**.
//!
//! The service adds no signature and re-serialises nothing. A response is
//! byte-identical to what was submitted, so an auditor pipes it into
//! `nexora-verify` with their own anchors and gets the same answer the
//! service got — which is the only reason to believe the service at all.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use aip_ledger::{AccessLedger, LedgerTrustAnchors};
use aip_reconcile::{ReconcilerTrustAnchors, SignedReconciliation};

use crate::artifacts::{ArtifactKind, StoredArtifact};
use crate::auth::Principal;
use crate::models::ErrorBody;
use crate::AppState;

type ApiError = (StatusCode, Json<ErrorBody>);

fn bad_request(msg: impl Into<String>) -> ApiError {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorBody { error: msg.into() }),
    )
}

/// Not-found and wrong-tenant are the same response, deliberately: a
/// distinguishable 403 would confirm that an id exists under some other
/// tenant, which is an existence oracle.
fn not_found() -> ApiError {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorBody {
            error: "not found".into(),
        }),
    )
}

fn store_error(e: crate::artifacts::ArtifactStoreError) -> ApiError {
    match e {
        // Same reasoning as above: an id held by another tenant reads as
        // absent rather than as a conflict.
        crate::artifacts::ArtifactStoreError::TenantConflict => not_found(),
        other => {
            tracing::error!(error = %other, "artifact store");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: "storage error".into(),
                }),
            )
        }
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Parse `id:version=hex` anchor entries.
///
/// The key version is part of the anchor because every signed artefact in
/// this system names the version it was signed under. An operator who
/// rotates a key must be able to say which version they are trusting, and an
/// old document must not silently verify against a new key.
fn parse_versioned_anchors(
    raw: &[String],
    what: &str,
) -> Result<Vec<(String, u32, Vec<u8>)>, ApiError> {
    let mut out = Vec::with_capacity(raw.len());
    for entry in raw {
        let (id_ver, hex_str) = entry
            .split_once('=')
            .ok_or_else(|| bad_request(format!("{what} expects ID:VERSION=HEX, got `{entry}`")))?;
        let (id, ver) = id_ver
            .rsplit_once(':')
            .ok_or_else(|| bad_request(format!("{what} expects ID:VERSION=HEX, got `{entry}`")))?;
        let version: u32 = ver
            .trim()
            .parse()
            .map_err(|_| bad_request(format!("{what}: key version `{ver}` is not a number")))?;
        let key = hex::decode(hex_str.trim())
            .map_err(|e| bad_request(format!("{what}: invalid key hex: {e}")))?;
        out.push((id.trim().to_string(), version, key));
    }
    if out.is_empty() {
        // A submission with no anchors cannot be verified, and storing an
        // unverified document is the one thing this tier must not do.
        return Err(bad_request(format!(
            "{what} is required: this service verifies a document before \
             storing it, and cannot verify one without an anchor"
        )));
    }
    Ok(out)
}

// ─── Verdicts ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SubmitVerdictRequest {
    /// The signed verdict, exactly as the reconciler produced it.
    pub verdict: SignedReconciliation,
    /// `reconciler_id:key_version=pubkey_hex`, repeatable.
    pub reconciler_anchors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct StoredResponse {
    pub id: String,
    pub kind: String,
}

/// `POST /v1/verdicts` — file a verdict this tenant stands behind.
///
/// The tenant comes from the caller's key. The verdict is verified under the
/// anchors in the request, which are the caller's statement of which
/// reconciler they trust; the service holds no such opinion of its own and
/// must not invent one.
pub async fn submit_verdict(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Json(req): Json<SubmitVerdictRequest>,
) -> Result<Json<StoredResponse>, ApiError> {
    let anchors_raw = parse_versioned_anchors(&req.reconciler_anchors, "reconciler_anchors")?;
    let mut anchors = ReconcilerTrustAnchors::new();
    for (id, version, key) in &anchors_raw {
        anchors = anchors.trust(id, *version, key);
    }
    req.verdict.verify(&anchors).map_err(|e| {
        // Counted before the error is returned: a rising rejection rate is
        // the signal that something is submitting documents this service
        // will not stand behind, and it is invisible in the store by
        // definition — nothing is stored.
        state.metrics.verdicts_rejected.incr();
        bad_request(format!(
            "verdict did not verify under the supplied anchors ({e:?}); \
             it is not stored"
        ))
    })?;

    // The id is a digest of the *document*, not of the JSON envelope, so two
    // serialisations of one verdict file under one id.
    let id = hex::encode(req.verdict.digest());
    // Verbatim bytes. A re-serialisation here would verify only if this
    // crate's serialiser agreed with the producer's.
    let body = serde_json::to_string(&req.verdict)
        .map_err(|e| bad_request(format!("verdict is not serialisable: {e}")))?;

    let stored = StoredArtifact {
        id: id.clone(),
        kind: ArtifactKind::Verdict,
        tenant_id: principal.tenant_id.clone(),
        // A `Reconciliation` names no agent: attribution is the reconciler's
        // finding, carried in evidence references, not a field to index on.
        agent_id: None,
        from_ms: None,
        to_ms: None,
        stored_at_ms: now_ms(),
        body,
    };
    let id = state.artifacts.put(stored).await.map_err(store_error)?;
    state.metrics.verdicts_stored.incr();
    Ok(Json(StoredResponse {
        id,
        kind: ArtifactKind::Verdict.as_str().to_string(),
    }))
}

/// `GET /v1/verdicts/:id` — the stored bytes, verbatim.
pub async fn get_verdict(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<String>,
) -> Result<(StatusCode, [(&'static str, &'static str); 1], String), ApiError> {
    let found = state
        .artifacts
        .get(&principal.tenant_id, ArtifactKind::Verdict, &id)
        .await
        .map_err(store_error)?
        .ok_or_else(not_found)?;
    Ok((
        StatusCode::OK,
        [("content-type", "application/json")],
        found.body,
    ))
}

// ─── Access ledgers ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SubmitLedgerRequest {
    pub ledger: AccessLedger,
    /// `ledger_signer_id:key_version=pubkey_hex`, repeatable.
    pub ledger_anchors: Vec<String>,
}

/// `POST /v1/ledgers` — file a per-agent access ledger.
pub async fn submit_ledger(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Json(req): Json<SubmitLedgerRequest>,
) -> Result<Json<StoredResponse>, ApiError> {
    let anchors_raw = parse_versioned_anchors(&req.ledger_anchors, "ledger_anchors")?;
    let mut anchors = LedgerTrustAnchors::new();
    for (id, version, key) in &anchors_raw {
        anchors = anchors.trust(id, *version, key);
    }
    req.ledger.verify(&anchors).map_err(|e| {
        state.metrics.ledgers_rejected.incr();
        bad_request(format!(
            "access ledger did not verify under the supplied anchors ({e:?}); \
             it is not stored"
        ))
    })?;

    let id = hex::encode(req.ledger.digest());
    let body = serde_json::to_string(&req.ledger)
        .map_err(|e| bad_request(format!("ledger is not serialisable: {e}")))?;

    let stored = StoredArtifact {
        id: id.clone(),
        kind: ArtifactKind::AccessLedger,
        tenant_id: principal.tenant_id.clone(),
        agent_id: Some(req.ledger.agent_id.clone()),
        from_ms: Some(req.ledger.window.from_ms as i64),
        to_ms: Some(req.ledger.window.to_ms as i64),
        stored_at_ms: now_ms(),
        body,
    };
    let id = state.artifacts.put(stored).await.map_err(store_error)?;
    state.metrics.ledgers_stored.incr();
    Ok(Json(StoredResponse {
        id,
        kind: ArtifactKind::AccessLedger.as_str().to_string(),
    }))
}

#[derive(Debug, Serialize)]
pub struct AgentLedgerResponse {
    pub agent_id: String,
    /// One entry per stored window, oldest first. Each `ledger` is the
    /// document verbatim; re-verify it with your own anchors.
    pub ledgers: Vec<serde_json::Value>,
}

/// `GET /v1/agents/:agent_id/ledger` — every window this tenant holds for
/// that agent, oldest first.
///
/// This is the endpoint an inspector asks. Each element is the signed
/// document, unchanged, so the answer does not depend on trusting the
/// service that served it.
pub async fn agent_ledger(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(agent_id): Path<String>,
) -> Result<Json<AgentLedgerResponse>, ApiError> {
    let rows = state
        .artifacts
        .for_agent(&principal.tenant_id, ArtifactKind::AccessLedger, &agent_id)
        .await
        .map_err(store_error)?;
    let mut ledgers = Vec::with_capacity(rows.len());
    for r in rows {
        // Parsed only to place it in a JSON array; the bytes are unchanged
        // in content, and a document that would not parse was never stored.
        ledgers.push(
            serde_json::from_str::<serde_json::Value>(&r.body).map_err(|e| {
                store_error(crate::artifacts::ArtifactStoreError::Backend(e.to_string()))
            })?,
        );
    }
    Ok(Json(AgentLedgerResponse { agent_id, ledgers }))
}
