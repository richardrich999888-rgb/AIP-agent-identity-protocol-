//! Tenant-scoped filing of immutable same-run records. The service recomputes
//! evaluation under administrator-provisioned anchors and checkpoints; callers
//! cannot supply trust keys or turn a historical archive into live coverage.
use std::{collections::BTreeMap, sync::Arc};

use aip_mcp_gateway::assurance::{evaluate_run, RunBundle, RunEvaluation, RunTrustConfig};
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header::CONTENT_TYPE, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    artifacts::{ArtifactKind, ArtifactStoreError, StoredArtifact},
    auth::{Principal, Role},
    enterprise::{Page, PageQuery},
    models::ErrorBody,
    AppState,
};

type ApiError = (StatusCode, Json<ErrorBody>);
pub const MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;
const SCOPE: &str = "same_run_evaluation";

fn error(status: StatusCode, message: &str) -> ApiError {
    (
        status,
        Json(ErrorBody {
            error: message.into(),
        }),
    )
}
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}
fn hash_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Trust is read at service startup from a separately configured public file.
/// There is no API that replaces these anchors or retained archive digests.
#[derive(Default)]
pub struct RunTrustStore {
    entries: BTreeMap<(String, String), RunTrustConfig>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustFile {
    tenants: Vec<TrustEntry>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustEntry {
    tenant_id: String,
    trust: RunTrustConfig,
}

impl RunTrustStore {
    pub fn load(path: Option<&str>) -> Result<Self, String> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        if path.trim().is_empty() {
            return Err("AIP_RUN_TRUST_PATH must not be empty".into());
        }
        let metadata = std::fs::metadata(path).map_err(|_| "cannot read same-run trust file")?;
        if metadata.len() > 1024 * 1024 {
            return Err("same-run trust file exceeds 1 MiB".into());
        }
        let text = std::fs::read_to_string(path).map_err(|_| "cannot read same-run trust file")?;
        Self::from_json(&text)
    }
    pub fn from_json(text: &str) -> Result<Self, String> {
        let config: TrustFile =
            serde_json::from_str(text).map_err(|_| "invalid same-run trust configuration")?;
        if config.tenants.len() > 1024 {
            return Err("too many same-run trust entries".into());
        }
        let mut result = Self::default();
        for entry in config.tenants {
            let trust = &entry.trust;
            trust.validate()?;
            if !valid_id(&entry.tenant_id)
                || !valid_id(&trust.agent_id)
                || !valid_id(&trust.decision_point_id)
                || !valid_id(&trust.gateway_id)
                || !valid_id(&trust.observer_id)
                || trust.gateway_key_version == 0
                || trust.observer_key_version == 0
                || [
                    &trust.agent_public_key_hex,
                    &trust.decision_point_public_key_hex,
                    &trust.gateway_public_key_hex,
                    &trust.observer_public_key_hex,
                ]
                .iter()
                .any(|key| !hash_hex(key))
                || trust.checkpoints.len() > 4096
                || trust.checkpoints.iter().any(|(id, cp)| {
                    !valid_id(id) || !hash_hex(&cp.batches_sha256) || !hash_hex(&cp.health_sha256)
                })
            {
                return Err("invalid same-run trust identifiers, anchors or checkpoints".into());
            }
            let key = (entry.tenant_id, trust.agent_id.clone());
            if result.entries.insert(key, entry.trust).is_some() {
                return Err("duplicate tenant/agent same-run trust entry".into());
            }
        }
        Ok(result)
    }
    fn evaluate(&self, tenant: &str, bundle: &RunBundle) -> Result<RunEvaluation, ApiError> {
        if self.entries.is_empty() {
            return Err(error(
                StatusCode::SERVICE_UNAVAILABLE,
                "same-run admission has no configured trust",
            ));
        }
        let trust = self
            .entries
            .get(&(tenant.into(), bundle.agent_id.clone()))
            .ok_or_else(|| {
                error(
                    StatusCode::FORBIDDEN,
                    "same-run trust is not approved for this tenant and agent",
                )
            })?;
        evaluate_run(bundle, trust).map_err(|_| {
            error(
                StatusCode::BAD_REQUEST,
                "same-run signatures, checkpoint or binding did not verify; record not admitted",
            )
        })
    }
}

fn parse_bundle(body: &str) -> Result<RunBundle, ApiError> {
    if body.len() > MAX_BUNDLE_BYTES {
        return Err(error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "same-run bundle exceeds 16 MiB",
        ));
    }
    let bundle: RunBundle = serde_json::from_str(body)
        .map_err(|_| error(StatusCode::BAD_REQUEST, "invalid same-run bundle"))?;
    if !valid_id(&bundle.run_id) || !valid_id(&bundle.agent_id) {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "invalid run or agent identifier",
        ));
    }
    Ok(bundle)
}
fn artifact_id(tenant: &str, body: &str) -> String {
    let mut bytes = b"VANIAN/RunBundle/v1\0".to_vec();
    bytes.extend_from_slice(&(tenant.len() as u64).to_be_bytes());
    bytes.extend_from_slice(tenant.as_bytes());
    bytes.extend_from_slice(body.as_bytes());
    hex::encode(aip_crypto::sha256(&bytes))
}
fn store_error(err: ArtifactStoreError) -> ApiError {
    if err == ArtifactStoreError::TenantConflict {
        return error(StatusCode::NOT_FOUND, "not found");
    }
    tracing::error!(error=%err, "same-run artifact store");
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "same-run artifact store unavailable",
    )
}

#[derive(Serialize)]
pub struct RunMetadata {
    pub run_artifact_id: String,
    pub run_id: String,
    pub agent_id: String,
    pub bundle_sha256: String,
    pub batches_sha256: String,
    pub health_sha256: String,
    pub verification_scope: &'static str,
    pub evaluation: RunEvaluation,
}
fn describe(id: String, body: &str, bundle: &RunBundle, evaluation: RunEvaluation) -> RunMetadata {
    RunMetadata {
        run_artifact_id: id,
        run_id: bundle.run_id.clone(),
        agent_id: bundle.agent_id.clone(),
        bundle_sha256: hex::encode(aip_crypto::sha256(body.as_bytes())),
        batches_sha256: hex::encode(aip_crypto::sha256(bundle.batches_jsonl.as_bytes())),
        health_sha256: hex::encode(aip_crypto::sha256(bundle.health_jsonl.as_bytes())),
        verification_scope: SCOPE,
        evaluation,
    }
}

pub async fn submit(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    body: Bytes,
) -> Result<Json<RunMetadata>, ApiError> {
    if principal.role == Role::Reader {
        return Err(error(StatusCode::FORBIDDEN, "writer credential required"));
    }
    if body.len() > MAX_BUNDLE_BYTES {
        return Err(error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "same-run bundle exceeds 16 MiB",
        ));
    }
    let body = std::str::from_utf8(&body)
        .map_err(|_| error(StatusCode::BAD_REQUEST, "same-run JSON must be UTF-8"))?;
    let bundle = parse_bundle(body)?;
    let evaluation = state.run_trust.evaluate(&principal.tenant_id, &bundle)?;
    let id = artifact_id(&principal.tenant_id, body);
    state
        .artifacts
        .put(StoredArtifact {
            id: id.clone(),
            kind: ArtifactKind::RunBundle,
            tenant_id: principal.tenant_id,
            agent_id: Some(bundle.agent_id.clone()),
            from_ms: None,
            to_ms: None,
            stored_at_ms: crate::store::now_ms() as i64,
            body: body.into(),
        })
        .await
        .map_err(store_error)?;
    Ok(Json(describe(id, body, &bundle, evaluation)))
}

async fn load(
    state: &AppState,
    principal: &Principal,
    id: &str,
) -> Result<(String, RunBundle, RunEvaluation), ApiError> {
    if !hash_hex(id) {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "invalid run artifact identifier",
        ));
    }
    let record = state
        .artifacts
        .get(&principal.tenant_id, ArtifactKind::RunBundle, id)
        .await
        .map_err(store_error)?
        .ok_or_else(|| error(StatusCode::NOT_FOUND, "not found"))?;
    if artifact_id(&principal.tenant_id, &record.body) != id {
        return Err(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "stored run artifact digest mismatch",
        ));
    }
    let bundle = parse_bundle(&record.body).map_err(|_| {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "stored run bundle is damaged",
        )
    })?;
    if record.agent_id.as_deref() != Some(bundle.agent_id.as_str()) {
        return Err(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "stored run agent index mismatch",
        ));
    }
    let evaluation = state.run_trust.evaluate(&principal.tenant_id, &bundle)?;
    Ok((record.body, bundle, evaluation))
}

pub async fn metadata(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<String>,
) -> Result<Json<RunMetadata>, ApiError> {
    let (body, bundle, evaluation) = load(&state, &principal, &id).await?;
    Ok(Json(describe(id, &body, &bundle, evaluation)))
}
pub async fn evaluation(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<String>,
) -> Result<Json<RunEvaluation>, ApiError> {
    Ok(Json(load(&state, &principal, &id).await?.2))
}
pub async fn verdict(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<String>,
) -> Result<Json<aip_reconcile::SignedReconciliation>, ApiError> {
    let (_, bundle, evaluation) = load(&state, &principal, &id).await?;
    if !evaluation.signed_reconciliation_verified {
        return Err(error(
            StatusCode::NOT_FOUND,
            "no verified signed reconciliation for this run",
        ));
    }
    Ok(Json(bundle.signed_reconciliation.ok_or_else(|| {
        error(
            StatusCode::NOT_FOUND,
            "no signed reconciliation for this run",
        )
    })?))
}
pub async fn raw(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    if principal.role == Role::Reader {
        return Err(error(
            StatusCode::FORBIDDEN,
            "raw run retrieval requires writer access",
        ));
    }
    let (body, _, _) = load(&state, &principal, &id).await?;
    Ok(([(CONTENT_TYPE, "application/json")], body).into_response())
}
pub async fn for_agent(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(agent): Path<String>,
    Query(query): Query<PageQuery>,
) -> Result<Json<Page<RunMetadata>>, ApiError> {
    query.validate()?;
    if !valid_id(&agent) {
        return Err(error(StatusCode::BAD_REQUEST, "invalid agent identifier"));
    }
    let records = state
        .artifacts
        .for_agent(&principal.tenant_id, ArtifactKind::RunBundle, &agent)
        .await
        .map_err(store_error)?;
    let mut metadata = Vec::new();
    for record in records.into_iter().skip(query.offset).take(query.limit + 1) {
        let (body, bundle, evaluation) = load(&state, &principal, &record.id).await?;
        metadata.push(describe(record.id, &body, &bundle, evaluation));
    }
    Ok(Json(Page::from_items(metadata, &query)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absent_or_broken_trust_is_not_an_implicit_approval() {
        assert!(RunTrustStore::load(None).unwrap().entries.is_empty());
        assert!(RunTrustStore::load(Some("")).is_err());
        assert!(RunTrustStore::from_json("{\"tenants\":[],\"caller_approved\":true}").is_err());
        assert_ne!(artifact_id("a", "{}"), artifact_id("b", "{}"));
        assert_ne!(artifact_id("a", "{}"), artifact_id("a", "{}\n"));
    }
}
