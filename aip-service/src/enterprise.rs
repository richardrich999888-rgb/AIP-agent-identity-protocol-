//! Read interfaces over the existing tenant-scoped evidence store.
//!
//! Inventory here means identities named in stored EvidencePackets. It is
//! neither a deployment registry nor independently observed process identity.
//! Collector observations are not currently ingested into this service; that
//! absence is reported explicitly instead of inferred from agent statements.

use std::{collections::BTreeMap, sync::Arc};

use axum::{
    extract::{MatchedPath, Path, Query, Request, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use aip_protocol::{EvidencePacket, VerificationReport};

use crate::{
    auth::{bearer_secret, Principal, Role},
    evidence::{verify_request_with_context, VerifyRequest},
    models::ErrorBody,
    AppState,
};

type ApiError = (StatusCode, Json<ErrorBody>);
const SOURCE: &str = "agent_signed_evidence_packet";

fn error(status: StatusCode, message: &str) -> ApiError {
    (
        status,
        Json(ErrorBody {
            error: message.into(),
        }),
    )
}

fn store_error(e: crate::store::StoreError) -> ApiError {
    tracing::error!(error = %e, "enterprise evidence store unavailable");
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "evidence store unavailable",
    )
}

fn valid_id(id: &str) -> Result<(), ApiError> {
    if id.is_empty()
        || id.len() > 256
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
    {
        return Err(error(StatusCode::BAD_REQUEST, "invalid identifier"));
    }
    Ok(())
}

/// A service-boundary backstop: a newly added mutation cannot accidentally
/// grant a Reader the Machine role's authority. Verification is computation,
/// not filing. Reader keys also cannot retrieve raw packets or export them.
pub async fn scope_and_audit(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let principal =
        bearer_secret(request.headers()).and_then(|secret| state.api_keys.authenticate(&secret));
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".into());
    if let Some(p) = &principal {
        let calculation = matches!(
            route.as_str(),
            "/v1/evidence/verify" | "/v1/identity/verify"
        );
        let mutation = !matches!(
            *request.method(),
            Method::GET | Method::HEAD | Method::OPTIONS
        ) && !calculation;
        let raw_evidence = matches!(
            route.as_str(),
            "/v1/evidence/:id" | "/v1/evidence/:id/export" | "/v1/observations/:id"
        );
        if p.role == Role::Reader && (mutation || raw_evidence) {
            tracing::info!(tenant = %p.tenant_id, key_id = %p.key_id, route, status = 403, "evidence access");
            return error(
                StatusCode::FORBIDDEN,
                "reader credential does not permit this operation",
            )
            .into_response();
        }
    }
    let response = next.run(request).await;
    if let Some(p) = principal {
        // Route templates, not user input or evidence contents. A read is
        // auditable without placing transaction data or credentials in logs.
        tracing::info!(tenant = %p.tenant_id, key_id = %p.key_id, route,
            status = response.status().as_u16(), "evidence access");
    } else if response.status() == StatusCode::UNAUTHORIZED {
        tracing::info!(
            route,
            status = 401,
            "unauthenticated evidence access refused"
        );
    }
    response
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
}
fn default_limit() -> usize {
    50
}
impl PageQuery {
    pub(crate) fn validate(&self) -> Result<(), ApiError> {
        if !(1..=100).contains(&self.limit) || self.offset > 100_000 {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "limit must be 1..100 and offset at most 100000",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub limit: usize,
    pub offset: usize,
    pub next_offset: Option<usize>,
}
impl<T> Page<T> {
    pub(crate) fn from_items(items: Vec<T>, query: &PageQuery) -> Self {
        let more = items.len() > query.limit;
        Self {
            items: items.into_iter().take(query.limit).collect(),
            limit: query.limit,
            offset: query.offset,
            next_offset: more.then_some(query.offset + query.limit),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AgentSummary {
    pub agent_id: String,
    pub evidence_count: usize,
    pub latest_created_at_ms: u64,
    pub identity_source: &'static str,
    pub independent_identity_verified: bool,
}

async fn summaries(state: &AppState, principal: &Principal) -> Result<Vec<AgentSummary>, ApiError> {
    let packets = state
        .store
        .all_for_tenant(&principal.tenant_id)
        .await
        .map_err(store_error)?;
    let mut agents = BTreeMap::<String, AgentSummary>::new();
    for packet in packets {
        let entry = agents
            .entry(packet.agent.aip_id.clone())
            .or_insert(AgentSummary {
                agent_id: packet.agent.aip_id,
                evidence_count: 0,
                latest_created_at_ms: 0,
                identity_source: SOURCE,
                independent_identity_verified: false,
            });
        entry.evidence_count += 1;
        entry.latest_created_at_ms = entry.latest_created_at_ms.max(packet.created_at);
    }
    Ok(agents.into_values().collect())
}

pub async fn agents(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Query(query): Query<PageQuery>,
) -> Result<Json<Page<AgentSummary>>, ApiError> {
    query.validate()?;
    let rows = summaries(&state, &principal).await?;
    Ok(Json(Page::from_items(
        rows.into_iter()
            .skip(query.offset)
            .take(query.limit + 1)
            .collect(),
        &query,
    )))
}

pub async fn agent(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<String>,
) -> Result<Json<AgentSummary>, ApiError> {
    valid_id(&id)?;
    summaries(&state, &principal)
        .await?
        .into_iter()
        .find(|a| a.agent_id == id)
        .map(Json)
        .ok_or_else(|| error(StatusCode::NOT_FOUND, "not found"))
}

#[derive(Debug, Serialize)]
pub struct EvidenceMetadata {
    pub evidence_id: String,
    pub agent_id: String,
    pub created_at_ms: u64,
    pub decision_id: String,
    pub action_count: usize,
    pub evidence_source: &'static str,
    pub independent_execution_verified: bool,
}
impl From<&EvidencePacket> for EvidenceMetadata {
    fn from(packet: &EvidencePacket) -> Self {
        Self {
            evidence_id: packet.packet_id_hex(),
            agent_id: packet.agent.aip_id.clone(),
            created_at_ms: packet.created_at,
            decision_id: hex::encode(packet.decision.decision_id),
            action_count: packet.actions.len(),
            evidence_source: SOURCE,
            independent_execution_verified: false,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AgentActivity {
    pub agent_id: String,
    #[serde(flatten)]
    pub page: Page<EvidenceMetadata>,
}
pub async fn activity(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<String>,
    Query(query): Query<PageQuery>,
) -> Result<Json<AgentActivity>, ApiError> {
    valid_id(&id)?;
    query.validate()?;
    let packets = state
        .store
        .all_for_tenant(&principal.tenant_id)
        .await
        .map_err(store_error)?;
    let mut items: Vec<EvidenceMetadata> = packets
        .iter()
        .filter(|p| p.agent.aip_id == id)
        .map(EvidenceMetadata::from)
        .collect();
    if items.is_empty() {
        return Err(error(StatusCode::NOT_FOUND, "not found"));
    }
    items.sort_by(|a, b| (a.created_at_ms, &a.evidence_id).cmp(&(b.created_at_ms, &b.evidence_id)));
    Ok(Json(AgentActivity {
        agent_id: id,
        page: Page::from_items(
            items
                .into_iter()
                .skip(query.offset)
                .take(query.limit + 1)
                .collect(),
            &query,
        ),
    }))
}

async fn packet(
    state: &AppState,
    principal: &Principal,
    id: &str,
) -> Result<EvidencePacket, ApiError> {
    valid_id(id)?;
    state
        .store
        .get(&principal.tenant_id, id)
        .await
        .map_err(store_error)?
        .ok_or_else(|| error(StatusCode::NOT_FOUND, "not found"))
}
pub async fn evidence_metadata(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<String>,
) -> Result<Json<EvidenceMetadata>, ApiError> {
    Ok(Json(EvidenceMetadata::from(
        &packet(&state, &principal, &id).await?,
    )))
}

#[derive(Debug, Serialize)]
pub struct StoredVerification {
    pub evidence_id: String,
    pub verification_scope: &'static str,
    pub report: VerificationReport,
    pub limitations: Vec<&'static str>,
}
pub async fn verify_stored(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<String>,
) -> Result<Json<StoredVerification>, ApiError> {
    let packet = packet(&state, &principal, &id).await?;
    let revoked =
        crate::revocation::evidence_jtis_for_tenant(&state.revocation_set, &principal.tenant_id);
    let req = VerifyRequest {
        packet,
        trusted_issuers: Default::default(),
        trusted_counterparties: Default::default(),
        revoked_jtis: Vec::new(),
        trace_data: None,
        receipt_data: None,
        verification_time_ms: None,
        future_tolerance_ms: None,
        check_replay: false,
    };
    let report = verify_request_with_context(&req, None, &revoked).map_err(|_| {
        error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "verification unavailable",
        )
    })?;
    Ok(Json(StoredVerification { evidence_id: id, verification_scope: "integrity_only", report,
        limitations: vec!["Institutional issuer and counterparty trust anchors are not configured for this read endpoint.",
            "Agent-signed statements do not establish independently observed execution.",
            "Replay history, trace contents and receipt contents are not evaluated by this endpoint."] }))
}

#[derive(Serialize)]
pub struct Access {
    tenant_id: String,
    key_id: String,
    role: Role,
}
pub async fn access(principal: Principal) -> Json<Access> {
    Json(Access {
        tenant_id: principal.tenant_id,
        key_id: principal.key_id,
        role: principal.role,
    })
}

#[derive(Serialize)]
pub struct Coverage {
    status: &'static str,
    reason: &'static str,
    independent_execution_verified: bool,
}
pub async fn coverage(_principal: Principal) -> Json<Coverage> {
    Json(Coverage {
        status: "unavailable",
        reason: "collector_observation_pipeline_not_connected",
        independent_execution_verified: false,
    })
}

#[derive(Serialize)]
pub struct Health {
    status: &'static str,
    service: &'static str,
    version: &'static str,
    evidence_store: &'static str,
    observation_pipeline: &'static str,
    probe_health: &'static str,
    collector_health: &'static str,
}
pub async fn health(
    State(state): State<Arc<AppState>>,
    _principal: Principal,
) -> Result<Json<Health>, ApiError> {
    state.store.count().await.map_err(store_error)?;
    state.artifacts.check_health().await.map_err(|e| {
        tracing::error!(error=%e,"artifact store readiness failed");
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "artifact store unavailable",
        )
    })?;
    Ok(Json(Health {
        status: "ok",
        service: "aip",
        version: env!("CARGO_PKG_VERSION"),
        evidence_store: "reachable",
        observation_pipeline: "not_connected",
        probe_health: "unavailable",
        collector_health: "unavailable",
    }))
}
