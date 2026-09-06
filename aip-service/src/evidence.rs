//! Evidence Service v1 — generate and verify EvidencePackets over HTTP.
//!
//! This module is the productization of `aip-protocol`. It exposes:
//!   POST /v1/evidence/generate   build + sign + store + index a packet
//!   POST /v1/evidence/verify     verify a packet against caller-supplied keys
//!   GET  /v1/evidence/{id}        fetch a stored packet
//!   GET  /v1/authority/{id}       authority-graph query (action / principal / agent)
//!
//! ## Key custody (migration note)
//! `/evidence/generate` signs the packet with an agent seed supplied in the
//! request. This is appropriate for the **single-tenant / managed reference
//! deployment** and for SDK-backed testing. In production, agents sign
//! client-side via an SDK and the service is used for verify + ingest only;
//! the request schema is forward-compatible with that split (the authority
//! tokens are already supplied pre-signed).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, State},
    http::{
        header::{CONTENT_DISPOSITION, CONTENT_TYPE},
        StatusCode,
    },
    response::Response,
    Json,
};
use serde::{Deserialize, Serialize};

use aip_crypto::{derive_aip_id, sha256};
use aip_protocol::{
    verify_packet, ActionAttestation, AgentIdentitySummary, DecisionRecord, EvidencePacket,
    EvidencePacketBuilder, ReceiptBinding, RootAuthority, TraceBinding, TrustFloor,
    VerificationContext, VerificationReport,
};
use aip_types::{
    Action, AlgorithmId, DelegationToken, ProvenanceTriple, PublicKey, ScopeAction, ScopedToken,
};

use crate::auth::Principal;
use crate::authority::{AuthorityGraph, AuthorityPath};
use crate::models::ErrorBody;
use crate::AppState;

type ApiError = (StatusCode, Json<ErrorBody>);

fn bad_request(msg: impl Into<String>) -> ApiError {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorBody { error: msg.into() }),
    )
}

fn not_found(msg: impl Into<String>) -> ApiError {
    (StatusCode::NOT_FOUND, Json(ErrorBody { error: msg.into() }))
}

// ─── Request / response schemas ────────────────────────────────────────────

/// A scope action expressed as a string; standard verbs map to [`Action`],
/// anything else becomes a custom scope action.
fn parse_scope_action(s: &str) -> ScopeAction {
    match s.to_ascii_lowercase().as_str() {
        "read" => ScopeAction::Standard(Action::Read),
        "write" => ScopeAction::Standard(Action::Write),
        "delete" => ScopeAction::Standard(Action::Delete),
        "admin" => ScopeAction::Standard(Action::Admin),
        "execute" => ScopeAction::Standard(Action::Execute),
        "delegate" => ScopeAction::Standard(Action::Delegate),
        other => ScopeAction::Custom(other.to_string()),
    }
}

#[derive(Debug, Deserialize)]
pub struct ProvenanceInput {
    pub model: String,
    pub environment: String,
    pub toolchain: String,
}

impl ProvenanceInput {
    pub fn to_triple(&self) -> ProvenanceTriple {
        ProvenanceTriple {
            model_commitment: sha256(self.model.as_bytes()),
            environment_commitment: sha256(self.environment.as_bytes()),
            toolchain_commitment: sha256(self.toolchain.as_bytes()),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct DecisionInput {
    pub action_kind: String,
    pub summary: String,
    /// Raw decision inputs; hashed into `input_hash`.
    pub input: String,
    /// Raw rationale; hashed into `rationale_hash`.
    pub rationale: String,
}

#[derive(Debug, Deserialize)]
pub struct ActionInput {
    pub action_kind: String,
    pub description: String,
    /// Raw action payload; hashed into `payload_hash`.
    pub payload: String,
}

#[derive(Debug, Deserialize)]
pub struct TraceInput {
    pub trace_id: String,
    pub trace_data: String,
}

#[derive(Deserialize)]
pub struct ReceiptInput {
    pub receipt_system: String,
    pub receipt_id: String,
    pub receipt_content: String,
    /// If present, the receipt is countersigned by this counterparty.
    pub counterparty_id: Option<String>,
    /// 32-byte hex seed of the counterparty signing key (managed/dev mode).
    pub counterparty_seed_hex: Option<String>,
}

#[derive(Deserialize)]
pub struct GenerateRequest {
    /// 32-byte hex seed of the acting agent's Ed25519 key.
    pub agent_seed_hex: String,
    pub provenance: ProvenanceInput,
    pub principal_id: String,
    pub principal_role: String,
    /// Root scoped token, already signed by the principal.
    pub root_token: ScopedToken,
    /// Delegation chain (each hop pre-signed), possibly empty.
    #[serde(default)]
    pub delegation_chain: Vec<DelegationToken>,
    pub decision: DecisionInput,
    pub actions: Vec<ActionInput>,
    #[serde(default)]
    pub trace: Option<TraceInput>,
    #[serde(default)]
    pub receipt: Option<ReceiptInput>,
    #[serde(default)]
    pub claimed_trust_floor: Option<TrustFloor>,
}

/// Redacting `Debug`. Derived `Debug` on a struct holding a private seed is
/// a leak waiting for the first `tracing::debug!(?req)` or `unwrap` panic
/// message; the field is printed as a placeholder instead (AUDIT B-7).
/// The presence of a seed is still visible, because whether one was supplied
/// is operationally relevant and is not itself secret.
/// Redacting `Debug`. Derived `Debug` on a struct holding a private seed is
/// a leak waiting for the first `tracing::debug!(?req)` or panic message that
/// formats it; the field is printed as a placeholder instead (AUDIT B-7).
/// Whether a seed was supplied is still visible, because that is
/// operationally relevant and is not itself secret.
impl std::fmt::Debug for GenerateRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenerateRequest")
            .field("agent_seed_hex", &"<redacted>")
            .field("provenance", &self.provenance)
            .field("principal_id", &self.principal_id)
            .field("principal_role", &self.principal_role)
            .field("root_token", &self.root_token)
            .field("delegation_chain", &self.delegation_chain)
            .field("decision", &self.decision)
            .field("actions", &self.actions)
            .field("trace", &self.trace)
            .field("receipt", &self.receipt)
            .field("claimed_trust_floor", &self.claimed_trust_floor)
            .finish()
    }
}

/// Redacting `Debug`; see [`GenerateRequest`]'s impl.
impl std::fmt::Debug for ReceiptInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiptInput")
            .field("receipt_system", &self.receipt_system)
            .field("receipt_id", &self.receipt_id)
            .field("receipt_content", &self.receipt_content)
            .field("counterparty_id", &self.counterparty_id)
            .field(
                "counterparty_seed_hex",
                &self.counterparty_seed_hex.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Debug, Serialize)]
pub struct GenerateResponse {
    pub packet_id: String,
    pub packet: EvidencePacket,
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub packet: EvidencePacket,
    /// AIP-ID → Ed25519 public key (hex) for the principal and each issuer.
    #[serde(default)]
    pub trusted_issuers: HashMap<String, String>,
    #[serde(default)]
    pub trusted_counterparties: HashMap<String, String>,
    /// JTIs (16-byte hex) the verifier considers revoked.
    #[serde(default)]
    pub revoked_jtis: Vec<String>,
    /// Raw trace data to cross-check against the packet's trace_hash.
    #[serde(default)]
    pub trace_data: Option<String>,
    /// Raw receipt data to cross-check against the packet's receipt_hash.
    #[serde(default)]
    pub receipt_data: Option<String>,
    /// Verify as of this Unix-ms instant instead of the service's own clock.
    ///
    /// For replaying a historical verification, or for an offline caller that
    /// knows the time it means. **Omitted is not unbounded**: the service
    /// substitutes its own clock, so the default path is the bounded one
    /// (AUDIT B-1a).
    #[serde(default)]
    pub verification_time_ms: Option<u64>,
    /// Slack allowed ahead of the verification time, absorbing declared clock
    /// skew. Defaults to zero: a tolerance is a bound, not a licence.
    #[serde(default)]
    pub future_tolerance_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct AuthorityResponse {
    pub query: String,
    /// Set when the query id resolved to a specific action.
    pub action_authority: Option<AuthorityPath>,
    /// Graphviz DOT of the full Human→…→Receipt chain, when an action resolved.
    pub accountability_dot: Option<String>,
    /// Packets where the query id is the root principal.
    pub as_principal: Vec<String>,
    /// Packets where the query id is the acting agent.
    pub as_agent: Vec<String>,
}

// ─── Core logic (pure, unit-testable without HTTP) ─────────────────────────

fn seed_from_hex(label: &str, hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("{label}: invalid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "{label}: expected 32-byte seed, got {}",
            bytes.len()
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

fn public_key_from_seed(seed: &[u8; 32]) -> Vec<u8> {
    use ed25519_dalek::SigningKey;
    SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
        .to_vec()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Build, sign, and return an EvidencePacket from a generate request.
/// Pure: performs no I/O.
pub fn generate_packet(req: &GenerateRequest) -> Result<EvidencePacket, String> {
    if req.actions.is_empty() {
        return Err("at least one action is required".into());
    }

    let agent_seed = seed_from_hex("agent_seed_hex", &req.agent_seed_hex)?;
    let agent_pubkey = public_key_from_seed(&agent_seed);
    let provenance = req.provenance.to_triple();
    let agent_id = derive_aip_id(&agent_pubkey, &provenance);

    let agent = AgentIdentitySummary {
        aip_id: agent_id.clone(),
        public_key: PublicKey {
            algorithm: AlgorithmId::Ed25519,
            key_bytes: agent_pubkey,
        },
        provenance,
    };

    let root_authority = RootAuthority {
        principal_id: req.principal_id.clone(),
        display_role: req.principal_role.clone(),
        root_token: req.root_token.clone(),
    };

    let decided_at = now_ms();
    let decision = DecisionRecord {
        decision_id: aip_core::capability::random_jti(),
        action_kind: parse_scope_action(&req.decision.action_kind),
        summary: req.decision.summary.clone(),
        input_hash: sha256(req.decision.input.as_bytes()),
        rationale_hash: sha256(req.decision.rationale.as_bytes()),
        decided_at,
    };

    let mut builder = EvidencePacketBuilder::new(agent, root_authority)
        .delegation_chain(req.delegation_chain.clone())
        .decision(decision.clone())
        .claimed_trust_floor(req.claimed_trust_floor.unwrap_or(TrustFloor::AgentSigned));

    for (i, a) in req.actions.iter().enumerate() {
        let attestation = ActionAttestation::create(
            &agent_id,
            &agent_seed,
            &decision.decision_id,
            parse_scope_action(&a.action_kind),
            &a.description,
            sha256(a.payload.as_bytes()),
            decided_at + 1 + i as u64,
        )
        .map_err(|e| format!("action attestation: {e}"))?;
        builder = builder.action(attestation);
    }

    if let Some(t) = &req.trace {
        builder = builder.trace(TraceBinding {
            trace_id: t.trace_id.clone(),
            trace_hash: sha256(t.trace_data.as_bytes()),
        });
    }

    if let Some(r) = &req.receipt {
        let mut receipt = ReceiptBinding {
            receipt_system: r.receipt_system.clone(),
            receipt_id: r.receipt_id.clone(),
            receipt_hash: sha256(r.receipt_content.as_bytes()),
            counterparty_id: None,
            counterparty_sig: None,
        };
        if let (Some(cp_id), Some(cp_seed_hex)) = (&r.counterparty_id, &r.counterparty_seed_hex) {
            let cp_seed = seed_from_hex("counterparty_seed_hex", cp_seed_hex)?;
            receipt
                .countersign(&decision.decision_id, cp_id, &cp_seed)
                .map_err(|e| format!("receipt countersign: {e}"))?;
        }
        builder = builder.receipt(receipt);
    }

    builder
        .build_and_sign(&agent_seed)
        .map_err(|e| format!("seal packet: {e}"))
}

/// Verify a packet against caller-supplied trust context. Pure.
///
/// Trust-boundary note: `trusted_issuers` / `trusted_counterparties` are the
/// *caller's* trust anchors. This endpoint is a deterministic calculator over
/// the packet and those anchors — it does not decide who is a legitimate
/// issuer, and a `valid` report means "consistent with the anchors the caller
/// supplied", not "authorized by this service". Authorization decisions
/// belong to an independent decision point, which this service is not.
pub fn verify_request(req: &VerifyRequest) -> Result<VerificationReport, String> {
    let mut ctx = VerificationContext::new();

    for (id, pk_hex) in &req.trusted_issuers {
        let pk = hex::decode(pk_hex).map_err(|e| format!("issuer {id} key hex: {e}"))?;
        ctx.issuer_public_keys.insert(id.clone(), pk);
    }
    for (id, pk_hex) in &req.trusted_counterparties {
        let pk = hex::decode(pk_hex).map_err(|e| format!("counterparty {id} key hex: {e}"))?;
        ctx.counterparty_public_keys.insert(id.clone(), pk);
    }
    let mut revoked: HashSet<[u8; 16]> = HashSet::new();
    for jti_hex in &req.revoked_jtis {
        let bytes = hex::decode(jti_hex).map_err(|e| format!("revoked jti hex: {e}"))?;
        if bytes.len() != 16 {
            return Err(format!("revoked jti must be 16 bytes, got {}", bytes.len()));
        }
        let mut jti = [0u8; 16];
        jti.copy_from_slice(&bytes);
        revoked.insert(jti);
    }
    ctx.revoked_jtis = revoked;
    ctx.trace_data = req.trace_data.as_ref().map(|s| s.as_bytes().to_vec());
    ctx.receipt_data = req.receipt_data.as_ref().map(|s| s.as_bytes().to_vec());

    // AUDIT B-1a. R16 is opt-in at the protocol layer, and correctly so: an
    // offline verifier must be able to say what "now" means to it, and an
    // unevaluated rule must not read as a failure. But opt-in propagates only
    // as far as someone remembers to opt in, and this tier did not — so every
    // service verification was unbounded and a future-dated packet returned
    // `valid: true`.
    //
    // The default is now the service's own clock. A caller may override it to
    // replay a historical verification, but omitting the field no longer
    // means "apply no bound"; it means "apply the bound the service knows".
    // The unsafe path has to be asked for explicitly, and cannot be reached
    // through this API at all.
    // `now_ms` is this module's existing clock helper — the protocol verifier
    // is deliberately clock-free so offline verification stays possible, and
    // this tier is online by definition, so it is where the time is known.
    ctx.verification_time_ms = Some(req.verification_time_ms.unwrap_or_else(now_ms));
    ctx.future_tolerance_ms = req.future_tolerance_ms.unwrap_or(0);

    Ok(verify_packet(&req.packet, &ctx))
}

// ─── HTTP handlers ─────────────────────────────────────────────────────────

// Authenticated (Machine or Admin). The tenant comes from the caller's key,
// never from the request body — a caller cannot write into another tenant.
pub async fn generate(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Json(req): Json<GenerateRequest>,
) -> Result<Json<GenerateResponse>, ApiError> {
    let packet = generate_packet(&req).map_err(bad_request)?;
    let packet_id = state
        .store
        .store(&principal.tenant_id, &packet)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: e.to_string(),
                }),
            )
        })?;
    // `managed_signed` is recorded on every packet produced this way so that
    // an auditor reading the service's logs can tell which packets carry a
    // signature the service itself could have produced (AUDIT B-7).
    tracing::info!(
        packet_id = %packet_id,
        tenant = %principal.tenant_id,
        agent = %packet.agent.aip_id,
        managed_signed = true,
        "evidence packet generated"
    );
    Ok(Json(GenerateResponse { packet_id, packet }))
}

/// The handler routed in place of [`generate`] when managed signing is
/// refused (AUDIT B-7).
///
/// Takes no body extractor on purpose: a caller that sends a private seed
/// here has it rejected by the routing table, not parsed and then declined.
/// The seed never reaches serde, a log line, or this process's heap.
///
/// 501 rather than 403: the endpoint is not disabled for *this caller*, it is
/// not implemented by this deployment. A 403 would invite a client to retry
/// with different credentials.
pub async fn generate_refused() -> ApiError {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(ErrorBody {
            error: "managed signing is not enabled on this deployment. \
                    POST /v1/evidence/generate requires the agent's private \
                    seed in the request body, which would place the signing \
                    key in every proxy, log and trace on the path and would \
                    make the resulting packet unable to distinguish the agent \
                    from this service. Sign client-side and submit the sealed \
                    packet to /v1/evidence/verify instead. A deployment that \
                    has accepted those costs sets AIP_ALLOW_MANAGED_SIGNING=1."
                .into(),
        }),
    )
}

// Authenticated but stateless: verification is a pure function of the packet
// and caller-supplied keys, so it is not tenant-scoped. Auth still required
// (no anonymous use of the service).
pub async fn verify(
    _principal: Principal,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerificationReport>, ApiError> {
    let report = verify_request(&req).map_err(bad_request)?;
    Ok(Json(report))
}

pub async fn get_evidence(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<String>,
) -> Result<Json<EvidencePacket>, ApiError> {
    let found = state
        .store
        .get(&principal.tenant_id, &id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: e.to_string(),
                }),
            )
        })?;
    // "not found" for both missing and wrong-tenant — no existence leak.
    found
        .map(Json)
        .ok_or_else(|| not_found(format!("no evidence packet with id {id}")))
}

// GET /v1/evidence/{id}/export — signed audit-export bundle (application/zip).
// Tenant-scoped: only the owning tenant can export. The bundled verification
// report is integrity-level (the service holds no external trust keys); the
// recipient runs `aip-verify bundle.zip [--trust ...]` for full verification.
pub async fn export_evidence(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let packet = state
        .store
        .get(&principal.tenant_id, &id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: e.to_string(),
                }),
            )
        })?
        // not found for both missing and wrong-tenant — no existence leak.
        .ok_or_else(|| not_found(format!("no evidence packet with id {id}")))?;

    let report = verify_packet(&packet, &VerificationContext::new());
    let zip = aip_protocol::build_zip(
        &principal.tenant_id,
        &packet,
        &report,
        &state.signer_seed,
        &state.signer_public,
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: format!("bundle build failed: {e}"),
            }),
        )
    })?;

    tracing::info!(packet_id = %id, tenant = %principal.tenant_id, bytes = zip.len(), "audit-export bundle generated");

    let filename = format!("aip-evidence-{id}.zip");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/zip")
        .header(
            CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .body(Body::from(zip))
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: e.to_string(),
                }),
            )
        })
}

pub async fn get_authority(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<String>,
) -> Result<Json<AuthorityResponse>, ApiError> {
    let tenant = &principal.tenant_id;
    let packets = state.store.all_for_tenant(tenant).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: e.to_string(),
            }),
        )
    })?;
    let graph = AuthorityGraph::from_packets(packets);
    let action_authority = graph.who_authorized(&id);
    // When the query resolved to an action, attach the full accountability
    // graph (Human→…→Receipt) of the proving packet for visualization.
    let accountability_dot = graph
        .packet_for_action(&id)
        .map(|packet| crate::authority::graph_for_packet(packet).to_dot());
    Ok(Json(AuthorityResponse {
        query: id.clone(),
        action_authority,
        accountability_dot,
        as_principal: graph.packets_for_principal(&id),
        as_agent: graph.packets_for_agent(&id),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{sample_generate_request, sample_packet, test_app_state};

    fn temp_vault() -> String {
        let mut p = std::env::temp_dir();
        p.push(format!("aip_export_test_{}.jsonl", uuid::Uuid::new_v4()));
        p.to_str().unwrap().to_owned()
    }

    #[tokio::test]
    async fn test_export_endpoint_roundtrip_and_tenant_isolation() {
        use crate::auth::{ApiKeyStore, Role};
        use crate::store::{EvidenceStore, JsonlEvidenceStore};
        use axum::body::Body as AxBody;
        use axum::http::Request;
        use tower::ServiceExt;

        let path = temp_vault();
        let store = std::sync::Arc::new(JsonlEvidenceStore::load(&path));
        let (packet, _) = sample_packet();
        store.store("acme", &packet).await.unwrap();
        let id = packet.packet_id_hex();

        let api_keys = ApiKeyStore::from_entries(vec![
            ("acme-secret", "k-acme", "acme", Role::Machine),
            ("other-secret", "k-other", "other", Role::Machine),
        ]);
        let state = test_app_state(store, api_keys);
        // Kept so the bundle can be verified against the key that signed it
        // (AUDIT B-4) rather than against a key the bundle supplies.
        let signer_public = state.signer_public;
        let app = crate::router(state);

        // Owning tenant exports → 200 application/zip, verifies offline.
        let resp = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/evidence/{id}/export"))
                    .header("authorization", "Bearer acme-secret")
                    .body(AxBody::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/zip"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        // Anchored on the service's own signer key (AUDIT B-4). Verifying
        // without an anchor would establish only that the bundle is
        // internally consistent — which a forgery also is — so anchoring is
        // what makes this an assertion about *this* service's export.
        let v = aip_protocol::verify_zip(
            &bytes,
            &VerificationContext::new().trust_bundle_signer(&signer_public),
        );
        assert_ne!(
            v.overall,
            aip_protocol::BundleStatus::Fail,
            "exported bundle must verify: {:?}",
            v.checks
        );
        let trust = v
            .checks
            .iter()
            .find(|c| c.name == "BUNDLE_SIGNER_TRUSTED")
            .expect("R5a present");
        assert_eq!(
            trust.status,
            aip_protocol::BundleStatus::Pass,
            "the export must be attributable to this service: {}",
            trust.detail
        );

        // Different tenant → 404 (no existence leak), no bundle produced.
        let resp2 = app
            .oneshot(
                Request::get(format!("/v1/evidence/{id}/export"))
                    .header("authorization", "Bearer other-secret")
                    .body(AxBody::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp2.status(), 404);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_generate_then_verify_roundtrip() {
        let (req, ctx_keys) = sample_generate_request();
        let packet = generate_packet(&req).expect("generation must succeed");

        // Build a verify request using the issuer keys the fixture exposes.
        let vreq = VerifyRequest {
            packet,
            trusted_issuers: ctx_keys,
            trusted_counterparties: HashMap::new(),
            revoked_jtis: vec![],
            trace_data: None,
            receipt_data: None,
            verification_time_ms: None,
            future_tolerance_ms: None,
        };
        let report = verify_request(&vreq).unwrap();
        assert!(report.valid, "failures: {:?}", report.failures());
        assert!(report.authority_chain_verified);
    }

    /// Characterization (Skill 5): `generate_packet` records, it does not
    /// decide. A caller holding only its own key can self-issue an admin root
    /// token, have the service seal a packet exercising it, and then have
    /// `verify_request` accept it by naming its own key as the trusted
    /// issuer. This pins the closed loop the Stage 2 decision point exists to
    /// break; the endpoint itself is unchanged in Stage 2.
    #[test]
    fn weakness_generate_then_verify_accepts_self_issued_authority() {
        use aip_core::capability::{issue_scoped_token, scope_admin};
        use aip_crypto::derive_aip_id;

        let (mut req, _) = sample_generate_request();
        let seed = seed_from_hex("agent_seed_hex", &req.agent_seed_hex).unwrap();
        let agent_pub = public_key_from_seed(&seed);
        let agent_id = derive_aip_id(&agent_pub, &req.provenance.to_triple());

        // Agent issues itself an ADMIN root token; no delegation chain.
        req.root_token =
            issue_scoped_token(&agent_id, &seed, &agent_id, scope_admin(), Some(3_600_000))
                .unwrap();
        req.delegation_chain.clear();
        req.principal_id = agent_id.clone();
        req.decision.action_kind = "admin".into();
        req.actions[0].action_kind = "admin".into();

        let packet = generate_packet(&req).expect("the service seals whatever it is told");

        let vreq = VerifyRequest {
            packet,
            trusted_issuers: HashMap::from([(agent_id, hex::encode(&agent_pub))]),
            trusted_counterparties: HashMap::new(),
            revoked_jtis: vec![],
            trace_data: None,
            receipt_data: None,
            verification_time_ms: None,
            future_tolerance_ms: None,
        };
        let report = verify_request(&vreq).unwrap();
        assert!(report.valid, "{:?}", report.failures());
        assert!(report.authority_chain_verified);
    }

    #[test]
    fn test_generate_requires_action() {
        let (mut req, _) = sample_generate_request();
        req.actions.clear();
        assert!(generate_packet(&req).is_err());
    }

    #[test]
    fn test_verify_detects_tamper() {
        let (mut packet, ctx_keys) = sample_packet();
        packet.decision.summary = "tampered".into();
        let vreq = VerifyRequest {
            packet,
            trusted_issuers: ctx_keys,
            trusted_counterparties: HashMap::new(),
            revoked_jtis: vec![],
            trace_data: None,
            receipt_data: None,
            verification_time_ms: None,
            future_tolerance_ms: None,
        };
        let report = verify_request(&vreq).unwrap();
        assert!(!report.valid);
        assert!(report.tampered);
    }
}
