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
    extract::{Path, State},
    http::StatusCode,
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

use crate::authority::{AuthorityGraph, AuthorityPath};
use crate::models::ErrorBody;
use crate::AppState;

type ApiError = (StatusCode, Json<ErrorBody>);

fn bad_request(msg: impl Into<String>) -> ApiError {
    (StatusCode::BAD_REQUEST, Json(ErrorBody { error: msg.into() }))
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

#[derive(Debug, Deserialize)]
pub struct ReceiptInput {
    pub receipt_system: String,
    pub receipt_id: String,
    pub receipt_content: String,
    /// If present, the receipt is countersigned by this counterparty.
    pub counterparty_id: Option<String>,
    /// 32-byte hex seed of the counterparty signing key (managed/dev mode).
    pub counterparty_seed_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
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
        return Err(format!("{label}: expected 32-byte seed, got {}", bytes.len()));
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

    Ok(verify_packet(&req.packet, &ctx))
}

// ─── HTTP handlers ─────────────────────────────────────────────────────────

pub async fn generate(
    State(state): State<Arc<AppState>>,
    Json(req): Json<GenerateRequest>,
) -> Result<Json<GenerateResponse>, ApiError> {
    let packet = generate_packet(&req).map_err(bad_request)?;
    let packet_id = state
        .vault
        .store(&packet)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorBody { error: e })))?;
    tracing::info!(packet_id = %packet_id, agent = %packet.agent.aip_id, "evidence packet generated");
    Ok(Json(GenerateResponse { packet_id, packet }))
}

pub async fn verify(
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerificationReport>, ApiError> {
    let report = verify_request(&req).map_err(bad_request)?;
    Ok(Json(report))
}

pub async fn get_evidence(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<EvidencePacket>, ApiError> {
    state
        .vault
        .get(&id)
        .map(Json)
        .ok_or_else(|| not_found(format!("no evidence packet with id {id}")))
}

pub async fn get_authority(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Json<AuthorityResponse> {
    let graph = AuthorityGraph::build(&state.vault);
    let action_authority = graph.who_authorized(&state.vault, &id);
    // When the query resolved to an action, attach the full accountability
    // graph (Human→…→Receipt) of the proving packet for visualization.
    let accountability_dot = action_authority
        .as_ref()
        .and_then(|p| state.vault.get(&p.packet_id))
        .map(|packet| crate::authority::graph_for_packet(&packet).to_dot());
    Json(AuthorityResponse {
        query: id.clone(),
        action_authority,
        accountability_dot,
        as_principal: graph.packets_for_principal(&id),
        as_agent: graph.packets_for_agent(&id),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{sample_generate_request, sample_packet};

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
        };
        let report = verify_request(&vreq).unwrap();
        assert!(report.valid, "failures: {:?}", report.failures());
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
        };
        let report = verify_request(&vreq).unwrap();
        assert!(!report.valid);
        assert!(report.tampered);
    }
}
