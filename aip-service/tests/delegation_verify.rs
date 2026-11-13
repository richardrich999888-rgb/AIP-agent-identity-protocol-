//! Authenticated, tenant-bound verification of signed AIP delegation chains.

mod support;

use std::sync::Arc;

use aip_core::{capability::token_signing_payload, delegation::delegation_signing_payload};
use aip_crypto::sign_ed25519;
use airon_aip::{
    agent_trust::AgentTrustStore,
    revocation::{self, RevocationEntry},
    store::{EvidenceStore, JsonlEvidenceStore},
    ManagedSigning,
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use support::{api_key_store, app_state_with_agent_trust, now_ms, packet_dated, Fixture};
use tower::ServiceExt;

const MACHINE_SECRET: &str = "delegation-verify-machine-secret";
const TENANT: &str = "acme";

fn trust_store(fixture: &Fixture, tenant: &str) -> AgentTrustStore {
    let anchors: Vec<_> = fixture
        .issuers
        .iter()
        .map(|(agent_id, public_key_hex)| {
            serde_json::json!({
                "tenant_id": tenant,
                "agent_id": agent_id,
                "public_key_hex": public_key_hex,
            })
        })
        .collect();

    AgentTrustStore::from_json(&serde_json::json!({ "anchors": anchors }).to_string())
        .expect("valid trust configuration")
}

fn empty_trust_store() -> AgentTrustStore {
    AgentTrustStore::from_json(r#"{"anchors":[]}"#).expect("empty trust configuration")
}

fn setup(
    fixture: &Fixture,
    trust: AgentTrustStore,
) -> (Router, Arc<airon_aip::AppState>, std::path::PathBuf) {
    let (api_keys, key_path) = api_key_store(MACHINE_SECRET, TENANT);

    let mut evidence_path = std::env::temp_dir();
    evidence_path.push(format!(
        "aip_delegation_verify_{}.jsonl",
        uuid::Uuid::new_v4()
    ));

    let store: Arc<dyn EvidenceStore> = Arc::new(JsonlEvidenceStore::load(
        evidence_path.to_str().expect("evidence path"),
    ));

    let state = app_state_with_agent_trust(store, api_keys, ManagedSigning::Refused, trust);

    let app = airon_aip::router(state.clone());
    let _ = fixture;
    (app, state, key_path)
}

async fn verify_call(
    app: &Router,
    body: serde_json::Value,
    bearer: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/v1/delegations/verify")
        .header("content-type", "application/json");

    if let Some(secret) = bearer {
        builder = builder.header("authorization", format!("Bearer {secret}"));
    }

    let request = builder.body(Body::from(body.to_string())).expect("request");

    let response = app.clone().oneshot(request).await.expect("router response");

    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");

    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);

    (status, json)
}

fn request_body(fixture: &Fixture) -> serde_json::Value {
    serde_json::json!({
        "root_token": fixture.packet.root_authority.root_token,
        "chain": fixture.packet.delegation_chain,
    })
}

#[tokio::test]
async fn verifies_a_valid_signed_chain_with_tenant_anchors() {
    let fixture = packet_dated(0);
    let trust = trust_store(&fixture, TENANT);
    let (app, _, _) = setup(&fixture, trust);

    let (status, body) = verify_call(&app, request_body(&fixture), Some(MACHINE_SECRET)).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["valid"], true);
    assert_eq!(body["tenant_id"], TENANT);
    assert_eq!(body["chain_depth"], 1);
    assert_eq!(
        body["leaf_agent_id"],
        fixture.packet.delegation_chain[0].grantee_id
    );
    assert!(body["trust_config_sha256"].is_string());
}

#[tokio::test]
async fn rejects_verification_when_trust_store_is_empty() {
    let fixture = packet_dated(0);
    let (app, _, _) = setup(&fixture, empty_trust_store());

    let (status, body) = verify_call(&app, request_body(&fixture), Some(MACHINE_SECRET)).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
}

#[tokio::test]
async fn rejects_issuer_anchors_configured_for_another_tenant() {
    let fixture = packet_dated(0);
    let trust = trust_store(&fixture, "globex");
    let (app, _, _) = setup(&fixture, trust);

    let (status, body) = verify_call(&app, request_body(&fixture), Some(MACHINE_SECRET)).await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn rejects_a_tampered_delegation_signature() {
    let mut fixture = packet_dated(0);
    let trust = trust_store(&fixture, TENANT);

    fixture.packet.delegation_chain[0]
        .issuer_sig
        .signature_bytes[0] ^= 1;

    let (app, _, _) = setup(&fixture, trust);

    let (status, body) = verify_call(&app, request_body(&fixture), Some(MACHINE_SECRET)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
}

#[tokio::test]
async fn rejects_a_revoked_root_token_for_its_tenant() {
    let fixture = packet_dated(0);
    let trust = trust_store(&fixture, TENANT);
    let (app, state, _) = setup(&fixture, trust);

    let root_jti = hex::encode(fixture.packet.root_authority.root_token.jti);
    let entry = RevocationEntry::new(
        TENANT,
        &root_jti,
        "integration-test",
        "delegation verification revocation test",
    );

    revocation::revoke(&state.revocation_log_path, &state.revocation_set, &entry)
        .expect("record revocation");

    let (status, body) = verify_call(&app, request_body(&fixture), Some(MACHINE_SECRET)).await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn rejects_a_validly_signed_future_issued_root_token() {
    let mut fixture = packet_dated(0);
    let trust = trust_store(&fixture, TENANT);

    let root = &mut fixture.packet.root_authority.root_token;
    root.issued_at = now_ms() + 60_000;
    let private_key = &fixture.issuer_private_keys[&root.issuer_id];
    root.issuer_sig = sign_ed25519(private_key, &root.issuer_id, &token_signing_payload(root))
        .expect("re-sign future-dated root");

    let (app, _, _) = setup(&fixture, trust);
    let (status, body) = verify_call(&app, request_body(&fixture), Some(MACHINE_SECRET)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
}

#[tokio::test]
async fn rejects_a_validly_signed_future_issued_delegation_hop() {
    let mut fixture = packet_dated(0);
    let trust = trust_store(&fixture, TENANT);

    let hop = &mut fixture.packet.delegation_chain[0];
    hop.issued_at = now_ms() + 60_000;
    let private_key = &fixture.issuer_private_keys[&hop.issuer_id];
    hop.issuer_sig = sign_ed25519(
        private_key,
        &hop.issuer_id,
        &delegation_signing_payload(hop),
    )
    .expect("re-sign future-dated delegation");

    let (app, _, _) = setup(&fixture, trust);
    let (status, body) = verify_call(&app, request_body(&fixture), Some(MACHINE_SECRET)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
}

#[tokio::test]
async fn rejects_an_unauthenticated_verification_request() {
    let fixture = packet_dated(0);
    let trust = trust_store(&fixture, TENANT);
    let (app, _, _) = setup(&fixture, trust);

    let (status, _) = verify_call(&app, request_body(&fixture), None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
