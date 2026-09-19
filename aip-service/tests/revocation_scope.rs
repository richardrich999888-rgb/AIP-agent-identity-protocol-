//! Revocation is a tenant-scoped, authenticated fact — and evidence
//! verification consults it.
//!
//! # The findings these tests pin
//!
//! 1. The unsigned delegation routes are gone. `POST /v1/identity/delegate`
//!    and `POST /v1/identity/verify-chain` were a second authority engine
//!    with no signatures, no attenuation at issuance and no tenancy. They no
//!    longer exist in the routing table.
//! 2. Revocation is scoped to the administrator's tenant. An administrator of
//!    tenant A cannot invalidate tenant B's token, and B cannot learn of A's
//!    revocations: `revocation-status` is authenticated and answers for the
//!    caller's tenant only.
//! 3. `POST /v1/evidence/verify` unions the caller's tenant's server-side
//!    revocations into the verification context. A chain JTI revoked through
//!    `POST /v1/identity/revoke` fails `REVOCATION` whether or not the caller
//!    lists it — and stays clear for a tenant that did not revoke it.

use aip_protocol::verification_report::rules;
use aip_protocol::VerificationReport;
use airon_aip::store::{EvidenceStore, JsonlEvidenceStore};
use airon_aip::ManagedSigning;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use std::sync::Arc;
use tower::ServiceExt;

mod support;
use support::{app_state, packet_dated};

const ACME_MACHINE: &str = "acme-machine-secret";
const ACME_ADMIN: &str = "acme-admin-secret";
const GLOBEX_MACHINE: &str = "globex-machine-secret";
const GLOBEX_ADMIN: &str = "globex-admin-secret";

/// Two tenants, each with a machine key and an admin key, through the real
/// key-file loader.
fn two_tenant_keys() -> airon_aip::auth::ApiKeyStore {
    let mut path = std::env::temp_dir();
    path.push(format!("aip_rev_scope_keys_{}.json", uuid::Uuid::new_v4()));
    let entry = |id: &str, secret: &str, tenant: &str, role: &str| {
        serde_json::json!({
            "key_id": id,
            "secret_sha256": hex::encode(aip_crypto::sha256(secret.as_bytes())),
            "tenant_id": tenant,
            "role": role,
        })
    };
    std::fs::write(
        &path,
        serde_json::json!({ "keys": [
            entry("acme-m", ACME_MACHINE, "acme", "machine"),
            entry("acme-a", ACME_ADMIN, "acme", "admin"),
            entry("globex-m", GLOBEX_MACHINE, "globex", "machine"),
            entry("globex-a", GLOBEX_ADMIN, "globex", "admin"),
        ]})
        .to_string(),
    )
    .expect("write keys");
    let store = airon_aip::auth::ApiKeyStore::load(path.to_str().expect("utf-8"));
    assert!(!store.is_empty());
    store
}

fn app() -> axum::Router {
    let mut path = std::env::temp_dir();
    path.push(format!("aip_rev_scope_{}.jsonl", uuid::Uuid::new_v4()));
    let store: Arc<dyn EvidenceStore> =
        Arc::new(JsonlEvidenceStore::load(path.to_str().expect("utf-8 path")));
    airon_aip::router(app_state(store, two_tenant_keys(), ManagedSigning::Refused))
}

async fn call(
    app: &axum::Router,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(b) = bearer {
        req = req.header("authorization", format!("Bearer {b}"));
    }
    let req = match body {
        Some(v) => req
            .header("content-type", "application/json")
            .body(Body::from(v.to_string())),
        None => req.body(Body::empty()),
    }
    .expect("request");
    let resp = app.clone().oneshot(req).await.expect("response");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// The `jti` claim of a JWT, read from its payload segment. The test reads
/// the token the way a relying party would, without the signing key.
fn jti_of(token: &str) -> String {
    let payload = token.split('.').nth(1).expect("three-segment JWT");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("base64url payload");
    let claims: serde_json::Value = serde_json::from_slice(&bytes).expect("claims json");
    claims["jti"].as_str().expect("jti claim").to_owned()
}

async fn issue_token(app: &axum::Router, bearer: &str) -> String {
    let (status, body) = call(
        app,
        "POST",
        "/v1/identity/issue",
        Some(bearer),
        Some(serde_json::json!({
            "agent_id": uuid::Uuid::new_v4().to_string(),
            "agent_type": "service",
            "ttl_seconds": 600,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "issue: {body}");
    body["token"].as_str().expect("token").to_owned()
}

async fn verify_token(app: &axum::Router, token: &str) -> (bool, Option<String>) {
    let (status, body) = call(
        app,
        "POST",
        "/v1/identity/verify",
        None,
        Some(serde_json::json!({ "token": token })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    (
        body["valid"].as_bool().expect("valid"),
        body["reason"].as_str().map(str::to_owned),
    )
}

async fn revoke(app: &axum::Router, bearer: &str, jti: &str) -> (StatusCode, serde_json::Value) {
    call(
        app,
        "POST",
        "/v1/identity/revoke",
        Some(bearer),
        Some(serde_json::json!({
            "jti": jti,
            "revoked_by": "ops-oncall",
            "reason": "test",
        })),
    )
    .await
}

// ── 1. The second authority engine is gone ────────────────────────────────────

#[tokio::test]
async fn the_unsigned_delegation_routes_no_longer_exist() {
    let app = app();
    for path in ["/v1/identity/delegate", "/v1/identity/verify-chain"] {
        let (status, _) = call(
            &app,
            "POST",
            path,
            Some(ACME_ADMIN),
            Some(serde_json::json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path} must not be routed");
    }
}

#[tokio::test]
async fn the_discovery_document_advertises_no_delegation_endpoint() {
    let app = app();
    let (status, body) = call(&app, "GET", "/.well-known/aip-configuration", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.get("delegation_endpoint").is_none(), "{body}");
    assert!(body.get("delegation_max_depth").is_none(), "{body}");
    assert!(body.get("revocation_endpoint").is_some(), "{body}");
}

// ── 2. Revocation is authenticated, admin-only and tenant-scoped ──────────────

#[tokio::test]
async fn a_machine_key_cannot_revoke_and_an_anonymous_caller_cannot_query_status() {
    let app = app();
    let token = issue_token(&app, ACME_MACHINE).await;
    let jti = jti_of(&token);

    let (status, _) = revoke(&app, ACME_MACHINE, &jti).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "machine role must not revoke"
    );

    let (status, _) = call(
        &app,
        "GET",
        &format!("/v1/identity/revocation-status/{jti}"),
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "revocation status was a public oracle over every tenant's log"
    );

    let (valid, _) = verify_token(&app, &token).await;
    assert!(valid, "nothing above may have revoked the token");
}

#[tokio::test]
async fn another_tenants_admin_cannot_revoke_this_tenants_token() {
    let app = app();
    let token = issue_token(&app, ACME_MACHINE).await;
    let jti = jti_of(&token);

    // Globex's administrator revokes Acme's JTI string. The call succeeds —
    // there is no error that would tell Globex whether the JTI exists
    // elsewhere — but it is recorded in Globex's namespace and is inert.
    let (status, body) = revoke(&app, GLOBEX_ADMIN, &jti).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (valid, reason) = verify_token(&app, &token).await;
    assert!(
        valid,
        "a foreign tenant's revocation must not bind: {reason:?}"
    );

    // Globex sees its own record; Acme does not.
    let (_, seen_by_globex) = call(
        &app,
        "GET",
        &format!("/v1/identity/revocation-status/{jti}"),
        Some(GLOBEX_MACHINE),
        None,
    )
    .await;
    assert_eq!(seen_by_globex["revoked"], true);
    let (_, seen_by_acme) = call(
        &app,
        "GET",
        &format!("/v1/identity/revocation-status/{jti}"),
        Some(ACME_MACHINE),
        None,
    )
    .await;
    assert_eq!(seen_by_acme["revoked"], false);
}

#[tokio::test]
async fn this_tenants_admin_revokes_this_tenants_token() {
    let app = app();
    let token = issue_token(&app, ACME_MACHINE).await;
    let jti = jti_of(&token);

    let (status, body) = revoke(&app, ACME_ADMIN, &jti).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["revoked_count"], 1);

    let (valid, reason) = verify_token(&app, &token).await;
    assert!(!valid);
    assert_eq!(reason.as_deref(), Some("token has been revoked"));

    let (_, status_body) = call(
        &app,
        "GET",
        &format!("/v1/identity/revocation-status/{jti}"),
        Some(ACME_MACHINE),
        None,
    )
    .await;
    assert_eq!(status_body["revoked"], true);
}

#[tokio::test]
async fn cascade_and_malformed_jtis_are_refused_not_ignored() {
    let app = app();
    let (status, body) = call(
        &app,
        "POST",
        "/v1/identity/revoke",
        Some(ACME_ADMIN),
        Some(serde_json::json!({
            "jti": uuid::Uuid::new_v4().to_string(),
            "revoked_by": "ops",
            "reason": "r",
            "cascade": true,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["error"].as_str().unwrap_or("").contains("cascade"));

    let (status, body) = revoke(&app, ACME_ADMIN, "not-a-token-id").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

// ── 3. Evidence verification consults the tenant's server-side revocations ───

async fn post_evidence_verify(
    app: &axum::Router,
    bearer: &str,
    fixture: &support::Fixture,
) -> VerificationReport {
    let (status, body) = call(
        app,
        "POST",
        "/v1/evidence/verify",
        Some(bearer),
        Some(serde_json::json!({
            "packet": fixture.packet,
            "trusted_issuers": fixture.issuers,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    serde_json::from_value(body).expect("verification report")
}

#[tokio::test]
async fn a_chain_jti_revoked_through_the_service_fails_revocation_for_that_tenant_only() {
    let app = app();
    let fixture = packet_dated(0);
    let root_jti = hex::encode(fixture.packet.root_authority.root_token.jti);

    // Before: clear for both tenants.
    for bearer in [ACME_MACHINE, GLOBEX_MACHINE] {
        let report = post_evidence_verify(&app, bearer, &fixture).await;
        let r = report
            .rule(rules::REVOCATION)
            .expect("REVOCATION evaluated");
        assert!(r.pass, "{bearer}: {}", r.detail);
    }

    // Acme's administrator revokes the root token — without the caller ever
    // listing it in `revoked_jtis`.
    let (status, body) = revoke(&app, ACME_ADMIN, &root_jti).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let acme = post_evidence_verify(&app, ACME_MACHINE, &fixture).await;
    let r = acme.rule(rules::REVOCATION).expect("REVOCATION evaluated");
    assert!(
        !r.pass,
        "the service's own revocation must bind: {}",
        r.detail
    );
    assert!(!acme.valid);
    assert!(!acme.revocation_clear);

    // Globex did not revoke it; Globex's verification is unaffected.
    let globex = post_evidence_verify(&app, GLOBEX_MACHINE, &fixture).await;
    let r = globex
        .rule(rules::REVOCATION)
        .expect("REVOCATION evaluated");
    assert!(r.pass, "{}", r.detail);
}
