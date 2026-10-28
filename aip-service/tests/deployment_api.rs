//! Real service router and persisted configuration. No fixture here is an
//! observation, an institutional identity binding or an authorization token.
use airon_aip::{
    auth::ApiKeyStore, deployments::DeploymentRegistry, store::JsonlEvidenceStore, ManagedSigning,
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::{json, Value};
use std::{path::PathBuf, sync::Arc};
use tower::ServiceExt;
mod support;

const ADMIN_A: &str = "registry-test-admin-a";
const ADMIN_B: &str = "registry-test-admin-b";
const READER_A: &str = "registry-test-reader-a";
const MACHINE_A: &str = "registry-test-machine-a";

fn temp(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("vanian-registry-{tag}-{}", uuid::Uuid::new_v4()))
}

fn definition(name: &str) -> Value {
    json!({"schema_version":"vanian.deployment.v1", "deployment_name":name,
        "workloads":[{"host_id":"agent-linux-01", "admin_group":"platform", "probe_id":"probe-01",
            "transport_public_key_hex":"ab".repeat(32), "logical_agent_ids":["agent:research"]}],
        "collector":{"host_id":"collector-01", "admin_group":"audit", "observer_id":"observer-01", "noise_public_key_hex":"cd".repeat(32)},
        "retention_days_requested":90, "contextforge":true, "evidence_mcp":true})
}

fn state() -> Arc<airon_aip::AppState> {
    let key_path = temp("keys");
    let entries: Vec<_> = [(ADMIN_A,"admin-a","tenant-a","admin"),(ADMIN_B,"admin-b","tenant-b","admin"),
        (READER_A,"reader-a","tenant-a","reader"),(MACHINE_A,"machine-a","tenant-a","machine")].into_iter()
        .map(|(secret,id,tenant,role)| json!({"key_id":id,"tenant_id":tenant,"role":role,"secret_sha256":hex::encode(aip_crypto::sha256(secret.as_bytes()))})).collect();
    std::fs::write(&key_path, json!({"keys":entries}).to_string()).unwrap();
    let keys = ApiKeyStore::load(key_path.to_str().unwrap());
    std::fs::remove_file(key_path).unwrap();
    support::app_state(
        Arc::new(JsonlEvidenceStore::load(temp("vault").to_str().unwrap())),
        keys,
        ManagedSigning::Refused,
    )
}

fn app(registry: Arc<DeploymentRegistry>) -> axum::Router {
    airon_aip::ingress::harden(
        airon_aip::router_with_deployments(state(), registry),
        Default::default(),
    )
}
async fn call(
    app: &axum::Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(
            request
                .body(
                    body.map(|b| Body::from(b.to_string()))
                        .unwrap_or(Body::empty()),
                )
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let raw = axum::body::to_bytes(response.into_body(), 128 * 1024)
        .await
        .unwrap();
    (status, serde_json::from_slice(&raw).unwrap_or(Value::Null))
}

#[tokio::test]
async fn default_is_disabled_and_authentication_remains_required() {
    let app = app(Arc::new(DeploymentRegistry::disabled()));
    assert_eq!(
        call(&app, "GET", "/v1/deployments", None, None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, "GET", "/v1/deployments", Some(READER_A), None)
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/deployments",
            Some(ADMIN_A),
            Some(definition("research"))
        )
        .await
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn only_administrator_can_register_and_caller_cannot_set_tenant_or_assurance() {
    let path = temp("role");
    let registry = Arc::new(DeploymentRegistry::open(&path).unwrap());
    let app = app(registry.clone());
    for token in [READER_A, MACHINE_A] {
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/deployments",
                Some(token),
                Some(definition("research"))
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        let request = Request::builder()
            .method("POST")
            .uri("/v1/deployments")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from("malformed"))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
    for field in [
        "tenant_id",
        "observer_active",
        "pilot_accepted",
        "private_key",
        "trust_anchors",
    ] {
        let mut value = definition("research");
        value[field] = json!("forged");
        assert_eq!(
            call(&app, "POST", "/v1/deployments", Some(ADMIN_A), Some(value))
                .await
                .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
    assert!(registry.records("tenant-a").unwrap().is_empty());
    drop(app);
    drop(registry);
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn registration_is_tenant_scoped_and_never_upgrades_assurance() {
    let path = temp("tenancy");
    let registry = Arc::new(DeploymentRegistry::open(&path).unwrap());
    let app = app(registry.clone());
    let (status, value) = call(
        &app,
        "POST",
        "/v1/deployments",
        Some(ADMIN_A),
        Some(definition("research")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(value["tenant_id"], "tenant-a");
    assert_eq!(value["registered_by_key_id"], "admin-a");
    assert_eq!(value["configuration_status"], "CONFIGURATION_VALID");
    for field in [
        "installed",
        "observer_active",
        "signed_evidence_available",
        "authorization_verified",
        "execution_reconciled",
        "pilot_accepted",
    ] {
        assert_eq!(value[field], "NOT_ASSESSED");
    }
    assert_eq!(value["trust_anchors_modified"], false);
    assert_eq!(value["retention_enforced"], false);
    assert_eq!(
        call(
            &app,
            "GET",
            "/v1/deployments/research",
            Some(READER_A),
            None
        )
        .await
        .1,
        value
    );
    assert_eq!(
        call(&app, "GET", "/v1/deployments/research", Some(ADMIN_B), None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&app, "GET", "/v1/deployments", Some(ADMIN_B), None)
            .await
            .1["items"],
        json!([])
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/deployments",
            Some(ADMIN_B),
            Some(definition("research"))
        )
        .await
        .0,
        StatusCode::CREATED
    );
    assert_eq!(
        call(&app, "GET", "/v1/coverage", Some(READER_A), None)
            .await
            .1["status"],
        "unavailable"
    );
    drop(app);
    drop(registry);
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn idempotency_conflicts_restart_and_pagination_preserve_records() {
    let path = temp("restart");
    let registry = Arc::new(DeploymentRegistry::open(&path).unwrap());
    let router = app(registry.clone());
    let (_, original) = call(
        &router,
        "POST",
        "/v1/deployments",
        Some(ADMIN_A),
        Some(definition("a")),
    )
    .await;
    let again = call(
        &router,
        "POST",
        "/v1/deployments",
        Some(ADMIN_A),
        Some(definition("a")),
    )
    .await;
    assert_eq!(again, (StatusCode::OK, original.clone()));
    let mut changed = definition("a");
    changed["retention_days_requested"] = json!(91);
    assert_eq!(
        call(
            &router,
            "POST",
            "/v1/deployments",
            Some(ADMIN_A),
            Some(changed)
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        call(
            &router,
            "POST",
            "/v1/deployments",
            Some(ADMIN_A),
            Some(definition("b"))
        )
        .await
        .0,
        StatusCode::CREATED
    );
    let page = call(
        &router,
        "GET",
        "/v1/deployments?limit=1&offset=0",
        Some(READER_A),
        None,
    )
    .await
    .1;
    assert_eq!(page["next_offset"], 1);
    assert_eq!(page["items"][0]["deployment_name"], "a");
    assert!(page["items"][0].get("definition").is_none());
    for query in [
        "limit=0",
        "limit=101",
        "offset=100001",
        "tenant_id=tenant-b",
    ] {
        assert_eq!(
            call(
                &router,
                "GET",
                &format!("/v1/deployments?{query}"),
                Some(READER_A),
                None
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
    drop(router);
    drop(registry);
    let registry = Arc::new(DeploymentRegistry::open(&path).unwrap());
    let router = app(registry.clone());
    assert_eq!(
        call(&router, "GET", "/v1/deployments/a", Some(READER_A), None)
            .await
            .1,
        original
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);
    drop(router);
    drop(registry);
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn invalid_topology_collisions_and_oversize_requests_are_refused() {
    let path = temp("invalid");
    let registry = Arc::new(DeploymentRegistry::open(&path).unwrap());
    let app = app(registry.clone());
    let mut changes = Vec::new();
    let mut v = definition("a");
    v["collector"]["host_id"] = json!("agent-linux-01");
    changes.push(v);
    let mut v = definition("a");
    v["collector"]["admin_group"] = json!("platform");
    changes.push(v);
    let mut v = definition("a");
    v["workloads"][0]["transport_public_key_hex"] = json!("00".repeat(32));
    changes.push(v);
    let mut v = definition("a");
    let repeated = v["workloads"][0].clone();
    v["workloads"].as_array_mut().unwrap().push(repeated);
    changes.push(v);
    let mut v = definition("a");
    v["retention_days_requested"] = json!(0);
    changes.push(v);
    for value in changes {
        assert_eq!(
            call(&app, "POST", "/v1/deployments", Some(ADMIN_A), Some(value))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }
    let mut v = definition("a");
    v["workloads"][0]["logical_agent_ids"] = json!(["x".repeat(40 * 1024)]);
    assert_eq!(
        call(&app, "POST", "/v1/deployments", Some(ADMIN_A), Some(v))
            .await
            .0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    drop(app);
    drop(registry);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn journal_refuses_corruption_repeated_records_and_concurrent_writers() {
    let path = temp("corruption");
    let registry = DeploymentRegistry::open(&path).unwrap();
    assert!(DeploymentRegistry::open(&path).is_err());
    drop(registry);
    for bytes in [b"broken\n".as_slice(), b"\n", b"{}"] {
        std::fs::write(&path, bytes).unwrap();
        assert!(DeploymentRegistry::open(&path).is_err());
    }
    std::fs::remove_file(path).unwrap();
    assert!(DeploymentRegistry::open(&temp("missing-parent").join("registry.jsonl")).is_err());
}

#[cfg(unix)]
#[test]
fn journal_refuses_symlinks_and_world_readable_configuration() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let path = temp("permissions");
    drop(DeploymentRegistry::open(&path).unwrap());
    let link = temp("link");
    symlink(&path, &link).unwrap();
    assert!(DeploymentRegistry::open(&link).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(DeploymentRegistry::open(&path).is_err());
    std::fs::remove_file(link).unwrap();
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
#[ignore = "explicit real HTTP SDK validation; requires Python/Node environments"]
async fn real_http_registry_clients() {
    let path = temp("http");
    let registry = Arc::new(DeploymentRegistry::open(&path).unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = app(registry.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let script = std::env::var("VANIAN_REGISTRY_SMOKE").expect("set VANIAN_REGISTRY_SMOKE");
    let python = std::env::var("VANIAN_REGISTRY_PYTHON").unwrap_or_else(|_| "python3".into());
    let status = tokio::process::Command::new(python)
        .arg(script)
        .env("VANIAN_REGISTRY_URL", format!("http://{address}"))
        .env("VANIAN_REGISTRY_ADMIN", ADMIN_A)
        .env("VANIAN_REGISTRY_OTHER", ADMIN_B)
        .env("VANIAN_REGISTRY_READER", READER_A)
        .env("VANIAN_REGISTRY_MACHINE", MACHINE_A)
        .status()
        .await;
    server.abort();
    assert!(status.unwrap().success());
    drop(registry);
    let _ = std::fs::remove_file(path);
}
