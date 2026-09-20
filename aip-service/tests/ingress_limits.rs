//! R9b — the in-process ingress limits, over the real hardened router.
//!
//! The body cap is the one that matters and the one that is exercised here
//! end to end: a body over the limit is rejected with `413` before any
//! handler deserializes it. The timeout and the concurrency cap are
//! configuration wired through one function (`ingress::harden`) and unit
//! tested in `src/ingress.rs`; asserting a wall-clock timeout in a unit
//! test would be slow and flaky, so the HTTP test pins the property that a
//! test can pin deterministically — that the limit is applied at all.

use std::sync::Arc;

use airon_aip::ingress::{harden, IngressLimits};
use airon_aip::store::{EvidenceStore, JsonlEvidenceStore};
use airon_aip::ManagedSigning;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

mod support;
use support::app_state;

const SECRET: &str = "acme-machine-secret";

fn keys() -> airon_aip::auth::ApiKeyStore {
    let mut path = std::env::temp_dir();
    path.push(format!("aip_ingress_keys_{}.json", uuid::Uuid::new_v4()));
    std::fs::write(
        &path,
        serde_json::json!({ "keys": [{
            "key_id": "acme-m",
            "secret_sha256": hex::encode(aip_crypto::sha256(SECRET.as_bytes())),
            "tenant_id": "acme",
            "role": "machine",
        }]})
        .to_string(),
    )
    .expect("write keys");
    airon_aip::auth::ApiKeyStore::load(path.to_str().expect("utf-8"))
}

fn hardened(limits: IngressLimits) -> axum::Router {
    let mut path = std::env::temp_dir();
    path.push(format!("aip_ingress_{}.jsonl", uuid::Uuid::new_v4()));
    let store: Arc<dyn EvidenceStore> =
        Arc::new(JsonlEvidenceStore::load(path.to_str().expect("utf-8 path")));
    harden(
        airon_aip::router(app_state(store, keys(), ManagedSigning::Refused)),
        limits,
    )
}

/// A body over the cap is rejected with 413, and the handler never runs —
/// so the rejection does not depend on authentication or on the body being
/// valid JSON.
#[tokio::test]
async fn a_body_over_the_cap_is_rejected_before_the_handler() {
    let limits = IngressLimits {
        max_body_bytes: 512,
        ..IngressLimits::default()
    };
    let app = hardened(limits);
    let oversized = vec![b'x'; 4096];
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/verdicts")
                .header("authorization", format!("Bearer {SECRET}"))
                .header("content-type", "application/json")
                .body(Body::from(oversized))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

/// A body under the cap reaches the handler: the limit does not break
/// ordinary requests. The handler then rejects the payload on its own
/// terms (here, a bad-request for an unparseable verdict), which is a
/// different status than 413 — proving the body was admitted.
#[tokio::test]
async fn a_body_under_the_cap_reaches_the_handler() {
    let app = hardened(IngressLimits::default());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/verdicts")
                .header("authorization", format!("Bearer {SECRET}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"not":"a verdict"}"#))
                .expect("request"),
        )
        .await
        .expect("response");
    // Admitted: the handler's JSON extractor rejects the shape with 422,
    // which is not 413 — the body reached the handler rather than being
    // capped.
    assert_ne!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

/// An unauthenticated request with a giant body spends no memory on it:
/// the `Principal` extractor runs before the body is read and returns 401
/// without buffering it. That is a stronger guarantee than the cap firing —
/// the body is never touched — and it is what actually protects the process
/// from an unauthenticated flood. (The cap itself is proven with a valid
/// key above; here the point is that the body is not read at all.)
#[tokio::test]
async fn an_unauthenticated_giant_body_is_rejected_without_being_read() {
    let limits = IngressLimits {
        max_body_bytes: 512,
        ..IngressLimits::default()
    };
    let app = hardened(limits);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/verdicts")
                .header("content-type", "application/json")
                .body(Body::from(vec![b'x'; 4096]))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// Health still serves through the hardened stack: the limits wrap the
/// whole router, they do not replace it.
#[tokio::test]
async fn the_hardened_router_still_serves() {
    let app = hardened(IngressLimits::default());
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
}
