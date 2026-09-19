//! R15 — the metrics endpoint, over the real router.
//!
//! Two things are checked and the second is the one that matters. That the
//! endpoint renders is table stakes. That it does not become a
//! cross-tenant disclosure channel — an unauthenticated counter telling an
//! observer how much evidence each institution files and when — is the
//! reason it is authenticated and unlabelled.

use std::sync::Arc;

use airon_aip::store::{EvidenceStore, JsonlEvidenceStore};
use airon_aip::ManagedSigning;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

mod support;
use support::app_state;

const ACME: &str = "acme-machine-secret";

fn keys() -> airon_aip::auth::ApiKeyStore {
    let mut path = std::env::temp_dir();
    path.push(format!("aip_metrics_keys_{}.json", uuid::Uuid::new_v4()));
    std::fs::write(
        &path,
        serde_json::json!({ "keys": [{
            "key_id": "acme-m",
            "secret_sha256": hex::encode(aip_crypto::sha256(ACME.as_bytes())),
            "tenant_id": "acme",
            "role": "machine",
        }]})
        .to_string(),
    )
    .expect("write keys");
    airon_aip::auth::ApiKeyStore::load(path.to_str().expect("utf-8"))
}

fn app() -> axum::Router {
    let mut path = std::env::temp_dir();
    path.push(format!("aip_metrics_{}.jsonl", uuid::Uuid::new_v4()));
    let store: Arc<dyn EvidenceStore> =
        Arc::new(JsonlEvidenceStore::load(path.to_str().expect("utf-8 path")));
    airon_aip::router(app_state(store, keys(), ManagedSigning::Refused))
}

/// Issue a request, optionally with a bearer token.
async fn get(app: &axum::Router, path: &str, bearer: Option<&str>) -> (StatusCode, String, String) {
    let mut req = Request::builder().method("GET").uri(path);
    if let Some(b) = bearer {
        req = req.header("authorization", format!("Bearer {b}"));
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::empty()).expect("request"))
        .await
        .expect("response");
    let status = resp.status();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    (
        status,
        content_type,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

/// **The rule.** Request volume is operationally sensitive: an
/// unauthenticated counter of filed evidence tells an observer when an
/// institution is busy, and with what. A scrape authenticates like any
/// other client.
#[tokio::test]
async fn metrics_are_not_public() {
    let app = app();
    let (status, _, body) = get(&app, "/metrics", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(
        !body.contains("aip_evidence_stored_total"),
        "no counter may reach an unauthenticated caller: {body}"
    );

    let (status, _, body) = get(&app, "/metrics", Some("wrong-secret")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

/// With a key, the endpoint serves the exposition format a scraper parses.
#[tokio::test]
async fn an_authenticated_scrape_gets_the_prometheus_format() {
    let (status, content_type, body) = get(&app(), "/metrics", Some(ACME)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        content_type.starts_with("text/plain; version=0.0.4"),
        "a scraper handed the wrong content type refuses the body: {content_type}"
    );
    assert!(body.ends_with('\n'));
    for expected in [
        "# TYPE aip_evidence_stored_total counter",
        "# TYPE aip_verdicts_rejected_total counter",
        "# TYPE aip_siem_exports_refused_total counter",
    ] {
        assert!(body.contains(expected), "{expected} missing from:\n{body}");
    }
}

/// **The disclosure test.** No series carries a label, so one tenant's
/// scrape says nothing about another's volume, and no unbounded
/// identifier can enter the time-series database.
#[tokio::test]
async fn no_series_is_labelled_by_tenant_agent_or_document() {
    let (_, _, body) = get(&app(), "/metrics", Some(ACME)).await;
    for line in body.lines().filter(|l| !l.starts_with('#')) {
        assert!(!line.contains('{'), "labelled series: {line}");
    }
    for forbidden in ["acme", "globex", "tenant_id", "agent_id"] {
        assert!(
            !body.to_lowercase().contains(forbidden),
            "`{forbidden}` must not appear in a shared scrape:\n{body}"
        );
    }
}

/// A verdict refused for failing verification is counted. Nothing is
/// stored by definition, so the counter is the only place that refusal
/// becomes visible to an operator.
#[tokio::test]
async fn a_refused_verdict_is_visible_in_the_counters() {
    let app = app();
    let (_, _, before) = get(&app, "/metrics", Some(ACME)).await;
    assert!(
        before.contains("\naip_verdicts_rejected_total 0\n"),
        "{before}"
    );

    // A real signed verdict, submitted with an anchor for the right
    // reconciler name but the wrong key. This reaches the verification
    // step and fails there — which is precisely what the counter claims
    // to measure. A malformed submission (no anchors, bad hex) is refused
    // earlier and is deliberately *not* counted here: conflating a client
    // bug with a document this service will not stand behind would blunt
    // the one alert that matters.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/verdicts")
                .header("authorization", format!("Bearer {ACME}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "verdict": verdict_json(),
                        "reconciler_anchors": [impostor_anchor()],
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let (_, _, after) = get(&app, "/metrics", Some(ACME)).await;
    assert!(
        after.contains("\naip_verdicts_rejected_total 1\n"),
        "a refused verdict must be countable:\n{after}"
    );
    assert!(
        after.contains("\naip_verdicts_stored_total 0\n"),
        "and must not be counted as stored:\n{after}"
    );
}

/// A real signed verdict, serialised.
fn verdict_json() -> serde_json::Value {
    use aip_reconcile::{ReconcilerSigner, Reconciliation};
    let kp = aip_crypto::generate_ed25519_keypair();
    let signer = ReconcilerSigner::new("reconciler-1", 1, &kp.private_key, &kp.public_key).unwrap();
    let r = Reconciliation::fixture_default();
    serde_json::to_value(signer.sign(&r).unwrap()).expect("serialisable")
}

/// A well-formed anchor naming the right reconciler and a key that did not
/// sign the verdict. The submission is syntactically perfect and the
/// signature does not check out.
fn impostor_anchor() -> String {
    let kp = aip_crypto::generate_ed25519_keypair();
    format!("reconciler-1:1={}", hex::encode(&kp.public_key))
}
