//! R10 — verdicts and access ledgers, stored and served by the regulated
//! entity's own service.
//!
//! The three properties that matter, checked over the real router:
//!
//! 1. **A document that does not verify is not stored.** The service must
//!    not become the place a forged verdict acquires a bank's endpoint as
//!    its provenance.
//! 2. **Tenancy holds, and does not leak.** Another tenant's document reads
//!    as 404, identical to not-found, so existence is not an oracle.
//! 3. **What comes back out verifies offline.** The response is piped
//!    straight back into the producing crate's own verifier with anchors the
//!    test holds — which is the only reason to believe the service at all.

use std::sync::Arc;

use aip_crypto::generate_ed25519_keypair;
use aip_ledger::{AccessLedger, AccessLedgerBuilder, LedgerSigner, LedgerTrustAnchors};
use aip_reconcile::{
    reconcile_expectation, ExpectedSideCoverage, ReconcilerSigner, ReconcilerTrustAnchors,
    ReconciliationContext, SignedReconciliation,
};
use aip_registry::{
    AddressRange, Criticality, PortRange, Protocol, RegistryTrustAnchors, ResourceEntry,
    ResourceRegistry,
};
use aip_types::CoverageWindow;
use airon_aip::store::{EvidenceStore, JsonlEvidenceStore};
use airon_aip::ManagedSigning;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

mod support;
use support::app_state;

const ACME: &str = "acme-machine-secret";
const GLOBEX: &str = "globex-machine-secret";
const AGENT: &str = "aip1LoanAgentXYZ";
const T0: u64 = 1_700_000_000_000;

fn two_tenant_keys() -> airon_aip::auth::ApiKeyStore {
    let mut path = std::env::temp_dir();
    path.push(format!("aip_verdict_keys_{}.json", uuid::Uuid::new_v4()));
    let entry = |id: &str, secret: &str, tenant: &str| {
        serde_json::json!({
            "key_id": id,
            "secret_sha256": hex::encode(aip_crypto::sha256(secret.as_bytes())),
            "tenant_id": tenant,
            "role": "machine",
        })
    };
    std::fs::write(
        &path,
        serde_json::json!({ "keys": [
            entry("acme-m", ACME, "acme"),
            entry("globex-m", GLOBEX, "globex"),
        ]})
        .to_string(),
    )
    .expect("write keys");
    airon_aip::auth::ApiKeyStore::load(path.to_str().expect("utf-8"))
}

fn app() -> axum::Router {
    let mut path = std::env::temp_dir();
    path.push(format!("aip_verdict_{}.jsonl", uuid::Uuid::new_v4()));
    let store: Arc<dyn EvidenceStore> =
        Arc::new(JsonlEvidenceStore::load(path.to_str().expect("utf-8 path")));
    airon_aip::router(app_state(store, two_tenant_keys(), ManagedSigning::Refused))
}

async fn call(
    app: &axum::Router,
    method: &str,
    path: &str,
    bearer: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, String) {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {bearer}"));
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
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

// ─── Fixtures: real documents from the real producing crates ───────────────

struct Reconciler {
    signer: ReconcilerSigner,
    anchors: ReconcilerTrustAnchors,
    anchor_arg: String,
}

fn reconciler() -> Reconciler {
    let kp = generate_ed25519_keypair();
    Reconciler {
        signer: ReconcilerSigner::new("reconciler-1", 1, &kp.private_key, &kp.public_key).unwrap(),
        anchors: ReconcilerTrustAnchors::new().trust("reconciler-1", 1, &kp.public_key),
        anchor_arg: format!("reconciler-1:1={}", hex::encode(&kp.public_key)),
    }
}

/// A genuine engine verdict: no observer, no anchors, so `CANNOT_PROVE` —
/// the engine's most conservative answer, and a real one.
fn a_verdict(r: &Reconciler) -> SignedReconciliation {
    let ee = support_expectation();
    let ctx = ReconciliationContext {
        decision_point_anchors: aip_authorize::DecisionPointTrustAnchors::new(),
        observer_anchors: aip_observe::ObserverTrustAnchors::new(),
        verification_time_ms: T0,
        health_max_age_ms: 60_000,
        window_tolerance_ms: 0,
        expected_side: ExpectedSideCoverage::Unknown,
        agent_public_key: None,
    };
    let rec = reconcile_expectation(&ee, None, &ctx);
    r.signer.sign(&rec).expect("sign verdict")
}

fn support_expectation() -> aip_authorize::ExpectedExecution {
    let dp = generate_ed25519_keypair();
    let agent = generate_ed25519_keypair();
    let mut ee = aip_authorize::ExpectedExecution {
        version: aip_authorize::EXPECTED_EXECUTION_VERSION,
        decision_id: [0xD1; 16],
        decision_point_id: "dp-1".into(),
        agent_id: AGENT.into(),
        authority: aip_authorize::AuthorityRef {
            root_jti: [1u8; 16],
            chain_jtis: vec![],
        },
        action_kind: aip_authorize::net_connect_action(),
        parameter_digest: aip_authorize::net_connect_parameters(
            aip_authorize::NetProtocol::Tcp,
            &[10, 0, 5, 20],
            8443,
        )
        .unwrap()
        .digest(),
        execution_binding: aip_types::ExecutionBinding {
            version: aip_types::EXECUTION_BINDING_VERSION,
            agent_id: AGENT.into(),
            process: aip_types::ProcessInstance {
                pid: 4242,
                pid_start_time_ticks: 99_000,
                boot_id: [7u8; 16],
            },
            exe_content_sha256: aip_crypto::sha256(b"the binary"),
            exe_path: "/usr/local/bin/agent".into(),
            bound_at_ms: T0,
            container: None,
        },
        issued_at: T0,
        valid_until: T0 + 60_000,
        decision_sig: aip_crypto::sign_ed25519(&agent.private_key, "dp-1", b"placeholder").unwrap(),
    };
    let preimage = ee.signing_preimage();
    ee.decision_sig = aip_crypto::sign_ed25519(&dp.private_key, "dp-1", &preimage).unwrap();
    ee
}

struct Ledger {
    ledger: AccessLedger,
    anchors: LedgerTrustAnchors,
    anchor_arg: String,
}

/// A real signed access ledger for `AGENT`, empty of rows (no observer
/// evidence was supplied) but genuinely signed and genuinely verifiable.
fn a_ledger() -> Ledger {
    let reg_kp = generate_ed25519_keypair();
    let reg = ResourceRegistry::sign(
        "bank/dc1",
        "bank.example",
        &reg_kp.private_key,
        5,
        T0 - 1_000,
        vec![ResourceEntry {
            id: "core-banking-api".into(),
            display_name: "Core banking API".into(),
            criticality: Criticality::TransactionCritical,
            protocol: Protocol::Tcp,
            addresses: vec![AddressRange::v4_host([10, 0, 5, 20])],
            ports: vec![PortRange::single(8443)],
        }],
    )
    .unwrap();
    let reg_anchors = RegistryTrustAnchors::new().trust("bank.example", &reg_kp.public_key);
    let window = CoverageWindow {
        from_ms: T0,
        to_ms: T0 + 60_000,
    };
    let builder = AccessLedgerBuilder::new(AGENT, window, &reg, &reg_anchors).unwrap();
    let kp = generate_ed25519_keypair();
    let signer = LedgerSigner::new("ledger-1", 1, &kp.private_key, &kp.public_key);
    Ledger {
        ledger: builder.build_and_sign(&signer, T0 + 70_000).unwrap(),
        anchors: LedgerTrustAnchors::new().trust("ledger-1", 1, &kp.public_key),
        anchor_arg: format!("ledger-1:1={}", hex::encode(&kp.public_key)),
    }
}

// ─── Verify before storing ─────────────────────────────────────────────────

/// A verdict whose signature does not check out is refused, and nothing is
/// filed. The service must not launder a forged document.
#[tokio::test]
async fn a_verdict_that_does_not_verify_is_refused_and_not_stored() {
    let app = app();
    let r = reconciler();
    let good = a_verdict(&r);
    let id = hex::encode(good.digest());

    // Same document, re-signed by someone the caller does not anchor.
    let impostor = generate_ed25519_keypair();
    let impostor_signer = ReconcilerSigner::new(
        "reconciler-1",
        1,
        &impostor.private_key,
        &impostor.public_key,
    )
    .unwrap();
    let forged = impostor_signer.sign(&good.reconciliation).unwrap();

    let (status, body) = call(
        &app,
        "POST",
        "/v1/verdicts",
        ACME,
        Some(serde_json::json!({
            "verdict": forged,
            "reconciler_anchors": [r.anchor_arg],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("did not verify"), "{body}");
    assert!(body.contains("not stored"), "{body}");

    // And nothing was filed under that document's id.
    let (status, _) = call(&app, "GET", &format!("/v1/verdicts/{id}"), ACME, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A submission with no anchors cannot be verified, so it is refused rather
/// than stored unverified.
#[tokio::test]
async fn a_submission_with_no_anchors_is_refused() {
    let app = app();
    let r = reconciler();
    let (status, body) = call(
        &app,
        "POST",
        "/v1/verdicts",
        ACME,
        Some(serde_json::json!({
            "verdict": a_verdict(&r),
            "reconciler_anchors": [],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body.contains("cannot verify one without an anchor"),
        "{body}"
    );
}

// ─── The round trip an inspector makes ─────────────────────────────────────

/// **The acceptance criterion.** A verdict filed through the API comes back
/// out and verifies offline, under anchors the caller holds — not the
/// service's.
#[tokio::test]
async fn a_stored_verdict_comes_back_and_verifies_offline() {
    let app = app();
    let r = reconciler();
    let verdict = a_verdict(&r);

    let (status, body) = call(
        &app,
        "POST",
        "/v1/verdicts",
        ACME,
        Some(serde_json::json!({
            "verdict": verdict,
            "reconciler_anchors": [r.anchor_arg],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        id,
        hex::encode(verdict.digest()),
        "id must be the document's own digest"
    );

    let (status, returned) = call(&app, "GET", &format!("/v1/verdicts/{id}"), ACME, None).await;
    assert_eq!(status, StatusCode::OK);

    // The whole point: parse what the endpoint returned and check it with
    // the reconciler's key, having never trusted the service.
    let back: SignedReconciliation = serde_json::from_str(&returned).expect("parse response");
    assert_eq!(
        back.verify(&r.anchors),
        Ok(()),
        "the returned verdict must verify"
    );
    assert_eq!(
        back.digest(),
        verdict.digest(),
        "the bytes must be the same document"
    );
    assert_eq!(back.reconciliation.result, verdict.reconciliation.result);
}

/// The same for an access ledger, through the per-agent route an inspector
/// actually asks.
#[tokio::test]
async fn an_agents_ledger_comes_back_and_verifies_offline() {
    let app = app();
    let l = a_ledger();

    let (status, body) = call(
        &app,
        "POST",
        "/v1/ledgers",
        ACME,
        Some(serde_json::json!({
            "ledger": l.ledger,
            "ledger_anchors": [l.anchor_arg],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = call(
        &app,
        "GET",
        &format!("/v1/agents/{AGENT}/ledger"),
        ACME,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["agent_id"], AGENT);
    let ledgers = v["ledgers"].as_array().expect("ledgers array");
    assert_eq!(ledgers.len(), 1, "{body}");

    let back: AccessLedger = serde_json::from_value(ledgers[0].clone()).expect("parse ledger");
    assert_eq!(
        back.verify(&l.anchors),
        Ok(()),
        "the returned ledger must verify"
    );
    assert_eq!(back.agent_id, AGENT);
    assert_eq!(back.registry_revision, 5);
}

// ─── Tenancy ───────────────────────────────────────────────────────────────

/// A cross-tenant read is 404 — identical to not-found, so a caller cannot
/// use the endpoint to learn that another tenant holds a document.
#[tokio::test]
async fn another_tenant_cannot_read_a_verdict_and_cannot_tell_it_exists() {
    let app = app();
    let r = reconciler();
    let verdict = a_verdict(&r);
    let (status, body) = call(
        &app,
        "POST",
        "/v1/verdicts",
        ACME,
        Some(serde_json::json!({
            "verdict": verdict,
            "reconciler_anchors": [r.anchor_arg],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let id = hex::encode(verdict.digest());

    let (mine, _) = call(&app, "GET", &format!("/v1/verdicts/{id}"), ACME, None).await;
    assert_eq!(mine, StatusCode::OK);

    let (theirs, theirs_body) =
        call(&app, "GET", &format!("/v1/verdicts/{id}"), GLOBEX, None).await;
    assert_eq!(theirs, StatusCode::NOT_FOUND);

    // A document that never existed gives the identical answer.
    let absent = "0".repeat(64);
    let (missing, missing_body) =
        call(&app, "GET", &format!("/v1/verdicts/{absent}"), GLOBEX, None).await;
    assert_eq!(missing, StatusCode::NOT_FOUND);
    assert_eq!(
        theirs_body, missing_body,
        "a wrong-tenant read must be indistinguishable from not-found"
    );
}

#[tokio::test]
async fn an_agents_ledger_is_empty_for_a_tenant_that_filed_none() {
    let app = app();
    let l = a_ledger();
    call(
        &app,
        "POST",
        "/v1/ledgers",
        ACME,
        Some(serde_json::json!({
            "ledger": l.ledger,
            "ledger_anchors": [l.anchor_arg],
        })),
    )
    .await;

    let (status, body) = call(
        &app,
        "GET",
        &format!("/v1/agents/{AGENT}/ledger"),
        GLOBEX,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        v["ledgers"].as_array().unwrap().is_empty(),
        "another tenant must see none of it: {body}"
    );
}

// ─── Authentication ────────────────────────────────────────────────────────

#[tokio::test]
async fn the_verdict_routes_are_authenticated() {
    let app = app();
    for (method, path) in [
        ("POST", "/v1/verdicts"),
        ("GET", "/v1/verdicts/abc"),
        ("POST", "/v1/ledgers"),
        ("GET", "/v1/agents/aip1x/ledger"),
    ] {
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {path} must require a key"
        );
    }
}

// ─── Idempotency ───────────────────────────────────────────────────────────

/// Filing the same document twice is one row, because the id is the
/// document's own digest rather than a fresh identifier per request.
#[tokio::test]
async fn filing_the_same_ledger_twice_yields_one_row() {
    let app = app();
    let l = a_ledger();
    let body = serde_json::json!({
        "ledger": l.ledger,
        "ledger_anchors": [l.anchor_arg],
    });
    let (s1, b1) = call(&app, "POST", "/v1/ledgers", ACME, Some(body.clone())).await;
    let (s2, b2) = call(&app, "POST", "/v1/ledgers", ACME, Some(body)).await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(b1, b2, "the same document must file under the same id");

    let (_, listed) = call(
        &app,
        "GET",
        &format!("/v1/agents/{AGENT}/ledger"),
        ACME,
        None,
    )
    .await;
    let v: serde_json::Value = serde_json::from_str(&listed).unwrap();
    assert_eq!(v["ledgers"].as_array().unwrap().len(), 1);
}
