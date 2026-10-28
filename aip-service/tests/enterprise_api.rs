//! Enterprise read interfaces use real signed protocol documents and the
//! same router and credential loader as the deployable service.
use std::sync::Arc;

use airon_aip::{
    auth::ApiKeyStore,
    store::{EvidenceStore, JsonlEvidenceStore},
    ManagedSigning,
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::{json, Value};
use tower::ServiceExt;

mod support;

const READER_A: &str = "test-reader-a-not-production";
const READER_B: &str = "test-reader-b-not-production";
const WRITER_A: &str = "test-writer-a-not-production";
const WRITER_B: &str = "test-writer-b-not-production";

fn keys() -> ApiKeyStore {
    let path = std::env::temp_dir().join(format!("enterprise_keys_{}.json", uuid::Uuid::new_v4()));
    let entries: Vec<Value> = [
        (READER_A, "reader-a", "tenant-a", "reader"),
        (READER_B, "reader-b", "tenant-b", "reader"),
        (WRITER_A, "writer-a", "tenant-a", "machine"),
        (WRITER_B, "writer-b", "tenant-b", "machine"),
    ]
    .into_iter()
    .map(|(secret, id, tenant, role)| {
        json!({"key_id":id,"tenant_id":tenant,"role":role,
            "secret_sha256":hex::encode(aip_crypto::sha256(secret.as_bytes()))})
    })
    .collect();
    std::fs::write(&path, json!({"keys":entries}).to_string()).unwrap();
    let keys = ApiKeyStore::load(path.to_str().unwrap());
    std::fs::remove_file(path).unwrap();
    keys
}

struct Fixture {
    app: axum::Router,
    packet: aip_protocol::EvidencePacket,
    issuers: std::collections::HashMap<String, String>,
    verdict_id: String,
    observation_id: String,
}

async fn fixture() -> Fixture {
    let path =
        std::env::temp_dir().join(format!("enterprise_vault_{}.jsonl", uuid::Uuid::new_v4()));
    let store = Arc::new(JsonlEvidenceStore::load(path.to_str().unwrap()));
    let (req, issuers) = support::sample_generate_request();
    let packet = airon_aip::evidence::generate_packet(&req).unwrap();
    store.store("tenant-a", &packet).await.unwrap();
    store
        .store(
            "tenant-a",
            &airon_aip::evidence::generate_packet(&req).unwrap(),
        )
        .await
        .unwrap();
    let other = support::packet_dated(0).packet;
    store.store("tenant-a", &other).await.unwrap();
    let mut state = support::app_state(store, keys(), ManagedSigning::Refused);
    let (observation, observer_key) = collector_archive();
    Arc::get_mut(&mut state).unwrap().observer_trust =
        airon_aip::observations::ObserverTrustStore::from_json(
            &json!({"anchors":[{"tenant_id":"tenant-a","observer_id":"enterprise-test-collector",
            "key_version":1,"public_key_hex":hex::encode(observer_key)}]})
            .to_string(),
        )
        .unwrap();
    let app = airon_aip::ingress::harden(airon_aip::router(state), Default::default());
    let (verdict, anchor) = signed_uncertainty(&packet.agent.aip_id);
    let (status, filed) = call(
        &app,
        "POST",
        "/v1/verdicts",
        Some(WRITER_A),
        Some(json!({
        "verdict":verdict,"reconciler_anchors":[anchor]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{filed}");
    let (status, archived) = call(
        &app,
        "POST",
        "/v1/observations",
        Some(WRITER_A),
        Some(serde_json::to_value(observation).unwrap()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{archived}");
    Fixture {
        app,
        packet,
        issuers,
        verdict_id: filed["id"].as_str().unwrap().into(),
        observation_id: archived["observation_id"].as_str().unwrap().into(),
    }
}

fn collector_archive() -> (airon_aip::observations::ObservationArchive, Vec<u8>) {
    use aip_observe::{
        CollectorKey, CollectorRuntime, CollectorStore, ContinuityPolicy, ProcfsProbe, Started,
    };
    let directory =
        std::env::temp_dir().join(format!("enterprise_collector_{}", uuid::Uuid::new_v4()));
    let key = CollectorKey::development();
    let public_key = key.public_key().to_vec();
    let started = CollectorRuntime::start_with_custodian(
        CollectorStore::open(&directory).unwrap(),
        "enterprise-test-collector",
        1,
        key.into_custodian(),
        ContinuityPolicy::Strict,
    )
    .unwrap();
    let mut runtime = match started {
        Started::Running(rt, _) => rt,
        Started::Refused(reason) => panic!("fresh collector refused: {reason:?}"),
    };
    let mut probe = ProcfsProbe::new("enterprise-test-probe");
    let mut batches = String::new();
    let mut health = String::new();
    for index in 0..2u64 {
        let from = 1000 + index * 100;
        // A genuinely signed, empty observation snapshot. This fixture
        // establishes archive integrity only, never kernel execution.
        let batch = probe.batch([index as u8; 16], from, from + 50, vec![]);
        batches.push_str(&serde_json::to_string(&runtime.attest(batch).unwrap()).unwrap());
        batches.push('\n');
        health.push_str(
            &serde_json::to_string(&runtime.health_with_clock(from + 60, None).unwrap()).unwrap(),
        );
        health.push('\n');
    }
    (
        airon_aip::observations::ObservationArchive {
            observer_id: "enterprise-test-collector".into(),
            key_version: 1,
            batches_jsonl: batches,
            health_jsonl: health,
        },
        public_key,
    )
}

fn signed_uncertainty(agent_id: &str) -> (aip_reconcile::SignedReconciliation, String) {
    use aip_crypto::{generate_ed25519_keypair, sign_ed25519};
    use aip_reconcile::{
        reconcile_expectation, ExpectedSideCoverage, ReconcilerSigner, ReconciliationContext,
    };
    let dp = generate_ed25519_keypair();
    let t = support::now_ms();
    let mut expected = aip_authorize::ExpectedExecution {
        version: aip_authorize::EXPECTED_EXECUTION_VERSION,
        decision_id: [0x61; 16],
        decision_point_id: "enterprise-test-authority".into(),
        agent_id: agent_id.into(),
        authority: aip_authorize::AuthorityRef {
            root_jti: [1; 16],
            chain_jtis: vec![],
        },
        action_kind: aip_authorize::net_connect_action(),
        parameter_digest: aip_authorize::net_connect_parameters(
            aip_authorize::NetProtocol::Tcp,
            &[127, 0, 0, 1],
            8443,
        )
        .unwrap()
        .digest(),
        execution_binding: aip_types::ExecutionBinding {
            version: aip_types::EXECUTION_BINDING_VERSION,
            agent_id: agent_id.into(),
            process: aip_types::ProcessInstance {
                pid: 4242,
                pid_start_time_ticks: 100,
                boot_id: [1; 16],
            },
            exe_content_sha256: aip_crypto::sha256(b"test fixture"),
            exe_path: "/test/agent".into(),
            bound_at_ms: t,
            container: None,
        },
        issued_at: t,
        valid_until: t + 60_000,
        decision_sig: sign_ed25519(&dp.private_key, "enterprise-test-authority", b"placeholder")
            .unwrap(),
    };
    expected.decision_sig = sign_ed25519(
        &dp.private_key,
        "enterprise-test-authority",
        &expected.signing_preimage(),
    )
    .unwrap();
    let context = ReconciliationContext {
        decision_point_anchors: Default::default(),
        observer_anchors: Default::default(),
        verification_time_ms: t,
        health_max_age_ms: 60_000,
        window_tolerance_ms: 0,
        expected_side: ExpectedSideCoverage::Unknown,
        agent_public_key: None,
    };
    // No observer is supplied. The real engine must preserve uncertainty.
    let verdict = reconcile_expectation(&expected, None, &context);
    let signer = generate_ed25519_keypair();
    let signed = ReconcilerSigner::new(
        "enterprise-test-reconciler",
        1,
        &signer.private_key,
        &signer.public_key,
    )
    .unwrap()
    .sign(&verdict)
    .unwrap();
    (
        signed,
        format!(
            "enterprise-test-reconciler:1={}",
            hex::encode(&signer.public_key)
        ),
    )
}

async fn call(
    app: &axum::Router,
    method: &str,
    path: &str,
    secret: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder().method(method).uri(path);
    if let Some(secret) = secret {
        request = request.header("authorization", format!("Bearer {secret}"));
    }
    let body = if let Some(body) = body {
        request = request.header("content-type", "application/json");
        Body::from(body.to_string())
    } else {
        Body::empty()
    };
    let response = app
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({"text":String::from_utf8_lossy(&bytes)}));
    (status, value)
}

#[tokio::test]
async fn read_routes_authenticate_and_cross_tenant_ids_are_indistinguishable_from_absent() {
    let f = fixture().await;
    let id = f.packet.packet_id_hex();
    let agent = &f.packet.agent.aip_id;
    for path in [
        "/v1/access".into(),
        "/v1/agents".into(),
        "/v1/coverage".into(),
        "/v1/health".into(),
        format!("/v1/agents/{agent}"),
        format!("/v1/agents/{agent}/activity"),
        format!("/v1/evidence/{id}/metadata"),
        format!("/v1/evidence/{id}/verification"),
    ] {
        assert_eq!(
            call(&f.app, "GET", &path, None, None).await.0,
            StatusCode::UNAUTHORIZED,
            "{path}"
        );
        assert_eq!(
            call(&f.app, "GET", &path, Some(READER_A), None).await.0,
            StatusCode::OK,
            "{path}"
        );
    }
    for path in [
        format!("/v1/agents/{agent}"),
        format!("/v1/agents/{agent}/activity"),
        format!("/v1/evidence/{id}/metadata"),
        format!("/v1/evidence/{id}/verification"),
        format!("/v1/verdicts/{}", f.verdict_id),
    ] {
        assert_eq!(
            call(&f.app, "GET", &path, Some(READER_B), None).await.0,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    let (_, access) = call(&f.app, "GET", "/v1/access", Some(READER_A), None).await;
    assert_eq!(
        access,
        json!({"tenant_id":"tenant-a","key_id":"reader-a","role":"reader"})
    );
    let (_, agents) = call(&f.app, "GET", "/v1/agents", Some(READER_B), None).await;
    assert_eq!(agents["items"], json!([]));
}

#[tokio::test]
async fn reader_refuses_every_mutation_and_raw_export_before_parsing_the_body() {
    let f = fixture().await;
    for path in [
        "/v1/identity/issue",
        "/v1/identity/revoke",
        "/v1/evidence/generate",
        "/v1/verdicts",
        "/v1/ledgers",
        "/v1/observations",
    ] {
        assert_eq!(
            call(&f.app, "POST", path, Some(READER_A), Some(json!({})))
                .await
                .0,
            StatusCode::FORBIDDEN,
            "{path}"
        );
    }
    for path in [
        format!("/v1/evidence/{}", f.packet.packet_id_hex()),
        format!("/v1/evidence/{}/export", f.packet.packet_id_hex()),
    ] {
        assert_eq!(
            call(&f.app, "GET", &path, Some(READER_A), None).await.0,
            StatusCode::FORBIDDEN
        );
    }
    let (status, report) = call(
        &f.app,
        "POST",
        "/v1/evidence/verify",
        Some(READER_A),
        Some(json!({
        "packet":f.packet,"trusted_issuers":f.issuers})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(report["authority_chain_verified"], true);
}

#[tokio::test]
async fn pagination_is_bounded_and_agent_claims_are_not_upgraded_into_observation() {
    let f = fixture().await;
    let (_, first) = call(&f.app, "GET", "/v1/agents?limit=1", Some(READER_A), None).await;
    assert_eq!(first["items"].as_array().unwrap().len(), 1);
    assert_eq!(first["next_offset"], 1);
    assert_eq!(first["items"][0]["independent_identity_verified"], false);
    let (_, second) = call(
        &f.app,
        "GET",
        "/v1/agents?limit=1&offset=1",
        Some(READER_A),
        None,
    )
    .await;
    assert_ne!(
        first["items"][0]["agent_id"],
        second["items"][0]["agent_id"]
    );
    assert!(second["next_offset"].is_null());
    for query in [
        "limit=0",
        "limit=101",
        "offset=100001",
        "tenant_id=tenant-a",
    ] {
        assert_eq!(
            call(
                &f.app,
                "GET",
                &format!("/v1/agents?{query}"),
                Some(READER_A),
                None
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
    let (_, activity) = call(
        &f.app,
        "GET",
        &format!("/v1/agents/{}/activity?limit=1", f.packet.agent.aip_id),
        Some(READER_A),
        None,
    )
    .await;
    assert_eq!(activity["items"].as_array().unwrap().len(), 1);
    assert_eq!(activity["next_offset"], 1);
    assert_eq!(
        activity["items"][0]["independent_execution_verified"],
        false
    );
    let (_, coverage) = call(&f.app, "GET", "/v1/coverage", Some(READER_A), None).await;
    assert_eq!(coverage["status"], "unavailable");
    assert_eq!(coverage["independent_execution_verified"], false);
    let (_, verification) = call(
        &f.app,
        "GET",
        &format!("/v1/evidence/{}/verification", f.packet.packet_id_hex()),
        Some(READER_A),
        None,
    )
    .await;
    assert_eq!(verification["verification_scope"], "integrity_only");
    assert_eq!(verification["report"]["authority_chain_verified"], false);
    assert_eq!(verification["report"]["tampered"], false);
    assert_eq!(verification["report"]["verification_time_checked"], true);
}

#[tokio::test]
async fn stored_verification_detects_actual_post_signature_tampering() {
    let path = std::env::temp_dir().join(format!(
        "enterprise_tampered_{}.jsonl",
        uuid::Uuid::new_v4()
    ));
    let store = Arc::new(JsonlEvidenceStore::load(path.to_str().unwrap()));
    let mut packet = support::packet_dated(0).packet;
    packet.decision.summary = "altered after signing".into();
    let id = store.store("tenant-a", &packet).await.unwrap();
    let state = support::app_state(store, keys(), ManagedSigning::Refused);
    let app = airon_aip::router(state);
    let (status, verification) = call(
        &app,
        "GET",
        &format!("/v1/evidence/{id}/verification"),
        Some(READER_A),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(verification["report"]["tampered"], true);
    assert_eq!(verification["report"]["valid"], false);
}

#[tokio::test]
async fn collector_archives_are_verified_stored_idempotently_and_tenant_scoped() {
    let f = fixture().await;
    let base = format!("/v1/observations/{}", f.observation_id);
    for suffix in ["/metadata", "/verification"] {
        assert_eq!(
            call(&f.app, "GET", &format!("{base}{suffix}"), None, None)
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(
                &f.app,
                "GET",
                &format!("{base}{suffix}"),
                Some(READER_B),
                None
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            call(
                &f.app,
                "GET",
                &format!("{base}{suffix}"),
                Some(READER_A),
                None
            )
            .await
            .0,
            StatusCode::OK
        );
    }
    assert_eq!(
        call(&f.app, "GET", &base, Some(READER_A), None).await.0,
        StatusCode::FORBIDDEN
    );
    let (_, raw) = call(&f.app, "GET", &base, Some(WRITER_A), None).await;
    assert_eq!(
        call(
            &f.app,
            "POST",
            "/v1/observations",
            Some(WRITER_B),
            Some(raw.clone())
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (status, again) = call(
        &f.app,
        "POST",
        "/v1/observations",
        Some(WRITER_A),
        Some(raw.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again["observation_id"], f.observation_id);
    let (_, verification) = call(
        &f.app,
        "GET",
        &format!("{base}/verification"),
        Some(READER_A),
        None,
    )
    .await;
    assert_eq!(verification["verified"], true);
    assert_eq!(verification["report"]["batches"]["records"], 2);
    assert_eq!(verification["report"]["findings"], json!([]));
    let (_, metadata) = call(
        &f.app,
        "GET",
        &format!("{base}/metadata"),
        Some(READER_A),
        None,
    )
    .await;
    assert_eq!(metadata["current_coverage_established"], false);
    assert_eq!(metadata["offhost_separation_established"], false);
    assert_eq!(metadata["execution_correlation_established"], false);
    let (_, coverage) = call(&f.app, "GET", "/v1/coverage", Some(READER_A), None).await;
    assert_eq!(coverage["status"], "unavailable");

    let mut wrong_version = raw.clone();
    wrong_version["key_version"] = json!(2);
    assert_eq!(
        call(
            &f.app,
            "POST",
            "/v1/observations",
            Some(WRITER_A),
            Some(wrong_version)
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let mut malformed = raw.clone();
    malformed["batches_jsonl"] = json!("{malformed\n");
    assert_eq!(
        call(
            &f.app,
            "POST",
            "/v1/observations",
            Some(WRITER_A),
            Some(malformed)
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let mut tampered = raw.clone();
    let lines: Vec<&str> = raw["batches_jsonl"].as_str().unwrap().lines().collect();
    let mut first: Value = serde_json::from_str(lines[0]).unwrap();
    first["batch"]["probe_id"] = json!("altered");
    tampered["batches_jsonl"] = json!(format!("{}\n{}\n", first, lines[1]));
    assert_eq!(
        call(
            &f.app,
            "POST",
            "/v1/observations",
            Some(WRITER_A),
            Some(tampered)
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let mut replayed = raw.clone();
    replayed["batches_jsonl"] = json!(format!("{}\n{}\n", lines[0], lines[0]));
    assert_eq!(
        call(
            &f.app,
            "POST",
            "/v1/observations",
            Some(WRITER_A),
            Some(replayed)
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let (other_key_archive, _) = collector_archive();
    assert_eq!(
        call(
            &f.app,
            "POST",
            "/v1/observations",
            Some(WRITER_A),
            Some(serde_json::to_value(other_key_archive).unwrap())
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let mut oversized = raw.clone();
    oversized["batches_jsonl"] = json!("x".repeat(512 * 1024 + 1));
    assert_eq!(
        call(
            &f.app,
            "POST",
            "/v1/observations",
            Some(WRITER_A),
            Some(oversized)
        )
        .await
        .0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let mut many = raw.clone();
    many["batches_jsonl"] = json!("{}\n".repeat(2049));
    assert_eq!(
        call(
            &f.app,
            "POST",
            "/v1/observations",
            Some(WRITER_A),
            Some(many)
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn accepted_collector_archives_survive_a_service_store_restart() {
    let directory = std::env::temp_dir().join(format!(
        "enterprise_archive_restart_{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir(&directory).unwrap();
    let (archive, key) = collector_archive();
    let original = serde_json::to_value(archive).unwrap();
    let trust=json!({"anchors":[{"tenant_id":"tenant-a","observer_id":"enterprise-test-collector","key_version":1,
        "public_key_hex":hex::encode(key)}]}).to_string();
    let create_app = || {
        let store = Arc::new(JsonlEvidenceStore::load(
            directory.join("packets.jsonl").to_str().unwrap(),
        ));
        let mut state = support::app_state(store, keys(), ManagedSigning::Refused);
        let editable = Arc::get_mut(&mut state).unwrap();
        editable.artifacts = Arc::new(
            airon_aip::artifacts::JsonlArtifactStore::open(directory.join("artifacts.jsonl"))
                .unwrap(),
        );
        editable.observer_trust =
            airon_aip::observations::ObserverTrustStore::from_json(&trust).unwrap();
        airon_aip::router(state)
    };
    let app = create_app();
    let (status, response) = call(
        &app,
        "POST",
        "/v1/observations",
        Some(WRITER_A),
        Some(original.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    drop(app);
    let app = create_app();
    let base = format!(
        "/v1/observations/{}",
        response["observation_id"].as_str().unwrap()
    );
    let (status, raw) = call(&app, "GET", &base, Some(WRITER_A), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        raw, original,
        "original archive strings must survive reopening unchanged"
    );
    let (_, verified) = call(
        &app,
        "GET",
        &format!("{base}/verification"),
        Some(READER_A),
        None,
    )
    .await;
    assert_eq!(verified["verified"], true);
}

#[tokio::test]
async fn explicitly_shared_observer_anchors_keep_each_tenants_archive_index_private() {
    let (archive, key) = collector_archive();
    let path = std::env::temp_dir().join(format!(
        "enterprise_shared_anchor_{}.jsonl",
        uuid::Uuid::new_v4()
    ));
    let mut state = support::app_state(
        Arc::new(JsonlEvidenceStore::load(path.to_str().unwrap())),
        keys(),
        ManagedSigning::Refused,
    );
    let entries: Vec<Value> = ["tenant-a", "tenant-b"]
        .into_iter()
        .map(|tenant| {
            json!({"tenant_id":tenant,"observer_id":"enterprise-test-collector","key_version":1,
            "public_key_hex":hex::encode(&key)})
        })
        .collect();
    Arc::get_mut(&mut state).unwrap().observer_trust =
        airon_aip::observations::ObserverTrustStore::from_json(
            &json!({"anchors":entries}).to_string(),
        )
        .unwrap();
    let app = airon_aip::router(state);
    let body = serde_json::to_value(archive).unwrap();
    let (a_status, a) = call(
        &app,
        "POST",
        "/v1/observations",
        Some(WRITER_A),
        Some(body.clone()),
    )
    .await;
    let (b_status, b) = call(&app, "POST", "/v1/observations", Some(WRITER_B), Some(body)).await;
    assert_eq!(a_status, StatusCode::OK);
    assert_eq!(b_status, StatusCode::OK);
    assert_ne!(
        a["observation_id"], b["observation_id"],
        "storage ids are tenant-bound; signatures remain unchanged"
    );
    assert_eq!(
        call(
            &app,
            "GET",
            &format!(
                "/v1/observations/{}/metadata",
                a["observation_id"].as_str().unwrap()
            ),
            Some(READER_B),
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(
            &app,
            "GET",
            &format!(
                "/v1/observations/{}/metadata",
                b["observation_id"].as_str().unwrap()
            ),
            Some(READER_A),
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn service_readiness_refuses_an_unavailable_artifact_path_without_creating_files() {
    let path = std::env::temp_dir().join(format!("enterprise_readiness_{}", uuid::Uuid::new_v4()));
    let artifacts = airon_aip::artifacts::JsonlArtifactStore::open(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    let packet_path = std::env::temp_dir().join(format!(
        "enterprise_readiness_packets_{}",
        uuid::Uuid::new_v4()
    ));
    let mut state = support::app_state(
        Arc::new(JsonlEvidenceStore::load(packet_path.to_str().unwrap())),
        keys(),
        ManagedSigning::Refused,
    );
    Arc::get_mut(&mut state).unwrap().artifacts = Arc::new(artifacts);
    let app = airon_aip::router(state);
    assert_eq!(
        call(&app, "GET", "/v1/health", Some(READER_A), None)
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(
        !path.exists(),
        "a Reader readiness request must not create an evidence file"
    );
}

#[tokio::test]
async fn unconfigured_collector_admission_is_unavailable_and_caller_anchors_are_refused() {
    let path = std::env::temp_dir().join(format!(
        "enterprise_no_anchor_{}.jsonl",
        uuid::Uuid::new_v4()
    ));
    let state = support::app_state(
        Arc::new(JsonlEvidenceStore::load(path.to_str().unwrap())),
        keys(),
        ManagedSigning::Refused,
    );
    let app = airon_aip::router(state);
    let (archive, key) = collector_archive();
    let mut body = serde_json::to_value(archive).unwrap();
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/observations",
            Some(WRITER_A),
            Some(body.clone())
        )
        .await
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    body["public_key_hex"] = json!(hex::encode(key));
    assert_eq!(
        call(&app, "POST", "/v1/observations", Some(WRITER_A), Some(body))
            .await
            .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

/// Public assets contain no stored data; protected data routes still require
/// a tenant-bound credential when requested from the same origin.
#[tokio::test]
async fn console_shell_is_public_but_contains_no_records_and_data_stays_authenticated() {
    let f = fixture().await;
    for (path, mime) in [
        ("/console", "text/html; charset=utf-8"),
        ("/console/app.js", "application/javascript; charset=utf-8"),
        ("/console/style.css", "text/css; charset=utf-8"),
    ] {
        let response = f
            .app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(response.headers()["content-type"], mime, "{path}");
        assert_eq!(response.headers()["cache-control"], "no-store", "{path}");
        assert_eq!(
            response.headers()["x-content-type-options"],
            "nosniff",
            "{path}"
        );
        let csp = response.headers()["content-security-policy"]
            .to_str()
            .unwrap();
        let directives: std::collections::BTreeSet<&str> = csp.split(';').map(str::trim).collect();
        for directive in [
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self'",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "form-action 'none'",
        ] {
            assert!(
                directives.contains(directive),
                "missing CSP directive {directive} for {path}"
            );
        }
        assert!(!csp.contains("unsafe-inline") && !csp.contains("unsafe-eval"));
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let body = std::str::from_utf8(&bytes).unwrap();
        for private in [
            READER_A,
            READER_B,
            WRITER_A,
            WRITER_B,
            &f.packet.agent.aip_id,
            &f.packet.packet_id_hex(),
            &f.verdict_id,
            &f.observation_id,
        ] {
            assert!(
                !body.contains(private),
                "static console must not embed credentials or stored records"
            );
        }
    }
    for path in [
        "/v1/access".into(),
        "/v1/agents".into(),
        "/v1/health".into(),
        "/v1/coverage".into(),
        format!("/v1/evidence/{}/metadata", f.packet.packet_id_hex()),
        format!("/v1/observations/{}/verification", f.observation_id),
        format!("/v1/verdicts/{}", f.verdict_id),
    ] {
        assert_eq!(
            call(&f.app, "GET", &path, None, None).await.0,
            StatusCode::UNAUTHORIZED,
            "{path}"
        );
    }
}

/// Cross-language smoke against the live Rust service and real signed
/// documents. Run with AIP_ENTERPRISE_CLIENT_SMOKE=/absolute/client_smoke.py.
#[tokio::test]
#[ignore = "requires the Python SDK/MCP client environment and a loopback listener"]
async fn real_http_clients_use_the_service_boundary() {
    let script =
        std::env::var("AIP_ENTERPRISE_CLIENT_SMOKE").expect("set AIP_ENTERPRISE_CLIENT_SMOKE");
    let python = std::env::var("AIP_ENTERPRISE_PYTHON").unwrap_or_else(|_| "python3".into());
    let f = fixture().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, f.app).await.unwrap() });
    let result = tokio::process::Command::new(python)
        .arg(script)
        .env("VANIAN_TEST_BASE_URL", format!("http://{address}"))
        .env("VANIAN_TEST_READER_A", READER_A)
        .env("VANIAN_TEST_READER_B", READER_B)
        .env("VANIAN_TEST_WRITER_A", WRITER_A)
        .env("VANIAN_TEST_EVIDENCE_ID", f.packet.packet_id_hex())
        .env("VANIAN_TEST_AGENT_ID", &f.packet.agent.aip_id)
        .env("VANIAN_TEST_VERDICT_ID", f.verdict_id)
        .env("VANIAN_TEST_OBSERVATION_ID", f.observation_id)
        .status()
        .await;
    server.abort();
    assert!(result.unwrap().success(), "enterprise client smoke failed");
}
