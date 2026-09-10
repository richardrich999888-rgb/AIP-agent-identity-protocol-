//! B-8 at the service boundary — replay checked against the tenant's store.
//!
//! The protocol half is in `aip-protocol/tests/replay.rs`: R17 catches a
//! duplicated attestation inside one packet, R18 catches a second packet
//! reusing a decision or action, and R18 is NOT EVALUATED without a history.
//!
//! This file establishes the half that only exists at the service: the
//! history is the tenant's own stored evidence, it is read only when the
//! caller asks, and the tenant boundary holds — one tenant's packets must
//! never make another tenant's packet look like a replay.

use aip_protocol::verification_report::rules;
use aip_protocol::VerificationReport;
use airon_aip::evidence::VerifyRequest;
use airon_aip::store::{EvidenceStore, JsonlEvidenceStore};
use airon_aip::ManagedSigning;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::collections::HashMap;
use std::sync::Arc;
use tower::ServiceExt;

mod support;
use support::{app_state, packet_dated, replay_pair};

/// A router plus the store behind it, so a test can seed the store directly
/// rather than through the generate endpoint — which is refused by default
/// now (B-7) and is not the ingest path under test here.
struct Service {
    app: axum::Router,
    store: Arc<dyn EvidenceStore>,
}

fn service() -> Service {
    let mut path = std::env::temp_dir();
    path.push(format!("aip_replay_{}.jsonl", uuid::Uuid::new_v4()));
    let store: Arc<dyn EvidenceStore> =
        Arc::new(JsonlEvidenceStore::load(path.to_str().expect("utf-8 path")));
    let (api_keys, _keys) = support::api_key_store("acme-secret", "acme");
    let app = airon_aip::router(app_state(
        Arc::clone(&store),
        api_keys,
        ManagedSigning::Refused,
    ));
    Service { app, store }
}

async fn post_verify(app: &axum::Router, req: &VerifyRequest) -> (StatusCode, String) {
    let body = serde_json::json!({
        "packet": req.packet,
        "trusted_issuers": req.trusted_issuers,
        "check_replay": req.check_replay,
    })
    .to_string();
    let resp = app
        .clone()
        .oneshot(
            Request::post("/v1/evidence/verify")
                .header("authorization", "Bearer acme-secret")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("request"),
        )
        .await
        .expect("response");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn report_of(body: &str) -> VerificationReport {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("report parses: {e}; body was {body}"))
}

fn vreq(
    packet: aip_protocol::EvidencePacket,
    issuers: HashMap<String, String>,
    check_replay: bool,
) -> VerifyRequest {
    VerifyRequest {
        packet,
        trusted_issuers: issuers,
        trusted_counterparties: HashMap::new(),
        revoked_jtis: vec![],
        trace_data: None,
        receipt_data: None,
        verification_time_ms: None,
        future_tolerance_ms: None,
        check_replay,
    }
}

fn r18(report: &VerificationReport) -> &aip_protocol::RuleResult {
    report
        .rule(rules::REPLAY_SCOPE)
        .expect("R18 must appear in the report")
}

#[tokio::test]
async fn not_asking_for_a_replay_check_reports_it_as_not_evaluated() {
    // The default must not imply freshness. A caller reading a clean report
    // without having asked has not been told the packet is new.
    let svc = service();
    let fx = packet_dated(0);
    let (status, body) = post_verify(&svc.app, &vreq(fx.packet, fx.issuers, false)).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let report = report_of(&body);
    assert!(
        !r18(&report).evaluated,
        "SECURITY (B-8): the service claimed to have checked for replay \
         without reading any history"
    );
}

#[tokio::test]
async fn asking_for_a_replay_check_against_an_empty_store_evaluates_and_passes() {
    // "I looked and found nothing" is a real answer, and distinct from the
    // test above. If this reported NOT EVALUATED, `check_replay` would be
    // doing nothing.
    let svc = service();
    let fx = packet_dated(0);
    let (status, body) = post_verify(&svc.app, &vreq(fx.packet, fx.issuers, true)).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let report = report_of(&body);
    let c = r18(&report);
    assert!(c.evaluated, "an empty store is still a history");
    assert!(c.pass, "{}", c.detail);
}

#[tokio::test]
async fn a_packet_already_in_the_store_is_not_a_replay_of_itself() {
    // The property that makes the feature usable. Ingest stores a packet and
    // re-verifies it; refusing it would break archival verification and make
    // `check_replay` unusable in the one place it belongs.
    let svc = service();
    let fx = packet_dated(0);
    svc.store
        .store("acme", &fx.packet)
        .await
        .expect("store the packet");

    let (_, body) = post_verify(&svc.app, &vreq(fx.packet, fx.issuers, true)).await;
    let report = report_of(&body);
    assert!(
        r18(&report).pass,
        "SECURITY (B-8): a stored packet was refused as a replay of itself: {}",
        r18(&report).detail
    );
    assert!(report.valid, "failures: {:?}", report.failures());
}

#[tokio::test]
async fn a_second_packet_reusing_a_stored_decision_is_refused() {
    // The attack at the service boundary: an agent submits a second,
    // different packet claiming a decision this tenant already recorded. Both
    // packets are correctly signed; only the store distinguishes them.
    let svc = service();
    let (first, second, issuers) = replay_pair();
    svc.store.store("acme", &first).await.expect("store first");

    let (_, body) = post_verify(&svc.app, &vreq(second, issuers, true)).await;
    let report = report_of(&body);
    assert!(
        !r18(&report).pass,
        "SECURITY (B-8): a second packet reusing a stored decision was accepted"
    );
    assert!(
        r18(&report).detail.contains(&hex::encode(first.packet_id)),
        "the refusal must name the packet that established the decision: {}",
        r18(&report).detail
    );
    assert!(!report.valid);
}

#[tokio::test]
async fn another_tenants_packets_do_not_make_this_one_a_replay() {
    // The tenant boundary, which the protocol layer cannot enforce because it
    // has no notion of tenants. The history is built from *this* caller's
    // tenant only; built from the whole store, one tenant could deny another
    // by ingesting a colliding packet first.
    //
    // The colliding packet is a genuinely different one sharing a decision
    // id — the same packet stored under another tenant would map to itself
    // and pass either way, proving nothing.
    let svc = service();
    let (first, second, issuers) = replay_pair();
    svc.store
        .store("other", &first)
        .await
        .expect("store under another tenant");

    let (_, body) = post_verify(&svc.app, &vreq(second, issuers, true)).await;
    let report = report_of(&body);
    assert!(
        r18(&report).pass,
        "SECURITY (B-8): another tenant's evidence made this packet look like \
         a replay. One tenant can deny another: {}",
        r18(&report).detail
    );
}

#[tokio::test]
async fn the_replay_check_is_reported_as_a_rule_the_caller_can_read() {
    // The report must carry the rule either way, so a caller can tell "no
    // replay" from "not checked" by reading `evaluated` rather than by
    // remembering what it asked for.
    let svc = service();
    for asked in [false, true] {
        let fx = packet_dated(0);
        let (_, body) = post_verify(&svc.app, &vreq(fx.packet, fx.issuers, asked)).await;
        let report = report_of(&body);
        assert_eq!(
            r18(&report).evaluated,
            asked,
            "R18's evaluated flag must reflect whether a history was consulted"
        );
    }
}
