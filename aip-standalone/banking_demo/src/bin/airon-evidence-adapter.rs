use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::Mutex;

use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::net::TcpListener;

use banking_demo::{generate_banking_evidence, verify_banking_packet, BankingEvidence};
#[path = "support/replay_journal.rs"]
mod replay_journal;
use replay_journal::ReplayStore;

#[derive(Clone)]
struct AppState {
    evidence: Arc<BankingEvidence>,
    store: Arc<Mutex<ReplayStore>>,
}

#[derive(Deserialize)]
struct VerifyRequest {
    packet: Value,
}

#[derive(Serialize)]
struct StatusResponse {
    status: &'static str,
    service: &'static str,
    mode: &'static str,
    verifier: &'static str,
    network_required: bool,
}

async fn status() -> Json<StatusResponse> {
    Json(StatusResponse {
        status: "ok",
        service: "AIRON Native Evidence Adapter",
        mode: "offline",
        verifier: "AIP cryptographic verifier",
        network_required: false,
    })
}

async fn demo(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "packet": state.evidence.packet,
        "description": "Generated and cryptographically signed banking EvidencePacket",
        "source": "AIP banking-demo library"
    }))
}

async fn replay_fixture(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let packet = state.evidence.generate_replay_packet().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "replay_fixture_generation_failed",
                "detail": e
            })),
        )
    })?;

    Ok(Json(json!({
        "packet": packet,
        "description": "Controlled replay fixture: validly signed packet reusing the original decision ID",
        "source": "AIP banking-demo replay fixture",
        "expected_result": "REJECTED_BY_REPLAY_SCOPE"
    })))
}

async fn action_replay_fixture(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let packet = state
        .evidence
        .generate_action_replay_packet()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "action_replay_fixture_generation_failed",
                    "detail": e
                })),
            )
        })?;

    Ok(Json(json!({
        "packet": packet,
        "description": "Controlled action replay fixture: validly signed packet with a new decision ID and reused action ID",
        "source": "AIP banking-demo action replay fixture",
        "expected_result": "REJECTED_BY_REPLAY_SCOPE"
    })))
}

async fn verify(
    State(state): State<AppState>,
    Json(request): Json<VerifyRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let packet: aip_protocol::EvidencePacket =
        serde_json::from_value(request.packet).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_evidence_packet",
                    "detail": e.to_string()
                })),
            )
        })?;

    // Serialize verification and history updates so concurrent requests
    // cannot both pass against the same stale replay history.
    let mut store = state.store.lock().await;

    let mut context = state.evidence.context.clone();
    context.observed_history = Some(store.history.clone());

    let report = verify_banking_packet(&packet, &context);

    // Persist accepted evidence before returning success. If persistence fails,
    // do not claim that replay protection has durably recorded the packet.
    if report.valid {
        store.record(&packet).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "replay_journal_write_failed",
                    "detail": e
                })),
            )
        })?;
    }

    drop(store);

    let unevaluated: Vec<_> = report
        .checks
        .iter()
        .filter(|check| !check.evaluated)
        .map(|check| {
            json!({
                "rule": check.rule,
                "detail": check.detail
            })
        })
        .collect();

    let evaluated_failures: Vec<_> = report
        .checks
        .iter()
        .filter(|check| check.evaluated && !check.pass)
        .map(|check| {
            json!({
                "rule": check.rule,
                "detail": check.detail
            })
        })
        .collect();

    let evaluated_checks = report.checks.iter().filter(|check| check.evaluated).count();

    let passed_checks = report
        .checks
        .iter()
        .filter(|check| check.evaluated && check.pass)
        .count();

    let unevaluated_count = unevaluated.len();
    let coverage_complete = unevaluated_count == 0;

    let verdict = if !report.valid {
        "REJECTED"
    } else if coverage_complete {
        "VERIFIED_COMPLETE"
    } else {
        "VALID_WITH_UNEVALUATED_CHECKS"
    };

    Ok(Json(json!({
        "valid": report.valid,
        "tampered": report.tampered,
        "verdict": verdict,
        "coverage_complete": coverage_complete,
        "evaluated_checks": evaluated_checks,
        "passed_checks": passed_checks,
        "evaluated_failure_count": evaluated_failures.len(),
        "unevaluated_count": unevaluated_count,
        "trust_floor": format!("{:?}", report.trust_floor),
        "claimed_trust_floor": format!("{:?}", report.claimed_trust_floor),
        "packet_id": report.packet_id,
        "agent_id": report.agent_id,
        "verification": report,
        "failures": evaluated_failures,
        "evaluated_failures": evaluated_failures,
        "not_evaluated": unevaluated
    })))
}

#[tokio::main]
async fn main() {
    let evidence = generate_banking_evidence().expect("Could not generate banking evidence");

    let report = verify_banking_packet(&evidence.packet, &evidence.context);

    println!("AIRON Native Evidence Adapter");
    println!("Generated packet: {}", evidence.packet.packet_id_hex());
    println!("Initial verification valid: {}", report.valid);
    println!("Initial trust floor: {:?}", report.trust_floor);

    let store = ReplayStore::open().expect("Could not open or validate persistent replay journal");
    println!("Replay journal: {}", store.path.display());
    println!("Loaded decisions: {}", store.history.decisions.len());
    println!("Loaded actions: {}", store.history.actions.len());

    let state = AppState {
        evidence: Arc::new(evidence),
        store: Arc::new(Mutex::new(store)),
    };

    let app = Router::new()
        .route("/api/evidence/status", get(status))
        .route("/api/evidence/demo", get(demo))
        .route("/api/evidence/replay-fixture", get(replay_fixture))
        .route(
            "/api/evidence/action-replay-fixture",
            get(action_replay_fixture),
        )
        .route("/api/evidence/verify", post(verify))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .with_state(state);

    let addr: SocketAddr = "127.0.0.1:8093".parse().unwrap();

    let listener = TcpListener::bind(addr)
        .await
        .expect("Could not bind adapter to 127.0.0.1:8093");

    println!("Listening at http://{addr}");
    println!("Offline mode: enabled");
    println!("No external network services required.");

    axum::serve(listener, app)
        .await
        .expect("Adapter server failed");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn journal_path() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "airon-evidence-replay-test-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        dir.join("journal.jsonl")
    }

    fn app_state(evidence: Arc<BankingEvidence>, store: ReplayStore) -> AppState {
        AppState {
            evidence,
            store: Arc::new(Mutex::new(store)),
        }
    }

    async fn submit(state: AppState, packet: Value) -> Result<Value, StatusCode> {
        verify(State(state), Json(VerifyRequest { packet }))
            .await
            .map(|response| response.0)
            .map_err(|(status, _)| status)
    }

    #[tokio::test]
    async fn verification_persists_before_success_and_rejects_replays_after_restart() {
        let path = journal_path();
        let evidence = Arc::new(generate_banking_evidence().unwrap());
        let decision_replay = evidence.generate_replay_packet().unwrap();
        let action_replay = evidence.generate_action_replay_packet().unwrap();
        let state = app_state(
            evidence.clone(),
            ReplayStore::open_path(path.clone()).unwrap(),
        );

        let malformed = submit(state.clone(), json!({"not": "an evidence packet"})).await;
        assert_eq!(malformed, Err(StatusCode::BAD_REQUEST));

        let mut tampered = serde_json::to_value(&evidence.packet).unwrap();
        tampered["decision"]["summary"] = json!("tampered after signing");
        let tampered_result = submit(state.clone(), tampered).await.unwrap();
        assert_eq!(tampered_result["valid"], false);

        let accepted = submit(
            state.clone(),
            serde_json::to_value(&evidence.packet).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(accepted["valid"], true);
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);

        for replay in [decision_replay.clone(), action_replay.clone()] {
            let response = submit(state.clone(), serde_json::to_value(replay).unwrap())
                .await
                .unwrap();
            assert_eq!(response["valid"], false);
            assert!(response["evaluated_failure_count"].as_u64().unwrap() > 0);
        }

        drop(state);
        let reopened = app_state(
            evidence.clone(),
            ReplayStore::open_path(path.clone()).unwrap(),
        );
        let replay_after_restart = submit(
            reopened.clone(),
            serde_json::to_value(decision_replay).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(replay_after_restart["valid"], false);

        drop(reopened);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
