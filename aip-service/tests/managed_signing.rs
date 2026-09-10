//! B-7 — private seeds in HTTP request bodies.
//!
//! # The finding
//!
//! `POST /v1/evidence/generate` requires `agent_seed_hex`: the acting agent's
//! *private* Ed25519 key, in a JSON body, on every call. It was served
//! unconditionally.
//!
//! Two costs, distinct and both real:
//!
//! **Exposure.** The key crosses the network and comes to rest wherever
//! request bodies come to rest — TLS-terminating proxies, access logs, APM
//! traces, crash reports, client retry buffers. A signing key cannot be
//! withdrawn from any of those.
//!
//! **Attribution.** A packet signed this way says "this agent acted", but the
//! service held the agent's key. The signature cannot distinguish the agent
//! from the service, which is precisely the distinction the packet exists to
//! carry.
//!
//! # What these tests establish
//!
//! That the route is refused unless a deployment opts in; that refusal is a
//! property of the routing table, so no request body is deserialized on the
//! refusing path; and that the seed is redacted from `Debug`, which is the
//! most likely accidental logging route on the path that *is* enabled.
//!
//! # What they do not establish
//!
//! That the seed is scrubbed from memory. `String` does not zeroise, and the
//! bytes survive in the heap and possibly in a core dump until reallocated.
//! Closing that needs a secret-string type through the deserialization path,
//! which is more than this blocker's minimum fix; it is recorded as a
//! residual risk rather than implied to be handled.

use airon_aip::store::{EvidenceStore, JsonlEvidenceStore};
use airon_aip::{router, ManagedSigning};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use tower::ServiceExt;

mod support;

/// The seed a caller would be asked to send. Distinctive so a test can search
/// a response for it and know it came from the request.
const SEED_HEX: &str = "aa11bb22cc33dd44ee55ff6607182930415263748596a7b8c9dae0f102132435";

fn app(managed: ManagedSigning) -> axum::Router {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "aip_managed_signing_{}.jsonl",
        uuid::Uuid::new_v4()
    ));
    let store: Arc<dyn EvidenceStore> =
        Arc::new(JsonlEvidenceStore::load(path.to_str().expect("utf-8 path")));
    let (api_keys, _keys_file) = support::api_key_store("acme-secret", "acme");
    router(support::app_state(store, api_keys, managed))
}

async fn post_generate_with(managed: ManagedSigning, body: String) -> (StatusCode, String) {
    let resp = app(managed)
        .oneshot(
            Request::post("/v1/evidence/generate")
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

/// Post a request carrying a distinctive substitute seed. Used by every test
/// that checks the refusing path, where generation never happens so the seed
/// need not match the fixture's identity.
async fn post_generate(managed: ManagedSigning) -> (StatusCode, String) {
    post_generate_with(managed, support::generate_request_json(Some(SEED_HEX))).await
}

// ═══ The endpoint is refused by default ═══

#[tokio::test]
async fn managed_signing_is_off_unless_a_deployment_opts_in() {
    let (status, body) = post_generate(ManagedSigning::Refused).await;
    assert_eq!(
        status,
        StatusCode::NOT_IMPLEMENTED,
        "SECURITY (B-7): the service accepted a private agent seed in a \
         request body without the deployment having enabled managed signing. \
         Body: {body}"
    );
}

#[tokio::test]
async fn the_refusal_says_what_to_do_instead() {
    // An operator hitting a 501 must be able to act on it without reading the
    // source. Both halves matter: the alternative, and the opt-in.
    let (_, body) = post_generate(ManagedSigning::Refused).await;
    assert!(
        body.contains("/v1/evidence/verify"),
        "the refusal must name the supported path: {body}"
    );
    assert!(
        body.contains("AIP_ALLOW_MANAGED_SIGNING"),
        "the refusal must name the opt-in: {body}"
    );
}

#[tokio::test]
async fn the_refusal_does_not_echo_the_seed() {
    // The failure mode that would make the fix worse than the defect: a
    // rejection that quotes the offending body back into a log or a client.
    let (_, body) = post_generate(ManagedSigning::Refused).await;
    assert!(
        !body.contains(SEED_HEX),
        "SECURITY (B-7): the refusal echoed the private seed"
    );
    assert!(
        !body.contains(&SEED_HEX[..16]),
        "SECURITY (B-7): the refusal echoed part of the private seed"
    );
}

#[tokio::test]
async fn the_refusing_route_does_not_parse_the_body_at_all() {
    // Refusal is a property of the routing table, not a check inside a
    // handler that already deserialized the seed. A body that no `Json`
    // extractor could accept must produce the same 501 — if it produced a 400
    // instead, something parsed it.
    let resp = app(ManagedSigning::Refused)
        .oneshot(
            Request::post("/v1/evidence/generate")
                .header("authorization", "Bearer acme-secret")
                .header("content-type", "application/json")
                .body(Body::from("{ this is not json"))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_IMPLEMENTED,
        "SECURITY (B-7): a malformed body reached a deserializer on the \
         refusing path, so a well-formed one carrying a seed would too"
    );
}

// ═══ Opting in still works, and is the only way in ═══

#[tokio::test]
async fn an_opted_in_deployment_still_serves_the_endpoint() {
    // The counterweight: refusal must be a posture, not a breakage. If this
    // failed, the tests above would be measuring a broken route.
    // The real seed, so the packet's agent identity matches its delegation.
    let (status, body) = post_generate_with(
        ManagedSigning::Permitted,
        support::generate_request_json(None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "generation failed: {body}");
}

// ═══ The environment is read fail-closed ═══

#[test]
fn only_an_explicit_opt_in_permits_managed_signing() {
    // Unset, empty, "0", "no", "TRUE", a typo — all refuse. A security
    // posture must not turn on because someone exported the variable while
    // trying to turn it off.
    for value in [
        "", "0", "no", "false", "yes", "TRUE", "True", " 1", "1 ", "enabled",
    ] {
        std::env::set_var("AIP_ALLOW_MANAGED_SIGNING", value);
        assert_eq!(
            ManagedSigning::from_env(),
            ManagedSigning::Refused,
            "SECURITY (B-7): {value:?} enabled managed signing"
        );
    }
    std::env::remove_var("AIP_ALLOW_MANAGED_SIGNING");
    assert_eq!(ManagedSigning::from_env(), ManagedSigning::Refused);

    for value in ["1", "true"] {
        std::env::set_var("AIP_ALLOW_MANAGED_SIGNING", value);
        assert_eq!(ManagedSigning::from_env(), ManagedSigning::Permitted);
    }
    std::env::remove_var("AIP_ALLOW_MANAGED_SIGNING");
}

// ═══ The seed is not printable ═══

#[test]
fn debug_formatting_redacts_the_agent_seed() {
    // The realistic leak on the enabled path: a `tracing::debug!(?req)` added
    // later, or a panic message from an `unwrap` on a struct holding the
    // request. A derived `Debug` would print the key.
    let (mut req, _) = support::sample_generate_request();
    req.agent_seed_hex = SEED_HEX.to_owned();
    let rendered = format!("{req:?}");

    assert!(
        !rendered.contains(SEED_HEX),
        "SECURITY (B-7): Debug printed the agent's private seed"
    );
    assert!(
        rendered.contains("<redacted>"),
        "the field must still be visible as present: {rendered}"
    );
    // And the non-secret fields must survive, or the redaction has destroyed
    // the diagnostic value the impl exists to preserve.
    assert!(rendered.contains("principal_id"));
}

#[test]
fn debug_formatting_redacts_the_counterparty_seed() {
    let receipt = airon_aip::evidence::ReceiptInput {
        receipt_system: "ledger".into(),
        receipt_id: "r-1".into(),
        receipt_content: "{}".into(),
        counterparty_id: Some("aip1counterparty".into()),
        counterparty_seed_hex: Some(SEED_HEX.to_owned()),
    };
    let rendered = format!("{receipt:?}");
    assert!(
        !rendered.contains(SEED_HEX),
        "SECURITY (B-7): Debug printed the counterparty's private seed"
    );
    assert!(
        rendered.contains("aip1counterparty"),
        "non-secret fields survive"
    );
}
