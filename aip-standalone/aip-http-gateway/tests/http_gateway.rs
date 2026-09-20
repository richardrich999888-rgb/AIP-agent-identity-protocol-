//! Exit gate for the HTTP tool boundary (B10).
//!
//! Three properties define this crate, and each gets tests that fail if it is
//! weakened:
//!
//!   1. **The institution names the routes, not the gateway.** The route map
//!      is signed; a map whose tool_id was edited after signing does not
//!      verify, and a map where two routes could name one request is refused
//!      before it is ever resolved against.
//!   2. **Nothing reaches the upstream unnamed or unidentified.** Every
//!      refusal path is enumerated, and the ones that can still be receipted
//!      are receipted — a gap in the receipt stream must never be how a
//!      refused request disappears.
//!   3. **The gateway commits to what it received.** The commitment is the
//!      gateway's own recomputation, it is stable across the ways HTTP can
//!      carry the same arguments, and it is **byte-identical to the MCP
//!      gateway's** for the same arguments, so an institution that moves a
//!      tool between boundaries does not invalidate its own history.

use aip_airi::{
    verify_tool_receipt, GatewayDisposition, GatewaySigner, GatewayTrustAnchors, ToolCallId,
};
use aip_crypto::{generate_ed25519_keypair, sha256, sign_ed25519};
use aip_http_gateway::*;
use aip_types::Signature;
use serde_json::{json, Value};

const ISSUER: &str = "did:aip:institution:BANK";
const GATEWAY: &str = "did:aip:gateway:EDGE-1";
const AGENT: &str = "did:aip:agent:A1";
const DECISION_HEX: &str = "0123456789abcdef0123456789abcdef";
const NOW: u64 = 1_700_000_000_000;

fn decision_bytes() -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&DECISION_HEX[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn route(tool_id: &str, method: &str, path: &str) -> RouteEntry {
    RouteEntry {
        tool_id: tool_id.into(),
        method: method.into(),
        path: path.into(),
    }
}

/// An unsigned map, for the well-formedness tests.
fn unsigned(routes: Vec<RouteEntry>) -> RouteMap {
    RouteMap {
        version: ROUTE_MAP_VERSION,
        map_id: "edge-1".into(),
        issuer_id: ISSUER.into(),
        revision: 1,
        valid_from_ms: NOW,
        routes,
        signature: Signature {
            algorithm: aip_types::AlgorithmId::Ed25519,
            signer_id: ISSUER.into(),
            timestamp: NOW,
            nonce: [0u8; 16],
            payload_hash: [0u8; 32],
            signature_bytes: Vec::new(),
        },
    }
}

/// A map signed by a fresh institution key, with that key returned.
fn signed(routes: Vec<RouteEntry>) -> (RouteMap, Vec<u8>) {
    let kp = generate_ed25519_keypair();
    let mut map = unsigned(routes);
    let preimage = map.signing_preimage();
    map.signature = sign_ed25519(&kp.private_key, ISSUER, &preimage).unwrap();
    (map, kp.public_key.to_vec())
}

/// The estate of a small API: two literal routes and one parameterised.
fn estate() -> Vec<RouteEntry> {
    let mut routes = vec![
        route("tool.avoidance.plan", "POST", "/avoidance"),
        route("tool.orbit.path", "GET", "/orbits/{norad}"),
        route("tool.transfer.create", "POST", "/v1/transfers"),
    ];
    routes.sort_by(|a, b| (&a.method, &a.path).cmp(&(&b.method, &b.path)));
    routes
}

fn parts(method: &str, path: &str) -> RequestParts {
    RequestParts {
        method: method.into(),
        path: path.into(),
        agent_id: Some(AGENT.into()),
        decision_id: Some(DECISION_HEX.into()),
        ..Default::default()
    }
}

// ── 1. The institution names the routes ───────────────────────────────────

#[test]
fn rm01_a_signed_map_verifies_and_resolves_both_literal_and_parameterised() {
    let (map, key) = signed(estate());
    let anchors = RouteMapAnchors::new().trust(ISSUER, &key);
    map.verify(&anchors).expect("a signed map verifies");

    match map.resolve("POST", "/avoidance") {
        Resolution::Named {
            route,
            path_arguments,
        } => {
            assert_eq!(route.tool_id, "tool.avoidance.plan");
            assert!(path_arguments.is_empty());
        }
        other => panic!("expected a named route, got {other:?}"),
    }
    match map.resolve("GET", "/orbits/25544") {
        Resolution::Named {
            route,
            path_arguments,
        } => {
            assert_eq!(route.tool_id, "tool.orbit.path");
            assert_eq!(
                path_arguments,
                vec![("norad".to_string(), "25544".to_string())]
            );
        }
        other => panic!("expected a named route, got {other:?}"),
    }
    assert_eq!(map.resolve("GET", "/nope"), Resolution::Unrouted);
    assert_eq!(
        map.resolve("DELETE", "/avoidance"),
        Resolution::Unrouted,
        "the method is part of the identity"
    );
}

#[test]
fn rm02_editing_a_tool_id_after_signing_invalidates_the_map() {
    // The load-bearing property. If a gateway operator could rename a route
    // without the institution, every receipt it signs is a claim about a name
    // only the operator controls.
    let (mut map, key) = signed(estate());
    let anchors = RouteMapAnchors::new().trust(ISSUER, &key);
    assert!(map.verify(&anchors).is_ok());

    map.routes[0].tool_id = "tool.something.harmless".into();
    assert_eq!(
        map.verify(&anchors),
        Err(RouteMapError::PayloadHashMismatch),
        "a renamed route must not verify"
    );
}

#[test]
fn rm03_two_routes_that_could_name_one_request_are_refused() {
    // `/orbits/latest` and `/orbits/{norad}` both match `/orbits/latest`. A
    // first-match rule would make the meaning of a receipt depend on file
    // order, which no auditor can check.
    let mut routes = estate();
    routes.push(route("tool.orbit.latest", "GET", "/orbits/latest"));
    routes.sort_by(|a, b| (&a.method, &a.path).cmp(&(&b.method, &b.path)));
    let err = unsigned(routes).check_well_formed().unwrap_err();
    assert!(
        matches!(err, RouteMapError::Overlapping { .. }),
        "expected an overlap refusal, got {err:?}"
    );
}

#[test]
fn rm04_two_parameterised_routes_of_the_same_shape_overlap() {
    let routes = vec![
        route("tool.a", "GET", "/x/{a}"),
        route("tool.b", "GET", "/x/{b}"),
    ];
    assert!(matches!(
        unsigned(routes).check_well_formed().unwrap_err(),
        RouteMapError::Overlapping { .. }
    ));
}

#[test]
fn rm05_different_shapes_and_methods_do_not_overlap() {
    // The overlap test must not be so eager that a legitimate estate is
    // unrepresentable.
    let mut routes = vec![
        route("tool.a", "GET", "/x/{a}"),
        route("tool.b", "GET", "/x/{a}/y"),
        route("tool.c", "POST", "/x/{a}"),
        route("tool.d", "GET", "/y/z"),
    ];
    routes.sort_by(|a, b| (&a.method, &a.path).cmp(&(&b.method, &b.path)));
    unsigned(routes)
        .check_well_formed()
        .expect("distinct shapes and methods are not overlaps");
}

#[test]
fn rm06_structural_refusals() {
    let dup = vec![route("tool.a", "GET", "/x"), route("tool.b", "GET", "/x")];
    assert!(matches!(
        unsigned(dup).check_well_formed().unwrap_err(),
        RouteMapError::Duplicate { .. }
    ));

    let unsorted = vec![route("tool.b", "GET", "/z"), route("tool.a", "GET", "/a")];
    assert_eq!(
        unsigned(unsorted).check_well_formed().unwrap_err(),
        RouteMapError::NotSorted
    );

    for (path, why) in [
        ("relative/path", "not absolute"),
        ("/a//b", "empty segment"),
    ] {
        assert!(
            matches!(
                unsigned(vec![route("tool.a", "GET", path)])
                    .check_well_formed()
                    .unwrap_err(),
                RouteMapError::BadPath(_)
            ),
            "{path} should be refused: {why}"
        );
    }

    for path in ["/a/{}", "/a/{x", "/a/{x}/{x}"] {
        assert!(
            matches!(
                unsigned(vec![route("tool.a", "GET", path)])
                    .check_well_formed()
                    .unwrap_err(),
                RouteMapError::BadParameter { .. }
            ),
            "{path} should be refused as a bad parameter"
        );
    }

    assert!(matches!(
        unsigned(vec![route("tool.a", "get", "/x")])
            .check_well_formed()
            .unwrap_err(),
        RouteMapError::BadMethod(_)
    ));
    assert_eq!(
        unsigned(vec![]).check_well_formed().unwrap_err(),
        RouteMapError::NoRoutes
    );
}

#[test]
fn rm07_cryptographic_refusals() {
    let (map, key) = signed(estate());

    assert_eq!(
        map.verify(&RouteMapAnchors::new()),
        Err(RouteMapError::UntrustedIssuer(ISSUER.into())),
        "an unanchored issuer is refused, not trusted on its own say-so"
    );

    // Another institution's key must not verify this institution's map.
    let other = generate_ed25519_keypair();
    let anchors = RouteMapAnchors::new().trust(ISSUER, &other.public_key);
    assert_eq!(map.verify(&anchors), Err(RouteMapError::SignatureInvalid));

    // A signature naming a different signer than the issuer.
    let mut mismatched = map.clone();
    mismatched.signature.signer_id = "did:aip:institution:OTHER".into();
    assert_eq!(
        mismatched.verify(&RouteMapAnchors::new().trust(ISSUER, &key)),
        Err(RouteMapError::SignerMismatch)
    );
}

#[test]
fn rm08_an_empty_segment_never_matches_a_parameter() {
    // `/orbits/` is not a request for orbit "".
    let (map, _) = signed(estate());
    assert_eq!(map.resolve("GET", "/orbits/"), Resolution::Unrouted);
}

// ── 2. Nothing reaches the upstream unnamed or unidentified ───────────────

#[test]
fn ad01_a_named_identified_readable_request_is_admitted_with_merged_arguments() {
    let (map, _) = signed(estate());
    let mut p = parts("GET", "/orbits/25544");
    p.query = Some("points=180".into());
    match admit(&map, &p) {
        Admission::Admit(call) => {
            assert_eq!(call.tool_id, "tool.orbit.path");
            assert_eq!(call.agent_id, AGENT);
            assert_eq!(call.decision_id, decision_bytes());
            assert_eq!(call.arguments, json!({"norad": "25544", "points": "180"}));
        }
        other => panic!("expected admission, got {other:?}"),
    }
}

#[test]
fn ad02_an_unrouted_request_is_refused_and_cannot_be_receipted() {
    // There is no tool, so there is nothing a signed sentence could be about.
    // Nothing reaches the upstream, so there is no effect left unaccounted.
    let (map, _) = signed(estate());
    match admit(&map, &parts("POST", "/v1/transfers/secret-backdoor")) {
        Admission::RefuseWithoutReceipt(Unreceiptable::Unrouted { method, path }) => {
            assert_eq!(method, "POST");
            assert_eq!(path, "/v1/transfers/secret-backdoor");
        }
        other => panic!("expected an unrouted refusal, got {other:?}"),
    }
}

#[test]
fn ad03_an_unidentified_or_uncited_request_is_refused() {
    let (map, _) = signed(estate());

    let mut p = parts("POST", "/avoidance");
    p.agent_id = None;
    assert_eq!(
        admit(&map, &p),
        Admission::RefuseWithoutReceipt(Unreceiptable::NoAgentId)
    );

    let mut p = parts("POST", "/avoidance");
    p.agent_id = Some(String::new());
    assert_eq!(
        admit(&map, &p),
        Admission::RefuseWithoutReceipt(Unreceiptable::NoAgentId),
        "an empty agent id is an absent one, not an agent named \"\""
    );

    let mut p = parts("POST", "/avoidance");
    p.decision_id = None;
    assert_eq!(
        admit(&map, &p),
        Admission::RefuseWithoutReceipt(Unreceiptable::NoDecisionId)
    );

    for bad in ["", "abc", &"f".repeat(31), &"f".repeat(33), &"z".repeat(32)] {
        let mut p = parts("POST", "/avoidance");
        p.decision_id = Some(bad.to_string());
        assert_eq!(
            admit(&map, &p),
            Admission::RefuseWithoutReceipt(Unreceiptable::MalformedDecisionId),
            "{bad:?} is not a decision id"
        );
    }
}

#[test]
fn ad04_a_named_request_that_cannot_be_read_is_refused_and_still_receipted() {
    // A tool, an agent and a decision all exist, so the refusal can be stated.
    // A gap in the receipt stream must not be how a refused request vanishes.
    let (map, _) = signed(estate());
    let mut p = parts("POST", "/v1/transfers");
    p.body = Some(b"{not json".to_vec());
    match admit(&map, &p) {
        Admission::RefuseWithReceipt(call) => {
            assert_eq!(call.tool_id, "tool.transfer.create");
            assert_eq!(call.agent_id, AGENT);
            assert_eq!(call.reason, ArgumentError::BodyNotJson);
        }
        other => panic!("expected a receipted refusal, got {other:?}"),
    }
}

#[test]
fn ad05_an_ambiguous_request_is_refused_rather_than_guessed() {
    let (map, _) = signed(estate());
    let mut p = parts("GET", "/orbits/25544");
    // The path says 25544 and the query says 99999. Picking one is a guess.
    p.query = Some("norad=99999".into());
    match admit(&map, &p) {
        Admission::RefuseWithReceipt(call) => {
            assert!(matches!(call.reason, ArgumentError::Collision { .. }))
        }
        other => panic!("expected a receipted refusal, got {other:?}"),
    }
}

#[test]
fn ad06_the_first_failing_check_is_the_one_reported() {
    // An unrouted request with no headers is Unrouted, not NoAgentId: the
    // later checks would be answering questions about a request that already
    // has no name.
    let (map, _) = signed(estate());
    let p = RequestParts {
        method: "GET".into(),
        path: "/nowhere".into(),
        ..Default::default()
    };
    assert!(matches!(
        admit(&map, &p),
        Admission::RefuseWithoutReceipt(Unreceiptable::Unrouted { .. })
    ));
}

// ── 3. The gateway commits to what it received ────────────────────────────

fn gateway() -> (GatewaySigner, GatewayTrustAnchors) {
    let kp = generate_ed25519_keypair();
    let signer = GatewaySigner::new(GATEWAY, 1, &kp.private_key).unwrap();
    let anchors = GatewayTrustAnchors::new().trust(GATEWAY, 1, &kp.public_key);
    (signer, anchors)
}

fn admitted(map: &RouteMap, p: &RequestParts) -> AdmittedCall {
    match admit(map, p) {
        Admission::Admit(call) => call,
        other => panic!("expected admission, got {other:?}"),
    }
}

#[test]
fn rc01_the_receipt_verifies_under_the_gateways_anchored_key() {
    let (map, _) = signed(estate());
    let (signer, anchors) = gateway();
    let mut p = parts("POST", "/v1/transfers");
    p.body = Some(br#"{"amount":4000000,"beneficiary":"acct-9"}"#.to_vec());

    let call = admitted(&map, &p);
    let receipt = receipt_for_admitted(
        &signer,
        &call,
        GatewayDisposition::Forwarded,
        Some(&json!({"status": "ok"})),
        NOW,
    )
    .unwrap();

    let verified = verify_tool_receipt(&receipt, &anchors, None).expect("receipt verifies");
    assert_eq!(verified.receipt().gateway_id, GATEWAY);
    assert_eq!(verified.receipt().tool_id, "tool.transfer.create");
    assert_eq!(verified.receipt().agent_id, AGENT);
    assert_eq!(verified.receipt().decision_id, decision_bytes());
    assert_eq!(
        verified.receipt().disposition,
        GatewayDisposition::Forwarded
    );
    assert!(verified.receipt().response_commitment.is_some());
}

#[test]
fn rc02_an_unanchored_gateway_key_does_not_verify() {
    let (map, _) = signed(estate());
    let (signer, _) = gateway();
    let call = admitted(&map, &parts("POST", "/avoidance"));
    let receipt =
        receipt_for_admitted(&signer, &call, GatewayDisposition::Forwarded, None, NOW).unwrap();
    assert!(
        verify_tool_receipt(&receipt, &GatewayTrustAnchors::new(), None).is_err(),
        "a receipt from an unanchored gateway is not evidence"
    );
}

#[test]
fn rc03_the_commitment_is_the_gateways_own_reading_and_changes_with_the_arguments() {
    let (map, _) = signed(estate());
    let (signer, _) = gateway();

    let commit = |body: &[u8]| {
        let mut p = parts("POST", "/v1/transfers");
        p.body = Some(body.to_vec());
        let call = admitted(&map, &p);
        receipt_for_admitted(&signer, &call, GatewayDisposition::Forwarded, None, NOW)
            .unwrap()
            .receipt
            .parameter_commitment
    };

    // Key order and whitespace in transit do not change the commitment.
    assert_eq!(
        commit(br#"{"amount":4000000,"beneficiary":"acct-9"}"#),
        commit(b"{ \"beneficiary\" : \"acct-9\" ,\n \"amount\" : 4000000 }"),
    );
    // One digit of the amount does.
    assert_ne!(
        commit(br#"{"amount":4000000,"beneficiary":"acct-9"}"#),
        commit(br#"{"amount":4000001,"beneficiary":"acct-9"}"#),
    );
    // So does the beneficiary. This is the whole point of the boundary: an
    // unauthorised transfer is no longer "a connection to a known host".
    assert_ne!(
        commit(br#"{"amount":4000000,"beneficiary":"acct-9"}"#),
        commit(br#"{"amount":4000000,"beneficiary":"acct-EVIL"}"#),
    );
}

#[test]
fn rc04_an_http_receipt_is_byte_identical_to_an_mcp_receipt_for_the_same_arguments() {
    // The cross-boundary property. An institution that moves a tool from an
    // HTTP route to an MCP server must not invalidate its own history, and a
    // reconciler must not need to know which boundary issued a receipt.
    let (map, _) = signed(estate());
    let (signer, _) = gateway();
    let arguments = json!({"amount": 4_000_000, "beneficiary": "acct-9"});

    let mut p = parts("POST", "/v1/transfers");
    p.body = Some(serde_json::to_vec(&arguments).unwrap());
    let http = receipt_for_admitted(
        &signer,
        &admitted(&map, &p),
        GatewayDisposition::Forwarded,
        None,
        NOW,
    )
    .unwrap();

    let mcp = aip_mcp_gateway::issue_receipt(
        &signer,
        &aip_mcp_gateway::ToolCall {
            method: "tools/call".into(),
            tool_name: "tool.transfer.create".into(),
            decision_id: decision_bytes(),
            agent_id: AGENT.into(),
            tool_call_id: None,
            arguments,
        },
        GatewayDisposition::Forwarded,
        None,
        NOW,
    )
    .unwrap();

    assert_eq!(
        http.receipt.parameter_commitment, mcp.receipt.parameter_commitment,
        "the two boundaries must commit to the same arguments identically"
    );
    assert_eq!(
        http.receipt.canonical_bytes(),
        mcp.receipt.canonical_bytes(),
        "the whole receipt, not only the commitment"
    );
}

#[test]
fn rc05_a_refused_receipt_commits_to_nothing_it_could_not_read() {
    let (map, _) = signed(estate());
    let (signer, anchors) = gateway();
    let mut p = parts("POST", "/v1/transfers");
    p.body = Some(b"[1,2,3]".to_vec());

    let Admission::RefuseWithReceipt(call) = admit(&map, &p) else {
        panic!("expected a receipted refusal");
    };
    let receipt = receipt_for_refused(&signer, &call, NOW).unwrap();
    let verified = verify_tool_receipt(&receipt, &anchors, None).expect("it still verifies");

    assert_eq!(verified.receipt().disposition, GatewayDisposition::Refused);
    assert_eq!(verified.receipt().response_commitment, None);
    assert_eq!(
        verified.receipt().parameter_commitment,
        aip_mcp_gateway::args_commitment(&Value::Null),
        "a refusal commits to 'nothing I could read', which matches no expectation"
    );
    // And that is genuinely different from any real argument set, so it cannot
    // be mistaken for one.
    assert_ne!(
        verified.receipt().parameter_commitment,
        aip_mcp_gateway::args_commitment(&json!({}))
    );
}

#[test]
fn rc06_the_tool_call_id_is_carried_when_the_runtime_supplied_one() {
    let (map, _) = signed(estate());
    let (signer, _) = gateway();
    let mut p = parts("POST", "/avoidance");
    p.tool_call_id = Some("call_abc123".into());
    let receipt = receipt_for_admitted(
        &signer,
        &admitted(&map, &p),
        GatewayDisposition::Forwarded,
        None,
        NOW,
    )
    .unwrap();
    assert_eq!(
        receipt.receipt.tool_call_id,
        Some(ToolCallId("call_abc123".into()))
    );
}

#[test]
fn rc07_a_failed_upstream_is_recorded_as_failed_not_as_forwarded() {
    // The receipt says what the gateway did. An upstream that never answered
    // must not be recorded as one that did.
    let (map, _) = signed(estate());
    let (signer, _) = gateway();
    let receipt = receipt_for_admitted(
        &signer,
        &admitted(&map, &parts("POST", "/avoidance")),
        GatewayDisposition::Failed,
        None,
        NOW,
    )
    .unwrap();
    assert_eq!(receipt.receipt.disposition, GatewayDisposition::Failed);
    assert_eq!(receipt.receipt.response_commitment, None);
}

#[test]
fn rc08_the_signing_preimage_is_domain_separated() {
    // A route map must not be verifiable as any other signed document in this
    // system, or one signature could be replayed as another.
    let (map, _) = signed(estate());
    let preimage = map.signing_preimage();
    assert!(
        preimage.starts_with(ROUTE_MAP_DOMAIN.as_bytes())
            || preimage[..64]
                .windows(ROUTE_MAP_DOMAIN.len())
                .any(|w| w == ROUTE_MAP_DOMAIN.as_bytes()),
        "the domain tag must be in the preimage"
    );
    assert_eq!(map.signature.payload_hash, sha256(&preimage));
}

// ── 4. The migration, demonstrated end to end on a real signed document ───

mod hybrid_migration {
    //! The evidence-horizon claim, exercised rather than asserted.
    //!
    //! A route map is the institution's own signed statement, it goes over the
    //! wire as JSON, and it is verified offline from a published key — the
    //! same shape as every other signed artefact in this system. So it is a
    //! fair end-to-end target for the migration: seal, serialise, deserialise,
    //! verify under a policy.
    //!
    //! **Scope, stated so it is not overread:** this demonstrates the
    //! signature path, the wire round trip and the transition policy on ONE
    //! document type. The four evidence-signing authorities — collector,
    //! decision point, reconciler, gateway — are **not** migrated, and the
    //! technical brief's section 9a says so.

    use super::*;
    use aip_crypto::hybrid::{ml_dsa_public_key_from_seed, sign_hybrid, SignaturePolicy};

    /// The same estate, sealed with a hybrid signature instead of Ed25519.
    fn hybrid_signed(routes: Vec<RouteEntry>) -> (RouteMap, Vec<u8>, Vec<u8>) {
        let ed = generate_ed25519_keypair();
        let seed = [0x5eu8; 32];
        let ml_public = ml_dsa_public_key_from_seed(&seed).unwrap();
        let mut map = unsigned(routes);
        let preimage = map.signing_preimage();
        map.signature = sign_hybrid(&ed.private_key, &seed, ISSUER, &preimage).unwrap();
        (map, ed.public_key.to_vec(), ml_public)
    }

    #[test]
    fn hm01_a_hybrid_signed_map_survives_the_wire_and_verifies_under_a_strict_policy() {
        let (map, ed_pub, ml_pub) = hybrid_signed(estate());
        // Over the wire and back, exactly as the gateway loads it from disk.
        let json = serde_json::to_string(&map).unwrap();
        let loaded: RouteMap = serde_json::from_str(&json).unwrap();

        let anchors = RouteMapAnchors::new().trust(ISSUER, &ed_pub);
        loaded
            .verify_under_policy(&anchors, SignaturePolicy::HybridRequired, Some(&ml_pub))
            .expect("a hybrid map satisfies an institution that requires one");
        // And it still resolves: the signature change is invisible above it.
        assert!(matches!(
            loaded.resolve("POST", "/avoidance"),
            Resolution::Named { .. }
        ));
    }

    #[test]
    fn hm02_an_ed25519_map_still_verifies_during_the_transition() {
        // The non-negotiable property: nothing already deployed breaks.
        let (map, key) = signed(estate());
        let anchors = RouteMapAnchors::new().trust(ISSUER, &key);
        map.verify(&anchors)
            .expect("the original path is untouched");
        map.verify_under_policy(&anchors, SignaturePolicy::Transitional, None)
            .expect("and a transitional verifier accepts it with no ML-DSA key at all");
    }

    #[test]
    fn hm03_a_strict_verifier_refuses_an_ed25519_map_as_insufficient() {
        // The migration's cut-over, and the distinction that keeps an estate
        // mid-migration from reading as if it were under attack: this is
        // "correctly signed, no longer sufficient", not "bad signature".
        let (map, key) = signed(estate());
        let anchors = RouteMapAnchors::new().trust(ISSUER, &key);
        let refused = map
            .verify_under_policy(&anchors, SignaturePolicy::HybridRequired, None)
            .unwrap_err();
        assert!(
            matches!(
                refused,
                RouteMapError::Signature(aip_crypto::hybrid::HybridError::PolicyRequiresHybrid)
            ),
            "expected an insufficiency, got {refused:?}"
        );
        assert!(
            map.verify(&anchors).is_ok(),
            "the map itself is still valid"
        );
    }

    #[test]
    fn hm04_editing_a_route_after_hybrid_signing_is_still_caught() {
        // The property the map exists for must survive the algorithm change.
        let (mut map, ed_pub, ml_pub) = hybrid_signed(estate());
        map.routes[0].tool_id = "tool.something.harmless".into();
        let anchors = RouteMapAnchors::new().trust(ISSUER, &ed_pub);
        assert_eq!(
            map.verify_under_policy(&anchors, SignaturePolicy::HybridRequired, Some(&ml_pub)),
            Err(RouteMapError::PayloadHashMismatch)
        );
    }

    #[test]
    fn hm05_a_hybrid_map_without_the_second_key_is_refused_not_half_checked() {
        // A gateway provisioned with only the Ed25519 anchor must not verify
        // half a hybrid signature and report success.
        let (map, ed_pub, _ml_pub) = hybrid_signed(estate());
        let anchors = RouteMapAnchors::new().trust(ISSUER, &ed_pub);
        assert!(
            map.verify_under_policy(&anchors, SignaturePolicy::Transitional, None)
                .is_err(),
            "half a hybrid signature is not a verification"
        );
    }
}
