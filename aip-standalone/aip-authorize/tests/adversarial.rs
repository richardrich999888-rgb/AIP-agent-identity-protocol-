//! Adversarial tests for the decision point and `ExpectedExecution`
//! (Skill 5 §24, Tests A–J) plus denial and temporal boundaries.
//!
//! Every negative test names the exact rejection. No test asserts that an
//! execution happened — this layer has no such concept.

use std::collections::HashMap;

use aip_authorize::*;
use aip_core::capability::{
    issue_scoped_token, scope_admin, scope_orchestrator, scope_submitter, verify_scoped_token,
};
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256, sign_ed25519};
use aip_types::{
    Action, ExecutionBinding, KeyPair, ProcessInstance, ProvenanceTriple, ScopeAction, ScopedToken,
    EXECUTION_BINDING_VERSION,
};

fn provenance(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("model-{tag}").as_bytes()),
        environment_commitment: sha256(format!("env-{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("toolchain-{tag}").as_bytes()),
    }
}

fn binding_for(agent_id: &str) -> ExecutionBinding {
    ExecutionBinding {
        version: EXECUTION_BINDING_VERSION,
        agent_id: agent_id.to_string(),
        process: ProcessInstance {
            pid: 4242,
            pid_start_time_ticks: 433_843,
            boot_id: [0x0c; 16],
        },
        exe_content_sha256: sha256(b"payments-agent binary v1"),
        exe_path: "/opt/agent/bin/payments-agent".into(),
        bound_at_ms: 1_700_000_000_000,
    }
}

const TTL: u64 = 60_000;
const MAX_TTL: u64 = 3_600_000;

struct Fx {
    dp: DecisionPoint,
    dp_kp: KeyPair,
    anchors: DecisionPointTrustAnchors,
    req: AuthorizationRequest,
    now: u64,
    cfo_id: String,
    cfo_kp: KeyPair,
    orch_id: String,
    orch_kp: KeyPair,
    agent_id: String,
    agent_kp: KeyPair,
}

fn fixture() -> Fx {
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo_kp.public_key, &provenance("cfo"));
    let (orch_aid, orch_kp) = create_identity(provenance("orchestrator"), None).unwrap();
    let (agent_aid, agent_kp) = create_identity(provenance("payments-agent"), None).unwrap();

    let root = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &orch_aid.id,
        scope_orchestrator(),
        Some(3_600_000),
    )
    .unwrap();
    let hop = create_delegation(
        &root,
        &orch_kp.private_key,
        &agent_aid.id,
        scope_submitter(),
    )
    .unwrap();
    let now = root.issued_at.max(hop.issued_at) + 1;

    let dp_kp = generate_ed25519_keypair();
    let dp_id = derive_aip_id(&dp_kp.public_key, &provenance("decision-point"));
    let dp = DecisionPoint::new(&dp_id, &dp_kp.private_key, &dp_kp.public_key, MAX_TTL)
        .unwrap()
        .trust_issuer(&cfo_id, &cfo_kp.public_key)
        .trust_issuer(&orch_aid.id, &orch_kp.public_key);
    let anchors = DecisionPointTrustAnchors::new().trust(&dp_id, &dp_kp.public_key);

    let req = AuthorizationRequest {
        agent_id: agent_aid.id.clone(),
        root_token: root,
        delegation_chain: vec![hop],
        action_kind: ScopeAction::Standard(Action::Write),
        parameters: ActionParameters::from_pairs([
            ("invoice", b"INV-2026-0142".to_vec()),
            ("amount_cents", b"4820000".to_vec()),
        ])
        .unwrap(),
        execution_binding: binding_for(&agent_aid.id),
        requested_ttl_ms: TTL,
    };

    Fx {
        dp,
        dp_kp,
        anchors,
        req,
        now,
        cfo_id,
        cfo_kp,
        orch_id: orch_aid.id,
        orch_kp,
        agent_id: agent_aid.id,
        agent_kp,
    }
}

fn authorized(f: &Fx) -> ExpectedExecution {
    match f.dp.authorize_at(&f.req, f.now) {
        Decision::Authorized(ee) => *ee,
        Decision::Denied(d) => panic!("expected authorization, got denial {d:?}"),
    }
}

fn denied_with(f: &Fx, req: &AuthorizationRequest, now: u64, reason: DenialReason) {
    match f.dp.authorize_at(req, now) {
        Decision::Denied(d) => {
            assert_eq!(d.reason, reason, "wrong denial reason: {d:?}");
        }
        Decision::Authorized(ee) => panic!("expected {reason:?}, got authorization {ee:?}"),
    }
}

// ─── Happy path ───

#[test]
fn honest_request_is_authorized_and_verifies_offline() {
    let f = fixture();
    let ee = authorized(&f);
    assert_eq!(ee.version, EXPECTED_EXECUTION_VERSION);
    assert_ne!(ee.decision_id, [0u8; 16]);
    assert_eq!(ee.decision_point_id, f.dp.id());
    assert_eq!(ee.agent_id, f.agent_id);
    assert_eq!(ee.authority.root_jti, f.req.root_token.jti);
    assert_eq!(ee.authority.chain_jtis, vec![f.req.delegation_chain[0].jti]);
    assert_eq!(ee.action_kind, ScopeAction::Standard(Action::Write));
    assert_eq!(ee.parameter_digest, f.req.parameters.digest());
    assert!(ee
        .execution_binding
        .same_execution(&f.req.execution_binding));
    assert_eq!(ee.issued_at, f.now);
    assert_eq!(ee.valid_until, f.now + TTL);
    assert_eq!(verify_expected_execution(&ee, &f.anchors), Ok(()));
    assert_eq!(
        verify_expected_execution_for_agent(&ee, &f.anchors, &f.agent_kp.public_key),
        Ok(())
    );

    // Offline: JSON round-trip, then verify with nothing but the anchor.
    let json = serde_json::to_string(&ee).unwrap();
    let restored: ExpectedExecution = serde_json::from_str(&json).unwrap();
    assert_eq!(restored, ee);
    assert_eq!(verify_expected_execution(&restored, &f.anchors), Ok(()));
}

#[test]
fn each_decision_gets_a_fresh_decision_id() {
    let f = fixture();
    let a = authorized(&f);
    let b = authorized(&f);
    assert_ne!(a.decision_id, b.decision_id);
}

// ─── Tests A–F: post-signing mutation of every security-sensitive field ───

fn assert_mutation_rejected(f: &Fx, name: &str, mutate: impl Fn(&mut ExpectedExecution)) {
    let mut ee = authorized(f);
    mutate(&mut ee);
    assert_eq!(
        verify_expected_execution(&ee, &f.anchors),
        Err(ExpectedVerifyError::PayloadHashMismatch),
        "mutating {name} must be rejected"
    );
}

#[test]
fn test_a_valid_until_mutation_rejected() {
    let f = fixture();
    assert_mutation_rejected(&f, "valid_until (extend)", |e| e.valid_until = u64::MAX);
    assert_mutation_rejected(&f, "valid_until (+1)", |e| e.valid_until += 1);
}

#[test]
fn test_b_issued_at_mutation_rejected() {
    let f = fixture();
    assert_mutation_rejected(&f, "issued_at", |e| e.issued_at -= 1);
}

#[test]
fn test_c_action_kind_mutation_rejected() {
    let f = fixture();
    assert_mutation_rejected(&f, "action_kind", |e| {
        e.action_kind = ScopeAction::Standard(Action::Admin)
    });
    assert_mutation_rejected(&f, "action_kind (custom)", |e| {
        e.action_kind = ScopeAction::Custom("write".into())
    });
}

#[test]
fn test_d_parameter_digest_mutation_rejected() {
    let f = fixture();
    let other = ActionParameters::from_pairs([
        ("invoice", b"INV-2026-0142".to_vec()),
        ("amount_cents", b"482000000".to_vec()),
    ])
    .unwrap()
    .digest();
    assert_ne!(other, f.req.parameters.digest());
    assert_mutation_rejected(&f, "parameter_digest", move |e| e.parameter_digest = other);
}

#[test]
fn test_e_execution_binding_mutation_rejected() {
    let f = fixture();
    assert_mutation_rejected(&f, "binding.pid_start", |e| {
        e.execution_binding.process.pid_start_time_ticks += 1
    });
    assert_mutation_rejected(&f, "binding.boot_id", |e| {
        e.execution_binding.process.boot_id[0] ^= 0xff
    });
    assert_mutation_rejected(&f, "binding.exe", |e| {
        e.execution_binding.exe_content_sha256[0] ^= 0x01
    });
    assert_mutation_rejected(&f, "binding.exe_path", |e| {
        e.execution_binding.exe_path.push('x')
    });
}

#[test]
fn test_f_decision_id_and_authority_mutation_rejected() {
    let f = fixture();
    assert_mutation_rejected(&f, "decision_id", |e| e.decision_id[0] ^= 0x01);
    assert_mutation_rejected(&f, "authority.root_jti", |e| {
        e.authority.root_jti[0] ^= 0x01
    });
    assert_mutation_rejected(&f, "authority.chain_jtis", |e| {
        e.authority.chain_jtis.clear()
    });
}

#[test]
fn version_mutation_is_rejected_structurally() {
    // `assert_mutation_rejected` expects PayloadHashMismatch; a version change
    // is caught even earlier, so pin that explicitly.
    let f = fixture();
    let mut ee = authorized(&f);
    ee.version = 7;
    assert_eq!(
        verify_expected_execution(&ee, &f.anchors),
        Err(ExpectedVerifyError::UnsupportedVersion(7))
    );
}

// ─── Test G: domain substitution ───

#[test]
fn test_g_expected_execution_signature_cannot_verify_as_scoped_token() {
    let f = fixture();
    let ee = authorized(&f);
    // A token whose fields mirror the expectation and which carries the
    // genuine decision-point signature. Different domain ⇒ different preimage.
    let forged = ScopedToken {
        jti: ee.decision_id,
        agent_id: ee.agent_id.clone(),
        issuer_id: ee.decision_point_id.clone(),
        scope: scope_submitter(),
        issued_at: ee.issued_at,
        expires_at: Some(ee.valid_until),
        issuer_sig: ee.decision_sig.clone(),
    };
    assert!(!verify_scoped_token(&forged, &f.dp_kp.public_key).unwrap());

    // And the preimage is led by its own tag, distinct from every other tag.
    let pre = ee.signing_preimage();
    let tag = EXPECTED_EXECUTION_DOMAIN.as_bytes();
    assert_eq!(&pre[4..4 + tag.len()], tag);
    for other in [
        aip_core::capability::SCOPED_TOKEN_DOMAIN,
        aip_core::delegation::DELEGATION_TOKEN_DOMAIN,
        aip_types::EXECUTION_BINDING_DOMAIN,
        aip_types::EXECUTION_IDENTITY_DOMAIN,
        ACTION_PARAMETERS_DOMAIN,
    ] {
        assert_ne!(EXPECTED_EXECUTION_DOMAIN, other);
    }
}

// ─── Test H: agent-controlled signing key ───

#[test]
fn test_h_agent_running_its_own_decision_point_is_denied() {
    let f = fixture();
    // The agent stands up a "decision point" under its own identity and key.
    let rogue = DecisionPoint::new(
        &f.agent_id,
        &f.agent_kp.private_key,
        &f.agent_kp.public_key,
        MAX_TTL,
    )
    .unwrap()
    .trust_issuer(&f.cfo_id, &f.cfo_kp.public_key)
    .trust_issuer(&f.orch_id, &f.orch_kp.public_key);
    match rogue.authorize_at(&f.req, f.now) {
        Decision::Denied(d) => assert_eq!(d.reason, DenialReason::SelfAuthorization),
        Decision::Authorized(_) => panic!("agent authorized itself"),
    }
}

#[test]
fn test_h_agent_key_under_a_fake_decision_point_id_is_not_trusted() {
    let f = fixture();
    // The agent stands up a decision point under a *different* id but with
    // its own key. It can sign anything it likes...
    let fake_id = "aip1FakeDecisionPoint";
    let rogue = DecisionPoint::new(
        fake_id,
        &f.agent_kp.private_key,
        &f.agent_kp.public_key,
        MAX_TTL,
    )
    .unwrap()
    .trust_issuer(&f.cfo_id, &f.cfo_kp.public_key)
    .trust_issuer(&f.orch_id, &f.orch_kp.public_key);
    let ee = match rogue.authorize_at(&f.req, f.now) {
        Decision::Authorized(ee) => *ee,
        Decision::Denied(d) => panic!("rogue could not even sign: {d:?}"),
    };
    // ...but the verifier's anchors do not include it.
    assert_eq!(
        verify_expected_execution(&ee, &f.anchors),
        Err(ExpectedVerifyError::UntrustedDecisionPoint(fake_id.into()))
    );
    // And if an operator is tricked into anchoring the agent's key under the
    // fake id, the agent-aware verifier still refuses.
    let tricked = DecisionPointTrustAnchors::new().trust(fake_id, &f.agent_kp.public_key);
    assert_eq!(
        verify_expected_execution(&ee, &tricked),
        Ok(()),
        "signature itself is valid"
    );
    assert_eq!(
        verify_expected_execution_for_agent(&ee, &tricked, &f.agent_kp.public_key),
        Err(ExpectedVerifyError::DecisionKeyIsAgentKey)
    );
}

#[test]
fn test_h_handcrafted_expectation_naming_agent_as_decision_point_rejected() {
    let f = fixture();
    let mut ee = authorized(&f);
    ee.decision_point_id = f.agent_id.clone();
    let pre = ee.signing_preimage();
    ee.decision_sig = sign_ed25519(&f.agent_kp.private_key, &f.agent_id, &pre).unwrap();
    let anchors = DecisionPointTrustAnchors::new().trust(&f.agent_id, &f.agent_kp.public_key);
    assert_eq!(
        verify_expected_execution(&ee, &anchors),
        Err(ExpectedVerifyError::SelfAuthorization)
    );
}

#[test]
fn wrong_anchor_key_or_signer_id_is_rejected_distinctly() {
    let f = fixture();
    let ee = authorized(&f);
    let other = generate_ed25519_keypair();
    let wrong = DecisionPointTrustAnchors::new().trust(f.dp.id(), &other.public_key);
    assert_eq!(
        verify_expected_execution(&ee, &wrong),
        Err(ExpectedVerifyError::SignatureInvalid)
    );
    let mut ee2 = ee.clone();
    ee2.decision_sig.signer_id = "aip1SomeoneElse".into();
    assert_eq!(
        verify_expected_execution(&ee2, &f.anchors),
        Err(ExpectedVerifyError::SignerMismatch)
    );
    let none = DecisionPointTrustAnchors::new();
    assert_eq!(
        verify_expected_execution(&ee, &none),
        Err(ExpectedVerifyError::UntrustedDecisionPoint(
            f.dp.id().to_string()
        ))
    );
}

// ─── Test I: temporal semantics ───

#[test]
fn test_i_window_is_inclusive_at_both_ends() {
    let f = fixture();
    let ee = authorized(&f);
    assert_eq!(
        ee.temporal_status_at(ee.issued_at - 1),
        TemporalStatus::NotYetValid
    );
    assert_eq!(ee.temporal_status_at(ee.issued_at), TemporalStatus::Valid);
    assert_eq!(ee.temporal_status_at(ee.valid_until), TemporalStatus::Valid);
    assert_eq!(
        ee.temporal_status_at(ee.valid_until + 1),
        TemporalStatus::Expired
    );
}

#[test]
fn test_i_decision_after_authority_expiry_is_denied() {
    let f = fixture();
    let exp = f.req.root_token.expires_at.unwrap();
    // Boundary: decision exactly at expiry is still inside (R10 convention).
    match f.dp.authorize_at(&f.req, exp) {
        Decision::Authorized(ee) => assert_eq!(ee.valid_until, exp, "clamped to authority expiry"),
        Decision::Denied(d) => panic!("at-boundary decision denied: {d:?}"),
    }
    denied_with(&f, &f.req, exp + 1, DenialReason::AuthorityExpired);
}

#[test]
fn test_i_decision_before_authority_issuance_is_denied() {
    let f = fixture();
    denied_with(
        &f,
        &f.req,
        f.req.root_token.issued_at - 1,
        DenialReason::AuthorityNotYetValid,
    );
}

#[test]
fn expectation_never_outlives_the_authority_chain() {
    let f = fixture();
    let mut req = f.req.clone();
    req.requested_ttl_ms = MAX_TTL; // longer than the remaining authority window
    match f.dp.authorize_at(&req, f.now) {
        Decision::Authorized(ee) => {
            let exp = f.req.root_token.expires_at.unwrap();
            assert_eq!(ee.valid_until, exp);
            assert!(ee.valid_until < f.now + MAX_TTL);
        }
        Decision::Denied(d) => panic!("{d:?}"),
    }
}

#[test]
fn ttl_policy_is_enforced() {
    let f = fixture();
    let mut req = f.req.clone();
    req.requested_ttl_ms = 0;
    denied_with(&f, &req, f.now, DenialReason::InvalidTtl);
    req.requested_ttl_ms = MAX_TTL + 1;
    denied_with(&f, &req, f.now, DenialReason::TtlExceedsPolicy);
}

#[test]
fn invalid_window_is_rejected_structurally() {
    let f = fixture();
    let mut ee = authorized(&f);
    ee.valid_until = ee.issued_at - 1;
    let pre = ee.signing_preimage();
    ee.decision_sig = sign_ed25519(&f.dp_kp.private_key, f.dp.id(), &pre).unwrap();
    assert_eq!(
        verify_expected_execution(&ee, &f.anchors),
        Err(ExpectedVerifyError::InvalidWindow {
            issued_at: ee.issued_at,
            valid_until: ee.valid_until
        })
    );
}

// ─── Test J: cross-decision / cross-binding transplantation ───

#[test]
fn test_j_expectation_covers_only_its_own_decision_and_execution() {
    let f = fixture();
    let a = authorized(&f);
    let b = authorized(&f);
    assert!(a.covers(&a.decision_id, &f.agent_id, &f.req.execution_binding));
    assert!(!a.covers(&b.decision_id, &f.agent_id, &f.req.execution_binding));
    assert!(!a.covers(&a.decision_id, &f.orch_id, &f.req.execution_binding));

    // Same PID, different start ticks — a different process instance.
    let mut reused_pid = f.req.execution_binding.clone();
    reused_pid.process.pid_start_time_ticks += 1;
    assert!(!a.covers(&a.decision_id, &f.agent_id, &reused_pid));

    // Different path spelling, same instance — still covered.
    let mut respelled = f.req.execution_binding.clone();
    respelled.exe_path = "/opt/../opt/agent/bin/payments-agent".into();
    assert!(a.covers(&a.decision_id, &f.agent_id, &respelled));

    // Transplanting B's decision id onto A breaks A's signature.
    let mut a2 = a.clone();
    a2.decision_id = b.decision_id;
    assert_eq!(
        verify_expected_execution(&a2, &f.anchors),
        Err(ExpectedVerifyError::PayloadHashMismatch)
    );
}

// ─── Denials: the decision point consumes AIP authority, it does not invent it ───

#[test]
fn unknown_root_issuer_is_denied() {
    let f = fixture();
    let dp = DecisionPoint::new(
        f.dp.id(),
        &f.dp_kp.private_key,
        &f.dp_kp.public_key,
        MAX_TTL,
    )
    .unwrap()
    .trust_issuer(&f.orch_id, &f.orch_kp.public_key); // cfo NOT trusted
    match dp.authorize_at(&f.req, f.now) {
        Decision::Denied(d) => assert_eq!(d.reason, DenialReason::UnknownIssuer),
        Decision::Authorized(_) => panic!("authorized under an untrusted issuer"),
    }
}

#[test]
fn unknown_hop_issuer_is_denied() {
    let f = fixture();
    let dp = DecisionPoint::new(
        f.dp.id(),
        &f.dp_kp.private_key,
        &f.dp_kp.public_key,
        MAX_TTL,
    )
    .unwrap()
    .trust_issuer(&f.cfo_id, &f.cfo_kp.public_key); // orchestrator NOT trusted
    match dp.authorize_at(&f.req, f.now) {
        Decision::Denied(d) => assert_eq!(d.reason, DenialReason::UnknownIssuer),
        Decision::Authorized(_) => panic!("authorized with an unknown hop issuer"),
    }
}

#[test]
fn self_issued_root_authority_is_denied_even_if_the_agent_key_is_trusted() {
    // The exact closed loop from CURRENT_SYSTEM §6: the agent issues itself
    // an admin token and an operator (mistakenly) trusts the agent as issuer.
    let f = fixture();
    let self_root = issue_scoped_token(
        &f.agent_id,
        &f.agent_kp.private_key,
        &f.agent_id,
        scope_admin(),
        Some(3_600_000),
    )
    .unwrap();
    let dp = DecisionPoint::new(
        f.dp.id(),
        &f.dp_kp.private_key,
        &f.dp_kp.public_key,
        MAX_TTL,
    )
    .unwrap()
    .trust_issuer(&f.agent_id, &f.agent_kp.public_key);
    let mut req = f.req.clone();
    req.root_token = self_root;
    req.delegation_chain.clear();
    req.action_kind = ScopeAction::Standard(Action::Admin);
    match dp.authorize_at(&req, f.now) {
        Decision::Denied(d) => assert_eq!(d.reason, DenialReason::SelfIssuedAuthority),
        Decision::Authorized(_) => panic!("agent authorized under its own root token"),
    }
}

#[test]
fn tampered_root_token_is_denied() {
    let f = fixture();
    let mut req = f.req.clone();
    req.root_token.scope = scope_admin(); // escalate after issuance
    denied_with(&f, &req, f.now, DenialReason::RootTokenSignatureInvalid);
}

#[test]
fn tampered_delegation_hop_is_denied() {
    let f = fixture();
    let mut req = f.req.clone();
    req.delegation_chain[0].expires_at = Some(u64::MAX); // the Skill 3 attack
    denied_with(&f, &req, f.now, DenialReason::DelegationChainInvalid);
}

#[test]
fn out_of_scope_action_is_denied() {
    let f = fixture();
    let mut req = f.req.clone();
    req.action_kind = ScopeAction::Standard(Action::Admin); // submitter is Write only
    denied_with(&f, &req, f.now, DenialReason::ActionOutOfScope);
    req.action_kind = ScopeAction::Standard(Action::Read);
    denied_with(&f, &req, f.now, DenialReason::ActionOutOfScope);
}

#[test]
fn chain_leaf_must_be_the_requesting_agent() {
    let f = fixture();
    // The orchestrator asks for authorization using a chain that ends at the agent.
    let mut req = f.req.clone();
    req.agent_id = f.orch_id.clone();
    req.execution_binding = binding_for(&f.orch_id);
    denied_with(&f, &req, f.now, DenialReason::ChainLeafNotAgent);
}

#[test]
fn binding_for_another_agent_or_degenerate_binding_is_denied() {
    let f = fixture();
    let mut req = f.req.clone();
    req.execution_binding = binding_for(&f.orch_id);
    denied_with(&f, &req, f.now, DenialReason::BindingAgentMismatch);

    let mut req = f.req.clone();
    req.execution_binding.process.pid = 0;
    denied_with(&f, &req, f.now, DenialReason::BindingMalformed);
    let mut req = f.req.clone();
    req.execution_binding.exe_content_sha256 = [0u8; 32];
    denied_with(&f, &req, f.now, DenialReason::BindingMalformed);
}

#[test]
fn a_denial_carries_no_expectation() {
    let f = fixture();
    let mut req = f.req.clone();
    req.action_kind = ScopeAction::Standard(Action::Admin);
    let d = f.dp.authorize_at(&req, f.now);
    assert!(d.expected().is_none());
    assert!(d.denial().is_some());
}

#[test]
fn decision_point_constructor_rejects_bad_material() {
    let kp = generate_ed25519_keypair();
    assert_eq!(
        DecisionPoint::new("", &kp.private_key, &kp.public_key, 1).err(),
        Some(DecisionPointError::EmptyId)
    );
    assert_eq!(
        DecisionPoint::new("dp", &kp.private_key[..31], &kp.public_key, 1).err(),
        Some(DecisionPointError::InvalidPrivateKeyLength(31))
    );
    assert_eq!(
        DecisionPoint::new("dp", &kp.private_key, &kp.public_key, 0).err(),
        Some(DecisionPointError::ZeroMaxTtl)
    );
    // Debug output never leaks the private key.
    let dp = DecisionPoint::new("dp", &kp.private_key, &kp.public_key, 1).unwrap();
    let dbg = format!("{dp:?}");
    assert!(dbg.contains("<redacted>"));
    assert!(!dbg.contains(&format!("{:?}", kp.private_key)));
}

#[test]
fn request_type_carries_no_key_material() {
    // Compile-time property made visible: an AuthorizationRequest is built
    // from public identifiers, signed tokens, parameters and a binding only.
    let f = fixture();
    let json = format!("{:?}", f.req);
    assert!(!json.contains("private_key"));
    assert!(!json.contains("seed"));
    let _unused: HashMap<String, Vec<u8>> = HashMap::new();
}
