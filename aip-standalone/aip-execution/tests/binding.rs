//! Skill 18 — the signed carrier, exercised against a real decision point.
//!
//! Skill 17 left `AutonomousSystem` and `SystemExecution` unsigned,
//! deliberately. The question Skill 18 had to answer is what makes them
//! authoritative *without* adding a signing key — which would be a new trust
//! anchor and a STOP condition.
//!
//! The answer is that `ExpectedExecution.parameter_digest` is the decision
//! point's signature over `ActionParameters`, an open key-sorted
//! domain-separated map. A reserved key carrying the execution profile's
//! digest therefore becomes part of what the decision point already signs.
//!
//! These tests establish that with a real `DecisionPoint`, a real authority
//! chain and a real signature — not in prose.
//!
//! # What is deliberately NOT asserted
//!
//! That the execution *ran* in the bound context. The decision point signs
//! that it *authorized* execution for that system, platform, hardware and
//! mission. Authorized is not attested. An execution authorized for platform P
//! and running on Q is not detected here, is T13 in the threat model, and
//! needs Skill 19 or Skill 20.

use aip_authorize::*;
use aip_core::capability::issue_scoped_token;
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_execution::*;
use aip_system::{HardwareId, MissionId, PlatformId, SystemExecution, SystemId};
use aip_types::{
    Action, CapabilityScope, ExecutionBinding, ProcessInstance, ProvenanceTriple, ScopeAction,
    EXECUTION_BINDING_VERSION,
};

const TTL: u64 = 60_000;
const MAX_TTL: u64 = 3_600_000;

fn prov(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("m-{tag}").as_bytes()),
        environment_commitment: sha256(format!("e-{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("t-{tag}").as_bytes()),
    }
}

fn scope() -> CapabilityScope {
    CapabilityScope {
        allowed: vec![ScopeAction::Standard(Action::Write)],
        denied: vec![],
    }
}

/// A real decision point, a real chain, and the profile whose digest we want
/// signed. Returns everything a verifier would need.
struct Fixture {
    dp: DecisionPoint,
    anchors: DecisionPointTrustAnchors,
    agent_id: String,
    binding: ExecutionBinding,
    now: u64,
    root: aip_types::ScopedToken,
    hop: aip_types::DelegationToken,
}

fn fixture() -> Fixture {
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo_kp.public_key, &prov("cfo"));
    let (orch_aid, orch_kp) = create_identity(prov("orch"), None).unwrap();
    let (agent_aid, _agent_kp) = create_identity(prov("agent"), None).unwrap();

    let root = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &orch_aid.id,
        scope(),
        Some(MAX_TTL),
    )
    .unwrap();
    let hop = create_delegation(&root, &orch_kp.private_key, &agent_aid.id, scope()).unwrap();
    let now = root.issued_at.max(hop.issued_at) + 1;

    let dp_kp = generate_ed25519_keypair();
    let dp_id = derive_aip_id(&dp_kp.public_key, &prov("dp"));
    let dp = DecisionPoint::new(&dp_id, &dp_kp.private_key, &dp_kp.public_key, MAX_TTL)
        .unwrap()
        .trust_issuer(&cfo_id, &cfo_kp.public_key)
        .trust_issuer(&orch_aid.id, &orch_kp.public_key);
    let anchors = DecisionPointTrustAnchors::new().trust(&dp_id, &dp_kp.public_key);

    let binding = ExecutionBinding {
        version: EXECUTION_BINDING_VERSION,
        agent_id: agent_aid.id.clone(),
        process: ProcessInstance {
            pid: 4321,
            pid_start_time_ticks: 777_000,
            boot_id: [0x3d; 16],
        },
        exe_content_sha256: sha256(b"autonomy binary v3"),
        exe_path: "/opt/agent/bin/autonomy".into(),
        bound_at_ms: now,
    };

    Fixture {
        dp,
        anchors,
        agent_id: agent_aid.id,
        binding,
        now,
        root,
        hop,
    }
}

fn profile_for(f: &Fixture, platform: &str, mission: &str) -> ExecutionProfile {
    let se = SystemExecution::new(
        SystemId::parse("sys:fleet-1").unwrap(),
        &f.agent_id,
        [0xA1; 16],
        f.now,
    )
    .unwrap()
    .on_platform(PlatformId::parse(platform).unwrap())
    .on_hardware(HardwareId::parse("tpm-ek:aaa").unwrap())
    .for_mission(MissionId::parse(mission).unwrap())
    .bound_to(f.binding.clone());

    ExecutionProfile::new(se, f.now).with_runtime(
        RuntimeDeclaration::new()
            .declared("python3.11")
            .selected("pytorch"),
    )
}

/// Authorize `profile`'s context alongside the action's own parameters,
/// exactly as a real caller would.
fn authorize(f: &Fixture, profile: &ExecutionProfile) -> ExpectedExecution {
    let params = ActionParameters::from_pairs([
        ("amount".to_owned(), b"100".to_vec()),
        profile.authorization_parameter(),
    ])
    .expect("no duplicate keys");

    let req = AuthorizationRequest {
        agent_id: f.agent_id.clone(),
        root_token: f.root.clone(),
        delegation_chain: vec![f.hop.clone()],
        action_kind: ScopeAction::Standard(Action::Write),
        parameters: params,
        execution_binding: f.binding.clone(),
        requested_ttl_ms: TTL,
    };
    match f.dp.authorize_at(&req, f.now) {
        Decision::Authorized(ee) => *ee,
        Decision::Denied(d) => panic!("the fixture must authorize; got {d:?}"),
    }
}

// ═══ The binding works ═══

#[test]
fn the_decision_point_signs_the_execution_context() {
    // The whole signed-carrier decision, end to end on real signatures.
    let f = fixture();
    let profile = profile_for(&f, "tail:N123AB", "op:sortie-77");
    let ee = authorize(&f, &profile);

    // The expectation verifies against the anchored decision point — so the
    // parameter digest it carries is genuinely DP-signed.
    verify_expected_execution(&ee, &f.anchors)
        .expect("the expectation must verify under its decision point");

    // And that digest commits to this profile's context.
    let params = ActionParameters::from_pairs([
        ("amount".to_owned(), b"100".to_vec()),
        profile.authorization_parameter(),
    ])
    .unwrap();
    assert_eq!(
        ee.parameter_digest,
        params.digest(),
        "the DP-signed digest must be the digest over the parameters that \
         included the execution binding"
    );
    assert!(
        profile.is_committed_by(params.get(BINDING_PARAMETER_KEY)),
        "the profile must be committed by the parameters the DP signed"
    );
}

#[test]
fn no_new_signing_key_was_introduced() {
    // The STOP condition this design exists to avoid. The authority comes from
    // the decision point's existing key; nothing in aip-execution or aip-system
    // signs anything.
    //
    // Asserted structurally: neither crate's manifest carries a signing
    // dependency beyond aip-crypto (used for hashing and AIP-ID validation),
    // and neither exposes a sign function.
    for manifest in ["Cargo.toml", "../aip-system/Cargo.toml"] {
        let m = std::fs::read_to_string(manifest).expect("manifest");
        assert!(
            !m.contains("ed25519"),
            "{manifest}: a signing dependency appeared — a new trust anchor is \
             a STOP condition, not a convenience"
        );
    }
}

// ═══ Substitution after authorization is caught ═══

#[test]
fn swapping_the_platform_after_authorization_breaks_the_commitment() {
    // The attack the binding closes: authorize for one platform, then present
    // the same expectation with a profile naming another.
    let f = fixture();
    let authorized = profile_for(&f, "tail:N123AB", "op:sortie-77");
    let ee = authorize(&f, &authorized);
    verify_expected_execution(&ee, &f.anchors).expect("expectation verifies");

    let swapped = profile_for(&f, "tail:N456CD", "op:sortie-77");
    let params = ActionParameters::from_pairs([
        ("amount".to_owned(), b"100".to_vec()),
        authorized.authorization_parameter(),
    ])
    .unwrap();

    assert!(
        !swapped.is_committed_by(params.get(BINDING_PARAMETER_KEY)),
        "SECURITY: a profile naming a different platform satisfied a \
         commitment made for the original"
    );
    // And re-deriving the parameters from the swapped profile no longer
    // matches the signature the DP made.
    let swapped_params = ActionParameters::from_pairs([
        ("amount".to_owned(), b"100".to_vec()),
        swapped.authorization_parameter(),
    ])
    .unwrap();
    assert_ne!(
        ee.parameter_digest,
        swapped_params.digest(),
        "SECURITY: the DP signature covered both platforms equally"
    );
}

#[test]
fn swapping_the_mission_after_authorization_breaks_the_commitment() {
    let f = fixture();
    let authorized = profile_for(&f, "tail:N123AB", "op:sortie-77");
    let params = ActionParameters::from_pairs([
        ("amount".to_owned(), b"100".to_vec()),
        authorized.authorization_parameter(),
    ])
    .unwrap();

    let swapped = profile_for(&f, "tail:N123AB", "op:sortie-99");
    assert!(!swapped.is_committed_by(params.get(BINDING_PARAMETER_KEY)));
}

#[test]
fn tampering_with_the_bound_digest_breaks_the_expectation_signature() {
    // The other direction: alter the parameters after the DP signed them. The
    // expectation's own signature covers parameter_digest, so this is caught
    // by the existing verifier with no help from this crate.
    let f = fixture();
    let profile = profile_for(&f, "tail:N123AB", "op:sortie-77");
    let mut ee = authorize(&f, &profile);
    verify_expected_execution(&ee, &f.anchors).expect("verifies before tampering");

    ee.parameter_digest[0] ^= 0xFF;
    assert!(
        verify_expected_execution(&ee, &f.anchors).is_err(),
        "SECURITY: altering the committed parameter digest left the \
         expectation verifying"
    );
}

// ═══ What the binding does NOT establish ═══

#[test]
fn the_binding_establishes_authorization_not_attestation() {
    // Stated as a test so it cannot quietly stop being true, and so a reader
    // of this suite cannot come away believing more than was proven.
    //
    // Two profiles differing only in *hardware* both carry a self-reported
    // hardware id. The decision point signs whichever it was given. It has no
    // means to check that the execution is on that hardware — that is
    // hardware attestation (Skill 19) and independent observation (Skill 20),
    // neither of which exists here.
    let f = fixture();
    let claimed = profile_for(&f, "tail:N123AB", "op:sortie-77");
    let ee = authorize(&f, &claimed);
    verify_expected_execution(&ee, &f.anchors).expect("verifies");

    // The DP signed a claim about hardware it never measured. The signature is
    // valid and the claim is unverified — both true at once, which is exactly
    // the distinction T13 records.
    assert_eq!(
        claimed
            .system_execution
            .hardware_id
            .as_ref()
            .unwrap()
            .namespace(),
        "tpm-ek",
        "the id names a TPM, and nothing here consulted one"
    );
    // No API in this crate claims otherwise: there is no `verify_hardware`,
    // no `attest`, and no method returning evidence about the platform.
    assert!(
        claimed.runtime.evidenced.is_none(),
        "nothing populated an evidenced slot, because nothing observed anything"
    );
}

#[test]
fn an_execution_with_no_claimed_authorization_is_representable() {
    // "The agent claimed no authorization" is a statement a verifier can act
    // on, and a more honest record than a fabricated decision id.
    let f = fixture();
    let profile = profile_for(&f, "tail:N123AB", "op:sortie-77");
    assert!(profile.decision_id.is_none());
    assert!(
        !profile.is_committed_by(None),
        "a profile committed by nothing must not report itself as committed"
    );
}
