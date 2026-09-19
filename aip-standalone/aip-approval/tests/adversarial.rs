//! Shown-versus-authorized under attack, and under the ordinary case where
//! no human ever saw anything.
//!
//! The organising rule: a divergence is a statement about **two signed
//! documents**. Anything that weakens either document weakens the answer to
//! "cannot say", never to an accusation.

use aip_approval::*;
use aip_authorize::{
    ActionParameters, AuthorityRef, DecisionPointTrustAnchors, ExpectedExecution,
    EXPECTED_EXECUTION_VERSION,
};
use aip_crypto::{generate_ed25519_keypair, sha256, sign_ed25519};
use aip_types::{
    Action, ExecutionBinding, KeyPair, ProcessInstance, ScopeAction, EXECUTION_BINDING_VERSION,
};

const AGENT: &str = "aip:agent-under-test";
const DP: &str = "dp:decision-point-1";
const SURFACE: &str = "surface:console-1";
const DECISION: [u8; 16] = [0x33; 16];

struct Rig {
    dp: KeyPair,
    surface: KeyPair,
    agent: KeyPair,
    dp_anchors: DecisionPointTrustAnchors,
    surface_anchors: ApprovalSurfaceAnchors,
}

fn rig() -> Rig {
    let dp = generate_ed25519_keypair();
    let surface = generate_ed25519_keypair();
    let agent = generate_ed25519_keypair();
    let dp_anchors = DecisionPointTrustAnchors::new().trust(DP, &dp.public_key);
    let surface_anchors = ApprovalSurfaceAnchors::new().trust(SURFACE, &surface.public_key);
    Rig {
        dp,
        surface,
        agent,
        dp_anchors,
        surface_anchors,
    }
}

fn binding() -> ExecutionBinding {
    ExecutionBinding {
        version: EXECUTION_BINDING_VERSION,
        agent_id: AGENT.into(),
        process: ProcessInstance {
            pid: 4242,
            pid_start_time_ticks: 99_000,
            boot_id: [7u8; 16],
        },
        exe_content_sha256: sha256(b"the binary"),
        exe_path: "/usr/local/bin/agent".into(),
        bound_at_ms: 1_000,
        container: None,
    }
}

fn params(amount: &str) -> ActionParameters {
    ActionParameters::from_pairs([
        ("target", b"prod-db".to_vec()),
        ("rows", amount.as_bytes().to_vec()),
    ])
    .expect("well-formed parameters")
}

/// An expectation the decision point actually signed.
fn expectation(rig: &Rig, action: ScopeAction, parameter_digest: [u8; 32]) -> ExpectedExecution {
    let mut ee = ExpectedExecution {
        version: EXPECTED_EXECUTION_VERSION,
        decision_id: DECISION,
        decision_point_id: DP.into(),
        agent_id: AGENT.into(),
        authority: AuthorityRef {
            root_jti: [1u8; 16],
            chain_jtis: vec![],
        },
        action_kind: action,
        parameter_digest,
        execution_binding: binding(),
        issued_at: 1_000,
        valid_until: 60_000,
        decision_sig: sign_ed25519(&rig.dp.private_key, DP, b"placeholder").unwrap(),
    };
    ee.decision_sig = sign_ed25519(&rig.dp.private_key, DP, &ee.signing_preimage()).unwrap();
    ee
}

/// An artifact the surface actually signed, committing to `ee`.
fn artifact_for(
    rig: &Rig,
    ee: &ExpectedExecution,
    shown_action: ScopeAction,
    shown_parameter_digest: [u8; 32],
) -> SignedApprovalArtifact {
    let a = ApprovalArtifact {
        version: APPROVAL_ARTIFACT_VERSION,
        surface_id: SURFACE.into(),
        decision_id: ee.decision_id,
        expectation_digest: sha256(&ee.signing_preimage()),
        shown_digest: sha256(b"Delete 1206 rows from prod-db? [approve]"),
        shown_form: RenderedForm::PlainText,
        shown_action,
        shown_parameter_digest,
        approver_ref: "operator-7".into(),
        approved_at_ms: 1_500,
    };
    SignedApprovalArtifact::sign(a, &rig.surface.private_key).unwrap()
}

fn verified(rig: &Rig, signed: &SignedApprovalArtifact) -> VerifiedApprovalArtifact {
    verify_artifact(signed, &rig.surface_anchors, Some(&rig.agent.public_key))
        .expect("a genuine artifact verifies")
}

// ─── the honest path ───

#[test]
fn a01_shown_and_authorized_agree_and_the_basis_is_recomputable() {
    let r = rig();
    let p = params("12").digest();
    let ee = expectation(&r, ScopeAction::Standard(Action::Write), p);
    let signed = artifact_for(&r, &ee, ScopeAction::Standard(Action::Write), p);
    let v = verified(&r, &signed);
    assert_eq!(
        compare_shown_to_authorized(Some(&v), &ee, &r.dp_anchors),
        ShownVsAuthorized::Agrees {
            basis: Basis::Recomputable
        }
    );
}

// ─── the failure this crate exists for ───

#[test]
fn a02_the_replit_class_a_genuine_approval_of_something_other_than_what_was_sealed() {
    let r = rig();
    // The human was shown "12 rows". The decision point sealed "1206 rows".
    let shown = params("12").digest();
    let authorized = params("1206").digest();
    assert_ne!(shown, authorized);
    let ee = expectation(&r, ScopeAction::Standard(Action::Write), authorized);
    let signed = artifact_for(&r, &ee, ScopeAction::Standard(Action::Write), shown);
    let v = verified(&r, &signed);

    let result = compare_shown_to_authorized(Some(&v), &ee, &r.dp_anchors);
    assert_eq!(
        result,
        ShownVsAuthorized::Diverges {
            divergence: Divergence::ParametersDiffer { shown, authorized },
            basis: Basis::Recomputable,
        }
    );
    // And this is the predicate a reconciler entry point would gate on.
    assert!(result.is_recomputable_divergence());
}

#[test]
fn a03_a_different_action_kind_diverges() {
    let r = rig();
    let p = params("12").digest();
    let ee = expectation(&r, ScopeAction::Standard(Action::Write), p);
    // Shown as a read; sealed as a write.
    let signed = artifact_for(&r, &ee, ScopeAction::Standard(Action::Read), p);
    let v = verified(&r, &signed);
    assert_eq!(
        compare_shown_to_authorized(Some(&v), &ee, &r.dp_anchors),
        ShownVsAuthorized::Diverges {
            divergence: Divergence::ActionDiffers {
                shown: ScopeAction::Standard(Action::Read),
                authorized: ScopeAction::Standard(Action::Write),
            },
            basis: Basis::Recomputable,
        }
    );
}

#[test]
fn a04_an_approval_of_a_reissued_expectation_under_the_same_decision_id_diverges() {
    let r = rig();
    let p = params("12").digest();
    let first = expectation(&r, ScopeAction::Standard(Action::Write), p);
    // The decision point reissues: same decision id, a later window.
    let mut second = first.clone();
    second.valid_until = 120_000;
    second.decision_sig = sign_ed25519(&r.dp.private_key, DP, &second.signing_preimage()).unwrap();
    assert_eq!(first.decision_id, second.decision_id);

    // The human approved the *first*. Comparing against the second must not
    // silently pass just because the decision ids match.
    let signed = artifact_for(&r, &first, ScopeAction::Standard(Action::Write), p);
    let v = verified(&r, &signed);
    let result = compare_shown_to_authorized(Some(&v), &second, &r.dp_anchors);
    assert!(matches!(
        result,
        ShownVsAuthorized::Diverges {
            divergence: Divergence::ExpectationDiffers { .. },
            basis: Basis::Recomputable,
        }
    ));
}

// ─── absence is never an accusation ───

#[test]
fn a05_a_decision_no_human_saw_is_not_evaluated_and_is_not_a_finding() {
    let r = rig();
    let p = params("12").digest();
    let ee = expectation(&r, ScopeAction::Standard(Action::Write), p);
    let result = compare_shown_to_authorized(None, &ee, &r.dp_anchors);
    assert_eq!(
        result,
        ShownVsAuthorized::NotEvaluated {
            reason: NotEvaluatedReason::NoApprovalArtifact
        }
    );
    assert!(!result.is_recomputable_divergence());
    assert!(result.divergence().is_none());
}

#[test]
fn a06_an_artifact_for_another_decision_is_not_evaluated_rather_than_accused() {
    let r = rig();
    let p = params("12").digest();
    let ee = expectation(&r, ScopeAction::Standard(Action::Write), p);
    let mut other = ee.clone();
    other.decision_id = [0x99; 16];
    other.decision_sig = sign_ed25519(&r.dp.private_key, DP, &other.signing_preimage()).unwrap();

    let signed = artifact_for(&r, &other, ScopeAction::Standard(Action::Write), p);
    let v = verified(&r, &signed);
    let result = compare_shown_to_authorized(Some(&v), &ee, &r.dp_anchors);
    assert!(matches!(
        result,
        ShownVsAuthorized::NotEvaluated {
            reason: NotEvaluatedReason::DifferentDecision { .. }
        }
    ));
    assert!(!result.is_recomputable_divergence());
}

#[test]
fn a07_an_unverifiable_expectation_yields_no_comparison_not_a_divergence() {
    let r = rig();
    let p = params("12").digest();
    let ee = expectation(&r, ScopeAction::Standard(Action::Write), p);
    let signed = artifact_for(&r, &ee, ScopeAction::Standard(Action::Read), p); // would diverge
    let v = verified(&r, &signed);

    // A verifier that anchors nobody for this decision point.
    let empty = DecisionPointTrustAnchors::new();
    let result = compare_shown_to_authorized(Some(&v), &ee, &empty);
    assert_eq!(
        result,
        ShownVsAuthorized::NotEvaluated {
            reason: NotEvaluatedReason::ExpectationNotVerified
        }
    );
    // Critically: an unverified expectation must not produce an arithmetic
    // divergence, because the arithmetic would be over bytes nobody checked.
    assert!(!result.is_recomputable_divergence());
}

// ─── the artifact cannot be manufactured by the party under scrutiny ───

#[test]
fn a08_an_agent_holding_the_surface_key_cannot_manufacture_agreement() {
    let r = rig();
    let p = params("12").digest();
    let ee = expectation(&r, ScopeAction::Standard(Action::Write), p);

    // An operator wires the agent's own key up as the approval surface.
    let agent_is_surface = ApprovalSurfaceAnchors::new().trust(SURFACE, &r.agent.public_key);
    let a = ApprovalArtifact {
        version: APPROVAL_ARTIFACT_VERSION,
        surface_id: SURFACE.into(),
        decision_id: ee.decision_id,
        expectation_digest: sha256(&ee.signing_preimage()),
        shown_digest: sha256(b"whatever the agent wants to claim it showed"),
        shown_form: RenderedForm::PlainText,
        shown_action: ScopeAction::Standard(Action::Write),
        shown_parameter_digest: p,
        approver_ref: "operator-7".into(),
        approved_at_ms: 1_500,
    };
    let self_signed = SignedApprovalArtifact::sign(a, &r.agent.private_key).unwrap();
    assert_eq!(
        verify_artifact(&self_signed, &agent_is_surface, Some(&r.agent.public_key)),
        Err(ArtifactError::SurfaceKeyIsAgentKey)
    );
}

#[test]
fn a09_an_artifact_from_an_unanchored_surface_is_refused() {
    let r = rig();
    let p = params("12").digest();
    let ee = expectation(&r, ScopeAction::Standard(Action::Write), p);
    let mallory = generate_ed25519_keypair();

    // Signed by someone else, claiming the anchored surface's name.
    let a = ApprovalArtifact {
        version: APPROVAL_ARTIFACT_VERSION,
        surface_id: SURFACE.into(),
        decision_id: ee.decision_id,
        expectation_digest: sha256(&ee.signing_preimage()),
        shown_digest: [0u8; 32],
        shown_form: RenderedForm::PlainText,
        shown_action: ScopeAction::Standard(Action::Write),
        shown_parameter_digest: p,
        approver_ref: "operator-7".into(),
        approved_at_ms: 1_500,
    };
    let forged = SignedApprovalArtifact::sign(a.clone(), &mallory.private_key).unwrap();
    assert_eq!(
        verify_artifact(&forged, &r.surface_anchors, Some(&r.agent.public_key)),
        Err(ArtifactError::SignatureInvalid)
    );

    // And under a name nobody anchored, the verifier has no opinion at all.
    let mut unknown = a;
    unknown.surface_id = "surface:nobody".into();
    let signed = SignedApprovalArtifact::sign(unknown, &mallory.private_key).unwrap();
    assert_eq!(
        verify_artifact(&signed, &r.surface_anchors, None),
        Err(ArtifactError::SurfaceNotAnchored("surface:nobody".into()))
    );
}

#[test]
fn a10_a_tampered_artifact_does_not_verify() {
    let r = rig();
    let p = params("12").digest();
    let authorized = params("1206").digest();
    let ee = expectation(&r, ScopeAction::Standard(Action::Write), authorized);
    let mut signed = artifact_for(&r, &ee, ScopeAction::Standard(Action::Write), p);

    // Rewrite the shown digest after signing, to make a divergence vanish.
    signed.artifact.shown_parameter_digest = authorized;
    assert_eq!(
        verify_artifact(&signed, &r.surface_anchors, Some(&r.agent.public_key)),
        Err(ArtifactError::PayloadHashMismatch)
    );
}

// ─── boundaries this crate must not cross ───

#[test]
fn a11_agreement_says_nothing_about_what_executed() {
    // A property asserted by construction and pinned here so a later reader
    // does not mistake `Agrees` for evidence of execution. The type carries
    // no execution field, and the crate cannot name an observation type.
    let r = rig();
    let p = params("12").digest();
    let ee = expectation(&r, ScopeAction::Standard(Action::Write), p);
    let signed = artifact_for(&r, &ee, ScopeAction::Standard(Action::Write), p);
    let v = verified(&r, &signed);
    let result = compare_shown_to_authorized(Some(&v), &ee, &r.dp_anchors);
    let json = serde_json::to_string(&result).unwrap();
    for forbidden in ["observ", "execut", "verdict", "strength", "proven"] {
        assert!(
            !json.to_lowercase().contains(forbidden),
            "the comparison result must not speak about {forbidden}: {json}"
        );
    }
}

#[test]
fn a12_this_crate_cannot_name_the_observation_or_reconciliation_path() {
    // ADR-015 §5.1 extended to the approval tier: a comparison is not a
    // verdict, and a crate that could depend on the engine could become one.
    let manifest =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
    let deps = manifest.split("[dependencies]").nth(1).unwrap();
    let deps = deps.split("[dev-dependencies]").next().unwrap();
    for forbidden in [
        "aip-observe",
        "aip-observation",
        "aip-reconcile",
        "aip-warrant",
        "aip-containment",
    ] {
        let line = deps
            .lines()
            .find(|l| l.trim_start().starts_with(forbidden) && !l.trim_start().starts_with('#'));
        assert!(
            line.is_none(),
            "aip-approval must not depend on {forbidden}: {line:?}"
        );
    }
}

#[test]
fn a13_the_approval_domain_collides_with_no_other_signed_object() {
    // An approval signature must not verify as an expectation, and vice
    // versa. The domain tag leads both preimages, so a shared prefix is the
    // thing to rule out.
    let r = rig();
    let p = params("12").digest();
    let ee = expectation(&r, ScopeAction::Standard(Action::Write), p);
    let signed = artifact_for(&r, &ee, ScopeAction::Standard(Action::Write), p);
    let approval_bytes = signed.artifact.canonical_bytes();
    let expectation_bytes = ee.signing_preimage();
    assert_ne!(approval_bytes, expectation_bytes);
    assert!(!approval_bytes.starts_with(&expectation_bytes));
    assert!(!expectation_bytes.starts_with(&approval_bytes));
    assert_ne!(sha256(&approval_bytes), sha256(&expectation_bytes));
}
