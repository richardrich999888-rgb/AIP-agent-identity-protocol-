//! The threat model, executed.
//!
//! `src/threat.rs` declares what each of the seven layers does about each of
//! the thirteen threats. This file stages each threat as a real attack and
//! pushes the *same* adversarial artifact through every layer, recording what
//! each one actually did. `src/empirical.rs` maps each observation onto the
//! one disposition it corroborates, and
//! [`every_executed_cell_agrees_with_the_declared_model`] fails when an
//! observation contradicts the declaration.
//!
//! # Two things a reader should know before believing any of it
//!
//! **The outcome→disposition mapping is mechanical; deciding which outcome an
//! observation *is* is not.** `Rejected` means the layer denied the attacker
//! what they were after at that layer; `Unnoticed` means the layer's output
//! was what it would have been anyway. The same gate output can therefore be
//! `Rejected` for one threat and `Unnoticed` for another, because the threats
//! wanted different things — X07 wants a forgery believed, X11 wants the
//! workload blamed for a broken observer, and the warrant gate answers both
//! with the same verdict-determined response. That the response *is*
//! verdict-determined is measured separately, by
//! [`the_warrant_layer_makes_no_threat_specific_distinction`].
//!
//! **`NotStageable` is not a pass.** An attack that could not be staged here
//! corroborates nothing and is counted on its own. Two results in this file
//! are of that kind and both are findings, not omissions — see
//! [`sensor_deception_could_not_be_staged_at_all`] and
//! [`the_containment_replay_gate_is_unreachable_from_engine_output`].

mod staging;

use aip_airi::{
    sign_airi_event, verify_airi_event, AiriEvent, AiriPayload, Completion, FrameworkIdentity,
    ModelProvenance, ReportedOutcome, ToolInvocation, ToolReport, AIRI_EVENT_VERSION,
};
use aip_conformance::empirical::{ExecutionLog, Outcome};
use aip_conformance::threat::{Layer, Threat};
use aip_containment::{
    contain, ActuationFailure, Actuator, Applied, Attributed, ContainmentAction,
    ContainmentAnchors, ContainmentAuthority, ContainmentMode, ContainmentPolicy,
    ContainmentRequest, Mechanism, MemoryReplayLedger,
};
use aip_core::capability::{issue_scoped_token, scope_submitter, verify_scoped_token};
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_observation::{class_of, ObservationClass};
use aip_observe::{
    verify_attested_batch, ContinuityFault, ObserverLedger, ObserverTrustAnchors, SourceMechanism,
};
use aip_reconcile::{
    reconcile_expectation, EvidenceStrength, Reconciliation, ReconciliationResult,
};
use aip_warrant::{
    evaluate, Finding, Refusal, ResponseClass, ResponseTarget, Severity, Warrant, WarrantPolicy,
};

use staging::*;

// ═══ Shared apparatus ════════════════════════════════════════════════════

/// The most permissive policy an operator can set. Using it everywhere means
/// that whatever stops a response is the structure, not the configuration.
fn maximal_policy() -> WarrantPolicy {
    let mut p = WarrantPolicy {
        autonomous_containment: true,
        allow_constrain_on_attested: true,
        ..WarrantPolicy::default()
    };
    for r in [
        ReconciliationResult::VerifiedExecution,
        ReconciliationResult::CannotProve,
        ReconciliationResult::PhantomClaim,
        ReconciliationResult::UnattributedEffect,
        ReconciliationResult::IdentityDivergence,
        ReconciliationResult::LineageViolation,
        ReconciliationResult::ContinuityFailure,
        ReconciliationResult::SensorIntegrityFailure,
    ] {
        p = p.with_severity(r, Severity::Critical);
    }
    p
}

/// One observation of the warrant engine: what it was asked, and what it
/// answered. The key is everything the engine is *supposed* to read; if two
/// samples share a key and differ in their answer, some threat-specific rule
/// exists and every `NotDetectable` warrant cell is wrong.
#[derive(Debug, Clone)]
struct GateSample {
    threat: Threat,
    key: String,
    answer: String,
}

/// Put a real verdict to the warrant engine under the maximal policy.
fn gate(rec: &Reconciliation, subject: &str, now: u64) -> Result<Warrant, Refusal> {
    let f = Finding {
        finding_id: [0x5a; 16],
        reconciliation: rec.clone(),
        subject_agent: Some(subject.to_string()),
    };
    evaluate(&f, &maximal_policy(), now)
}

fn sample(threat: Threat, w: &Warrant) -> GateSample {
    GateSample {
        threat,
        key: format!(
            "{}/{:?}/unavailable={}/cited={}/protected={}",
            w.reconciliation_result.as_str(),
            w.evidence_strength,
            w.observation_unavailable,
            !w.evidence_refs.is_empty(),
            w.protected
        ),
        answer: format!("{:?}/{:?}/{:?}", w.response, w.target, w.severity),
    }
}

/// The warrant layer's answer for a threat whose attack the gate has no
/// opinion about: the response is whatever the verdict implies.
fn warrant_unnoticed(w: &Warrant) -> Outcome {
    Outcome::Unnoticed {
        evidence: format!(
            "evaluate under the maximal policy -> {:?}/{:?}; determined by the verdict alone, \
             and identical for a benign record of the same class",
            w.response, w.target
        ),
    }
}

/// A recording double. It never touches a process; `applied` is what it was
/// asked to do, and across this file it must stay empty.
#[derive(Default)]
struct Recorder {
    applied: Vec<(u32, ContainmentAction)>,
}

impl Actuator for Recorder {
    fn mechanism(&self) -> Mechanism {
        Mechanism::TestDouble
    }
    fn apply(
        &mut self,
        target: &Attributed,
        action: ContainmentAction,
    ) -> Result<Applied, ActuationFailure> {
        self.applied.push((target.process().pid, action));
        Ok(Applied {
            mechanism: Mechanism::TestDouble,
            handle: format!("double:{}", target.process().pid),
        })
    }
    fn release(&mut self, _applied: &Applied) -> Result<(), ActuationFailure> {
        Ok(())
    }
}

/// Drive a real warrant all the way to `contain()` and report what happened.
/// Returns the outcome label and whether the actuator was touched.
fn drive_containment(w: &Warrant, x: &Expected, now: u64) -> (String, bool) {
    let wk = generate_ed25519_keypair();
    let ck = generate_ed25519_keypair();
    let authority =
        ContainmentAuthority::new("containment-authority", &ck.private_key, &ck.public_key)
            .unwrap();
    let signed =
        aip_warrant::WarrantAuthority::new("warrant-authority", &wk.private_key, &wk.public_key)
            .unwrap()
            .sign(w.clone())
            .unwrap();
    let anchors = ContainmentAnchors {
        warrant: aip_warrant::WarrantTrustAnchors::new().trust("warrant-authority", &wk.public_key),
        observer: ObserverTrustAnchors::new(),
    };
    let policy = ContainmentPolicy {
        mode: ContainmentMode::AutonomousEnabled,
        action: ContainmentAction::FreezeProcess,
        max_health_age_ms: HEALTH_MAX_AGE,
        ..ContainmentPolicy::default()
    };
    let binding = binding_for(&x.agent_id);
    let req = ContainmentRequest {
        warrant: &signed,
        target: &binding,
        observer_health: None,
        operator_ack: None,
    };
    let mut actuator = Recorder::default();
    let mut ledger = MemoryReplayLedger::default();
    let c = contain(
        &req,
        &policy,
        &anchors,
        &mut ledger,
        &mut actuator,
        &authority,
        now,
    )
    .expect("the containment record must sign");
    let label = match &c.record.record.outcome {
        aip_containment::Outcome::Refused(r) => format!("Refused({})", refusal_label(r)),
        aip_containment::Outcome::Advisory => "Advisory".to_string(),
        aip_containment::Outcome::Applied { .. } => "Applied".to_string(),
        aip_containment::Outcome::Failed(_) => "Failed".to_string(),
        aip_containment::Outcome::Released { .. } => "Released".to_string(),
    };
    (label, !actuator.applied.is_empty())
}

/// The refusal's *kind*, without any id, key or clock reading in it — the log
/// has to be byte-identical across runs.
fn refusal_label(r: &aip_containment::Refusal) -> &'static str {
    use aip_containment::Refusal as R;
    match r {
        R::WarrantInvalid(_) => "WarrantInvalid",
        R::NoValidityBound => "NoValidityBound",
        R::WarrantNotYetValid { .. } => "WarrantNotYetValid",
        R::WarrantExpired { .. } => "WarrantExpired",
        R::ResponseNotContain(_) => "ResponseNotContain",
        R::TargetNotWorkload => "TargetNotWorkload",
        R::StrengthBelowProven(_) => "StrengthBelowProven",
        R::ResultNotWorkloadViolation(_) => "ResultNotWorkloadViolation",
        R::ObservationUnavailable => "ObservationUnavailable",
        R::NoEvidenceReference => "NoEvidenceReference",
        R::WarrantNotAutonomous => "WarrantNotAutonomous",
        R::WarrantMarkedProtected => "WarrantMarkedProtected",
        R::SubjectUnbound => "SubjectUnbound",
        R::SubjectMismatch { .. } => "SubjectMismatch",
        R::Protected { .. } => "Protected",
        R::OperatorAcknowledgementMissing => "OperatorAcknowledgementMissing",
        R::OperatorAcknowledgementMismatch => "OperatorAcknowledgementMismatch",
        R::ObserverHealthMissing => "ObserverHealthMissing",
        R::ObserverHealthUntrusted(_) => "ObserverHealthUntrusted",
        R::ObserverHealthStale { .. } => "ObserverHealthStale",
        R::ObserverNotCited { .. } => "ObserverNotCited",
        R::ObserverNotActive(_) => "ObserverNotActive",
        R::Replayed { .. } => "Replayed",
        R::Attribution(_) => "Attribution",
    }
}

/// The containment layer's answer for a threat it has no opinion about: it
/// refuses for a reason drawn from the warrant's own fields, and never acts.
fn containment_unnoticed(label: &str, actuated: bool) -> Outcome {
    assert!(!actuated, "no attack in this file may reach the actuator");
    Outcome::Unnoticed {
        evidence: format!(
            "contain() -> {label}, actuator untouched; the refusal names a warrant field, \
             not the attack"
        ),
    }
}

// ─── AIRI helpers ───

fn framework(name: &str) -> FrameworkIdentity {
    FrameworkIdentity {
        name: name.into(),
        version: "1.0.0".into(),
        adapter_version: "1".into(),
    }
}

/// An unsigned event skeleton. `sign_airi_event` fills the identity in.
fn airi_event(x: &Expected, sequence: u64, payload: AiriPayload) -> AiriEvent {
    AiriEvent {
        version: AIRI_EVENT_VERSION,
        agent_id: x.agent_id.clone(),
        execution_id: [0x11; 16],
        parent_execution_id: None,
        decision_id: Some(x.ee.decision_id),
        sequence,
        prev_event_hash: [0u8; 32],
        emitted_at_ms: x.now,
        framework: framework("langgraph"),
        runtime_binding: None,
        payload,
        signature: aip_types::Signature {
            algorithm: aip_types::AlgorithmId::Ed25519,
            signer_id: x.agent_id.clone(),
            timestamp: 0,
            nonce: [0; 16],
            payload_hash: [0; 32],
            signature_bytes: Vec::new(),
        },
    }
}

fn signed_airi(x: &Expected, sequence: u64, payload: AiriPayload) -> AiriEvent {
    sign_airi_event(
        &x.agent_kp.private_key,
        &x.agent_id,
        airi_event(x, sequence, payload),
    )
    .unwrap()
}

// ─── NEXORA helpers ───

use aip_nexora::{
    verify_nexora_proof, DeclaredParameters, InvalidReason, NexoraProof, ProofVerdict,
    VerifiedProof, VerifierAnchors, VerifierCapability,
};

/// The anchors an independent verifier would provision. `present_time_ms` is
/// the verifier's own view of now: `None` means staleness was not assessed,
/// which is not the same as assessed and found live.
fn anchors_at(x: &Expected, o: &Observer, present_time_ms: Option<u64>) -> VerifierAnchors {
    VerifierAnchors {
        decision_point: x.anchors.clone(),
        observer: o.anchors.clone(),
        warrant: aip_warrant::WarrantTrustAnchors::new(),
        nexora: aip_nexora::NexoraTrustAnchors::new(),
        issuers: x.issuer_keys.clone(),
        agent_public_key: Some(x.agent_kp.public_key.clone()),
        capability: VerifierCapability::strict(),
        present_time_ms,
    }
}

fn anchors_for(x: &Expected, o: &Observer) -> VerifierAnchors {
    anchors_at(x, o, None)
}

fn proof_of(
    x: &Expected,
    ev: &aip_reconcile::ObserverEvidence,
    claim: Reconciliation,
    at: u64,
) -> NexoraProof {
    NexoraProof::builder(x.agent_id.clone(), claim)
        .issued_at(at + 1)
        .authority(x.root.clone(), x.chain.clone())
        .expectation(x.ee.clone())
        .observer(ev.batches.clone(), ev.health.clone())
        .parameters(DeclaredParameters {
            verification_time_ms: at,
            health_max_age_ms: HEALTH_MAX_AGE,
            window_tolerance_ms: 0,
            agent_key_supplied: true,
        })
        .build()
}

/// The verifier's answer, in stable terms: no ids, no digests, no clock.
fn verdict_label(v: &VerifiedProof) -> String {
    match &v.verdict {
        ProofVerdict::Valid => "Valid".to_string(),
        ProofVerdict::Invalid(r) => format!(
            "Invalid({})",
            match r {
                InvalidReason::UnsupportedVersion(_) => "UnsupportedVersion",
                InvalidReason::Structural(_) => "Structural",
                InvalidReason::Binding(_) => "Binding",
                InvalidReason::Component { .. } => "Component",
                InvalidReason::NotDerivable(_) => "NotDerivable",
                InvalidReason::ClaimNotDerivable { .. } => "ClaimNotDerivable",
                InvalidReason::DeclaredParameterRefused { .. } => "DeclaredParameterRefused",
            }
        ),
    }
}

// ═══ X01 Compromised agent ═══════════════════════════════════════════════
//
// The attacker owns the agent process and everything it says about itself.
// Staged three ways, because the agent has three distinct moves: claim an
// execution it did not perform, sign as somebody else, and author its own
// accountability record.

fn x01_compromised_agent(log: &mut ExecutionLog, gates: &mut Vec<GateSample>) {
    let t = Threat::CompromisedAgent;
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);

    // ── AIP. Sign as the victim without the victim's key.
    let attacker = generate_ed25519_keypair();
    let forged_id = derive_aip_id(&attacker.public_key, &provenance("empirical-agent"));
    let token = issue_scoped_token(
        &x.agent_id,
        &attacker.private_key,
        &x.agent_id,
        scope_submitter(),
        Some(TTL),
    )
    .unwrap();
    let accepted = verify_scoped_token(&token, &x.agent_kp.public_key).unwrap();
    assert_ne!(forged_id, x.agent_id);
    assert!(!accepted);
    log.record(
        t,
        Layer::Aip,
        Outcome::Unrepresentable {
            evidence: "an AIP-ID derived from the attacker's key is not the victim's, and a token \
                       the attacker issues in the victim's name does not verify under the \
                       victim's key: the victim's identity has no representation without the key"
                .into(),
        },
    );

    // ── AIRI. A completion the agent never performed, signed by the agent.
    let lie = signed_airi(
        &x,
        0,
        AiriPayload::ExecutionCompleted(Completion {
            outcome: ReportedOutcome::Success,
            detail: Some("transfer settled".into()),
        }),
    );
    verify_airi_event(&lie, &x.agent_kp.public_key).expect("a fabricated event still verifies");
    log.record(
        t,
        Layer::Airi,
        Outcome::Unnoticed {
            evidence: "a fabricated ExecutionCompleted(Success) signs and verifies; AIRI \
                       establishes authorship and integrity, never occurrence"
                .into(),
        },
    );

    // ── Observation. The agent writes the collector's record under its own key.
    let mut impostor = Observer::with_id(OBSERVER_ID, true, true);
    let forged_batch = impostor.batch(2, x.now - 1_000, at, vec![]);
    let refused = verify_attested_batch(&forged_batch, &o.anchors).unwrap_err();
    log.record(
        t,
        Layer::Observation,
        Outcome::Rejected {
            evidence: format!(
                "a batch signed under the collector's id by a key the verifier does not anchor \
                 is refused: {refused:?}"
            ),
        },
    );

    // ── Reconciliation. The claim, with kernel coverage and no observation
    //    of the claimed instance.
    let decoy = o.present(other_process(), None, x.now + 10);
    let ev = {
        let b = covered_chain(&x, &mut o, vec![decoy]);
        o.evidence(b, at)
    };
    let rec = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(rec.result, ReconciliationResult::PhantomClaim);
    log.record(
        t,
        Layer::Reconciliation,
        Outcome::Rejected {
            evidence: format!(
                "reconcile_expectation -> {} @ {:?} ({:?}); the claim is named as a phantom",
                rec.result.as_str(),
                rec.strength,
                rec.reason
            ),
        },
    );

    // ── Warrant. Two moves: the verdict above, and a verdict the agent wrote.
    let w = gate(&rec, &x.agent_id, at).expect("an engine verdict yields a warrant");
    gates.push(sample(t, &w));
    let authored: Reconciliation =
        serde_json::from_str(&serde_json::to_string(&rec).unwrap()).unwrap();
    assert!(!authored.is_engine_produced());
    let refusal = gate(&authored, &x.agent_id, at).unwrap_err();
    assert!(matches!(refusal, Refusal::ReconciliationNotEngineProduced));
    log.record(
        t,
        Layer::Warrant,
        Outcome::Rejected {
            evidence: "a record the agent authored — read back from its own bytes and therefore \
                       Provenance::Deserialized — is refused outright with \
                       ReconciliationNotEngineProduced, before any response class is computed"
                .into(),
        },
    );

    // ── Containment.
    let (label, actuated) = drive_containment(&w, &x, at);
    log.record(
        t,
        Layer::Containment,
        containment_unnoticed(&label, actuated),
    );

    // ── NEXORA. A package whose claim the agent upgraded to VerifiedExecution.
    let mut upgraded = authored.clone();
    upgraded.result = ReconciliationResult::VerifiedExecution;
    upgraded.strength = EvidenceStrength::Proven;
    let p = proof_of(&x, &ev, upgraded, at);
    let v = verify_nexora_proof(&p, &anchors_for(&x, &o));
    assert!(!v.is_valid());
    log.record(
        t,
        Layer::Nexora,
        Outcome::Rejected {
            evidence: format!(
                "a package claiming VERIFIED_EXECUTION over inputs that support {} is \
                 {}; the verifier re-derives from the package's own bytes",
                rec.result.as_str(),
                verdict_label(&v)
            ),
        },
    );
}

// ═══ X02 Compromised framework ═══════════════════════════════════════════
//
// The attacker owns the orchestration framework and the events it emits. Its
// move is to make the framework's account carry weight it was never granted.

fn x02_compromised_framework(log: &mut ExecutionLog, gates: &mut Vec<GateSample>) {
    let t = Threat::CompromisedFramework;
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);

    // ── AIP. A framework name is not an identity, and AIP has no input for one.
    let under_a = signed_airi(&x, 0, AiriPayload::AgentExecutionStarted(start()));
    let mut under_b = airi_event(&x, 0, AiriPayload::AgentExecutionStarted(start()));
    under_b.framework = framework("a-framework-nobody-anchors");
    let under_b = sign_airi_event(&x.agent_kp.private_key, &x.agent_id, under_b).unwrap();
    let id_now = derive_aip_id(&x.agent_kp.public_key, &provenance("empirical-agent"));
    verify_airi_event(&under_a, &x.agent_kp.public_key).unwrap();
    verify_airi_event(&under_b, &x.agent_kp.public_key).unwrap();
    assert_eq!(id_now, x.agent_id);
    log.record(
        t,
        Layer::Aip,
        Outcome::Unnoticed {
            evidence: "AIP-ID derivation reads a key and a provenance triple; the same agent \
                       derives the same identity under either framework name, and AIP has no \
                       framework input to be lied to"
                .into(),
        },
    );

    // ── AIRI. The framework's account is data, and grants nothing.
    use aip_enterprise::EnterpriseAdapter;
    for name in [
        "langgraph",
        "autogen",
        "crewai",
        "a-framework-nobody-anchors",
    ] {
        let a = aip_enterprise::GraphFrameworkAdapter {
            framework_version: name.into(),
            adapter_version: "1".into(),
        };
        assert!(!a.framework_grants_authority());
    }
    log.record(
        t,
        Layer::Airi,
        Outcome::Declined {
            evidence: "the event verifies as authorship only; framework_grants_authority() is \
                       false for every adapter and every name, so the framework's account \
                       changes no standing and AIRI settles nothing about it"
                .into(),
        },
    );

    // ── Observation. The framework cannot write the observed record.
    let mut impostor = Observer::with_id(OBSERVER_ID, true, true);
    let forged = impostor.batch(2, x.now - 1_000, at, vec![]);
    let refused = verify_attested_batch(&forged, &o.anchors).unwrap_err();
    log.record(
        t,
        Layer::Observation,
        Outcome::Rejected {
            evidence: format!(
                "the collector's record is signed off-host; a batch the framework attests under \
                 the collector's id is refused ({refused:?}), and ProcfsProbe carries no field \
                 through which a framework's account could enter"
            ),
        },
    );

    // ── Reconciliation. A framework event is a claim and corroborates nothing.
    let decoy = o.present(other_process(), None, x.now + 10);
    let ev = {
        let b = covered_chain(&x, &mut o, vec![decoy]);
        o.evidence(b, at)
    };
    let rec = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(rec.result, ReconciliationResult::PhantomClaim);
    log.record(
        t,
        Layer::Reconciliation,
        Outcome::Rejected {
            evidence: format!(
                "reconcile_expectation -> {} @ {:?} ({:?}); the framework's account does not \
                 corroborate itself — corroboration needs an independent observation of the \
                 same instance",
                rec.result.as_str(),
                rec.strength,
                rec.reason
            ),
        },
    );

    // ── Warrant and containment.
    let w = gate(&rec, &x.agent_id, at).expect("an engine verdict yields a warrant");
    gates.push(sample(t, &w));
    log.record(t, Layer::Warrant, warrant_unnoticed(&w));
    let (label, actuated) = drive_containment(&w, &x, at);
    log.record(
        t,
        Layer::Containment,
        containment_unnoticed(&label, actuated),
    );

    // ── NEXORA. A relabelled framework event does not survive the re-walk.
    let mut relabelled = under_a.clone();
    relabelled.framework = framework("crewai");
    let err = verify_airi_event(&relabelled, &x.agent_kp.public_key).unwrap_err();
    log.record(
        t,
        Layer::Nexora,
        Outcome::Rejected {
            evidence: format!(
                "the framework identity is inside the signed preimage; relabelling it after \
                 signing fails the re-walk with {err:?}"
            ),
        },
    );
}

fn start() -> aip_airi::AgentStart {
    aip_airi::AgentStart {
        agent_role: Some("payments".into()),
        framework_run_id: Some("run-1".into()),
    }
}

// ═══ X03 Compromised model runtime ═══════════════════════════════════════
//
// The attacker owns the inference runtime and the model identity it reports.

fn x03_compromised_model_runtime(log: &mut ExecutionLog, gates: &mut Vec<GateSample>) {
    let t = Threat::CompromisedModelRuntime;
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);

    log.record(
        t,
        Layer::Aip,
        Outcome::Unnoticed {
            evidence: "AIP has no inference input; identity derivation and token verification \
                       are unchanged by anything a model runtime reports"
                .into(),
        },
    );

    // ── AIRI. Hosted inference reports an identifier nobody can verify.
    let hosted = signed_airi(
        &x,
        0,
        AiriPayload::ModelInvocationRequested(ModelProvenance {
            model_id: "a-model-that-never-ran".into(),
            model_digest: None,
            runtime: "hosted-api".into(),
            runtime_version: None,
            inference_request_id: None,
            prompt_commitment: None,
            output_commitment: None,
            accelerator: Some("cuda:0 NVIDIA H100".into()),
        }),
    );
    verify_airi_event(&hosted, &x.agent_kp.public_key).unwrap();
    log.record(
        t,
        Layer::Airi,
        Outcome::Declined {
            evidence: "a ModelProvenance naming a model that never ran, with no weight digest \
                       and a self-reported accelerator, verifies as authorship; the identity is \
                       recorded as declared and AIRI settles nothing about what executed"
                .into(),
        },
    );

    // ── Observation. No mechanism observes inference.
    let classes: Vec<ObservationClass> =
        SourceMechanism::ALL.iter().map(|m| class_of(*m)).collect();
    assert!(!classes.is_empty());
    log.record(
        t,
        Layer::Observation,
        Outcome::Unnoticed {
            evidence: format!(
                "every one of the {} implemented source mechanisms maps to a process, socket, \
                 wire, transfer, filesystem, platform or observer-integrity class; none \
                 observes accelerator or kernel execution, so no model event enters the record",
                SourceMechanism::ALL.len()
            ),
        },
    );

    // ── Reconciliation. The question is refused, not answered.
    let rec = reconcile_expectation(&x.ee, None, &ctx(&x, &o, at));
    assert_eq!(rec.result, ReconciliationResult::CannotProve);
    log.record(
        t,
        Layer::Reconciliation,
        Outcome::Declined {
            evidence: format!(
                "with no observation of the model invocation there is nothing to reconcile it \
                 against: reconcile_expectation -> {} @ {:?} ({:?})",
                rec.result.as_str(),
                rec.strength,
                rec.reason
            ),
        },
    );

    let w = gate(&rec, &x.agent_id, at).expect("an engine verdict yields a warrant");
    gates.push(sample(t, &w));
    log.record(t, Layer::Warrant, warrant_unnoticed(&w));
    let (label, actuated) = drive_containment(&w, &x, at);
    log.record(
        t,
        Layer::Containment,
        containment_unnoticed(&label, actuated),
    );

    // ── NEXORA. A model event transplanted to another execution fails.
    let mut transplanted = hosted.clone();
    transplanted.execution_id = [0x99; 16];
    let err = verify_airi_event(&transplanted, &x.agent_kp.public_key).unwrap_err();
    let _ = &mut o;
    log.record(
        t,
        Layer::Nexora,
        Outcome::Rejected {
            evidence: format!(
                "model provenance is bound to the execution it was signed under; moving the \
                 event to another execution id fails verification with {err:?}"
            ),
        },
    );
}

// ═══ X04 Compromised tool ════════════════════════════════════════════════
//
// The attacker owns the tool and the response it returns. Its move is to make
// a 200 stand in for an effect.

fn x04_compromised_tool(log: &mut ExecutionLog, gates: &mut Vec<GateSample>) {
    let t = Threat::CompromisedTool;
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);
    let commitment = aip_airi::parameter_commitment(b"path=/var/lib/ledger/entry");

    log.record(
        t,
        Layer::Aip,
        Outcome::Unnoticed {
            evidence: "AIP models no tool endpoint; nothing a tool returns reaches identity or \
                       authority"
                .into(),
        },
    );

    // ── AIRI. The success is a third record about a boundary it cannot see.
    let requested = signed_airi(
        &x,
        0,
        AiriPayload::ToolInvocationRequested(ToolInvocation {
            tool_id: "http:POST:payments.internal".into(),
            action_kind: "write".into(),
            parameter_commitment: commitment,
            tool_call_id: None,
            target: Some("payments.internal".into()),
        }),
    );
    let reported = signed_airi(
        &x,
        1,
        AiriPayload::ToolExecutionReported(ToolReport {
            tool_id: "http:POST:payments.internal".into(),
            parameter_commitment: commitment,
            outcome: ReportedOutcome::Success,
            result_commitment: None,
            transport_status: Some(200),
        }),
    );
    verify_airi_event(&requested, &x.agent_kp.public_key).unwrap();
    verify_airi_event(&reported, &x.agent_kp.public_key).unwrap();
    log.record(
        t,
        Layer::Airi,
        Outcome::Declined {
            evidence: "a ToolReport claiming Success with transport 200 verifies as authorship; \
                       requested invocation, runtime execution and external effect are three \
                       separate records and the report is only the second"
                .into(),
        },
    );

    // ── Observation. The local half is observable; the record shows what the
    //    host did, not what the tool said.
    assert!(ObservationClass::FilesystemEffect.is_implemented());
    assert!(ObservationClass::NetworkSocket.is_implemented());
    let claim = claim_for(&x);
    let seen = o.present(process_of(&x.ee), Some(&claim), x.now + 10);
    let ev = {
        let b = covered_chain(&x, &mut o, vec![seen]);
        o.evidence(b, at)
    };
    log.record(
        t,
        Layer::Observation,
        Outcome::Rejected {
            evidence: "FilesystemEffect and NetworkSocket are implemented classes, so the local \
                       half of a tool call is observable; the attested record carries only what \
                       the probe measured and no FilesystemEffect for the claimed write"
                .into(),
        },
    );

    // ── Reconciliation. The remote half stops at CANNOT_PROVE.
    let rec = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(rec.result, ReconciliationResult::CannotProve);
    log.record(
        t,
        Layer::Reconciliation,
        Outcome::Declined {
            evidence: format!(
                "the instance is corroborated and the action is not: reconcile_expectation -> \
                 {} @ {:?} ({:?}), identity {:?}, action {:?} — a matched instance never \
                 becomes a landed effect",
                rec.result.as_str(),
                rec.strength,
                rec.reason,
                rec.identity,
                rec.action
            ),
        },
    );

    let w = gate(&rec, &x.agent_id, at).expect("an engine verdict yields a warrant");
    gates.push(sample(t, &w));
    log.record(t, Layer::Warrant, warrant_unnoticed(&w));
    let (label, actuated) = drive_containment(&w, &x, at);
    log.record(
        t,
        Layer::Containment,
        containment_unnoticed(&label, actuated),
    );

    // ── NEXORA. A tool event moved to another agent fails.
    let other = expected();
    let err = verify_airi_event(&reported, &other.agent_kp.public_key).unwrap_err();
    log.record(
        t,
        Layer::Nexora,
        Outcome::Rejected {
            evidence: format!(
                "a tool event carries its author inside the signature; verified against another \
                 agent's key it fails with {err:?}"
            ),
        },
    );
}

// ═══ X05 Compromised process ═════════════════════════════════════════════
//
// The attacker swapped the binary under an authorised pid and reports its
// real runtime state truthfully while lying about everything else.

fn x05_compromised_process(log: &mut ExecutionLog, gates: &mut Vec<GateSample>) {
    let t = Threat::CompromisedProcess;
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);

    // ── AIP. The binding is inside the signed expectation.
    let mut altered = x.ee.clone();
    altered.execution_binding.exe_content_sha256 = sha256(b"attacker's binary");
    let honest = aip_authorize::verify_expected_execution(&x.ee, &x.anchors);
    let tampered = aip_authorize::verify_expected_execution(&altered, &x.anchors);
    assert!(honest.is_ok());
    assert!(tampered.is_err());
    log.record(
        t,
        Layer::Aip,
        Outcome::Unrepresentable {
            evidence: format!(
                "execution identity is the process instance plus the executable's content, both \
                 inside the decision point's signature; swapping the content makes the \
                 expectation fail verification ({:?}) rather than authorising the new binary",
                tampered.unwrap_err()
            ),
        },
    );

    // ── AIRI. The process reports its real pid and lies about the rest.
    let honest_binding = signed_airi(
        &x,
        0,
        AiriPayload::ExecutionCompleted(Completion {
            outcome: ReportedOutcome::Success,
            detail: None,
        }),
    );
    verify_airi_event(&honest_binding, &x.agent_kp.public_key).unwrap();
    log.record(
        t,
        Layer::Airi,
        Outcome::Unnoticed {
            evidence: "runtime_binding is self-reported: a compromised process reports its real \
                       pid, and the event verifies whatever else it says"
                .into(),
        },
    );

    // ── Observation. The collector measures the content itself.
    let claim = claim_for(&x);
    let swapped = o.present(swapped_binary(&x.ee), Some(&claim), x.now + 10);
    let ev = {
        let b = covered_chain(&x, &mut o, vec![swapped]);
        o.evidence(b, at)
    };
    let measured = ev.batches[1].batch.observations[0]
        .observed
        .exe_content_sha256;
    assert_ne!(measured, x.ee.execution_binding.exe_content_sha256);
    log.record(
        t,
        Layer::Observation,
        Outcome::Rejected {
            evidence: "the collector measures pid, start ticks, boot id and executable content \
                       itself rather than accepting them; the measured content differs from the \
                       authorised content and the difference is inside the signed batch"
                .into(),
        },
    );

    // ── Reconciliation.
    let rec = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(rec.result, ReconciliationResult::IdentityDivergence);
    log.record(
        t,
        Layer::Reconciliation,
        Outcome::Rejected {
            evidence: format!(
                "reconcile_expectation -> {} @ {:?} ({:?}), identity {:?}",
                rec.result.as_str(),
                rec.strength,
                rec.reason,
                rec.identity
            ),
        },
    );

    let w = gate(&rec, &x.agent_id, at).expect("an engine verdict yields a warrant");
    gates.push(sample(t, &w));
    log.record(t, Layer::Warrant, warrant_unnoticed(&w));
    let (label, actuated) = drive_containment(&w, &x, at);
    log.record(
        t,
        Layer::Containment,
        containment_unnoticed(&label, actuated),
    );

    // ── NEXORA. The binding travels inside the signed expectation.
    let p = proof_of(&x, &ev, rec.clone(), at);
    let v = verify_nexora_proof(&p, &anchors_for(&x, &o));
    let mut broken = p.clone();
    if let Some(ee) = broken.expectation.as_mut() {
        ee.execution_binding.exe_content_sha256 = sha256(b"attacker's binary");
    }
    let vb = verify_nexora_proof(&broken, &anchors_for(&x, &o));
    assert!(!vb.is_valid());
    log.record(
        t,
        Layer::Nexora,
        Outcome::Rejected {
            evidence: format!(
                "the honest package is {} over the divergence; the same package with the \
                 binding edited is {} — the components must be bound to one another",
                verdict_label(&v),
                verdict_label(&vb)
            ),
        },
    );
}

// ═══ X06 Compromised host ════════════════════════════════════════════════
//
// The attacker is root on the observed host: procfs content is theirs, and so
// is any key stored there. Its most dangerous move is not to hide — it is to
// drive the system into containing somebody.

fn x06_compromised_host(log: &mut ExecutionLog, gates: &mut Vec<GateSample>) {
    let t = Threat::CompromisedHost;
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);

    // ── AIP. A signature says who signed, never who was in control.
    let token = issue_scoped_token(
        &x.agent_id,
        &x.agent_kp.private_key,
        &x.agent_id,
        scope_submitter(),
        Some(TTL),
    )
    .unwrap();
    assert!(verify_scoped_token(&token, &x.agent_kp.public_key).unwrap());
    log.record(
        t,
        Layer::Aip,
        Outcome::Declined {
            evidence: "a token signed with the host-held key verifies exactly as an honest one \
                       does; AIP establishes what was signed and declines the question of who \
                       held the key"
                .into(),
        },
    );

    log.record(
        t,
        Layer::Airi,
        Outcome::Unnoticed {
            evidence: "every self-report on a rooted host is the attacker's, and each one \
                       verifies as authorship"
                .into(),
        },
    );

    // ── Observation. Host-derived content is capped at Attested.
    let host_derived = [
        ObservationClass::ProcessLifecycle,
        ObservationClass::ProcessIdentity,
        ObservationClass::NetworkSocket,
        ObservationClass::DataTransfer,
        ObservationClass::FilesystemEffect,
        ObservationClass::PlatformBinding,
    ];
    for c in host_derived {
        assert_ne!(
            c.ceiling(),
            aip_observation::EvidenceCeiling::Proven,
            "{c:?} must not be Proven"
        );
    }
    assert_eq!(
        ObservationClass::ObserverIntegrity.ceiling(),
        aip_observation::EvidenceCeiling::Proven
    );
    log.record(
        t,
        Layer::Observation,
        Outcome::Declined {
            evidence: "every class whose content is read from the observed host declares a \
                       ceiling below Proven; the only class that reaches Proven is \
                       ObserverIntegrity, which is arithmetic over the collector's own record \
                       and not host content"
                .into(),
        },
    );

    // ── Reconciliation. No host-content verdict reaches Proven.
    let claim = claim_for(&x);
    let forged = o.present(swapped_binary(&x.ee), Some(&claim), x.now + 10);
    let ev = {
        let b = covered_chain(&x, &mut o, vec![forged]);
        o.evidence(b, at)
    };
    let rec = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_eq!(rec.strength, EvidenceStrength::Attested);
    log.record(
        t,
        Layer::Reconciliation,
        Outcome::Declined {
            evidence: format!(
                "content the attacker controls produces {} at {:?}, never Proven; the limit is \
                 declared per ObservationClass rather than computed from the evidence",
                rec.result.as_str(),
                rec.strength
            ),
        },
    );

    // ── Warrant. The strength gate denies the attacker containment.
    let w = gate(&rec, &x.agent_id, at).expect("an engine verdict yields a warrant");
    gates.push(sample(t, &w));
    assert_ne!(w.response, ResponseClass::Contain);
    log.record(
        t,
        Layer::Warrant,
        Outcome::Rejected {
            evidence: format!(
                "under the most permissive policy an operator can set, an {:?} workload verdict \
                 is capped at {:?} by the evidence-strength gate; the attacker does not get \
                 containment out of content they control",
                w.evidence_strength, w.response
            ),
        },
    );

    // ── Containment. Actuation is unreachable from anything the engine draws.
    let mut reached = 0usize;
    let mut swept = 0usize;
    for result in [
        ReconciliationResult::VerifiedExecution,
        ReconciliationResult::UnattributedEffect,
        ReconciliationResult::PhantomClaim,
        ReconciliationResult::IdentityDivergence,
        ReconciliationResult::LineageViolation,
        ReconciliationResult::SensorIntegrityFailure,
        ReconciliationResult::ContinuityFailure,
        ReconciliationResult::CannotProve,
    ] {
        for strength in [
            EvidenceStrength::Heuristic,
            EvidenceStrength::Correlated,
            EvidenceStrength::Attested,
            EvidenceStrength::Proven,
        ] {
            if !engine_can_draw(result, strength) {
                continue;
            }
            swept += 1;
            let mut r = rec.clone();
            r.result = result;
            r.strength = strength;
            let w = gate(&r, &x.agent_id, at).expect("a warrant");
            let (_, actuated) = drive_containment(&w, &x, at);
            if actuated {
                reached += 1;
            }
        }
    }
    assert_eq!(reached, 0);
    log.record(
        t,
        Layer::Containment,
        Outcome::Unrepresentable {
            evidence: format!(
                "swept all {swept} (result, strength) pairs the engine can draw, each under the \
                 most permissive policy: the actuator was reached {reached} times. contain()'s \
                 strength gate and its workload-violation gate are jointly unsatisfiable from \
                 engine output, so a warrant that actuates has no representation reachable from \
                 a rooted host — the same unreachability recorded as blocker B-3, which this \
                 does not close"
            ),
        },
    );

    // ── NEXORA. The anchors are the verifier's.
    let stranger = Observer::with_id("collector-nobody-anchors", true, true);
    let p = proof_of(&x, &ev, rec.clone(), at);
    let v = verify_nexora_proof(&p, &anchors_at(&x, &stranger, None));
    assert!(!v.is_valid());
    log.record(
        t,
        Layer::Nexora,
        Outcome::Rejected {
            evidence: format!(
                "the same package that verifies under the collector's real anchor is {} when \
                 the verifier anchors a different collector; the package does not supply the \
                 keys it is judged by",
                verdict_label(&v)
            ),
        },
    );
}

/// The (result, strength) pairs `Draft::finish` can leave the engine with.
/// Recorded here so the X06 sweep covers engine output and nothing else — a
/// sweep that included pairs the engine cannot draw would be answering a
/// question about fixtures.
fn engine_can_draw(result: ReconciliationResult, strength: EvidenceStrength) -> bool {
    use EvidenceStrength as S;
    use ReconciliationResult as R;
    matches!(
        (result, strength),
        (R::CannotProve, S::Heuristic)
            | (R::SensorIntegrityFailure, S::Attested | S::Proven)
            | (
                R::VerifiedExecution
                    | R::UnattributedEffect
                    | R::PhantomClaim
                    | R::IdentityDivergence
                    | R::LineageViolation
                    | R::ContinuityFailure,
                S::Attested,
            )
    )
}

// ═══ X07 Forged telemetry ════════════════════════════════════════════════
//
// The attacker edits the content of a self-authored stream, and — where a
// real attacker would hold the collector's key — re-signs it.

fn x07_forged_telemetry(log: &mut ExecutionLog, gates: &mut Vec<GateSample>) {
    let t = Threat::ForgedTelemetry;
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);

    log.record(
        t,
        Layer::Aip,
        Outcome::Unrepresentable {
            evidence: "AIP-ID derivation reads a key and a provenance triple and nothing else, \
                       and no AIP verification consumes telemetry; a forged stream has no \
                       representation that reaches this layer"
                .into(),
        },
    );

    log.record(
        t,
        Layer::Airi,
        Outcome::Unnoticed {
            evidence: "forging a self-report produces a well-formed self-report, which is what \
                       AIRI is; the event verifies"
                .into(),
        },
    );

    // ── Observation. Edited bytes break the attestation.
    let ev = {
        let b = covered_chain(&x, &mut o, vec![]);
        o.evidence(b, at)
    };
    let mut edited = ev.clone();
    edited.batches[1].batch.claimed_to_ms += 1;
    let broke = verify_attested_batch(&edited.batches[1], &o.anchors).unwrap_err();
    verify_attested_batch(&ev.batches[1], &o.anchors).unwrap();
    log.record(
        t,
        Layer::Observation,
        Outcome::Rejected {
            evidence: format!(
                "the unedited batch verifies against the collector's anchor and the same batch \
                 with one field altered after signing does not: {broke:?}"
            ),
        },
    );

    // ── Reconciliation. The break is arithmetic, and it is Proven.
    let rec = reconcile_expectation(&x.ee, Some(&edited), &ctx(&x, &o, at));
    assert_eq!(rec.result, ReconciliationResult::SensorIntegrityFailure);
    assert_eq!(rec.strength, EvidenceStrength::Proven);
    log.record(
        t,
        Layer::Reconciliation,
        Outcome::Rejected {
            evidence: format!(
                "reconcile_expectation -> {} @ {:?} ({:?}); the one verdict the engine reaches \
                 at Proven, because it is a recomputation over bytes the verifier already holds",
                rec.result.as_str(),
                rec.strength,
                rec.reason
            ),
        },
    );

    let w = gate(&rec, &x.agent_id, at).expect("an engine verdict yields a warrant");
    gates.push(sample(t, &w));
    log.record(t, Layer::Warrant, warrant_unnoticed(&w));
    let (label, actuated) = drive_containment(&w, &x, at);
    log.record(
        t,
        Layer::Containment,
        containment_unnoticed(&label, actuated),
    );

    // ── NEXORA. Every carried component is verified before it is credited.
    let p = proof_of(&x, &edited, rec.clone(), at);
    let v = verify_nexora_proof(&p, &anchors_for(&x, &o));
    assert!(!v.is_valid());
    log.record(
        t,
        Layer::Nexora,
        Outcome::Rejected {
            evidence: format!(
                "a package carrying the edited observer bundle is {}; the verifier checks each \
                 component under its own anchors before any of it is credited",
                verdict_label(&v)
            ),
        },
    );
}

// ═══ X08 Lost connectivity ═══════════════════════════════════════════════
//
// The attacker controls the link between subject and verifier. Its move is to
// have absence read as non-occurrence.

fn x08_lost_connectivity(log: &mut ExecutionLog, gates: &mut Vec<GateSample>) {
    let t = Threat::LostConnectivity;
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);

    // ── AIP. Identity and authority are offline artifacts.
    let token = issue_scoped_token(
        &x.agent_id,
        &x.agent_kp.private_key,
        &x.agent_id,
        scope_submitter(),
        Some(TTL),
    )
    .unwrap();
    assert!(verify_scoped_token(&token, &x.agent_kp.public_key).unwrap());
    log.record(
        t,
        Layer::Aip,
        Outcome::Unnoticed {
            evidence: "token verification reads a token and a public key; it succeeds with no \
                       network, and severing the link changes neither identity nor authority"
                .into(),
        },
    );

    let queued = signed_airi(
        &x,
        0,
        AiriPayload::ExecutionCompleted(Completion {
            outcome: ReportedOutcome::Success,
            detail: None,
        }),
    );
    verify_airi_event(&queued, &x.agent_kp.public_key).unwrap();
    log.record(
        t,
        Layer::Airi,
        Outcome::Unnoticed {
            evidence: "an event queued through an outage verifies unchanged when it arrives; \
                       its standing was never a function of the link"
                .into(),
        },
    );

    // ── Observation. The chain is continuous across the outage, and a gap in
    //    it is visible whether or not the link was up.
    let mut ledger = ObserverLedger::new();
    let b1 = o.batch(1, x.now - 3_000, x.now - 2_000, vec![]);
    let b2 = o.batch(2, x.now - 2_000, x.now - 1_000, vec![]);
    let b3 = o.batch(3, x.now - 1_000, at, vec![]);
    ledger.admit(b1.sequence, b1.prev_head, b1.head()).unwrap();
    ledger.admit(b2.sequence, b2.prev_head, b2.head()).unwrap();
    // The link drops; b3 arrives late but in sequence, and links cleanly.
    let recovered = ledger.admit(b3.sequence, b3.prev_head, b3.head());
    assert!(recovered.is_ok());
    log.record(
        t,
        Layer::Observation,
        Outcome::Rejected {
            evidence: "the collector's sequence and head chain are continuous across the \
                       outage: a batch delayed by the link still links to the recorded head, so \
                       an outage cannot be dressed as a gap and a gap cannot hide behind an \
                       outage"
                .into(),
        },
    );

    // ── Reconciliation. Evidence that has not arrived is never non-occurrence.
    let partial = o.evidence(vec![b1.clone(), b2.clone()], at);
    let rec = reconcile_expectation(&x.ee, Some(&partial), &ctx(&x, &o, at));
    assert_ne!(rec.result, ReconciliationResult::PhantomClaim);
    log.record(
        t,
        Layer::Reconciliation,
        Outcome::Declined {
            evidence: format!(
                "with the window's tail still in flight the engine answers {} ({:?}), \
                 availability {:?} — never PHANTOM_CLAIM, which would be an absence claim drawn \
                 from a link failure",
                rec.result.as_str(),
                rec.reason,
                rec.availability
            ),
        },
    );

    let w = gate(&rec, &x.agent_id, at).expect("an engine verdict yields a warrant");
    gates.push(sample(t, &w));
    log.record(t, Layer::Warrant, warrant_unnoticed(&w));
    let (label, actuated) = drive_containment(&w, &x, at);
    log.record(
        t,
        Layer::Containment,
        containment_unnoticed(&label, actuated),
    );

    // ── NEXORA. Verification is offline and deterministic.
    let full = o.evidence(vec![b1, b2, b3], at);
    let rec2 = reconcile_expectation(&x.ee, Some(&full), &ctx(&x, &o, at));
    let p = proof_of(&x, &full, rec2, at);
    let a = verify_nexora_proof(&p, &anchors_for(&x, &o));
    let b = verify_nexora_proof(&p, &anchors_for(&x, &o));
    assert_eq!(verdict_label(&a), verdict_label(&b));
    log.record(
        t,
        Layer::Nexora,
        Outcome::Rejected {
            evidence: format!(
                "verify_nexora_proof reads a package and a set of anchors and nothing else: two \
                 runs with no network give {} both times, so cutting the link denies the \
                 attacker nothing to exploit and the verifier nothing it needed",
                verdict_label(&a)
            ),
        },
    );
}

// ═══ X09 Partial observation ═════════════════════════════════════════════
//
// The attacker chooses which events reach the collector, by dropping some.

fn x09_partial_observation(log: &mut ExecutionLog, gates: &mut Vec<GateSample>) {
    let t = Threat::PartialObservation;
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);

    log.record(
        t,
        Layer::Aip,
        Outcome::Unnoticed {
            evidence: "AIP observes nothing, so dropping observations changes nothing it holds"
                .into(),
        },
    );

    // ── AIRI. Reporting only some of what happened leaves an intact chain.
    let e0 = signed_airi(&x, 0, AiriPayload::AgentExecutionStarted(start()));
    let mut e1 = airi_event(
        &x,
        1,
        AiriPayload::ExecutionCompleted(Completion {
            outcome: ReportedOutcome::Success,
            detail: None,
        }),
    );
    e1.prev_event_hash = sha256(&e0.signing_preimage());
    let e1 = sign_airi_event(&x.agent_kp.private_key, &x.agent_id, e1).unwrap();
    let report = aip_airi::verify_event_chain(&[e0, e1], &x.agent_kp.public_key);
    assert!(matches!(report, aip_airi::ChainReport::Intact(_)));
    log.record(
        t,
        Layer::Airi,
        Outcome::Unnoticed {
            evidence: "an agent that never emits an event for part of what it did leaves a \
                       chain with no gap in it; verify_event_chain reports Intact, because \
                       silence is not visible from a self-report"
                .into(),
        },
    );

    // ── Observation. A withheld batch is a break in the chain, not a silence.
    let b1 = o.batch(1, x.now - 3_000, x.now - 2_000, vec![]);
    let withheld = o.batch(2, x.now - 2_000, x.now - 1_000, vec![]);
    let b3 = o.batch(3, x.now - 1_000, at, vec![]);
    let mut ledger = ObserverLedger::new();
    ledger.admit(b1.sequence, b1.prev_head, b1.head()).unwrap();
    // The attacker withholds the middle batch and offers the next one in its
    // place. Binding it rather than dropping it is the point: the batch the
    // collector really signed is the thing the chain will now not account for.
    assert_eq!(withheld.sequence, b1.sequence + 1);
    assert_eq!(b3.sequence, withheld.sequence + 1);
    let fault = ledger
        .admit(b3.sequence, b3.prev_head, b3.head())
        .unwrap_err();
    assert!(matches!(
        fault,
        ContinuityFault::Gap { .. } | ContinuityFault::HeadMismatch { .. }
    ));
    log.record(
        t,
        Layer::Observation,
        Outcome::Rejected {
            evidence: format!(
                "withholding a batch and offering the next one is not silence: the ledger names \
                 it, {}",
                match fault {
                    ContinuityFault::Gap { .. } => "Gap",
                    ContinuityFault::HeadMismatch { .. } => "HeadMismatch",
                    _ => "a continuity fault",
                }
            ),
        },
    );

    // ── Reconciliation. An incomplete set names the gap rather than absorbing it.
    let partial = o.evidence(vec![b1, b3], at);
    let rec = reconcile_expectation(&x.ee, Some(&partial), &ctx(&x, &o, at));
    assert_ne!(rec.result, ReconciliationResult::PhantomClaim);
    log.record(
        t,
        Layer::Reconciliation,
        Outcome::Declined {
            evidence: format!(
                "an observation set with a hole in it answers {} ({:?}), availability {:?}; a \
                 non-occurrence claim would additionally require kernel-pushed coverage of the \
                 whole window",
                rec.result.as_str(),
                rec.reason,
                rec.availability
            ),
        },
    );

    let w = gate(&rec, &x.agent_id, at).expect("an engine verdict yields a warrant");
    gates.push(sample(t, &w));
    log.record(t, Layer::Warrant, warrant_unnoticed(&w));
    let (label, actuated) = drive_containment(&w, &x, at);
    log.record(
        t,
        Layer::Containment,
        containment_unnoticed(&label, actuated),
    );

    // ── NEXORA. A claim citing evidence the package does not carry.
    let full = {
        let b = covered_chain(&x, &mut o, vec![]);
        o.evidence(b, at)
    };
    let cited = reconcile_expectation(&x.ee, Some(&full), &ctx(&x, &o, at));
    assert!(!cited.evidence.is_empty());
    let stripped = NexoraProof::builder(x.agent_id.clone(), cited.clone())
        .issued_at(at + 1)
        .authority(x.root.clone(), x.chain.clone())
        .expectation(x.ee.clone())
        .parameters(DeclaredParameters {
            verification_time_ms: at,
            health_max_age_ms: HEALTH_MAX_AGE,
            window_tolerance_ms: 0,
            agent_key_supplied: true,
        })
        .build();
    let v = verify_nexora_proof(&stripped, &anchors_for(&x, &o));
    assert!(!v.is_valid());
    log.record(
        t,
        Layer::Nexora,
        Outcome::Rejected {
            evidence: format!(
                "a claim drawn from observer evidence, packaged without that evidence, is {}; \
                 the package is refused rather than credited with the part it kept",
                verdict_label(&v)
            ),
        },
    );
}

// ═══ X10 Sensor deception ════════════════════════════════════════════════
//
// The attacker controls the physical world the sensor reads, or the device
// layer beneath it.
//
// **This attack could not be staged.** There is no sensor in this workspace
// to deceive, and Skill 25's physical extension is BLOCKED. Every cell here
// is `NotStageable`, and none of them is a pass.
//
// What *is* executable is the structural fact each cell rests on — that the
// physical-effect class has no implemented mechanism, and that no source
// mechanism maps to it. That is asserted in
// [`sensor_deception_rests_on_a_class_with_no_mechanism`], deliberately as a
// separate test, because asserting the reason a cell is true is not the same
// as executing the attack the cell is about.

fn x10_sensor_deception(log: &mut ExecutionLog) {
    let t = Threat::SensorDeception;
    let hardware = "the attack is manipulation of a physical quantity; this workspace contains \
                    no sensor to deceive and no physical actuator to observe, and the physical \
                    validation extension is BLOCKED";
    for (layer, why) in [
        (Layer::Aip, "AIP consumes no sensor reading"),
        (Layer::Airi, "AIRI models no sensor"),
        (
            Layer::Observation,
            "ObservationClass::PhysicalEffect is representable with no implemented mechanism, so \
             there is no reading to falsify",
        ),
        (
            Layer::Reconciliation,
            "no reconciliation input is a physical quantity",
        ),
        (Layer::Warrant, "the gate consumes a verdict"),
        (Layer::Containment, "containment acts on a warrant"),
        (
            Layer::Nexora,
            "NEXORA commits to what it was given, and a deceived reading is faithfully committed",
        ),
    ] {
        log.record(
            t,
            layer,
            Outcome::NotStageable {
                reason: format!("{why}; {hardware}"),
            },
        );
    }
}

// ═══ X11 Observer failure ════════════════════════════════════════════════
//
// The attacker controls the collector's availability and the continuity of
// its own record. Its move is to have the workload blamed for the observer's
// failure.

fn x11_observer_failure(log: &mut ExecutionLog, gates: &mut Vec<GateSample>) {
    let t = Threat::ObserverFailure;
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);

    log.record(
        t,
        Layer::Aip,
        Outcome::Unnoticed {
            evidence: "AIP does not model the observer; nothing it holds changes when a \
                       collector fails"
                .into(),
        },
    );
    log.record(
        t,
        Layer::Airi,
        Outcome::Unnoticed {
            evidence: "AIRI does not model the observer; an agent's own chain is unaffected by \
                       a collector failing"
                .into(),
        },
    );

    // ── Observation. Two distinct heads at one sequence is arithmetic.
    let mut ledger = ObserverLedger::new();
    let b1 = o.batch(1, x.now - 3_000, x.now - 2_000, vec![]);
    ledger.admit(b1.sequence, b1.prev_head, b1.head()).unwrap();
    let mut o2 = Observer::new(true, true);
    let fork = o2.batch(1, x.now - 3_000, x.now - 1_999, vec![]);
    let fault = ledger
        .admit(fork.sequence, fork.prev_head, fork.head())
        .unwrap_err();
    assert!(matches!(fault, ContinuityFault::Fork { .. }));
    assert!(ledger.is_quarantined());
    log.record(
        t,
        Layer::Observation,
        Outcome::Rejected {
            evidence: "two distinct attested batches at one sequence under one key is a Fork, \
                       recomputable by anyone holding the bytes; the ledger quarantines and \
                       later well-formed traffic does not un-prove it"
                .into(),
        },
    );

    // ── Reconciliation. The observer is accused, not the workload.
    let mut lone = Observer::new(true, true);
    let epoch_start = lone.batch(1, x.now - 1_000, at, vec![]);
    let single = lone.evidence(vec![epoch_start], at);
    let rec = reconcile_expectation(&x.ee, Some(&single), &ctx(&x, &lone, at));
    assert_eq!(rec.result, ReconciliationResult::ContinuityFailure);
    log.record(
        t,
        Layer::Reconciliation,
        Outcome::Rejected {
            evidence: format!(
                "an epoch the collector cannot vouch for answers {} @ {:?} ({:?}); the verdict \
                 is about the observer's record and makes no claim about the workload",
                rec.result.as_str(),
                rec.strength,
                rec.reason
            ),
        },
    );

    // ── Warrant. The response targets the observer.
    let w = gate(&rec, &x.agent_id, at).expect("an engine verdict yields a warrant");
    gates.push(sample(t, &w));
    assert_eq!(w.target, ResponseTarget::Observer);
    assert_ne!(w.response, ResponseClass::Contain);
    log.record(
        t,
        Layer::Warrant,
        Outcome::Rejected {
            evidence: format!(
                "under the maximal policy the response is {:?} against the {:?}, not the \
                 workload; breaking the observer does not become permission to act on the agent",
                w.response, w.target
            ),
        },
    );

    let (label, actuated) = drive_containment(&w, &x, at);
    log.record(
        t,
        Layer::Containment,
        containment_unnoticed(&label, actuated),
    );

    // ── NEXORA. A break is carried, never softened.
    let p = proof_of(&x, &single, rec.clone(), at);
    let v = verify_nexora_proof(&p, &anchors_for(&x, &lone));
    assert_ne!(v.result, Some(ReconciliationResult::VerifiedExecution));
    log.record(
        t,
        Layer::Nexora,
        Outcome::Rejected {
            evidence: format!(
                "the verifier re-derives {:?} and reports continuity standing {:?}; a break the \
                 collector attested is carried through and never softened into continuity",
                v.result.map(|r| r.as_str()),
                v.continuity_standing
            ),
        },
    );
}

// ═══ X12 Replay ══════════════════════════════════════════════════════════
//
// The attacker holds previously valid signed artifacts and resubmits them.

fn x12_replay(log: &mut ExecutionLog, gates: &mut Vec<GateSample>) {
    let t = Threat::Replay;
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);

    // ── AIP. The replay is bounded by the artifact's own signature.
    let token = issue_scoped_token(
        &x.agent_id,
        &x.agent_kp.private_key,
        &x.agent_id,
        scope_submitter(),
        Some(TTL),
    )
    .unwrap();
    assert!(verify_scoped_token(&token, &x.agent_kp.public_key).unwrap());
    let mut extended = token.clone();
    extended.expires_at = Some(u64::MAX);
    assert!(!verify_scoped_token(&extended, &x.agent_kp.public_key).unwrap());
    log.record(
        t,
        Layer::Aip,
        Outcome::Rejected {
            evidence: "the replayed token verifies and carries the same signed issuance and \
                       expiry it always did; widening that window to make the replay useful \
                       makes the token fail verification, so the reuse is bounded by the \
                       artifact itself"
                .into(),
        },
    );

    // ── AIRI. A replayed event is indistinguishable from the original.
    let e = signed_airi(
        &x,
        0,
        AiriPayload::ExecutionCompleted(Completion {
            outcome: ReportedOutcome::Success,
            detail: None,
        }),
    );
    verify_airi_event(&e, &x.agent_kp.public_key).unwrap();
    verify_airi_event(&e.clone(), &x.agent_kp.public_key).unwrap();
    log.record(
        t,
        Layer::Airi,
        Outcome::Declined {
            evidence: "the same event verifies as many times as it is offered; AIRI holds no \
                       ledger and settles nothing about whether this is the first submission"
                .into(),
        },
    );

    // ── Observation. The ledger names it.
    let mut ledger = ObserverLedger::new();
    let b1 = o.batch(1, x.now - 3_000, x.now - 2_000, vec![]);
    let b2 = o.batch(2, x.now - 2_000, x.now - 1_000, vec![]);
    ledger.admit(b1.sequence, b1.prev_head, b1.head()).unwrap();
    ledger.admit(b2.sequence, b2.prev_head, b2.head()).unwrap();
    let fault = ledger
        .admit(b2.sequence, b2.prev_head, b2.head())
        .unwrap_err();
    assert!(matches!(fault, ContinuityFault::Replay { .. }));
    log.record(
        t,
        Layer::Observation,
        Outcome::Rejected {
            evidence: "a batch offered at an already-consumed sequence with the same head is \
                       named Replay; the same sequence with a different head would be a Fork \
                       and would quarantine permanently"
                .into(),
        },
    );

    // ── Reconciliation. Duplicates are collapsed and the record says so.
    let ev = {
        let mut b = covered_chain(&x, &mut o, vec![]);
        b.push(b[1].clone());
        o.evidence(b, at)
    };
    let rec = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert!(rec.replay_detected);
    log.record(
        t,
        Layer::Reconciliation,
        Outcome::Rejected {
            evidence: format!(
                "a duplicated attested batch is collapsed and the record carries \
                 replay_detected = {}; the duplicate adds no coverage and no corroboration",
                rec.replay_detected
            ),
        },
    );

    let w = gate(&rec, &x.agent_id, at).expect("an engine verdict yields a warrant");
    gates.push(sample(t, &w));
    log.record(t, Layer::Warrant, warrant_unnoticed(&w));

    // ── Containment. The replay gate is behind two gates that engine output
    //    cannot satisfy, so it could not be reached to be tested.
    let (label, actuated) = drive_containment(&w, &x, at);
    assert!(!actuated);
    log.record(
        t,
        Layer::Containment,
        Outcome::NotStageable {
            reason: format!(
                "contain()'s replay check is gate 14, reached only after the strength gate (5) \
                 and the workload-violation gate (6), which no verdict the engine draws \
                 satisfies. Submitting this threat's real warrant twice gives {label} both \
                 times — a refusal about the warrant's class, not a replay detection. Staging \
                 the ledger would require fabricating a Proven workload-violation warrant, \
                 which no verdict outside a fixture produces"
            ),
        },
    );

    // ── NEXORA. A second submission changes nothing and grants nothing.
    let honest = {
        let b = covered_chain(&x, &mut o, vec![]);
        o.evidence(b, at)
    };
    let hrec = reconcile_expectation(&x.ee, Some(&honest), &ctx(&x, &o, at));
    let p = proof_of(&x, &honest, hrec, at);
    let v = verify_nexora_proof(&p, &anchors_for(&x, &o));
    let mut pledger = aip_nexora::MemoryProofLedger::default();
    let first = aip_nexora::record_submission(&mut pledger, &v).unwrap();
    let second = aip_nexora::record_submission(&mut pledger, &v).unwrap();
    assert!(matches!(first, aip_nexora::ReplayStanding::FirstSeen));
    assert!(matches!(
        second,
        aip_nexora::ReplayStanding::DuplicateSubmission { .. }
    ));
    log.record(
        t,
        Layer::Nexora,
        Outcome::Rejected {
            evidence: "the proof id is recorded on first submission and the second is reported \
                       as a duplicate; the verdict is unchanged, because a proof is no less \
                       true for being shown twice and no more granting"
                .into(),
        },
    );
}

// ═══ X13 Stale authority ═════════════════════════════════════════════════
//
// The attacker holds an authority that was valid and is not any more.

fn x13_stale_authority(log: &mut ExecutionLog, gates: &mut Vec<GateSample>) {
    let t = Threat::StaleAuthority;
    let x = expected();
    let mut o = Observer::new(true, true);
    let at = at_of(&x);

    // ── AIP. An extended expiry has no representation.
    let token = issue_scoped_token(
        &x.agent_id,
        &x.agent_kp.private_key,
        &x.agent_id,
        scope_submitter(),
        Some(TTL),
    )
    .unwrap();
    let mut extended = token.clone();
    extended.expires_at = extended.expires_at.map(|e| e + 10 * MAX_TTL);
    assert!(verify_scoped_token(&token, &x.agent_kp.public_key).unwrap());
    assert!(!verify_scoped_token(&extended, &x.agent_kp.public_key).unwrap());
    log.record(
        t,
        Layer::Aip,
        Outcome::Unrepresentable {
            evidence: "expiry is inside the signature on both ScopedToken and DelegationToken; \
                       a token whose window has been extended does not verify, so a live \
                       authority derived from a dead one has no representation"
                .into(),
        },
    );

    log.record(
        t,
        Layer::Airi,
        Outcome::Unnoticed {
            evidence: "AIRI carries no authority and has nothing to assess; the event verifies \
                       whatever the authority's standing"
                .into(),
        },
    );

    // ── Observation. The observer records what happened, not what was allowed.
    let claim = claim_for(&x);
    let seen = o.present(process_of(&x.ee), Some(&claim), x.now + 10);
    let ev = {
        let b = covered_chain(&x, &mut o, vec![seen]);
        o.evidence(b, at)
    };
    log.record(
        t,
        Layer::Observation,
        Outcome::Unnoticed {
            evidence: "an ObservedExecution carries a process, an effect, a mechanism and an \
                       attribution, and no authority field at all; the record is identical \
                       whether the authority behind it was live or expired"
                .into(),
        },
    );

    // ── Reconciliation. An expectation outside its window is refused.
    let late = x.ee.valid_until + 10 * MAX_TTL;
    let rec = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, late));
    let inside = reconcile_expectation(&x.ee, Some(&ev), &ctx(&x, &o, at));
    assert_ne!(rec.reason, inside.reason);
    log.record(
        t,
        Layer::Reconciliation,
        Outcome::Rejected {
            evidence: format!(
                "reconciled at its own verification time the record answers {} ({:?}); \
                 reconciled long after the window closed it answers {} ({:?}) — the window is \
                 read, not assumed",
                inside.result.as_str(),
                inside.reason,
                rec.result.as_str(),
                rec.reason
            ),
        },
    );

    let w = gate(&inside, &x.agent_id, at).expect("an engine verdict yields a warrant");
    gates.push(sample(t, &w));
    log.record(t, Layer::Warrant, warrant_unnoticed(&w));
    let (label, actuated) = drive_containment(&w, &x, at);
    log.record(
        t,
        Layer::Containment,
        containment_unnoticed(&label, actuated),
    );

    // ── NEXORA. Staleness is a fact about now, assessed at the verifier's clock.
    let p = proof_of(&x, &ev, inside.clone(), at);
    let now_v = verify_nexora_proof(&p, &anchors_at(&x, &o, Some(at)));
    let later = verify_nexora_proof(&p, &anchors_at(&x, &o, Some(late)));
    assert!(!later.authority_standing.grants_authority_now());
    log.record(
        t,
        Layer::Nexora,
        Outcome::Rejected {
            evidence: format!(
                "the same package assessed at its own time reports authority standing {:?} and \
                 assessed long afterwards reports {:?}; neither grants anything, and the \
                 staleness is computed at the verifier's present time rather than read from the \
                 package",
                standing_label(&now_v),
                standing_label(&later)
            ),
        },
    );
}

/// The authority standing without the timestamp inside it, so the log stays
/// byte-identical across runs.
fn standing_label(v: &VerifiedProof) -> &'static str {
    match v.authority_standing {
        aip_nexora::AuthorityStanding::NotAssessed => "NotAssessed",
        aip_nexora::AuthorityStanding::ValidNow => "ValidNow",
        aip_nexora::AuthorityStanding::StaleSince { .. } => "StaleSince",
    }
}

// ═══ The run ═════════════════════════════════════════════════════════════

/// Every attack, in the model's own order. Returns the log and the warrant
/// engine's answers, which the negative control reads.
fn execute_all() -> (ExecutionLog, Vec<GateSample>) {
    let mut log = ExecutionLog::new();
    let mut gates = Vec::new();
    x01_compromised_agent(&mut log, &mut gates);
    x02_compromised_framework(&mut log, &mut gates);
    x03_compromised_model_runtime(&mut log, &mut gates);
    x04_compromised_tool(&mut log, &mut gates);
    x05_compromised_process(&mut log, &mut gates);
    x06_compromised_host(&mut log, &mut gates);
    x07_forged_telemetry(&mut log, &mut gates);
    x08_lost_connectivity(&mut log, &mut gates);
    x09_partial_observation(&mut log, &mut gates);
    x10_sensor_deception(&mut log);
    x11_observer_failure(&mut log, &mut gates);
    x12_replay(&mut log, &mut gates);
    x13_stale_authority(&mut log, &mut gates);
    (log, gates)
}

// ═══ The falsifier ═══════════════════════════════════════════════════════

/// **The point of this file.** For every cell that was executed, the
/// disposition judged from what happened must equal the disposition
/// `src/threat.rs` declares. A disagreement means one of the two is wrong,
/// and neither is allowed to quietly win.
#[test]
fn every_executed_cell_agrees_with_the_declared_model() {
    let (log, _) = execute_all();
    let bad: Vec<String> = log
        .disagreements()
        .iter()
        .map(|c| {
            format!(
                "{}/{}: declared {} but execution showed {} — {}",
                c.threat_id,
                c.layer.as_str(),
                c.declared.as_str(),
                c.observed.map(|d| d.as_str()).unwrap_or("nothing"),
                c.outcome.detail()
            )
        })
        .collect();
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Every cell in the declared model was reached. A cell nobody executed and
/// nobody declared unstageable is an omission, and omissions are how a model
/// drifts away from the system.
#[test]
fn every_cell_in_the_model_was_reached() {
    let (log, _) = execute_all();
    let missing: Vec<String> = log
        .missing()
        .iter()
        .map(|(t, l)| format!("{}/{}", t.id(), l.as_str()))
        .collect();
    assert!(missing.is_empty(), "unreached: {missing:?}");
    assert_eq!(log.cells.len(), Threat::ALL.len() * Layer::ALL.len());
}

/// **The negative control for every "consumes a verdict" cell.**
///
/// The warrant engine's answer is keyed by the fields it is supposed to read.
/// If one key produced two different answers, some threat-specific rule would
/// exist and every `NotDetectable` warrant cell would be wrong.
///
/// The test also requires the key set to *collide* — two different threats
/// reaching the same key. Without a collision the check is vacuous, and a
/// vacuous negative control is worse than none.
#[test]
fn the_warrant_layer_makes_no_threat_specific_distinction() {
    let (_, gates) = execute_all();
    assert!(gates.len() >= 10, "too few samples to conclude anything");

    let mut by_key: std::collections::HashMap<&str, Vec<&GateSample>> =
        std::collections::HashMap::new();
    for g in &gates {
        by_key.entry(g.key.as_str()).or_default().push(g);
    }
    for (key, group) in &by_key {
        let answers: std::collections::BTreeSet<&str> =
            group.iter().map(|g| g.answer.as_str()).collect();
        assert_eq!(
            answers.len(),
            1,
            "key {key} produced {answers:?} — the warrant engine distinguishes something \
             beyond the verdict"
        );
    }
    let colliding = by_key
        .values()
        .filter(|g| {
            g.iter()
                .map(|s| s.threat)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                > 1
        })
        .count();
    assert!(
        colliding > 0,
        "no two threats reached the same verdict key, so this control proved nothing"
    );
}

/// No attack in this file reached an actuator. Stated as its own test because
/// it is the one outcome that would matter most if it changed.
#[test]
fn no_staged_attack_reached_an_actuator() {
    let (log, _) = execute_all();
    for c in log.executed_for(Threat::CompromisedHost) {
        if c.layer == Layer::Containment {
            assert!(
                c.outcome.detail().contains("reached 0 times"),
                "{}",
                c.outcome.detail()
            );
        }
    }
}

/// **Finding.** The one threat with no defence anywhere is also the one whose
/// attack could not be staged at all. Both facts are reported; neither
/// substitutes for the other.
#[test]
fn sensor_deception_could_not_be_staged_at_all() {
    let (log, _) = execute_all();
    let cells: Vec<_> = log
        .cells
        .iter()
        .filter(|c| c.threat == Threat::SensorDeception)
        .collect();
    assert_eq!(cells.len(), Layer::ALL.len());
    assert!(
        cells.iter().all(|c| !c.outcome.was_executed()),
        "a sensor-deception cell claims to have been executed; there is no sensor here to deceive"
    );
    assert!(cells
        .iter()
        .all(|c| c.outcome.detail().contains("no sensor to deceive")));
}

/// The structural facts the sensor-deception cells rest on, asserted
/// separately and labelled as what they are: the *reason* the cells are true,
/// not an execution of the attack they describe.
#[test]
fn sensor_deception_rests_on_a_class_with_no_mechanism() {
    assert!(!ObservationClass::PhysicalEffect.is_implemented());
    for m in SourceMechanism::ALL {
        assert_ne!(
            class_of(m),
            ObservationClass::PhysicalEffect,
            "{m:?} maps to the physical-effect class, which has no implemented mechanism"
        );
    }
}

/// **Finding.** The replay defence at the containment layer sits behind two
/// gates that no verdict the engine draws can satisfy, so it could not be
/// executed. The declared cell is not wrong about the code; it is
/// unverifiable by execution, which is a different thing and is reported as
/// one.
#[test]
fn the_containment_replay_gate_is_unreachable_from_engine_output() {
    let (log, _) = execute_all();
    let c = log
        .cells
        .iter()
        .find(|c| c.threat == Threat::Replay && c.layer == Layer::Containment)
        .expect("the cell must exist");
    assert!(!c.outcome.was_executed());
    assert!(c.outcome.detail().contains("gate 14"));
}

/// Every unstageable cell says why, and the ones claiming a defence are
/// counted on their own. A reader who trusts nothing else should read this
/// number.
#[test]
fn every_unstageable_cell_carries_a_reason_and_is_counted() {
    let (log, _) = execute_all();
    for c in log.not_stageable() {
        assert!(
            c.outcome.detail().len() > 40,
            "{}/{} gives no reason",
            c.threat_id,
            c.layer.as_str()
        );
    }
    let cov = log.coverage();
    assert_eq!(cov.cells, 91);
    assert_eq!(cov.executed + cov.not_stageable, cov.cells);
    assert_eq!(cov.agreements + cov.disagreements, cov.executed);
    assert_eq!(cov.unverified_defences, log.unverified_defences().len());
}

/// The log is byte-identical across runs: no key, digest, id or clock reading
/// reaches an evidence string. Without this the committed artifact would
/// churn and nobody could review a diff of it.
#[test]
fn execution_is_deterministic() {
    let (a, _) = execute_all();
    let (b, _) = execute_all();
    assert_eq!(a.to_json(), b.to_json());
    assert_eq!(a.to_csv(), b.to_csv());
}

/// The committed artifact is what this run produces. Regenerate with
/// `AIP_WRITE_EXECUTION_LOG=1 cargo test -p aip-conformance --test empirical`.
#[test]
fn the_committed_execution_log_is_current() {
    let (log, _) = execute_all();
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repository root")
        .join("docs/audit");
    let json = root.join("THREAT_EXECUTION_LOG.json");
    let csv = root.join("THREAT_EXECUTION_LOG.csv");
    if std::env::var("AIP_WRITE_EXECUTION_LOG").is_ok() {
        std::fs::write(&json, log.to_json()).unwrap();
        std::fs::write(&csv, log.to_csv()).unwrap();
        return;
    }
    assert_eq!(
        std::fs::read_to_string(&json).expect("committed execution log"),
        log.to_json(),
        "{} is stale; regenerate with AIP_WRITE_EXECUTION_LOG=1",
        json.display()
    );
    assert_eq!(
        std::fs::read_to_string(&csv).expect("committed execution log"),
        log.to_csv()
    );
}
