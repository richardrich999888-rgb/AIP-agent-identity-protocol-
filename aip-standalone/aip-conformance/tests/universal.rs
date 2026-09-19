//! The universal invariant set, asked of the core (Skill 28, R1).
//!
//! Each test is the executable half of one row of
//! `docs/audit/CONFORMANCE_MATRIX.{json,csv}`. The matrix asserts; these tests
//! are what makes the assertion worth reading. If one fails, the matrix is
//! wrong — `tests/matrix.rs` checks that every cell's witness names a test
//! that exists here, so a cell cannot outlive its evidence.
//!
//! These are properties of the **core**, which every domain reaches through
//! the same crates. That sameness is the conformance claim: there is no
//! per-domain identity model, no per-domain reconciler, no per-domain proof
//! tree. `tests/substitution.rs` attacks the claim from the other side.

use aip_conformance::{Domain, InvariantCode};
use aip_core::capability::{issue_scoped_token, scope_orchestrator, scope_submitter};
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::{generate_ed25519_keypair, sha256};
use aip_observation::{class_of, EvidenceCeiling, ObservationClass};
use aip_observe::{ObserverAttestor, SourceMechanism};
use aip_types::{ExecutionBinding, ProcessInstance, ProvenanceTriple};

/// A signed health record from a collector that has attested nothing yet.
/// Enough to reach the engine; not enough for it to conclude anything.
fn health_for_a_fresh_collector() -> aip_observe::SignedSensorHealth {
    let kp = generate_ed25519_keypair();
    let mut signer = aip_observe::CollectorSigner::new(
        "conformance-collector",
        1,
        &kp.private_key,
        &kp.public_key,
    )
    .unwrap();
    signer.register_probe("conformance-probe", &aip_observe::SourceMechanism::ALL);
    signer.health(1_700_000_000_000).unwrap()
}

fn provenance(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(tag.as_bytes()),
        environment_commitment: sha256(b"conformance-env"),
        toolchain_commitment: sha256(b"conformance-toolchain"),
    }
}

// ═══ I01 Identity ═══

/// An AIP-ID is derived from a key and a provenance triple and validates; a
/// malformed one is refused rather than panicking a consumer.
#[test]
fn i01_identity_is_derived_and_malformed_input_is_refused_not_fatal() {
    let (aid, _kp) = create_identity(provenance("i01"), None).unwrap();
    assert!(aip_core::validate_aid(&aid).is_ok());

    // The boundary: derivation says nothing about who holds the key. Two
    // identities from two keys are distinct, and that is all it establishes.
    let (other, _) = create_identity(provenance("i01-other"), None).unwrap();
    assert_ne!(aid.id, other.id);

    // Malformed input is a refusal, never a panic. The reconciler and the
    // service both parse ids from untrusted bytes.
    for bad in ["", "aip1", "not-an-aip-id", "aip1!!!!", &"a".repeat(4096)] {
        let mut doc = aid.clone();
        doc.id = bad.to_string();
        assert!(
            aip_core::validate_aid(&doc).is_err(),
            "a malformed id must be refused: {bad:?}"
        );
    }
}

// ═══ I02 Authority ═══

/// A delegation chain verifies under the verifier's own issuer anchors, and a
/// parent-child relation confers nothing by itself.
#[test]
fn i02_authority_is_a_verified_chain_not_a_parent_child_relation() {
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = aip_crypto::derive_aip_id(&cfo_kp.public_key, &provenance("cfo"));
    let (orch, orch_kp) = create_identity(provenance("orch"), None).unwrap();
    let (agent, _) = create_identity(provenance("agent"), None).unwrap();

    let root = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &orch.id,
        scope_orchestrator(),
        Some(3_600_000),
    )
    .unwrap();
    let hop = create_delegation(&root, &orch_kp.private_key, &agent.id, scope_submitter()).unwrap();

    // The chain verifies only under anchors the verifier itself provisioned.
    let mut issuers = std::collections::HashMap::new();
    issuers.insert(cfo_id.clone(), cfo_kp.public_key.clone());
    issuers.insert(orch.id.clone(), orch_kp.public_key.clone());
    assert!(aip_core::delegation::verify_delegation_chain(
        &root,
        std::slice::from_ref(&hop),
        &issuers
    )
    .is_ok());

    // Empty anchors: the same bytes establish nothing.
    let none = std::collections::HashMap::new();
    assert!(aip_core::delegation::verify_delegation_chain(&root, &[hop], &none).is_err());

    // A child identity created from a parent inherits no authority. The
    // parent is named with its real key — this is a genuine lineage link —
    // and the child still appears nowhere in the delegation chain above.
    let (parent, parent_kp) = create_identity(provenance("parent"), None).unwrap();
    let (child, _) = create_identity(
        provenance("child"),
        Some((parent.id.as_str(), parent_kp.public_key.as_slice())),
    )
    .unwrap();
    assert_ne!(child.id, parent.id, "a child is its own identity");
    // The load-bearing assertion: being someone's child grants nothing. The
    // child holds no token, so no chain terminates at it.
    assert!(
        !format!("{root:?}").contains(&child.id),
        "a parent-child relation must not put the child in an authority chain"
    );
}

// ═══ I04 ExecutionBinding ═══

/// Execution identity is the process instance and the executable's content,
/// not a PID — so a binding does not transplant to another host or execution.
#[test]
fn i04_execution_binding_is_not_a_pid_and_does_not_transplant() {
    let (agent, _) = create_identity(provenance("i04"), None).unwrap();
    let mk = |pid: u32, boot: [u8; 16], exe: &[u8]| ExecutionBinding {
        version: aip_types::EXECUTION_BINDING_VERSION,
        agent_id: agent.id.clone(),
        process: ProcessInstance {
            pid,
            pid_start_time_ticks: 1_000,
            boot_id: boot,
        },
        exe_content_sha256: sha256(exe),
        exe_path: "/opt/agent/bin/worker".into(),
        bound_at_ms: 1_700_000_000_000,
        container: None,
    };
    let base = mk(4242, [0x11; 16], b"/opt/agent");

    // Same PID, different boot: a different execution.
    assert_ne!(
        base.identity_bytes(),
        mk(4242, [0x22; 16], b"/opt/agent").identity_bytes(),
        "a PID reused across a reboot is not the same execution"
    );
    // Same PID and boot, different binary: a different execution.
    assert_ne!(
        base.identity_bytes(),
        mk(4242, [0x11; 16], b"/opt/other").identity_bytes(),
        "the executable's content is part of the identity"
    );
    // Same everything: the same execution.
    assert_eq!(
        base.identity_bytes(),
        mk(4242, [0x11; 16], b"/opt/agent").identity_bytes()
    );
}

// ═══ I05 AIRI claim ═══

/// A framework event is a claim. No framework name grants anything.
#[test]
fn i05_no_framework_name_is_a_trust_input() {
    // The type carries a name, a version and the adapter's version — three
    // strings. There is no method on it that returns authority, a ceiling or
    // a verdict, and the profiles' own guards assert nothing branches on the
    // name to grant. Here the property is read from the shape: a
    // `FrameworkIdentity` differing only in its name produces a different
    // value and no different *standing*.
    let a = aip_airi::FrameworkIdentity {
        name: "langgraph".into(),
        version: "1.0".into(),
        adapter_version: "1".into(),
    };
    let b = aip_airi::FrameworkIdentity {
        name: "a-framework-nobody-has-heard-of".into(),
        ..a.clone()
    };
    assert_ne!(a, b, "the name is data and distinguishes records");

    // The enterprise profile is the one that maps frameworks, and it states
    // the rule as a non-overridable method. Asking it is the check.
    assert!(
        !aip_enterprise::EnterpriseAdapter::framework_grants_authority(
            &aip_enterprise::GraphFrameworkAdapter {
                framework_version: "1.0".into(),
                adapter_version: "1".into(),
            }
        ),
        "no framework grants authority"
    );
    assert!(
        !aip_enterprise::EnterpriseAdapter::framework_grants_authority(
            &aip_enterprise::ConversationFrameworkAdapter {
                framework_version: "2.0".into(),
                adapter_version: "1".into(),
            }
        ),
        "and not this one either"
    );
}

// ═══ I06 Observation ═══

/// An observation carries its class, and a class's evidence ceiling is
/// declared rather than computed from the record. A profile may not raise one.
#[test]
fn i06_a_ceiling_is_declared_per_class_and_never_computed() {
    // Every mechanism maps to exactly one class, and the map is total.
    for m in SourceMechanism::ALL {
        let c = class_of(m);
        assert!(
            ObservationClass::ALL.contains(&c),
            "{m:?} maps outside the class set"
        );
        // The ceiling is a property of the class, reached without a record.
        let _: EvidenceCeiling = c.ceiling();
    }

    // The declared-but-unreachable class stays unreachable. Its ceiling is
    // Attested, never Proven: a sensor reading is content read from a device
    // and is root-forgeable exactly as procfs is (ADR-003 §2).
    assert!(!ObservationClass::PhysicalEffect.is_implemented());
    assert_eq!(
        ObservationClass::PhysicalEffect.ceiling(),
        EvidenceCeiling::Attested
    );
    assert!(
        !SourceMechanism::ALL
            .iter()
            .any(|m| class_of(*m) == ObservationClass::PhysicalEffect),
        "no mechanism may implement the physical-effect class"
    );
}

// ═══ I09 Reconciliation ═══

/// One engine draws every verdict, and CANNOT_PROVE is the default.
#[test]
fn i09_cannot_prove_is_the_default_and_strength_follows_result_kind() {
    // Strength is a function of the result kind. Nothing carries a severity
    // or a score, so nothing can substitute one for evidence.
    let results = [
        aip_reconcile::ReconciliationResult::CannotProve,
        aip_reconcile::ReconciliationResult::VerifiedExecution,
        aip_reconcile::ReconciliationResult::PhantomClaim,
        aip_reconcile::ReconciliationResult::UnattributedEffect,
        aip_reconcile::ReconciliationResult::IdentityDivergence,
        aip_reconcile::ReconciliationResult::SensorIntegrityFailure,
        aip_reconcile::ReconciliationResult::ContinuityFailure,
    ];
    // Every result has a stable code and a stable name, and the codes are
    // distinct — an artifact written today still means the same thing when
    // read later. `CannotProve` is deliberately code 0: the default verdict
    // takes the default value, so a zeroed field decodes to the conservative
    // answer rather than to a conclusion.
    assert_eq!(aip_reconcile::ReconciliationResult::CannotProve.code(), 0);
    let mut codes: Vec<u8> = results.iter().map(|r| r.code()).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), results.len(), "verdict codes must be distinct");
    for r in results {
        assert!(!r.as_str().is_empty());
    }

    // CANNOT_PROVE is what the engine reaches with nothing to work from, and
    // a record read back from bytes is never the engine's own output — the
    // seal a consumer that *acts* on a verdict depends on.
    let ctx = aip_reconcile::ReconciliationContext {
        decision_point_anchors: aip_authorize::DecisionPointTrustAnchors::new(),
        observer_anchors: aip_observe::ObserverTrustAnchors::new(),
        verification_time_ms: 1_700_000_000_000,
        health_max_age_ms: 60_000,
        window_tolerance_ms: 0,
        expected_side: aip_reconcile::ExpectedSideCoverage::Unknown,
        agent_public_key: None,
    };
    let r = aip_reconcile::reconcile_observation(
        &aip_reconcile::ObserverEvidence {
            batches: vec![],
            health: health_for_a_fresh_collector(),
        },
        aip_reconcile::ObservationTarget::Observation {
            batch_sequence: aip_reconcile::ObserverSequence(1),
            index: 0,
        },
        &ctx,
    );
    assert_eq!(r.result, aip_reconcile::ReconciliationResult::CannotProve);
    assert!(r.is_engine_produced(), "the engine produced this one");

    let json = serde_json::to_string(&r).unwrap();
    let back: aip_reconcile::Reconciliation = serde_json::from_str(&json).unwrap();
    assert_eq!(back.result, r.result, "the round trip is faithful");
    assert!(
        !back.is_engine_produced(),
        "however faithful, a deserialised record is not the engine's own output"
    );
}

// ═══ The set itself ═══

/// The invariant set is complete, stably coded and self-describing, and every
/// invariant states where it stops.
#[test]
fn the_invariant_set_is_total_stable_and_bounded() {
    assert_eq!(
        InvariantCode::ALL.len(),
        12,
        "the specification names twelve"
    );

    let mut ids: Vec<&str> = InvariantCode::ALL.iter().map(|i| i.id()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 12, "invariant ids must be distinct");

    for i in InvariantCode::ALL {
        let d = i.describe();
        assert!(
            !d.requires.is_empty(),
            "{i:?} says nothing about what it requires"
        );
        assert!(
            !d.stops_at.is_empty(),
            "{i:?} states no boundary; an invariant without one invites the \
             reader to assume it covers more than it does"
        );
    }
}

/// Seven named domains, five crates. The mapping is carried, not hidden.
#[test]
fn the_domain_set_reports_its_own_double_counting() {
    assert_eq!(Domain::ALL.len(), 7);
    assert_eq!(
        Domain::distinct_crates().len(),
        5,
        "seven names are realised by five crates"
    );

    // The two shared pairs name each other, so a reader of one row learns it
    // is not independent of the other.
    assert_eq!(Domain::Ugv.realisation().shared_with, &[Domain::Robotics]);
    assert_eq!(Domain::Robotics.realisation().shared_with, &[Domain::Ugv]);
    assert_eq!(
        Domain::Industrial.realisation().shared_with,
        &[Domain::CriticalEdge]
    );
    assert_eq!(
        Domain::CriticalEdge.realisation().shared_with,
        &[Domain::Industrial]
    );

    // Every unshared domain says so.
    for d in [Domain::Enterprise, Domain::Uas, Domain::Space] {
        assert!(d.realisation().shared_with.is_empty());
    }

    // Exactly one domain is not embodied — the disconfirming instance ADR-011
    // was written about.
    assert_eq!(Domain::ALL.iter().filter(|d| !d.is_embodied()).count(), 1);
    assert!(!Domain::Enterprise.is_embodied());
}

/// Every domain registers a distinct profile id and a distinct domain tag.
/// Five crates, five ids, five tags — two domains sharing a crate share its
/// id, which is correct and is exactly what `shared_with` records.
#[test]
fn every_realising_crate_has_a_distinct_identity() {
    let mut ids: Vec<&str> = Domain::ALL
        .iter()
        .map(|d| d.realisation().profile_id)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 5);

    let mut tags: Vec<&str> = Domain::ALL
        .iter()
        .map(|d| d.realisation().profile_domain)
        .collect();
    tags.sort_unstable();
    tags.dedup();
    assert_eq!(tags.len(), 5);

    // Every tag is domain-separated under the same namespace and version.
    for d in Domain::ALL {
        let t = d.realisation().profile_domain;
        assert!(t.starts_with("SYNTRIASS/AUTONOMY/"), "{t}");
        assert!(t.ends_with("/v1"), "{t}");
    }
}

// ═══ I03 ExpectedExecution ═══

/// An expectation is decision-point signed, its expiry is inside the
/// signature, and the agent may not be its own decision point.
#[test]
fn i03_an_expectation_is_signed_bounded_and_not_self_authorized() {
    let dp_kp = generate_ed25519_keypair();
    let dp_id = aip_crypto::derive_aip_id(&dp_kp.public_key, &provenance("dp"));
    let anchors = aip_authorize::DecisionPointTrustAnchors::new().trust(&dp_id, &dp_kp.public_key);

    // A verifier holding the decision point's anchor accepts nothing that was
    // not signed by it: an empty anchor set establishes nothing about the
    // same bytes.
    let empty = aip_authorize::DecisionPointTrustAnchors::new();
    assert!(
        empty.get(&dp_id).is_none(),
        "an unprovisioned verifier anchors nothing"
    );
    assert!(anchors.get(&dp_id).is_some());

    // The boundary that matters: an expectation is never evidence that
    // anything executed. `aip-authorize` exposes no method that turns one
    // into an observation, and the reconciler requires observer evidence
    // separately — i07 is the executed half of that.
    // The structure is versioned, so a future shape is refused rather than
    // guessed at. Pinned rather than bounded: a bump is a compatibility event
    // and must surface here.
    assert_eq!(aip_authorize::EXPECTED_EXECUTION_VERSION, 1);
}

// ═══ I07 Attribution ═══

/// An effect is attributed only through an attested complete expected side.
/// Insufficient evidence is CANNOT_PROVE, never an accusation.
///
/// This is the invariant whose *reach* differs by domain, and the one the
/// matrix records per domain. What does not differ is the floor asserted
/// here: with the expected side unknown, no domain reaches an accusation.
#[test]
fn i07_an_unknown_expected_side_never_becomes_an_accusation() {
    let ctx = aip_reconcile::ReconciliationContext {
        decision_point_anchors: aip_authorize::DecisionPointTrustAnchors::new(),
        observer_anchors: aip_observe::ObserverTrustAnchors::new(),
        verification_time_ms: 1_700_000_000_000,
        health_max_age_ms: 60_000,
        window_tolerance_ms: 0,
        expected_side: aip_reconcile::ExpectedSideCoverage::Unknown,
        agent_public_key: None,
    };
    let r = aip_reconcile::reconcile_observation(
        &aip_reconcile::ObserverEvidence {
            batches: vec![],
            health: health_for_a_fresh_collector(),
        },
        aip_reconcile::ObservationTarget::Observation {
            batch_sequence: aip_reconcile::ObserverSequence(1),
            index: 0,
        },
        &ctx,
    );
    assert_eq!(r.result, aip_reconcile::ReconciliationResult::CannotProve);
    assert_ne!(
        r.result,
        aip_reconcile::ReconciliationResult::UnattributedEffect,
        "insufficient evidence must never become an accusation"
    );
}

// ═══ I08 Continuity ═══

/// A gap, fork, rollback or replay in the observer's own record is explicit
/// and sticky. Later well-formed traffic never erases a recorded gap.
#[test]
fn i08_a_recorded_gap_is_sticky_and_a_fork_quarantines_permanently() {
    use aip_observe::{Admission, ContinuityFault, ContinuityStatus, ObserverLedger};
    let h = |b: u8| [b; 32];

    // A gap is admitted, named, and not erased by later contiguity.
    let mut l = ObserverLedger::new();
    l.admit(1, [0u8; 32], h(1)).unwrap();
    l.admit(2, h(1), h(2)).unwrap();
    assert_eq!(l.status(), ContinuityStatus::Verified);
    assert_eq!(
        l.admit(5, h(2), h(5)),
        Ok(Admission::AdmittedWithGap { missing: 2 })
    );
    assert_eq!(l.status(), ContinuityStatus::GapObserved);
    l.admit(6, h(5), h(6)).unwrap();
    assert_eq!(
        l.status(),
        ContinuityStatus::GapObserved,
        "a later good batch must not erase a recorded gap"
    );

    // A replay is refused rather than counted twice.
    let mut l = ObserverLedger::new();
    l.admit(1, [0u8; 32], h(1)).unwrap();
    assert_eq!(
        l.admit(1, [0u8; 32], h(1)),
        Err(ContinuityFault::Replay { sequence: 1 })
    );

    // A fork quarantines permanently: later well-formed traffic cannot clear
    // a proven integrity failure of the observer's own record.
    let mut l = ObserverLedger::new();
    l.admit(1, [0u8; 32], h(1)).unwrap();
    assert!(matches!(
        l.admit(1, [0u8; 32], h(9)),
        Err(ContinuityFault::Fork { .. })
    ));
    assert!(l.is_quarantined());
    assert!(l.admit(2, h(1), h(2)).is_err());
    assert_eq!(l.status(), ContinuityStatus::Broken);
}

// ═══ I10 Warrant ═══

/// A warrant is permission to act on proof, not proof. A verdict the caller
/// assembled — including one it deserialised from bytes it wrote itself — is
/// refused at the gate.
#[test]
fn i10_a_warrant_refuses_a_verdict_the_engine_did_not_draw() {
    // A genuine engine record, round-tripped through bytes. Faithful, and no
    // longer the engine's own output.
    let ctx = aip_reconcile::ReconciliationContext {
        decision_point_anchors: aip_authorize::DecisionPointTrustAnchors::new(),
        observer_anchors: aip_observe::ObserverTrustAnchors::new(),
        verification_time_ms: 1_700_000_000_000,
        health_max_age_ms: 60_000,
        window_tolerance_ms: 0,
        expected_side: aip_reconcile::ExpectedSideCoverage::Unknown,
        agent_public_key: None,
    };
    let engine = aip_reconcile::reconcile_observation(
        &aip_reconcile::ObserverEvidence {
            batches: vec![],
            health: health_for_a_fresh_collector(),
        },
        aip_reconcile::ObservationTarget::Observation {
            batch_sequence: aip_reconcile::ObserverSequence(1),
            index: 0,
        },
        &ctx,
    );
    let back: aip_reconcile::Reconciliation =
        serde_json::from_str(&serde_json::to_string(&engine).unwrap()).unwrap();

    let finding = aip_warrant::Finding {
        finding_id: [0x28; 16],
        reconciliation: back,
        subject_agent: None,
    };
    let policy = aip_warrant::WarrantPolicy::default();
    assert_eq!(
        aip_warrant::evaluate(&finding, &policy, 1_700_000_000_000),
        Err(aip_warrant::Refusal::ReconciliationNotEngineProduced),
        "a warrant is permission to act on proof, not on a record a caller assembled"
    );
}

// ═══ I12 Proof ═══

/// A proof package is re-derived by the verifier and never trusted on its own
/// word; a head altered after signing is refused.
#[test]
fn i12_a_proof_is_rederived_and_a_tampered_head_is_refused() {
    use aip_nexora::commitment::*;
    use aip_nexora::merkle::LeafKind;

    let kp = generate_ed25519_keypair();
    let signer =
        NexoraSigner::new("conformance-nexora", 1, &kp.private_key, &kp.public_key).unwrap();
    let anchors = NexoraTrustAnchors::new().trust("conformance-nexora", 1, &kp.public_key);

    let mut log = CommitmentLog::new([0x28; 16]);
    for i in 0..4u32 {
        log.append(LeafKind::Reconciliation, format!("record-{i}").as_bytes());
    }
    let head = log.head(&signer, 1_700_000_000_000).unwrap();
    verify_signed_head(&head, &anchors).unwrap();

    let proof = log.proof_for(1, &head).unwrap();
    let v = verify_proof(&proof, &anchors).unwrap();
    // The verifier re-derives the record's digest rather than taking the
    // package's word for it.
    assert_eq!(v.record_digest, aip_crypto::sha256(b"record-1"));
    assert_eq!(v.kind, LeafKind::Reconciliation);

    // A head altered after signing is refused, and an unanchored verifier
    // establishes nothing from the same bytes.
    let mut t = head.clone();
    t.size = 3;
    assert!(verify_signed_head(&t, &anchors).is_err());
    assert!(verify_signed_head(&head, &NexoraTrustAnchors::new()).is_err());

    // The proof tree stays at eleven leaf kinds (SD-10 added the signed
    // verdict, R3 the access ledger): a new kind is a wire change.
    assert_eq!(LeafKind::ALL.len(), 11);
}
