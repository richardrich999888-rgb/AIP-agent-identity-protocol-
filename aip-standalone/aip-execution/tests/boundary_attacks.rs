//! Skill 18 — the 25-case adversarial matrix.
//!
//! Each test attacks one boundary of the execution model. The rule the skill
//! sets is that a failed attack must **prove the intended boundary**, not
//! merely return an error — so every assertion names which boundary held and
//! why, and the substitution cases assert that the *encoding* changed rather
//! than that some unrelated validation tripped.
//!
//! # What "the boundary held" means here
//!
//! `ExecutionProfile` is unsigned by design. An unsigned record cannot stop
//! anyone writing what they like into it, and these tests do not pretend
//! otherwise. What they establish is that a substitution changes the canonical
//! bytes — so the digest the decision point signed no longer matches, and the
//! substitution cannot be *silent*.
//!
//! Silence is the property under attack. Prevention belongs to the DP
//! signature over `ActionParameters`, which is exercised in `binding.rs`.

use aip_execution::*;
use aip_system::{HardwareId, MissionId, PlatformId, SystemExecution, SystemId};
use aip_types::{ExecutionBinding, ProcessInstance, EXECUTION_BINDING_VERSION};

const NOW: u64 = 1_700_000_000_000;
const EXEC_A: [u8; 16] = [0xA1; 16];
const EXEC_B: [u8; 16] = [0xB2; 16];
const DECISION_A: [u8; 16] = [0xD1; 16];
const DECISION_B: [u8; 16] = [0xD2; 16];

fn agent(tag: &str) -> String {
    use aip_crypto::{derive_aip_id, sha256};
    use aip_types::ProvenanceTriple;
    aip_crypto::derive_aip_id(
        &sha256(format!("pk-{tag}").as_bytes()),
        &ProvenanceTriple {
            model_commitment: sha256(format!("m-{tag}").as_bytes()),
            environment_commitment: sha256(format!("e-{tag}").as_bytes()),
            toolchain_commitment: sha256(format!("t-{tag}").as_bytes()),
        },
    )
    .to_owned()
    .pipe(|s| {
        let _ = derive_aip_id;
        s
    })
}

trait Pipe: Sized {
    fn pipe<R>(self, f: impl FnOnce(Self) -> R) -> R {
        f(self)
    }
}
impl<T> Pipe for T {}

/// A baseline execution: one agent, one system, one platform, one hardware,
/// one mission. Every attack below is this with exactly one thing changed.
fn base_execution() -> SystemExecution {
    SystemExecution::new(
        SystemId::parse("sys:fleet-1").unwrap(),
        &agent("alpha"),
        EXEC_A,
        NOW,
    )
    .unwrap()
    .on_platform(PlatformId::parse("tail:N123AB").unwrap())
    .on_hardware(HardwareId::parse("tpm-ek:aaa").unwrap())
    .for_mission(MissionId::parse("op:sortie-77").unwrap())
}

fn commitment(tag: u8) -> [u8; 32] {
    [tag; 32]
}

fn requested(action: &str, param: u8) -> RequestedEffect {
    RequestedEffect {
        action_kind: action.to_owned(),
        parameter_commitment: commitment(param),
        target: Some("payments.internal".to_owned()),
    }
}

fn runtime_ok(param: u8) -> RuntimeAction {
    RuntimeAction {
        parameter_commitment: commitment(param),
        transport_status: Some(200),
        result_commitment: Some(commitment(0xCC)),
        reported_at_ms: NOW + 10,
    }
}

fn base_profile() -> ExecutionProfile {
    ExecutionProfile::new(base_execution(), NOW)
        .claiming_decision(DECISION_A)
        .with_airi_chain_head(commitment(0xAE))
        .with_runtime(
            RuntimeDeclaration::new()
                .declared("python3.11")
                .selected("pytorch"),
        )
        .with_effect(EffectOutcome::reported(
            requested("write", 0x11),
            runtime_ok(0x11),
        ))
}

/// Assert that `altered` is a genuinely different security context from the
/// baseline, and say which boundary that protects.
fn assert_distinct(altered: &ExecutionProfile, what: &str) {
    let base = base_profile();
    assert_ne!(
        base.canonical_bytes(),
        altered.canonical_bytes(),
        "SECURITY: {what} produced identical canonical bytes. The decision \
         point's signature over the profile digest would still verify, so the \
         substitution would be invisible."
    );
    assert_ne!(
        base.digest(),
        altered.digest(),
        "SECURITY: {what} collided on the digest that is actually signed"
    );
}

// ═══ 1-8. Cross-identity substitution ═══

#[test]
fn a01_cross_agent_execution_substitution() {
    // Agent B presents agent A's execution. The agent id is inside the
    // embedded SystemExecution encoding, so the profile digest changes.
    let p = ExecutionProfile::new(
        SystemExecution::new(
            SystemId::parse("sys:fleet-1").unwrap(),
            &agent("bravo"),
            EXEC_A,
            NOW,
        )
        .unwrap()
        .on_platform(PlatformId::parse("tail:N123AB").unwrap())
        .on_hardware(HardwareId::parse("tpm-ek:aaa").unwrap())
        .for_mission(MissionId::parse("op:sortie-77").unwrap()),
        NOW,
    )
    .claiming_decision(DECISION_A)
    .with_airi_chain_head(commitment(0xAE))
    .with_runtime(
        RuntimeDeclaration::new()
            .declared("python3.11")
            .selected("pytorch"),
    )
    .with_effect(EffectOutcome::reported(
        requested("write", 0x11),
        runtime_ok(0x11),
    ));
    assert_distinct(&p, "agent A → agent B");
}

#[test]
fn a02_cross_execution_substitution() {
    let mut e = base_execution();
    e.execution_id = EXEC_B;
    let p = rebuild(e);
    assert_distinct(&p, "execution X → execution Y");
}

#[test]
fn a03_cross_platform_substitution() {
    let p = rebuild(
        SystemExecution::new(
            SystemId::parse("sys:fleet-1").unwrap(),
            &agent("alpha"),
            EXEC_A,
            NOW,
        )
        .unwrap()
        .on_platform(PlatformId::parse("tail:N456CD").unwrap())
        .on_hardware(HardwareId::parse("tpm-ek:aaa").unwrap())
        .for_mission(MissionId::parse("op:sortie-77").unwrap()),
    );
    assert_distinct(&p, "platform A → platform B");
}

#[test]
fn a04_cross_hardware_substitution() {
    let mut e = base_execution();
    e.hardware_id = Some(HardwareId::parse("tpm-ek:bbb").unwrap());
    assert_distinct(&rebuild(e), "hardware A → hardware B");
}

#[test]
fn a05_cross_mission_substitution() {
    let mut e = base_execution();
    e.mission_id = Some(MissionId::parse("op:sortie-99").unwrap());
    assert_distinct(&rebuild(e), "mission A → mission B");
}

#[test]
fn a06_cross_decision_substitution() {
    // The claimed authorization is swapped. This is the attack the DP
    // signature exists to catch: the profile digest is what the decision point
    // signed, and it covers the decision the profile claims.
    let p = base_profile_with(|p| p.claiming_decision(DECISION_B));
    assert_distinct(&p, "decision A → decision B");
}

#[test]
fn a07_cross_model_substitution() {
    // The model claim lives in the AIRI chain, committed to by
    // airi_chain_head. Exchanging the chain for one describing a different
    // model changes the head, and so the profile digest.
    let p = base_profile_with(|p| p.with_airi_chain_head(commitment(0xBE)));
    assert_distinct(&p, "model claim chain A → chain B");
}

#[test]
fn a08_cross_framework_substitution() {
    // Framework identity is part of the AIRI event and of the runtime
    // declaration. Changing the selected runtime changes the encoding.
    let p = base_profile_with(|p| {
        p.with_runtime(
            RuntimeDeclaration::new()
                .declared("python3.11")
                .selected("jax"),
        )
    });
    assert_distinct(&p, "framework pytorch → jax");
}

fn rebuild(e: SystemExecution) -> ExecutionProfile {
    ExecutionProfile::new(e, NOW)
        .claiming_decision(DECISION_A)
        .with_airi_chain_head(commitment(0xAE))
        .with_runtime(
            RuntimeDeclaration::new()
                .declared("python3.11")
                .selected("pytorch"),
        )
        .with_effect(EffectOutcome::reported(
            requested("write", 0x11),
            runtime_ok(0x11),
        ))
}

fn base_profile_with(f: impl FnOnce(ExecutionProfile) -> ExecutionProfile) -> ExecutionProfile {
    f(ExecutionProfile::new(base_execution(), NOW)
        .claiming_decision(DECISION_A)
        .with_airi_chain_head(commitment(0xAE))
        .with_runtime(
            RuntimeDeclaration::new()
                .declared("python3.11")
                .selected("pytorch"),
        )
        .with_effect(EffectOutcome::reported(
            requested("write", 0x11),
            runtime_ok(0x11),
        )))
}

// ═══ 9-10. Parameter and temporal substitution ═══

#[test]
fn a09_parameter_substitution() {
    // The requested effect's parameters are swapped after authorization —
    // "transfer 100" authorized, "transfer 100000" attempted.
    let p = ExecutionProfile::new(base_execution(), NOW)
        .claiming_decision(DECISION_A)
        .with_airi_chain_head(commitment(0xAE))
        .with_runtime(
            RuntimeDeclaration::new()
                .declared("python3.11")
                .selected("pytorch"),
        )
        .with_effect(EffectOutcome::reported(
            requested("write", 0x99),
            runtime_ok(0x99),
        ));
    assert_distinct(&p, "parameter commitment A → B");
}

#[test]
fn a10_temporal_substitution() {
    let p = ExecutionProfile::new(base_execution(), NOW + 86_400_000)
        .claiming_decision(DECISION_A)
        .with_airi_chain_head(commitment(0xAE))
        .with_runtime(
            RuntimeDeclaration::new()
                .declared("python3.11")
                .selected("pytorch"),
        )
        .with_effect(EffectOutcome::reported(
            requested("write", 0x11),
            runtime_ok(0x11),
        ));
    assert_distinct(&p, "assembled_at moved a day");
}

#[test]
fn a11_stale_expected_execution_is_not_this_models_to_judge() {
    // Temporal validity lives in ExpectedExecution.valid_until, DP-signed, and
    // is judged by the reconciler's temporal comparison. This model must not
    // duplicate that judgement — a second temporal check is a second place for
    // the two to disagree.
    //
    // What it *does* do is commit to which decision is claimed, so a stale
    // expectation cannot be swapped for a fresh one after the fact.
    let stale = base_profile_with(|p| p.claiming_decision(DECISION_A));
    let fresh = base_profile_with(|p| p.claiming_decision(DECISION_B));
    assert_ne!(
        stale.digest(),
        fresh.digest(),
        "the claimed decision must be committed, so staleness is a question \
         the reconciler can still ask of the right expectation"
    );
    // And this crate offers no temporal verdict of its own.
    assert!(
        !std::any::type_name::<ExecutionProfile>().contains("Verdict"),
        "structural reminder: no verdict type here"
    );
}

// ═══ 12-15. Replay, duplication, ordering, omission ═══

#[test]
fn a12_replayed_execution_into_a_different_context_changes_the_digest() {
    // A genuine profile resubmitted under a different system. Replay into the
    // *same* context is a stateful question answered by R18 REPLAY_SCOPE in
    // aip-protocol (B-8); this model's contribution is that a replay into a
    // *different* context cannot be silent.
    let mut e = base_execution();
    e.system_id = SystemId::parse("sys:fleet-2").unwrap();
    assert_distinct(&rebuild(e), "replay into another system");
}

#[test]
fn a13_duplicated_effect_is_visible() {
    // Two identical effects is a different execution from one. If effects were
    // encoded as a set, a double-spend would be invisible.
    let one = base_profile();
    let two = base_profile().with_effect(EffectOutcome::reported(
        requested("write", 0x11),
        runtime_ok(0x11),
    ));
    assert_ne!(
        one.canonical_bytes(),
        two.canonical_bytes(),
        "SECURITY: a duplicated effect encoded identically to a single one — a \
         repeated action would be invisible"
    );
    assert_eq!(one.effects.len(), 1);
    assert_eq!(two.effects.len(), 2);
}

#[test]
fn a14_reordered_effects_are_a_different_execution() {
    // Order is meaningful for effects in a way it is not for a set: two
    // executions that did the same things in a different sequence did
    // different things. "Read then write" is not "write then read".
    let ab = base_profile_with(|p| {
        p.with_effect(EffectOutcome::reported(
            requested("read", 0x22),
            runtime_ok(0x22),
        ))
    });
    let mut ba_effects = ab.effects.clone();
    ba_effects.reverse();
    let mut ba = ab.clone();
    ba.effects = ba_effects;

    assert_ne!(
        ab.canonical_bytes(),
        ba.canonical_bytes(),
        "SECURITY: reordering effects did not change the encoding"
    );
}

#[test]
fn a15_a_missing_effect_is_visible() {
    let with = base_profile();
    let mut without = base_profile();
    without.effects.clear();
    assert_ne!(
        with.canonical_bytes(),
        without.canonical_bytes(),
        "SECURITY: dropping an effect left the encoding unchanged — omission \
         would be invisible"
    );
}

// ═══ 16-19. The claim/observation boundary ═══

#[test]
fn a16_claimed_runtime_without_observation_stays_a_claim() {
    // The core non-collapse rule for the runtime ladder.
    let r = RuntimeDeclaration::new().selected("cuda:0 NVIDIA H100");
    assert_eq!(
        r.best_origin(),
        Some(EvidenceOrigin::SelfReported),
        "SECURITY: a selected runtime was treated as observed"
    );
    assert!(
        r.observed.is_none() && r.evidenced.is_none(),
        "a claim must not populate an observation slot"
    );
    assert!(
        !EvidenceOrigin::SelfReported.can_establish_occurrence(),
        "a self-report can never establish occurrence"
    );
    assert_eq!(
        r.selection_matches_observation(),
        None,
        "no comparison is possible with nothing to compare — and None is not \
         agreement"
    );
}

#[test]
fn a17_observed_runtime_without_a_matching_claim_is_a_disagreement_not_a_pass() {
    let r = RuntimeDeclaration::new()
        .selected("pytorch")
        .evidenced("onnxruntime");
    assert_eq!(
        r.selection_matches_observation(),
        Some(false),
        "SECURITY: a claim and a contradicting measurement compared equal"
    );
    // And a match is a match, so the test above is not passing vacuously.
    let agree = RuntimeDeclaration::new()
        .selected("pytorch")
        .evidenced("pytorch");
    assert_eq!(agree.selection_matches_observation(), Some(true));
}

#[test]
fn a18_tool_success_without_evidence_is_never_a_confirmed_effect() {
    // The single most important assertion in this file, and the reason the
    // effect module exists. A 200 is not an effect.
    let outcome = EffectOutcome::reported(requested("write", 0x11), runtime_ok(0x11));

    assert_eq!(
        outcome.disposition(),
        &EffectDisposition::NotEvaluated,
        "SECURITY: a 200 response produced something other than NotEvaluated"
    );
    assert!(
        !outcome.disposition().asserts_occurrence(),
        "SECURITY: a tool success asserted that an external effect occurred"
    );
    // The runtime layer reported success, and that is recorded — the point is
    // not that the report is discarded, but that it does not cross the
    // boundary.
    assert_eq!(
        outcome.runtime.as_ref().unwrap().transport_status,
        Some(200)
    );
}

#[test]
fn a18b_confirmed_is_unconstructible_without_independent_evidence() {
    // Structural, and the enforcement behind a18. There is no constructor,
    // setter or builder that reaches Confirmed from a RuntimeAction — the only
    // path takes an EffectEvidence, which needs an observer id the agent does
    // not hold.
    let evidence = EffectEvidence::new("collector-1", 2, 0, true).expect("valid reference");
    let confirmed =
        EffectOutcome::reported(requested("write", 0x11), runtime_ok(0x11)).with_evidence(evidence);
    assert!(confirmed.disposition().asserts_occurrence());

    // ...and the evidence's own finding decides, not the caller.
    let contradicting = EffectEvidence::new("collector-1", 2, 0, false).unwrap();
    let contradicted = EffectOutcome::reported(requested("write", 0x11), runtime_ok(0x11))
        .with_evidence(contradicting);
    assert!(
        matches!(
            contradicted.disposition(),
            EffectDisposition::Contradicted(_)
        ),
        "SECURITY: a caller chose the disposition rather than the evidence"
    );
    assert!(!contradicted.disposition().asserts_occurrence());
}

#[test]
fn a18c_unconfirmed_is_not_the_same_as_not_evaluated() {
    // "We looked and did not find it" and "we did not look" are different
    // states. Summing them turns a blind spot into a clean bill of health —
    // the same error CANNOT_PROVE exists to prevent.
    let not_looked = EffectOutcome::reported(requested("write", 0x11), runtime_ok(0x11));
    let looked = EffectOutcome::reported(requested("write", 0x11), runtime_ok(0x11)).unconfirmed();

    assert_eq!(not_looked.disposition(), &EffectDisposition::NotEvaluated);
    assert_eq!(looked.disposition(), &EffectDisposition::Unconfirmed);
    assert_ne!(not_looked.disposition(), looked.disposition());
    assert_ne!(
        not_looked.canonical_bytes_for_test(),
        looked.canonical_bytes_for_test(),
        "the two states must be distinguishable in the encoding too"
    );
    // Neither asserts occurrence, and neither asserts non-occurrence.
    assert!(!not_looked.disposition().asserts_occurrence());
    assert!(!looked.disposition().asserts_occurrence());
}

#[test]
fn a19_a_model_claim_without_runtime_evidence_establishes_nothing() {
    // model requested ≠ model served ≠ weights loaded ≠ accelerator executed.
    // The AIRI chain head commits to what was claimed; it does not promote it.
    let p = base_profile_with(|p| p.with_airi_chain_head(commitment(0xAE)));
    assert!(p.airi_chain_head.is_some());
    assert_eq!(
        ExecutionStage::ModelInvocation.origin(),
        EvidenceOrigin::SelfReported,
        "SECURITY: the model-invocation stage was classified as observation"
    );
    assert!(
        !ExecutionStage::ModelInvocation.may_establish(ExecutionStage::IndependentObservation),
        "SECURITY: a model claim was allowed to establish an independent \
         observation"
    );
    assert!(
        !ExecutionStage::RuntimeExecution.may_establish(ExecutionStage::ExternalEffect),
        "SECURITY: a runtime report was allowed to establish an external effect"
    );
}

// ═══ 20-22. Malformed, versioned, colliding ═══

#[test]
fn a20_malformed_execution_structure_fails_closed() {
    // An anonymous observation is not an observation, and a reference nothing
    // can resolve is worse than none.
    assert!(EffectEvidence::new("", 1, 0, true).is_err());
    assert!(EffectEvidence::new(&"x".repeat(129), 1, 0, true).is_err());
    // The boundary is exact, not approximate.
    assert!(EffectEvidence::new(&"x".repeat(128), 1, 0, true).is_ok());
}

#[test]
fn a21_unsupported_version_is_refused_not_guessed() {
    let mut p = base_profile();
    p.check_version().expect("current version accepted");
    for found in [0u16, 2, 99, u16::MAX] {
        p.version = found;
        assert_eq!(
            p.check_version(),
            Err(ExecutionError::UnsupportedVersion {
                found,
                supported: EXECUTION_PROFILE_VERSION
            }),
            "SECURITY: version {found} was read as though its fields were understood"
        );
    }
    // And the embedded record's version is checked too: a profile is only as
    // well formed as what it contains.
    let mut p = base_profile();
    p.system_execution.version = 7;
    assert!(
        p.check_version().is_err(),
        "SECURITY: a profile accepted an embedded record of unknown version"
    );
}

#[test]
fn a22_canonicalization_does_not_collide_across_the_matrix() {
    // Every distinct security context in this file, encoded, must be distinct
    // from every other. Pairwise inequality is not enough on its own: two
    // different attacks landing on the same encoding would be a collision even
    // if each differed from the baseline.
    let mut all: Vec<Vec<u8>> = vec![
        base_profile().canonical_bytes(),
        base_profile_with(|p| p.claiming_decision(DECISION_B)).canonical_bytes(),
        base_profile_with(|p| p.with_airi_chain_head(commitment(0xBE))).canonical_bytes(),
        base_profile_with(|p| {
            p.with_runtime(
                RuntimeDeclaration::new()
                    .declared("python3.11")
                    .selected("jax"),
            )
        })
        .canonical_bytes(),
    ];
    for e in [
        {
            let mut x = base_execution();
            x.execution_id = EXEC_B;
            x
        },
        {
            let mut x = base_execution();
            x.hardware_id = Some(HardwareId::parse("tpm-ek:bbb").unwrap());
            x
        },
        {
            let mut x = base_execution();
            x.mission_id = Some(MissionId::parse("op:sortie-99").unwrap());
            x
        },
        {
            let mut x = base_execution();
            x.system_id = SystemId::parse("sys:fleet-2").unwrap();
            x
        },
    ] {
        all.push(rebuild(e).canonical_bytes());
    }

    let n = all.len();
    all.sort();
    all.dedup();
    assert_eq!(
        n,
        all.len(),
        "SECURITY: two distinct contexts encoded identically"
    );
}

#[test]
fn a22b_the_runtime_slots_cannot_shift_into_one_another() {
    // The injectivity attack aimed at the ladder itself: if the four runtime
    // slots were encoded without presence bytes, a self-report in `selected`
    // would encode identically to a measurement in `evidenced` — promoting a
    // claim to evidence for free.
    let selected = base_profile_with(|p| p.with_runtime(RuntimeDeclaration::new().selected("x")));
    let observed = base_profile_with(|p| p.with_runtime(RuntimeDeclaration::new().observed("x")));
    let evidenced = base_profile_with(|p| p.with_runtime(RuntimeDeclaration::new().evidenced("x")));
    let declared = base_profile_with(|p| p.with_runtime(RuntimeDeclaration::new().declared("x")));

    let mut all = vec![
        selected.canonical_bytes(),
        observed.canonical_bytes(),
        evidenced.canonical_bytes(),
        declared.canonical_bytes(),
    ];
    let n = all.len();
    all.sort();
    all.dedup();
    assert_eq!(
        n,
        all.len(),
        "SECURITY: the same value in two different runtime slots encoded \
         identically — a claim could be presented as a measurement"
    );
}

// ═══ 23-25. Forgery, transplantation, serialization ═══

#[test]
fn a23_a_forged_binding_changes_the_committed_digest() {
    // A self-collected ExecutionBinding describing a different process
    // instance. The binding is inside the embedded SystemExecution encoding,
    // so the profile digest — the value the decision point signs — changes.
    let binding = |pid: u32| ExecutionBinding {
        version: EXECUTION_BINDING_VERSION,
        agent_id: agent("alpha"),
        process: ProcessInstance {
            pid,
            pid_start_time_ticks: 777_000,
            boot_id: [0x3d; 16],
        },
        exe_content_sha256: [0x11; 32],
        exe_path: "/opt/agent/bin/autonomy".into(),
        bound_at_ms: NOW,
    };
    let real = rebuild(base_execution().bound_to(binding(4321)));
    let forged = rebuild(base_execution().bound_to(binding(9999)));
    assert_ne!(
        real.digest(),
        forged.digest(),
        "SECURITY: a forged process binding produced the same committed digest"
    );
}

#[test]
fn a24_identity_transplantation_across_every_slot() {
    // The full sweep, asserted together so a future edit that merges two slots
    // fails here rather than in review.
    let variants: Vec<(&str, ExecutionProfile)> = vec![
        ("agent", {
            let e = SystemExecution::new(
                SystemId::parse("sys:fleet-1").unwrap(),
                &agent("bravo"),
                EXEC_A,
                NOW,
            )
            .unwrap()
            .on_platform(PlatformId::parse("tail:N123AB").unwrap())
            .on_hardware(HardwareId::parse("tpm-ek:aaa").unwrap())
            .for_mission(MissionId::parse("op:sortie-77").unwrap());
            rebuild(e)
        }),
        ("execution", {
            let mut e = base_execution();
            e.execution_id = EXEC_B;
            rebuild(e)
        }),
        ("platform", {
            let mut e = base_execution();
            e.platform_id = Some(PlatformId::parse("tail:N456CD").unwrap());
            rebuild(e)
        }),
        ("hardware", {
            let mut e = base_execution();
            e.hardware_id = Some(HardwareId::parse("tpm-ek:bbb").unwrap());
            rebuild(e)
        }),
        ("mission", {
            let mut e = base_execution();
            e.mission_id = Some(MissionId::parse("op:sortie-99").unwrap());
            rebuild(e)
        }),
        ("system", {
            let mut e = base_execution();
            e.system_id = SystemId::parse("sys:fleet-2").unwrap();
            rebuild(e)
        }),
        (
            "decision",
            base_profile_with(|p| p.claiming_decision(DECISION_B)),
        ),
    ];
    for (slot, p) in &variants {
        assert_distinct(p, &format!("transplant of {slot}"));
    }
}

#[test]
fn a25_serialization_round_trip_does_not_permit_substitution() {
    // Two attacks in one: the round trip must be faithful (or a signature
    // stops verifying after transport, which is a denial of service), and it
    // must not be a path to constructing something the constructors refuse.
    let original = base_profile();
    let json = serde_json::to_string(&original).expect("serialise");
    let parsed: ExecutionProfile = serde_json::from_str(&json).expect("deserialise");

    assert_eq!(parsed, original);
    assert_eq!(
        parsed.canonical_bytes(),
        original.canonical_bytes(),
        "a round trip must not change the committed encoding"
    );
    parsed.check_version().expect("version accepted");

    // The disposition survives transport as itself — a NotEvaluated must not
    // parse back as anything stronger.
    assert_eq!(
        parsed.disposition_of_first(),
        &EffectDisposition::NotEvaluated
    );

    // And a hand-written JSON claiming Confirmed still needs the evidence
    // structure; there is no shorthand that conjures one.
    let forged = json.replace("\"NotEvaluated\"", "\"Confirmed\"");
    assert!(
        serde_json::from_str::<ExecutionProfile>(&forged).is_err(),
        "SECURITY: Confirmed was constructible through serde without evidence"
    );
}

/// Small helpers used by the tests above, kept out of the crate's public API.
trait TestAccess {
    fn canonical_bytes_for_test(&self) -> Vec<u8>;
}
impl TestAccess for EffectOutcome {
    fn canonical_bytes_for_test(&self) -> Vec<u8> {
        ExecutionProfile::new(base_execution(), NOW)
            .with_effect(self.clone())
            .canonical_bytes()
    }
}

trait FirstDisposition {
    fn disposition_of_first(&self) -> &EffectDisposition;
}
impl FirstDisposition for ExecutionProfile {
    fn disposition_of_first(&self) -> &EffectDisposition {
        self.effects[0].disposition()
    }
}

#[test]
fn a25b_effect_evidence_deserialization_applies_the_same_validation() {
    // The bypass this test exists for was real and was found by probing rather
    // than assumed absent: serde's derived Deserialize constructed
    // EffectEvidence field by field, so a JSON writer obtained a value the
    // constructor refuses. `#[serde(try_from)]` closes it.
    // The over-long case is built in code rather than hand-written: an
    // earlier draft of this test hand-counted the x's, got 127, and passed
    // vacuously. A boundary test that miscounts its own boundary is worse
    // than none.
    let too_long = "x".repeat(129);
    let over = format!(
        r#"{{"observer_id":"{too_long}","batch_sequence":1,"observation_index":0,"corroborates":true}}"#
    );
    for bad in [
        r#"{"observer_id":"","batch_sequence":1,"observation_index":0,"corroborates":true}"#
            .to_owned(),
        over,
    ] {
        assert!(
            serde_json::from_str::<EffectEvidence>(&bad).is_err(),
            "SECURITY: an EffectEvidence the constructor refuses was built through serde: {bad}"
        );
    }
    // The boundary is exact: 128 is accepted, so the guard is a bound rather
    // than a blanket refusal.
    let at_limit = "x".repeat(128);
    assert!(serde_json::from_str::<EffectEvidence>(&format!(
        r#"{{"observer_id":"{at_limit}","batch_sequence":1,"observation_index":0,"corroborates":true}}"#
    ))
    .is_ok());

    // A well-formed one still parses, so the guard is not simply refusing
    // everything.
    let good = r#"{"observer_id":"collector-1","batch_sequence":2,"observation_index":0,"corroborates":true}"#;
    let parsed: EffectEvidence = serde_json::from_str(good).expect("valid evidence parses");
    assert_eq!(parsed.observer_id(), "collector-1");
}
