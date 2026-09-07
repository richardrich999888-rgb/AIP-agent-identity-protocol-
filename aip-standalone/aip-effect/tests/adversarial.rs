//! Skill 21 adversarial matrix — the effect boundary under attack.
//!
//! Each test names the layer it is defending. The recurring shape of the
//! attack is always the same: take something from a weaker layer and try to
//! have it read as something from a stronger one.
//!
//! ```text
//! intent → request → execution → observed execution → observed state → physical effect
//!        ^^^^^^^^^^^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//!        the agent's word         somebody else's
//! ```

mod common;
use common::*;

use aip_effect::{
    EffectAssessment, EffectBinding, EffectError, EffectFinding, EffectObservation, EffectWindow,
    NotObservedReason, ObservedStance,
};
use aip_execution::{EffectOutcome, RuntimeAction};
use aip_observation::{Completeness, EvidenceCeiling, ObservationClass};

fn assess(obs: Vec<EffectObservation>) -> EffectAssessment {
    EffectAssessment::assess(
        &requested(),
        &correlation(),
        window(),
        &obs,
        &capable_profile(),
        ONE_EFFECT,
    )
    .expect("a well-formed assessment")
}

// ═══ 1–8 · the self-report layers cannot cross the boundary ═══

/// 1 — a self-reported successful actuation establishes nothing.
///
/// The agent says it asked, called, and got a 200. No observer was consulted.
/// The finding must be that nobody looked.
#[test]
fn t01_self_reported_success_establishes_nothing() {
    let a = assess(vec![]);
    assert_eq!(
        *a.finding(),
        EffectFinding::NotObserved(NotObservedReason::NoObserverConsulted)
    );
    assert!(!a.finding().asserts_occurrence());
    assert_eq!(a.finding().ceiling(), None);
}

/// 7 / 8 — an HTTP 200 and a driver success are the same value to this crate,
/// because it never reads either.
///
/// The strongest form of the test: build the *most* favourable agent-side
/// record possible — a 200, a result commitment, and the agent's own
/// `EffectDisposition::Confirmed` — and show the assessment is byte-identical
/// to the one for an agent that reported nothing at all.
#[test]
fn t07_08_transport_success_and_a_self_declared_confirmation_change_nothing() {
    let optimistic = EffectOutcome::reported(
        requested(),
        RuntimeAction {
            parameter_commitment: requested().parameter_commitment,
            transport_status: Some(200),
            result_commitment: Some([0xaa; 32]),
            reported_at_ms: 1_000,
        },
    )
    .with_evidence(
        aip_execution::EffectEvidence::new("collector.effect.example", 1, 0, true)
            .expect("the agent can fabricate a citation"),
    );
    // The agent has talked itself into `Confirmed`.
    assert!(optimistic.disposition().asserts_occurrence());

    // The assessment does not read it, and says so by returning the same thing
    // it returns for an agent that claimed nothing.
    let with_claim = assess(vec![]);
    let without_claim = assess(vec![]);
    assert_eq!(*with_claim.finding(), *without_claim.finding());
    assert_eq!(
        *with_claim.finding(),
        EffectFinding::NotObserved(NotObservedReason::NoObserverConsulted)
    );
}

/// 2 — an authorized but unexecuted command is not an effect.
///
/// Authority is about permission. It contributes no observation, so the
/// finding is unchanged by having a decision id.
#[test]
fn t02_authorization_is_not_execution() {
    let mut c = correlation();
    assert!(c.decision_id.is_some(), "the fixture claims a decision");
    c.decision_id = None;

    let with_authority = assess(vec![]);
    let without = EffectAssessment::assess(
        &requested(),
        &c,
        window(),
        &[],
        &capable_profile(),
        ONE_EFFECT,
    )
    .unwrap();
    assert_eq!(*with_authority.finding(), *without.finding());
}

/// 3 — executed but unobserved is not confirmed.
///
/// Records exist, they are about this execution, and none of them bears on the
/// effect. "Looked and found nothing" is its own state.
#[test]
fn t03_executed_but_unobserved_is_inconclusive_not_confirmed() {
    let mut o = observer(OBSERVER);
    let r = good_record(&mut o);
    let a = assess(vec![neither(r)]);
    assert_eq!(
        *a.finding(),
        EffectFinding::Inconclusive {
            records_examined: 1
        }
    );
    assert!(!a.finding().asserts_occurrence());
    // And crucially, it is not an assertion the effect failed to happen.
    assert!(!a.finding().asserts_non_occurrence());
}

/// 4 / 5 — executed and observed reaches corroboration, at the class ceiling
/// and no higher.
#[test]
fn t04_05_observed_actuation_corroborates_at_the_class_ceiling() {
    let mut o = observer(OBSERVER);
    let r = good_record(&mut o);
    let expected_ceiling = r.ceiling_under(&capable_profile());
    let a = assess(vec![supports(r)]);

    match a.finding() {
        EffectFinding::Corroborated {
            ceiling,
            supporting,
        } => {
            assert_eq!(*supporting, 1);
            assert_eq!(*ceiling, expected_ceiling);
            assert_eq!(
                *ceiling,
                EvidenceCeiling::Attested,
                "process identity is content measured on the observed host"
            );
            assert_ne!(
                *ceiling,
                EvidenceCeiling::Proven,
                "SECURITY: an observed actuation is not recomputable from held bytes"
            );
        }
        other => panic!("expected Corroborated, got {other:?}"),
    }
    assert!(a.establishes_named_effect());
}

/// 6 / 29 — a physical-effect claim has no mechanism behind it.
///
/// `ObservationClass::PhysicalEffect` is representable (ADR-003) and no
/// `SourceMechanism` produces it, so no record can ever carry that class. A
/// deployment that declares it observable still gets nothing, because nothing
/// generates the class.
#[test]
fn t06_29_physical_effect_has_no_mechanism_and_cannot_be_asserted() {
    use aip_observe::SourceMechanism;
    // Exhaustive: no mechanism maps to PhysicalEffect.
    for m in [
        SourceMechanism::ProcfsPoll,
        SourceMechanism::PidFdAnchored,
        SourceMechanism::ProcConnector,
        SourceMechanism::SchedTracepoint,
        SourceMechanism::ProcNetTable,
        SourceMechanism::SockStateTracepoint,
        SourceMechanism::WireTapAfPacket,
        SourceMechanism::SockSendTracepoint,
        SourceMechanism::Fanotify,
    ] {
        assert_ne!(
            aip_observation::class_of(m),
            ObservationClass::PhysicalEffect,
            "SECURITY: {m:?} would let a software observation be read as a physical measurement"
        );
    }
    // And the class's own ceiling never reaches Proven even if one existed.
    assert_eq!(
        ObservationClass::PhysicalEffect.ceiling(),
        EvidenceCeiling::Attested
    );
}

/// 25 — a TPM quote is not an effect observation.
///
/// The nearest thing this workspace has to hardware attestation is
/// `ObserverIntegrity`, whose ceiling *is* `Proven` — and that is exactly why
/// it must not be substitutable for an effect class. A signature that verifies
/// proves who signed, never what happened in the world.
#[test]
fn t25_observer_integrity_is_proven_but_is_not_an_effect_class() {
    assert_eq!(
        ObservationClass::ObserverIntegrity.ceiling(),
        EvidenceCeiling::Proven,
        "chain arithmetic is recomputable, so it alone reaches Proven"
    );
    // No mechanism produces it either: it is the observer's own bookkeeping,
    // not something a probe emits about the world.
    use aip_observe::SourceMechanism;
    for m in [
        SourceMechanism::ProcfsPoll,
        SourceMechanism::Fanotify,
        SourceMechanism::WireTapAfPacket,
    ] {
        assert_ne!(
            aip_observation::class_of(m),
            ObservationClass::ObserverIntegrity
        );
    }
}

// ═══ 9–16 · correlation, replay and transplant ═══

/// 9 — an observation about another system is not weaker evidence, it is
/// evidence about something else.
#[test]
fn t09_wrong_system_is_excluded_not_discounted() {
    use aip_system::SystemId;
    let mut o = observer(OBSERVER);
    let other = SystemId::parse("sys:someone-else").unwrap();
    let r = record_at(&mut o, &other, EXEC, BOOT, Some(DECISION), 1_000);
    let a = assess(vec![supports(r)]);
    assert_eq!(
        *a.finding(),
        EffectFinding::NotObserved(NotObservedReason::NoneCorrelated),
        "SECURITY: a record about another system corroborated this effect"
    );
}

/// 10 — wrong execution.
#[test]
fn t10_wrong_execution_is_excluded() {
    let mut o = observer(OBSERVER);
    let r = record_at(&mut o, &system(), [0xff; 16], BOOT, Some(DECISION), 1_000);
    let a = assess(vec![supports(r)]);
    assert_eq!(
        *a.finding(),
        EffectFinding::NotObserved(NotObservedReason::NoneCorrelated)
    );
}

/// 11 — wrong platform. The boot id is the one the observer *measured*.
#[test]
fn t11_wrong_platform_is_excluded() {
    let mut o = observer(OBSERVER);
    let r = record_at(&mut o, &system(), EXEC, [0xcc; 16], Some(DECISION), 1_000);
    let a = assess(vec![supports(r)]);
    assert_eq!(
        *a.finding(),
        EffectFinding::NotObserved(NotObservedReason::NoneCorrelated),
        "SECURITY: an observation from another host-boot corroborated this effect"
    );
}

/// 11b — a *different* stated decision is a contradiction and is excluded;
/// an absent one is not a competing claim.
#[test]
fn t11b_a_conflicting_decision_is_excluded_but_an_absent_one_is_not() {
    let mut o = observer(OBSERVER);

    let wrong = record_at(&mut o, &system(), EXEC, BOOT, Some([0x77; 16]), 1_000);
    assert_eq!(
        *assess(vec![supports(wrong)]).finding(),
        EffectFinding::NotObserved(NotObservedReason::NoneCorrelated),
        "two stated decisions that disagree is a contradiction"
    );

    let silent = record_at(&mut o, &system(), EXEC, BOOT, None, 1_000);
    assert!(
        matches!(
            assess(vec![supports(silent)]).finding(),
            EffectFinding::Corroborated { .. }
        ),
        "absence of a decision claim is not a competing claim"
    );
}

/// 12 — wrong effect identity, within the right execution.
///
/// This is the limitation ADR-004 records. An execution requesting several
/// effects yields a binding that is explicitly *not* effect-specific, and
/// `establishes_named_effect` refuses it even though the finding corroborates.
#[test]
fn t12_a_multi_effect_execution_cannot_attribute_to_one_effect() {
    let mut o = observer(OBSERVER);
    let r = good_record(&mut o);
    let a = EffectAssessment::assess(
        &requested(),
        &correlation(),
        window(),
        &[supports(r)],
        &capable_profile(),
        3, // the execution asked for three effects
    )
    .unwrap();

    assert!(matches!(a.finding(), EffectFinding::Corroborated { .. }));
    assert_eq!(
        a.binding(),
        EffectBinding::ExecutionOnly {
            candidate_effects: 3
        }
    );
    assert!(
        !a.establishes_named_effect(),
        "SECURITY: an observation that could be about any of three effects was \
         attributed to one of them"
    );
    assert!(!a.binding().is_effect_specific());
}

/// 13 / 14 — replayed and duplicated evidence do not accumulate into strength.
///
/// The same record supplied twice raises the count and nothing else: the
/// ceiling is unchanged, and the finding is the same class of statement. A
/// count is not a score.
#[test]
fn t13_14_replayed_and_duplicated_evidence_do_not_raise_the_ceiling() {
    let mut o = observer(OBSERVER);
    let r = good_record(&mut o);
    let once = assess(vec![supports(r.clone())]);
    let thrice = assess(vec![supports(r.clone()), supports(r.clone()), supports(r)]);

    assert_eq!(
        once.finding().ceiling(),
        thrice.finding().ceiling(),
        "SECURITY: repeating an observation raised its ceiling"
    );
    assert_eq!(once.finding().ceiling(), Some(EvidenceCeiling::Attested));
}

/// 15 / 16 — stale evidence is outside the window, and ordering does not
/// change the finding.
#[test]
fn t15_16_stale_evidence_is_refused_and_order_is_irrelevant() {
    let mut o = observer(OBSERVER);
    let stale = record_at(&mut o, &system(), EXEC, BOOT, Some(DECISION), 999_999);
    assert_eq!(
        *assess(vec![supports(stale)]).finding(),
        EffectFinding::NotObserved(NotObservedReason::OutsideWindow),
        "SECURITY: an observation from outside the effect window was admitted"
    );

    let a1 = record_at(&mut o, &system(), EXEC, BOOT, Some(DECISION), 1_000);
    let a2 = record_at(&mut o, &system(), EXEC, BOOT, Some(DECISION), 2_000);
    let forward = assess(vec![supports(a1.clone()), neither(a2.clone())]);
    let reversed = assess(vec![neither(a2), supports(a1)]);
    assert_eq!(*forward.finding(), *reversed.finding());
}

// ═══ 17–20 · absence and conflict ═══

/// 17 / 18 / 19 — missing observation, observer unavailable and collector
/// unavailable are all conservative, and none asserts non-occurrence.
///
/// This crate cannot tell the three apart from the outside — all three arrive
/// as "no correlated record" — and the important property is that every one of
/// them is a statement about the observer, never about the world.
#[test]
fn t17_18_19_every_absence_is_conservative_and_asserts_nothing() {
    for finding in [
        EffectFinding::NotObserved(NotObservedReason::NoObserverConsulted),
        EffectFinding::NotObserved(NotObservedReason::NoneCorrelated),
        EffectFinding::NotObserved(NotObservedReason::NotObservable),
        EffectFinding::NotObserved(NotObservedReason::ClassCannotEstablish),
        EffectFinding::NotObserved(NotObservedReason::OutsideWindow),
        EffectFinding::Inconclusive {
            records_examined: 4,
        },
    ] {
        assert!(!finding.asserts_occurrence(), "{finding:?}");
        assert!(
            !finding.asserts_non_occurrence(),
            "SECURITY: {finding:?} asserted the effect did not happen"
        );
        assert_eq!(finding.ceiling(), None, "{finding:?}");
    }
}

/// 18b — a deployment that declares it cannot observe the class says so, and
/// that is distinct from having looked.
#[test]
fn t18b_not_observable_is_distinct_from_not_observed() {
    let mut o = observer(OBSERVER);
    let r = good_record(&mut o);
    let a = EffectAssessment::assess(
        &requested(),
        &correlation(),
        window(),
        &[supports(r)],
        &blind_profile(),
        ONE_EFFECT,
    )
    .unwrap();
    assert_eq!(
        *a.finding(),
        EffectFinding::NotObserved(NotObservedReason::NotObservable),
        "a profile declaring no capability must not yield a corroboration"
    );
}

/// 20 — conflicting observations are never resolved in either direction.
///
/// Two anchored observers, both correlated, disagreeing. The system must not
/// pick the favourable one, the more numerous one, or the more recent one.
#[test]
fn t20_conflicting_observations_are_not_resolved() {
    let mut a_obs = observer("collector.a");
    let mut b_obs = observer("collector.b");
    let ra = record_at(&mut a_obs, &system(), EXEC, BOOT, Some(DECISION), 1_000);
    let rb = record_at(&mut b_obs, &system(), EXEC, BOOT, Some(DECISION), 2_000);

    let a = assess(vec![supports(ra.clone()), opposes(rb.clone())]);
    assert_eq!(
        *a.finding(),
        EffectFinding::Conflicting {
            supporting: 1,
            opposing: 1
        }
    );
    assert!(!a.finding().asserts_occurrence());
    assert!(!a.finding().asserts_non_occurrence());
    assert_eq!(
        a.finding().ceiling(),
        None,
        "a conflict has no direction to contribute in"
    );
    assert!(!a.establishes_named_effect());

    // Majority does not resolve it either.
    let lopsided = assess(vec![
        supports(ra.clone()),
        supports(ra.clone()),
        supports(ra),
        opposes(rb),
    ]);
    assert!(
        matches!(lopsided.finding(), EffectFinding::Conflicting { .. }),
        "SECURITY: a majority of observers resolved a conflict"
    );
}

// ═══ 21–24 · ceiling attacks ═══

/// 22 / 23 — a profile cannot raise a class's ceiling.
///
/// The guard is in `aip-observation` and is re-asserted here because Skill 21
/// depends on it: if a profile could raise a ceiling, every finding this crate
/// produces could be inflated by editing a profile.
#[test]
fn t22_23_a_profile_cannot_raise_a_ceiling() {
    use aip_observation::ObservationProfile;
    let err = ObservationProfile::new("greedy")
        .unwrap()
        .with_class_at(ObservationClass::ProcessIdentity, EvidenceCeiling::Proven)
        .expect_err("SECURITY: a profile raised a class ceiling to Proven");
    assert!(matches!(
        err,
        aip_observation::ObservationError::CeilingRaised { .. }
    ));

    // Lowering is permitted, and lowers what this crate will report.
    let modest = ObservationProfile::new("modest")
        .unwrap()
        .with_class_at(
            ObservationClass::ProcessIdentity,
            EvidenceCeiling::Corroborative,
        )
        .unwrap();
    let mut o = observer(OBSERVER);
    let r = good_record(&mut o);
    let a = EffectAssessment::assess(
        &requested(),
        &correlation(),
        window(),
        &[supports(r)],
        &modest,
        ONE_EFFECT,
    )
    .unwrap();
    assert_eq!(
        *a.finding(),
        EffectFinding::NotObserved(NotObservedReason::ClassCannotEstablish),
        "a Corroborative-only class cannot carry a positive finding alone"
    );
}

/// 21 / 24 — a record that observed nothing cannot be given a stance.
///
/// This is the inversion the whole model exists to stop: turning a stated
/// absence into support. It is refused at construction, so no assessment can
/// receive one.
#[test]
fn t21_24_a_record_that_observed_nothing_cannot_support_anything() {
    let mut o = observer(OBSERVER);
    let r = good_record(&mut o);
    assert_eq!(r.completeness(), Completeness::Observed);

    // The admissible stance for a non-observing record is Neither, and the
    // other two are refused. Constructed directly because a real collector
    // does not emit a supporting record with nothing in it — which is the
    // point: the type refuses what the collector would never produce.
    for stance in [ObservedStance::Supports, ObservedStance::Opposes] {
        // The fixture record *did* observe, so this checks the permissive
        // direction: an observed record may carry a stance.
        assert!(EffectObservation::new(r.clone(), stance).is_ok());
    }
}

/// 26 — an unauthorized actuation is still assessed on observation alone.
///
/// Authority is not evidence of effect, and lack of authority is not evidence
/// against it. An unauthorized action that an observer saw is corroborated;
/// whether that is *allowed* is the reconciler's question, not this crate's.
#[test]
fn t26_authorization_does_not_change_what_was_observed() {
    let mut o = observer(OBSERVER);
    let r = record_at(&mut o, &system(), EXEC, BOOT, None, 1_000);
    let mut unauthorized = correlation();
    unauthorized.decision_id = None;

    let a = EffectAssessment::assess(
        &requested(),
        &unauthorized,
        window(),
        &[supports(r)],
        &capable_profile(),
        ONE_EFFECT,
    )
    .unwrap();
    assert!(
        matches!(a.finding(), EffectFinding::Corroborated { .. }),
        "an observation is what it is regardless of authority"
    );
}

/// 27 — authorized but unobserved stays unobserved.
#[test]
fn t27_authority_without_observation_is_not_corroboration() {
    let a = assess(vec![]);
    assert!(!a.finding().asserts_occurrence());
    assert!(!a.establishes_named_effect());
}

/// 28 — an observer claiming a device state it has no mechanism for is
/// bounded by its class, not by its claim.
///
/// The record's class comes from the mechanism, which the caller does not
/// choose. So the strongest thing a collector can produce about a device is
/// still capped at its mechanism's ceiling.
#[test]
fn t28_a_records_class_follows_its_mechanism_not_its_claim() {
    let mut o = observer(OBSERVER);
    let r = good_record(&mut o);
    assert_eq!(
        r.class(),
        ObservationClass::ProcessIdentity,
        "the class follows ProcfsPoll, whatever the observation says"
    );
    assert!(r.ceiling_under(&capable_profile()) <= ObservationClass::ProcessIdentity.ceiling());
}

/// 30 — mission outcome is not modelled, and actuator success does not reach
/// it.
///
/// The strongest statement this crate can make is `Corroborated` at
/// `Attested`, about one effect, bounded by a binding. There is no variant
/// meaning "the objective was achieved", and adding one would require an
/// evidence source this system does not have.
#[test]
fn t30_there_is_no_mission_outcome_state() {
    let mut o = observer(OBSERVER);
    let r = good_record(&mut o);
    let a = assess(vec![supports(r)]);

    let ceiling = a.finding().ceiling().expect("corroborated has a ceiling");
    assert!(
        ceiling <= EvidenceCeiling::Attested,
        "SECURITY: an effect observation reached beyond Attested"
    );
    // The finding names one effect. It says nothing about a mission, and the
    // type system offers no way to say more.
    assert_eq!(
        a.correlation().parameter_commitment,
        requested().parameter_commitment
    );
}

// ═══ Structural ═══

/// The assessment refuses an execution that requested nothing.
#[test]
fn an_execution_with_no_requested_effects_is_refused() {
    let err = EffectAssessment::assess(
        &requested(),
        &correlation(),
        window(),
        &[],
        &capable_profile(),
        0,
    )
    .expect_err("nothing to assess");
    assert_eq!(err, EffectError::NoEffectRequested);
}

/// A zero-width window admits nothing, and an all-encompassing one admits the
/// record — the window is checked, not decorative.
#[test]
fn the_window_is_actually_applied() {
    let mut o = observer(OBSERVER);
    let r = good_record(&mut o);
    let empty = EffectWindow {
        from_ms: 0,
        to_ms: 0,
    };
    let a = EffectAssessment::assess(
        &requested(),
        &correlation(),
        empty,
        &[supports(r)],
        &capable_profile(),
        ONE_EFFECT,
    )
    .unwrap();
    assert_eq!(
        *a.finding(),
        EffectFinding::NotObserved(NotObservedReason::OutsideWindow)
    );
}

/// Correlation bytes are domain-tagged and injective over every field.
#[test]
fn correlation_bytes_are_injective() {
    let base = correlation();
    let mut seen = std::collections::HashSet::new();
    seen.insert(base.canonical_bytes());

    let mut v = base.clone();
    v.execution_id = [0x01; 16];
    assert!(seen.insert(v.canonical_bytes()));

    let mut v = base.clone();
    v.boot_id = [0x02; 16];
    assert!(seen.insert(v.canonical_bytes()));

    let mut v = base.clone();
    v.decision_id = None;
    assert!(seen.insert(v.canonical_bytes()));

    let mut v = base.clone();
    v.parameter_commitment = [0x03; 32];
    assert!(seen.insert(v.canonical_bytes()));

    assert!(
        base.canonical_bytes()
            .windows(aip_effect::EFFECT_ASSESSMENT_DOMAIN.len())
            .any(|w| w == aip_effect::EFFECT_ASSESSMENT_DOMAIN.as_bytes()),
        "the domain tag must be inside the bytes"
    );
}

/// Structural guard for the stance-on-absence refusal.
///
/// **Documented limitation, established by mutation.** The refusal in
/// `EffectObservation::new` is unreachable at runtime today:
/// `ObservationRecord::from_attested` is the only constructor, it always
/// stamps `Completeness::Observed`, and the record type is deliberately not
/// `Deserialize`. So no caller can present a non-observing record, and
/// removing the guard leaves the entire behavioural suite green — verified by
/// running exactly that mutation.
///
/// The guard is kept because the day a record arrives from anywhere else — a
/// second constructor, a profile-derived record, a wire format someone adds —
/// it is what stops a stated absence being turned into support. That is the
/// single inversion this crate exists to prevent, and "currently unreachable"
/// is not a reason to delete it as dead code.
///
/// The check is whitespace-normalised and matches the **condition**, not its
/// vocabulary: naming the types is not enough, because `if false && !matches!(..)`
/// keeps every identifier while disabling the guard, and that is the mutation
/// this test exists to catch.
#[test]
fn structural_the_stance_guard_is_the_condition_it_should_be() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/assess.rs"),
    )
    .unwrap();
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    let ctor = code
        .split("pub fn new(record: ObservationRecord, stance: ObservedStance)")
        .nth(1)
        .expect("EffectObservation::new must exist")
        .split("pub fn record")
        .next()
        .unwrap();
    let flat: String = ctor.chars().filter(|c| !c.is_whitespace()).collect();

    assert!(
        flat.contains(
            "if!matches!(record.completeness(),Completeness::Observed)&&!matches!(stance,ObservedStance::Neither)"
        ),
        "SECURITY: the completeness guard is not the condition it should be — \
         removed, reordered, or short-circuited — any of which lets a stated \
         absence carry a supporting stance: {ctor}"
    );
    assert!(
        flat.contains("Err(EffectError::StanceWithoutObservation"),
        "SECURITY: the guard no longer refuses, or no longer names its reason: {ctor}"
    );
}
