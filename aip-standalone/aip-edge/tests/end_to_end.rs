//! Phase 10 across the **real** reference path.
//!
//! Every test in this file spawns the real workload and the real observer as
//! separate operating-system processes, performs (or withholds) a real TCP
//! connection, and reads batches an independently keyed collector actually
//! signed. No `AttestedBatch`, `ObservedExecution` or `ObservationRecord` is
//! constructed by hand anywhere below.
//!
//! The expectation is a fixture, because a decision is a fixture: someone
//! decided it. The observation never is.

mod common;

use aip_edge::orchestrate::Scenario;
use aip_effect::{EffectFinding, NotObservedReason};
use aip_observation::Completeness;
use aip_platform::PlatformDisposition;

use common::run_scenario;

// ─── 1-2. Self-report versus independent observation ───

#[test]
fn t1_a_signed_success_self_report_establishes_nothing() {
    // The workload emits exactly the AIRI events it emits on the honest path —
    // correctly signed, correctly chained, claiming `ReportedOutcome::Success`
    // — and opens no connection. Everything else about the run is identical.
    let o = run_scenario("t1", Scenario::SelfReportOnly);
    let r = &o.reference;

    assert!(
        !r.establishes_named_effect,
        "a self-report reached the effect boundary: {:?}",
        r.finding
    );
    assert!(
        matches!(r.finding, EffectFinding::Inconclusive { .. }),
        "an observer looked with adequate coverage and found nothing bearing on the effect, \
         which is Inconclusive and not NotObserved: {:?}",
        r.finding
    );
    assert_eq!(
        r.reconciliation.result.as_str(),
        "CANNOT_PROVE",
        "the existing engine must not verify an execution nobody observed"
    );
    // And the honest run, for contrast, must reach the opposite.
    let honest = run_scenario("t1-honest", Scenario::Honest);
    assert!(
        honest.reference.establishes_named_effect,
        "the honest path must establish the effect, or this test proves only that \
         everything fails"
    );
    assert_eq!(
        honest.reference.reconciliation.result.as_str(),
        "VERIFIED_EXECUTION"
    );
}

#[test]
fn t2_observation_that_disagrees_with_the_self_report_is_visible() {
    // The self-report says Success. The observer, with real coverage of the
    // instance, records the instance present and no socket to the endpoint.
    // The reference must show the disagreement rather than average it.
    let o = run_scenario("t2", Scenario::SelfReportOnly);
    assert!(
        o.reference.observations_offered > 0,
        "the observer must have looked, or this is a coverage test rather than a \
         disagreement test"
    );
    assert!(!o.reference.establishes_named_effect);
    assert!(
        !o.reference.ladder.contiguous_to("OBSERVED ACTUATION"),
        "the ladder must stop below observed actuation"
    );
    assert!(
        o.reference.ladder.contiguous_to("INDEPENDENT OBSERVATION"),
        "and it must reach independent observation, because an observer did run"
    );
}

// ─── 3-4. Loss ───

#[test]
fn t3_and_t4_observer_and_collector_loss_are_conservative() {
    // The observer process holds both the probe and the collector key, so
    // killing it is simultaneously observer loss and collector loss. Neither
    // may be read as "the effect did not happen".
    let o = run_scenario("t3", Scenario::ObserverLost);
    let r = &o.reference;
    assert_eq!(r.observations_offered, 0, "nobody looked");
    assert_eq!(
        r.finding,
        EffectFinding::NotObserved(NotObservedReason::NoObserverConsulted)
    );
    assert!(!r.finding.asserts_occurrence());
    assert!(
        !r.finding.asserts_non_occurrence(),
        "loss of the observer must never assert non-occurrence"
    );
    assert_eq!(r.reconciliation.result.as_str(), "CANNOT_PROVE");
    assert_eq!(
        r.platform_binding.disposition(),
        &PlatformDisposition::NotEvaluated,
        "absence of observation is not evidence of location"
    );
}

// ─── 5. The workload is gone before anyone looks ───

#[test]
fn t5_a_workload_that_exits_first_yields_an_attested_empty_window() {
    let o = run_scenario("t5", Scenario::WorkloadExitsFirst);
    let r = &o.reference;
    assert!(
        o.batches.len() >= 2,
        "the observer must still attest the window it looked at: {} batch(es)",
        o.batches.len()
    );
    assert_eq!(
        r.observations_offered, 0,
        "it looked and there was nothing there"
    );
    assert!(!r.establishes_named_effect);
    assert!(!r.finding.asserts_non_occurrence());
    assert_eq!(r.reconciliation.result.as_str(), "CANNOT_PROVE");
}

// ─── 7-9. Wrong identifiers ───

#[test]
fn t7_and_t13_an_observation_of_another_instance_is_excluded_not_downgraded() {
    // The observer really measures a different live process on this host. The
    // batch verifies; its subject is wrong.
    let o = run_scenario("t7", Scenario::CrossExecutionInjection);
    let r = &o.reference;
    assert!(
        r.observations_offered > 0,
        "the injected observation must actually exist, or nothing was excluded"
    );
    assert_eq!(
        r.records.len(),
        0,
        "an observation of another process instance must not become evidence about this one"
    );
    assert!(!r.establishes_named_effect);
    assert_eq!(
        r.reconciliation.result.as_str(),
        "IDENTITY_DIVERGENCE",
        "the existing engine reaches its own conclusion about the same evidence"
    );
}

#[test]
fn t9_a_boot_the_observer_did_not_measure_yields_no_record() {
    let o = run_scenario("t9", Scenario::WrongBoot);
    let r = &o.reference;
    assert!(r.observations_offered > 0, "the observer did look");
    assert_eq!(
        r.records.len(),
        0,
        "a verified batch may not be relabelled onto another host"
    );
    assert_eq!(
        r.platform_binding.disposition(),
        &PlatformDisposition::NotEvaluated
    );
    assert!(!r.establishes_named_effect);
}

#[test]
fn t8_a_platform_other_than_the_authorized_one_is_a_mismatch() {
    let o = run_scenario("t8", Scenario::WrongPlatform);
    let d = o.reference.platform_binding.disposition();
    match d {
        PlatformDisposition::Mismatch {
            authorized,
            observed,
        } => {
            assert_ne!(authorized, observed);
        }
        other => panic!("expected a platform mismatch, got {other:?}"),
    }
    assert!(
        !d.asserts_platform(),
        "a mismatch must not assert the execution ran on the authorized platform"
    );
}

// ─── 10-11. Replay and duplication ───

#[test]
fn t10_and_t11_a_replayed_batch_is_detected_and_does_not_inflate_the_count() {
    let o = run_scenario("t10", Scenario::ReplayedObservation);
    let r = &o.reference;
    assert!(
        r.reconciliation.replay_detected,
        "the existing engine must detect the duplicate"
    );
    // The same observation offered twice is one observation. Counting it twice
    // would be evidence inflation performed by the verifier's own loop.
    match &r.finding {
        EffectFinding::Corroborated { supporting, .. } => assert_eq!(
            *supporting, 1,
            "one connection observed once must not read as two corroborations"
        ),
        other => panic!("expected a corroborated finding, got {other:?}"),
    }
    let honest = run_scenario("t10-honest", Scenario::Honest);
    assert_eq!(
        r.records.len(),
        honest.reference.records.len(),
        "the duplicated run must produce the same number of records as the honest one"
    );
}

// ─── 21-22. The two errors this architecture exists to prevent ───

#[test]
fn t21_a_successful_call_with_no_observation_does_not_become_an_effect() {
    let o = run_scenario("t21", Scenario::ObserverLost);
    let r = &o.reference;
    // The workload's runtime report is present and says the call returned.
    let effects = &r.execution_profile.effects;
    assert_eq!(effects.len(), 1);
    assert!(
        effects[0].runtime.is_some(),
        "the reference must actually carry a runtime report, or the test is vacuous"
    );
    assert!(
        !effects[0].disposition().asserts_occurrence(),
        "a transport status reached an occurrence claim: {:?}",
        effects[0].disposition()
    );
    assert!(!r.establishes_named_effect);
}

#[test]
fn t22_missing_observation_is_never_read_as_non_occurrence() {
    for (tag, scenario) in [
        ("t22-lost", Scenario::ObserverLost),
        ("t22-exit", Scenario::WorkloadExitsFirst),
        ("t22-boot", Scenario::WrongBoot),
        ("t22-cross", Scenario::CrossExecutionInjection),
    ] {
        let o = run_scenario(tag, scenario);
        assert!(
            !o.reference.finding.asserts_non_occurrence(),
            "{tag}: absence became evidence of absence"
        );
        assert!(
            !o.reference.finding.asserts_occurrence(),
            "{tag}: absence became evidence of occurrence"
        );
        assert_ne!(
            o.reference.reconciliation.result.as_str(),
            "PHANTOM_CLAIM",
            "{tag}: this reference must not reach an accusation the evidence cannot support"
        );
    }
}

// ─── 23. The physical-effect ceiling ───

#[test]
fn t23_physical_effect_stays_unreachable_on_every_scenario() {
    for (tag, scenario) in [
        ("t23-honest", Scenario::Honest),
        ("t23-self", Scenario::SelfReportOnly),
        ("t23-lost", Scenario::ObserverLost),
    ] {
        let o = run_scenario(tag, scenario);
        let p = &o.reference.physical_effect;
        assert!(!p.class_implemented, "{tag}");
        assert!(!p.observable_in_profile, "{tag}");
        assert!(!p.establishes_physical_effect(), "{tag}");
        assert_eq!(p.completeness, Completeness::NotObservable, "{tag}");
        let rung = o
            .reference
            .ladder
            .rungs
            .iter()
            .find(|r| r.name == "PHYSICAL EFFECT")
            .expect("physical rung");
        assert!(!rung.established, "{tag}");
        assert!(
            rung.stage.is_none(),
            "{tag}: no stage on the twelve-rung ladder is a physical measurement"
        );
    }
}

// ─── Process topology (Phase 5) ───

#[test]
fn the_workload_and_the_observer_are_different_operating_system_processes() {
    let o = run_scenario("topology", Scenario::Honest);
    assert_ne!(
        o.workload_pid, o.observer_pid,
        "the observer must be independently instantiated"
    );
    assert_ne!(
        o.workload_pid,
        std::process::id(),
        "the workload must not be the verifier"
    );
    assert_ne!(
        o.observer_pid,
        std::process::id(),
        "the observer must not be the verifier"
    );
}

// ─── Determinism of the report structure ───

#[test]
fn two_honest_runs_agree_on_everything_except_per_run_identity() {
    let a = run_scenario("det-a", Scenario::Honest);
    let b = run_scenario("det-b", Scenario::Honest);
    assert_eq!(
        a.reference.reconciliation.result.as_str(),
        b.reference.reconciliation.result.as_str()
    );
    assert_eq!(a.reference.finding.code(), b.reference.finding.code());
    assert_eq!(a.reference.binding.code(), b.reference.binding.code());
    assert_eq!(
        a.reference.establishes_named_effect,
        b.reference.establishes_named_effect
    );
    assert_eq!(a.reference.records.len(), b.reference.records.len());
    // The digests must differ: they commit to the execution id, the process
    // instance and the collector's clock, all of which are per-run. A stable
    // digest across runs would mean the report was not about the run.
    assert_ne!(
        a.reference.digest(),
        b.reference.digest(),
        "the report must commit to per-run identity"
    );
}

#[test]
fn the_reference_digest_is_stable_for_one_report() {
    let o = run_scenario("digest", Scenario::Honest);
    assert_eq!(o.reference.digest(), o.reference.digest());
    assert_eq!(o.reference.canonical_bytes(), o.reference.canonical_bytes());
}
