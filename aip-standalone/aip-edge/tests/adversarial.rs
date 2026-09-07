//! Tampering with real evidence.
//!
//! Every batch used below was signed by a real collector in a real run. The
//! tests mutate that material the way an attacker would and assert the
//! reference refuses. Nothing here builds a batch or a record from nothing:
//! the whole point is that these are the genuine artifacts, altered.

mod common;

use aip_edge::correlate::{observation_record, records_for_subject};
use aip_edge::effect::{assess_effect, requested_effect, stance_of, EffectInputs};
use aip_edge::orchestrate::Scenario;
use aip_edge::EdgeError;
use aip_effect::{EffectFinding, EffectObservation, EffectWindow, ObservedStance};
use aip_observation::ObservationRecord;

use common::run_scenario;

/// A run that produced at least one correlated record, for tampering.
fn honest_run(tag: &str) -> aip_edge::orchestrate::RunOutcome {
    let o = run_scenario(tag, Scenario::Honest);
    assert!(
        !o.reference.records.is_empty(),
        "{tag}: the honest run must produce records, or there is nothing to tamper with"
    );
    o
}

// ─── 14. A forged observer ───

#[test]
fn t14_a_batch_naming_an_observer_the_verifier_never_anchored_yields_no_record() {
    let o = honest_run("t14");
    let mut forged = o.batches.last().expect("a batch").clone();
    // The cheapest forgery: claim to be someone else. The signature is still a
    // real signature over real observations — it is simply not one the
    // verifier anchored, and naming an observer grants nothing.
    forged.observer_id = "attacker-invented-observer".to_string();

    let err = observation_record(&forged, &o.observer_anchors, 0, &o.subject)
        .expect_err("a batch from an unanchored observer must yield no record");
    assert!(
        matches!(err, EdgeError::BatchNotTrusted { .. }),
        "expected BatchNotTrusted, got {err:?}"
    );
    assert!(
        records_for_subject(&forged, &o.observer_anchors, &o.subject).is_err(),
        "the sweep must refuse the whole batch, not return an empty set that a caller \
         could mistake for `the observer saw nothing`"
    );
}

#[test]
fn t14b_a_batch_signed_under_an_unanchored_key_version_yields_no_record() {
    let o = honest_run("t14b");
    let mut forged = o.batches.last().expect("a batch").clone();
    // Rotation is anchoring the new version alongside the old; revocation is
    // removing a pair. A version the verifier never anchored is neither.
    forged.key_version = forged.key_version.wrapping_add(1);
    assert!(
        observation_record(&forged, &o.observer_anchors, 0, &o.subject).is_err(),
        "an unanchored key version must not verify"
    );
}

// ─── 15. Modified bytes inside a genuinely attested batch ───

#[test]
fn t15_altering_an_observation_after_signing_yields_no_record() {
    let o = honest_run("t15");
    let mut tampered = o.batches.last().expect("a batch").clone();
    assert!(
        !tampered.batch.observations.is_empty(),
        "the batch under test must carry an observation"
    );
    // Change the measured pid. On an honest host this is the difference
    // between "this instance" and "some other instance"; here it is simply a
    // byte the attestation covers.
    tampered.batch.observations[0].observed.process.pid ^= 0xFFFF;

    let err = observation_record(&tampered, &o.observer_anchors, 0, &o.subject)
        .expect_err("altered bytes must not verify");
    assert!(
        matches!(err, EdgeError::BatchNotTrusted { .. }),
        "the refusal must come from the signature, not from a downstream check that \
         happened to notice: {err:?}"
    );
}

#[test]
fn t15b_altering_the_measured_boot_after_signing_yields_no_record() {
    let o = honest_run("t15b");
    let mut tampered = o.batches.last().expect("a batch").clone();
    tampered.batch.observations[0].observed.process.boot_id[0] ^= 0xFF;
    assert!(
        observation_record(&tampered, &o.observer_anchors, 0, &o.subject).is_err(),
        "relabelling an observation onto another host must fail at the signature"
    );
}

#[test]
fn t15c_a_record_cannot_be_deserialized_into_existence() {
    // `ObservationRecord` is Serialize and deliberately not Deserialize: a
    // derived Deserialize was a construction path that consulted no batch and
    // no anchors. The reference depends on that, so it is asserted here as
    // well as in `aip-observation` — this crate is the one that would be
    // compromised by a regression.
    let o = honest_run("t15c");
    let json = serde_json::to_string(&o.reference.records[0]).expect("serialize");
    assert!(
        !json.is_empty(),
        "a record must still be writable; only reading one back is refused"
    );
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../aip-observation/src/record.rs"
    ))
    .expect("record source");
    assert!(
        source.contains("#[derive(Debug, Clone, PartialEq, Eq, Serialize)]"),
        "ObservationRecord must derive Serialize and not Deserialize"
    );
    assert!(
        !source.contains("Serialize, Deserialize)]\npub struct ObservationRecord"),
        "a Deserialize derive would restore the bypass"
    );
}

// ─── 12. Staleness, on the collector's clock ───

#[test]
fn t12_an_observation_outside_the_window_establishes_nothing() {
    let o = honest_run("t12");
    let requested = requested_effect(o.endpoint.ip().octets(), o.endpoint.port());
    let profile = &o.reference.observation_profile;

    // A window entirely before every batch's attested time. The bound is the
    // *collector's* signed clock, so an agent that could move the window would
    // be able to admit an observation from another moment; here the verifier
    // moves it and the finding degrades accordingly.
    let earliest = o.batches.iter().map(|b| b.attested_at_ms).min().unwrap();
    let stale = EffectWindow {
        from_ms: earliest.saturating_sub(10_000),
        to_ms: earliest.saturating_sub(5_000),
    };
    let inputs = EffectInputs {
        requested: &requested,
        subject: &o.subject,
        window: stale,
        profile,
        requested_effects_in_execution: 1,
    };
    let assessment = assess_effect(
        &inputs,
        &o.correlated,
        o.endpoint.ip().octets(),
        o.endpoint.port(),
    )
    .expect("assessment");
    assert_eq!(
        assessment.finding(),
        &EffectFinding::NotObserved(aip_effect::NotObservedReason::OutsideWindow),
        "a stale observation must be reported as stale, not as absent and not as evidence"
    );
    assert!(!assessment.establishes_named_effect());
}

// ─── 24. The effect boundary cannot be walked around ───

#[test]
fn t24_a_corroborating_finding_alone_does_not_establish_the_named_effect() {
    let o = honest_run("t24");
    let requested = requested_effect(o.endpoint.ip().octets(), o.endpoint.port());
    let profile = &o.reference.observation_profile;
    let window = EffectWindow {
        from_ms: 0,
        to_ms: u64::MAX,
    };
    // Same real records, same real stance — but the execution requested two
    // effects, so the observation binds at execution granularity and cannot
    // name which. ADR-004.
    let inputs = EffectInputs {
        requested: &requested,
        subject: &o.subject,
        window,
        profile,
        requested_effects_in_execution: 2,
    };
    let assessment = assess_effect(
        &inputs,
        &o.correlated,
        o.endpoint.ip().octets(),
        o.endpoint.port(),
    )
    .expect("assessment");
    assert!(
        assessment.finding().asserts_occurrence(),
        "the finding itself is still a corroboration"
    );
    assert!(
        !assessment.binding().is_effect_specific(),
        "with two candidate effects the binding is ExecutionOnly"
    );
    assert!(
        !assessment.establishes_named_effect(),
        "a corroboration that could equally be about a sibling effect is not evidence \
         about this one"
    );
}

#[test]
fn t24b_an_assessment_of_zero_requested_effects_is_refused() {
    let o = honest_run("t24b");
    let requested = requested_effect(o.endpoint.ip().octets(), o.endpoint.port());
    let inputs = EffectInputs {
        requested: &requested,
        subject: &o.subject,
        window: EffectWindow {
            from_ms: 0,
            to_ms: u64::MAX,
        },
        profile: &o.reference.observation_profile,
        requested_effects_in_execution: 0,
    };
    assert!(
        assess_effect(
            &inputs,
            &o.correlated,
            o.endpoint.ip().octets(),
            o.endpoint.port()
        )
        .is_err(),
        "there is nothing to assess, and a nonsensical count must not default to the \
         stronger binding"
    );
}

// ─── Contradiction and conflict, over real records ───
//
// The live reference derives only `Supports` and `Neither`; it has no
// observation that contradicts "a connection to X was held" (see
// `aip_edge::effect`). `Contradicted` and `Conflicting` are therefore
// exercised here with the stance supplied explicitly, which is legitimate —
// supplying the stance is the caller's documented job — over records an
// anchored observer really signed.

#[test]
fn a_real_record_with_an_opposing_stance_reaches_contradicted() {
    let o = honest_run("contra");
    let requested = requested_effect(o.endpoint.ip().octets(), o.endpoint.port());
    let observations: Vec<EffectObservation> = o
        .reference
        .records
        .iter()
        .map(|r| EffectObservation::new(r.clone(), ObservedStance::Opposes).expect("stance"))
        .collect();
    let inputs = EffectInputs {
        requested: &requested,
        subject: &o.subject,
        window: EffectWindow {
            from_ms: 0,
            to_ms: u64::MAX,
        },
        profile: &o.reference.observation_profile,
        requested_effects_in_execution: 1,
    };
    let assessment = aip_effect::EffectAssessment::assess(
        &requested,
        &inputs.correlation(),
        inputs.window,
        &observations,
        inputs.profile,
        1,
    )
    .expect("assessment");
    assert!(matches!(
        assessment.finding(),
        EffectFinding::Contradicted { .. }
    ));
    assert!(!assessment.finding().asserts_occurrence());
    assert!(
        !assessment.finding().asserts_non_occurrence(),
        "the strongest negative available is still a statement about an observation"
    );
}

#[test]
fn conflicting_stances_over_real_records_are_never_resolved() {
    let o = honest_run("conflict");
    assert!(
        o.reference.records.len() >= 2,
        "this test needs two real records to disagree"
    );
    let requested = requested_effect(o.endpoint.ip().octets(), o.endpoint.port());
    let mut observations = Vec::new();
    for (i, r) in o.reference.records.iter().enumerate() {
        let stance = if i == 0 {
            ObservedStance::Supports
        } else {
            ObservedStance::Opposes
        };
        observations.push(EffectObservation::new(r.clone(), stance).expect("stance"));
    }
    let inputs = EffectInputs {
        requested: &requested,
        subject: &o.subject,
        window: EffectWindow {
            from_ms: 0,
            to_ms: u64::MAX,
        },
        profile: &o.reference.observation_profile,
        requested_effects_in_execution: 1,
    };
    let assessment = aip_effect::EffectAssessment::assess(
        &requested,
        &inputs.correlation(),
        inputs.window,
        &observations,
        inputs.profile,
        1,
    )
    .expect("assessment");
    match assessment.finding() {
        EffectFinding::Conflicting {
            supporting,
            opposing,
        } => {
            assert!(*supporting > 0 && *opposing > 0);
        }
        other => panic!("a conflict must be reported as a conflict, got {other:?}"),
    }
    assert!(
        !assessment.establishes_named_effect(),
        "a conflict is not a weak yes"
    );
    assert!(assessment.finding().ceiling().is_none());
}

// ─── The stance guard, over a real record ───

#[test]
fn a_record_that_observed_nothing_cannot_be_given_a_stance() {
    // Every record the reference produces has `Completeness::Observed`,
    // because `from_attested` sets it and there is no other constructor. The
    // guard is therefore asserted through its positive form: the observed
    // record accepts a stance, and the type system provides no route to a
    // non-observed one for this crate to try.
    let o = honest_run("stance");
    let r: &ObservationRecord = &o.reference.records[0];
    assert_eq!(r.completeness(), aip_observation::Completeness::Observed);
    assert!(EffectObservation::new(r.clone(), ObservedStance::Supports).is_ok());
    assert!(EffectObservation::new(r.clone(), ObservedStance::Neither).is_ok());
}

// ─── The stance reading itself, over real observations ───

#[test]
fn the_stance_read_from_the_real_socket_row_is_supports_exactly_once() {
    let o = honest_run("stance-read");
    let ip = o.endpoint.ip().octets();
    let port = o.endpoint.port();
    let supports = o
        .correlated
        .iter()
        .filter(|(_, obs)| stance_of(obs, ip, port) == ObservedStance::Supports)
        .count();
    assert_eq!(
        supports, 1,
        "one held connection must read as exactly one supporting observation"
    );
    let neither = o
        .correlated
        .iter()
        .filter(|(_, obs)| stance_of(obs, ip, port) == ObservedStance::Neither)
        .count();
    assert!(
        neither >= 1,
        "the anchored process measurement says nothing about the effect and must read \
         as Neither"
    );
}
