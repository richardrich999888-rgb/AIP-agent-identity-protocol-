//! Regression over real, signed observations. Repeating an already verified
//! record models a repeated socket sighting; it does not create new evidence.

mod common;

use aip_edge::effect::{assess_effect, requested_effect, EffectInputs};
use aip_edge::orchestrate::Scenario;
use aip_effect::{EffectFinding, EffectWindow};

fn run_with_optional_archive(tag: &str, scenario: Scenario) -> aip_edge::orchestrate::RunOutcome {
    let Ok(root) = std::env::var("P0_048_RETAIN_DIR") else {
        return common::run_scenario(tag, scenario);
    };
    common::ensure_sibling_binaries();
    let dir = std::path::Path::new(&root).join(format!("{tag}-{scenario:?}"));
    assert!(
        !dir.exists(),
        "refuse to overwrite an earlier acceptance archive"
    );
    let run = aip_edge::orchestrate::run(&common::config(dir.clone(), scenario))
        .expect("live reference run");
    // The existing transport files contain original signed batches/health,
    // workload claims and public announcements. Private keys stay in memory.
    let report = serde_json::json!({
        "scope": "Live synthetic reference; one host and administrator",
        "scenario": format!("{scenario:?}"),
        "endpoint": run.endpoint.to_string(),
        "workload_pid": run.workload_pid,
        "observer_pid": run.observer_pid,
        "result": run.reference.reconciliation.result.as_str(),
        "finding": run.reference.finding,
        "establishes_named_effect": run.reference.establishes_named_effect,
        "replay_detected": run.reference.reconciliation.replay_detected,
        "records": run.reference.records,
        "correlation": run.subject.correlation(),
    });
    std::fs::write(
        dir.join("result.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    std::fs::write(
        dir.join("expectation.json"),
        serde_json::to_vec_pretty(&run.expectation).unwrap(),
    )
    .unwrap();
    std::fs::write(
        dir.join("decision-anchors.json"),
        serde_json::to_vec_pretty(&run.dp_anchors.entries()).unwrap(),
    )
    .unwrap();
    run
}

#[test]
fn repeated_signed_socket_records_count_as_one_fact() {
    let run = run_with_optional_archive("socket-repeat", Scenario::Honest);
    let requested = requested_effect(run.endpoint.ip().octets(), run.endpoint.port());
    let inputs = EffectInputs {
        requested: &requested,
        subject: &run.subject,
        window: EffectWindow {
            from_ms: 0,
            to_ms: u64::MAX,
        },
        profile: &run.reference.observation_profile,
        requested_effects_in_execution: 1,
    };
    let repeated: Vec<_> = (0..4)
        .flat_map(|_| run.correlated.iter().cloned())
        .collect();
    let assessment = assess_effect(
        &inputs,
        &repeated,
        run.endpoint.ip().octets(),
        run.endpoint.port(),
    )
    .expect("verified records remain assessable");
    match assessment.finding() {
        EffectFinding::Corroborated { supporting, .. } => assert_eq!(
            *supporting, 1,
            "four sightings of one connection are not four facts",
        ),
        other => panic!("honest live socket was not corroborated: {other:?}"),
    }
}

#[test]
fn repeated_absence_or_self_report_never_establishes_execution() {
    for scenario in [Scenario::SelfReportOnly, Scenario::ObserverLost] {
        let run = run_with_optional_archive("socket-absence", scenario);
        assert_eq!(run.reference.reconciliation.result.as_str(), "CANNOT_PROVE");
        let requested = requested_effect(run.endpoint.ip().octets(), run.endpoint.port());
        let inputs = EffectInputs {
            requested: &requested,
            subject: &run.subject,
            window: EffectWindow {
                from_ms: 0,
                to_ms: u64::MAX,
            },
            profile: &run.reference.observation_profile,
            requested_effects_in_execution: 1,
        };
        let repeated: Vec<_> = (0..20)
            .flat_map(|_| run.correlated.iter().cloned())
            .collect();
        let assessment = assess_effect(
            &inputs,
            &repeated,
            run.endpoint.ip().octets(),
            run.endpoint.port(),
        )
        .expect("absence remains assessable");
        assert!(!assessment.establishes_named_effect());
        assert!(!assessment.finding().asserts_occurrence());
        assert!(!assessment.finding().asserts_non_occurrence());
    }
}
