//! `aip-edge` — run the Linux autonomous edge reference and print what it
//! established. **NOT_PRODUCTION_CAPABILITY.**
//!
//!     cargo run -p aip-edge --bin aip-edge -- [--scenario <name>] [--all]
//!
//! Contains argument parsing and printing only. The run itself is
//! `aip_edge::orchestrate::run`, which the tests drive too, so the
//! demonstration path and the tested path are one piece of code.

use aip_edge::identity::IdentityKind;
use aip_edge::orchestrate::{run, RunConfig, Scenario};
use aip_system::{PlatformId, SystemId};

const ALL: [Scenario; 8] = [
    Scenario::Honest,
    Scenario::SelfReportOnly,
    Scenario::ObserverLost,
    Scenario::WorkloadExitsFirst,
    Scenario::WrongBoot,
    Scenario::WrongPlatform,
    Scenario::CrossExecutionInjection,
    Scenario::ReplayedObservation,
];

fn main() {
    let scenarios = match parse() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("aip-edge: {e}");
            std::process::exit(2);
        }
    };
    println!("aip-edge — Linux autonomous edge reference (NOT_PRODUCTION_CAPABILITY)");
    println!(
        "three processes: workload (agent key) · observer (collector key) · verifier (anchors)"
    );
    println!();

    let mut failures = 0usize;
    for scenario in scenarios {
        let dir =
            std::env::temp_dir().join(format!("aip-edge-{}-{:?}", std::process::id(), scenario));
        let config = RunConfig {
            dir: dir.clone(),
            system_id: SystemId::parse("edge:reference-system").expect("system id"),
            authorized_platform: PlatformId::parse("edge:reference-platform").expect("platform"),
            registered_platform: if matches!(scenario, Scenario::WrongPlatform) {
                PlatformId::parse("edge:other-platform").expect("platform")
            } else {
                PlatformId::parse("edge:reference-platform").expect("platform")
            },
            scenario,
        };
        println!("{}", scenario.label());
        match run(&config) {
            Ok(outcome) => print_outcome(&outcome),
            Err(e) => {
                failures += 1;
                println!("    run refused: {e}");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
        println!();
    }

    print_identity_table();
    println!();
    println!("Nothing above establishes a physical effect, and nothing here can: no mechanism");
    println!("implements ObservationClass::PhysicalEffect (ADR-003 decision 2). Positive");
    println!("findings are ceilinged at Attested, never Proven, because every mechanism reads");
    println!("content from the observed host and host root forges that content. Running the");
    println!("collector as a second process establishes a process boundary and not a host");
    println!("boundary; production places it off-host entirely.");
    if failures > 0 {
        std::process::exit(1);
    }
}

fn print_outcome(outcome: &aip_edge::orchestrate::RunOutcome) {
    let r = &outcome.reference;
    println!(
        "    processes: workload pid {} · observer pid {} (distinct: {})",
        outcome.workload_pid,
        outcome.observer_pid,
        outcome.workload_pid != outcome.observer_pid
    );
    println!(
        "    batches {} · observations offered {} · correlated {} · endpoint {}",
        outcome.batches.len(),
        r.observations_offered,
        r.records.len(),
        outcome.endpoint
    );
    println!(
        "    reconciliation: result={} strength={:?} reason={:?}",
        r.reconciliation.result.as_str(),
        r.reconciliation.strength,
        r.reconciliation.reason
    );
    println!(
        "    replay_detected={} availability={:?}",
        r.reconciliation.replay_detected, r.reconciliation.availability
    );
    println!("    platform: {:?}", r.platform_binding.disposition());
    println!("    effect finding: {:?}", r.finding);
    println!(
        "    effect binding: {:?} · establishes named effect: {}",
        r.binding, r.establishes_named_effect
    );
    println!(
        "    physical effect: establishes={} completeness={:?}",
        r.physical_effect.establishes_physical_effect(),
        r.physical_effect.completeness
    );
    for rung in &r.ladder.rungs {
        println!(
            "      {:<24} {}  {}",
            rung.name,
            if rung.established { "yes" } else { "no " },
            rung.note
        );
    }
    println!("    reference digest: {}", hex(&r.digest()));
}

fn print_identity_table() {
    println!("identity kinds — what survives what");
    println!(
        "    {:<10} {:<14} {:<16} {:<16} derived from",
        "kind", "independent", "workload restart", "host reboot"
    );
    for k in IdentityKind::ALL {
        println!(
            "    {:<10} {:<14} {:<16} {:<16} {}",
            format!("{k:?}"),
            k.independently_established(),
            format!("{:?}", k.across_workload_restart()),
            format!("{:?}", k.across_host_reboot()),
            k.derived_from()
        );
    }
}

fn parse() -> Result<Vec<Scenario>, String> {
    let mut it = std::env::args().skip(1);
    let mut chosen: Option<Vec<Scenario>> = None;
    while let Some(a) = it.next() {
        match a.as_str() {
            "--all" => chosen = Some(ALL.to_vec()),
            "--scenario" => {
                let name = it.next().ok_or("--scenario needs a name")?;
                let s = ALL
                    .iter()
                    .copied()
                    .find(|s| format!("{s:?}").eq_ignore_ascii_case(&name))
                    .ok_or_else(|| format!("unknown scenario {name}"))?;
                chosen = Some(vec![s]);
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(chosen.unwrap_or_else(|| ALL.to_vec()))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
