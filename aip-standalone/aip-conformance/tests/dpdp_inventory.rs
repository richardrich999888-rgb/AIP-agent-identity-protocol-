//! R20 — the DPDP field inventory cannot silently fall behind the code.
//!
//! The inventory in `aip_conformance::dpdp` is a document a Data Protection
//! Officer signs. The risk is not that it is wrong when written; it is that
//! a field is added later and nobody tells them. So the field set is derived
//! here from a real, fully-populated `ObservationBatch` rather than from the
//! inventory's own list, and any disagreement fails the build.

use aip_conformance::dpdp::{inventory, leaf_paths, PersonalDataRisk, AGGREGATED_PATHS};
use aip_observe::{
    AgentAttribution, BootClockAnchor, KernelLifecycleEvent, KernelLifecycleKind,
    MechanismIntegrity, MechanismIntegrityReport, ObservationBatch, ObservedEffect,
    ObservedExecution, ObservedProcess, SocketEndpoint, SocketProtocol, SourceMechanism,
    OBSERVE_PROTOCOL_VERSION,
};
use aip_types::ProcessInstance;
use std::collections::BTreeSet;

fn process() -> ObservedProcess {
    ObservedProcess {
        process: ProcessInstance {
            pid: 4242,
            pid_start_time_ticks: 99_000,
            boot_id: [7u8; 16],
        },
        exe_content_sha256: [0x33; 32],
        exe_path: "/usr/local/bin/agent".into(),
    }
}

fn endpoint(port: u16) -> SocketEndpoint {
    SocketEndpoint {
        addr: [0u8; 16],
        is_v6: false,
        port,
    }
}

/// A batch with **every optional field present** and both collections
/// non-empty. An inventory checked against a sparse fixture would miss
/// exactly the fields a sparse fixture omits.
fn populated_batch() -> ObservationBatch {
    ObservationBatch {
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: "probe-1".into(),
        batch_id: [1u8; 16],
        probe_run_id: [2u8; 16],
        probe_seq_first: 1,
        probe_seq_last: 9,
        dropped_events: Some(0),
        active_mechanisms: SourceMechanism::canonical_set(vec![
            SourceMechanism::PidFdAnchored,
            SourceMechanism::SockStateTracepoint,
        ]),
        mechanism_integrity: vec![MechanismIntegrityReport {
            mechanism: SourceMechanism::SockStateTracepoint,
            integrity: MechanismIntegrity::Verified,
        }],
        claimed_from_ms: 1_000,
        claimed_to_ms: 2_000,
        observations: vec![ObservedExecution {
            version: OBSERVE_PROTOCOL_VERSION,
            probe_id: "probe-1".into(),
            observed: process(),
            attribution: AgentAttribution::Claimed {
                agent_id: "aip1Agent".into(),
                claim_source: "orchestrator".into(),
            },
            effect: ObservedEffect::SocketObserved {
                protocol: SocketProtocol::Tcp,
                local: endpoint(40_000),
                remote: endpoint(8443),
                state: 1,
                inode: 9_001,
            },
            mechanism: SourceMechanism::ProcNetTable,
            claimed_decision_id: Some([0xD1; 16]),
            host_wall_clock_ms: 1_500,
            probe_monotonic_ns: 5_000,
        }],
        kernel_events: vec![KernelLifecycleEvent {
            version: OBSERVE_PROTOCOL_VERSION,
            probe_id: "probe-1".into(),
            mechanism: SourceMechanism::SockStateTracepoint,
            kind: KernelLifecycleKind::SocketState {
                protocol: SocketProtocol::Tcp,
                local: endpoint(40_000),
                remote: endpoint(8443),
                old_state: 7,
                new_state: 2,
                sk: 0xDEAD,
                current_pid: 4242,
            },
            cpu: 1,
            kernel_timestamp_ns: 1_000_000,
            probe_seq: 2,
            bound: Some(process()),
            attribution: AgentAttribution::Claimed {
                agent_id: "aip1Agent".into(),
                claim_source: "orchestrator".into(),
            },
            claimed_decision_id: Some([0xD1; 16]),
        }],
        clock_anchor: Some(BootClockAnchor {
            realtime_ms: 1_000,
            boottime_ns: 0,
            monotonic_ns: 0,
            clk_tck: 100,
        }),
    }
}

fn actual_paths() -> BTreeSet<String> {
    let json = serde_json::to_value(populated_batch()).expect("serialise batch");
    leaf_paths(&json, "", AGGREGATED_PATHS)
        .into_iter()
        .collect()
}

fn inventoried_paths() -> BTreeSet<String> {
    inventory()
        .into_iter()
        .map(|r| r.path.to_string())
        .collect()
}

/// **The drift check.** A field added to the observation batch fails this
/// test until someone writes down what it is and why it may be collected.
#[test]
fn every_field_that_leaves_the_host_is_in_the_inventory() {
    let actual = actual_paths();
    let inventoried = inventoried_paths();

    let undocumented: Vec<&String> = actual.difference(&inventoried).collect();
    assert!(
        undocumented.is_empty(),
        "these fields leave the observed host and are not in the DPDP inventory: {undocumented:#?}\n\
         Add a row to aip_conformance::dpdp::inventory() saying what each holds, \
         whether it can carry personal data, and why it is collected."
    );
}

/// The converse: an inventory row for a field that no longer exists is a
/// document describing a system that is not there, which is its own kind of
/// wrong when a regulator reads it.
#[test]
fn the_inventory_describes_no_field_that_does_not_exist() {
    let actual = actual_paths();
    let inventoried = inventoried_paths();
    let stale: Vec<&String> = inventoried.difference(&actual).collect();
    assert!(
        stale.is_empty(),
        "the inventory names fields the batch no longer has: {stale:#?}"
    );
}

/// Every row has to answer the two questions a DPO asks, and no row may
/// answer them with nothing.
#[test]
fn every_row_states_a_risk_and_a_purpose() {
    for r in inventory() {
        assert!(!r.what.trim().is_empty(), "{}: empty description", r.path);
        assert!(
            r.purpose.trim().len() > 20,
            "{}: the purpose must be a reason, not a label: {:?}",
            r.path,
            r.purpose
        );
    }
}

/// The claim the pilot rests on: **no payload leaves the host**. If a field
/// were ever added that carried message content, it would have to be
/// inventoried as `Direct`, and this test is where that decision surfaces
/// instead of shipping quietly.
#[test]
fn no_field_carries_personal_data_directly() {
    let direct: Vec<&'static str> = inventory()
        .iter()
        .filter(|r| r.risk == PersonalDataRisk::Direct)
        .map(|r| r.path)
        .collect();
    assert!(
        direct.is_empty(),
        "a field now carries personal data directly: {direct:#?}\n\
         That is a change to what the pilot may claim under the DPDP Act and \
         needs the DPO's decision, not a passing test."
    );
}

/// The artefacts are deterministic, so a diff in a committed file is a
/// change in the system rather than a change in the run.
#[test]
fn the_emitted_artefacts_are_stable_and_ordered() {
    assert_eq!(
        aip_conformance::dpdp::to_csv(),
        aip_conformance::dpdp::to_csv()
    );
    let paths: Vec<&str> = inventory().iter().map(|r| r.path).collect();
    let mut sorted = paths.clone();
    sorted.sort();
    assert_eq!(paths, sorted, "rows must be ordered by path");

    let csv = aip_conformance::dpdp::to_csv();
    assert!(csv.starts_with("FIELD_PATH,WHAT,PERSONAL_DATA_RISK,PURPOSE\n"));
    assert_eq!(
        csv.lines().count(),
        inventory().len() + 1,
        "one line per row plus the header; a comma in a cell must not split a line"
    );
}
