//! The process boundary, checked mechanically rather than believed.
//!
//! Skill 22 Phase 5 requires that the workload cannot hold observer signing
//! capability and that the observer cannot author agent evidence. Both are
//! enforced by the dependency graph: an expression that reaches
//! `CollectorSigner` needs `aip-observe` linked, and one that reaches
//! `sign_airi_event` needs `aip-airi` linked.
//!
//! These tests read the manifests. That is the whole mechanism, and it is
//! worth more than a runtime check would be: a runtime check tests the code
//! that exists, and a manifest guard tests every line of code anyone will ever
//! write in those crates.
//!
//! The dependency scan covers `[dev-dependencies]` and `[build-dependencies]`
//! too, because adding `aip-observe` there is the cheapest way to reintroduce
//! exactly what this file forbids.

mod common;

use common::{declared_dependencies, manifest, strip_comments};

/// Crates that would give a workload the ability to sign, verify or construct
/// observation evidence.
const OBSERVER_CAPABILITY: [&str; 3] = ["aip-observe", "aip-observation", "aip-effect"];

/// Crates that would give an observer the ability to author the subject's own
/// account of itself, or to decide what it was permitted to do.
const SUBJECT_CAPABILITY: [&str; 2] = ["aip-airi", "aip-authorize"];

/// The workload's source with comments removed.
///
/// Stripping matters: both binaries *document* at length what they are unable
/// to do, and a raw substring search would either fail on that prose or be
/// weakened until it passed. What must be absent is the name in **code**.
fn workload_code() -> String {
    strip_comments(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../aip-edge-workload/src/main.rs"
        ))
        .expect("workload source"),
    )
}

fn observer_code() -> String {
    strip_comments(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../aip-edge-observer/src/main.rs"
        ))
        .expect("observer source"),
    )
}

#[test]
fn t18_the_workload_cannot_link_aip_observe() {
    let deps = declared_dependencies(&manifest("aip-edge-workload"));
    for forbidden in OBSERVER_CAPABILITY {
        assert!(
            !deps.iter().any(|d| d == forbidden),
            "aip-edge-workload declares {forbidden}: the subject would be able to construct \
             or verify evidence about itself. Phase 10 test 18."
        );
    }
}

#[test]
fn t17_the_workload_has_no_route_to_a_collector_key() {
    // `CollectorSigner`, `CollectorKey` and `ObserverTrustAnchors` all live in
    // `aip-observe`. With that crate absent there is no name in scope that
    // denotes a collector key, so "the workload attempts to access the
    // observer key" is not a runtime event that could succeed or fail — it is
    // a compile error in a crate that does not exist.
    let src = workload_code();
    for name in [
        "CollectorSigner",
        "CollectorKey",
        "ObserverTrustAnchors",
        "aip_observe",
    ] {
        assert!(
            !src.contains(name),
            "aip-edge-workload names {name}; it must not be able to reach the observer key. \
             Phase 10 test 17."
        );
    }
}

#[test]
fn t16_the_workload_cannot_construct_observer_evidence() {
    let src = workload_code();
    for name in [
        "AttestedBatch",
        "ObservationBatch",
        "ObservedExecution",
        "ObservationRecord",
        "from_attested",
        "attest",
    ] {
        assert!(
            !src.contains(name),
            "aip-edge-workload names {name}; a subject that could construct observer evidence \
             would be nominating the evidence used to judge it. Phase 10 test 16."
        );
    }
}

#[test]
fn t19_the_observer_cannot_author_airi_evidence() {
    let deps = declared_dependencies(&manifest("aip-edge-observer"));
    for forbidden in SUBJECT_CAPABILITY {
        assert!(
            !deps.iter().any(|d| d == forbidden),
            "aip-edge-observer declares {forbidden}: the witness would be able to write both \
             sides of the comparison. Phase 10 test 19."
        );
    }
    let src = observer_code();
    for name in ["sign_airi_event", "AiriEvent", "aip_airi"] {
        assert!(
            !src.contains(name),
            "aip-edge-observer names {name}. Phase 10 test 19."
        );
    }
}

#[test]
fn t20_the_observer_cannot_alter_an_expected_execution() {
    let src = observer_code();
    for name in [
        "ExpectedExecution",
        "DecisionPoint",
        "authorize",
        "aip_authorize",
    ] {
        assert!(
            !src.contains(name),
            "aip-edge-observer names {name}; an observer that could construct an authorization \
             could decide what the workload was permitted to do and then testify that it did \
             it. Phase 10 test 20."
        );
    }
}

#[test]
fn the_shared_contract_crate_re_links_neither_side() {
    // The contract is what makes the two exclusions survivable: without it the
    // three processes could not agree on a protocol, and the pressure would be
    // to add a shared crate that depends on everything. If the contract itself
    // grew either dependency, both guards above would be vacuous — the
    // capability would arrive transitively.
    let deps = declared_dependencies(&manifest("aip-edge-contract"));
    for forbidden in OBSERVER_CAPABILITY.iter().chain(SUBJECT_CAPABILITY.iter()) {
        assert!(
            !deps.iter().any(|d| d == forbidden),
            "aip-edge-contract declares {forbidden}; it is linked by both the workload and the \
             observer, so this would restore transitively exactly what the manifests exclude"
        );
    }
}

#[test]
fn the_observer_publishes_a_public_key_and_never_a_private_one() {
    let src = observer_code();
    // The observer *must* name `private_key` once: it generates a keypair and
    // hands the private half to `CollectorSigner`, which wraps it in a
    // custodian and exposes no accessor. What must never happen is a second
    // mention — every additional use is a chance for it to reach a file, a log
    // or the announcement. So the guard is a count and a location, not an
    // absence: an absence guard here would be satisfied by code that could not
    // sign at all.
    let uses: Vec<&str> = src.lines().filter(|l| l.contains("private_key")).collect();
    assert_eq!(
        uses.len(),
        1,
        "aip-edge-observer mentions private_key {} times; it may be named exactly once, where \
         it is handed to CollectorSigner: {uses:?}",
        uses.len()
    );
    assert!(
        uses[0].contains("CollectorSigner::new"),
        "the single use of private_key must be the handoff to the collector signer, not {:?}",
        uses[0]
    );
    assert!(
        src.contains("public_key()"),
        "the observer must publish its public key, or no verifier can anchor it"
    );
}

#[test]
fn the_contract_announcement_carries_no_private_material() {
    // A structural read of the published shape: if a field for a private key
    // ever appears here, every observer that speaks this protocol leaks one.
    let src = strip_comments(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../aip-edge-contract/src/lib.rs"
        ))
        .expect("contract source"),
    );
    for name in ["private_key", "secret", "seed"] {
        assert!(
            !src.contains(name),
            "aip-edge-contract names {name}: the wire contract must carry no private material"
        );
    }
}
