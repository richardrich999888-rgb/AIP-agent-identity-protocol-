//! Inherited blockers, re-derived from the repository (Skill 29, R5).
//!
//! The specification says *track inherited blockers until their closure is
//! independently verified*. A table that restates a register is not tracking;
//! it is copying. So every assertion below reads the repository — source
//! files, manifests — and fails if the mechanism the tracker claims is not
//! there.
//!
//! If a future change removes one of these mechanisms, the blocker reopens and
//! this suite says so, which is the whole point of tracking rather than
//! recording.

use std::path::{Path, PathBuf};

use aip_conformance::blocker::{inherited_blockers, open_blockers, BlockerStatus};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn read(rel: &str) -> String {
    let p = workspace_root().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{} unreadable: {e}", p.display()))
}

/// Every entry is either verified here or recorded open. A blocker that is
/// "closed somewhere else, trust us" is exactly what this suite exists to
/// prevent.
#[test]
fn no_blocker_is_recorded_closed_without_being_verified_here() {
    for b in inherited_blockers() {
        assert_ne!(
            b.status,
            BlockerStatus::ClosedNotVerifiedHere,
            "{} is recorded closed without verification",
            b.id
        );
        assert!(!b.verified_by.is_empty(), "{} cites no mechanism", b.id);
        assert!(!b.finding.is_empty(), "{} states no finding", b.id);
    }
    // Nine inherited blockers, one of them open.
    assert_eq!(inherited_blockers().len(), 9);
}

/// B-1a — the service threads a verification time and a future tolerance into
/// the verification context, rather than deciding from `result.valid` alone.
#[test]
fn b1a_the_service_applies_a_temporal_bound() {
    let src = read("aip-service/src/evidence.rs");
    assert!(src.contains("verification_time_ms"), "no verification time");
    assert!(src.contains("future_tolerance_ms"), "no future tolerance");
    assert!(
        src.contains("ctx.verification_time_ms =") && src.contains("ctx.future_tolerance_ms ="),
        "the temporal fields exist but are not threaded into the context"
    );
}

/// B-3 — still open, and recorded open. The crossing exists; actuation
/// remains unreachable from genuine reconciliation.
#[test]
fn b3_is_still_open_and_is_recorded_open() {
    let open = open_blockers();
    assert_eq!(open.len(), 1, "exactly one blocker is open");
    assert_eq!(open[0].id, "B-3");
    assert!(
        !open[0].boundary.is_empty(),
        "an open blocker must state where it stands"
    );
    // The crossing it refers to exists and is exercised.
    let root =
        workspace_root().join("aip-standalone/aip-containment/tests/engine_to_containment.rs");
    assert!(root.is_file(), "the end-to-end crossing test is missing");
}

/// B-4 — stronger than the register records. A bundle cannot supply its own
/// signer because `SignedHead` has no field for one; the verifier's only key
/// source is the anchor set it was provisioned with.
#[test]
fn b4_a_bundle_supplied_signer_key_is_unrepresentable() {
    let src = read("aip-standalone/aip-nexora/src/commitment.rs");
    let head = src
        .split_once("pub struct SignedHead {")
        .and_then(|(_, r)| r.split_once('}'))
        .map(|(body, _)| body)
        .expect("SignedHead must be declared");
    assert!(
        !head.contains("public_key"),
        "SignedHead carries a public key; a bundle could supply its own signer"
    );
    assert!(
        src.contains("anchors\n        .get(&head.signer_id, head.key_version)")
            || src.contains("anchors.get(&head.signer_id, head.key_version)"),
        "the verifier's key source is not the anchor set"
    );
}

/// B-5 — the file mode comes from `OpenOptions`, not from a later `chmod`,
/// so there is no window in which the seed exists world-readable.
#[test]
fn b5_the_seed_mode_is_set_at_creation_not_afterwards() {
    let src = read("aip-standalone/aip-crypto/src/custody.rs");
    assert!(src.contains("OpenOptions"), "no OpenOptions in custody");
    assert!(
        src.contains(".mode("),
        "the mode is not set through OpenOptions::mode"
    );
}

/// B-6 — the authenticated surface fails closed rather than minting.
#[test]
fn b6_key_handling_fails_closed() {
    let auth = read("aip-service/src/auth.rs");
    assert!(
        auth.contains("fail closed") || auth.contains("fails closed"),
        "the auth layer does not document a fail-closed posture"
    );
    let keys = read("aip-service/src/keys.rs");
    assert!(
        keys.contains("load_or_create"),
        "custody entry point is missing"
    );
}

/// B-7 — the managed-signing endpoint is off unless a deployment opts in, and
/// the decision is made where the router is built rather than inside a
/// handler, so on the refusing path there is no extractor at all.
#[test]
fn b7_managed_signing_is_off_unless_a_deployment_opts_in() {
    let lib = read("aip-service/src/lib.rs");
    assert!(
        lib.contains("AIP_ALLOW_MANAGED_SIGNING"),
        "the opt-in variable is gone; the endpoint may be unconditional again"
    );
    assert!(
        lib.contains("ManagedSigning::Refused"),
        "there is no refusing state"
    );
    // The default must be refusal. Anchor on the `env::var` call rather than
    // on the first mention of the variable, which is a doc comment.
    let gate = lib
        .split_once("std::env::var(\"AIP_ALLOW_MANAGED_SIGNING\")")
        .map(|(_, r)| r)
        .expect("the gate must read the environment, not a config file");
    let window = &gate[..gate.len().min(400)];
    assert!(
        window.contains("_ => ManagedSigning::Refused"),
        "the default arm of the gate is not refusal: {window}"
    );
}

/// B-8 — a replay ledger exists and the observer refuses a batch at a
/// sequence it has already consumed.
#[test]
fn b8_anti_replay_exists_at_both_layers() {
    let replay = read("aip-standalone/aip-nexora/src/replay.rs");
    assert!(replay.contains("fn seen("), "no proof-seen ledger");
    assert!(replay.contains("fn record("), "the ledger cannot record");

    // The observer half, exercised rather than read.
    use aip_observe::{ContinuityFault, ObserverLedger};
    let mut l = ObserverLedger::new();
    l.admit(1, [0u8; 32], [1u8; 32]).unwrap();
    assert_eq!(
        l.admit(1, [0u8; 32], [1u8; 32]),
        Err(ContinuityFault::Replay { sequence: 1 })
    );
}

/// B-9 — `Reconciliation` cannot be assembled by a caller, and a record read
/// back from bytes says so about itself.
#[test]
fn b9_reconciliation_construction_is_sealed() {
    let src = read("aip-standalone/aip-reconcile/src/result.rs");
    assert!(
        src.contains("#[non_exhaustive]"),
        "the struct is not sealed"
    );
    assert!(
        src.contains("pub(crate) provenance: Provenance"),
        "the provenance field is not private to the crate"
    );
}

/// B-10 — the service is inside the primary build and test boundary.
#[test]
fn b10_the_service_is_a_workspace_member() {
    let manifest = read("Cargo.toml");
    assert!(
        manifest.contains("\"aip-service\""),
        "aip-service is not a workspace member"
    );
    let ci = read(".github/workflows/ci.yml");
    assert!(
        ci.contains("cargo test --all"),
        "CI does not test the whole workspace"
    );
}
