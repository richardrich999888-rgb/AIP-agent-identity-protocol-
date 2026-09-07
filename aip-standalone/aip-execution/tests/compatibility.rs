//! Skill 18 — the accountability core must be unchanged by this crate.
//!
//! Two claims are load-bearing and both are asserted mechanically rather than
//! documented: that this crate cannot reach the verdict path, and that it
//! duplicates none of the primitives it composes.

use std::fs;
use std::path::Path;

/// The crates that decide something. If any depends on `aip-execution`, this
/// model has become part of the verdict path and the isolation argument stops
/// holding.
const VERDICT_PATH: [&str; 6] = [
    "aip-reconcile",
    "aip-warrant",
    "aip-containment",
    "aip-nexora",
    "aip-airi",
    "aip-observe",
];

/// Source with comment lines removed, so a scan for a forbidden *use* is not
/// satisfied by a doc comment that explains why the thing is forbidden.
fn code_only(files: &[&str]) -> String {
    files
        .iter()
        .map(|f| fs::read_to_string(Path::new("src").join(f)).expect("source"))
        .flat_map(|c| {
            c.lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn manifest(crate_name: &str) -> String {
    let path = Path::new("..").join(crate_name).join("Cargo.toml");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn no_crate_in_the_verdict_path_depends_on_this_one() {
    for c in VERDICT_PATH {
        assert!(
            !manifest(c).contains("aip-execution"),
            "SECURITY: {c} now depends on aip-execution. This model produces \
             no verdicts and must not be reachable from the engine that does; \
             if the dependency is genuinely required it needs its own \
             justification and its own gate."
        );
    }
}

#[test]
fn this_crate_does_not_reach_the_verdict_path() {
    // The mirror: a dependency *out* would let a future edit here touch
    // semantics it must not. Note aip-authorize and aip-core appear under
    // dev-dependencies only — the binding test drives a real decision point,
    // which is a test concern, not a runtime one.
    let m = fs::read_to_string("Cargo.toml").expect("own manifest");
    let (deps, _dev) = m
        .split_once("[dev-dependencies]")
        .expect("manifest has a dev-dependencies section");
    for forbidden in VERDICT_PATH {
        assert!(
            !deps.contains(forbidden),
            "aip-execution must not depend on {forbidden} at runtime"
        );
    }
}

#[test]
fn there_is_no_second_reconciliation_engine_here() {
    // Structural. This crate exposes no verdict, no result class, no severity
    // and no evidence-strength type. `EvidenceOrigin` is a static property of
    // a stage, not a computed judgement, and the reconciler assigns strength
    // alone.
    // Comments are stripped first. `EvidenceStrength` *should* appear in the
    // documentation — explaining that `EvidenceOrigin` is deliberately not it
    // is the single most important sentence in the stage module. What must not
    // appear is a use of the type in code. An earlier draft of this test
    // scanned raw source and failed on its own doc comment, which would have
    // pushed the explanation out of the code to satisfy a test — exactly
    // backwards.
    let src = code_only(&[
        "stage.rs",
        "effect.rs",
        "runtime.rs",
        "profile.rs",
        "error.rs",
    ]);

    for forbidden in [
        "EvidenceStrength",
        "ReconciliationResult",
        "Severity",
        "VerifiedExecution",
        "PhantomClaim",
        "CannotProve",
    ] {
        assert!(
            !src.contains(forbidden),
            "SECURITY: `{forbidden}` appears in aip-execution. Verdict \
             vocabulary belongs to the one engine that owns it."
        );
    }
}

#[test]
fn no_primitive_is_duplicated() {
    // Nine of the twelve stages already have authoritative types. This crate
    // must reference them, never redefine them — a second definition is a
    // second place for the truth to drift.
    let src = code_only(&["stage.rs", "effect.rs", "runtime.rs", "profile.rs"]);

    for forbidden in [
        "struct ExpectedExecution",
        "struct ExecutionBinding",
        "struct AiriEvent",
        "struct ObservedExecution",
        "struct AttestedBatch",
        "fn derive_aip_id",
    ] {
        assert!(
            !src.contains(forbidden),
            "SECURITY: `{forbidden}` is redefined in aip-execution rather than \
             reused from the crate that owns it"
        );
    }
}

#[test]
fn the_domain_tags_do_not_collide() {
    let ours = aip_execution::EXECUTION_PROFILE_DOMAIN;
    assert!(ours.starts_with("SYNTRIASS/AUTONOMY/"));
    for existing in [
        "SYNTRIASS/AUTONOMY/SYSTEM/v1",
        "SYNTRIASS/AUTONOMY/EXECUTION/v1",
        "SYNTRIASS/GHOST/RECONCILIATION/v1",
        "SYNTRIASS/GHOST/WARRANT/v1",
        "SYNTRIASS/AIRI/EVENT/v1",
    ] {
        assert_ne!(ours, existing, "domain tag collides with {existing}");
    }
}

#[test]
fn the_binding_parameter_key_is_versioned_in_the_key() {
    // A v2 binding uses a different key, so a decision point that signed a v1
    // binding can never be read as having signed a v2 one. Versioning inside
    // the value would require every reader to remember to look.
    assert!(
        aip_execution::BINDING_PARAMETER_KEY.ends_with(".v1"),
        "the binding key must carry its version: {}",
        aip_execution::BINDING_PARAMETER_KEY
    );
    assert!(aip_execution::BINDING_PARAMETER_KEY.starts_with("aip."));
}

#[test]
fn the_stage_ladder_is_complete_and_ordered() {
    use aip_execution::{EvidenceOrigin, ExecutionStage};

    assert_eq!(ExecutionStage::ALL.len(), 12);
    // Ordered: each stage strictly follows the previous.
    for w in ExecutionStage::ALL.windows(2) {
        assert!(w[0] < w[1], "{:?} must precede {:?}", w[0], w[1]);
    }
    // Distinct wire codes.
    let mut codes: Vec<u8> = ExecutionStage::ALL.iter().map(|s| s.code()).collect();
    let n = codes.len();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(n, codes.len(), "stage codes must be distinct");

    // The four agent-authored stages are all SelfReported. This is the
    // machine-checkable form of "the agent holds the pen for all of these".
    for s in [
        ExecutionStage::AiClaim,
        ExecutionStage::ModelInvocation,
        ExecutionStage::ToolInvocation,
        ExecutionStage::RuntimeExecution,
    ] {
        assert_eq!(
            s.origin(),
            EvidenceOrigin::SelfReported,
            "SECURITY: {s:?} was classified as something other than a self-report"
        );
        assert!(!s.origin().can_establish_occurrence());
    }
    // And the observation stages are not.
    for s in [
        ExecutionStage::ExternalEffect,
        ExecutionStage::IndependentObservation,
    ] {
        assert!(s.origin().can_establish_occurrence());
    }
}
