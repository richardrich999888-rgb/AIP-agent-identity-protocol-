//! There is exactly one reconciliation engine and one evidence-strength
//! vocabulary, and this crate is not either of them.
//!
//! Skill 22 forbids a second reconciler, a second verifier and any weakening
//! of `EvidenceStrength`. The strongest available check is not "we did not do
//! that" but "this crate cannot name the types you would need in order to".
//! These tests read `aip-edge`'s own source, with comments and doc comments
//! stripped, and assert the names are absent from the code.
//!
//! Stripping comments matters: this crate's documentation discusses
//! `ReconciliationResult` and `CANNOT_PROVE` at length, and a naive substring
//! search would either fail on the prose or be weakened until it passed.

mod common;

use common::strip_comments;
use std::path::{Path, PathBuf};

fn source_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    walk(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut out,
    );
    assert!(!out.is_empty(), "no source files found");
    out
}

#[test]
fn this_crate_constructs_no_reconciliation_result() {
    for path in source_files() {
        let code = strip_comments(&std::fs::read_to_string(&path).expect("read"));
        assert!(
            !code.contains("ReconciliationResult"),
            "{} names ReconciliationResult in code: a second thing that can produce a verdict \
             is a second thing that can be wrong about one",
            path.display()
        );
    }
}

#[test]
fn this_crate_constructs_no_evidence_strength() {
    for path in source_files() {
        let code = strip_comments(&std::fs::read_to_string(&path).expect("read"));
        assert!(
            !code.contains("EvidenceStrength"),
            "{} names EvidenceStrength in code: strength is per-record, computed, and assigned \
             by aip-reconcile alone",
            path.display()
        );
    }
}

#[test]
fn this_crate_calls_the_existing_engine_and_does_not_reimplement_it() {
    let code: String = source_files()
        .iter()
        .map(|p| strip_comments(&std::fs::read_to_string(p).expect("read")))
        .collect();
    assert!(
        code.contains("reconcile_expectation"),
        "the reference must drive the existing engine, not describe it"
    );
    // The other two entry points are the engine's own; a reference that called
    // them too would still be reusing it, but a reference that defined a
    // function whose name ends in `reconcile` would not be.
    assert!(
        !code.contains("fn reconcile_"),
        "this crate must define no reconciliation entry point of its own"
    );
}

#[test]
fn this_crate_defines_no_verdict_or_ceiling_vocabulary_of_its_own() {
    let code: String = source_files()
        .iter()
        .map(|p| strip_comments(&std::fs::read_to_string(p).expect("read")))
        .collect();
    for forbidden in [
        "enum EvidenceCeiling",
        "enum Completeness",
        "enum ObservationClass",
        "enum PlatformDisposition",
        "enum EffectFinding",
        "struct ObservationRecord",
        "struct PlatformBinding",
        "struct SystemExecution",
    ] {
        assert!(
            !code.contains(forbidden),
            "this crate defines `{forbidden}`: the reference adapts the existing model and \
             must not fork it"
        );
    }
}

#[test]
fn the_comment_stripper_does_not_defeat_the_guards() {
    // If `strip_comments` were broken toward emptiness every assertion above
    // would pass vacuously. Pin its behaviour on both sides.
    let src =
        "let a = 1; // ReconciliationResult\n/* EvidenceStrength */ let b = \"//not a comment\";";
    let out = strip_comments(src);
    assert!(!out.contains("ReconciliationResult"));
    assert!(!out.contains("EvidenceStrength"));
    assert!(out.contains("let a = 1;"));
    assert!(
        out.contains("//not a comment"),
        "a `//` inside a string literal is not a comment"
    );
}

#[test]
fn the_stripper_handles_non_ascii_comments() {
    // Byte slicing would panic here. The reference's own documentation uses
    // en dashes and box-drawing characters throughout.
    let src = "let x = 1; // ceiling — never Proven ─────\nlet y = 2;";
    let out = strip_comments(src);
    assert!(out.contains("let y = 2;"));
    assert!(!out.contains("Proven"));
}
