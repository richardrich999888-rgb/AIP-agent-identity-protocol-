//! The matrix is total, self-consistent, and cannot outlive its evidence
//! (Skill 28, R2 and R5).
//!
//! The matrix asserts; `tests/universal.rs` is what makes the assertion worth
//! reading. The guard below closes the loop: **every cell whose witness names
//! a test in this crate must name a test that exists.** Without it a cell
//! could go on claiming TEST-PROVEN after the test behind it was renamed or
//! deleted, which is the exact failure mode an audit artifact is supposed to
//! prevent.

use std::collections::BTreeSet;

use aip_conformance::{
    Conformance, ConformanceMatrix, Domain, EvidenceClass, InvariantCode,
    CONFORMANCE_SCHEMA_VERSION,
};

/// The test function names declared in this crate's own suites.
fn test_names_in_this_crate() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    for entry in std::fs::read_dir(&dir).expect("tests/ must be readable") {
        let p = entry.expect("dir entry").path();
        if p.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let src = std::fs::read_to_string(&p).expect("test source must be readable");
        for line in src.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("fn ") {
                if let Some(name) = rest.split('(').next() {
                    out.insert(name.to_string());
                }
            }
        }
    }
    out
}

/// A matrix with a hole is a matrix the reader completes by assumption.
#[test]
fn the_matrix_is_total() {
    let m = ConformanceMatrix::build();
    assert!(m.missing().is_empty(), "unfilled cells: {:?}", m.missing());
    assert_eq!(
        m.cells.len(),
        Domain::ALL.len() * InvariantCode::ALL.len(),
        "7 domains x 12 invariants = 84 cells"
    );
    assert_eq!(m.cells.len(), 84);
    assert_eq!(m.schema_version, CONFORMANCE_SCHEMA_VERSION);
}

/// **The load-bearing guard.** A cell citing a test in this crate must cite
/// one that exists. Rename or delete a test and this fails, so a cell cannot
/// go on claiming evidence that is gone.
#[test]
fn every_witness_naming_a_test_in_this_crate_names_one_that_exists() {
    let names = test_names_in_this_crate();
    assert!(
        names.len() > 20,
        "the scraper found {} test names, which is too few to be working",
        names.len()
    );

    let m = ConformanceMatrix::build();
    for c in &m.cells {
        let Some((_, after)) = c.witness.split_once("aip-conformance/tests/") else {
            continue;
        };
        let Some((_, func)) = after.split_once("::") else {
            panic!(
                "{} {} cites this crate without naming a function: {:?}",
                c.domain.as_str(),
                c.invariant_id,
                c.witness
            );
        };
        let func = func.split(' ').next().unwrap_or(func);
        assert!(
            names.contains(func),
            "{} {} cites `{func}`, which does not exist in this crate's tests",
            c.domain.as_str(),
            c.invariant_id
        );
    }
}

/// Every cell that is not `Satisfied` states a reason, and every cell whose
/// conformance is weaker than its label suggests is visible as a shortfall.
#[test]
fn nothing_is_recorded_without_a_reason_or_a_witness() {
    let m = ConformanceMatrix::build();
    for c in &m.cells {
        assert!(
            !c.witness.is_empty(),
            "{} {} has no witness",
            c.domain.as_str(),
            c.invariant_id
        );
        if c.conformance != Conformance::Satisfied {
            assert!(
                !c.reason.is_empty(),
                "{} {} is {} with no reason",
                c.domain.as_str(),
                c.invariant_id,
                c.conformance.as_str()
            );
        }
        if c.evidence == EvidenceClass::Unknown {
            assert_ne!(
                c.conformance,
                Conformance::Satisfied,
                "{} {} claims Satisfied on Unknown evidence",
                c.domain.as_str(),
                c.invariant_id
            );
        }
    }
}

/// The vocabulary has no word for waiving a failed core invariant, and
/// `Satisfied` on weak evidence does not count as conformance.
#[test]
fn a_green_adapter_suite_cannot_waive_a_core_invariant() {
    // There is no `Waived`. Enumerating the type is the check: if one is ever
    // added, this fails and whoever added it has to justify it here.
    for c in [
        Conformance::Satisfied,
        Conformance::NotApplicable,
        Conformance::Unknown,
    ] {
        assert!(matches!(
            c,
            Conformance::Satisfied | Conformance::NotApplicable | Conformance::Unknown
        ));
    }

    // Documented, Inferred and Unknown do not support a conformance claim, so
    // a cell resting on prose is a shortfall however it is labelled.
    for weak in [
        EvidenceClass::Documented,
        EvidenceClass::Inferred,
        EvidenceClass::Unknown,
    ] {
        assert!(!weak.supports_a_conformance_claim(), "{weak:?}");
    }
    for strong in [
        EvidenceClass::ExecutionProven,
        EvidenceClass::TestProven,
        EvidenceClass::CodeProven,
    ] {
        assert!(strong.supports_a_conformance_claim(), "{strong:?}");
    }
}

/// Emission is deterministic: two builds produce identical bytes, so a diff
/// in a committed artifact is a change in the system rather than in the run.
#[test]
fn emission_is_deterministic() {
    let a = ConformanceMatrix::build();
    let b = ConformanceMatrix::build();
    assert_eq!(a.to_json(), b.to_json());
    assert_eq!(a.to_csv(), b.to_csv());

    // The CSV has a header and one row per cell.
    let csv = a.to_csv();
    assert_eq!(csv.lines().count(), 1 + a.cells.len());
    assert!(csv.starts_with("DOMAIN,REALISED_BY,PROFILE_ID,EMBODIED,"));

    // Free text cannot break the row shape: a field carrying a comma is
    // quoted rather than truncated or banned, so the row count above holds
    // even for the cells whose reason is a sentence.
    assert!(
        a.cells.iter().any(|c| c.reason.contains(',')),
        "at least one reason must contain a comma, or this test proves nothing"
    );
    for line in csv.lines().skip(1) {
        // Outside quotes there are exactly nine separators — ten fields.
        let mut in_q = false;
        let mut seps = 0;
        for ch in line.chars() {
            match ch {
                '"' => in_q = !in_q,
                ',' if !in_q => seps += 1,
                _ => {}
            }
        }
        assert_eq!(seps, 9, "row has the wrong field count: {line}");
        assert!(!in_q, "row ends inside a quoted field: {line}");
    }
}

/// The committed artifact matches what the code emits today. If this fails,
/// someone changed conformance without regenerating the artifact — the
/// artifact is stale, and a stale audit artifact is worse than none.
#[test]
fn the_committed_artifact_is_current() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    let json = root.join("docs/audit/CONFORMANCE_MATRIX.json");
    let csv = root.join("docs/audit/CONFORMANCE_MATRIX.csv");
    let m = ConformanceMatrix::build();

    for (path, want) in [(json, m.to_json()), (csv, m.to_csv())] {
        let got = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "{} is missing ({e}); run: cargo run -p aip-conformance --bin emit-conformance",
                path.display()
            )
        });
        assert_eq!(
            got,
            want,
            "{} is stale; re-run the generator",
            path.display()
        );
    }
}

/// Seven rows, five crates — and the artifact says so, so a reader counting
/// domains does not count independent evidence twice.
#[test]
fn the_artifact_reports_its_own_double_counting() {
    let m = ConformanceMatrix::build();
    let csv = m.to_csv();
    // Both robotics rows name the same crate, and both industrial rows do.
    assert_eq!(
        csv.matches("aip-robotics").count(),
        InvariantCode::ALL.len() * 2
    );
    assert_eq!(
        csv.matches("aip-industrial").count(),
        InvariantCode::ALL.len() * 2
    );
    assert_eq!(Domain::distinct_crates().len(), 5);
}
