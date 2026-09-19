//! R18 — the control map cannot claim a control it cannot show.
//!
//! A control map is read by someone deciding whether to believe a system.
//! The failure mode is not an incorrect row; it is a row that says
//! "implemented" and points at nothing, which no reader can distinguish from
//! one that points at something. So every claim is checked against the
//! repository, and every gap has to be a sentence rather than an omission.

use aip_conformance::regulatory::{control_map, to_csv, Coverage, Instrument};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The repository root, from this crate's manifest directory.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent() // aip-standalone
        .and_then(Path::parent) // repository root
        .expect("crate sits two levels below the repository root")
        .to_path_buf()
}

/// **The rule.** A row that claims a control names a file, and that file is
/// in the repository. Without this the map degrades into assertion.
#[test]
fn every_claimed_control_names_evidence_that_exists() {
    let root = repo_root();
    let mut missing = Vec::new();
    for row in control_map() {
        if let Some(path) = row.coverage.evidence_path() {
            if !root.join(path).exists() {
                missing.push(format!("{} -> {path}", row.control_id));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "these control rows point at files that are not in the repository:\n{}\n\
         A claim whose evidence has moved is a claim a reader cannot check.",
        missing.join("\n")
    );
}

/// A gap is stated, never omitted. A map whose gaps are missing reads as
/// complete, which is the one way it can mislead a regulator.
#[test]
fn every_gap_says_what_is_missing_and_what_would_close_it() {
    for row in control_map() {
        match &row.coverage {
            Coverage::None { note } => assert!(
                note.len() > 40,
                "{}: a gap must say what is missing and what would close it, got {note:?}",
                row.control_id
            ),
            Coverage::EntityResponsibility { note } => assert!(
                note.len() > 20,
                "{}: say whose control it is, got {note:?}",
                row.control_id
            ),
            _ => {}
        }
    }
}

/// The map must contain the gaps the coverage matrix already admits. This is
/// the test that stops the two documents drifting into disagreement, with
/// the control map quietly becoming the more flattering one.
#[test]
fn the_known_open_items_appear_as_gaps_not_as_claims() {
    let map = control_map();
    for id in [
        "ITG-BCP-DR",
        "ITG-INGRESS-SECURITY",
        "CERTIN-INCIDENT-REPORT-6H",
    ] {
        let row = map
            .iter()
            .find(|r| r.control_id == id)
            .unwrap_or_else(|| panic!("{id} must be in the map"));
        assert!(
            matches!(row.coverage, Coverage::None { .. }),
            "{id} is open in the coverage matrix and must read as a gap here, not {:?}",
            row.coverage.as_str()
        );
    }
}

/// Control identifiers are what an auditor cites, so they must be unique and
/// stable in shape.
#[test]
fn control_ids_are_unique_and_well_formed() {
    let map = control_map();
    let ids: BTreeSet<&str> = map.iter().map(|r| r.control_id).collect();
    assert_eq!(ids.len(), map.len(), "duplicate control id");
    for r in map {
        assert!(
            r.control_id
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-'),
            "{}: ids are upper-case and hyphenated so they survive a spreadsheet",
            r.control_id
        );
        assert!(
            r.requirement.len() > 30,
            "{}: state the requirement in the instrument's own terms",
            r.control_id
        );
        assert!(
            r.mechanism.len() > 30,
            "{}: state what addresses it, not a pointer",
            r.control_id
        );
    }
}

/// Every instrument the map indexes has at least one row. An instrument
/// listed in the vocabulary but absent from the map would suggest coverage
/// that was never written.
#[test]
fn every_instrument_has_at_least_one_row() {
    let map = control_map();
    for instrument in Instrument::ALL {
        assert!(
            map.iter().any(|r| r.instrument == instrument),
            "{} appears in the vocabulary with no rows",
            instrument.as_str()
        );
    }
}

/// Deterministic, ordered output, so a diff in the committed artefact is a
/// change in the system rather than a change in the run.
#[test]
fn the_emitted_artefact_is_stable_and_ordered() {
    assert_eq!(to_csv(), to_csv());
    let map = control_map();
    let keys: Vec<(String, &str)> = map
        .iter()
        .map(|r| (r.instrument.as_str().to_string(), r.control_id))
        .collect();
    let mut sorted = keys.clone();
    sorted.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(b.1)));
    // Ordering is by the enum's declaration order, then control id — not
    // alphabetical by name, so compare on the same key the map sorts with.
    let mut by_decl: Vec<(usize, &str)> = map
        .iter()
        .map(|r| {
            (
                Instrument::ALL
                    .iter()
                    .position(|i| *i == r.instrument)
                    .unwrap(),
                r.control_id,
            )
        })
        .collect();
    let original = by_decl.clone();
    by_decl.sort();
    assert_eq!(
        original, by_decl,
        "rows must be ordered by instrument then id"
    );

    let csv = to_csv();
    assert!(csv.starts_with("INSTRUMENT,CONTROL_ID,REQUIREMENT,MECHANISM,COVERAGE,EVIDENCE\n"));
    assert_eq!(
        csv.lines().count(),
        map.len() + 1,
        "one line per row plus the header; a comma in a cell must not split a line"
    );
}

/// The map states facts about this repository, not compliance opinions. A
/// row that claimed a direction was *satisfied* would be a judgement this
/// crate is not entitled to make.
#[test]
fn no_row_claims_compliance() {
    for r in control_map() {
        let text = format!("{} {}", r.requirement, r.mechanism).to_lowercase();
        for word in [
            "compliant",
            "complies",
            "fully meets",
            "satisfies the direction",
        ] {
            assert!(
                !text.contains(word),
                "{}: `{word}` is a compliance opinion; this map reports mechanisms and evidence",
                r.control_id
            );
        }
    }
}
