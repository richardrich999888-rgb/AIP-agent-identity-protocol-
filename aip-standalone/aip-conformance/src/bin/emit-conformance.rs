//! The audit artifact generator (Skill 28, R5).
//!
//! Writes the conformance matrix in two forms — JSON for a tool, CSV for a
//! reviewer with a spreadsheet — plus a short human summary on stdout. The
//! output is deterministic: two runs over unchanged code produce identical
//! bytes, so any diff in a committed artifact is a change in the system
//! rather than a change in the run.
//!
//! Usage: `cargo run -p aip-conformance --bin emit-conformance -- <out-dir>`
//! (defaults to `docs/audit/`).

use std::path::PathBuf;

use aip_conformance::{Conformance, ConformanceMatrix, Domain, EvidenceClass, InvariantCode};

fn main() -> std::io::Result<()> {
    let out: PathBuf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "docs/audit".to_string())
        .into();
    std::fs::create_dir_all(&out)?;

    let m = ConformanceMatrix::build();

    // A matrix with a hole is a matrix the reader completes by assumption.
    let missing = m.missing();
    assert!(
        missing.is_empty(),
        "the matrix must be total; missing: {missing:?}"
    );

    std::fs::write(out.join("CONFORMANCE_MATRIX.json"), m.to_json())?;
    std::fs::write(out.join("CONFORMANCE_MATRIX.csv"), m.to_csv())?;

    println!(
        "Vanian universal conformance matrix (schema v{})",
        m.schema_version
    );
    println!(
        "{} domains x {} invariants = {} cells",
        Domain::ALL.len(),
        InvariantCode::ALL.len(),
        m.cells.len()
    );

    // The count a reader should actually use. Seven names, five crates.
    let crates = Domain::distinct_crates();
    println!(
        "realised by {} distinct crates: {}",
        crates.len(),
        crates.join(", ")
    );
    println!("  (UGV and Robotics share aip-robotics; Industrial and Critical Edge share aip-industrial)");

    for c in EvidenceClass::ALL {
        let n = m.cells.iter().filter(|x| x.evidence == c).count();
        if n > 0 {
            println!("  {:<18} {n}", c.as_str());
        }
    }
    for s in [
        Conformance::Satisfied,
        Conformance::NotApplicable,
        Conformance::Unknown,
    ] {
        let n = m.cells.iter().filter(|x| x.conformance == s).count();
        println!("  {:<18} {n}", s.as_str());
    }

    let conformant = m.conformant_domains();
    println!(
        "conformant domains: {}/{}",
        conformant.len(),
        Domain::ALL.len()
    );
    let short = m.shortfalls();
    if short.is_empty() {
        println!("shortfalls: none");
    } else {
        println!("shortfalls: {}", short.len());
        for c in short {
            println!(
                "  {} {} {} ({})",
                c.domain.as_str(),
                c.invariant_id,
                c.conformance.as_str(),
                c.evidence.as_str()
            );
        }
    }
    println!("-> {}", out.join("CONFORMANCE_MATRIX.json").display());
    println!("-> {}", out.join("CONFORMANCE_MATRIX.csv").display());
    Ok(())
}
