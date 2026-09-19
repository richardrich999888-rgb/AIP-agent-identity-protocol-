//! The threat-model artifact generator (Skill 29).
//!
//! Usage: `cargo run -p aip-conformance --bin emit-threat-model -- <out-dir>`
//! (defaults to `docs/audit/`).

use std::path::PathBuf;

use aip_conformance::blocker::{inherited_blockers, open_blockers, BlockerStatus};
use aip_conformance::threat::{Disposition, Layer, Threat, ThreatModel};

fn main() -> std::io::Result<()> {
    let out: PathBuf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "docs/audit".to_string())
        .into();
    std::fs::create_dir_all(&out)?;

    let m = ThreatModel::build();
    let missing = m.missing();
    assert!(
        missing.is_empty(),
        "the model must be total; missing: {missing:?}"
    );

    std::fs::write(out.join("THREAT_MODEL_MATRIX.json"), m.to_json())?;
    std::fs::write(out.join("THREAT_MODEL_MATRIX.csv"), m.to_csv())?;

    println!(
        "Vanian autonomous-edge threat model (schema v{})",
        m.schema_version
    );
    println!(
        "{} threats x {} layers = {} cells",
        Threat::ALL.len(),
        Layer::ALL.len(),
        m.cells.len()
    );

    for d in [
        Disposition::Prevented,
        Disposition::Detected,
        Disposition::Uncertainty,
        Disposition::NotDetectable,
    ] {
        let n = m.cells.iter().filter(|c| c.disposition == d).count();
        println!("  {:<16} {n}", d.as_str());
    }

    // The gate: every high-impact threat needs a defence or a stated
    // uncertainty. A threat with neither is the failure condition.
    let unanswered = m.threats_with_no_answer();
    println!(
        "threats with no answer at all: {} {}",
        unanswered.len(),
        if unanswered.is_empty() {
            ""
        } else {
            "<-- GATE FAILURE"
        }
    );

    // Not a failure, but a reader should know which threats the system only
    // responds to by asserting less.
    let no_defence = m.threats_with_no_defence();
    println!("threats answered only by uncertainty: {}", no_defence.len());
    for t in &no_defence {
        println!("  {} {:?}", t.id(), t);
    }

    println!("\ninherited blockers:");
    for b in inherited_blockers() {
        println!("  {:<5} {:<26} {}", b.id, b.status.as_str(), b.finding);
    }
    let open = open_blockers();
    println!(
        "open: {} {}",
        open.len(),
        if open.is_empty() {
            String::new()
        } else {
            open.iter().map(|b| b.id).collect::<Vec<_>>().join(", ")
        }
    );
    assert!(
        inherited_blockers()
            .iter()
            .all(|b| b.status != BlockerStatus::ClosedNotVerifiedHere),
        "every blocker must be verified here or recorded open"
    );

    println!("-> {}", out.join("THREAT_MODEL_MATRIX.json").display());
    println!("-> {}", out.join("THREAT_MODEL_MATRIX.csv").display());
    Ok(())
}
