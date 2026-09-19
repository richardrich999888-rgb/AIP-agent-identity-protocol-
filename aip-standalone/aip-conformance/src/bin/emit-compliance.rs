//! Emit the regulatory control map (R18) and the DPDP field inventory
//! (R20).
//!
//! Both are artefacts a reviewer reads without running anything, and both
//! are deterministic: two runs over unchanged code produce identical bytes,
//! so a diff in a committed file is a change in the system rather than a
//! change in the run.
//!
//! Usage: `cargo run -p aip-conformance --bin emit-compliance -- <out-dir>`
//! (defaults to `docs/compliance/`).

use std::path::PathBuf;

use aip_conformance::dpdp;
use aip_conformance::regulatory::{self, Coverage, Instrument};

fn main() -> std::io::Result<()> {
    let out: PathBuf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "docs/compliance".to_string())
        .into();
    std::fs::create_dir_all(&out)?;

    let map = regulatory::control_map();
    std::fs::write(out.join("CONTROL_MAP.json"), regulatory::to_json())?;
    std::fs::write(out.join("CONTROL_MAP.csv"), regulatory::to_csv())?;
    std::fs::write(out.join("DPDP_FIELD_INVENTORY.json"), dpdp::to_json())?;
    std::fs::write(out.join("DPDP_FIELD_INVENTORY.csv"), dpdp::to_csv())?;

    println!("Regulatory control map: {} rows", map.len());
    for instrument in Instrument::ALL {
        let rows: Vec<_> = map.iter().filter(|r| r.instrument == instrument).collect();
        let gaps = rows
            .iter()
            .filter(|r| matches!(r.coverage, Coverage::None { .. }))
            .count();
        println!(
            "  {:<22} {:>2} rows, {gaps} stated gap(s)",
            instrument.as_str(),
            rows.len()
        );
    }

    // The number a reader should look at first. A map with no gaps is a map
    // that is not being honest about a system this young.
    let gaps: Vec<&str> = map
        .iter()
        .filter(|r| matches!(r.coverage, Coverage::None { .. }))
        .map(|r| r.control_id)
        .collect();
    println!("\nStated gaps ({}): {}", gaps.len(), gaps.join(", "));

    let entity: usize = map
        .iter()
        .filter(|r| matches!(r.coverage, Coverage::EntityResponsibility { .. }))
        .count();
    println!("Controls that belong to the regulated entity, not to this system: {entity}");

    println!(
        "\nDPDP field inventory: {} fields that leave the observed host",
        dpdp::inventory().len()
    );
    for risk in [
        dpdp::PersonalDataRisk::Direct,
        dpdp::PersonalDataRisk::PossibleByConfiguration,
        dpdp::PersonalDataRisk::IndirectViaHost,
        dpdp::PersonalDataRisk::None,
    ] {
        let n = dpdp::inventory().iter().filter(|r| r.risk == risk).count();
        println!("  {:<26} {n}", risk.as_str());
    }

    println!("\nwrote {}", out.display());
    Ok(())
}
