use std::env;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use aip_wasm::samples::{generate_all_fixtures, self_verify_fixtures, AllFixtures};

fn find_out_dir() -> PathBuf {
    let args: Vec<String> = env::args().collect();
    for i in 1..args.len() {
        if args[i] == "--out-dir" && i + 1 < args.len() {
            return PathBuf::from(&args[i + 1]);
        }
    }

    // Try relative paths depending on where the binary is invoked from
    let candidates = [
        "aip-console/public/fixtures",
        "../../aip-console/public/fixtures",
        "../aip-console/public/fixtures",
    ];

    for c in &candidates {
        let p = Path::new(c);
        if p.exists() || p.parent().map(|par| par.exists()).unwrap_or(false) {
            return p.to_path_buf();
        }
    }

    PathBuf::from("aip-console/public/fixtures")
}

fn write_fixtures(fixtures: &AllFixtures, out_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    create_dir_all(out_dir)?;

    println!("Writing fixtures to: {:?}", out_dir.canonicalize().unwrap_or(out_dir.to_path_buf()));

    // 1. Honest Counterparty
    File::create(out_dir.join("honest_counterparty.json"))?
        .write_all(fixtures.honest_counterparty.packet.to_json()?.as_bytes())?;
    File::create(out_dir.join("honest_counterparty.context.json"))?
        .write_all(fixtures.honest_counterparty.context_json.as_bytes())?;

    // 2. Authority Bound
    File::create(out_dir.join("authority_bound.json"))?
        .write_all(fixtures.authority_bound.packet.to_json()?.as_bytes())?;
    File::create(out_dir.join("authority_bound.context.json"))?
        .write_all(fixtures.authority_bound.context_json.as_bytes())?;

    // 3. Agent Signed
    File::create(out_dir.join("agent_signed.json"))?
        .write_all(fixtures.agent_signed.packet.to_json()?.as_bytes())?;
    File::create(out_dir.join("agent_signed.context.json"))?
        .write_all(fixtures.agent_signed.context_json.as_bytes())?;

    // 4. Tampered Summary
    File::create(out_dir.join("tampered_summary.json"))?
        .write_all(fixtures.tampered_summary.packet.to_json()?.as_bytes())?;

    // 5. Tampered Hash
    File::create(out_dir.join("tampered_hash.json"))?
        .write_all(fixtures.tampered_hash.packet.to_json()?.as_bytes())?;

    // 6. Tampered Signature
    File::create(out_dir.join("tampered_signature.json"))?
        .write_all(fixtures.tampered_signature.packet.to_json()?.as_bytes())?;

    // 7. Scope Escalation
    File::create(out_dir.join("scope_escalation.json"))?
        .write_all(fixtures.scope_escalation.packet.to_json()?.as_bytes())?;

    // 8. Revoked Token
    File::create(out_dir.join("revoked_token.json"))?
        .write_all(fixtures.revoked_token.packet.to_json()?.as_bytes())?;
    File::create(out_dir.join("revoked_token.context.json"))?
        .write_all(fixtures.revoked_token.context_json.as_bytes())?;

    // 9. Valid Audit ZIP bundle
    File::create(out_dir.join("audit_bundle_valid.zip"))?
        .write_all(&fixtures.valid_bundle_zip)?;

    // 10. Tampered Audit ZIP bundle
    File::create(out_dir.join("audit_bundle_tampered.zip"))?
        .write_all(&fixtures.tampered_bundle_zip)?;

    // Catalog index.json
    File::create(out_dir.join("index.json"))?
        .write_all(fixtures.index_json.as_bytes())?;

    println!("All 10 fixtures + companion contexts + index.json successfully written.");
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== AIP Fixture Generator Pipeline ===");

    println!("Generating deterministic cryptographic fixtures...");
    let fixtures = generate_all_fixtures();

    println!("Running cryptographic self-verification on all fixtures...");
    self_verify_fixtures(&fixtures)?;
    println!("✓ Self-verification PASSED for all 10 fixtures (8 JSON + 2 ZIP).");

    let out_dir = find_out_dir();
    write_fixtures(&fixtures, &out_dir)?;

    let args: Vec<String> = env::args().collect();
    for i in 1..args.len() {
        if args[i] == "--also-e2e" && i + 1 < args.len() {
            let e2e_dir = PathBuf::from(&args[i + 1]);
            println!("Writing duplicate fixtures to e2e directory: {:?}", e2e_dir);
            write_fixtures(&fixtures, &e2e_dir)?;
        }
    }

    println!("✓ Fixture generation pipeline completed successfully.");
    Ok(())
}
