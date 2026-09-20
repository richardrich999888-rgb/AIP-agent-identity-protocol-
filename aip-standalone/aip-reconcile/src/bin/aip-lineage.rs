//! `aip-lineage` — derive the observed delegation chain from a collector's
//! attested-batch archive, and print it deterministically.
//!
//! # The invariant this binary exists to enforce
//!
//! Lineage is derived **only from evidence that verified under the anchor**.
//! The binary first runs the same offline verification the auditor's
//! `aip-observe-verify` runs (every signature, then the chain that links the
//! records) and, if that finds anything wrong, it prints the findings and
//! exits without deriving a single edge. Deriving a delegation chain from
//! bytes that do not verify would be attributing execution on the strength of
//! an archive nobody signed — the exact failure the whole system refuses.
//! Fail closed: no proof, no edges.
//!
//! It reuses `aip-observe-verify` for parsing and verification and
//! `aip-reconcile` for the derivation and rendering; it invents no crypto and
//! no parsing of its own. The argument surface is identical to the verifier's,
//! minus `--health` (a health archive carries no lineage).
//!
//! EXIT STATUS:
//!   0  the archive verified and the delegation chain (possibly empty) printed
//!   1  the archive had findings; none derived (fail closed)
//!   2  the arguments could not be used

use std::process::ExitCode;

use aip_observe::AttestedBatch;
use aip_observe_verify::cli::{parse, Parse};
use aip_observe_verify::verify::{parse_jsonl, verify_archives, Parsed};
use aip_reconcile::{derive_lineage_edges, render_report};

const USAGE: &str = "\
aip-lineage — derive the observed delegation chain from an attested archive

USAGE:
    aip-lineage --observer-id <ID> --key-version <N> \
(--pubkey <HEX> | --pubkey-file <PATH>) --batches <PATH>

It verifies the archive offline under the anchor FIRST; only if every record
verifies and the chain links does it derive and print the delegation chain.
An archive with any finding derives nothing and exits 1.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("aip-lineage: {msg}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    let opts = match parse(args)? {
        Parse::Run(o) => *o,
        Parse::Help => {
            println!("{USAGE}");
            return Ok(ExitCode::SUCCESS);
        }
        Parse::Version => {
            println!("aip-lineage {}", env!("CARGO_PKG_VERSION"));
            return Ok(ExitCode::SUCCESS);
        }
    };

    // Lineage needs the batch archive specifically; --health carries none.
    let batches_path = opts
        .batches
        .ok_or("--batches <PATH> is required (the attested-batch archive)")?;
    let text = std::fs::read_to_string(&batches_path)
        .map_err(|e| format!("cannot read {}: {e}", batches_path.display()))?;

    let parsed: Vec<Parsed<AttestedBatch>> = parse_jsonl(&text);

    // Verify FIRST. `verify_archives` consumes the parsed vec, so clone the
    // successfully-parsed records now; a parse failure surfaces as a finding
    // below and stops derivation regardless.
    let verified_batches: Vec<AttestedBatch> = parsed
        .iter()
        .filter_map(|p| match p {
            Parsed::Ok(line) => Some(line.record.clone()),
            Parsed::Failed { .. } => None,
        })
        .collect();
    let batches_examined = verified_batches.len();

    let report = verify_archives(
        &opts.observer_id,
        opts.key_version,
        &opts.public_key,
        Some(parsed),
        None,
    );

    if !report.ok() {
        eprintln!("REFUSED: the archive did not verify under the anchor; no lineage derived.");
        for f in &report.findings {
            eprintln!("  finding: {f:?}");
        }
        return Ok(ExitCode::from(1));
    }

    // Only now — every record signed by the anchored key, chain intact — do
    // we derive the delegation chain.
    let edges = derive_lineage_edges(&verified_batches);
    print!("{}", render_report(edges, batches_examined));
    Ok(ExitCode::SUCCESS)
}
