//! `ot-verifier` — headless offline verification of certified mission
//! dossiers (`.json`), AIP forensic streams (`.jsonl`), and ML-DSA-signed
//! governance attestations.
//!
//! Exit codes: 0 = every check passed deterministically; 1 = integrity
//! breach, broken chain, corrupted signature — or, under `--strict`, any
//! warning (placeholder digests and other suspect-but-inconclusive facts).

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use ot_verifier::report::{Report, Severity};
use ot_verifier::verify::{verify_dossier, verify_packet_stream_reader};

#[derive(Parser)]
#[command(
    name = "ot-verifier",
    about = "Offline verifier for ASC SENTINEL certified mission dossiers, forensic streams, and signed attestations",
    version
)]
struct Args {
    /// Path to an exported .json mission dossier or .jsonl forensic stream.
    #[arg(
        long,
        required_unless_present = "attestation",
        conflicts_with = "attestation"
    )]
    dossier: Option<PathBuf>,

    /// Path to an ML-DSA-signed attestation envelope (a governance hub
    /// receipt or snapshot) to verify offline.
    #[arg(long)]
    attestation: Option<PathBuf>,

    /// Expected signer identity (64-hex), pinned out of band. With
    /// --attestation only; without it the signature still verifies but the
    /// signer is merely reported, not trusted.
    #[arg(long, requires = "attestation")]
    signer: Option<String>,

    /// Fail on any warning or deprecated/placeholder hash format.
    #[arg(long)]
    strict: bool,

    /// Emit a line-by-line verification trace of every anchor and packet.
    #[arg(short, long)]
    verbose: bool,

    /// Output verification results as machine-readable JSON on stdout.
    #[arg(long)]
    json: bool,
}

/// Verifies a signed attestation envelope and reports the verdict.
fn run_attestation(path: &PathBuf, args: &Args) -> ExitCode {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) => {
            eprintln!("[FAIL] cannot read {}: {err}", path.display());
            return ExitCode::from(1);
        }
    };
    let doc = match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(doc) => doc,
        Err(err) => {
            eprintln!("[FAIL] not valid JSON: {err}");
            return ExitCode::from(1);
        }
    };
    match ot_pqc::verify_attestation_json(&doc, args.signer.as_deref()) {
        Ok(verified) => {
            let pinned = args.signer.is_some();
            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "pass": true,
                        "signerIdentity": verified.signer_identity,
                        "signerPinned": pinned,
                        "context": verified.context,
                        "algorithm": verified.algorithm,
                        "payload": verified.payload,
                    }))
                    .expect("result serializes"),
                );
            } else {
                println!(
                    "[PASS] attestation verified — signer {}{} · context {} · {}",
                    verified.signer_identity,
                    if pinned {
                        " (pinned)"
                    } else {
                        " (unpinned: report, don't trust)"
                    },
                    verified.context,
                    verified.algorithm,
                );
            }
            ExitCode::from(0)
        }
        Err(err) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "pass": false,
                        "error": err.to_string(),
                    }))
                    .expect("result serializes"),
                );
            } else {
                println!("[FAIL] {err}");
            }
            ExitCode::from(1)
        }
    }
}

fn main() -> ExitCode {
    let args = Args::parse();

    if let Some(path) = &args.attestation {
        return run_attestation(path, &args);
    }
    let dossier_path = args
        .dossier
        .clone()
        .expect("clap enforces --dossier when --attestation is absent");

    let mut report = Report::default();
    let is_stream = dossier_path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"));

    if is_stream {
        // Forensic streams verify line by line in O(1) memory — a fleet
        // archive never needs to fit in RAM.
        match fs::File::open(&dossier_path) {
            Ok(file) => verify_packet_stream_reader(std::io::BufReader::new(file), &mut report),
            Err(err) => {
                eprintln!("[FAIL] cannot read {}: {err}", dossier_path.display());
                return ExitCode::from(1);
            }
        }
    } else {
        let text = match fs::read_to_string(&dossier_path) {
            Ok(text) => text,
            Err(err) => {
                eprintln!("[FAIL] cannot read {}: {err}", dossier_path.display());
                return ExitCode::from(1);
            }
        };
        match serde_json::from_str::<serde_json::Value>(&text) {
            Ok(dossier) => verify_dossier(&dossier, &mut report),
            Err(err) => report.fail("parse", format!("not valid JSON: {err}")),
        }
    }

    let passed = report.passed(args.strict);

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report.to_json(args.strict))
                .expect("report always serializes")
        );
    } else {
        if args.verbose {
            for line in &report.trace {
                println!("{line}");
            }
        }
        for finding in &report.findings {
            let tag = match finding.severity {
                Severity::Fail => "FAIL",
                Severity::Warn => "WARN",
                Severity::Info => "INFO",
            };
            println!("[{tag}] {}: {}", finding.step, finding.message);
        }
        println!(
            "[{}] {} anchors, {} packets, {} ledger entries — {} failure(s), {} warning(s){}",
            if passed { "PASS" } else { "FAIL" },
            report.stats.anchors,
            report.stats.packets,
            report.stats.ledger_entries,
            report.failures(),
            report.warnings(),
            if args.strict { " (strict)" } else { "" },
        );
    }

    ExitCode::from(if passed { 0 } else { 1 })
}
