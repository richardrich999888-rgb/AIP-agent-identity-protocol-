//! The offline NEXORA verifier.
//!
//!     nexora-verify --proof <file> --anchors <file> [--json]
//!
//! Reads a proof package and a set of trust anchors, and prints what the
//! package establishes. It opens no socket, contacts no service, reads no
//! database and needs no relationship to the system that produced the
//! proof — the two files and the code are the whole input.
//!
//! The anchors are a separate file on purpose. A verifier that took its
//! trust from beside the artifact it is checking would have verified
//! nothing; in a deployment it provisions them itself, and this flag
//! exists so the same binary can be pointed at whatever it already holds.

use std::process::ExitCode;

use aip_nexora::export::{import_anchors, import_proof};
use aip_nexora::verify::{verify_nexora_proof, ProofVerdict};

fn main() -> ExitCode {
    let mut proof_path: Option<String> = None;
    let mut anchors_path: Option<String> = None;
    let mut json = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--proof" => proof_path = args.next(),
            "--anchors" => anchors_path = args.next(),
            "--json" => json = true,
            "--help" | "-h" => {
                println!("nexora-verify --proof <file> --anchors <file> [--json]");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument {other}");
                return ExitCode::from(2);
            }
        }
    }
    let (Some(proof_path), Some(anchors_path)) = (proof_path, anchors_path) else {
        eprintln!("both --proof and --anchors are required");
        return ExitCode::from(2);
    };

    let proof = match std::fs::read(&proof_path).map_err(|e| e.to_string()) {
        Ok(bytes) => match import_proof(&bytes) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{proof_path}: {e}");
                return ExitCode::from(2);
            }
        },
        Err(e) => {
            eprintln!("{proof_path}: {e}");
            return ExitCode::from(2);
        }
    };
    let anchors = match std::fs::read(&anchors_path).map_err(|e| e.to_string()) {
        Ok(bytes) => match import_anchors(&bytes) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("{anchors_path}: {e}");
                return ExitCode::from(2);
            }
        },
        Err(e) => {
            eprintln!("{anchors_path}: {e}");
            return ExitCode::from(2);
        }
    };

    let v = verify_nexora_proof(&proof, &anchors);
    if json {
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
    } else {
        let hex: String = v.proof_id.iter().map(|b| format!("{b:02x}")).collect();
        println!("proof_id={hex}");
        println!(
            "verdict={}",
            match &v.verdict {
                ProofVerdict::Valid => "Valid".to_string(),
                ProofVerdict::Invalid(r) => format!("Invalid({r})"),
            }
        );
        match (&v.result, &v.strength) {
            (Some(r), Some(s)) => {
                println!("result={r:?}");
                println!("strength={s:?}");
            }
            _ => println!("result=<not derivable from this package>"),
        }
        println!("coverage={:?}", v.coverage.observation);
        println!("completeness={:?}", v.coverage.completeness);
        println!("continuity={:?}", v.continuity_standing);
        println!("independence={:?}", v.independence);
        println!(
            "lineage: identity={:?} authority={:?} process={:?}",
            v.lineage_report.identity, v.lineage_report.authority, v.lineage_report.process
        );
        for (name, verdict) in [
            ("subject", &v.subject),
            ("authority", &v.authority),
            ("expectation", &v.expectation),
            ("observer", &v.observer),
            ("continuity", &v.continuity),
            ("lineage", &v.lineage),
            ("warrant", &v.warrant),
            ("commitment", &v.commitment),
            ("envelope", &v.envelope),
        ] {
            println!("  {name:<12} {verdict:?}");
        }
        if let Some(who) = &v.assembled_by {
            println!("assembled_by={who}");
        }
        println!();
        println!("This states what the package supports about a past execution.");
        println!("It is not authority to act now.");
    }
    if v.is_valid() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
