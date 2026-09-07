//! The offline NEXORA verifier.
//!
//!     nexora-verify --proof <file> --anchors <file> [options]
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
//!
//! The remaining options are the verifier's own judgement, and they are on
//! the command line for the same reason the anchors are in a separate file:
//! `import_anchors` deliberately refuses to carry them, so a package cannot
//! tell a verifier what it will accept or what time it is. Without them the
//! verifier applies no bound at all — it re-derives under whatever
//! parameters the package declares — so a deployment that cares about
//! staleness must state its limits here.
//!
//!     --max-health-age-ms <n>        refuse a package reconciled under a
//!                                    larger health_max_age_ms than this
//!     --max-window-tolerance-ms <n>  the same for window_tolerance_ms
//!     --now-ms <n>                   this verifier's present time, used
//!                                    only to report whether the authority
//!                                    behind the execution has since
//!                                    expired. It never changes the verdict
//!                                    and never grants anything.

use std::process::ExitCode;

use aip_nexora::export::{import_anchors, import_proof};
use aip_nexora::verify::{verify_nexora_proof, ProofVerdict};

fn main() -> ExitCode {
    let mut proof_path: Option<String> = None;
    let mut anchors_path: Option<String> = None;
    let mut json = false;
    let mut max_health_age: Option<u64> = None;
    let mut max_window_tolerance: Option<u64> = None;
    let mut now_ms: Option<u64> = None;
    let mut args = std::env::args().skip(1);
    let number = |args: &mut dyn Iterator<Item = String>, flag: &str| -> Option<u64> {
        match args.next().map(|v| v.parse::<u64>()) {
            Some(Ok(n)) => Some(n),
            _ => {
                eprintln!("{flag} needs a whole number of milliseconds");
                None
            }
        }
    };
    while let Some(a) = args.next() {
        match a.as_str() {
            "--proof" => proof_path = args.next(),
            "--anchors" => anchors_path = args.next(),
            "--json" => json = true,
            "--max-health-age-ms" => match number(&mut args, "--max-health-age-ms") {
                Some(n) => max_health_age = Some(n),
                None => return ExitCode::from(2),
            },
            "--max-window-tolerance-ms" => match number(&mut args, "--max-window-tolerance-ms") {
                Some(n) => max_window_tolerance = Some(n),
                None => return ExitCode::from(2),
            },
            "--now-ms" => match number(&mut args, "--now-ms") {
                Some(n) => now_ms = Some(n),
                None => return ExitCode::from(2),
            },
            "--help" | "-h" => {
                println!("nexora-verify --proof <file> --anchors <file> [options]");
                println!("  --json                         machine-readable output");
                println!("  --max-health-age-ms <n>        refuse a larger declared health age");
                println!("  --max-window-tolerance-ms <n>  refuse a larger declared tolerance");
                println!("  --now-ms <n>                   this verifier's present time");
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
    let mut anchors = match std::fs::read(&anchors_path).map_err(|e| e.to_string()) {
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

    // The verifier's own terms, applied after the anchor file is read so
    // that nothing in the file can set or widen them.
    anchors.max_declared_health_age_ms = max_health_age;
    anchors.max_declared_window_tolerance_ms = max_window_tolerance;
    anchors.present_time_ms = now_ms;

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
        // Where the authority behind the execution stands at the time this
        // verifier was told it is. Reported beside the verdict and never
        // folded into it: what happened does not stop having happened when
        // the authority expires, and no value of this grants anything.
        println!("authority_standing={:?}", v.authority_standing);
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
