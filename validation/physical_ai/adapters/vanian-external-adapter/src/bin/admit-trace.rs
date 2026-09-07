//! `admit-trace` — run the admission gate over a collector's trace, offline.
//!
//! Reads an `observations.json` produced by a physical-observation collector,
//! classifies every record, and prints the verdict. It writes nothing back into
//! the trace: a re-derivation that could edit its own input would not be a
//! re-derivation.
//!
//! Exit status is 0 whenever the file was readable and every record was
//! classified. **A refusal is a successful classification**, not an error: the
//! whole point is that refusing is the correct answer most of the time, and a
//! non-zero exit would invite a caller to retry until it got an admission.
//!
//! Usage:
//!   admit-trace <trace-dir> [--posture Present|PresentAndSilent|Unavailable|IntegrityUnknown]
//!                           [--now-ms N] [--freshness-ms N]

use std::process::ExitCode;

use vanian_external_adapter::{
    admit, Admission, AdmissionLedger, AdmissionPolicy, ExternalObservation, ObserverPosture,
};

fn posture_from(name: &str) -> Option<ObserverPosture> {
    match name {
        "Present" => Some(ObserverPosture::Present),
        "PresentAndSilent" => Some(ObserverPosture::PresentAndSilent),
        "Unavailable" => Some(ObserverPosture::Unavailable),
        "IntegrityUnknown" => Some(ObserverPosture::IntegrityUnknown),
        _ => None,
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: admit-trace <trace-dir> [--posture P] [--now-ms N] [--freshness-ms N]");
        return ExitCode::from(2);
    }
    let dir = std::path::PathBuf::from(&args[0]);
    let mut posture = ObserverPosture::Present;
    let mut now_ms: Option<u64> = None;
    let mut freshness_ms: u64 = 30_000;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--posture" if i + 1 < args.len() => {
                match posture_from(&args[i + 1]) {
                    Some(p) => posture = p,
                    None => {
                        eprintln!("unknown posture: {}", args[i + 1]);
                        return ExitCode::from(2);
                    }
                }
                i += 2;
            }
            "--now-ms" if i + 1 < args.len() => {
                now_ms = args[i + 1].parse().ok();
                i += 2;
            }
            "--freshness-ms" if i + 1 < args.len() => {
                freshness_ms = match args[i + 1].parse() {
                    Ok(v) => v,
                    Err(_) => {
                        eprintln!("--freshness-ms wants an integer");
                        return ExitCode::from(2);
                    }
                };
                i += 2;
            }
            other => {
                eprintln!("unexpected argument: {other}");
                return ExitCode::from(2);
            }
        }
    }

    let path = dir.join("observations.json");
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot read {}: {e}", path.display());
            return ExitCode::from(2);
        }
    };
    let values: Vec<serde_json::Value> = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("cannot parse {}: {e}", path.display());
            return ExitCode::from(2);
        }
    };

    // The collector may emit non-observation notes (a frame with no detection
    // is a real result and is recorded as one). They are counted and skipped,
    // never coerced into observations.
    let mut ledger = AdmissionLedger::new();
    let (mut admitted, mut refused, mut notes, mut physical) = (0u32, 0u32, 0u32, 0u32);

    println!("trace: {}", dir.display());
    println!("posture: {posture:?}   freshness bound: {freshness_ms} ms");
    println!();

    for (n, value) in values.iter().enumerate() {
        let observation: ExternalObservation = match serde_json::from_value(value.clone()) {
            Ok(o) => o,
            Err(_) => {
                notes += 1;
                println!("  [{n}] NOTE (not an observation): {}", compact(value));
                continue;
            }
        };
        let now = now_ms.unwrap_or(observation.timestamp_ms);
        let verdict = admit(
            &observation,
            posture,
            now,
            AdmissionPolicy {
                freshness_bound_ms: freshness_ms,
            },
            &mut ledger,
        );
        if verdict.is_admitted() {
            admitted += 1;
        } else {
            refused += 1;
        }
        if verdict.supports_physical_effect() {
            physical += 1;
        }
        println!(
            "  [{n}] {:<18} {:<20} -> {}",
            format!("{:?}", observation.event_type),
            format!("{:?}", observation.provenance_class),
            describe(&verdict)
        );
    }

    println!();
    println!("admitted: {admitted}   refused: {refused}   notes: {notes}");
    println!("records supporting a physical-effect claim: {physical}");
    if physical == 0 {
        println!("PHYSICAL EFFECT: NOT ESTABLISHED — no source in this trace can carry the class");
    } else {
        // Unreachable in this build. Printed rather than asserted so that if a
        // future mechanism makes it reachable, the run says so out loud.
        println!("PHYSICAL EFFECT: {physical} record(s) claim support — verify the mechanism");
    }
    ExitCode::SUCCESS
}

fn describe(a: &Admission) -> String {
    match a {
        Admission::Refused { reason } => format!("REFUSED ({reason:?})"),
        Admission::AdmittedAsClaim { ceiling } => format!("CLAIM (ceiling {ceiling:?})"),
        Admission::AdmittedAsCorroboration { ceiling } => {
            format!("CORROBORATION (ceiling {ceiling:?})")
        }
        Admission::EligibleForObservationRecord { ceiling, mechanism } => {
            format!("ELIGIBLE (ceiling {ceiling:?}, mechanism {mechanism:?})")
        }
    }
}

fn compact(v: &serde_json::Value) -> String {
    let s = v.to_string();
    if s.len() > 96 {
        format!("{}…", &s[..96])
    } else {
        s
    }
}
