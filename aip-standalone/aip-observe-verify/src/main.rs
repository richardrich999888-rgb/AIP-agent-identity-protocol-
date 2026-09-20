//! The IO shell: read the archives, call the pure core, render, exit.
//!
//! Everything that decides anything lives in [`aip_observe_verify::verify`].
//! This file opens files, writes to stdout and picks an exit code, and does
//! no verification of its own.

use std::process::ExitCode;

use aip_observe::{AttestedBatch, SignedSensorHealth};
use aip_observe_verify::cli::{self, Options, Parse, USAGE};
use aip_observe_verify::report::{ChainReport, ChainStart, Finding};
use aip_observe_verify::verify::{parse_jsonl, verify_archives, Parsed};

/// Arguments unusable. Distinct from 1 so a script can tell "I invoked it
/// wrongly" from "the evidence did not verify" — conflating those two is how
/// a broken harness reports clean runs.
const EXIT_USAGE: u8 = 2;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match cli::parse(&argv) {
        Ok(Parse::Help) => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Parse::Version) => {
            println!("aip-observe-verify {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(Parse::Run(opts)) => match run(&opts) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("aip-observe-verify: {e}");
                ExitCode::from(EXIT_USAGE)
            }
        },
        Err(e) => {
            eprintln!("aip-observe-verify: {e}\n");
            eprint!("{USAGE}");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

fn read(path: &std::path::Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

fn run(opts: &Options) -> Result<ExitCode, String> {
    let batches: Option<Vec<Parsed<AttestedBatch>>> = match &opts.batches {
        Some(p) => Some(parse_jsonl(&read(p)?)),
        None => None,
    };
    let health: Option<Vec<Parsed<SignedSensorHealth>>> = match &opts.health {
        Some(p) => Some(parse_jsonl(&read(p)?)),
        None => None,
    };

    let report = verify_archives(
        &opts.observer_id,
        opts.key_version,
        &opts.public_key,
        batches,
        health,
    );

    if opts.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        print_text(&report);
    }

    Ok(if report.ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn print_text(r: &ChainReport) {
    println!(
        "observer   : {} (key version {})",
        r.observer_id, r.key_version
    );
    println!("anchor     : {}", r.public_key);

    if let Some(b) = &r.batches {
        println!();
        println!("ATTESTED BATCHES");
        println!("  records            : {}", b.records);
        match (b.first_sequence, b.last_sequence) {
            (Some(f), Some(t)) => println!("  chain positions    : {f}..={t}"),
            _ => println!("  chain positions    : none"),
        }
        match b.start {
            Some(ChainStart::Epoch) => {
                println!("  chain start        : the observer's epoch (complete from origin)")
            }
            Some(ChainStart::MidChain) => println!(
                "  chain start        : mid-chain — this file is a window; what preceded it \
                 was not seen"
            ),
            None => {}
        }
        println!(
            "  final head         : {}",
            b.final_head.as_deref().unwrap_or("-")
        );
        println!("  observations       : {}", b.observations);
        println!("  kernel events      : {}", b.kernel_events);
    }

    if let Some(h) = &r.health {
        println!();
        println!("SIGNED HEALTH");
        println!("  records            : {}", h.records);
        println!("  states signed      : {}", h.states.join(", "));
        println!("  asserting coverage : {}", h.with_coverage);
        println!("  asserting none     : {}", h.without_coverage);
        println!(
            "  heads cross-checked against batches : {}",
            h.cross_checked_against_batches
        );
        // Protocol 12. Stated, never judged: the acceptable error bound is
        // the institution's policy. The three counts are kept apart on
        // purpose -- "said its clock was steered", "said it was not", and
        // "said nothing" are three different facts, and an auditor needs the
        // third not to disappear into the first.
        println!(
            "  clock, steered / adrift / not stated : {} / {} / {}",
            h.clock_synchronised, h.clock_unsynchronised, h.clock_not_stated
        );
        match h.clock_worst_max_error_us {
            Some(us) => println!(
                "  worst error bound the collector signed : {us} us ({:.1} ms)",
                us as f64 / 1000.0
            ),
            None => println!(
                "  worst error bound the collector signed : none stated (pre-protocol-12 \
                 records, or a collector with no clock source)"
            ),
        }
    }

    println!();
    if r.ok() {
        println!("VERIFIED");
        println!(
            "The anchored observer key signed exactly these records, in this order, and each \
             record's prev_head equals the recomputed head of the one before it."
        );
        println!(
            "This does not mean the observations are true: a host with root can lie to its own \
             probe. It means these bytes are what the off-host collector received and recorded, \
             and that nothing has been added, removed or altered since."
        );
    } else {
        println!("NOT VERIFIED — {} finding(s)", r.findings.len());
        for f in &r.findings {
            println!("  {}", describe(f));
        }
    }
}

/// One line per finding, naming the record and what is wrong with it.
fn describe(f: &Finding) -> String {
    match f {
        Finding::Unparseable { line, error } => {
            format!("line {line}: not a valid record: {error}")
        }
        Finding::SignatureRejected {
            line,
            sequence,
            error,
        } => format!("line {line} (sequence {sequence}): signature rejected: {error}"),
        Finding::SequenceNotContiguous {
            line,
            expected,
            found,
        } => format!(
            "line {line}: chain position {found} where {expected} was expected — a record is \
             missing, repeated or out of order"
        ),
        Finding::ChainBroken {
            line,
            sequence,
            expected_prev_head,
            found_prev_head,
        } => format!(
            "line {line} (sequence {sequence}): prev_head {found_prev_head} does not match the \
             recomputed head {expected_prev_head} of the preceding record — the chain is forked \
             or spliced"
        ),
        Finding::HealthHeadMismatch {
            sequence,
            health_head,
            batch_head,
        } => format!(
            "sequence {sequence}: the signed health record states head {health_head} but the \
             attested batch at that position computes to {batch_head} — two signed answers about \
             one chain position"
        ),
        Finding::HealthHeadHasNoBatch { sequence } => format!(
            "sequence {sequence}: a signed health record names this chain position and the batch \
             archive, which covers it, has no batch there — a record was removed"
        ),
        Finding::Empty { what } => {
            format!("the {what} archive holds no records; there is nothing to verify")
        }
    }
}
