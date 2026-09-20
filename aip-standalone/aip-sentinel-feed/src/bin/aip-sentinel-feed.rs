//! `aip-sentinel-feed` — turn an attested AIP archive into an effect log.
//!
//! It verifies the archive under the observer's anchor **first**, exactly as
//! `aip-lineage` and `aip-corroborate` do, and emits nothing at all if that
//! fails. An effect log derived from unverified bytes would be a statement
//! about a file, not about a machine — and it would be handed to a detector
//! that raises critical findings from it.
//!
//! Exit status:
//!
//! * `0` — the archive verified and a feed was produced (possibly empty).
//! * `1` — the archive did not verify, or no batch could be read from it.
//! * `2` — bad arguments.
//!
//! The scope report goes to stderr so that `--out -` can be piped without the
//! diagnostics contaminating the log. It is not optional output: a reader who
//! sees only the records cannot tell an empty window from a blinded one.

use std::process::ExitCode;

use aip_observe::AttestedBatch;
use aip_observe_verify::verify::{parse_jsonl, verify_archives, Parsed};
use aip_sentinel_feed::feed;

const USAGE: &str = "\
aip-sentinel-feed — render attested AIP evidence as an out-of-band effect log

USAGE:
    aip-sentinel-feed --observer-id <ID> --key-version <N> --pubkey-file <PATH>
                      --batches <ARCHIVE> [--out <PATH>]

    --observer-id   the collector whose signature the archive must carry
    --key-version   which of that observer's keys
    --pubkey-file   hex-encoded ed25519 public key, as published
    --batches       attested archive, JSONL
    --out           where to write the effect log (default: stdout)

The archive is verified before anything is rendered. If verification fails,
no effect log is written and the exit status is 1.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("aip-sentinel-feed: {message}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn val(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s.trim()).map_err(|e| format!("--pubkey-file is not hex: {e}"))
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return Ok(ExitCode::SUCCESS);
    }
    let observer_id = val(args, "--observer-id").ok_or("--observer-id is required")?;
    let key_version: u32 = val(args, "--key-version")
        .ok_or("--key-version is required")?
        .parse()
        .map_err(|e| format!("--key-version: {e}"))?;
    let pubkey_file = val(args, "--pubkey-file").ok_or("--pubkey-file is required")?;
    let batches_path = val(args, "--batches").ok_or("--batches is required")?;
    let out_path = val(args, "--out");

    let pubkey = hex_decode(
        &std::fs::read_to_string(&pubkey_file)
            .map_err(|e| format!("cannot read {pubkey_file}: {e}"))?,
    )?;
    let archive = std::fs::read_to_string(&batches_path)
        .map_err(|e| format!("cannot read {batches_path}: {e}"))?;

    let parsed: Vec<Parsed<AttestedBatch>> = parse_jsonl(&archive);
    let verified: Vec<AttestedBatch> = parsed
        .iter()
        .filter_map(|p| match p {
            Parsed::Ok(line) => Some(line.record.clone()),
            Parsed::Failed { .. } => None,
        })
        .collect();

    // The gate. Nothing below this point runs on unverified bytes.
    let report = verify_archives(&observer_id, key_version, &pubkey, Some(parsed), None);
    if !report.ok() {
        eprintln!(
            "aip-sentinel-feed: refusing to render an effect log — {} did not verify under \
             {observer_id} key {key_version}:",
            batches_path
        );
        for finding in &report.findings {
            eprintln!("  - {finding:?}");
        }
        return Ok(ExitCode::from(1));
    }
    if verified.is_empty() {
        eprintln!("aip-sentinel-feed: {batches_path} contained no batch to render");
        return Ok(ExitCode::from(1));
    }

    let produced = feed(&verified);
    let jsonl = produced.to_jsonl(&observer_id);
    match out_path.as_deref() {
        None | Some("-") => print!("{jsonl}"),
        Some(path) => {
            std::fs::write(path, &jsonl).map_err(|e| format!("cannot write {path}: {e}"))?
        }
    }

    let scope = &produced.scope;
    eprintln!(
        "aip-sentinel-feed: {} batches verified; emitted {} records ({} spawn, {} egress, {} with \
         measured bytes); not rendered {} (fork without bound execution {}, exec start \
         unverified {}, connect attempt not established {}, no clock anchor {}, timestamp before \
         epoch {}, unbound: spawn {} exec {} connect {})",
        verified.len(),
        scope.emitted(),
        scope.spawns_emitted,
        scope.egress_emitted,
        scope.egress_with_measured_bytes,
        scope.dropped(),
        scope.fork_without_bound_execution,
        scope.exec_start_unverified,
        scope.connect_attempt_not_established,
        scope.dropped_no_clock_anchor,
        scope.dropped_timestamp_before_epoch,
        scope.spawn_unbound,
        scope.exec_unbound,
        scope.connect_initiation_unbound,
    );
    Ok(ExitCode::SUCCESS)
}
