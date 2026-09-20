//! `aip-corroborate` — compare an AIP attested archive against a third-party
//! runtime observer's output, and print where they agree and where they do not.
//!
//! It verifies the archive under the anchor first, exactly as `aip-lineage`
//! does, and refuses to corroborate evidence that does not verify: a
//! corroboration report over unverified bytes would be a statement about a
//! file, not about the system.
//!
//! Exit status is deliberately NOT a pass/fail grade on agreement. It is 0
//! whenever a report was produced, 1 when the archive did not verify or the
//! comparison was refused, and 2 on bad arguments. Whether the disagreement in
//! a report is acceptable is a judgement for the reader, not a threshold this
//! tool applies to itself.

use std::process::ExitCode;

use aip_corroborate::{
    corroborate, parse_auditd, parse_bpftrace, CorroborateError, ExternalSource, Parsed,
    DEFAULT_MATCH_WINDOW_MS,
};
use aip_observe::AttestedBatch;
use aip_observe_verify::verify::{parse_jsonl, verify_archives, Parsed as ParsedLine};

const USAGE: &str = "\
aip-corroborate — compare AIP's attested evidence with an independent observer

USAGE:
    aip-corroborate --observer-id <ID> --key-version <N> --pubkey-file <PATH>
                    --batches <ARCHIVE> --external <FILE> --source <bpftrace|auditd>
                    [--window-ms <N>] [--from-ms <N> --to-ms <N>] [--json]

    --source          which third-party observer produced --external
    --window-ms       pairing tolerance in ms (default 250)
    --from-ms/--to-ms the observer's own run window, wall-clock ms. Supply it:
                      without it the window is inferred from the observer's
                      first and last event, which excuses AIP for anything the
                      observer missed at the edges of its run.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(c) => c,
        Err(m) => {
            eprintln!("aip-corroborate: {m}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn val(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
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
    let external_path = val(args, "--external").ok_or("--external is required")?;
    let source = match val(args, "--source")
        .ok_or("--source is required")?
        .as_str()
    {
        "bpftrace" => ExternalSource::Bpftrace,
        "auditd" => ExternalSource::Auditd,
        other => return Err(format!("unknown --source {other:?} (bpftrace|auditd)")),
    };
    let window_ms: i64 = match val(args, "--window-ms") {
        Some(v) => v.parse().map_err(|e| format!("--window-ms: {e}"))?,
        None => DEFAULT_MATCH_WINDOW_MS,
    };
    let external_window = match (val(args, "--from-ms"), val(args, "--to-ms")) {
        (Some(a), Some(b)) => Some((
            a.parse::<i64>().map_err(|e| format!("--from-ms: {e}"))?,
            b.parse::<i64>().map_err(|e| format!("--to-ms: {e}"))?,
        )),
        (None, None) => None,
        _ => return Err("--from-ms and --to-ms must be given together".into()),
    };
    let json = args.iter().any(|a| a == "--json");

    let key_hex = std::fs::read_to_string(&pubkey_file)
        .map_err(|e| format!("cannot read {pubkey_file}: {e}"))?;
    let key = decode_hex(key_hex.trim())?;
    let archive = std::fs::read_to_string(&batches_path)
        .map_err(|e| format!("cannot read {batches_path}: {e}"))?;
    let external_text = std::fs::read_to_string(&external_path)
        .map_err(|e| format!("cannot read {external_path}: {e}"))?;

    // Verify first; corroborating unverified bytes proves nothing.
    let parsed: Vec<ParsedLine<AttestedBatch>> = parse_jsonl(&archive);
    let verified: Vec<AttestedBatch> = parsed
        .iter()
        .filter_map(|p| match p {
            ParsedLine::Ok(l) => Some(l.record.clone()),
            ParsedLine::Failed { .. } => None,
        })
        .collect();
    let report = verify_archives(&observer_id, key_version, &key, Some(parsed), None);
    if !report.ok() {
        eprintln!("REFUSED: the archive did not verify under the anchor; nothing corroborated.");
        for f in &report.findings {
            eprintln!("  finding: {f:?}");
        }
        return Ok(ExitCode::from(1));
    }

    let Parsed { events, unparsed } = match source {
        ExternalSource::Bpftrace => parse_bpftrace(&external_text),
        ExternalSource::Auditd => parse_auditd(&external_text),
        ExternalSource::Falco => return Err("falco adapter not implemented".into()),
    };

    match corroborate(&verified, &events, external_window, window_ms, unparsed) {
        Ok(c) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&c).map_err(|e| e.to_string())?
                );
            } else {
                print!("{}", render(&c));
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(e @ (CorroborateError::NoOverlap | CorroborateError::NoExternalEvents)) => {
            eprintln!("REFUSED: {e}");
            Ok(ExitCode::from(1))
        }
        Err(e) => {
            eprintln!("REFUSED: {e}");
            Ok(ExitCode::from(1))
        }
    }
}

fn render(c: &aip_corroborate::Corroboration) -> String {
    use std::fmt::Write as _;
    let mut o = String::new();
    let _ = writeln!(o, "INDEPENDENT CORROBORATION");
    let _ = writeln!(o, "third-party observer : {}", c.source.name());
    let _ = writeln!(
        o,
        "independence         : {:?}{}",
        c.independence,
        match c.independence {
            aip_corroborate::IndependenceClass::DifferentMechanism =>
                "  (different kernel subsystem; survives a gate on AIP's mechanism)",
            aip_corroborate::IndependenceClass::SameMechanism =>
                "  (independent implementation, same kernel mechanism; a gate on it blinds both)",
        }
    );
    let _ = writeln!(
        o,
        "window compared (ms) : {} .. {}  ({} ms)",
        c.window_from_ms,
        c.window_to_ms,
        c.window_to_ms - c.window_from_ms
    );
    let _ = writeln!(o, "pairing tolerance    : +/- {} ms", c.match_window_ms);
    let _ = writeln!(o, "---");
    let _ = writeln!(o, "agreed (both saw it)        : {}", c.agreed.len());
    let _ = writeln!(o, "AIP only                    : {}", c.aip_only.len());
    let _ = writeln!(o, "THIRD-PARTY ONLY (AIP gap)  : {}", c.external_only.len());
    if c.external_unparsed > 0 {
        let _ = writeln!(
            o,
            "unparsed observer lines     : {}  <-- this report is INCOMPLETE",
            c.external_unparsed
        );
    }
    if c.external_failed_attempts > 0 {
        let _ = writeln!(
            o,
            "failed execve ATTEMPTS       : {}  (excluded: nothing executed)",
            c.external_failed_attempts
        );
    }
    let _ = writeln!(
        o,
        "agreement                   : {:.1}%",
        c.agreement_ratio() * 100.0
    );
    let _ = writeln!(o, "---");
    if c.external_only.is_empty() {
        let _ = writeln!(
            o,
            "NO AIP BLIND SPOT: every execution the independent observer recorded inside the\n\
             window AIP claims to have covered is present in AIP's signed evidence."
        );
    } else {
        let _ = writeln!(
            o,
            "AIP BLIND SPOT: the independent observer recorded {} execution(s) inside a window\n\
             AIP claims to have covered, which are absent from AIP's signed evidence. Each is\n\
             listed below and is a defect to explain, not to discount.",
            c.external_only.len()
        );
        for e in &c.external_only {
            let _ = writeln!(o, "  MISSING  pid={} image={:?}", e.pid, e.image);
        }
    }
    if !c.aip_only.is_empty() {
        let _ = writeln!(
            o,
            "---\nAIP recorded {} execution(s) the third-party observer did not. This is not by\n\
             itself a defect: the observers are configured for different scopes, and the\n\
             third-party tracer starts and stops as a process of its own.",
            c.aip_only.len()
        );
    }
    if c.external_failed_attempts > 0 {
        let _ = writeln!(
            o,
            "---\nScope difference (not a defect): the independent observer also recorded {} failed\n\
             execve ATTEMPT(s) — a $PATH search producing ENOENT, for example. Nothing executed,\n\
             so AIP's scheduler tracepoint correctly does not report them and they are excluded\n\
             from the comparison above. auditd sees attempts; AIP sees executions.",
            c.external_failed_attempts
        );
    }
    let _ = writeln!(
        o,
        "---\nThis compares reported executions. It does not make the host kernel trustworthy:\n\
         a sufficiently privileged attacker may deceive both observers, and where both read\n\
         the same kernel mechanism, one gate blinds both."
    );
    o
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("public key hex has odd length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
