//! `aip-spiffe-check` — compare SPIRE's workload identity assertion against
//! AIP's attested evidence for the same process.
//!
//! It verifies the AIP archive under its anchor FIRST and refuses to compare
//! anything if that fails: a comparison against unverified bytes is a statement
//! about a file, not about the system.
//!
//! Exit status reports whether a comparison could be made, not whether the
//! answer was flattering: 0 when a comparison was produced (agreeing or not),
//! 1 when the archive did not verify, 2 on bad arguments.

use std::process::ExitCode;

use aip_observe::AttestedBatch;
use aip_observe_verify::verify::{parse_jsonl, verify_archives, Parsed};
use aip_spiffe::{compare_workload_identity, parse_assertion, parse_entry_show};

const USAGE: &str = "\
aip-spiffe-check — SPIRE's identity assertion vs AIP's measurement

USAGE:
    aip-spiffe-check --observer-id <ID> --key-version <N> --pubkey-file <PATH>
                     --batches <ARCHIVE> --svid <SVID.JSON> --entries <ENTRY_SHOW.TXT>
                     [--json]

    --svid     the sidecar's JSON (what SPIRE issued to the workload)
    --entries  `spire-server entry show` output (SPIRE's own registry record)
";

fn val(a: &[String], f: &str) -> Option<String> {
    a.iter()
        .position(|x| x == f)
        .and_then(|i| a.get(i + 1).cloned())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(c) => c,
        Err(m) => {
            eprintln!("aip-spiffe-check: {m}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
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
    let svid_path = val(args, "--svid").ok_or("--svid is required")?;
    let entries_path = val(args, "--entries").ok_or("--entries is required")?;
    let json = args.iter().any(|a| a == "--json");

    let key_hex = std::fs::read_to_string(&pubkey_file)
        .map_err(|e| format!("cannot read {pubkey_file}: {e}"))?;
    let key = decode_hex(key_hex.trim())?;
    let archive = std::fs::read_to_string(&batches_path)
        .map_err(|e| format!("cannot read {batches_path}: {e}"))?;
    let svid_json =
        std::fs::read_to_string(&svid_path).map_err(|e| format!("cannot read {svid_path}: {e}"))?;
    let entries_txt = std::fs::read_to_string(&entries_path)
        .map_err(|e| format!("cannot read {entries_path}: {e}"))?;

    let parsed: Vec<Parsed<AttestedBatch>> = parse_jsonl(&archive);
    let verified: Vec<AttestedBatch> = parsed
        .iter()
        .filter_map(|p| match p {
            Parsed::Ok(l) => Some(l.record.clone()),
            Parsed::Failed { .. } => None,
        })
        .collect();
    let report = verify_archives(&observer_id, key_version, &key, Some(parsed), None);
    if !report.ok() {
        eprintln!("REFUSED: the AIP archive did not verify under the anchor; nothing compared.");
        for f in &report.findings {
            eprintln!("  finding: {f:?}");
        }
        return Ok(ExitCode::from(1));
    }

    let assertion = parse_assertion(&svid_json)?;
    let registry = parse_entry_show(&entries_txt);
    let outcome = compare_workload_identity(&assertion, &registry, &verified);

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&outcome).map_err(|e| e.to_string())?
        );
    } else {
        print!("{}", render(&assertion, &registry, &outcome));
    }
    Ok(ExitCode::SUCCESS)
}

fn render(
    a: &aip_spiffe::WorkloadIdentityAssertion,
    r: &aip_spiffe::Registry,
    o: &aip_spiffe::WorkloadIdentityComparison,
) -> String {
    use aip_spiffe::WorkloadIdentityComparison as C;
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "WORKLOAD IDENTITY CROSS-CHECK");
    let _ = writeln!(s, "asserting authority : SPIRE (unix workload attestor)");
    let _ = writeln!(
        s,
        "measuring authority : AIP (kernel probe + off-host collector)"
    );
    let _ = writeln!(s, "SPIFFE ID           : {}", a.spiffe_id);
    let _ = writeln!(s, "pid                 : {}", a.pid);
    let _ = writeln!(s, "registry entries    : {}", r.len());
    let _ = writeln!(s, "---");
    match o {
        C::Agrees {
            digest_hex,
            other_selectors,
            ..
        } => {
            let _ = writeln!(
                s,
                "AGREES\nBoth authorities independently measured the same executable for this\n\
                 process instance:\n  {digest_hex}"
            );
            if !other_selectors.is_empty() {
                let _ = writeln!(
                    s,
                    "\nThe identity also rested on selectors AIP cannot check: {}.\n\
                     Those are SPIRE's alone and are not corroborated here.",
                    other_selectors.join(", ")
                );
            }
        }
        C::Diverges { divergence } => {
            let _ = writeln!(
                s,
                "DIVERGES — this is a finding, not a diagnostic\n{divergence:#?}"
            );
        }
        C::NotComparable { reason } => {
            let _ = writeln!(
                s,
                "NOT COMPARABLE — stated, never reported as agreement\n{reason:#?}"
            );
        }
    }
    let _ = writeln!(
        s,
        "---\nBounds: SPIRE's unix attestor and AIP both measure from /proc/<pid>/exe, so\n\
         for this attestor the two share that attack surface. Agreement means two\n\
         independently built implementations concur; it does not make the host kernel\n\
         trustworthy, and neither project claims it does."
    );
    s
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
