//! `aip-incident` — assemble or check an incident evidence bundle (R14).
//!
//! ```text
//! aip-incident export --agent <id> --from <ms> --to <ms> \
//!     --exporter <id>:<version> --key <hex> \
//!     --batch f.json [--batch g.json ...] \
//!     [--verdict v.json ...] [--ledger l.json] [--health h.json] \
//!     --out bundle.json
//!
//! aip-incident verify bundle.json --trust <id>:<version>=<pubkey_hex>
//! aip-incident summary bundle.json
//! ```
//!
//! The export reads only files. It does not reach a collector or a service,
//! because an incident is the wrong moment to discover that a network path
//! is down, and because a bundle assembled from files is one an operator can
//! reproduce.

use std::collections::BTreeMap;
use std::process::ExitCode;

use aip_crypto::sha256;
use aip_incident::{
    export, summary_markdown, verify_bundle, verify_coverage, Document, DocumentKind, Exporter,
    ExporterAnchors, IncidentBundle,
};
use aip_observe::AttestedBatch;
use aip_types::canonical::{put_bytes, put_domain, put_str, put_u32, put_u64};
use aip_types::CoverageWindow;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("export") => do_export(&args[1..]),
        Some("verify") => do_verify(&args[1..]),
        Some("summary") => do_summary(&args[1..]),
        _ => Err(usage()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> String {
    "usage:\n  \
     aip-incident export --agent <id> --from <ms> --to <ms> \
     --exporter <id>:<version> --key <hex> --batch <file> [...] \
     [--verdict <file>] [--ledger <file>] [--health <file>] \
     [--expectation <file>] --out <file>\n  \
     aip-incident verify <bundle.json> --trust <id>:<version>=<pubkey_hex> \
     [--batch <file> ...]\n  \
     aip-incident summary <bundle.json>"
        .to_string()
}

/// Collect repeated `--flag value` pairs and single-valued options.
fn parse(args: &[String]) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(name) = a.strip_prefix("--") {
            let value = args
                .get(i + 1)
                .ok_or_else(|| format!("--{name} expects a value"))?;
            out.entry(name.to_string()).or_default().push(value.clone());
            i += 2;
        } else {
            out.entry("_positional".into()).or_default().push(a.clone());
            i += 1;
        }
    }
    Ok(out)
}

fn one<'a>(m: &'a BTreeMap<String, Vec<String>>, k: &str) -> Result<&'a str, String> {
    let v = m.get(k).ok_or_else(|| format!("--{k} is required"))?;
    if v.len() != 1 {
        return Err(format!("--{k} may be given once"));
    }
    Ok(&v[0])
}

fn ms(m: &BTreeMap<String, Vec<String>>, k: &str) -> Result<u64, String> {
    one(m, k)?
        .parse()
        .map_err(|_| format!("--{k} must be Unix milliseconds"))
}

fn do_export(args: &[String]) -> Result<(), String> {
    let m = parse(args)?;
    let agent = one(&m, "agent")?;
    let window = CoverageWindow {
        from_ms: ms(&m, "from")?,
        to_ms: ms(&m, "to")?,
    };
    if window.to_ms < window.from_ms {
        return Err("--to precedes --from".into());
    }

    let (exporter_id, version) = one(&m, "exporter")?
        .rsplit_once(':')
        .ok_or("--exporter expects <id>:<version>")?;
    let key_version: u32 = version
        .parse()
        .map_err(|_| "--exporter key version must be a number".to_string())?;
    let key = hex_decode(one(&m, "key")?)?;
    let exporter =
        Exporter::new(exporter_id, key_version, &key).map_err(|e| format!("exporter key: {e}"))?;

    // Read every document, keeping its bytes verbatim.
    let mut jsons: Vec<(String, DocumentKind, String)> = Vec::new();
    let mut batch_values: Vec<AttestedBatch> = Vec::new();
    // (flag, directory inside the bundle, kind). The directory is spelled
    // out rather than derived from the flag, so a name inside a signed
    // manifest never depends on English pluralisation.
    for (flag, dir, kind) in [
        ("batch", "batches", DocumentKind::AttestedBatch),
        ("verdict", "verdicts", DocumentKind::Verdict),
        ("ledger", "ledgers", DocumentKind::AccessLedger),
        ("health", "health", DocumentKind::SensorHealth),
        ("expectation", "expectations", DocumentKind::Expectation),
    ] {
        for (i, path) in m.get(flag).into_iter().flatten().enumerate() {
            let text = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
            if kind == DocumentKind::AttestedBatch {
                batch_values.push(
                    serde_json::from_str(&text)
                        .map_err(|e| format!("{path} is not an AttestedBatch: {e}"))?,
                );
            }
            jsons.push((format!("{dir}/{i}.json"), kind, text));
        }
    }
    if batch_values.is_empty() {
        // Not an error: a window with no batches is a real and important
        // answer. Say so, because an operator who meant to pass some will
        // want to know before they file the report.
        eprintln!(
            "note: no --batch supplied, so the bundle will state the whole \
             window as uncovered"
        );
    }

    let documents: Vec<Document<'_>> = jsons
        .iter()
        .map(|(name, kind, json)| Document {
            name: name.clone(),
            kind: *kind,
            json,
        })
        .collect();
    let batch_refs: Vec<&AttestedBatch> = batch_values.iter().collect();

    let exported_at_ms = now_ms();
    let bundle = export(
        &exporter,
        agent,
        window,
        derive_bundle_id(agent, window, exported_at_ms, &jsons),
        exported_at_ms,
        &documents,
        &batch_refs,
    )
    .map_err(|e| format!("export: {e}"))?;

    let out_path = one(&m, "out")?;
    std::fs::write(
        out_path,
        serde_json::to_string_pretty(&bundle).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("write {out_path}: {e}"))?;

    // The number the operator needs before anything else.
    let c = &bundle.manifest.coverage;
    if c.is_complete() {
        println!("coverage: complete over the requested window");
    } else {
        println!(
            "coverage: INCOMPLETE — {} ms uncovered across {} gap(s)",
            c.uncovered_ms,
            c.gaps.len()
        );
        for (f, t) in &c.gaps {
            println!("  gap {f} .. {t}");
        }
    }
    if c.batches_with_integrity_findings > 0 {
        println!(
            "warning: {} of {} batches carry a sensor integrity finding",
            c.batches_with_integrity_findings, c.batches
        );
    }
    println!(
        "wrote {out_path} ({} document(s))",
        bundle.manifest.files.len()
    );
    Ok(())
}

fn do_verify(args: &[String]) -> Result<(), String> {
    let m = parse(args)?;
    let path = m
        .get("_positional")
        .and_then(|v| v.first())
        .ok_or("give the bundle path")?;
    let bundle: IncidentBundle = serde_json::from_str(
        &std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?,
    )
    .map_err(|e| format!("{path} is not an incident bundle: {e}"))?;

    let mut anchors = ExporterAnchors::new();
    for entry in m.get("trust").into_iter().flatten() {
        let (id_ver, key_hex) = entry
            .split_once('=')
            .ok_or("--trust expects <id>:<version>=<pubkey_hex>")?;
        let (id, ver) = id_ver
            .rsplit_once(':')
            .ok_or("--trust expects <id>:<version>=<pubkey_hex>")?;
        let version: u32 = ver
            .parse()
            .map_err(|_| "--trust key version must be a number".to_string())?;
        anchors = anchors.trust(id.trim(), version, &hex_decode(key_hex)?);
    }

    verify_bundle(&bundle, &anchors).map_err(|e| format!("bundle did not verify: {e}"))?;
    println!("bundle:   {path}");
    println!("agent:    {}", bundle.manifest.agent_id);
    println!("exporter: {}", bundle.manifest.exporter_id);
    println!("files:    {}", bundle.manifest.files.len());
    println!("signature: OK");

    // Recomputing coverage is a separate defence: the signature proves the
    // exporter stated these gaps, this proves the gaps are the ones the
    // evidence has. An exporter key could be held by whoever wants the
    // bundle to look complete.
    let mut batches: Vec<AttestedBatch> = Vec::new();
    for f in &bundle.manifest.files {
        if f.kind == DocumentKind::AttestedBatch {
            if let Some(text) = bundle.files.get(&f.name) {
                batches.push(
                    serde_json::from_str(text)
                        .map_err(|e| format!("{}: not an AttestedBatch: {e}", f.name))?,
                );
            }
        }
    }
    let refs: Vec<&AttestedBatch> = batches.iter().collect();
    match verify_coverage(&bundle, &refs) {
        Ok(()) => println!("coverage:  recomputed and matches the manifest"),
        Err(e) => return Err(format!("coverage claim does not match the evidence: {e}")),
    }

    let c = &bundle.manifest.coverage;
    if !c.is_complete() {
        println!(
            "note:      {} ms of the requested window is uncovered; statements \
             about those intervals are not supported by this bundle",
            c.uncovered_ms
        );
    }
    println!(
        "\nThe exporter's signature means this set of documents was assembled \
         by that exporter. Each enclosed document keeps its own signature and \
         must be verified under its own anchors."
    );
    Ok(())
}

fn do_summary(args: &[String]) -> Result<(), String> {
    let m = parse(args)?;
    let path = m
        .get("_positional")
        .and_then(|v| v.first())
        .ok_or("give the bundle path")?;
    let bundle: IncidentBundle = serde_json::from_str(
        &std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?,
    )
    .map_err(|e| format!("{path} is not an incident bundle: {e}"))?;
    print!("{}", summary_markdown(&bundle));
    Ok(())
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err("hex must have an even number of digits".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("invalid hex: {e}")))
        .collect()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Derive the bundle identifier from what the bundle contains.
///
/// Deterministic on purpose. A random identifier cannot be reproduced, so
/// an operator asked six months later to show how a filed bundle was built
/// has no way to demonstrate that re-running the export yields the same
/// artefact. Here the identifier is the first 16 bytes of a SHA-256 over
/// the agent, the window, the export instant and every document digest, so
/// two exports collide only if they enclose the same evidence for the same
/// agent and window at the same millisecond — in which case they are the
/// same bundle. Truncation to 16 bytes leaves 128 bits, which is the
/// collision resistance this identifier needs (it names a document, it does
/// not authenticate one; the manifest signature does that).
fn derive_bundle_id(
    agent: &str,
    window: CoverageWindow,
    exported_at_ms: u64,
    documents: &[(String, DocumentKind, String)],
) -> [u8; 16] {
    let mut buf = Vec::new();
    put_domain(&mut buf, "GHOST/IncidentBundle/Id/v1");
    put_str(&mut buf, agent);
    put_u64(&mut buf, window.from_ms);
    put_u64(&mut buf, window.to_ms);
    put_u64(&mut buf, exported_at_ms);
    // Sorted, so the identifier does not depend on the order the operator
    // happened to pass the flags in.
    let mut digests: Vec<[u8; 32]> = documents
        .iter()
        .map(|(name, kind, json)| {
            let mut d = Vec::new();
            put_str(&mut d, name);
            put_str(&mut d, kind.as_str());
            put_bytes(&mut d, &sha256(json.as_bytes()));
            sha256(&d)
        })
        .collect();
    digests.sort();
    put_u32(&mut buf, digests.len() as u32);
    for d in &digests {
        put_bytes(&mut buf, d);
    }
    let full = sha256(&buf);
    let mut id = [0u8; 16];
    id.copy_from_slice(&full[..16]);
    id
}
