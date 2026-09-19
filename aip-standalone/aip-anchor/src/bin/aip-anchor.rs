//! `aip-anchor` — the witness, as a command an institution runs on its own
//! system (R11).
//!
//! ```text
//! aip-anchor witness --head head.json [--consistency proof.json] \
//!     --witness <id>:<version> --key <hex> \
//!     --trust-log <signer>:<version>=<pubkey_hex> \
//!     --receipts receipts.jsonl
//!
//! aip-anchor verify --receipts receipts.jsonl \
//!     --trust-witness <id>:<version>=<pubkey_hex>
//!
//! aip-anchor state --receipts receipts.jsonl
//! ```
//!
//! # Where this runs matters more than what it does
//!
//! The code here is small. What makes a receipt worth anything is that the
//! host running this command, the key it reads, and the file it appends to
//! are outside the control of whoever operates the log. No flag can
//! establish that. `deploy/pilot/ANCHOR_WITNESS.md` states what the
//! deployment has to do.
//!
//! The witness never receives the log, only heads and consistency proofs.
//! A witness that held the log could be argued to have produced it.

use std::collections::BTreeMap;
use std::process::ExitCode;

use aip_anchor::store::FileReceiptStore;
use aip_anchor::{verify_receipt_chain, Witness, WitnessAnchors, WitnessReceipt};
use aip_nexora::{ConsistencyProof, NexoraTrustAnchors, SignedHead};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("witness") => do_witness(&args[1..]),
        Some("verify") => do_verify(&args[1..]),
        Some("state") => do_state(&args[1..]),
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
     aip-anchor witness --head <file> [--consistency <file>] \
     --witness <id>:<version> --key <hex> \
     --trust-log <signer>:<version>=<pubkey_hex> [...] --receipts <file>\n  \
     aip-anchor verify --receipts <file> \
     --trust-witness <id>:<version>=<pubkey_hex> [...]\n  \
     aip-anchor state --receipts <file>"
        .to_string()
}

fn parse(args: &[String]) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        let Some(name) = args[i].strip_prefix("--") else {
            return Err(format!("unexpected argument `{}`", args[i]));
        };
        let value = args
            .get(i + 1)
            .ok_or_else(|| format!("--{name} expects a value"))?;
        out.entry(name.to_string()).or_default().push(value.clone());
        i += 2;
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

fn read_json<T: serde::de::DeserializeOwned>(path: &str, what: &str) -> Result<T, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("{path} is not {what}: {e}"))
}

/// Split `<id>:<version>=<pubkey_hex>` into its three parts.
fn split_anchor(entry: &str, flag: &str) -> Result<(String, u32, Vec<u8>), String> {
    let (id_ver, key_hex) = entry
        .split_once('=')
        .ok_or_else(|| format!("--{flag} expects <id>:<version>=<pubkey_hex>"))?;
    let (id, ver) = id_ver
        .rsplit_once(':')
        .ok_or_else(|| format!("--{flag} expects <id>:<version>=<pubkey_hex>"))?;
    let version: u32 = ver
        .parse()
        .map_err(|_| format!("--{flag} key version must be a number"))?;
    Ok((id.trim().to_string(), version, hex_decode(key_hex)?))
}

fn do_witness(args: &[String]) -> Result<(), String> {
    let m = parse(args)?;

    // The NEXORA keys this witness will accept heads from. Supplied here,
    // never read out of the head.
    let mut log_anchors = NexoraTrustAnchors::new();
    let trusted = m.get("trust-log").map(Vec::as_slice).unwrap_or(&[]);
    if trusted.is_empty() {
        return Err(
            "--trust-log is required: a witness with no anchors would countersign \
                    any head presented to it, which is the opposite of what a witness is for"
                .into(),
        );
    }
    for entry in trusted {
        let (id, version, key) = split_anchor(entry, "trust-log")?;
        log_anchors = log_anchors.trust(&id, version, &key);
    }

    let (witness_id, ver) = one(&m, "witness")?
        .rsplit_once(':')
        .ok_or("--witness expects <id>:<version>")?;
    let key_version: u32 = ver
        .parse()
        .map_err(|_| "--witness key version must be a number".to_string())?;
    let private_key = hex_decode(one(&m, "key")?)?;
    let public_key = aip_crypto::public_key_from_private(&private_key)
        .map_err(|e| format!("witness key: {e:?}"))?;

    let store = FileReceiptStore::new(one(&m, "receipts")?);
    // State is replayed from the receipts rather than stored separately,
    // so a restart cannot be used to slip a rollback past the witness.
    let state = store.resume_state().map_err(|e| e.to_string())?;
    let resumed_size = state.last_size;

    let mut witness = Witness::new(
        witness_id,
        key_version,
        &private_key,
        &public_key,
        log_anchors,
    )
    .map_err(|e| e.to_string())?
    .resume(state);

    let head: SignedHead = read_json(one(&m, "head")?, "a signed head")?;
    let consistency: Option<ConsistencyProof> = match m.get("consistency") {
        Some(v) if v.len() == 1 => Some(read_json(&v[0], "a consistency proof")?),
        Some(_) => return Err("--consistency may be given once".into()),
        None => None,
    };

    let receipt = witness
        .witness(&head, consistency.as_ref(), now_ms())
        .map_err(|e| format!("refused to countersign: {e}"))?;
    // Durable before it is reported. A receipt the witness announced but
    // did not persist is the one a later audit will be missing.
    store.append(&receipt).map_err(|e| e.to_string())?;

    println!("witnessed log  {}", hex(&receipt.log_id));
    println!("size           {} (was {resumed_size})", receipt.size);
    println!("root           {}", hex(&receipt.root));
    println!(
        "witnessed at   {} (this host's clock)",
        receipt.witnessed_at_ms
    );
    if let Some(skew) = receipt.log_clock_ahead_by_ms() {
        println!("note           the log's clock reads {skew} ms ahead of this one");
    }
    println!("receipt        appended to {}", store.path().display());
    Ok(())
}

fn do_verify(args: &[String]) -> Result<(), String> {
    let m = parse(args)?;
    let store = FileReceiptStore::new(one(&m, "receipts")?);
    let receipts = store.load().map_err(|e| e.to_string())?;
    if receipts.is_empty() {
        return Err(
            "no receipts: nothing about the log's history is established. This is not \
                    a clean result, it is the absence of one"
                .into(),
        );
    }

    let mut anchors = WitnessAnchors::new();
    let trusted = m.get("trust-witness").map(Vec::as_slice).unwrap_or(&[]);
    if trusted.is_empty() {
        return Err(
            "--trust-witness is required: receipts are judged against anchors the \
                    verifier holds, never against the key the receipt names"
                .into(),
        );
    }
    for entry in trusted {
        let (id, version, key) = split_anchor(entry, "trust-witness")?;
        anchors = anchors.trust(&id, version, &key);
    }

    verify_receipt_chain(&receipts, &anchors)
        .map_err(|e| format!("the receipt set did not verify: {e}"))?;

    let first = &receipts[0];
    let last = &receipts[receipts.len() - 1];
    println!("log            {}", hex(&last.log_id));
    println!("receipts       {}, chain unbroken", receipts.len());
    println!(
        "witness        {} (key version {})",
        last.witness_id, last.key_version
    );
    println!(
        "witnessed from size {} at {} to size {} at {}",
        first.size, first.witnessed_at_ms, last.size, last.witnessed_at_ms
    );
    println!("highest root   {}", hex(&last.root));
    println!(
        "\nThese receipts establish that a log with this root existed at size {} and was \
         seen by {}. To establish that the log held today still carries that history, run \
         the audit where the log is: the witness does not hold it.",
        last.size, last.witness_id
    );
    Ok(())
}

fn do_state(args: &[String]) -> Result<(), String> {
    let m = parse(args)?;
    let store = FileReceiptStore::new(one(&m, "receipts")?);
    let state = store.resume_state().map_err(|e| e.to_string())?;
    match state.log_id {
        None => println!("no receipts yet: this witness has countersigned nothing"),
        Some(id) => {
            println!("log            {}", hex(&id));
            println!("receipts       {}", state.receipts_issued);
            println!("last size      {}", state.last_size);
            println!("last root      {}", hex(&state.last_root));
        }
    }
    Ok(())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
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

// Keep the type visible to readers of this file: the receipts the store
// returns are exactly what `verify` checks.
const _: fn(&[WitnessReceipt], &WitnessAnchors) -> Result<(), aip_anchor::WitnessError> =
    verify_receipt_chain;
