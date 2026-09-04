//! The verification routine: schema, anchor chain, evidence packets,
//! action ledger, and the certified root digest — each recomputed from the
//! exported bytes alone.

use ot_accountability_core::chain::verify_hash_chain;
use ot_accountability_core::merkle::merkle_root;
use serde_json::Value;

use crate::report::Report;
use crate::{canonical_json, is_hex_digest, is_placeholder_digest, sha256_hex};

pub const DOSSIER_STANDARD: &str = "ASC-SENTINEL-MISSION-DOSSIER-v1";

fn str_field<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn u64_field(v: &Value, key: &str) -> u64 {
    v.get(key).and_then(Value::as_u64).unwrap_or(0)
}

/// Runs the shared core's chain verification, translating the verdict into
/// report findings plus a per-record trace for the verified prefix.
/// Returns the sequence of the first broken record, or `None` when valid.
fn verify_chain(
    records: &[Value],
    prev_field: &'static str,
    hash_field: &'static str,
    label: &'static str,
    report: &mut Report,
) -> Option<u64> {
    let verdict = verify_hash_chain(records, prev_field, hash_field);
    let verified = verdict
        .broken_sequence
        .map(|s| s.saturating_sub(1) as usize)
        .unwrap_or(records.len());
    for record in records.iter().take(verified) {
        report.trace(format!(
            "[TRACE] {label} #{:03} {} hash ok",
            u64_field(record, "sequenceNumber"),
            str_field(record, "anchorType"),
        ));
    }
    if !verdict.valid {
        report.fail(
            label,
            verdict
                .reason
                .unwrap_or_else(|| "chain verification failed".into()),
        );
    }
    verdict.broken_sequence
}

fn is_terminal_revocation(anchor: &Value) -> bool {
    str_field(anchor, "anchorType") == "AUTHORITY_REVOCATION"
        && anchor
            .get("payload")
            .and_then(|p| p.get("terminal"))
            .and_then(Value::as_bool)
            == Some(true)
}

/// Step 1: dossier schema, identities, and provenance digests.
fn verify_schema(dossier: &Value, report: &mut Report) {
    let standard = str_field(dossier, "standard");
    if standard != DOSSIER_STANDARD {
        report.fail(
            "schema",
            format!("unknown dossier standard {standard:?}; expected {DOSSIER_STANDARD:?}",),
        );
    }

    let identity = dossier
        .pointer("/agent/identity")
        .cloned()
        .unwrap_or(Value::Null);
    if identity.is_null() {
        report.warn("schema", "dossier carries no agent identity credential");
        return;
    }
    let did = str_field(&identity, "did");
    if !did.starts_with("did:syntriass:agent:") || did.len() <= "did:syntriass:agent:".len() {
        report.fail(
            "schema",
            format!("agent DID {did:?} is not a did:syntriass:agent identifier"),
        );
    }
    let supervisor = str_field(&identity, "supervisorDid");
    if !supervisor.starts_with("did:syntriass:officer:") {
        report.fail(
            "schema",
            format!("supervisor DID {supervisor:?} is not a did:syntriass:officer identifier",),
        );
    }
    for key in ["modelDigest", "systemPromptHash"] {
        let digest = str_field(&identity, key);
        if !is_hex_digest(digest) {
            report.fail("schema", format!("{key} is not a 64-hex SHA-256 digest"));
        } else if is_placeholder_digest(digest) {
            report.warn(
                "schema",
                format!("{key} is the all-zero placeholder — configuration attested, weights not",),
            );
        }
    }
    report.trace(format!(
        "[TRACE] schema agent {did} supervised by {supervisor}"
    ));
}

/// Steps 2–3: the NEXORA anchor chain and the AIP evidence packets, plus
/// every cross-reference binding them, the revocation law, and multi-sig.
fn verify_nexora(dossier: &Value, report: &mut Report) {
    let anchors: Vec<Value> = dossier
        .get("lifecycleAnchors")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let packets: Vec<Value> = dossier
        .get("evidencePackets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    report.stats.anchors = anchors.len();
    report.stats.packets = packets.len();

    // ── Anchor chain continuity ────────────────────────────────────────
    if !anchors.is_empty() && str_field(&anchors[0], "anchorType") != "AGENT_GENESIS" {
        report.fail(
            "anchor-chain",
            format!(
                "chain must begin with AGENT_GENESIS, found {}",
                str_field(&anchors[0], "anchorType"),
            ),
        );
    }
    let mut terminal_revocation: Option<(u64, String)> = None; // (sequence, timestamp)
    for anchor in &anchors {
        let sequence = u64_field(anchor, "sequenceNumber");
        if sequence > 1 && str_field(anchor, "anchorType") == "AGENT_GENESIS" {
            report.fail(
                "anchor-chain",
                format!("second AGENT_GENESIS at sequence {sequence} — an agent is born once",),
            );
        }
        if let Some((closed_at, _)) = terminal_revocation {
            report.fail(
                "anchor-chain",
                format!(
                "anchor at sequence {sequence} after terminal revocation at sequence {closed_at} \
                 (LIFECYCLE_CLOSED)",
            ),
            );
        }
        if is_terminal_revocation(anchor) {
            terminal_revocation = Some((sequence, str_field(anchor, "timestampUtc").to_string()));
            report.info(
                "anchor-chain",
                format!("terminal AUTHORITY_REVOCATION at sequence {sequence}: lifecycle closed",),
            );
        }
    }
    verify_chain(
        &anchors,
        "previousAnchorHash",
        "anchorHash",
        "anchor-chain",
        report,
    );

    // ── Evidence packet integrity ──────────────────────────────────────
    verify_chain(
        &packets,
        "previousPacketHash",
        "packetHash",
        "packet-chain",
        report,
    );

    let anchor_hashes: Vec<&str> = anchors.iter().map(|a| str_field(a, "anchorHash")).collect();
    let sealed_packet_hashes: Vec<&str> = anchors
        .iter()
        .filter(|a| str_field(a, "anchorType") == "ACTION_EXECUTION_SEAL")
        .filter_map(|a| a.pointer("/payload/packetHash").and_then(Value::as_str))
        .collect();
    let packet_hashes: Vec<&str> = packets.iter().map(|p| str_field(p, "packetHash")).collect();

    // The Merkle commitment over the evidence set — the one digest an
    // after-action report can carry for the whole execution record.
    let merkle = merkle_root(
        &packet_hashes
            .iter()
            .map(|h| h.to_string())
            .collect::<Vec<_>>(),
    );
    report.trace(format!("[TRACE] packet-set merkle root {merkle}"));
    report.stats.packet_merkle_root = Some(merkle);

    for sealed in &sealed_packet_hashes {
        if !packet_hashes.contains(sealed) {
            report.fail(
                "cross-reference",
                format!(
                "an ACTION_EXECUTION_SEAL names packet hash {}… absent from the evidence ledger",
                &sealed[..12.min(sealed.len())],
            ),
            );
        }
    }

    let gated_tools: Vec<String> = dossier
        .pointer("/agent/identity/requiresDualKeyAuthorization")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();

    for packet in &packets {
        let sequence = u64_field(packet, "sequenceNumber");
        let status = packet
            .pointer("/toolExecuted/status")
            .and_then(Value::as_str)
            .unwrap_or("");
        let tool = packet
            .pointer("/toolExecuted/name")
            .and_then(Value::as_str)
            .unwrap_or("");
        let pre = str_field(packet, "preStateHash");
        let post = str_field(packet, "postStateHash");

        for (key, digest) in [("preStateHash", pre), ("postStateHash", post)] {
            if !is_hex_digest(digest) {
                report.fail(
                    "packet-chain",
                    format!("packet #{sequence} {key} is not a 64-hex SHA-256 digest",),
                );
            }
        }
        // A blocked action never ran, so its state cannot have mutated: a
        // BLOCKED packet whose pre/post hashes differ records an execution
        // its own verdict denies.
        if status == "BLOCKED_BY_POLICY" && pre != post {
            report.fail(
                "packet-chain",
                format!(
                    "packet #{sequence} is BLOCKED_BY_POLICY but pre/post state hashes differ — \
                 state mutated under a policy block",
                ),
            );
        }

        // Lifecycle binding: a non-empty anchorHash must be a real anchor
        // of this agent, and an anchored execution must have its seal.
        let bound = str_field(packet, "anchorHash");
        if !bound.is_empty() {
            if !anchor_hashes.contains(&bound) {
                report.fail(
                    "cross-reference",
                    format!(
                        "packet #{sequence} binds anchor hash {}… absent from the lifecycle chain",
                        &bound[..12.min(bound.len())],
                    ),
                );
            }
            let own_hash = str_field(packet, "packetHash");
            if !sealed_packet_hashes.contains(&own_hash) {
                report.fail(
                    "cross-reference",
                    format!(
                    "packet #{sequence} ({status}) has no ACTION_EXECUTION_SEAL anchor naming it \
                     — the lifecycle chain does not acknowledge this action",
                ),
                );
            }
        }

        // The revocation law: nothing executes past a terminal revocation.
        if let Some((closed_at, closed_ts)) = &terminal_revocation {
            let ts = str_field(packet, "timestampUtc");
            if (status == "SUCCESS" || status == "FAILED") && ts > closed_ts.as_str() {
                report.fail("revocation", format!(
                    "UNAUTHORIZED_POST_REVOCATION_EXECUTION: packet #{sequence} ({tool}, {status}) \
                     at {ts} executed after the terminal revocation at sequence {closed_at} ({closed_ts})",
                ));
            }
        }

        // Multi-sig: clearance-gated tools carry a supervisor co-signature.
        if gated_tools.iter().any(|t| t == tool) && status == "SUCCESS" {
            let sig = packet
                .pointer("/toolExecuted/supervisorCoSignature")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !is_hex_digest(sig) {
                report.fail(
                    "multisig",
                    format!(
                        "packet #{sequence} executed clearance-gated tool {tool:?} without a \
                     well-formed supervisor co-signature",
                    ),
                );
            } else {
                report.trace(format!(
                    "[TRACE] multisig packet #{sequence:03} {tool} co-signature present",
                ));
            }
        }
    }
}

/// Step 3b: the agent action ledger chain.
fn verify_ledger(dossier: &Value, report: &mut Report) {
    let entries: Vec<Value> = dossier
        .get("actionLedger")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    report.stats.ledger_entries = entries.len();
    let broken = verify_chain(
        &entries,
        "previousHash",
        "chainHash",
        "action-ledger",
        report,
    );

    // The dossier's own recorded verdict must agree with the recomputation.
    let claimed_valid = dossier
        .pointer("/verification/actionChain/valid")
        .and_then(Value::as_bool);
    if claimed_valid == Some(true) && broken.is_some() {
        report.fail(
            "action-ledger",
            "dossier claims a valid action chain that does not verify",
        );
    }
}

/// Step 4: the certified root digest over everything but the certification.
fn verify_root_digest(dossier: &Value, report: &mut Report) {
    let Some(recorded) = dossier
        .pointer("/certification/rootDigest")
        .and_then(Value::as_str)
    else {
        report.fail("root-digest", "dossier carries no certification.rootDigest");
        return;
    };
    let mut body = dossier.clone();
    if let Some(obj) = body.as_object_mut() {
        obj.remove("certification");
    }
    let recomputed = sha256_hex(&canonical_json(&body));
    if recomputed != recorded {
        report.fail(
            "root-digest",
            format!(
                "root digest mismatch: dossier body modified after certification \
             (recomputed {}…, recorded {}…)",
                &recomputed[..12],
                recorded.get(..12).unwrap_or(recorded),
            ),
        );
    } else {
        report.trace(format!("[TRACE] root-digest {recomputed} ok"));
    }
}

/// Verifies a full certified mission dossier.
pub fn verify_dossier(dossier: &Value, report: &mut Report) {
    verify_schema(dossier, report);
    verify_nexora(dossier, report);
    verify_ledger(dossier, report);
    verify_root_digest(dossier, report);
}

/// Verifies a `.jsonl` forensic stream: one AIP evidence packet per line,
/// chain-checked in order via the core's streaming verifier — **O(1)
/// memory**, so a multi-gigabyte fleet archive verifies without loading.
/// Streams carry no anchors or certification, so only the packet chain and
/// hash formats are in scope.
pub fn verify_packet_stream_reader<R: std::io::BufRead>(reader: R, report: &mut Report) {
    let mut verifier = ot_accountability_core::stream::StreamingChainVerifier::new(
        "previousPacketHash",
        "packetHash",
    );
    let mut count = 0usize;
    for (n, line) in reader.lines().enumerate() {
        let line = match line {
            Ok(line) => line,
            Err(err) => {
                report.fail("stream", format!("read error at line {}: {err}", n + 1));
                report.stats.packets = count;
                return;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let packet: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(err) => {
                report.fail("stream", format!("line {} is not valid JSON: {err}", n + 1));
                report.stats.packets = count;
                return;
            }
        };
        count += 1;
        let sequence = u64_field(&packet, "sequenceNumber");
        for key in ["preStateHash", "postStateHash"] {
            if !is_hex_digest(str_field(&packet, key)) {
                report.fail(
                    "packet-chain",
                    format!("packet #{sequence} {key} is not a 64-hex SHA-256 digest"),
                );
            }
        }
        if let Err(broken) = verifier.push(&packet) {
            report.fail("packet-chain", broken.reason);
            report.stats.packets = count;
            return;
        }
        report.trace(format!("[TRACE] packet-chain #{sequence:03}  hash ok"));
    }
    report.stats.packets = count;
}

/// In-memory convenience over [`verify_packet_stream_reader`].
pub fn verify_packet_stream(text: &str, report: &mut Report) {
    verify_packet_stream_reader(text.as_bytes(), report);
}
