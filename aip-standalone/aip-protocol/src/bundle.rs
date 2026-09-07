//! Audit-export bundle — a portable, signed ZIP an enterprise can hand to an
//! auditor, regulator, or counterparty for **offline** verification.
//!
//! Contents (see `AUDIT_EXPORT_SPEC.md`):
//!   evidence.json · verification_report.json · verification_report.md
//!   authority_graph.json · authority_graph.dot · manifest.json
//!   bundle_signature.sig
//!
//! Integrity model:
//! - Each content file's SHA-256 is listed in `manifest.json` (`files`).
//! - `bundle_hash` = SHA-256 over the sorted `(name, sha256)` list — binds the
//!   whole content set.
//! - `bundle_signature.sig` = hex Ed25519 signature over the exact
//!   `manifest.json` bytes, made with the service signing key whose public key
//!   is embedded in the manifest. A verifier checks the signature offline and
//!   surfaces the signer fingerprint for out-of-band comparison.

use std::collections::HashMap;
use std::io::{Cursor, Read, Write};

use serde::{Deserialize, Serialize};

use aip_crypto::{sha256, verify_ed25519_raw};
use aip_custody::SigningCustodian;

use crate::{verify_packet, AccountabilityGraph, EvidencePacket, VerificationContext};

pub const BUNDLE_SCHEMA_VERSION: &str = "aip-bundle-1";

pub const F_EVIDENCE: &str = "evidence.json";
pub const F_REPORT_JSON: &str = "verification_report.json";
pub const F_REPORT_MD: &str = "verification_report.md";
pub const F_GRAPH_JSON: &str = "authority_graph.json";
pub const F_GRAPH_DOT: &str = "authority_graph.dot";
pub const F_MANIFEST: &str = "manifest.json";
pub const F_SIG: &str = "bundle_signature.sig";

/// Content files that must be present (manifest + signature handled separately).
pub const CONTENT_FILES: [&str; 5] = [
    F_EVIDENCE,
    F_REPORT_JSON,
    F_REPORT_MD,
    F_GRAPH_JSON,
    F_GRAPH_DOT,
];

#[derive(Debug)]
pub enum BundleError {
    Zip(String),
    Serialize(String),
    Crypto(String),
}
impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BundleError::Zip(e) => write!(f, "bundle zip error: {e}"),
            BundleError::Serialize(e) => write!(f, "bundle serialize error: {e}"),
            BundleError::Crypto(e) => write!(f, "bundle crypto error: {e}"),
        }
    }
}
impl std::error::Error for BundleError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    pub schema_version: String,
    pub bundle_id: String,
    pub tenant_id: String,
    pub packet_id: String,
    pub exported_at: u64,
    pub packet_hash: String,
    pub bundle_hash: String,
    pub signer_algorithm: String,
    pub signer_public_key: String,
    pub files: Vec<FileEntry>,
}

/// SHA-256 (hex) over the sorted `(name, sha256)` content-file list.
fn compute_bundle_hash(files: &[FileEntry]) -> String {
    let mut sorted: Vec<&FileEntry> = files.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let mut buf = Vec::new();
    for f in sorted {
        buf.extend_from_slice(f.name.as_bytes());
        buf.push(b':');
        buf.extend_from_slice(f.sha256.as_bytes());
        buf.push(b'\n');
    }
    hex::encode(sha256(&buf))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Build a signed audit-export ZIP for `packet`.
///
/// `report` is the verification report computed at export time (typically at
/// the integrity level the service can attest without external trust keys).
///
/// Takes a [`SigningCustodian`] rather than a raw seed. The previous signature
/// required the caller to hold the service's 32-byte private key and pass it
/// in — which is why the service kept one in its shared HTTP state, reachable
/// from every request handler in the process. The custodian removes that: the
/// bundle is signed by an object that can sign, and the key stays where it is
/// held.
///
/// The bundle bytes are unchanged. `signer_public_key` in the manifest is the
/// custodian's public key, the signature covers the identical manifest bytes,
/// and `verify_zip` is untouched — bundles produced before and after this
/// change verify the same way.
pub fn build_zip(
    tenant_id: &str,
    packet: &EvidencePacket,
    report: &crate::VerificationReport,
    signer: &dyn SigningCustodian,
) -> Result<Vec<u8>, BundleError> {
    let graph = AccountabilityGraph::from_packet(packet).with_report(report);

    let evidence_json = packet
        .to_json()
        .map_err(|e| BundleError::Serialize(e.to_string()))?;
    let report_json = report
        .to_json()
        .map_err(|e| BundleError::Serialize(e.to_string()))?;
    let report_md = report_markdown(packet, report);
    let graph_json = graph
        .to_json()
        .map_err(|e| BundleError::Serialize(e.to_string()))?;
    let graph_dot = graph.to_dot();

    let content: Vec<(&str, Vec<u8>)> = vec![
        (F_EVIDENCE, evidence_json.into_bytes()),
        (F_REPORT_JSON, report_json.into_bytes()),
        (F_REPORT_MD, report_md.into_bytes()),
        (F_GRAPH_JSON, graph_json.into_bytes()),
        (F_GRAPH_DOT, graph_dot.into_bytes()),
    ];

    let files: Vec<FileEntry> = content
        .iter()
        .map(|(name, bytes)| FileEntry {
            name: name.to_string(),
            sha256: hex::encode(sha256(bytes)),
        })
        .collect();

    let manifest = BundleManifest {
        schema_version: BUNDLE_SCHEMA_VERSION.to_string(),
        bundle_id: hex::encode(aip_core::capability::random_jti()),
        tenant_id: tenant_id.to_string(),
        packet_id: packet.packet_id_hex(),
        exported_at: now_ms(),
        packet_hash: hex::encode(packet.packet_hash),
        bundle_hash: compute_bundle_hash(&files),
        signer_algorithm: "Ed25519".to_string(),
        signer_public_key: hex::encode(signer.public_key()),
        files,
    };

    let manifest_bytes =
        serde_json::to_vec_pretty(&manifest).map_err(|e| BundleError::Serialize(e.to_string()))?;
    let sig = signer
        .sign(&manifest_bytes)
        .map_err(|e| BundleError::Crypto(e.to_string()))?;
    let sig_hex = hex::encode(sig);

    // Assemble the ZIP.
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zw = zip::ZipWriter::new(&mut cursor);
        let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, bytes) in &content {
            zw.start_file(*name, opts)
                .map_err(|e| BundleError::Zip(e.to_string()))?;
            zw.write_all(bytes)
                .map_err(|e| BundleError::Zip(e.to_string()))?;
        }
        zw.start_file(F_MANIFEST, opts)
            .map_err(|e| BundleError::Zip(e.to_string()))?;
        zw.write_all(&manifest_bytes)
            .map_err(|e| BundleError::Zip(e.to_string()))?;
        zw.start_file(F_SIG, opts)
            .map_err(|e| BundleError::Zip(e.to_string()))?;
        zw.write_all(sig_hex.as_bytes())
            .map_err(|e| BundleError::Zip(e.to_string()))?;
        zw.finish().map_err(|e| BundleError::Zip(e.to_string()))?;
    }
    Ok(cursor.into_inner())
}

// ─── Verification ───

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum BundleStatus {
    Pass,
    Warning,
    Fail,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleCheck {
    pub name: String,
    pub status: BundleStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleVerification {
    pub overall: BundleStatus,
    pub bundle_id: String,
    pub packet_id: String,
    pub signer_fingerprint: String,
    pub checks: Vec<BundleCheck>,
}

struct CheckCollector {
    checks: Vec<BundleCheck>,
}
impl CheckCollector {
    fn add(&mut self, name: &str, status: BundleStatus, detail: impl Into<String>) {
        self.checks.push(BundleCheck {
            name: name.to_string(),
            status,
            detail: detail.into(),
        });
    }
}

fn read_zip(bytes: &[u8]) -> Result<HashMap<String, Vec<u8>>, BundleError> {
    let mut archive =
        zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| BundleError::Zip(e.to_string()))?;
    let mut map = HashMap::new();
    for i in 0..archive.len() {
        let mut f = archive
            .by_index(i)
            .map_err(|e| BundleError::Zip(e.to_string()))?;
        let name = f.name().to_string();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)
            .map_err(|e| BundleError::Zip(e.to_string()))?;
        map.insert(name, buf);
    }
    Ok(map)
}

/// Verify an audit-export ZIP offline. `ctx` supplies any trusted issuer/
/// counterparty keys + revocations the verifier wants to apply for full
/// authority verification; with an empty context only integrity is asserted.
pub fn verify_zip(bytes: &[u8], ctx: &VerificationContext) -> BundleVerification {
    let mut c = CheckCollector { checks: vec![] };
    let mut bundle_id = String::new();
    let mut packet_id = String::new();
    let mut signer_fp = String::new();

    let files = match read_zip(bytes) {
        Ok(f) => f,
        Err(e) => {
            c.add("BUNDLE_READABLE", BundleStatus::Fail, e.to_string());
            return finalize(c, bundle_id, packet_id, signer_fp);
        }
    };

    // R1 STRUCTURE — all expected members present.
    let mut missing: Vec<&str> = vec![];
    for name in CONTENT_FILES.iter().chain([F_MANIFEST, F_SIG].iter()) {
        if !files.contains_key(*name) {
            missing.push(name);
        }
    }
    if missing.is_empty() {
        c.add(
            "BUNDLE_STRUCTURE",
            BundleStatus::Pass,
            "all bundle files present",
        );
    } else {
        c.add(
            "BUNDLE_STRUCTURE",
            BundleStatus::Fail,
            format!("missing bundle files: {}", missing.join(", ")),
        );
    }

    // R2 MANIFEST_PARSE
    let manifest: Option<BundleManifest> = files
        .get(F_MANIFEST)
        .and_then(|b| serde_json::from_slice(b).ok());
    let Some(manifest) = manifest else {
        c.add(
            "MANIFEST_PARSE",
            BundleStatus::Fail,
            "manifest.json missing or unparseable",
        );
        return finalize(c, bundle_id, packet_id, signer_fp);
    };
    bundle_id = manifest.bundle_id.clone();
    packet_id = manifest.packet_id.clone();
    if let Ok(pk) = hex::decode(&manifest.signer_public_key) {
        signer_fp = hex::encode(sha256(&pk));
    }
    c.add(
        "MANIFEST_PARSE",
        BundleStatus::Pass,
        format!(
            "schema {} · bundle {}",
            manifest.schema_version, manifest.bundle_id
        ),
    );

    // R3 FILE_HASHES — each listed file present and matches its SHA-256.
    let mut hash_problems: Vec<String> = vec![];
    for entry in &manifest.files {
        match files.get(&entry.name) {
            None => hash_problems.push(format!("{} listed but absent", entry.name)),
            Some(bytes) => {
                let actual = hex::encode(sha256(bytes));
                if actual != entry.sha256 {
                    hash_problems.push(format!("{} hash mismatch (tampered)", entry.name));
                }
            }
        }
    }
    c.add(
        "FILE_HASHES",
        if hash_problems.is_empty() {
            BundleStatus::Pass
        } else {
            BundleStatus::Fail
        },
        if hash_problems.is_empty() {
            "every file matches its manifest SHA-256".to_string()
        } else {
            hash_problems.join("; ")
        },
    );

    // R4 BUNDLE_HASH
    let recomputed_bundle_hash = compute_bundle_hash(&manifest.files);
    c.add(
        "BUNDLE_HASH",
        if recomputed_bundle_hash == manifest.bundle_hash {
            BundleStatus::Pass
        } else {
            BundleStatus::Fail
        },
        if recomputed_bundle_hash == manifest.bundle_hash {
            "bundle_hash matches the file set".to_string()
        } else {
            "bundle_hash does not match the file set (manifest tampered)".to_string()
        },
    );

    // R5 BUNDLE_SIGNATURE — signature over the exact manifest bytes.
    let sig_ok = verify_bundle_signature(&files, &manifest);
    c.add(
        "BUNDLE_SIGNATURE",
        if sig_ok {
            BundleStatus::Pass
        } else {
            BundleStatus::Fail
        },
        if sig_ok {
            format!("Ed25519 signature valid (signer fp {signer_fp})")
        } else {
            "bundle signature invalid — manifest not signed by the embedded key".to_string()
        },
    );

    // R6 EVIDENCE_INTEGRITY — packet parses, matches manifest packet_hash, self-consistent.
    let packet: Option<EvidencePacket> = files
        .get(F_EVIDENCE)
        .and_then(|b| serde_json::from_slice(b).ok());
    match &packet {
        None => c.add(
            "EVIDENCE_INTEGRITY",
            BundleStatus::Fail,
            "evidence.json missing or unparseable",
        ),
        Some(p) => {
            let recomputed = hex::encode(p.compute_hash());
            let hash_ok = recomputed == manifest.packet_hash && p.packet_hash == p.compute_hash();
            let sig_payload_ok = p.agent_sig.payload_hash == p.compute_hash();
            if hash_ok && sig_payload_ok {
                c.add(
                    "EVIDENCE_INTEGRITY",
                    BundleStatus::Pass,
                    "packet self-consistent and matches manifest packet_hash",
                );
            } else {
                c.add(
                    "EVIDENCE_INTEGRITY",
                    BundleStatus::Fail,
                    "evidence packet hash/signature inconsistent — tampered",
                );
            }
        }
    }

    // R7 PACKET_VERIFICATION — full cryptographic verification against ctx.
    if let Some(p) = &packet {
        let report = verify_packet(p, ctx);
        if report.valid {
            c.add(
                "PACKET_VERIFICATION",
                BundleStatus::Pass,
                format!("packet verifies; trust floor {:?}", report.trust_floor),
            );
        } else if report.tampered {
            c.add(
                "PACKET_VERIFICATION",
                BundleStatus::Fail,
                "packet verification failed: tampering detected",
            );
        } else if ctx.issuer_public_keys.is_empty() {
            // No trust roots supplied → authority can't be confirmed, but the
            // packet is not tampered. Warn rather than fail.
            c.add(
                "PACKET_VERIFICATION",
                BundleStatus::Warning,
                format!(
                    "integrity OK (floor {:?}); supply --trust keys to verify the authority chain",
                    report.trust_floor
                ),
            );
        } else {
            c.add(
                "PACKET_VERIFICATION",
                BundleStatus::Fail,
                format!("packet verification failed: {}", first_failure(&report)),
            );
        }
    }

    finalize(c, bundle_id, packet_id, signer_fp)
}

fn verify_bundle_signature(files: &HashMap<String, Vec<u8>>, manifest: &BundleManifest) -> bool {
    let (Some(manifest_bytes), Some(sig_hex_bytes)) = (files.get(F_MANIFEST), files.get(F_SIG))
    else {
        return false;
    };
    let Ok(pk) = hex::decode(&manifest.signer_public_key) else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(String::from_utf8_lossy(sig_hex_bytes).trim()) else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.as_slice().try_into() else {
        return false;
    };
    verify_ed25519_raw(&pk, manifest_bytes, &sig_arr)
}

fn first_failure(report: &crate::VerificationReport) -> String {
    report
        .failures()
        .first()
        .map(|c| format!("{}: {}", c.rule, c.detail))
        .unwrap_or_else(|| "unknown".to_string())
}

fn finalize(
    c: CheckCollector,
    bundle_id: String,
    packet_id: String,
    signer_fp: String,
) -> BundleVerification {
    let overall = if c.checks.iter().any(|x| x.status == BundleStatus::Fail) {
        BundleStatus::Fail
    } else if c.checks.iter().any(|x| x.status == BundleStatus::Warning) {
        BundleStatus::Warning
    } else {
        BundleStatus::Pass
    };
    BundleVerification {
        overall,
        bundle_id,
        packet_id,
        signer_fingerprint: signer_fp,
        checks: c.checks,
    }
}

// ─── Human-readable report ───

fn iso(ms: u64) -> String {
    // Minimal UTC ISO-8601 from epoch ms without extra deps.
    let secs = (ms / 1000) as i64;
    // Days since epoch → y/m/d via civil-from-days (Howard Hinnant's algorithm).
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// A plain-language report for auditors / compliance / regulators — no
/// protocol jargon. Explains who authorized, who executed, when, and the
/// verification result.
pub fn report_markdown(packet: &EvidencePacket, report: &crate::VerificationReport) -> String {
    let principal = &packet.root_authority;
    let mut out = String::new();
    out.push_str("# AI Agent Action — Accountability Report\n\n");
    out.push_str(&format!(
        "**Evidence record ID:** {}\n\n",
        packet.packet_id_hex()
    ));
    out.push_str(&format!(
        "**Generated for review at:** {}\n\n",
        iso(report.verified_at)
    ));

    out.push_str("## What happened\n\n");
    out.push_str(&format!("- **Decision:** {}\n", packet.decision.summary));
    out.push_str(&format!(
        "- **When decided:** {}\n",
        iso(packet.decision.decided_at)
    ));
    out.push_str(&format!(
        "- **Actions performed:** {}\n",
        packet.actions.len()
    ));
    for a in &packet.actions {
        out.push_str(&format!(
            "  - {} (at {})\n",
            a.description,
            iso(a.performed_at)
        ));
    }
    if let Some(r) = &packet.receipt_binding {
        out.push_str(&format!(
            "- **External record:** {} in {}{}\n",
            r.receipt_id,
            r.receipt_system,
            if r.counterparty_sig.is_some() {
                " (counter-signed by that system)"
            } else {
                ""
            }
        ));
    }

    out.push_str("\n## Who authorized it\n\n");
    out.push_str(&format!(
        "- **Authorizing party (human/root):** {} — `{}`\n",
        principal.display_role, principal.principal_id
    ));
    if packet.delegation_chain.is_empty() {
        out.push_str("- **Delegation:** the acting agent held the authority directly.\n");
    } else {
        out.push_str("- **Delegation chain (authority passed down, narrowing at each step):**\n");
        out.push_str(&format!(
            "  1. {} granted authority to `{}`\n",
            principal.display_role, principal.root_token.agent_id
        ));
        for (i, hop) in packet.delegation_chain.iter().enumerate() {
            out.push_str(&format!(
                "  {}. `{}` delegated to `{}`\n",
                i + 2,
                hop.issuer_id,
                hop.grantee_id
            ));
        }
    }
    out.push_str(&format!(
        "- **Executing agent:** `{}`\n",
        packet.agent.aip_id
    ));

    out.push_str("\n## Is this record trustworthy?\n\n");
    let integrity_ok = report
        .rule(crate::verification_report::rules::CANONICAL_HASH)
        .map(|r| r.pass)
        .unwrap_or(false)
        && report
            .rule(crate::verification_report::rules::AGENT_SIGNATURE)
            .map(|r| r.pass)
            .unwrap_or(false);
    out.push_str(&format!(
        "- **Tamper check:** {}\n",
        if report.tampered {
            "FAILED — this record was altered after it was sealed."
        } else if integrity_ok {
            "PASSED — the record is cryptographically intact and unaltered."
        } else {
            "not established."
        }
    ));
    out.push_str(&format!(
        "- **Authority chain verified:** {}\n",
        if report.authority_chain_verified {
            "Yes"
        } else {
            "Not in this report"
        }
    ));
    out.push_str(&format!(
        "- **Assurance level:** {:?}\n",
        report.trust_floor
    ));
    out.push_str(&format!(
        "- **Overall verification result:** {}\n",
        if report.valid {
            "VALID"
        } else {
            "NOT FULLY VERIFIED"
        }
    ));

    out.push_str(
        "\n## How to verify this independently\n\n\
         This bundle can be checked offline, without contacting the issuing system:\n\n\
         ```\n\
         aip-verify bundle.zip\n\
         ```\n\n\
         To additionally confirm the authority chain, supply the public keys of the \
         authorizing party and any intermediaries (obtained out of band):\n\n\
         ```\n\
         aip-verify bundle.zip --trust <authority-id>=<public-key-hex>\n\
         ```\n\n\
         Any modification to the evidence, the authority chain, or this bundle causes \
         verification to fail.\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iso_epoch() {
        assert_eq!(iso(0), "1970-01-01T00:00:00Z");
        // 2026-06-17T08:00:00Z = 1_781_683_200 s = 1_781_683_200_000 ms
        assert_eq!(iso(1_781_683_200_000), "2026-06-17T08:00:00Z");
        // sub-second ms are truncated to the second
        assert_eq!(iso(1_781_683_200_999), "2026-06-17T08:00:00Z");
    }

    #[test]
    fn test_bundle_hash_order_independent() {
        let a = vec![
            FileEntry {
                name: "b".into(),
                sha256: "22".into(),
            },
            FileEntry {
                name: "a".into(),
                sha256: "11".into(),
            },
        ];
        let b = vec![
            FileEntry {
                name: "a".into(),
                sha256: "11".into(),
            },
            FileEntry {
                name: "b".into(),
                sha256: "22".into(),
            },
        ];
        assert_eq!(compute_bundle_hash(&a), compute_bundle_hash(&b));
    }
}
