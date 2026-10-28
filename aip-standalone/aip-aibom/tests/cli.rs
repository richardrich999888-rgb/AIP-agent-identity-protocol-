//! The `aibom` binary end to end: real files, real exit codes.

mod common;

use aip_aibom::evidence::{AuthorityChain, ContextFile, EvidenceBundle};
use common::*;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Command, Output};

const SECRET: &str = "sk-live-cli-test-77aa";

fn dir(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("aibom-cli")
        .join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn aibom(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_aibom"))
        .args(args)
        .output()
        .unwrap()
}

fn code(o: &Output) -> i32 {
    o.status.code().expect("exited normally")
}

fn write_json<T: serde::Serialize>(path: &PathBuf, v: &T) -> String {
    std::fs::write(path, serde_json::to_vec_pretty(v).unwrap()).unwrap();
    path.display().to_string()
}

#[test]
fn digest_prints_the_canonical_sha256() {
    let d = dir("digest");
    let m = manifest("agent");
    let p = write_json(&d.join("m.json"), &m);
    let o = aibom(&["digest", "--manifest", &p]);
    assert_eq!(code(&o), 0);
    let out = String::from_utf8(o.stdout).unwrap();
    assert_eq!(
        out.trim(),
        format!("sha256:{}", aip_aibom::canonical::manifest_digest_hex(&m))
    );
}

#[test]
fn a_refused_manifest_exits_with_the_input_error_status() {
    let d = dir("refused");
    let p = d.join("m.json");
    std::fs::write(&p, br#"{"schema_version": 1, "verified": true}"#).unwrap();
    let o = aibom(&["digest", "--manifest", p.to_str().unwrap()]);
    assert_eq!(code(&o), 1);
    assert!(!o.stderr.is_empty());
}

/// A mistyped flag is an input error, never the gate status.
#[test]
fn a_usage_error_is_not_the_gate_status() {
    assert_eq!(code(&aibom(&["assess", "--manifest", "x.json"])), 1);
    assert_eq!(code(&aibom(&["no-such-command"])), 1);
    assert_eq!(code(&aibom(&["--help"])), 0);
}

#[test]
fn assess_verifies_through_the_context_and_gates_on_critical_findings() {
    let d = dir("assess");
    let cfo = principal("cfo");
    let (doc, _) = active_identity("treasury-agent");
    let token = grant(
        &cfo,
        &doc.id,
        scope(&["create_payment"], &[]),
        Some(HOUR_MS),
    );
    let now = (token.issued_at + 1).to_string();

    let mut m = manifest(&doc.id);
    m.permissions.allowed = vec![custom("create_payment")];
    let mp = write_json(&d.join("manifest.json"), &m);
    let bundle = EvidenceBundle {
        identity: Some(doc),
        authority: vec![AuthorityChain {
            root: token,
            delegations: vec![],
        }],
        ..Default::default()
    };
    let ep = write_json(&d.join("evidence.json"), &bundle);
    let mut issuers = BTreeMap::new();
    issuers.insert(cfo.id.clone(), hex::encode(&cfo.kp.public_key));
    let cp = write_json(
        &d.join("context.json"),
        &ContextFile {
            issuers,
            ..Default::default()
        },
    );

    let o = aibom(&[
        "assess",
        "--manifest",
        &mp,
        "--evidence",
        &ep,
        "--context",
        &cp,
        "--now-ms",
        &now,
        "--format",
        "json",
    ]);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let field = v["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"] == "$.permissions.allowed[0]")
        .unwrap();
    assert_eq!(field["standing"]["standing"], "verified");

    // Without the assessor's context, the same evidence verifies nothing.
    let o = aibom(&[
        "assess",
        "--manifest",
        &mp,
        "--evidence",
        &ep,
        "--now-ms",
        &now,
        "--format",
        "json",
    ]);
    assert_eq!(code(&o), 2, "a rejected chain is critical");

    // A secret in an MCP config trips the gate and never reaches the output.
    let cfg = d.join("mcp.json");
    std::fs::write(&cfg, format!(r#"{{"mcpServers": {{"ledger": {{"command": "npx", "env": {{"LEDGER_API_KEY": "{SECRET}"}}}}}}}}"#)).unwrap();
    for format in ["text", "json", "fields-csv", "findings-csv"] {
        let o = aibom(&[
            "assess",
            "--manifest",
            &mp,
            "--evidence",
            &ep,
            "--context",
            &cp,
            "--mcp-config",
            cfg.to_str().unwrap(),
            "--now-ms",
            &now,
            "--format",
            format,
        ]);
        assert_eq!(code(&o), 2, "{format}");
        assert!(
            !String::from_utf8_lossy(&o.stdout).contains(SECRET),
            "{format} leaked the secret"
        );
        assert!(!String::from_utf8_lossy(&o.stderr).contains(SECRET));
    }
    let o = aibom(&["discover", "--mcp-config", cfg.to_str().unwrap()]);
    assert_eq!(code(&o), 0);
    assert!(!String::from_utf8_lossy(&o.stdout).contains(SECRET));
}

#[test]
fn diff_gates_on_widening_only() {
    let d = dir("diff");
    let old = manifest("agent");
    let mut wider = old.clone();
    wider.permissions.allowed.push(custom("wire_transfer"));
    let mut bumped = old.clone();
    bumped.agent.version = "1.3.0".into();
    let (o, w, b) = (
        write_json(&d.join("old.json"), &old),
        write_json(&d.join("wider.json"), &wider),
        write_json(&d.join("bumped.json"), &bumped),
    );
    assert_eq!(code(&aibom(&["diff", "--old", &o, "--new", &w])), 2);
    assert_eq!(code(&aibom(&["diff", "--old", &o, "--new", &b])), 0);
    let j = aibom(&["diff", "--old", &o, "--new", &w, "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&j.stdout).unwrap();
    assert_eq!(v[0]["direction"], "widening");
}
