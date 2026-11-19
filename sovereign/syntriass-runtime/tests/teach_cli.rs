//! `syntriass teach` through the real binary.
//!
//! These tests drive the compiled CLI, not the library, so they cover the
//! parts the unit tests cannot: argument parsing, the clause-file contract
//! shared with the A1 Python ingester, the document-digest check, and the
//! file mode of what lands on disk.
//!
//! The clause files here are written by the test rather than produced by the
//! ingester, so no Python is needed to run them. The *end-to-end* run against
//! a real PDF, with clauses from `ingest_documents.py`, is a recorded run
//! (`docs/demo/results/A2_teach_session.json`), not a test, because it needs
//! the staged Python environment.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use syntriass_runtime::adapters::supervisor::file_sha256;

const BIN: &str = env!("CARGO_BIN_EXE_syntriass");

/// A config with only the fields `teach` reads filled in meaningfully. The
/// model and sidecar paths are never opened by this command; `health` is the
/// command that checks them.
fn config(dir: &Path) -> PathBuf {
    let state = dir.join("state");
    let cfg = dir.join("config.json");
    let body = serde_json::json!({
        "state": state,
        "policy_version": "test-1",
        "security_domain": "test",
        "rag_k": 4,
        "approvers": {},
        "python": "/nonexistent/python3",
        "sidecar_script": "/nonexistent/sidecar.py",
        "llama_server": "/nonexistent/llama-server",
        "profile": "none",
        "q4": {"path": "/nonexistent/q4.gguf", "sha256": "0".repeat(64)},
        "q8": {"path": "/nonexistent/q8.gguf", "sha256": "0".repeat(64)},
        "port": 18080
    });
    std::fs::write(&cfg, serde_json::to_vec_pretty(&body).unwrap()).unwrap();
    cfg
}

/// A document and a clause file over it, in the A1 ingester's schema.
///
/// `pages` is a list of (page, clause texts). Spans are assigned so that each
/// clause's text is exactly as long as its span claims, which is what the
/// ingester guarantees and what the core checks.
fn document(dir: &Path, name: &str, pages: &[(u32, &[&str])]) -> (PathBuf, PathBuf) {
    let doc = dir.join(name);
    let mut body = String::new();
    for (page, texts) in pages {
        body.push_str(&format!("--- page {page} ---\n"));
        for t in *texts {
            body.push_str(t);
            body.push('\n');
        }
    }
    std::fs::write(&doc, &body).unwrap();
    let sha = file_sha256(&doc).unwrap();

    let mut clauses = Vec::new();
    for (page, texts) in pages {
        let mut start = 0usize;
        for (index, t) in texts.iter().enumerate() {
            clauses.push(serde_json::json!({
                "document": name,
                "document_sha256": sha,
                "page": page,
                "index": index,
                "text": t,
                "char_start": start,
                "char_end": start + t.chars().count(),
                "extraction": "txt",
            }));
            start += t.chars().count() + 1;
        }
    }
    let clause_file = dir.join(format!("{name}.clauses.json"));
    std::fs::write(
        &clause_file,
        serde_json::to_vec_pretty(&serde_json::json!({
            "document": name,
            "document_sha256": sha,
            "clause_count": clauses.len(),
            "clauses": clauses,
        }))
        .unwrap(),
    )
    .unwrap();
    (doc, clause_file)
}

fn examples(dir: &Path, lines: &[serde_json::Value]) -> PathBuf {
    let path = dir.join("examples.jsonl");
    let text: String = lines
        .iter()
        .map(|l| format!("{l}\n"))
        .collect::<Vec<_>>()
        .concat();
    std::fs::write(&path, text).unwrap();
    path
}

fn good_examples(dir: &Path) -> PathBuf {
    examples(
        dir,
        &[
            serde_json::json!({"id": "e1", "text": "Stored at 18 C for two days.",
                               "label": "allowed", "reason": "inside the stated range"}),
            serde_json::json!({"id": "e2", "text": "Stored at 31 C overnight.",
                               "label": "not_allowed", "reason": "above the 25 C ceiling"}),
        ],
    )
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("run syntriass")
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

fn stdout_json(o: &Output) -> serde_json::Value {
    assert!(o.status.success(), "command failed: {}", stderr(o));
    serde_json::from_slice(&o.stdout).expect("stdout is one JSON object")
}

const PAGE4: &[&str] = &[
    "Samples must be stored between 10 C and 25 C.",
    "Deviations require written approval.",
];
const PAGE5: &[&str] = &["Annex A lists the exempt sample classes."];

/// The whole command, start to read-back.
#[test]
fn a_teach_session_is_created_persisted_owner_only_and_read_back() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let cfg = config(tmp.path());
    let (doc, clauses) = document(tmp.path(), "policy.txt", &[(4, PAGE4)]);
    let ex = good_examples(tmp.path());

    let out = stdout_json(&run(&[
        "teach",
        "start",
        "--config",
        cfg.to_str().unwrap(),
        "--tenant",
        "acme",
        "--task",
        "storage_temperature",
        "--expert",
        "expert:qa-lead",
        "--doc",
        doc.to_str().unwrap(),
        "--page",
        "4",
        "--clauses",
        clauses.to_str().unwrap(),
        "--rule",
        "Reject anything stored outside 10 to 25 degrees.",
        "--examples",
        ex.to_str().unwrap(),
    ]));

    let id = out["session_id"].as_str().expect("session_id");
    assert_eq!(id.len(), 64);
    assert_eq!(out["tenant"], "acme");
    assert_eq!(out["document"], "policy.txt");
    assert_eq!(out["clauses"], 2);
    assert_eq!(out["examples"], 2);
    assert_eq!(out["allowed"], 1);
    assert_eq!(out["not_allowed"], 1);
    assert_eq!(out["pages"], serde_json::json!([4]));
    // Nothing came from OCR here, and the field says so rather than being absent.
    assert_eq!(out["needs_confirmation"], serde_json::json!([]));
    assert_eq!(
        out["citations"],
        serde_json::json!(["policy.txt p.4 [0:45]", "policy.txt p.4 [46:82]",])
    );

    // On disk: under the tenant, named by the hash, owner-only.
    let path = PathBuf::from(out["path"].as_str().unwrap());
    assert_eq!(
        path,
        tmp.path()
            .join("state/teach/acme")
            .join(format!("{id}.json"))
    );
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "{}", path.display());

    // `show` re-reads it and verifies the hash on the way.
    let shown = stdout_json(&run(&[
        "teach",
        "show",
        "--config",
        cfg.to_str().unwrap(),
        "--tenant",
        "acme",
        "--session",
        id,
    ]));
    assert_eq!(shown["session_id"], id);
    assert_eq!(
        shown["rule"],
        "Reject anything stored outside 10 to 25 degrees."
    );
    assert_eq!(shown["examples"][0]["reason"], "inside the stated range");

    // `list` finds exactly it.
    let listed = run(&[
        "teach",
        "list",
        "--config",
        cfg.to_str().unwrap(),
        "--tenant",
        "acme",
    ]);
    assert!(listed.status.success(), "{}", stderr(&listed));
    let lines: Vec<&str> = std::str::from_utf8(&listed.stdout)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    assert_eq!(lines.len(), 1);
    let row: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(row["session_id"], id);
    assert_eq!(row["task"], "storage_temperature");
}

#[test]
fn page_selects_which_clauses_are_cited() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = config(tmp.path());
    // The clause file holds both pages; the expert teaches from page 5 only.
    let (doc, clauses) = document(tmp.path(), "policy.txt", &[(4, PAGE4), (5, PAGE5)]);
    let ex = good_examples(tmp.path());
    let out = stdout_json(&run(&[
        "teach",
        "start",
        "--config",
        cfg.to_str().unwrap(),
        "--tenant",
        "acme",
        "--task",
        "exempt_classes",
        "--expert",
        "expert:qa-lead",
        "--doc",
        doc.to_str().unwrap(),
        "--page",
        "5",
        "--clauses",
        clauses.to_str().unwrap(),
        "--rule",
        "Exempt classes come from Annex A.",
        "--examples",
        ex.to_str().unwrap(),
    ]));
    assert_eq!(out["pages"], serde_json::json!([5]));
    assert_eq!(out["clauses"], 1);
    assert_eq!(
        out["citations"],
        serde_json::json!(["policy.txt p.5 [0:40]"])
    );
}

#[test]
fn two_pages_may_be_taught_together() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = config(tmp.path());
    let (doc, clauses) = document(tmp.path(), "policy.txt", &[(4, PAGE4), (5, PAGE5)]);
    let ex = good_examples(tmp.path());
    let out = stdout_json(&run(&[
        "teach",
        "start",
        "--config",
        cfg.to_str().unwrap(),
        "--tenant",
        "acme",
        "--task",
        "storage",
        "--expert",
        "expert:qa-lead",
        "--doc",
        doc.to_str().unwrap(),
        "--page",
        "5",
        "--page",
        "4",
        "--clauses",
        clauses.to_str().unwrap(),
        "--rule",
        "Storage range with the Annex A exemptions.",
        "--examples",
        ex.to_str().unwrap(),
    ]));
    assert_eq!(out["pages"], serde_json::json!([4, 5]));
    assert_eq!(out["clauses"], 3);
}

/// Helper for the refusal cases: run `teach start` with one thing wrong.
fn start_expecting_failure(tmp: &Path, mutate: impl FnOnce(&Path, &mut Vec<String>)) -> Output {
    let cfg = config(tmp);
    let (doc, clauses) = document(tmp, "policy.txt", &[(4, PAGE4)]);
    let ex = good_examples(tmp);
    let mut args: Vec<String> = [
        "teach",
        "start",
        "--config",
        cfg.to_str().unwrap(),
        "--tenant",
        "acme",
        "--task",
        "storage_temperature",
        "--expert",
        "expert:qa-lead",
        "--doc",
        doc.to_str().unwrap(),
        "--page",
        "4",
        "--clauses",
        clauses.to_str().unwrap(),
        "--rule",
        "Reject anything outside 10 to 25 degrees.",
        "--examples",
        ex.to_str().unwrap(),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    mutate(tmp, &mut args);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = run(&refs);
    assert!(
        !out.status.success(),
        "expected failure, got: {:?}",
        out.stdout
    );
    out
}

#[test]
fn a_document_edited_after_extraction_is_refused() {
    // The clause spans point into text that no longer exists. This is the
    // failure that would otherwise produce a session citing a revision
    // nobody can reconstruct.
    let tmp = tempfile::tempdir().unwrap();
    let out = start_expecting_failure(tmp.path(), |dir, _| {
        std::fs::write(dir.join("policy.txt"), "Everything has changed.\n").unwrap();
    });
    let e = stderr(&out);
    assert!(e.contains("does not match"), "{e}");
    assert!(e.contains("re-run the ingester"), "{e}");
}

#[test]
fn a_clause_file_for_a_different_document_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let out = start_expecting_failure(tmp.path(), |dir, args| {
        // Same bytes, so the digest matches; different name.
        let other = dir.join("other.txt");
        std::fs::copy(dir.join("policy.txt"), &other).unwrap();
        let i = args.iter().position(|a| a == "--doc").unwrap();
        args[i + 1] = other.to_str().unwrap().to_string();
    });
    assert!(
        stderr(&out).contains("clauses are for policy.txt"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_requested_page_with_no_clause_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let out = start_expecting_failure(tmp.path(), |_, args| {
        let i = args.iter().position(|a| a == "--page").unwrap();
        args[i + 1] = "9".to_string();
    });
    assert!(
        stderr(&out).contains("page 9: requested, but no clause was extracted"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn examples_of_a_single_class_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let out = start_expecting_failure(tmp.path(), |dir, _| {
        examples(
            dir,
            &[
                serde_json::json!({"id": "e1", "text": "Stored at 18 C.",
                                   "label": "allowed", "reason": "inside range"}),
                serde_json::json!({"id": "e2", "text": "Stored at 12 C.",
                                   "label": "allowed", "reason": "inside range"}),
            ],
        );
    });
    assert!(
        stderr(&out).contains("one of each label is required"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn one_example_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let out = start_expecting_failure(tmp.path(), |dir, _| {
        examples(
            dir,
            &[serde_json::json!({"id": "e1", "text": "Stored at 18 C.",
                                 "label": "allowed", "reason": "inside range"})],
        );
    });
    assert!(
        stderr(&out).contains("at least 2 required"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn an_unknown_example_label_is_refused_rather_than_coerced() {
    let tmp = tempfile::tempdir().unwrap();
    let out = start_expecting_failure(tmp.path(), |dir, _| {
        examples(
            dir,
            &[
                serde_json::json!({"id": "e1", "text": "Stored at 18 C.",
                                   "label": "probably_fine", "reason": "unsure"}),
                serde_json::json!({"id": "e2", "text": "Stored at 31 C.",
                                   "label": "not_allowed", "reason": "too warm"}),
            ],
        );
    });
    assert!(stderr(&out).contains("examples.jsonl"), "{}", stderr(&out));
}

#[test]
fn giving_both_rule_and_rule_file_is_a_usage_error() {
    let tmp = tempfile::tempdir().unwrap();
    let out = start_expecting_failure(tmp.path(), |dir, args| {
        let f = dir.join("rule.txt");
        std::fs::write(&f, "Reject anything outside 10 to 25 degrees.\n").unwrap();
        args.push("--rule-file".into());
        args.push(f.to_str().unwrap().to_string());
    });
    assert!(
        stderr(&out).contains("--rule or --rule-file, not both"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_rule_from_a_file_is_accepted() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = config(tmp.path());
    let (doc, clauses) = document(tmp.path(), "policy.txt", &[(4, PAGE4)]);
    let ex = good_examples(tmp.path());
    let rule = tmp.path().join("rule.txt");
    std::fs::write(&rule, "Reject anything stored outside 10 to 25 degrees.\n").unwrap();
    let out = stdout_json(&run(&[
        "teach",
        "start",
        "--config",
        cfg.to_str().unwrap(),
        "--tenant",
        "acme",
        "--task",
        "storage",
        "--expert",
        "expert:qa-lead",
        "--doc",
        doc.to_str().unwrap(),
        "--page",
        "4",
        "--clauses",
        clauses.to_str().unwrap(),
        "--rule-file",
        rule.to_str().unwrap(),
        "--examples",
        ex.to_str().unwrap(),
    ]));
    let shown = stdout_json(&run(&[
        "teach",
        "show",
        "--config",
        cfg.to_str().unwrap(),
        "--tenant",
        "acme",
        "--session",
        out["session_id"].as_str().unwrap(),
    ]));
    // Trailing newline from the file is preserved: the session records what
    // the expert's file said, byte for byte.
    assert_eq!(
        shown["rule"],
        "Reject anything stored outside 10 to 25 degrees.\n"
    );
}

#[test]
fn giving_no_rule_at_all_is_a_usage_error() {
    let tmp = tempfile::tempdir().unwrap();
    let out = start_expecting_failure(tmp.path(), |_, args| {
        let i = args.iter().position(|a| a == "--rule").unwrap();
        args.drain(i..i + 2);
    });
    assert!(
        stderr(&out).contains("--rule or --rule-file required"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn omitting_page_is_a_usage_error_rather_than_teaching_the_whole_document() {
    let tmp = tempfile::tempdir().unwrap();
    let out = start_expecting_failure(tmp.path(), |_, args| {
        let i = args.iter().position(|a| a == "--page").unwrap();
        args.drain(i..i + 2);
    });
    assert!(stderr(&out).contains("--page required"), "{}", stderr(&out));
}

#[test]
fn a_non_numeric_page_is_a_usage_error() {
    let tmp = tempfile::tempdir().unwrap();
    let out = start_expecting_failure(tmp.path(), |_, args| {
        let i = args.iter().position(|a| a == "--page").unwrap();
        args[i + 1] = "four".to_string();
    });
    assert!(stderr(&out).contains("--page four"), "{}", stderr(&out));
}

#[test]
fn an_unknown_teach_subcommand_prints_usage() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = config(tmp.path());
    let out = run(&["teach", "finish", "--config", cfg.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("teach {start|list|show}"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn listing_a_tenant_with_no_sessions_prints_nothing_and_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = config(tmp.path());
    let out = run(&[
        "teach",
        "list",
        "--config",
        cfg.to_str().unwrap(),
        "--tenant",
        "never-taught",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(out.stdout.is_empty(), "{:?}", out.stdout);
}

#[test]
fn one_tenant_cannot_read_anothers_session_through_the_cli() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = config(tmp.path());
    let (doc, clauses) = document(tmp.path(), "policy.txt", &[(4, PAGE4)]);
    let ex = good_examples(tmp.path());
    let out = stdout_json(&run(&[
        "teach",
        "start",
        "--config",
        cfg.to_str().unwrap(),
        "--tenant",
        "acme",
        "--task",
        "storage",
        "--expert",
        "expert:qa-lead",
        "--doc",
        doc.to_str().unwrap(),
        "--page",
        "4",
        "--clauses",
        clauses.to_str().unwrap(),
        "--rule",
        "Reject anything outside 10 to 25 degrees.",
        "--examples",
        ex.to_str().unwrap(),
    ]));
    let id = out["session_id"].as_str().unwrap();
    let other = run(&[
        "teach",
        "show",
        "--config",
        cfg.to_str().unwrap(),
        "--tenant",
        "beta",
        "--session",
        id,
    ]);
    assert!(!other.status.success());
    assert!(stderr(&other).contains("no session"), "{}", stderr(&other));
}

#[test]
fn a_session_edited_on_disk_is_refused_by_show() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = config(tmp.path());
    let (doc, clauses) = document(tmp.path(), "policy.txt", &[(4, PAGE4)]);
    let ex = good_examples(tmp.path());
    let out = stdout_json(&run(&[
        "teach",
        "start",
        "--config",
        cfg.to_str().unwrap(),
        "--tenant",
        "acme",
        "--task",
        "storage",
        "--expert",
        "expert:qa-lead",
        "--doc",
        doc.to_str().unwrap(),
        "--page",
        "4",
        "--clauses",
        clauses.to_str().unwrap(),
        "--rule",
        "Reject anything outside 10 to 25 degrees.",
        "--examples",
        ex.to_str().unwrap(),
    ]));
    let id = out["session_id"].as_str().unwrap().to_string();
    let path = PathBuf::from(out["path"].as_str().unwrap());

    let text = std::fs::read_to_string(&path).unwrap();
    let edited = text.replacen("\"not_allowed\"", "\"allowed\"", 1);
    assert_ne!(text, edited);
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, edited).unwrap();

    for cmd in [
        vec![
            "teach",
            "show",
            "--config",
            cfg.to_str().unwrap(),
            "--tenant",
            "acme",
            "--session",
            &id,
        ],
        vec![
            "teach",
            "list",
            "--config",
            cfg.to_str().unwrap(),
            "--tenant",
            "acme",
        ],
    ] {
        let o = run(&cmd);
        assert!(
            !o.status.success(),
            "{cmd:?} succeeded on a tampered session"
        );
        assert!(
            stderr(&o).contains("does not match its content"),
            "{cmd:?}: {}",
            stderr(&o)
        );
    }
}

#[test]
fn an_ocr_clause_is_flagged_for_confirmation_on_the_way_through() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = config(tmp.path());
    let (doc, clauses) = document(tmp.path(), "policy.txt", &[(4, PAGE4)]);
    // Mark the second clause as OCR, as the ingester does for an image-only page.
    let mut file: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&clauses).unwrap()).unwrap();
    file["clauses"][1]["extraction"] = serde_json::json!("pdf_ocr");
    std::fs::write(&clauses, serde_json::to_vec_pretty(&file).unwrap()).unwrap();

    let ex = good_examples(tmp.path());
    let out = stdout_json(&run(&[
        "teach",
        "start",
        "--config",
        cfg.to_str().unwrap(),
        "--tenant",
        "acme",
        "--task",
        "storage",
        "--expert",
        "expert:qa-lead",
        "--doc",
        doc.to_str().unwrap(),
        "--page",
        "4",
        "--clauses",
        clauses.to_str().unwrap(),
        "--rule",
        "Reject anything outside 10 to 25 degrees.",
        "--examples",
        ex.to_str().unwrap(),
    ]));
    assert_eq!(out["needs_confirmation"], serde_json::json!(["p4#1"]));
}
