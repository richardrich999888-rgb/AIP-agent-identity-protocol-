//! Gate 8 — a collector *process* restarts. Linux only. The
//! `ghost-demo-collector` binary (NOT_PRODUCTION_CAPABILITY) starts a
//! collector runtime over a state directory, attests a few empty batches
//! with a health record after each, and exits; run again over the same
//! directory it must resume the same chain; run over a rolled-back state
//! file in strict mode it must refuse.

#![cfg(target_os = "linux")]

use std::process::Command;

const COLLECTOR: &str = env!("CARGO_BIN_EXE_ghost-demo-collector");

fn run(dir: &std::path::Path, extra: &[&str]) -> (i32, String) {
    let out = Command::new(COLLECTOR)
        .arg("--dir")
        .arg(dir)
        .arg("--observer")
        .arg("demo-collector")
        .arg("--batches")
        .arg("2")
        .args(extra)
        .output()
        .expect("run collector");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

fn field<'a>(out: &'a str, key: &str) -> &'a str {
    out.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("no {key} in {out}"))
}

#[test]
fn p_r_the_collector_resumes_its_own_chain_across_a_process_restart_and_refuses_a_rollback() {
    let dir = std::env::temp_dir().join(format!("ghost-collector-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let (code, out) = run(&dir, &["--strict"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(field(&out, "started"), "fresh");
    assert_eq!(field(&out, "sequence"), "2");
    let head1 = field(&out, "head").to_string();
    let state_file = dir.join("collector.snapshot.json");
    let old_state = std::fs::read(&state_file).unwrap();

    let (code, out) = run(&dir, &["--strict"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(field(&out, "started"), "resumed");
    assert_eq!(field(&out, "state-at-start"), "Recovering");
    assert_eq!(
        field(&out, "sequence"),
        "4",
        "one chain across two processes"
    );
    assert_ne!(field(&out, "head"), head1);
    assert_eq!(field(&out, "state-at-end"), "Active");

    // An operator restores the state file from after the first run.
    std::fs::write(&state_file, &old_state).unwrap();
    let (code, out) = run(&dir, &["--strict"]);
    assert_eq!(code, 3, "strict refuses to sign after a rollback: {out}");
    assert!(
        field(&out, "started").starts_with("refused:RolledBack"),
        "{out}"
    );
    let reports = std::fs::read_to_string(dir.join("continuity.reports.jsonl")).unwrap();
    assert_eq!(reports.lines().count(), 1, "the refusal is a signed report");

    // Advisory: adopts the archive head and continues from it.
    let (code, out) = run(&dir, &[]);
    assert_eq!(code, 0, "{out}");
    assert!(
        field(&out, "started").starts_with("resumed-with-break:RolledBack"),
        "{out}"
    );
    assert_eq!(
        field(&out, "sequence"),
        "6",
        "the archive head (4) was adopted, not the old state (2)"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
