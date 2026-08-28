//! Cross-language proof for the Python SDK: a chain built by
//! `sdks/python/otgovern` must verify byte-for-byte under this Rust
//! verifier — the fourth implementation (after Rust native, browser WASM,
//! and TypeScript) of the one canonical-bytes contract.
//!
//! Skips cleanly when `python3` is not on PATH (self-hosted runners without
//! Python); CI's ubuntu runners have it.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate lives two levels under the repo root")
        .to_path_buf()
}

fn python3() -> Option<&'static str> {
    Command::new("python3")
        .arg("--version")
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|_| "python3")
}

fn run_selftest(out: &Path, tamper: bool) {
    let mut cmd = Command::new("python3");
    cmd.current_dir(repo_root().join("sdks/python"))
        .arg("-m")
        .arg("otgovern.selftest")
        .arg(out);
    if tamper {
        cmd.arg("--tamper");
    }
    let output = cmd.output().expect("selftest runs");
    assert!(
        output.status.success(),
        "python selftest failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );
}

fn verify(path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ot-verifier"))
        .args(["--dossier", path.to_str().unwrap()])
        .output()
        .expect("verifier runs")
}

#[test]
fn a_chain_built_by_the_python_sdk_verifies_under_the_rust_core() {
    if python3().is_none() {
        eprintln!("skipping: python3 not on PATH");
        return;
    }
    let out = std::env::temp_dir().join(format!("otgovern-py-{}.jsonl", std::process::id()));

    run_selftest(&out, false);
    let output = verify(&out);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "expected [PASS]: {stdout}");
    // The selftest seals a SUCCESS, a FAILED, and a BLOCKED packet.
    assert!(stdout.contains("3 packets"), "{stdout}");

    // A one-string edit to the Python-built stream breaks at its sequence.
    run_selftest(&out, true);
    let output = verify(&out);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("sequence 1"),
        "{}",
        String::from_utf8_lossy(&output.stdout),
    );
}
