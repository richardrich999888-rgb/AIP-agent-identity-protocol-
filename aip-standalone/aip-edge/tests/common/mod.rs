//! Shared harness for the reference tests.
//!
//! Every helper here drives the **real** three-process path. Nothing in this
//! module builds an `ObservationRecord`, an `AttestedBatch` or an
//! `ObservedExecution` by hand: a fixture may configure the expectation, and a
//! fixture must never manufacture the observation.
//!
//! Each test binary uses a different subset of these helpers, so unused ones
//! are expected rather than a sign of drift.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use aip_edge::orchestrate::{run, RunConfig, RunOutcome, Scenario};
use aip_system::{PlatformId, SystemId};

/// Monotonic counter so concurrently running tests never share a state
/// directory. Combined with the pid it is unique across parallel test binaries
/// too.
static NONCE: AtomicU64 = AtomicU64::new(0);

pub fn scratch(tag: &str) -> PathBuf {
    let n = NONCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aip-edge-test-{}-{tag}-{n}", std::process::id()))
}

pub fn system_id() -> SystemId {
    SystemId::parse("edge:reference-system").expect("system id")
}

pub fn platform(name: &str) -> PlatformId {
    PlatformId::parse(name).expect("platform id")
}

pub fn config(dir: PathBuf, scenario: Scenario) -> RunConfig {
    RunConfig {
        dir,
        system_id: system_id(),
        authorized_platform: platform("edge:reference-platform"),
        registered_platform: match scenario {
            Scenario::WrongPlatform => platform("edge:other-platform"),
            _ => platform("edge:reference-platform"),
        },
        scenario,
    }
}

/// Build the sibling binaries the reference spawns.
///
/// The logic moved into `aip_edge::transport` so the five profile crates that
/// drive the same orchestrator share one copy rather than each needing their
/// own -- which none of them had, so their tests passed only when this
/// crate's tests happened to run first in the same invocation. This wrapper
/// stays so the harness reads the same as before.
pub fn ensure_sibling_binaries() {
    aip_edge::transport::ensure_sibling_binaries().expect("build the sibling binaries");
}

/// Run one scenario end to end and clean up the state directory.
///
/// Panics with the underlying error rather than skipping. A reference test
/// that quietly does nothing when its own binaries are missing is worse than
/// one that stops and names the command that builds them.
pub fn run_scenario(tag: &str, scenario: Scenario) -> RunOutcome {
    ensure_sibling_binaries();
    let dir = scratch(tag);
    let cfg = config(dir.clone(), scenario);
    let outcome = run(&cfg).unwrap_or_else(|e| panic!("{tag}: {e}"));
    let _ = std::fs::remove_dir_all(&dir);
    outcome
}

/// Read a workspace member's manifest. Used by the dependency-isolation
/// guards, which are the mechanical form of the reference's central claim.
pub fn manifest(crate_name: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("aip-standalone")
        .to_path_buf();
    let path = root.join(crate_name).join("Cargo.toml");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The dependency names a manifest declares, ignoring comments.
///
/// Deliberately naive and deliberately *inclusive*: it takes every
/// `name = ...` line inside any `[...dependencies]` table, so a dependency
/// added under `[dev-dependencies]` or `[build-dependencies]` is caught too.
/// A guard that only looked at `[dependencies]` would miss the easiest way to
/// reintroduce the linkage it exists to forbid.
pub fn declared_dependencies(manifest: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_deps = false;
    for raw in manifest.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') {
            in_deps = line.contains("dependencies");
            continue;
        }
        if !in_deps || line.is_empty() {
            continue;
        }
        if let Some((name, _)) = line.split_once('=') {
            let name = name.trim();
            if !name.is_empty() {
                out.push(name.to_string());
            }
        }
    }
    out
}

/// Remove `//` line comments and `/* */` block comments, over characters
/// rather than bytes so a non-ASCII character in a comment cannot split a
/// slice mid-codepoint.
pub fn strip_comments(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0usize;
    let mut in_line = false;
    let mut in_block = false;
    let mut in_string = false;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if in_line {
            if c == '\n' {
                in_line = false;
                out.push(c);
            }
            i += 1;
            continue;
        }
        if in_block {
            if c == '*' && next == Some('/') {
                in_block = false;
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if in_string {
            if c == '\\' {
                out.push(c);
                if let Some(n) = next {
                    out.push(n);
                }
                i += 2;
                continue;
            }
            if c == '"' {
                in_string = false;
            }
            out.push(c);
            i += 1;
            continue;
        }
        match (c, next) {
            ('/', Some('/')) => {
                in_line = true;
                i += 2;
            }
            ('/', Some('*')) => {
                in_block = true;
                i += 2;
            }
            ('"', _) => {
                in_string = true;
                out.push(c);
                i += 1;
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}
