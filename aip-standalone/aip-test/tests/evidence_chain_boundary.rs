//! The interim rule of `docs/adr/ADR-EVIDENCE-CHAIN-FORMAT.md`, enforced
//! mechanically rather than believed.
//!
//! # What this guards
//!
//! This repository contains two hash-chained evidence constructions, and they
//! are **not byte-compatible**: `aip-core` chains raw 32-byte digests,
//! `ot-accountability-core` chains `SHA-256(previous ‖ canonical JSON)` as
//! hex. A packet sealed by one will not verify under the other. Which of them
//! this system settles on is an open decision with an owner and an ADR; it is
//! not a decision anyone should make by adding a line to a `Cargo.toml`.
//!
//! Before the OrbitalTrust crates were wired into the workspace the second
//! construction was inert — files on disk that nothing compiled. It is now a
//! workspace member, which means a caller can reach it, seal something with
//! it, and get evidence that none of this repository's three offline
//! verifiers will accept. That failure is silent at the point of the mistake
//! and loud months later at an audit.
//!
//! So the boundary is a test. The ADR says in terms that "the exclusion is
//! only worth what it is checked by", and prose in a README is checked by
//! nothing.
//!
//! # Why a manifest scan rather than a runtime check
//!
//! Same reasoning as `aip-edge/tests/dependency_isolation.rs`: a runtime
//! check tests the code that exists, a manifest guard tests every line anyone
//! will ever write in those crates. `[dev-dependencies]` and
//! `[build-dependencies]` are scanned too, because adding the dependency
//! there is the cheapest way to reintroduce exactly what this forbids.
//!
//! # How to make this test pass legitimately
//!
//! By closing the ADR, not by editing this file. If the decision is that the
//! imported format is adopted somewhere, that is option A or B in
//! `ADR-EVIDENCE-CHAIN-FORMAT.md` and it changes what this test asserts.

use std::path::{Path, PathBuf};

/// The imported crate whose chain format is incompatible with `aip-core`'s.
const FOREIGN_CHAIN: &str = "ot-accountability-core";

/// Where the imported crates live. Anything under here may depend on the
/// imported format: that is the bounded region the ADR's interim rule draws.
const IMPORT_ROOT: &str = "orbitaltrust-accountability";

fn repo_root() -> PathBuf {
    // `aip-standalone/aip-test` → `aip-standalone` → repository root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("aip-test lives two levels below the repository root")
        .to_path_buf()
}

/// Every `Cargo.toml` in the repository, excluding `target/` and the imported
/// tree itself.
fn manifests_outside_the_import(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if name == "target" || name == ".git" || name == IMPORT_ROOT {
                continue;
            }
            manifests_outside_the_import(&path, out);
        } else if name == "Cargo.toml" {
            out.push(path);
        }
    }
}

/// Dependency names a manifest declares, ignoring comments.
///
/// Deliberately inclusive: every `name = …` line inside any `[…dependencies]`
/// table, so a dependency added under `[dev-dependencies]` is caught too. A
/// commented-out line is not a dependency, which matters here because
/// `ot-sentinel`'s manifest documents its absent dependencies as comments.
fn declared_dependencies(manifest: &str) -> Vec<String> {
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

#[test]
fn no_crate_outside_the_import_depends_on_the_foreign_evidence_chain() {
    let root = repo_root();
    let mut manifests = Vec::new();
    manifests_outside_the_import(&root, &mut manifests);
    assert!(
        manifests.len() > 30,
        "expected to scan the whole workspace, found only {} manifests under {} — the walk \
         is broken and this test is passing vacuously",
        manifests.len(),
        root.display()
    );

    let mut offenders = Vec::new();
    for path in &manifests {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        if declared_dependencies(&text)
            .iter()
            .any(|d| d == FOREIGN_CHAIN)
        {
            offenders.push(
                path.strip_prefix(&root)
                    .unwrap_or(path)
                    .display()
                    .to_string(),
            );
        }
    }

    assert!(
        offenders.is_empty(),
        "{offenders:?} depend on `{FOREIGN_CHAIN}`, whose hash chain is not byte-compatible \
         with `aip-core`'s: it chains SHA-256(previous || canonical JSON) as hex where \
         aip-core chains raw 32-byte digests, so a packet sealed by one will not verify \
         under the other. Which format this system settles on is open — see \
         docs/adr/ADR-EVIDENCE-CHAIN-FORMAT.md — and is not a decision to make by adding a \
         dependency. Close the ADR first."
    );
}

/// The guard above is worthless if the crate it names has been renamed or
/// removed, because then it forbids something that does not exist and passes
/// forever. This pins that it is still there to be depended on.
#[test]
fn the_foreign_chain_crate_still_exists_under_the_import() {
    let manifest = repo_root()
        .join(IMPORT_ROOT)
        .join("rust")
        .join(FOREIGN_CHAIN)
        .join("Cargo.toml");
    assert!(
        manifest.exists(),
        "{} is missing, so the boundary test above forbids a dependency nothing could \
         declare and would pass whatever anyone did. If the crate moved, move this guard \
         with it; if it was removed, the ADR is closed and both tests should go.",
        manifest.display()
    );
}
