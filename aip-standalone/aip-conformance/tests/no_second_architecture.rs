//! The conformance program's own discipline.
//!
//! A conformance program is in an unusual position: it depends on everything
//! and is trusted to say whether everything is correct. Two things keep that
//! from becoming a second source of truth.
//!
//! **It states no semantics.** Every invariant is a question asked of the
//! core by calling the core. Nothing here defines a verdict, a ceiling, an
//! observation class or an identifier; nothing holds a key or signs anything.
//!
//! **Nothing depends on it.** A conformance program something else depended
//! on could change what it is checking. The manifest guard below reads every
//! crate in the workspace and fails if any names this one.

use std::path::PathBuf;

/// Strip `//` line comments and `/* */` blocks so a guard cannot be defeated
/// by the word it is looking for appearing in prose. Same approach as the
/// five profile crates' own guards.
fn strip_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    let (mut in_line, mut in_block, mut in_str) = (false, false, false);
    while let Some(c) = chars.next() {
        if in_line {
            if c == '\n' {
                in_line = false;
                out.push(c);
            }
            continue;
        }
        if in_block {
            if c == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block = false;
            }
            continue;
        }
        if in_str {
            if c == '\\' {
                chars.next();
                continue;
            }
            if c == '"' {
                in_str = false;
            }
            out.push(c);
            continue;
        }
        match c {
            '"' => {
                in_str = true;
                out.push(c);
            }
            '/' if chars.peek() == Some(&'/') => {
                chars.next();
                in_line = true;
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                in_block = true;
            }
            _ => out.push(c),
        }
    }
    out
}

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// This crate's library sources, comments stripped, `#[cfg(test)]` onwards
/// truncated — a guard that read its own test module would find every word it
/// forbids.
fn library_code() -> String {
    let mut all = String::new();
    let src = crate_root().join("src");
    let mut stack = vec![src];
    let mut files: Vec<PathBuf> = Vec::new();
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).expect("src must be readable") {
            let p = e.expect("entry").path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
                files.push(p);
            }
        }
    }
    files.sort();
    for f in files {
        let raw = std::fs::read_to_string(&f).expect("source readable");
        let stripped = strip_comments(&raw);
        let cut = stripped.find("#[cfg(test)]").unwrap_or(stripped.len());
        all.push_str(&stripped[..cut]);
        all.push('\n');
    }
    all
}

/// The program defines no verdict, no ceiling, no observation class and no
/// evidence hierarchy of its own. Its vocabulary is `Conformance`, which is
/// about *the check*, not about a workload.
#[test]
fn the_program_defines_no_security_semantics_of_its_own() {
    let code = library_code();
    for forbidden in [
        "enum ReconciliationResult",
        "enum EvidenceCeiling",
        "enum ObservationClass",
        "enum EvidenceStrength",
        "enum SourceMechanism",
        "enum ObserverState",
        "enum ProofVerdict",
        "fn reconcile",
        "fn verify_proof",
        "fn verify_nexora_proof",
    ] {
        assert!(
            !code.contains(forbidden),
            "the conformance program must not define `{forbidden}`; it asks the core, it does not restate it"
        );
    }
}

/// It holds no key and signs nothing. A conformance program that could sign
/// could manufacture the evidence it reports on.
#[test]
fn the_program_holds_no_key_and_signs_nothing() {
    let code = library_code();
    for forbidden in [
        "generate_ed25519_keypair",
        "sign_ed25519",
        "SigningKey",
        "private_key",
        "CollectorSigner",
        "NexoraSigner",
    ] {
        assert!(
            !code.contains(forbidden),
            "the conformance program's library must not reference `{forbidden}`"
        );
    }
}

/// It mints no identifier. Every id in the artifact is read from the crate
/// that owns it.
#[test]
fn the_program_mints_no_identifier() {
    let code = library_code();
    for forbidden in [
        "derive_aip_id",
        "create_identity",
        "fn mint",
        "Uuid",
        "rand",
    ] {
        assert!(
            !code.contains(forbidden),
            "the conformance program must not mint `{forbidden}`"
        );
    }
    // Every profile id in the artifact comes from the profile's own constant.
    assert!(code.contains("aip_uas::UAS_PROFILE_ID"));
    assert!(code.contains("aip_enterprise::ENTERPRISE_PROFILE_ID"));
    assert!(code.contains("aip_space::SPACE_PROFILE_ID"));
    assert!(code.contains("aip_robotics::ROBOTICS_PROFILE_ID"));
    assert!(code.contains("aip_industrial::INDUSTRIAL_PROFILE_ID"));
}

/// **The direction guard.** Nothing in the workspace depends on the
/// conformance program. A program something depended on could change what it
/// is checking.
#[test]
fn nothing_in_the_workspace_depends_on_the_conformance_program() {
    let standalone = crate_root().parent().expect("aip-standalone").to_path_buf();
    let mut checked = 0usize;
    for e in std::fs::read_dir(&standalone).expect("aip-standalone readable") {
        let p = e.expect("entry").path();
        let manifest = p.join("Cargo.toml");
        if !manifest.is_file() || p == crate_root() {
            continue;
        }
        let body = std::fs::read_to_string(&manifest).expect("manifest readable");
        let code: String = body
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !code.contains("aip-conformance"),
            "{} depends on the conformance program",
            p.display()
        );
        checked += 1;
    }
    assert!(
        checked >= 25,
        "only {checked} manifests were checked, which is too few to be working"
    );

    // The service tier is a sibling of aip-standalone, not inside it.
    let service = standalone
        .parent()
        .expect("workspace root")
        .join("aip-service/Cargo.toml");
    if service.is_file() {
        let body = std::fs::read_to_string(&service).expect("service manifest readable");
        assert!(!body.contains("aip-conformance"));
    }
}

/// The comment stripper is real: a guard defeated by prose would pass while
/// the property it names was violated.
#[test]
fn the_comment_stripper_does_not_defeat_the_guards() {
    let src = r#"
// fn reconcile in a line comment
/* enum EvidenceCeiling in a block */
let s = "fn reconcile in a string survives";
fn actual_code() {}
"#;
    let out = strip_comments(src);
    assert!(!out.contains("in a line comment"));
    assert!(!out.contains("in a block"));
    assert!(out.contains("in a string survives"), "strings are code");
    assert!(out.contains("fn actual_code"));

    // And the truncation is real.
    let code = library_code();
    assert!(!code.is_empty());
    assert!(
        code.contains("pub fn build"),
        "the library body must be present"
    );
}
