//! Structural guards (ADR-017). The product consumes the core; it must not
//! become a second copy of it.

use std::path::{Path, PathBuf};

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Strip `//` and `/* */` comments so a guard is not tripped — or defeated —
/// by prose. String literals are kept.
fn strip_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    let (mut line, mut block, mut string) = (false, false, false);
    while let Some(c) = chars.next() {
        if line {
            if c == '\n' {
                line = false;
                out.push(c);
            }
            continue;
        }
        if block {
            if c == '*' && chars.peek() == Some(&'/') {
                chars.next();
                block = false;
            }
            continue;
        }
        if string {
            out.push(c);
            if c == '\\' {
                if let Some(n) = chars.next() {
                    out.push(n);
                }
            } else if c == '"' {
                string = false;
            }
            continue;
        }
        match c {
            '"' => {
                string = true;
                out.push(c);
            }
            '/' if chars.peek() == Some(&'/') => {
                chars.next();
                line = true;
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                block = true;
            }
            _ => out.push(c),
        }
    }
    out
}

fn sources(dir: &Path, skip: &[&str]) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if skip.iter().any(|s| p.ends_with(s)) {
                continue;
            }
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push((
                    p.clone(),
                    strip_comments(&std::fs::read_to_string(&p).unwrap()),
                ));
            }
        }
    }
    out.sort();
    out
}

fn library() -> Vec<(PathBuf, String)> {
    sources(&crate_root().join("src"), &[])
}

/// **A6.** NEXORA is the authoritative verifier. The assessor reads
/// `VerifiedProof`; it never reconciles.
#[test]
fn the_assessor_never_reconciles() {
    for (p, code) in library() {
        for f in [
            "reconcile_expectation",
            "reconcile_observation",
            "reconcile_lineage",
            "fn reconcile",
        ] {
            assert!(!code.contains(f), "{} calls or defines `{f}`", p.display());
        }
    }
}

/// **A7.** No verdict, strength, ceiling, observation class or proof verdict
/// of its own.
#[test]
fn the_crate_defines_no_security_semantics_of_its_own() {
    for (p, code) in library() {
        for f in [
            "enum ReconciliationResult",
            "enum EvidenceStrength",
            "enum EvidenceCeiling",
            "enum ObservationClass",
            "enum ProofVerdict",
            "fn verify_nexora_proof",
            "fn verify_delegation_chain",
            "fn validate_aid",
            "fn verify_expected_execution",
        ] {
            assert!(!code.contains(f), "{} defines `{f}`", p.display());
        }
    }
}

/// The output vocabulary has no word for an overclaim.
#[test]
fn the_vocabulary_has_no_word_for_an_overclaim() {
    for (p, code) in library() {
        for w in [
            "Assumed",
            "Trusted",
            "Compliant",
            "Mitigated",
            "Waived",
            "Certified",
        ] {
            assert!(!code.contains(w), "{} uses `{w}`", p.display());
        }
    }
}

/// **A8.** Outputs cannot be read back from bytes.
#[test]
fn outputs_are_not_deserialisable() {
    let all: String = library().into_iter().map(|(_, c)| c).collect();
    for item in [
        "pub struct Assessment",
        "pub struct AssessedField",
        "pub enum SealStanding",
        "pub enum Standing",
        "pub struct Finding",
        "pub struct Discovery",
        "pub struct DiscoveredServer",
        "pub struct SecretExposure",
    ] {
        let at = all.find(item).unwrap_or_else(|| panic!("{item} not found"));
        let before = &all[..at];
        let derive = before.rfind("#[derive(").expect("a derive precedes it");
        assert!(
            !before[derive..].contains("Deserialize"),
            "{item} is Deserialize"
        );
    }
}

/// **A3.** The bundle has exactly the fields it has: no key, anchor,
/// revocation or clock can be added without this test failing.
#[test]
fn the_bundle_carries_no_trust_input() {
    let v = serde_json::to_value(aip_aibom::evidence::EvidenceBundle::default()).unwrap();
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort();
    // Every entry is an artifact the assessor re-verifies under anchors of its
    // own. Adding a field here is a review decision, not a refactor: if the
    // new field could carry a key, an anchor, a revocation or a time, it does
    // not belong in the bundle.
    assert_eq!(
        keys,
        [
            "access_ledgers",
            "approvals",
            "authority",
            "expectations",
            "identity",
            "parent_identity",
            "proofs",
            "spend_attestations",
            "spend_policies",
            "spend_refusals",
            "tool_receipts",
        ]
    );
}

/// The engine reads no clock, environment, or file. IO lives in `adapters/`
/// and `bin/`.
#[test]
fn the_core_performs_no_io() {
    for (p, code) in sources(&crate_root().join("src"), &["adapters", "bin"]) {
        for f in [
            "SystemTime",
            "Instant::now",
            "std::env",
            "std::fs",
            "File::open",
            "std::net",
        ] {
            assert!(!code.contains(f), "{} uses `{f}`", p.display());
        }
    }
}

/// Cited non-establishments are quoted verbatim from the file that records
/// them, so the two cannot drift.
#[test]
fn every_cited_non_establishment_matches_the_record() {
    use aip_aibom::standing::NonEstablishment as N;
    let record =
        std::fs::read_to_string(crate_root().join("../../docs/architecture/AIRI_LIMITATIONS.md"))
            .unwrap();
    for n in [N::N2, N::N3, N::N4, N::N10] {
        let row = format!("| {} | {} |", n.code(), n.statement());
        assert!(
            record.contains(&row),
            "AIRI_LIMITATIONS.md has no row `{row}`"
        );
    }
}

/// **A14.** Nothing in the workspace depends on the product.
#[test]
fn nothing_depends_on_the_product() {
    let standalone = crate_root().parent().unwrap().to_path_buf();
    let mut checked = 0;
    for e in std::fs::read_dir(&standalone).unwrap() {
        let p = e.unwrap().path();
        let manifest = p.join("Cargo.toml");
        if !manifest.is_file() || p == crate_root() {
            continue;
        }
        let body: String = std::fs::read_to_string(&manifest)
            .unwrap()
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !body.contains("aip-aibom"),
            "{} depends on aip-aibom",
            p.display()
        );
        checked += 1;
    }
    assert!(checked >= 25, "only {checked} manifests checked");
}

#[test]
fn the_comment_stripper_keeps_code_and_drops_prose() {
    let s = strip_comments("let a = 1; // Mitigated\n/* Trusted */ let b = \"// kept\";");
    assert!(!s.contains("Mitigated") && !s.contains("Trusted"));
    assert!(s.contains("let a = 1;") && s.contains("\"// kept\""));
}
