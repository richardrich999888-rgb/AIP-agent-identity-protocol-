//! The profile adds no architecture, checked against its own source.
//!
//! Skill 25 forbids a second reconciler, a second verifier, a second evidence
//! hierarchy, a second identity framework, a second custody model and a second
//! proof tree. The strongest available check is not "we did not build those"
//! but "this crate cannot name the types you would need in order to".
//!
//! These tests read `aip-industrial`'s source with comments stripped, because the
//! crate documents at length what it deliberately does not do, and a raw
//! substring search would either fail on that prose or be weakened until it
//! passed.

use std::path::{Path, PathBuf};

/// Remove `//` line comments and `/* */` block comments, over characters
/// rather than bytes so a non-ASCII character in a comment cannot split a
/// slice mid-codepoint. String literals are preserved.
fn strip_comments(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0usize;
    let (mut in_line, mut in_block, mut in_string) = (false, false, false);
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

fn source_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    walk(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut out,
    );
    assert!(!out.is_empty(), "no source files found");
    out
}

/// The crate's code with `#[cfg(test)]` modules and comments removed.
///
/// Unit tests legitimately construct counterfactual evidence to exercise
/// branches that no real deployment can reach; the guards below are about what
/// the *library* can do.
fn library_code() -> String {
    source_files()
        .iter()
        .map(|p| {
            let stripped = strip_comments(&std::fs::read_to_string(p).expect("read"));
            match stripped.find("#[cfg(test)]") {
                Some(i) => stripped[..i].to_string(),
                None => stripped,
            }
        })
        .collect()
}

#[test]
fn the_profile_names_no_verdict_or_strength_vocabulary() {
    let code = library_code();
    for forbidden in ["ReconciliationResult", "EvidenceStrength", "Reconciliation"] {
        assert!(
            !code.contains(forbidden),
            "aip-industrial names {forbidden} in code: a vertical profile that could produce a \
             verdict is a second verdict engine wearing a domain hat"
        );
    }
}

#[test]
fn the_profile_defines_no_reconciler_and_no_verifier() {
    let code = library_code();
    for forbidden in [
        "fn reconcile",
        "fn verify_",
        "struct Verifier",
        "struct Reconciler",
    ] {
        assert!(
            !code.contains(forbidden),
            "aip-industrial defines `{forbidden}`: reconciliation and verification belong to the core"
        );
    }
}

#[test]
fn the_profile_forks_no_core_type() {
    let code = library_code();
    for forbidden in [
        "struct SystemExecution",
        "struct ExpectedExecution",
        "struct PlatformBinding",
        "struct ObservationRecord",
        "struct ObservationProfile",
        "struct EffectAssessment",
        "enum EvidenceCeiling",
        "enum ObservationClass",
        "enum Completeness",
        "enum SourceMechanism",
    ] {
        assert!(
            !code.contains(forbidden),
            "aip-industrial defines `{forbidden}`: the profile consumes the core and must not fork it"
        );
    }
}

#[test]
fn the_profile_mints_no_identifier() {
    let code = library_code();
    for forbidden in [
        "struct SystemId",
        "struct PlatformId",
        "struct HardwareId",
        "struct MissionId",
        "struct DeviceId",
        "struct PointId",
        "struct ControllerId",
        "struct LoopId",
        "struct BoundaryId",
    ] {
        assert!(
            !code.contains(forbidden),
            "aip-industrial defines `{forbidden}`: `aip-system` owns the identifiers, and an industrial \
             deployment is expressed with them rather than beside them"
        );
    }
}

#[test]
fn the_profile_holds_no_key_and_signs_nothing() {
    let code = library_code();
    for forbidden in [
        "private_key",
        "sign_ed25519",
        "Custodian",
        "CollectorSigner",
        "signing_key",
        "keypair",
    ] {
        assert!(
            !code.contains(forbidden),
            "aip-industrial names {forbidden}: observer key custody stays in aip-observe, and a \
             profile that signed would be a second trust anchor"
        );
    }
}

#[test]
fn the_profile_builds_no_observation_record_and_attests_nothing() {
    let code = library_code();
    // Call-and-type syntax, not the bare word: this crate's prose describes
    // attestation at length in `ProcessSensingSource::trust_basis`, which
    // returns a string literal, and literals are preserved by the stripper on purpose —
    // a guard that could be satisfied by deleting documentation is a bad guard.
    for forbidden in [
        "from_attested",
        "AttestedBatch",
        "ObservedExecution",
        ".attest(",
        "verify_attested_batch",
    ] {
        assert!(
            !code.contains(forbidden),
            "aip-industrial names {forbidden}: a profile that could construct observation evidence \
             could decide what was observed about the thing it describes"
        );
    }
}

#[test]
fn the_profile_adds_no_proof_tree() {
    let code = library_code();
    for forbidden in ["LeafKind", "CommitmentLog", "merkle", "NexoraSigner"] {
        assert!(
            !code.contains(forbidden),
            "aip-industrial names {forbidden}: NEXORA's leaf kinds are frozen and an industrial proof tree \
             would be a second proof tree"
        );
    }
}

#[test]
fn the_library_never_asserts_independent_observation_directly() {
    // `PhysicalProcessEffect.independently_observed` is the field an attacker
    // — or a hurried integrator — would most want to set. It is computed in
    // exactly one place, `from_sources`, and never written anywhere else.
    let code = library_code();
    assert_eq!(
        code.matches(".independently_observed =").count(),
        0,
        "the library assigns to the field; it must be computed once and left alone"
    );
    assert_eq!(
        code.matches("let independently_observed =").count(),
        1,
        "expected exactly one computation of the value, in `from_sources`"
    );
    assert_eq!(
        code.matches("independently_observed:").count(),
        1,
        "expected exactly one field declaration; the struct literal uses field shorthand, so a \
         second `field:` would be a second place the value is decided"
    );
}

#[test]
fn no_protocol_is_marked_trusted_anywhere_in_the_library() {
    // The specification's rule: industrial protocol messages are not
    // automatically proof of physical process change. The strongest available
    // check is that the library has no vocabulary for trusting a protocol at
    // all, so a future edit has to introduce one rather than flip a flag.
    let code = library_code();
    for forbidden in [
        "is_trusted",
        "trusted_protocol",
        "fn trust(",
        "TrustedProtocol",
        "assume_authenticated",
    ] {
        assert!(
            !code.contains(forbidden),
            "aip-industrial names {forbidden}: a protocol a deployment could mark trusted is a \
             protocol whose acknowledgement becomes evidence"
        );
    }
}

#[test]
fn the_profile_contains_nothing_and_actuates_nothing() {
    // Containment stays in `aip-containment`, behind a warrant. A profile that
    // could name an actuator could eventually drive one.
    let code = library_code();
    for forbidden in [
        "struct Warrant",
        "fn contain(",
        "CgroupV2Freezer",
        "trait Actuator",
        "fn actuate",
        "fn release(",
    ] {
        assert!(
            !code.contains(forbidden),
            "aip-industrial names {forbidden}: enforcement belongs to the warrant path"
        );
    }
}

#[test]
fn the_comment_stripper_does_not_defeat_the_guards() {
    let src = "let a = 1; // EvidenceStrength\n/* ReconciliationResult */ let b = \"//kept\";";
    let out = strip_comments(src);
    assert!(!out.contains("EvidenceStrength"));
    assert!(!out.contains("ReconciliationResult"));
    assert!(out.contains("let a = 1;"));
    assert!(
        out.contains("//kept"),
        "a `//` inside a literal is not a comment"
    );
}

#[test]
fn the_stripper_handles_non_ascii_and_the_test_split_is_real() {
    let src = "let x = 1; // ceiling — never Proven ─────\nlet y = 2;";
    assert!(strip_comments(src).contains("let y = 2;"));
    assert!(!strip_comments(src).contains("Proven"));
    // And `library_code` really is smaller than the whole crate, so the
    // `#[cfg(test)]` split is doing something rather than silently no-opping.
    let whole: usize = source_files()
        .iter()
        .map(|p| std::fs::read_to_string(p).expect("read").len())
        .sum();
    assert!(
        library_code().len() < whole,
        "library_code did not strip anything"
    );
}
