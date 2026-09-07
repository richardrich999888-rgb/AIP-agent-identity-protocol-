//! The adapter adds no architecture, checked against its own source.
//!
//! The brief forbids a second identity framework, authorization engine,
//! reconciliation engine, evidence hierarchy, observation hierarchy, verifier,
//! proof tree, signer/custody system and NEXORA implementation. The strongest
//! available check is not "we did not build those" but "this crate cannot name
//! the types you would need in order to".
//!
//! Same stripper as the vertical profiles' guards: comments are removed, string
//! literals are kept, and `#[cfg(test)]` modules are dropped — because the
//! library's prose describes at length what it deliberately does not do, and a
//! raw substring search would either fail on that prose or be weakened until it
//! passed.

use std::path::{Path, PathBuf};

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
fn the_adapter_defines_no_verdict_or_strength_vocabulary() {
    let code = library_code();
    for forbidden in ["ReconciliationResult", "EvidenceStrength", "Reconciliation"] {
        assert!(
            !code.contains(forbidden),
            "the adapter names {forbidden}: a validation tool that could produce a verdict is a \
             second verdict engine wearing a laboratory coat"
        );
    }
}

#[test]
fn the_adapter_defines_no_reconciler_and_no_verifier() {
    let code = library_code();
    for forbidden in [
        "fn reconcile",
        "fn verify_",
        "struct Verifier",
        "struct Reconciler",
    ] {
        assert!(
            !code.contains(forbidden),
            "the adapter defines `{forbidden}`: reconciliation and verification belong to the core"
        );
    }
}

#[test]
fn the_adapter_forks_no_core_type() {
    let code = library_code();
    for forbidden in [
        "struct ObservationRecord",
        "struct ObservationProfile",
        "struct SystemExecution",
        "struct ExpectedExecution",
        "struct PlatformBinding",
        "struct EffectAssessment",
        "enum EvidenceCeiling",
        "enum ObservationClass",
        "enum SourceMechanism",
        "enum Completeness",
    ] {
        assert!(
            !code.contains(forbidden),
            "the adapter defines `{forbidden}`: it consumes the core vocabulary and must not \
             fork it"
        );
    }
}

#[test]
fn the_adapter_mints_no_identifier() {
    let code = library_code();
    for forbidden in [
        "struct SystemId",
        "struct PlatformId",
        "struct HardwareId",
        "struct MissionId",
        "struct AgentId",
        "struct ObserverId",
    ] {
        assert!(
            !code.contains(forbidden),
            "the adapter defines `{forbidden}`: `aip-system` owns the identifiers"
        );
    }
}

#[test]
fn the_adapter_holds_no_key_and_signs_nothing() {
    let code = library_code();
    for forbidden in [
        "private_key",
        "signing_key",
        "keypair",
        "sign_ed25519",
        "Custodian",
        "CollectorSigner",
        "fn sign(",
    ] {
        assert!(
            !code.contains(forbidden),
            "the adapter names {forbidden}: an adapter that signed would be a second trust anchor, \
             and the external collector's key custody is the deployment's, not this crate's"
        );
    }
}

#[test]
fn the_adapter_builds_no_observation_record_and_attests_nothing() {
    let code = library_code();
    for forbidden in [
        "from_attested",
        "AttestedBatch",
        "ObservedExecution",
        ".attest(",
        "verify_attested_batch",
    ] {
        assert!(
            !code.contains(forbidden),
            "the adapter names {forbidden}: a validation tool that could construct observation \
             evidence could decide what was observed about the thing it is validating"
        );
    }
}

#[test]
fn the_adapter_adds_no_proof_tree_and_no_nexora() {
    let code = library_code();
    for forbidden in [
        "LeafKind",
        "CommitmentLog",
        "merkle",
        "NexoraSigner",
        "Nexora",
    ] {
        assert!(
            !code.contains(forbidden),
            "the adapter names {forbidden}: NEXORA's leaf kinds are frozen and a validation proof \
             tree would be a second proof tree"
        );
    }
}

#[test]
fn the_adapter_names_no_external_framework_type() {
    // The production-dependency rule, applied to the adapter itself. This crate
    // is the boundary between external tooling and the evidence model, so it
    // must describe those tools without linking any of them: a `rclcpp` type
    // here would put ROS 2 on the path to the evidence model.
    let code = library_code();
    for forbidden in [
        "rclrs",
        "rclpy",
        "rclcpp",
        "gz::",
        "gazebo::",
        "opencv::",
        "apriltag_t",
        "mavlink::",
        "mavsdk",
        "open62541",
        "UA_Client",
    ] {
        assert!(
            !code.contains(forbidden),
            "the adapter names {forbidden}: external frameworks are described by string and never \
             linked, or the boundary is not a boundary"
        );
    }
}

#[test]
fn independence_is_never_a_settable_field() {
    // The single most dangerous line anyone could add: `obs.independent = true`.
    // `is_independent` is derived from the provenance class, and the library
    // must contain no assignment that could override it.
    let code = library_code();
    assert_eq!(
        code.matches("independent =").count(),
        0,
        "the library assigns to an independence field; independence must be derived from the \
         provenance class and never asserted"
    );
    assert_eq!(
        code.matches("fn is_independent").count(),
        1,
        "expected exactly one definition of the derived independence rule"
    );
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
    let whole: usize = source_files()
        .iter()
        .map(|p| std::fs::read_to_string(p).expect("read").len())
        .sum();
    assert!(
        library_code().len() < whole,
        "library_code did not strip anything"
    );
}
