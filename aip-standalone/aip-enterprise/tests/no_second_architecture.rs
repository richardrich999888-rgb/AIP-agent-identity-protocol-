//! The profile adds no architecture, checked against its own source.
//!
//! Skill 27 forbids a second reconciler, a second verifier, a second evidence
//! hierarchy, a second identity framework, a second custody model and a second
//! proof tree. The strongest available check is not "we did not build those"
//! but "this crate cannot name the types you would need in order to".
//!
//! These tests read `aip-enterprise`'s source with comments stripped, because the
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
            "aip-enterprise names {forbidden} in code: a vertical profile that could produce a \
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
            "aip-enterprise defines `{forbidden}`: reconciliation and verification belong to the core"
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
            "aip-enterprise defines `{forbidden}`: the profile consumes the core and must not fork it"
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
        "struct TenantId",
        "struct WorkloadId",
        "struct ContainerId",
        "struct ClusterId",
        "struct AccountId",
    ] {
        assert!(
            !code.contains(forbidden),
            "aip-enterprise defines `{forbidden}`: `aip-system` owns the identifiers; a tenant is a validated \
             string inside a commitment, not a parallel identity system"
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
            "aip-enterprise names {forbidden}: observer key custody stays in aip-observe, and a \
             profile that signed would be a second trust anchor"
        );
    }
}

#[test]
fn the_profile_builds_no_observation_record_and_attests_nothing() {
    let code = library_code();
    // Call-and-type syntax, not the bare word: this crate's prose describes
    // attestation at length in `EnterpriseSource::does_not_establish`, which
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
            "aip-enterprise names {forbidden}: a profile that could construct observation evidence \
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
            "aip-enterprise names {forbidden}: NEXORA's leaf kinds are frozen and an enterprise proof tree \
             would be a second proof tree"
        );
    }
}

#[test]
fn the_profile_defines_no_enterprise_only_trust_score() {
    // Skill 27's sharpest prohibition. A "trust score" is how an enterprise
    // product ends up with a second verdict system that nobody calls a verdict
    // system. The crate must have no vocabulary for one.
    let code = library_code();
    for forbidden in [
        "TrustScore",
        "trust_score",
        "RiskScore",
        "risk_score",
        "confidence_score",
        "fn score(",
        "Reputation",
        "TrustLevel",
        "TrustTier",
    ] {
        assert!(
            !code.contains(forbidden),
            "aip-enterprise names {forbidden}: an enterprise-only score is a second verdict \
             system wearing a dashboard"
        );
    }
}

#[test]
fn no_framework_name_is_ever_branched_on_to_grant_anything() {
    // `aip-airi::FrameworkIdentity` says it is not a trust input. This keeps
    // that true one layer up: the adapters map their own event names, and
    // nothing compares a framework name to decide what evidence is worth.
    let code = library_code();
    for forbidden in [
        "framework_grants",
        "if name ==",
        "match name",
        "name.contains",
        "is_trusted_framework",
        "TRUSTED_FRAMEWORKS",
        "allowlist",
    ] {
        // `framework_grants_authority` is the *refusal*, so it is exempted by
        // being matched exactly rather than by prefix.
        if forbidden == "framework_grants" {
            assert_eq!(
                code.matches("fn framework_grants_authority").count(),
                1,
                "expected exactly the one refusal method"
            );
            continue;
        }
        assert!(
            !code.contains(forbidden),
            "aip-enterprise names {forbidden}: a framework name must grant nothing"
        );
    }
}

#[test]
fn the_execution_identity_is_the_only_route_into_a_binding() {
    // There must be no constructor that takes a tenant, a workload and a
    // digest — only one that takes the `ExecutionBinding` itself. Otherwise a
    // caller holding copied strings and a copied digest could build a binding.
    let code = library_code();
    assert_eq!(
        code.matches("pub fn new(\n        tenant: &str,").count(),
        1,
        "expected exactly one WorkloadBinding constructor"
    );
    assert_eq!(
        code.matches("execution_identity_digest: sha256(&execution.identity_bytes())")
            .count(),
        1,
        "the digest must be computed from the binding, never accepted from a caller"
    );
    for forbidden in [
        "pub fn from_digest",
        "pub fn unchecked",
        "pub fn trust_context",
        "pub fn with_execution_digest",
    ] {
        assert!(
            !code.contains(forbidden),
            "aip-enterprise defines `{forbidden}`: a binding built from strings alone is the \
             attack this profile exists to refuse"
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
