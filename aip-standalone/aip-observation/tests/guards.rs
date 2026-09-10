//! Skill 20 — structural guards.
//!
//! Some properties here are enforced by the type system for external callers
//! but not against a later edit inside the crate. Skill 19 learned that the
//! hard way: adding a public escape-hatch constructor was caught by nothing
//! until a source-scanning guard was added. These are that guard, for this
//! crate's equivalents.

use std::fs;
use std::path::Path;

/// The crates that decide something. `aip-observe` is deliberately absent: it
/// is the observation layer, this crate depends on it at runtime on purpose,
/// and that dependency is what makes an `ObservationRecord` constructible only
/// from verified evidence.
const VERDICT_ENGINES: [&str; 5] = [
    "aip-reconcile",
    "aip-warrant",
    "aip-containment",
    "aip-nexora",
    "aip-airi",
];

/// Source with comment lines stripped, so a scan for a forbidden *use* is not
/// satisfied by a doc comment explaining why the thing is forbidden.
fn code_only(files: &[&str]) -> String {
    files
        .iter()
        .map(|f| fs::read_to_string(Path::new("src").join(f)).expect("source"))
        .flat_map(|c| {
            c.lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Manifest lines that declare something, with comments removed.
fn manifest_declarations(path: &str) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {path}: {e}"))
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

const SRC: [&str; 5] = [
    "class.rs",
    "completeness.rs",
    "error.rs",
    "profile.rs",
    "record.rs",
];

#[test]
fn observation_record_has_no_constructor_bypassing_verification() {
    // The property the whole crate rests on. The private fields stop an
    // external caller inventing a record; nothing stops a later edit adding a
    // public escape hatch, so this asserts none exists.
    let src = code_only(&["record.rs"]);
    for banned in [
        "pub fn new(",
        "pub fn from_parts",
        "pub fn from_bytes",
        "pub fn from_airi",
        "pub fn from_self_report",
        "pub observer_id",
        "pub mechanism",
        "pub completeness",
    ] {
        assert!(
            !src.contains(banned),
            "SECURITY: `{banned}` appears in record.rs. An ObservationRecord \
             must be obtainable only by verifying an attested batch; any other \
             route lets the subject manufacture the evidence used to judge it."
        );
    }
    // Every public constructor-shaped function must be the verifying one.
    for line in src
        .lines()
        .filter(|l| l.trim_start().starts_with("pub fn "))
    {
        let name = line.trim_start().trim_start_matches("pub fn ");
        let is_accessor = [
            "observer_id",
            "key_version",
            "sequence",
            "mechanism",
            "attested_at_ms",
            "completeness",
            "class",
            "ceiling_under",
            "describes",
            "measured_on",
            "check_version",
            "canonical_bytes",
            "digest",
        ]
        .iter()
        .any(|a| name.starts_with(a));
        assert!(
            is_accessor || name.starts_with("from_attested"),
            "SECURITY: unexpected public function on ObservationRecord: {line}"
        );
    }
}

#[test]
fn no_observer_key_material_lives_here() {
    // Observer key custody stays in aip-observe. This crate verifies using the
    // verifier's anchors and never holds, derives or stores a key.
    let src = code_only(&SRC);
    for banned in [
        "SigningKey",
        "private_key",
        "CollectorSigner",
        "sign_ed25519",
    ] {
        assert!(
            !src.contains(banned),
            "SECURITY: `{banned}` appears in aip-observation. Observer key \
             custody must stay in aip-observe."
        );
    }
    let m = manifest_declarations("Cargo.toml");
    for banned in ["ed25519", "rsa", "p256"] {
        assert!(!m.contains(banned), "SECURITY: signing dependency {banned}");
    }
}

#[test]
fn there_is_no_second_verdict_engine_here() {
    let src = code_only(&SRC);
    for banned in [
        "EvidenceStrength",
        "ReconciliationResult",
        "Severity",
        "VerifiedExecution",
        "PhantomClaim",
        "CannotProve",
        "IdentityDivergence",
    ] {
        assert!(
            !src.contains(banned),
            "SECURITY: `{banned}` appears in aip-observation. Verdict \
             vocabulary belongs to the one engine that owns it."
        );
    }
}

#[test]
fn no_verdict_engine_depends_on_this_crate() {
    for c in VERDICT_ENGINES.iter().chain(["aip-observe"].iter()) {
        let m = manifest_declarations(Path::new("..").join(c).join("Cargo.toml").to_str().unwrap());
        assert!(
            !m.contains("aip-observation"),
            "SECURITY: {c} now depends on aip-observation. This crate produces \
             no verdicts and must not be reachable from the engine that does."
        );
    }
}

#[test]
fn this_crate_does_not_depend_on_a_verdict_engine_at_runtime() {
    let m = manifest_declarations("Cargo.toml");
    let (deps, _dev) = m
        .split_once("[dev-dependencies]")
        .expect("manifest has dev-dependencies");
    for banned in VERDICT_ENGINES {
        assert!(
            !deps.contains(banned),
            "aip-observation must not depend on {banned} at runtime"
        );
    }
    assert!(
        deps.contains("aip-observe"),
        "the observation dependency is load-bearing: without it a record could \
         be built from unverified bytes"
    );
}

#[test]
fn no_attestation_material_is_accepted() {
    // ADR-002 remains PROPOSED. No field, parameter or type here carries an
    // attestation, a quote, or a hardware key.
    let src = code_only(&SRC);
    for banned in ["TpmQuote", "Attestation", "quote", "ek_pub", "hardware_key"] {
        assert!(
            !src.contains(banned),
            "SECURITY: `{banned}` appears. An observer relaying an attestation \
             is relaying an attestation; the trust-anchor question is unchanged \
             by which process carries the bytes."
        );
    }
}

#[test]
fn no_primitive_is_duplicated() {
    // Nine Linux mechanisms, the anchor model, the batch, the health model and
    // the boot id all exist. A second definition is a second place to drift.
    let src = code_only(&SRC);
    for banned in [
        "enum SourceMechanism",
        "struct AttestedBatch",
        "struct ObserverTrustAnchors",
        "struct SensorHealth",
        "enum ObserverState",
        "enum ObservationAvailability",
    ] {
        assert!(
            !src.contains(banned),
            "SECURITY: `{banned}` is redefined here rather than reused"
        );
    }
}

#[test]
fn the_mechanism_to_class_mapping_is_total_and_excludes_physical_effect() {
    // Exhaustive over SourceMechanism::ALL, so a mechanism added later cannot
    // silently lack a class — and none maps to PhysicalEffect, which is what
    // keeps "declared" from being read as "implemented".
    use aip_observation::{class_of, ObservationClass};
    use aip_observe::SourceMechanism;

    let mut seen = std::collections::BTreeSet::new();
    for m in SourceMechanism::ALL {
        let c = class_of(m);
        assert_ne!(c, ObservationClass::PhysicalEffect);
        seen.insert(c.code());
    }
    assert_eq!(SourceMechanism::ALL.len(), 9, "mapping must stay total");
    assert!(!seen.is_empty());
}

#[test]
fn class_codes_and_domains_are_distinct_and_namespaced() {
    use aip_observation::*;
    let mut codes: Vec<u8> = ObservationClass::ALL.iter().map(|c| c.code()).collect();
    let n = codes.len();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(n, codes.len(), "class codes must be distinct");

    assert_ne!(OBSERVATION_PROFILE_DOMAIN, OBSERVATION_RECORD_DOMAIN);
    for d in [OBSERVATION_PROFILE_DOMAIN, OBSERVATION_RECORD_DOMAIN] {
        assert!(d.starts_with("SYNTRIASS/AUTONOMY/"));
        for existing in [
            "SYNTRIASS/AUTONOMY/SYSTEM/v1",
            "SYNTRIASS/AUTONOMY/EXECUTION/v1",
            "SYNTRIASS/AUTONOMY/EXECUTION_PROFILE/v1",
            "SYNTRIASS/AUTONOMY/PLATFORM_BINDING/v1",
            "SYNTRIASS/GHOST/RECONCILIATION/v1",
            "SYNTRIASS/AIRI/EVENT/v1",
        ] {
            assert_ne!(d, existing, "domain collides with {existing}");
        }
    }
}
