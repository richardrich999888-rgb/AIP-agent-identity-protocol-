//! Skill 19 — the accountability core must be unchanged by this crate.

use std::fs;
use std::path::Path;

/// The crates that decide something. `aip-observe` is deliberately **not**
/// here: it is the observation layer, not a verdict engine, and this crate now
/// depends on it at runtime on purpose — that dependency is what makes an
/// `ObservedBoot` constructible only from verified evidence. `aip-reconcile`
/// itself depends on `aip-observe`, so this is not a new kind of edge.
const VERDICT_ENGINES: [&str; 5] = [
    "aip-reconcile",
    "aip-warrant",
    "aip-containment",
    "aip-nexora",
    "aip-airi",
];

/// Manifest lines that actually declare something, with comments removed.
///
/// Scanning a raw manifest is a trap this test fell into: the word
/// "load-bearing" in a comment contains "ring", and a comment mentioning
/// `aip-reconcile` read as a dependency on it. Both fired falsely. Rewording
/// the comments to dodge a substring scan would have been exactly backwards —
/// the scan is what needed to be precise.
fn manifest_declarations(path: &str) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {path}: {e}"))
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Source with comment lines removed, so a scan for a forbidden *use* is not
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

#[test]
fn no_crate_in_the_verdict_path_depends_on_this_one() {
    for c in VERDICT_ENGINES.iter().chain(["aip-observe"].iter()) {
        let m = manifest_declarations(Path::new("..").join(c).join("Cargo.toml").to_str().unwrap());
        assert!(
            !m.contains("aip-platform"),
            "SECURITY: {c} now depends on aip-platform. The registry is a \
             verifier input, not a participant in any decision; if this \
             dependency is genuinely required it needs its own justification."
        );
    }
}

#[test]
fn this_crate_does_not_depend_on_a_verdict_engine_at_runtime() {
    let m = manifest_declarations("Cargo.toml");
    let (deps, _dev) = m
        .split_once("[dev-dependencies]")
        .expect("manifest has dev-dependencies");
    for forbidden in VERDICT_ENGINES {
        assert!(
            !deps.contains(forbidden),
            "aip-platform must not depend on {forbidden} at runtime — the \
             reconciler appears under dev-dependencies only, so the T13 tests \
             can drive the real engine without this crate joining it"
        );
    }
    // `aip-observe` is a runtime dependency, deliberately: it is what makes an
    // ObservedBoot constructible only from verified evidence.
    assert!(
        deps.contains("aip-observe"),
        "the observation dependency is load-bearing; without it the boot id \
         would be bare bytes a caller could self-report"
    );
}

#[test]
fn there_is_no_second_verdict_engine_here() {
    let src = code_only(&[
        "binding.rs",
        "registry.rs",
        "method.rs",
        "error.rs",
        "observed.rs",
    ]);
    for forbidden in [
        "EvidenceStrength",
        "ReconciliationResult",
        "Severity",
        "VerifiedExecution",
        "PhantomClaim",
        "CannotProve",
        "IdentityDivergence",
    ] {
        assert!(
            !src.contains(forbidden),
            "SECURITY: `{forbidden}` appears in aip-platform. Verdict \
             vocabulary belongs to the one engine that owns it."
        );
    }
}

#[test]
fn no_signing_capability_was_introduced() {
    // The ADR-002 stop, asserted structurally. A hardware signing key is a new
    // trust anchor; this crate must have no means to make one.
    let m = manifest_declarations("Cargo.toml");
    for forbidden in ["ed25519", "rsa", "p256", "ring"] {
        assert!(
            !m.contains(forbidden),
            "SECURITY: a signing dependency ({forbidden}) appeared in \
             aip-platform. ADR-002 must be ACCEPTED before a hardware trust \
             anchor exists."
        );
    }
    let src = code_only(&["binding.rs", "registry.rs", "method.rs", "observed.rs"]);
    for forbidden in ["SigningKey", "private_key"] {
        assert!(
            !src.contains(forbidden),
            "SECURITY: `{forbidden}` appears in aip-platform — this crate \
             signs nothing"
        );
    }
}

#[test]
fn no_primitive_is_duplicated() {
    let src = code_only(&["binding.rs", "registry.rs", "method.rs"]);
    for forbidden in [
        "struct ExecutionBinding",
        "struct ProcessInstance",
        "struct PlatformId",
        "struct HardwareId",
        "struct ObserverTrustAnchors",
    ] {
        assert!(
            !src.contains(forbidden),
            "SECURITY: `{forbidden}` is redefined here rather than reused from \
             the crate that owns it"
        );
    }
}

#[test]
fn the_domain_tag_does_not_collide() {
    let ours = aip_platform::PLATFORM_BINDING_DOMAIN;
    assert!(ours.starts_with("SYNTRIASS/AUTONOMY/"));
    for existing in [
        "SYNTRIASS/AUTONOMY/SYSTEM/v1",
        "SYNTRIASS/AUTONOMY/EXECUTION/v1",
        "SYNTRIASS/AUTONOMY/EXECUTION_PROFILE/v1",
        "SYNTRIASS/GHOST/RECONCILIATION/v1",
        "SYNTRIASS/AIRI/EVENT/v1",
    ] {
        assert_ne!(ours, existing, "domain tag collides with {existing}");
    }
}

#[test]
fn the_registry_reads_no_clock() {
    // Every resolution takes the instant explicitly, for the same reason the
    // reconciler does: a historical verification must be able to say what
    // "then" means, and an offline verifier has no authoritative clock.
    let src = code_only(&["binding.rs", "registry.rs", "observed.rs"]);
    for forbidden in ["SystemTime", "Instant::now", "UNIX_EPOCH"] {
        assert!(
            !src.contains(forbidden),
            "SECURITY: `{forbidden}` appears — this crate must read no clock"
        );
    }
}

#[test]
fn observed_boot_has_no_constructor_that_bypasses_verification() {
    // The type system stops an *external* caller inventing an ObservedBoot,
    // because the field is private. It does not stop someone inside this crate
    // adding a public escape hatch later — and a mutation test confirmed that
    // adding `pub fn from_bytes` is caught by nothing.
    //
    // This guard closes that. Every public constructor must take an
    // AttestedBatch and anchors; any that takes bare bytes is a way to launder
    // a self-reported boot id into a trusted one, which is the exact defect
    // this type exists to prevent.
    let src = code_only(&["observed.rs"]);

    for banned in [
        "pub fn from_bytes",
        "pub fn new(",
        "impl From<[u8; 16]>",
        "pub boot_id",
    ] {
        assert!(
            !src.contains(banned),
            "SECURITY: `{banned}` appears in observed.rs. An ObservedBoot must \
             be obtainable only by verifying an attested batch; any other \
             route launders a self-reported boot id into a trusted one."
        );
    }

    // And every public function that does exist takes both a batch and anchors.
    for line in src
        .lines()
        .filter(|l| l.trim_start().starts_with("pub fn "))
    {
        let name = line.trim_start().trim_start_matches("pub fn ");
        if name.starts_with("boot_id") {
            continue; // the accessor
        }
        assert!(
            name.starts_with("from_attested"),
            "SECURITY: unexpected public constructor on ObservedBoot: {line}"
        );
    }
}
