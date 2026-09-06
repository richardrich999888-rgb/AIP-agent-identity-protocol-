//! Skill 19 — the accountability core must be unchanged by this crate.

use std::fs;
use std::path::Path;

const VERDICT_PATH: [&str; 6] = [
    "aip-reconcile",
    "aip-warrant",
    "aip-containment",
    "aip-nexora",
    "aip-airi",
    "aip-observe",
];

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
    for c in VERDICT_PATH {
        let m = fs::read_to_string(Path::new("..").join(c).join("Cargo.toml")).expect("manifest");
        assert!(
            !m.contains("aip-platform"),
            "SECURITY: {c} now depends on aip-platform. The registry is a \
             verifier input, not a participant in any decision; if this \
             dependency is genuinely required it needs its own justification."
        );
    }
}

#[test]
fn this_crate_does_not_reach_the_verdict_path_at_runtime() {
    let m = fs::read_to_string("Cargo.toml").expect("own manifest");
    let (deps, _dev) = m
        .split_once("[dev-dependencies]")
        .expect("manifest has dev-dependencies");
    for forbidden in VERDICT_PATH {
        assert!(
            !deps.contains(forbidden),
            "aip-platform must not depend on {forbidden} at runtime — the \
             reconciler and observer appear under dev-dependencies only, so \
             the T13 tests can drive the real engine"
        );
    }
}

#[test]
fn there_is_no_second_verdict_engine_here() {
    let src = code_only(&["binding.rs", "registry.rs", "method.rs", "error.rs"]);
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
    let m = fs::read_to_string("Cargo.toml").expect("own manifest");
    for forbidden in ["ed25519", "rsa", "p256", "ring"] {
        assert!(
            !m.contains(forbidden),
            "SECURITY: a signing dependency ({forbidden}) appeared in \
             aip-platform. ADR-002 must be ACCEPTED before a hardware trust \
             anchor exists."
        );
    }
    let src = code_only(&["binding.rs", "registry.rs", "method.rs"]);
    for forbidden in ["sign", "SigningKey", "private_key"] {
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
    let src = code_only(&["binding.rs", "registry.rs"]);
    for forbidden in ["SystemTime", "Instant::now", "UNIX_EPOCH"] {
        assert!(
            !src.contains(forbidden),
            "SECURITY: `{forbidden}` appears — this crate must read no clock"
        );
    }
}
