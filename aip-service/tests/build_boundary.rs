//! B-10 — the service is inside the primary build/test boundary.
//!
//! # What went wrong, and what this file is for
//!
//! `aip-standalone` and `aip-service` used to be independent Cargo roots.
//! `cargo test --workspace`, run in `aip-standalone`, did not compile the
//! service. So when `aip-protocol` gained rule R16 and a
//! `verification_time_ms` field on `VerificationContext`, nothing failed
//! when the service did not adopt them — the service simply was not built by
//! the command anybody ran. That is finding **B-1a**, and **B-10** is its
//! cause.
//!
//! These tests are compile-time and link-time assertions. Their value is not
//! the assertions themselves; it is that this file is *compiled at all* by
//! the primary command. If the service ever leaves the workspace again, this
//! file stops being built and the coverage it represents disappears silently
//! — which is why the workspace membership is also asserted from the
//! manifest below, where a human will see it.

use aip_protocol::{verify_packet, VerificationContext};

/// The service links the protocol crate and can construct its context.
///
/// A protocol change that removes or renames anything used here is a compile
/// error in `cargo test --workspace`, which is the whole point of B-10.
#[test]
fn the_service_compiles_against_the_protocol_crate() {
    let ctx = VerificationContext::new();
    // The fields B-1a is about must exist and be reachable from this tier.
    assert!(ctx.verification_time_ms.is_none());
    assert_eq!(ctx.future_tolerance_ms, 0);
    // And the entry point the handlers depend on must still be callable.
    let _: fn(&aip_protocol::EvidencePacket, &VerificationContext) -> _ = verify_packet;
}

/// The temporal API the service must use is present and behaves as a builder.
///
/// If `at_time` or `with_future_tolerance` were removed, the service's
/// adoption of the bound would break here rather than silently regressing to
/// unbounded verification.
#[test]
fn the_temporal_bound_api_is_reachable_from_the_service() {
    let ctx = VerificationContext::new()
        .at_time(1_700_000_000_000)
        .with_future_tolerance(5_000);
    assert_eq!(ctx.verification_time_ms, Some(1_700_000_000_000));
    assert_eq!(ctx.future_tolerance_ms, 5_000);
}

/// The manifest says the service is a workspace member.
///
/// Read from the repository root's `Cargo.toml` rather than inferred, so the
/// assertion fails loudly if someone splits the roots again. A test that only
/// checked behaviour would vanish along with the compilation it depends on.
#[test]
fn the_service_is_declared_a_member_of_the_root_workspace() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("aip-service sits below the repository root")
        .join("Cargo.toml");
    let manifest = std::fs::read_to_string(&root)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", root.display()));
    assert!(
        manifest.contains("\"aip-service\""),
        "SECURITY/PROCESS (B-10): aip-service is no longer a member of the root \
         workspace. The primary test command will stop compiling the service, and \
         the next protocol change will not be checked against its callers — which \
         is exactly how B-1a happened."
    );
}
