//! Phase B — the bundle's signer, RED.
//!
//! `BUNDLE_SIGNATURE` verifies the manifest against
//! `manifest.signer_public_key` — a key carried *inside the bundle*. That
//! establishes that the manifest matches the key shipped beside it, which
//! is internal consistency and nothing else. A forger ships their own key.
//!
//! ```text
//! VALID SIGNATURE   ≠   TRUSTED SIGNER
//! ```
//!
//! The distinction is missing, and a reader who stops at
//! `BUNDLE_SIGNATURE: Pass` learns less than the word "signature"
//! suggests: the bundle answers "this manifest matches this key" and never
//! "this manifest came from anyone in particular".

mod common;
use common::*;

use aip_protocol::bundle::{build_zip, verify_zip, BundleStatus};
use aip_protocol::VerificationContext;

/// PHASE B DEFECT — a bundle signed by a key nobody anchored still reaches
/// the fully-trusted result.
///
/// INVARIANT: the caller's anchor set decides who is trusted. A key the
/// bundle carries must not become its own trust anchor, so a bundle whose
/// signer the verifier has never heard of cannot reach `Pass`.
///
/// MODELS: a bundle handed to an auditor by someone other than the party
/// that produced it — which is the entire point of an audit-export bundle
/// and therefore the case that matters most.
///
/// DOES NOT PROVE: that the bundle is forged. An unanchored signer is
/// *unattributed*, not invalid, which is why the expected outcome below is
/// a warning rather than a failure.
#[test]
fn b1_an_unanchored_signer_must_not_reach_the_trusted_result() {
    let (packet, report, ctx, seed, public) = fixture();
    let zip = build_zip("acme", &packet, &report, &seed, &public).unwrap();

    // `ctx` anchors the issuers, so the packet inside verifies. It says
    // nothing about who signed the bundle, and the verifier has never been
    // told to trust `public`.
    let v = verify_zip(&zip, &ctx);

    assert_ne!(
        v.overall,
        BundleStatus::Pass,
        "a bundle signed by an unanchored key reached the fully-trusted \
         result; checks: {:?}",
        v.checks
    );
}

/// PHASE B DEFECT — there is no check that reports the distinction at all.
///
/// INVARIANT: a verifier must be able to say which of the three it
/// established — that the signature is cryptographically valid, that the
/// signer is one it anchors, and therefore whether the bundle is
/// trustworthy under its own anchor set. Today it reports only the first
/// and the reader is left to assume the rest.
#[test]
fn b2_the_report_must_name_the_signer_anchoring_result() {
    let (packet, report, _ctx, seed, public) = fixture();
    let zip = build_zip("acme", &packet, &report, &seed, &public).unwrap();
    let v = verify_zip(&zip, &VerificationContext::new());

    assert!(
        v.checks.iter().any(|c| c.name == "SIGNER_ANCHORED"),
        "no check reports whether the signer is anchored; the report has \
         only {:?}",
        v.checks.iter().map(|c| &c.name).collect::<Vec<_>>()
    );
}
