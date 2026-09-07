//! Phase B — the bundle's signer.
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
//! `SIGNER_ANCHORED` answers the second question, from the caller's anchor
//! set and from nowhere else. The three states a reader now gets:
//!
//! | | meaning |
//! |---|---|
//! | `BUNDLE_SIGNATURE: Pass` | the manifest matches the key the bundle carries |
//! | `SIGNER_ANCHORED: Pass`  | that key is one this verifier was told to trust |
//! | `overall: Pass`          | both, plus every integrity and packet check |
//!
//! An unanchored signer is a **warning**, not a failure. The bundle is
//! unattributed, not forged, and treating every bundle from an unknown
//! party as an attack would make the status useless for the case
//! audit-export bundles exist to serve.

mod common;
use common::*;

use aip_protocol::bundle::{build_zip, verify_zip, BundleStatus};
use aip_protocol::VerificationContext;

/// The fixture's context minus the bundle-signer anchor: a verifier that
/// trusts the issuers and has never been told who may publish a bundle.
fn without_signer_anchor(ctx: &VerificationContext) -> VerificationContext {
    let mut c = ctx.clone();
    c.bundle_signer_public_keys.clear();
    c
}

fn check<'a>(v: &'a aip_protocol::bundle::BundleVerification, name: &str) -> &'a BundleStatus {
    &v.checks
        .iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("no {name} check in {:?}", v.checks))
        .status
}

// ═══ A — valid signature, anchored signer ═══

/// PROVES: the pre-existing successful behaviour is unchanged when the
/// verifier has anchored the signer — which is what `Pass` now means.
#[test]
fn ba_valid_signature_and_anchored_signer_passes() {
    let (packet, report, ctx, seed, public) = fixture();
    let zip = build_zip("acme", &packet, &report, &signer_custodian(&seed, &public)).unwrap();
    let v = verify_zip(&zip, &ctx);

    assert_eq!(*check(&v, "BUNDLE_SIGNATURE"), BundleStatus::Pass);
    assert_eq!(*check(&v, "SIGNER_ANCHORED"), BundleStatus::Pass);
    assert_eq!(v.overall, BundleStatus::Pass, "{:?}", v.checks);
    // The report names *who*, not merely that somebody signed.
    let detail = &v
        .checks
        .iter()
        .find(|c| c.name == "SIGNER_ANCHORED")
        .unwrap()
        .detail;
    assert!(detail.contains("acme"), "{detail}");
}

// ═══ B — valid signature, unanchored signer ═══

/// PROVES: the signature is still valid and the bundle still cannot reach
/// the trusted result. The two facts are reported separately, so a reader
/// can see that the container is intact and the author is unknown.
///
/// DOES NOT PROVE: that the bundle is forged. It is unattributed.
#[test]
fn bb_valid_signature_with_an_unanchored_signer_cannot_reach_pass() {
    let (packet, report, ctx, seed, public) = fixture();
    let zip = build_zip("acme", &packet, &report, &signer_custodian(&seed, &public)).unwrap();
    let v = verify_zip(&zip, &without_signer_anchor(&ctx));

    assert_eq!(
        *check(&v, "BUNDLE_SIGNATURE"),
        BundleStatus::Pass,
        "the signature is valid; that was never the question"
    );
    assert_eq!(*check(&v, "SIGNER_ANCHORED"), BundleStatus::Warning);
    assert_ne!(v.overall, BundleStatus::Pass);
    assert_ne!(
        v.overall,
        BundleStatus::Fail,
        "an unknown publisher is not an attack"
    );
}

// ═══ C — forged signature ═══

/// PROVES: unchanged. A broken signature was a failure before this work
/// and still is; `SIGNER_ANCHORED` does not soften it.
#[test]
fn bc_a_forged_signature_still_fails() {
    let (packet, report, ctx, seed, public) = fixture();
    let zip = build_zip("acme", &packet, &report, &signer_custodian(&seed, &public)).unwrap();
    let mut files = unzip(&zip);
    files.insert(
        aip_protocol::bundle::F_SIG.to_string(),
        hex::encode([0u8; 64]).into_bytes(),
    );
    let v = verify_zip(&rezip(&files), &ctx);

    assert_eq!(*check(&v, "BUNDLE_SIGNATURE"), BundleStatus::Fail);
    assert_eq!(v.overall, BundleStatus::Fail);
}

// ═══ D — the bundle supplies its own anchor ═══

/// PROVES: a key inside the bundle cannot make itself trusted. A forger
/// who re-signs the whole manifest with their own key gets a valid
/// signature and no attribution, because the anchor set is the verifier's.
///
/// MODELS: the actual attack — not tampering with a real bundle, but
/// producing a wholly self-consistent one.
#[test]
fn bd_a_bundle_cannot_supply_its_own_trust_anchor() {
    let (packet, report, ctx, _seed, _public) = fixture();

    // A forger's own keypair, used to build a completely valid bundle.
    let forger = aip_crypto::generate_ed25519_keypair();
    let f_seed: [u8; 32] = forger.private_key.clone().try_into().unwrap();
    let f_public: [u8; 32] = forger.public_key.clone().try_into().unwrap();
    let zip = build_zip(
        "acme",
        &packet,
        &report,
        &signer_custodian(&f_seed, &f_public),
    )
    .unwrap();

    // Against the real verifier's anchors — which anchor the *real* signer.
    let v = verify_zip(&zip, &ctx);
    assert_eq!(
        *check(&v, "BUNDLE_SIGNATURE"),
        BundleStatus::Pass,
        "the forger signed their own manifest correctly"
    );
    assert_eq!(
        *check(&v, "SIGNER_ANCHORED"),
        BundleStatus::Warning,
        "and the verifier does not know them"
    );
    assert_ne!(v.overall, BundleStatus::Pass);
}

// ═══ E — the wrong anchored signer ═══

/// PROVES: anchoring *somebody* is not anchoring *this* signer. The check
/// compares keys, not counts.
#[test]
fn be_a_different_anchored_signer_does_not_vouch_for_this_one() {
    let (packet, report, ctx, seed, public) = fixture();
    let zip = build_zip("acme", &packet, &report, &signer_custodian(&seed, &public)).unwrap();

    let someone_else = aip_crypto::generate_ed25519_keypair();
    let mut c = without_signer_anchor(&ctx);
    c = c.trust_bundle_signer("other-auditor", &someone_else.public_key);

    let v = verify_zip(&zip, &c);
    assert_eq!(*check(&v, "SIGNER_ANCHORED"), BundleStatus::Warning);
    assert_ne!(v.overall, BundleStatus::Pass);
    // The message says how many were anchored, so the operator can tell
    // "I anchored nobody" from "I anchored the wrong party".
    let detail = &v
        .checks
        .iter()
        .find(|c| c.name == "SIGNER_ANCHORED")
        .unwrap()
        .detail;
    assert!(detail.contains("not among the 1"), "{detail}");
}

// ═══ F — several anchors ═══

/// PROVES: the correct anchor is found among several, and the report names
/// which one matched rather than merely that one did.
#[test]
fn bf_the_right_anchor_is_found_among_several() {
    let (packet, report, ctx, seed, public) = fixture();
    let zip = build_zip("acme", &packet, &report, &signer_custodian(&seed, &public)).unwrap();

    let mut c = without_signer_anchor(&ctx);
    for name in ["auditor-a", "auditor-b", "auditor-c"] {
        let k = aip_crypto::generate_ed25519_keypair();
        c = c.trust_bundle_signer(name, &k.public_key);
    }
    c = c.trust_bundle_signer("the-real-one", &public);

    let v = verify_zip(&zip, &c);
    assert_eq!(*check(&v, "SIGNER_ANCHORED"), BundleStatus::Pass);
    assert_eq!(v.overall, BundleStatus::Pass, "{:?}", v.checks);
    let detail = &v
        .checks
        .iter()
        .find(|c| c.name == "SIGNER_ANCHORED")
        .unwrap()
        .detail;
    assert!(detail.contains("the-real-one"), "{detail}");
}

// ═══ G — no anchor set at all ═══

/// PROVES: an empty anchor set is conservative, never permissive. A
/// verifier that anchored nobody attributes nothing, and says so with a
/// message that distinguishes it from having anchored the wrong party.
#[test]
fn bg_an_empty_anchor_set_is_conservative() {
    let (packet, report, _ctx, seed, public) = fixture();
    let zip = build_zip("acme", &packet, &report, &signer_custodian(&seed, &public)).unwrap();
    let v = verify_zip(&zip, &VerificationContext::new());

    assert_eq!(*check(&v, "SIGNER_ANCHORED"), BundleStatus::Warning);
    assert_ne!(v.overall, BundleStatus::Pass);
    let detail = &v
        .checks
        .iter()
        .find(|c| c.name == "SIGNER_ANCHORED")
        .unwrap()
        .detail;
    assert!(detail.contains("anchored no bundle signers"), "{detail}");
    // Integrity is still established — a bundle from an unknown party is
    // still checkable for tampering, which is most of what it is for.
    assert_eq!(*check(&v, "FILE_HASHES"), BundleStatus::Pass);
    assert_eq!(*check(&v, "BUNDLE_HASH"), BundleStatus::Pass);
}

// ═══ H — a bundle built before this check existed ═══

/// PROVES, and documents: nothing about the bundle format changed. A
/// bundle built by any prior version parses, its integrity verifies, and
/// its signature verifies. What changed is what a verifier *reports*: the
/// same bytes now reach `Warning` instead of `Pass` at a verifier that has
/// anchored no signer, because that verifier never could attribute them
/// and now says so.
///
/// There is no historical exemption. A bundle does not become attributable
/// by being old, and giving one a pass for its age would be exactly the
/// self-authorisation this check exists to prevent.
#[test]
fn bh_a_historical_bundle_is_readable_and_is_not_grandfathered() {
    let (packet, report, ctx, seed, public) = fixture();
    // The format is unchanged, so a bundle built now is byte-identical to
    // one built by a prior version from the same inputs; this stands in
    // for a historical artifact.
    let zip = build_zip("acme", &packet, &report, &signer_custodian(&seed, &public)).unwrap();

    let unanchored = verify_zip(&zip, &without_signer_anchor(&ctx));
    assert_eq!(*check(&unanchored, "BUNDLE_STRUCTURE"), BundleStatus::Pass);
    assert_eq!(*check(&unanchored, "FILE_HASHES"), BundleStatus::Pass);
    assert_eq!(*check(&unanchored, "BUNDLE_SIGNATURE"), BundleStatus::Pass);
    assert_eq!(unanchored.overall, BundleStatus::Warning);

    // Anchor the signer out of band — which is what an operator does with
    // a historical bundle whose publisher they can still identify — and it
    // reaches Pass with no change to the bytes.
    let anchored = verify_zip(&zip, &ctx);
    assert_eq!(anchored.overall, BundleStatus::Pass);
    assert_eq!(
        unanchored.bundle_id, anchored.bundle_id,
        "the same bundle throughout"
    );
}

// ═══ Consumers ═══

/// PROVES: the one production consumer is unaffected in the way that
/// matters. `aip-verify` exits on `overall != Fail`, so a Pass→Warning
/// transition does not change any exit code; only the printed result and
/// the new check line change.
#[test]
fn b_consumer_exit_semantics_are_unchanged() {
    let (packet, report, ctx, seed, public) = fixture();
    let zip = build_zip("acme", &packet, &report, &signer_custodian(&seed, &public)).unwrap();

    for c in [ctx.clone(), without_signer_anchor(&ctx)] {
        let v = verify_zip(&zip, &c);
        assert_ne!(
            v.overall,
            BundleStatus::Fail,
            "an intact bundle must never become a failure merely because \
             its signer is unanchored; aip-verify would start exiting non-zero"
        );
    }
}
