//! Defect #5 — the verifier's own bounds, RED.
//!
//! Gate 10 gave the verifier the ability to refuse a package reconciled
//! under parameters it will not accept. Defect #5 is that the ability is
//! not reachable in practice: the bounds are `Option`s that default to
//! `None`, and `None` means *accept whatever the package declares*.
//!
//! The property that must hold is one sentence:
//!
//! > A package must not be able to cause the verifier to report a stronger
//! > result than the verifier's own declared capability permits.
//!
//! Two ways it fails today, both demonstrated below against the current
//! API. Both are about the same confusion — a package declaration being
//! read as though it were a statement about the verifier.

mod common;

use aip_nexora::proof::*;
use aip_nexora::verify::*;

fn package(s: &common::Scenario, health_age_ms: u64, agent_key_supplied: bool) -> NexoraProof {
    NexoraProof::builder(s.a.agent_id.clone(), s.reconciliation.clone())
        .issued_at(s.at + 1)
        .authority(s.a.root.clone(), s.a.chain.clone())
        .expectation(s.a.ee.clone())
        .observer(s.evidence.batches.clone(), s.evidence.health.clone())
        .parameters(DeclaredParameters {
            verification_time_ms: s.at,
            health_max_age_ms: health_age_ms,
            window_tolerance_ms: 0,
            agent_key_supplied,
        })
        .build()
}

fn anchors(s: &common::Scenario) -> VerifierAnchors {
    VerifierAnchors {
        decision_point: s.a.dp_anchors.clone(),
        observer: s.o.anchors.clone(),
        warrant: aip_warrant::WarrantTrustAnchors::new(),
        nexora: aip_nexora::NexoraTrustAnchors::new(),
        issuers: s.a.issuer_keys.clone(),
        agent_public_key: Some(s.a.agent_kp.public_key.clone()),
        ..Default::default()
    }
}

const A_CENTURY_MS: u64 = 100 * 365 * 24 * 3_600_000;

/// DEFECT #5a — a verifier that has not stated a bound has no bound.
///
/// INVARIANT: an unstated bound must never mean an unlimited one. A
/// verifier that was never told what staleness it accepts has not thereby
/// agreed to accept a century of it.
///
/// WHAT THIS MODELS: an operator who provisioned trust anchors — out of
/// band, correctly — and never thought about declared parameters, because
/// nothing made them. `import_anchors` produces exactly this verifier, and
/// so does `VerifierAnchors::default()`.
///
/// WHAT IT DOES NOT PROVE: that the package is dishonest. A package
/// reconciled under a century of allowed staleness may be perfectly
/// truthful about having been reconciled that way. The defect is that the
/// verifier adopts the package's terms without ever having agreed to them.
#[test]
fn d5a_a_verifier_that_stated_no_bound_must_not_accept_any_bound() {
    let s = common::verified_execution();
    let p = package(&s, A_CENTURY_MS, true);
    let v = verify_nexora_proof(&p, &anchors(&s));

    assert!(
        !v.is_valid(),
        "a package declaring {A_CENTURY_MS} ms of allowed staleness was accepted \
         by a verifier that never stated a bound: {:?}",
        v.verdict
    );
    assert_eq!(v.result, None, "a refused package establishes nothing");
}

/// DEFECT #5b — the verifier reports the package's claim about the
/// verifier.
///
/// INVARIANT: `Independence::Checked` is a statement about what *this
/// verifier* did. It must rest on this verifier holding the agent's key,
/// not on the package saying the original run held one.
///
/// WHAT THIS MODELS: a package that truthfully records that the original
/// reconciliation ran with the agent key, presented to a verifier that
/// does not have that key. The verifier cannot check I1 or I10, and must
/// not report that it did.
///
/// WHAT IT DOES NOT PROVE: that such a package would be accepted — it is
/// refused on other grounds. The defect is in what the report *says* while
/// refusing, because a reader who looks at `independence` sees a claim the
/// verifier is in no position to make.
#[test]
fn d5b_independence_is_what_this_verifier_did_not_what_the_package_says() {
    let s = common::verified_execution();
    let mut p = package(&s, common::HEALTH_MAX_AGE, true);
    // Force a refusal that happens *before* re-derivation, so the reported
    // independence is whatever the constructor put there.
    p.expectation = None;

    let mut a = anchors(&s);
    a.agent_public_key = None; // this verifier holds no agent key at all

    let v = verify_nexora_proof(&p, &a);
    assert!(!v.is_valid(), "the setup must refuse, for other reasons");
    assert_eq!(
        v.independence,
        Independence::NotChecked,
        "the verifier reported Checked while holding no agent key — that is \
         the package's claim about the original run, not this verifier's \
         account of its own work"
    );
}
