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

use aip_nexora::capability::{ReconciliationAge, VerifierCapability};
use aip_nexora::export::*;
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
        capability: VerifierCapability::strict(),
        present_time_ms: None,
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

// ═══════════════════════════════════════════════════════════════════
// Gate 10 closure — A through H
// ═══════════════════════════════════════════════════════════════════

/// A — a package declaring parameters inside the verifier's bounds is
/// accepted, subject to everything else the verifier checks.
///
/// PROVES: bounding declared parameters does not break honest packages.
/// DOES NOT PROVE: that the package is true — only that the bound is not
/// what stopped it.
#[test]
fn ga_within_bounds_is_accepted_subject_to_the_rest() {
    let s = common::verified_execution();
    let p = package(&s, common::HEALTH_MAX_AGE, true);
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert!(v.is_valid(), "{:?}", v.verdict);
    assert_eq!(
        v.evaluated_under.health_age_bound(),
        VerifierCapability::strict().health_age_bound()
    );
}

/// B — outside the bounds, the package cannot receive the stronger result.
///
/// PROVES: the refusal names the parameter, its declared value and the
/// most this verifier accepts, and no result or strength survives it.
/// MODELS: an assembler widening a declared parameter to make a stale
/// health record acceptable.
#[test]
fn gb_outside_bounds_cannot_receive_the_stronger_result() {
    let s = common::verified_execution();
    let p = package(&s, A_CENTURY_MS, true);
    let v = verify_nexora_proof(&p, &anchors(&s));
    match &v.verdict {
        ProofVerdict::Invalid(InvalidReason::DeclaredParameterRefused {
            parameter,
            declared,
            max_accepted,
        }) => {
            assert_eq!(parameter, "health_max_age_ms");
            assert_eq!(*declared, A_CENTURY_MS);
            assert_eq!(
                *max_accepted,
                VerifierCapability::strict().health_age_bound()
            );
        }
        other => panic!("expected a named parameter refusal, got {other:?}"),
    }
    assert_eq!(v.result, None);
    assert_eq!(v.strength, None);
}

/// C — a package claiming the verifier supports something it does not.
///
/// The only such claim a package can make is `agent_key_supplied`: an
/// assertion that the original run held the agent's key, which the
/// verifier can only honour by holding that key itself.
///
/// PROVES: the claim is downgraded, not honoured — `independence` reports
/// what this verifier could do, and the package is refused as not derivable
/// because the verifier cannot reproduce a run it lacks an input for.
#[test]
fn gc_a_claim_about_verifier_support_is_downgraded_not_honoured() {
    let s = common::verified_execution();
    let p = package(&s, common::HEALTH_MAX_AGE, true);
    let mut a = anchors(&s);
    a.agent_public_key = None;

    let v = verify_nexora_proof(&p, &a);
    assert_eq!(
        v.independence,
        Independence::NotChecked,
        "the verifier must report its own reach, not the package's claim"
    );
    assert!(
        !v.is_valid(),
        "and must not claim to have reproduced the run"
    );
    assert_eq!(v.result, None);
}

/// D — a package that omits the parameter block, or a field of it, is not
/// read optimistically.
///
/// PROVES: absence is a parse failure, never a default. A missing
/// `health_max_age_ms` does not become `0` (which would sail under any
/// bound) and does not become "unbounded".
#[test]
fn gd_omitted_parameters_are_not_read_optimistically() {
    let s = common::verified_execution();
    let bytes = export_proof(&package(&s, common::HEALTH_MAX_AGE, true)).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    // The whole block removed.
    let mut without = value.clone();
    without.as_object_mut().unwrap().remove("parameters");
    assert!(
        import_proof(&serde_json::to_vec(&without).unwrap()).is_err(),
        "a package with no declared parameters must not import"
    );

    // One field removed.
    value["parameters"]
        .as_object_mut()
        .unwrap()
        .remove("health_max_age_ms");
    assert!(
        import_proof(&serde_json::to_vec(&value).unwrap()).is_err(),
        "a missing declared parameter must not default to anything"
    );
}

/// E — malformed or unknown bound metadata inside a package is refused.
///
/// PROVES: `DeclaredParameters` denies unknown fields, so an assembler
/// cannot smuggle a parameter this build does not implement and have it
/// silently ignored while the result reads as though everything declared
/// had been evaluated.
#[test]
fn ge_malformed_or_unknown_parameter_metadata_is_refused() {
    let s = common::verified_execution();
    let bytes = export_proof(&package(&s, common::HEALTH_MAX_AGE, true)).unwrap();

    // A parameter this build does not implement.
    let mut extra: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    extra["parameters"]["max_health_age_ms"] = serde_json::json!(A_CENTURY_MS);
    assert!(
        import_proof(&serde_json::to_vec(&extra).unwrap()).is_err(),
        "an unknown declared parameter must be refused, not ignored"
    );

    // A declared parameter of the wrong shape.
    let mut wrong: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    wrong["parameters"]["health_max_age_ms"] = serde_json::json!("as long as you like");
    assert!(import_proof(&serde_json::to_vec(&wrong).unwrap()).is_err());
}

/// F — when the verifier is narrower than the package, the verifier wins.
#[test]
fn gf_the_narrower_verifier_bound_wins() {
    let s = common::verified_execution();
    let p = package(&s, common::HEALTH_MAX_AGE, true);
    assert!(verify_nexora_proof(&p, &anchors(&s)).is_valid());

    let mut narrow = anchors(&s);
    narrow.capability = VerifierCapability::strict().max_health_age_ms(common::HEALTH_MAX_AGE - 1);
    let v = verify_nexora_proof(&p, &narrow);
    assert!(!v.is_valid(), "the narrower bound must decide");
    assert_eq!(v.result, None);
}

/// G — a package cannot widen the verifier's capability.
///
/// PROVES: there is no field in a package, or in an anchor file, that
/// contributes to a `VerifierCapability`. Both are checked as text, so the
/// property does not depend on knowing which struct field to look at.
#[test]
fn gg_a_package_cannot_widen_the_verifiers_capability() {
    let s = common::verified_execution();
    let p = package(&s, A_CENTURY_MS, true);
    let proof_text = String::from_utf8(export_proof(&p).unwrap()).unwrap();
    let anchor_text = String::from_utf8(export_anchors(&anchors(&s)).unwrap()).unwrap();

    for word in [
        "capability",
        "understood_versions",
        "max_health_age_ms",
        "max_window_tolerance_ms",
        "max_reconciliation_age",
    ] {
        assert!(
            !proof_text.contains(word),
            "{word} is stateable in a package"
        );
        assert!(
            !anchor_text.contains(word),
            "{word} is stateable in an anchor file"
        );
    }

    // And injecting one anyway changes nothing about what the verifier
    // accepts: the package is still refused by the verifier's own bound.
    let mut forged: serde_json::Value = serde_json::from_slice(&export_proof(&p).unwrap()).unwrap();
    forged["capability"] = serde_json::json!({"max_health_age_ms": A_CENTURY_MS});
    // The injected field is not part of the proof, so it does not survive
    // import — and if it ever did, the bound it names is not consulted.
    if let Ok(back) = import_proof(&serde_json::to_vec(&forged).unwrap()) {
        let v = verify_nexora_proof(&back, &anchors(&s));
        assert!(!v.is_valid(), "an injected capability widened the verifier");
    }
}

/// H — a version the verifier does not understand is not a success.
///
/// PROVES: the version check is against what *this verifier* says it
/// reads, not against a constant a future build might quietly change. A
/// verifier can be configured to understand fewer versions than it
/// implements, and then it refuses the ones it excluded.
#[test]
fn gh_a_version_the_verifier_does_not_understand_is_never_a_success() {
    let s = common::verified_execution();
    let p = package(&s, common::HEALTH_MAX_AGE, true);

    // A package from a version this verifier does not read.
    let mut future = p.clone();
    future.version = NEXORA_PROOF_VERSION + 1;
    let v = verify_nexora_proof(&future, &anchors(&s));
    assert_eq!(
        v.verdict,
        ProofVerdict::Invalid(InvalidReason::UnsupportedVersion(future.version))
    );
    assert_eq!(v.result, None);

    // A verifier cannot escape that by declaring the version understood.
    // There is one parser and one set of rules in this build, so a package
    // labelled v2 would be read under v1's rules while the report claimed
    // v2 was understood — a declaration is not an implementation, and the
    // capability refuses to pretend otherwise.
    let over_claim = std::panic::catch_unwind(|| {
        VerifierCapability::strict().understanding([NEXORA_PROOF_VERSION + 1])
    });
    assert!(
        over_claim.is_err(),
        "a verifier declared a proof version this build does not implement"
    );

    // Narrowing to the implemented set is fine, and is the only direction
    // that is.
    assert_eq!(
        VerifierCapability::IMPLEMENTED_VERSIONS,
        &[NEXORA_PROOF_VERSION]
    );
    let mut only_current = anchors(&s);
    only_current.capability = VerifierCapability::strict().understanding([NEXORA_PROOF_VERSION]);
    assert!(verify_nexora_proof(&p, &only_current).is_valid());
}

// ═══════════════════════════════════════════════════════════════════
// Adversarial — the ten, against one invariant
//
//     A PACKAGE CANNOT INCREASE VERIFIER POWER.
//
// Several of these end up asserting the same thing from different
// directions, which is the point: the property should be hard to get round
// rather than defended in exactly one place.
// ═══════════════════════════════════════════════════════════════════

/// 1 & 2 — a forged or widened capability, injected wherever it might fit.
///
/// PROVES: neither a package nor an anchor file has anywhere to put one,
/// and injecting the field into the JSON of either changes no verdict.
#[test]
fn adv01_02_forged_and_widened_capability_have_nowhere_to_live() {
    let s = common::verified_execution();
    let honest = package(&s, common::HEALTH_MAX_AGE, true);
    let baseline = verify_nexora_proof(&honest, &anchors(&s));
    assert!(baseline.is_valid());

    for field in ["capability", "verifier_capability", "evaluated_under"] {
        let mut forged: serde_json::Value =
            serde_json::from_slice(&export_proof(&honest).unwrap()).unwrap();
        forged[field] = serde_json::json!({
            "understood_versions": [NEXORA_PROOF_VERSION, 99],
            "max_health_age_ms": A_CENTURY_MS,
            "max_window_tolerance_ms": A_CENTURY_MS,
            "max_reconciliation_age": "Unbounded",
        });
        let bytes = serde_json::to_vec(&forged).unwrap();
        if let Ok(back) = import_proof(&bytes) {
            let v = verify_nexora_proof(&back, &anchors(&s));
            assert_eq!(
                v.evaluated_under,
                VerifierCapability::strict(),
                "{field}: an injected capability reached the verifier"
            );
        }
    }

    // The same against the anchor file, which is the other thing that
    // travels beside a proof.
    let mut forged: serde_json::Value =
        serde_json::from_slice(&export_anchors(&anchors(&s)).unwrap()).unwrap();
    forged["capability"] = serde_json::json!({"max_health_age_ms": A_CENTURY_MS});
    let imported = import_anchors(
        &serde_json::to_vec(&forged).unwrap(),
        VerifierCapability::strict(),
    );
    if let Ok(a) = imported {
        assert_eq!(a.capability, VerifierCapability::strict());
    }
}

/// 3 & 9 — an unsupported or unknown parameter.
///
/// PROVES: refused at import, never ignored. A verifier that ignored an
/// unknown declared parameter would be verifying under terms it never
/// evaluated while reporting as though it had.
#[test]
fn adv03_09_unknown_parameters_are_refused_not_ignored() {
    let s = common::verified_execution();
    let bytes = export_proof(&package(&s, common::HEALTH_MAX_AGE, true)).unwrap();
    for (k, val) in [
        ("allow_stale_health", serde_json::json!(true)),
        ("trust_me", serde_json::json!("yes")),
        ("max_health_age_ms", serde_json::json!(A_CENTURY_MS)),
    ] {
        let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        v["parameters"][k] = val;
        assert!(
            import_proof(&serde_json::to_vec(&v).unwrap()).is_err(),
            "unknown declared parameter {k} was accepted"
        );
    }
}

/// 4 — a missing bound.
///
/// PROVES: there is no such thing. Every bound is a concrete value, the
/// type has no `Default`, and neither does `VerifierAnchors`, so a verifier
/// that never stated its terms cannot be built. The structural check is on
/// the source, so it does not depend on remembering which field to look at.
#[test]
fn adv04_a_missing_bound_is_not_constructible() {
    // Concrete values, not options.
    let c = VerifierCapability::strict();
    let _: u64 = c.health_age_bound();
    let _: u64 = c.window_tolerance_bound();

    // The structural half looks at code and not at prose: this file and the
    // modules it checks both discuss `Deserialize` and `Option<u64>` in
    // their doc comments, and a check that matched those would pass for the
    // wrong reason and fail for the wrong reason too.
    let verify_src = code_of("src/verify.rs");
    assert!(
        !verify_src.contains("Default)]\npub struct VerifierAnchors"),
        "VerifierAnchors regained a Default, and with it a verifier that \
         states no bounds"
    );
    let cap_src = code_of("src/capability.rs");
    assert!(
        !cap_src.contains("impl Default for VerifierCapability"),
        "VerifierCapability gained a Default; every bound must be written down"
    );
    assert!(
        !cap_src.contains("Option<u64>"),
        "a bound became optional again, and an unstated bound is an \
         unlimited one"
    );
}

/// A source file with its comments removed, so a structural assertion is
/// about the code rather than about how the code is described.
fn code_of(path: &str) -> String {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// 5 — malformed bound metadata.
///
/// PROVES: a `VerifierCapability` cannot be deserialized at all, so there
/// is no byte sequence — well-formed or not — that becomes one. Checked
/// structurally, because the property is the *absence* of an impl and an
/// absence cannot be called.
#[test]
fn adv05_a_capability_cannot_be_built_from_bytes() {
    let src = code_of("src/capability.rs");
    assert!(
        src.contains("use serde::Serialize;"),
        "capability.rs must import Serialize alone"
    );
    assert!(
        !src.contains("Deserialize"),
        "VerifierCapability became deserializable; a capability that can be \
         read out of bytes is one an attacker can write"
    );
    // The output type that carries it is likewise write-only.
    let verify_src = code_of("src/verify.rs");
    let idx = verify_src.find("pub struct VerifiedProof").unwrap();
    let header = &verify_src[idx.saturating_sub(120)..idx];
    assert!(
        !header.contains("Deserialize"),
        "VerifiedProof became deserializable, which would make its \
         evaluated_under forgeable"
    );
}

/// 6 & 7 — a stale verifier version, and a package/verifier mismatch.
///
/// PROVES: an unimplemented version cannot be declared understood, and a
/// package naming one is refused rather than read under this build's rules.
#[test]
fn adv06_07_version_mismatch_is_never_a_false_success() {
    let s = common::verified_execution();
    let mut future = package(&s, common::HEALTH_MAX_AGE, true);
    future.version = NEXORA_PROOF_VERSION + 5;
    let v = verify_nexora_proof(&future, &anchors(&s));
    assert_eq!(
        v.verdict,
        ProofVerdict::Invalid(InvalidReason::UnsupportedVersion(future.version))
    );
    assert_eq!(v.result, None);
    assert!(std::panic::catch_unwind(|| {
        VerifierCapability::strict().understanding([NEXORA_PROOF_VERSION + 5])
    })
    .is_err());
}

/// 8 — the verifier configured narrowly while the package claims broadly.
///
/// PROVES: across every bound the capability carries, narrowing the
/// verifier refuses the package. Swept rather than spot-checked so that a
/// bound added later without a check is visible as an untested row.
#[test]
fn adv08_a_narrow_verifier_refuses_every_broad_declaration() {
    let s = common::verified_execution();

    // health age
    let p = package(&s, common::HEALTH_MAX_AGE, true);
    let mut a = anchors(&s);
    a.capability = VerifierCapability::strict().max_health_age_ms(0);
    assert!(!verify_nexora_proof(&p, &a).is_valid(), "health age");

    // window tolerance
    let mut wide = package(&s, common::HEALTH_MAX_AGE, true);
    wide.parameters.window_tolerance_ms = 5_000;
    assert!(
        !verify_nexora_proof(&wide, &anchors(&s)).is_valid(),
        "window tolerance"
    );

    // reconciliation age, with a clock
    let mut aged = anchors(&s);
    aged.capability =
        VerifierCapability::strict().max_reconciliation_age(ReconciliationAge::AtMost(1_000));
    aged.present_time_ms = Some(s.at + 10_000_000);
    let v = verify_nexora_proof(&p, &aged);
    assert!(!v.is_valid(), "reconciliation age");
    match refused_reason(&v) {
        InvalidReason::DeclaredParameterRefused { parameter, .. } => {
            assert_eq!(parameter, "verification_time_ms")
        }
        other => panic!("expected an age refusal, got {other:?}"),
    }

    // and a verifier that bounds the age but holds no clock cannot compute
    // it, so it refuses rather than skipping the check it promised
    let mut blind = anchors(&s);
    blind.capability = VerifierCapability::strict()
        .max_reconciliation_age(ReconciliationAge::AtMost(u64::MAX - 1));
    blind.present_time_ms = None;
    assert!(
        !verify_nexora_proof(&p, &blind).is_valid(),
        "a bounded verifier with no clock must refuse, not wave through"
    );
}

/// 10 — a declaration that one verifier accepted, replayed at a narrower
/// one.
///
/// PROVES: acceptance is not a property of the package. The same bytes,
/// unchanged and with the same `proof_id`, are accepted by the verifier
/// that agreed to those terms and refused by the one that did not — and
/// each result states which terms it was reached under.
#[test]
fn adv10_acceptance_travels_with_the_verifier_not_the_package() {
    let s = common::verified_execution();
    let p = package(&s, A_CENTURY_MS, true);
    let bytes = export_proof(&p).unwrap();

    let mut wide = anchors(&s);
    wide.capability = VerifierCapability::strict().max_health_age_ms(A_CENTURY_MS);
    let first = verify_nexora_proof(&import_proof(&bytes).unwrap(), &wide);
    assert!(
        first.is_valid(),
        "the widened verifier agreed to these terms"
    );
    assert_eq!(first.evaluated_under.health_age_bound(), A_CENTURY_MS);

    // The identical bytes, at a verifier that did not agree.
    let second = verify_nexora_proof(&import_proof(&bytes).unwrap(), &anchors(&s));
    assert!(!second.is_valid(), "the same package, a narrower verifier");
    assert_eq!(second.result, None);
    assert_eq!(
        first.proof_id, second.proof_id,
        "the same package throughout"
    );
    assert_ne!(
        first.evaluated_under, second.evaluated_under,
        "and each result says which terms produced it"
    );
}

#[track_caller]
fn refused_reason(v: &VerifiedProof) -> InvalidReason {
    match &v.verdict {
        ProofVerdict::Invalid(r) => r.clone(),
        ProofVerdict::Valid => panic!("expected a refusal"),
    }
}
