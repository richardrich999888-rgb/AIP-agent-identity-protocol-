//! Skill 19 — the platform/hardware adversarial matrix.
//!
//! Cases 1-2 and 21-23 that need the real reconciler live in `t13.rs`; this
//! file covers the binding, registry and lifecycle layers.
//!
//! # What these establish, precisely
//!
//! `PlatformBinding` is unsigned, like Skill 17's and Skill 18's records. An
//! unsigned record cannot stop anyone writing what they like into it. What is
//! established is that a substitution **changes the canonical bytes and the
//! digest**, so any signature over them stops verifying and the substitution
//! cannot be *silent* — and that the registry, which is verifier-held and
//! never travels with the evidence, cannot be influenced by the subject at all.

use aip_platform::*;
use aip_system::{HardwareId, PlatformId};

const EXEC_A: [u8; 16] = [0xA1; 16];
const EXEC_B: [u8; 16] = [0xB2; 16];
const BOOT_P: [u8; 16] = [0x11; 16];
const BOOT_Q: [u8; 16] = [0x22; 16];
const NOW: u64 = 1_700_000_000_000;

fn p(v: &str) -> PlatformId {
    PlatformId::parse(v).unwrap()
}
fn h(v: &str) -> HardwareId {
    HardwareId::parse(v).unwrap()
}

fn open_reg(platform: &str, hardware: Option<&str>) -> HostRegistration {
    HostRegistration {
        platform_id: p(platform),
        hardware_id: hardware.map(h),
        registered_from_ms: 0,
        registered_until_ms: None,
    }
}

fn registry() -> PlatformRegistry {
    PlatformRegistry::new()
        .register(BOOT_P, open_reg("tail:N123AB", Some("mod:EC-02")))
        .unwrap()
        .register(BOOT_Q, open_reg("tail:N456CD", Some("mod:EC-09")))
        .unwrap()
}

mod support;

/// A verified `ObservedBoot` for `boot`, produced the only way one can be: by
/// an anchored observer attesting a batch that this crate then verifies.
///
/// The helper exists because there is no shortcut — and the absence of a
/// shortcut is itself the property under test in `a16b`.
fn observed(boot: [u8; 16]) -> ObservedBoot {
    let (batch, anchors) = support::attested_batch_on(boot);
    ObservedBoot::from_attested(&batch, &anchors)
        .expect("an anchored observer's batch must verify")
        .expect("the batch carries an observation")
}

fn bind(exec: [u8; 16], boot: Option<[u8; 16]>, auth: Option<&str>) -> PlatformBinding {
    PlatformBinding::resolve(
        exec,
        boot.map(observed),
        auth.map(p).as_ref(),
        &registry(),
        NOW,
    )
}

/// Assert a substitution changed both the encoding and the digest.
fn assert_distinct(a: &PlatformBinding, b: &PlatformBinding, what: &str) {
    assert_ne!(
        a.canonical_bytes(),
        b.canonical_bytes(),
        "SECURITY: {what} produced identical canonical bytes"
    );
    assert_ne!(
        a.digest(),
        b.digest(),
        "SECURITY: {what} collided on the digest"
    );
}

// ═══ 3-7. Identity substitution ═══

#[test]
fn a03_platform_id_substitution() {
    // The same execution, resolved against hosts registered to two platforms.
    let on_p = bind(EXEC_A, Some(BOOT_P), None);
    let on_q = bind(EXEC_A, Some(BOOT_Q), None);
    assert_distinct(&on_p, &on_q, "platform P → Q");
}

#[test]
fn a04_hardware_id_substitution() {
    // Same platform, different compute element — the multi-module case. The
    // hardware id is inside the encoding, so the two are distinguishable even
    // though they share a platform.
    let reg = PlatformRegistry::new()
        .register(BOOT_P, open_reg("tail:N123AB", Some("mod:EC-02")))
        .unwrap()
        .register(BOOT_Q, open_reg("tail:N123AB", Some("mod:EC-09")))
        .unwrap();
    let a = PlatformBinding::resolve(EXEC_A, Some(observed(BOOT_P)), None, &reg, NOW);
    let b = PlatformBinding::resolve(EXEC_A, Some(observed(BOOT_Q)), None, &reg, NOW);

    // Same platform...
    match (a.disposition(), b.disposition()) {
        (
            PlatformDisposition::Bound {
                platform_id: pa,
                hardware_id: ha,
                ..
            },
            PlatformDisposition::Bound {
                platform_id: pb,
                hardware_id: hb,
                ..
            },
        ) => {
            assert_eq!(pa, pb, "one platform, two compute modules");
            assert_ne!(ha, hb, "SECURITY: two modules resolved to one hardware id");
        }
        other => panic!("both must bind: {other:?}"),
    }
    assert_distinct(&a, &b, "hardware EC-02 → EC-09");
}

#[test]
fn a05_execution_id_substitution() {
    let a = bind(EXEC_A, Some(BOOT_P), None);
    let b = bind(EXEC_B, Some(BOOT_P), None);
    assert_distinct(&a, &b, "execution A → B");
}

#[test]
fn a06_a_binding_carries_no_agent_identity_to_substitute() {
    // Structural, and worth asserting: agent identity is portable across
    // platforms by design, so putting it in a platform binding would fuse two
    // things Skill 17 exists to keep apart. There is no agent field here.
    let b = bind(EXEC_A, Some(BOOT_P), None);
    let json = serde_json::to_string(&b).unwrap();
    assert!(
        !json.contains("agent"),
        "SECURITY: a platform binding carries an agent identity: {json}"
    );
}

#[test]
fn a07_a_binding_carries_no_mission_to_substitute() {
    // Same reasoning: a mission is what was being attempted, not where.
    let b = bind(EXEC_A, Some(BOOT_P), None);
    assert!(!serde_json::to_string(&b).unwrap().contains("mission"));
}

// ═══ 8-13. Lifecycle ═══

#[test]
fn a08_platform_reuse_by_another_agent_is_not_a_platform_change() {
    // A platform runs agent A, then agent B. The platform binding is about
    // *where*, so it is unchanged — and that is correct. Substituting the
    // agent is caught by the reconciler's identity comparison, not here.
    let first = bind(EXEC_A, Some(BOOT_P), None);
    let second = bind(EXEC_B, Some(BOOT_P), None);
    match (first.disposition(), second.disposition()) {
        (
            PlatformDisposition::Bound { platform_id: a, .. },
            PlatformDisposition::Bound { platform_id: b, .. },
        ) => assert_eq!(a, b, "the platform did not change"),
        other => panic!("both must bind: {other:?}"),
    }
    // ...but the two bindings are still distinguishable, because the
    // execution differs.
    assert_distinct(&first, &second, "platform reuse by another execution");
}

#[test]
fn a09_hardware_replacement_does_not_silently_preserve_old_trust() {
    // The requirement stated most sharply in the brief. The old registration
    // is closed and a new one opened; a verification at a later instant
    // resolves the new hardware, and one at an earlier instant still resolves
    // the old — history is not rewritten.
    let mut reg = PlatformRegistry::new()
        .register(BOOT_P, open_reg("tail:N123AB", Some("mod:EC-02")))
        .unwrap();

    let replaced_at = NOW;
    assert!(reg.close(&BOOT_P, replaced_at), "the open entry must close");
    let reg = reg
        .register(
            BOOT_P,
            HostRegistration {
                platform_id: p("tail:N123AB"),
                hardware_id: Some(h("mod:EC-77")),
                registered_from_ms: replaced_at,
                registered_until_ms: None,
            },
        )
        .expect("the replacement registers after the old entry closed");

    let before =
        PlatformBinding::resolve(EXEC_A, Some(observed(BOOT_P)), None, &reg, replaced_at - 1);
    let after =
        PlatformBinding::resolve(EXEC_A, Some(observed(BOOT_P)), None, &reg, replaced_at + 1);

    let hw = |b: &PlatformBinding| match b.disposition() {
        PlatformDisposition::Bound { hardware_id, .. } => {
            hardware_id.as_ref().unwrap().as_str().to_owned()
        }
        other => panic!("must bind: {other:?}"),
    };
    assert_eq!(hw(&before), "mod:EC-02", "history must not be rewritten");
    assert_eq!(
        hw(&after),
        "mod:EC-77",
        "SECURITY: after hardware replacement the old registration still applied"
    );
}

#[test]
fn a09b_overlapping_registrations_are_refused_not_resolved() {
    // Guessing which of two applicable registrations was meant is how a
    // replacement gets attributed to the wrong platform.
    let reg = PlatformRegistry::new()
        .register(BOOT_P, open_reg("tail:N123AB", None))
        .unwrap();
    assert_eq!(
        reg.register(BOOT_P, open_reg("tail:N456CD", None)).err(),
        Some(PlatformError::OverlappingRegistration),
        "SECURITY: two registrations applying at one instant were accepted"
    );
}

#[test]
fn a09c_an_empty_registration_window_is_refused() {
    for (from, until) in [(100u64, 100u64), (100, 50)] {
        assert_eq!(
            PlatformRegistry::new()
                .register(
                    BOOT_P,
                    HostRegistration {
                        platform_id: p("tail:N123AB"),
                        hardware_id: None,
                        registered_from_ms: from,
                        registered_until_ms: Some(until),
                    },
                )
                .err(),
            Some(PlatformError::EmptyRegistrationWindow)
        );
    }
}

#[test]
fn a10_a_reboot_produces_a_new_boot_and_the_old_registration_stops_applying() {
    // boot_id identifies a boot, not a machine (ADR-002 G1). A reboot is
    // therefore an unregistered host until the verifier registers it — which
    // is fail-closed and is exactly why durable hardware identity needs
    // attestation.
    let reg = registry();
    let after_reboot = [0x33; 16];
    let b = PlatformBinding::resolve(EXEC_A, Some(observed(after_reboot)), None, &reg, NOW);
    assert_eq!(
        b.disposition(),
        &PlatformDisposition::Unregistered,
        "a rebooted host is unknown until registered — not silently the old one"
    );
}

#[test]
fn a11_a_container_restart_on_a_registered_host_still_binds() {
    // A container restart does not change the host boot, so the platform
    // binding is unaffected. Execution identity changes, and that is the
    // reconciler's business, not this crate's.
    let first = bind(EXEC_A, Some(BOOT_P), None);
    let restarted = bind(EXEC_B, Some(BOOT_P), None);
    assert!(first.disposition().asserts_platform());
    assert!(restarted.disposition().asserts_platform());
}

#[test]
fn a13_a_stale_registration_does_not_apply() {
    let reg = PlatformRegistry::new()
        .register(
            BOOT_P,
            HostRegistration {
                platform_id: p("tail:N123AB"),
                hardware_id: None,
                registered_from_ms: 0,
                registered_until_ms: Some(NOW),
            },
        )
        .unwrap();
    // Exactly at the closing instant the window is half-open, so it no longer
    // applies — an overlap at handover is precisely when ambiguity is worst.
    let at_close = PlatformBinding::resolve(EXEC_A, Some(observed(BOOT_P)), None, &reg, NOW);
    assert_eq!(at_close.disposition(), &PlatformDisposition::Unregistered);
    let before = PlatformBinding::resolve(EXEC_A, Some(observed(BOOT_P)), None, &reg, NOW - 1);
    assert!(before.disposition().asserts_platform());
}

// ═══ 14-20. Forgery, transplant, replay ═══

#[test]
fn a14_a15_hardware_attestation_is_unconstructible() {
    // The ADR-002 stop, enforced rather than documented. There is no
    // constructor, builder or code path producing a HardwareAttested binding,
    // so a forged platform or hardware attestation has nothing to forge into.
    assert!(
        !BindingMethod::HardwareAttested.is_implemented(),
        "SECURITY: hardware attestation became constructible. That is a new \
         trust anchor and requires ADR-002 to be ACCEPTED first."
    );
    // Every binding this build can produce uses the registry.
    for boot in [BOOT_P, BOOT_Q] {
        if let PlatformDisposition::Bound { method, .. } =
            bind(EXEC_A, Some(boot), None).disposition()
        {
            assert_eq!(*method, BindingMethod::DeploymentRegistry);
        }
    }
}

#[test]
fn a16_a_binding_claiming_an_unimplemented_method_is_refused() {
    // The deserialization path: a record claiming HardwareAttested is either
    // from a future build or forged. Both are refused rather than read — the
    // same discipline as an unknown version.
    let b = bind(EXEC_A, Some(BOOT_P), None);
    b.check_version().expect("a registry binding is fine");

    let json = serde_json::to_string(&b)
        .unwrap()
        .replace("DeploymentRegistry", "HardwareAttested");
    let forged: PlatformBinding = serde_json::from_str(&json).expect("serde parses it");
    assert!(
        forged.check_version().is_err(),
        "SECURITY: a binding claiming hardware attestation passed validation \
         on a build that cannot perform it"
    );
}

#[test]
fn a17_a18_a_binding_names_the_boot_it_resolved_from() {
    // "Attestation from the wrong hardware" and "correct hardware, wrong
    // execution" both reduce to the same property here: the observed boot and
    // the execution are both inside the encoding, so neither can be exchanged
    // for another without changing the digest.
    let right = bind(EXEC_A, Some(BOOT_P), None);
    let wrong_hw = bind(EXEC_A, Some(BOOT_Q), None);
    let wrong_exec = bind(EXEC_B, Some(BOOT_P), None);
    assert_distinct(&right, &wrong_hw, "same execution, other hardware");
    assert_distinct(&right, &wrong_exec, "same hardware, other execution");
    assert_distinct(&wrong_hw, &wrong_exec, "the two substitutions differ");
}

#[test]
fn a19_replaying_a_binding_at_another_instant_changes_the_digest() {
    // A binding is resolved *at* an instant, and the instant is committed. A
    // replay presenting an old resolution as current changes the bytes.
    let then = PlatformBinding::resolve(EXEC_A, Some(observed(BOOT_P)), None, &registry(), NOW);
    let now = PlatformBinding::resolve(
        EXEC_A,
        Some(observed(BOOT_P)),
        None,
        &registry(),
        NOW + 60_000,
    );
    assert_distinct(&then, &now, "replay at another instant");
}

#[test]
fn a20_cross_system_transplant_changes_the_digest() {
    // Every distinct context in this file must encode distinctly — pairwise
    // inequality is not enough, since two attacks landing on one encoding
    // would be a collision even if each differed from the baseline.
    let mut all: Vec<Vec<u8>> = vec![
        bind(EXEC_A, Some(BOOT_P), None).canonical_bytes(),
        bind(EXEC_A, Some(BOOT_Q), None).canonical_bytes(),
        bind(EXEC_B, Some(BOOT_P), None).canonical_bytes(),
        bind(EXEC_B, Some(BOOT_Q), None).canonical_bytes(),
        bind(EXEC_A, None, None).canonical_bytes(),
        bind(EXEC_A, Some([0xEE; 16]), None).canonical_bytes(),
        bind(EXEC_A, Some(BOOT_Q), Some("tail:N123AB")).canonical_bytes(),
    ];
    let n = all.len();
    all.sort();
    all.dedup();
    assert_eq!(
        n,
        all.len(),
        "SECURITY: two distinct contexts encoded identically"
    );
}

// ═══ 21-23. Absence ═══

#[test]
fn a21_observer_unavailable_is_not_evaluated() {
    // No observation reached the verifier. That is not evidence of location,
    // and not evidence that the claim is false.
    let b = bind(EXEC_A, None, Some("tail:N123AB"));
    assert_eq!(b.disposition(), &PlatformDisposition::NotEvaluated);
    assert!(!b.disposition().asserts_platform());
}

#[test]
fn a22_an_empty_registry_yields_unregistered_not_bound() {
    // A verifier that registered nothing has asserted nothing. Every observed
    // host is unknown, and none is silently accepted.
    let empty = PlatformRegistry::new();
    assert!(empty.is_empty());
    let b = PlatformBinding::resolve(EXEC_A, Some(observed(BOOT_P)), None, &empty, NOW);
    assert_eq!(b.disposition(), &PlatformDisposition::Unregistered);
}

#[test]
fn a23_an_agent_cannot_influence_the_registry() {
    // Structural, and the reason this is not a new trust anchor: the registry
    // is constructed by the verifier and never travels with the evidence. A
    // binding carries no registry, so a record cannot assert its own context —
    // which is B-4's defect, one layer down.
    let b = bind(EXEC_A, Some(BOOT_P), None);
    let json = serde_json::to_string(&b).unwrap();
    for leaked in ["registered_from", "registered_until", "hosts"] {
        assert!(
            !json.contains(leaked),
            "SECURITY: a binding carries registry state ({leaked}): {json}"
        );
    }
}

// ═══ 24-25. Multi-module platforms, serialization ═══

#[test]
fn a24_one_platform_may_contain_several_compute_modules() {
    // The UAS/UGV/robotics shape from the brief: UAS-07 with compute modules
    // EC-02 and EC-09, each booting separately. One platform, several boots,
    // no change to core semantics.
    let reg = PlatformRegistry::new()
        .register(BOOT_P, open_reg("tail:UAS-07", Some("mod:EC-02")))
        .unwrap()
        .register(BOOT_Q, open_reg("tail:UAS-07", Some("mod:EC-09")))
        .unwrap()
        .register([0x44; 16], open_reg("chassis:UGV-03", Some("mod:EC-14")))
        .unwrap();

    let uas = reg.boots_of(&p("tail:UAS-07"), NOW);
    assert_eq!(uas.len(), 2, "one platform, two compute modules");
    assert_eq!(reg.boots_of(&p("chassis:UGV-03"), NOW).len(), 1);
    assert!(reg.boots_of(&p("hull:USV-99"), NOW).is_empty());
    // Deterministic ordering, so a caller comparing two results is comparing
    // sets rather than iteration order.
    let mut sorted = uas.clone();
    sorted.sort();
    assert_eq!(uas, sorted);
}

#[test]
fn a25_serialization_round_trip_preserves_the_binding() {
    for b in [
        bind(EXEC_A, Some(BOOT_P), None),
        bind(EXEC_A, Some(BOOT_Q), Some("tail:N123AB")),
        bind(EXEC_A, Some([0xEE; 16]), None),
        bind(EXEC_A, None, None),
    ] {
        let parsed: PlatformBinding =
            serde_json::from_str(&serde_json::to_string(&b).unwrap()).expect("round trip");
        assert_eq!(parsed, b);
        assert_eq!(
            parsed.canonical_bytes(),
            b.canonical_bytes(),
            "a round trip must not change the committed encoding"
        );
        assert_eq!(
            parsed.disposition(),
            b.disposition(),
            "SECURITY: the disposition changed in transport"
        );
        parsed.check_version().expect("version accepted");
    }
}

#[test]
fn a25b_unsupported_versions_are_refused_not_guessed() {
    let mut b = bind(EXEC_A, Some(BOOT_P), None);
    for found in [0u16, 2, 99, u16::MAX] {
        b.version = found;
        assert_eq!(
            b.check_version(),
            Err(PlatformError::UnsupportedVersion {
                found,
                supported: PLATFORM_BINDING_VERSION
            })
        );
    }
}

// ═══ 16, 23b. The observation must be earned ═══
//
// These close a defect found by auditing this crate's own API after Skill 19
// was first completed. `PlatformBinding::resolve` originally took a bare
// `Option<[u8; 16]>`, so nothing stopped a caller passing the boot id out of
// the agent's own self-reported `ExecutionBinding` and receiving a `Bound`
// disposition — exactly the failure acceptance criterion 4 prohibits,
// prevented only by caller discipline, which is not prevention.

#[test]
fn a16b_a_batch_from_an_unanchored_observer_yields_no_observed_boot() {
    // Case 16 — "attestation signed by an untrusted key" — in the form this
    // architecture actually has one. The batch is validly signed; the verifier
    // simply does not anchor that observer. A failed verification must yield
    // no boot id at all, so a caller cannot proceed with a value it did not
    // earn.
    let (batch, foreign_anchors) = support::attested_batch_from_untrusted_observer(BOOT_P);

    let refused = ObservedBoot::from_attested(&batch, &foreign_anchors);
    assert!(
        refused.is_err(),
        "SECURITY: a batch from an observer the verifier does not anchor \
         produced an ObservedBoot"
    );

    // The same batch under the anchors that do trust it verifies — so the
    // refusal above is about trust, not about a broken fixture.
    let (batch, own_anchors) = support::attested_batch_on(BOOT_P);
    assert!(ObservedBoot::from_attested(&batch, &own_anchors)
        .expect("verifies under its own anchors")
        .is_some());
}

#[test]
fn a16c_an_empty_anchor_set_trusts_nothing() {
    let (batch, _) = support::attested_batch_on(BOOT_P);
    assert!(
        ObservedBoot::from_attested(&batch, &aip_observe::ObserverTrustAnchors::new()).is_err(),
        "SECURITY: a verifier anchoring no observers accepted an observation"
    );
}

#[test]
fn a16d_a_verified_but_silent_batch_is_an_absence_not_an_error() {
    // A batch that verifies and carries no observation is not a failure. The
    // two must not be conflated: "the observer signed nothing about this" and
    // "the observer is untrusted" are different states, and only the second is
    // an error.
    let (batch, anchors) = support::empty_attested_batch();
    let result = ObservedBoot::from_attested(&batch, &anchors);
    assert!(result.is_ok(), "a verified batch is not an error");
    assert!(
        result.unwrap().is_none(),
        "a batch with no observations yields no boot id"
    );
}

#[test]
fn a23b_a_self_reported_boot_id_cannot_become_a_binding() {
    // The defect, stated as the property that now prevents it.
    //
    // An agent's self-collected `ExecutionBinding` carries a boot id. There is
    // no constructor, conversion or builder taking those bytes into an
    // `ObservedBoot` — no `from_bytes`, no `new`, no `From<[u8; 16]>` — so the
    // only thing a caller can do with a self-reported boot id is pass `None`.
    //
    // That is enforced by the type system and cannot be asserted at runtime;
    // what is asserted here is the consequence.
    let self_reported = aip_types::ExecutionBinding {
        version: aip_types::EXECUTION_BINDING_VERSION,
        agent_id: "aip1selfreported".into(),
        process: aip_types::ProcessInstance {
            pid: 4321,
            pid_start_time_ticks: 777_000,
            // The agent claims the registered host.
            boot_id: BOOT_P,
        },
        exe_content_sha256: [0x11; 32],
        exe_path: "/opt/agent/bin/autonomy".into(),
        bound_at_ms: NOW,
    };
    // Those bytes are available to the caller...
    assert_eq!(self_reported.process.boot_id, BOOT_P);

    // ...and the only binding reachable from them is one with no observation.
    let b = PlatformBinding::resolve(EXEC_A, None, Some(&p("tail:N123AB")), &registry(), NOW);
    assert_eq!(
        b.disposition(),
        &PlatformDisposition::NotEvaluated,
        "SECURITY: a self-reported boot id established a platform binding"
    );
    assert!(!b.disposition().asserts_platform());
}
