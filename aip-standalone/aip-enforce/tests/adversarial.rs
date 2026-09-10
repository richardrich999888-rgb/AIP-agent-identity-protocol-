//! The enforcement tier without a kernel: every way an epoch, a request or
//! the enforcer's own condition can be wrong, and the deny each one earns.

use aip_crypto::{generate_ed25519_keypair, sha256};
use aip_enforce::*;

const AGENT: &str = "aip:agent-under-test";
const NOW: u64 = 1_000_000;

fn prog(tag: &str) -> [u8; 32] {
    sha256(tag.as_bytes())
}

fn draft(programs: &[[u8; 32]], issued_at: u64, valid_until: u64) -> EpochDraft {
    EpochDraft {
        epoch_id: [0x11; 16],
        agent_id: AGENT.into(),
        expectation_digest: sha256(b"ExpectedExecution preimage"),
        allowed_programs: programs.to_vec(),
        allowed_egress: vec![Egress {
            addr_v4: [10, 0, 0, 5],
            port: 443,
        }],
        issued_at,
        valid_until,
    }
}

struct Rig {
    issuer: SoftwareIssuer,
    cache: EpochCache,
}

fn rig() -> Rig {
    let kp = generate_ed25519_keypair();
    let anchors =
        EpochAnchors::new().trust("issuer:soft-1", &kp.public_key, RootOfTrust::SoftwareKey);
    Rig {
        issuer: SoftwareIssuer::new("issuer:soft-1", kp, 1),
        cache: EpochCache::new(anchors, AGENT),
    }
}

fn exec(p: [u8; 32]) -> SyscallRequest {
    SyscallRequest::Exec {
        program: ProgramIdentity::ContentHash(p),
    }
}

#[test]
fn e01_no_epoch_denies() {
    let r = rig();
    assert_eq!(
        decide(EnforcerHealth::Nominal, &r.cache, &exec(prog("sh")), NOW),
        Decision::Deny(DenyReason::NoEpoch)
    );
}

#[test]
fn e02_an_expired_or_not_yet_valid_epoch_denies() {
    let mut r = rig();
    let e = r
        .issuer
        .issue(draft(&[prog("sh")], NOW + 10, NOW + 20))
        .unwrap();
    r.cache.admit(&e).unwrap();
    assert_eq!(
        decide(EnforcerHealth::Nominal, &r.cache, &exec(prog("sh")), NOW),
        Decision::Deny(DenyReason::EpochNotYetValid)
    );
    assert_eq!(
        decide(
            EnforcerHealth::Nominal,
            &r.cache,
            &exec(prog("sh")),
            NOW + 21
        ),
        Decision::Deny(DenyReason::EpochExpired)
    );
    assert_eq!(
        decide(
            EnforcerHealth::Nominal,
            &r.cache,
            &exec(prog("sh")),
            NOW + 15
        ),
        Decision::Allow
    );
}

#[test]
fn e03_a_program_outside_the_allowed_set_denies() {
    let mut r = rig();
    let e = r
        .issuer
        .issue(draft(&[prog("sh"), prog("true")], NOW, NOW + 60_000))
        .unwrap();
    r.cache.admit(&e).unwrap();
    assert_eq!(
        decide(EnforcerHealth::Nominal, &r.cache, &exec(prog("false")), NOW),
        Decision::Deny(DenyReason::ProgramNotAuthorised)
    );
}

#[test]
fn e04_an_allowed_program_inside_the_window_allows_and_nothing_else_changes() {
    let mut r = rig();
    let e = r
        .issuer
        .issue(draft(&[prog("sh"), prog("true")], NOW, NOW + 60_000))
        .unwrap();
    r.cache.admit(&e).unwrap();
    assert_eq!(
        decide(EnforcerHealth::Nominal, &r.cache, &exec(prog("true")), NOW),
        Decision::Allow
    );
    assert_eq!(
        decide(EnforcerHealth::Nominal, &r.cache, &exec(prog("sh")), NOW),
        Decision::Allow
    );
}

#[test]
fn e05_a_replayed_or_stale_epoch_is_refused_at_admission_and_evicts_nothing() {
    let mut r = rig();
    let first = r
        .issuer
        .issue(draft(&[prog("sh")], NOW, NOW + 60_000))
        .unwrap(); // counter 1
    let second = r
        .issuer
        .issue(draft(&[prog("sh")], NOW, NOW + 60_000))
        .unwrap(); // counter 2
    r.cache.admit(&second).unwrap();
    assert_eq!(
        r.cache.admit(&first).err(),
        Some(AdmitError::CounterNotIncreasing { last: 2, got: 1 })
    );
    assert_eq!(
        r.cache.admit(&second).err(),
        Some(AdmitError::CounterNotIncreasing { last: 2, got: 2 })
    );
    // The good epoch is still active.
    assert!(decide(EnforcerHealth::Nominal, &r.cache, &exec(prog("sh")), NOW).is_allow());
}

#[test]
fn e06_an_epoch_from_an_unanchored_issuer_is_refused() {
    let mut r = rig();
    let mallory = SoftwareIssuer::new("issuer:soft-1", generate_ed25519_keypair(), 1);
    let mut mallory = mallory;
    let forged = mallory
        .issue(draft(&[prog("evil")], NOW, NOW + 60_000))
        .unwrap();
    assert_eq!(
        r.cache.admit(&forged).err(),
        Some(AdmitError::Verify(EpochError::SignatureInvalid))
    );
    let mut nobody = SoftwareIssuer::new("issuer:nobody", generate_ed25519_keypair(), 1);
    let unknown = nobody
        .issue(draft(&[prog("evil")], NOW, NOW + 60_000))
        .unwrap();
    assert_eq!(
        r.cache.admit(&unknown).err(),
        Some(AdmitError::Verify(EpochError::IssuerNotAnchored(
            "issuer:nobody".into()
        )))
    );
    assert_eq!(r.cache.status(NOW), EpochStatus::None);
}

#[test]
fn e07_a_tampered_epoch_is_refused() {
    let mut r = rig();
    let mut e = r
        .issuer
        .issue(draft(&[prog("sh")], NOW, NOW + 60_000))
        .unwrap();
    e.epoch.allowed_programs = vec![prog("evil")];
    assert_eq!(
        r.cache.admit(&e).err(),
        Some(AdmitError::Verify(EpochError::PayloadHashMismatch))
    );
    let mut e = r
        .issuer
        .issue(draft(&[prog("sh")], NOW, NOW + 60_000))
        .unwrap();
    e.epoch.valid_until += 1;
    assert_eq!(
        r.cache.admit(&e).err(),
        Some(AdmitError::Verify(EpochError::PayloadHashMismatch))
    );
}

#[test]
fn e08_a_degraded_enforcer_denies_everything_including_what_the_epoch_allows() {
    let mut r = rig();
    let e = r
        .issuer
        .issue(draft(&[prog("sh")], NOW, NOW + 60_000))
        .unwrap();
    r.cache.admit(&e).unwrap();
    for reason in [
        DegradedReason::ListenerLost,
        DegradedReason::ClockUnavailable,
    ] {
        assert_eq!(
            decide(
                EnforcerHealth::Degraded(reason),
                &r.cache,
                &exec(prog("sh")),
                NOW
            ),
            Decision::Deny(DenyReason::EnforcerDegraded(reason))
        );
    }
}

#[test]
fn e09_a_software_key_cannot_present_itself_as_a_hardware_root() {
    let kp = generate_ed25519_keypair();
    let mut issuer = SoftwareIssuer::new("issuer:soft-1", kp, 1);
    assert_eq!(issuer.root_of_trust(), RootOfTrust::SoftwareKey);
    let e = issuer
        .issue(draft(&[prog("sh")], NOW, NOW + 60_000))
        .unwrap();
    assert_eq!(e.epoch.counter_root, RootOfTrust::SoftwareKey);

    // An operator who anchors the same key as an ATECC608B has misdeclared;
    // the epoch's own root does not match and it is refused.
    let over_trusting =
        EpochAnchors::new().trust("issuer:soft-1", issuer.public_key(), RootOfTrust::Atecc608b);
    assert_eq!(
        verify_epoch(&e, &over_trusting).err(),
        Some(EpochError::RootOfTrustMismatch {
            anchored: RootOfTrust::Atecc608b,
            claimed: RootOfTrust::SoftwareKey
        })
    );

    // And an epoch that *claims* a hardware root under a software anchor is
    // refused before the signature is even checked.
    let mut claimed = e.clone();
    claimed.epoch.counter_root = RootOfTrust::Atecc608b;
    let honest = EpochAnchors::new().trust(
        "issuer:soft-1",
        issuer.public_key(),
        RootOfTrust::SoftwareKey,
    );
    assert_eq!(
        verify_epoch(&claimed, &honest).err(),
        Some(EpochError::RootOfTrustMismatch {
            anchored: RootOfTrust::SoftwareKey,
            claimed: RootOfTrust::Atecc608b
        })
    );
}

#[test]
fn e10_the_standing_table_and_the_row_the_separation_exists_for() {
    use EnforcementStanding::*;
    use EnforcerClaim::*;
    use ObserverFinding::*;
    assert_eq!(standing(Denied, NoExecutionObserved), Held);
    assert_eq!(standing(Denied, ExecutionObserved), Bypassed);
    assert_eq!(standing(Allowed, ExecutionObserved), Ordinary);
    assert_eq!(standing(Allowed, NoExecutionObserved), Unexercised);
    // Silence from the observer never confirms a denial held.
    assert_eq!(standing(Denied, ObservationUnavailable), CannotEstablish);
    assert_eq!(standing(Allowed, ObservationUnavailable), CannotEstablish);
}

#[test]
fn e11_this_crate_cannot_name_the_observation_or_reconciliation_path() {
    // ADR-008 §5.1 and §5.6: the enforcer is a claimant. If it could depend
    // on the observer it could become one, and a bypassed enforcer would
    // then be undetectable.
    let manifest =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
    let deps = manifest.split("[dependencies]").nth(1).unwrap();
    let deps = deps.split("[dev-dependencies]").next().unwrap();
    for forbidden in [
        "aip-observe",
        "aip-observation",
        "aip-reconcile",
        "aip-warrant",
        "aip-containment",
    ] {
        let line = deps
            .lines()
            .find(|l| l.trim_start().starts_with(forbidden) && !l.trim_start().starts_with('#'));
        assert!(
            line.is_none(),
            "aip-enforce must not depend on {forbidden}: {line:?}"
        );
    }
}

#[test]
fn e12_an_unhashable_program_denies_with_the_reason() {
    let mut r = rig();
    let e = r
        .issuer
        .issue(draft(&[prog("sh")], NOW, NOW + 60_000))
        .unwrap();
    r.cache.admit(&e).unwrap();
    for reason in [
        UnhashableReason::RelativePath,
        UnhashableReason::TargetMemoryUnreadable,
        UnhashableReason::PathMalformed,
        UnhashableReason::ReadFailed,
        UnhashableReason::ExecveatUnsupported,
    ] {
        let req = SyscallRequest::Exec {
            program: ProgramIdentity::Unhashable(reason),
        };
        assert_eq!(
            decide(EnforcerHealth::Nominal, &r.cache, &req, NOW),
            Decision::Deny(DenyReason::ProgramUnhashable(reason))
        );
    }
}

#[test]
fn e13_an_epoch_for_another_agent_is_refused() {
    let mut r = rig();
    let mut d = draft(&[prog("sh")], NOW, NOW + 60_000);
    d.agent_id = "aip:someone-else".into();
    let e = r.issuer.issue(d).unwrap();
    assert_eq!(
        r.cache.admit(&e).err(),
        Some(AdmitError::AgentMismatch {
            expected: AGENT.into(),
            got: "aip:someone-else".into()
        })
    );
}

#[test]
fn e14_egress_is_permitted_only_where_named() {
    let mut r = rig();
    let e = r
        .issuer
        .issue(draft(&[prog("sh")], NOW, NOW + 60_000))
        .unwrap();
    r.cache.admit(&e).unwrap();
    let named = SyscallRequest::Connect {
        egress: Egress {
            addr_v4: [10, 0, 0, 5],
            port: 443,
        },
    };
    let other_port = SyscallRequest::Connect {
        egress: Egress {
            addr_v4: [10, 0, 0, 5],
            port: 80,
        },
    };
    assert_eq!(
        decide(EnforcerHealth::Nominal, &r.cache, &named, NOW),
        Decision::Allow
    );
    assert_eq!(
        decide(EnforcerHealth::Nominal, &r.cache, &other_port, NOW),
        Decision::Deny(DenyReason::EgressNotAuthorised)
    );
}

#[test]
fn e15_the_epoch_preimage_is_injective_over_sets_and_every_field() {
    let mut r = rig();
    let a = r
        .issuer
        .issue(draft(&[prog("a"), prog("b")], NOW, NOW + 1))
        .unwrap();
    let b = r
        .issuer
        .issue(draft(&[prog("b"), prog("a")], NOW, NOW + 1))
        .unwrap();
    // Same set, same canonical order: the issuer sorted both.
    assert_eq!(a.epoch.allowed_programs, b.epoch.allowed_programs);
    // A hand-built epoch with the set out of order is refused rather than
    // signed over a second encoding of the same set.
    let mut unsorted = a.clone();
    unsorted.epoch.allowed_programs.reverse();
    let anchors = EpochAnchors::new().trust(
        "issuer:soft-1",
        r.issuer.public_key(),
        RootOfTrust::SoftwareKey,
    );
    assert_eq!(
        verify_epoch(&unsorted, &anchors).err(),
        Some(EpochError::SetsNotCanonical)
    );
}

#[test]
fn e16_an_enforcement_decision_verifies_under_the_enforcer_key_only() {
    let enforcer = generate_ed25519_keypair();
    let other = generate_ed25519_keypair();
    let anchors = EnforcerAnchors::new().trust("enforcer:host-1", &enforcer.public_key);
    let d = EnforcementDecision {
        version: ENFORCEMENT_DECISION_VERSION,
        enforcer_id: "enforcer:host-1".into(),
        agent_id: AGENT.into(),
        epoch_id: Some([0x11; 16]),
        process: None,
        request: RequestKind::Exec,
        program_hash: Some(prog("false")),
        decision: Decision::Deny(DenyReason::ProgramNotAuthorised),
        decided_at_ms: NOW,
    };
    let good = SignedEnforcementDecision::sign(d.clone(), &enforcer.private_key).unwrap();
    assert_eq!(verify_decision(&good, &anchors), Ok(&d));
    let forged = SignedEnforcementDecision::sign(d, &other.private_key).unwrap();
    assert_eq!(
        verify_decision(&forged, &anchors),
        Err(RecordError::SignatureInvalid)
    );
}
