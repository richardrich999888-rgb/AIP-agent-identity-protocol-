//! Adversarial tests for the observer attestation layer (Skill 6 §21, §22).
//!
//! The four security properties under test, stated as the skill states them:
//!
//! ```text
//! agent controls observation input  ≠  agent controls observation signature
//! observation absence               ≠  non-execution
//! observer attestation              ≠  authorization
//! observer restart                  ≠  continuous coverage
//! ```

use aip_crypto::{generate_ed25519_keypair, sha256, sign_ed25519};
use aip_observe::*;
use aip_types::{ExecutionBinding, KeyPair, ProcessInstance, EXECUTION_BINDING_VERSION};

const OBSERVER_ID: &str = "collector.syntriass.example";
const KEY_V1: u32 = 1;

struct Fx {
    signer: CollectorSigner,
    observer_kp: KeyPair,
    agent_kp: KeyPair,
    anchors: ObserverTrustAnchors,
    probe: ProcfsProbe,
}

fn fixture() -> Fx {
    let observer_kp = generate_ed25519_keypair();
    let agent_kp = generate_ed25519_keypair();
    let signer = CollectorSigner::new(
        OBSERVER_ID,
        KEY_V1,
        &observer_kp.private_key,
        &observer_kp.public_key,
    )
    .unwrap();
    let anchors = ObserverTrustAnchors::new().trust(OBSERVER_ID, KEY_V1, &observer_kp.public_key);
    Fx {
        signer,
        observer_kp,
        agent_kp,
        anchors,
        probe: ProcfsProbe::new("probe-host-1"),
    }
}

fn process(pid: u32, start: u64, boot: u8, exe: u8) -> ObservedProcess {
    ObservedProcess {
        process: ProcessInstance {
            pid,
            pid_start_time_ticks: start,
            boot_id: [boot; 16],
        },
        exe_content_sha256: [exe; 32],
        exe_path: "/opt/agent/bin/payments-agent".into(),
    }
}

fn binding(agent_id: &str, pid: u32, start: u64, boot: u8, exe: u8) -> ExecutionBinding {
    ExecutionBinding {
        version: EXECUTION_BINDING_VERSION,
        agent_id: agent_id.into(),
        process: ProcessInstance {
            pid,
            pid_start_time_ticks: start,
            boot_id: [boot; 16],
        },
        exe_content_sha256: [exe; 32],
        exe_path: "/opt/agent/bin/payments-agent".into(),
        bound_at_ms: 1_700_000_000_000,
        container: None,
    }
}

fn batch_of(f: &mut Fx, id: u8, from: u64, to: u64, p: ObservedProcess) -> ObservationBatch {
    let obs = f
        .probe
        .observation(p, ObservedEffect::ProcessPresent, None, from);
    f.probe.batch([id; 16], from, to, vec![obs])
}

// ─── Happy path ───

#[test]
fn attested_batch_verifies_offline_and_chains() {
    let mut f = fixture();
    let b1 = batch_of(&mut f, 1, 100, 200, process(42, 1000, 0xb0, 0xe0));
    let a1 = f.signer.attest(b1).unwrap();
    assert_eq!(verify_attested_batch(&a1, &f.anchors), Ok(()));
    assert_eq!(a1.sequence, 1);
    assert_eq!(a1.prev_head, [0u8; 32]);

    let b2 = batch_of(&mut f, 2, 200, 300, process(42, 1000, 0xb0, 0xe0));
    let a2 = f.signer.attest(b2).unwrap();
    assert_eq!(verify_attested_batch(&a2, &f.anchors), Ok(()));
    assert_eq!(a2.sequence, 2);
    assert_eq!(a2.prev_head, a1.head(), "batch 2 must chain to batch 1");

    // JSON round-trip: verification needs nothing but the anchor.
    let json = serde_json::to_string(&a2).unwrap();
    let restored: AttestedBatch = serde_json::from_str(&json).unwrap();
    assert_eq!(restored, a2);
    assert_eq!(verify_attested_batch(&restored, &f.anchors), Ok(()));
}

// ─── §21.1–3, 15: mutation of every attested field is detected ───

#[test]
fn every_attested_field_mutation_is_detected() {
    let mut f = fixture();
    let b = batch_of(&mut f, 1, 100, 200, process(42, 1000, 0xb0, 0xe0));
    let good = f.signer.attest(b).unwrap();

    type Mutation = (&'static str, fn(&mut AttestedBatch));
    let mutations: Vec<Mutation> = vec![
        ("observer_id", |a| a.observer_id.push('x')),
        ("key_version", |a| a.key_version += 1),
        ("sequence", |a| a.sequence += 1),
        ("prev_head", |a| a.prev_head[0] ^= 0xff),
        ("batch.probe_id", |a| a.batch.probe_id.push('x')),
        ("batch.batch_id", |a| a.batch.batch_id[0] ^= 0x01),
        ("batch.claimed_from_ms", |a| a.batch.claimed_from_ms -= 1),
        ("batch.claimed_to_ms", |a| a.batch.claimed_to_ms += 1),
        ("observation.pid", |a| {
            a.batch.observations[0].observed.process.pid += 1
        }),
        ("observation.start_ticks", |a| {
            a.batch.observations[0]
                .observed
                .process
                .pid_start_time_ticks += 1
        }),
        ("observation.boot_id", |a| {
            a.batch.observations[0].observed.process.boot_id[0] ^= 0xff
        }),
        ("observation.exe_hash", |a| {
            a.batch.observations[0].observed.exe_content_sha256[0] ^= 0x01
        }),
        ("observation.exe_path", |a| {
            a.batch.observations[0].observed.exe_path.push('x')
        }),
        ("observation.effect", |a| {
            a.batch.observations[0].effect = ObservedEffect::ProcessNoLongerPresent
        }),
        ("observation.attribution", |a| {
            a.batch.observations[0].attribution = AgentAttribution::Claimed {
                agent_id: "aip1injected".into(),
                claim_source: "attacker".into(),
            }
        }),
        ("observation.decision_id", |a| {
            a.batch.observations[0].claimed_decision_id = Some([7u8; 16])
        }),
        ("observation.wall_clock", |a| {
            a.batch.observations[0].host_wall_clock_ms += 1
        }),
        ("observation dropped", |a| {
            a.batch.observations.clear();
        }),
        ("observation duplicated", |a| {
            let o = a.batch.observations[0].clone();
            a.batch.observations.push(o);
        }),
    ];

    // `observer_id` and `key_version` also select the anchor, so mutating
    // them is caught one step earlier, as a trust failure rather than a
    // payload failure. Both are rejections; the distinction is deliberate
    // and must not be flattened.
    let identity_scoped = ["observer_id", "key_version"];

    for (name, mutate) in mutations {
        let mut bad = good.clone();
        mutate(&mut bad);
        let result = verify_attested_batch(&bad, &f.anchors);
        assert!(result.is_err(), "mutating {name} was not detected");
        if identity_scoped.contains(&name) {
            assert!(
                matches!(result, Err(VerifyError::UntrustedObserverKey { .. })),
                "mutating {name} should fail anchor selection, got {result:?}"
            );
        } else {
            assert_eq!(
                result,
                Err(VerifyError::PayloadHashMismatch),
                "mutating {name} must fail as a payload mismatch"
            );
        }
        assert_ne!(bad.head(), good.head(), "{name} must change the head");
    }

    // And with the mutated identity anchored, the signature itself still
    // fails: the bytes changed, so no key can rescue it.
    let mut bumped = good.clone();
    bumped.key_version += 1;
    let anchored_bump = ObserverTrustAnchors::new().trust(
        OBSERVER_ID,
        bumped.key_version,
        &f.observer_kp.public_key,
    );
    assert_eq!(
        verify_attested_batch(&bumped, &anchored_bump),
        Err(VerifyError::PayloadHashMismatch)
    );
}

#[test]
fn signature_mutation_and_signer_mismatch_are_distinct() {
    let mut f = fixture();
    let b = batch_of(&mut f, 1, 100, 200, process(42, 1000, 0xb0, 0xe0));
    let good = f.signer.attest(b).unwrap();

    let mut flipped = good.clone();
    flipped.attestation.signature_bytes[0] ^= 0x01;
    assert_eq!(
        verify_attested_batch(&flipped, &f.anchors),
        Err(VerifyError::SignatureInvalid)
    );

    let mut renamed = good.clone();
    renamed.attestation.signer_id = "someone-else".into();
    assert_eq!(
        verify_attested_batch(&renamed, &f.anchors),
        Err(VerifyError::SignerMismatch)
    );

    // Valid signature, unanchored signer: trust failure, not crypto failure.
    let empty = ObserverTrustAnchors::new();
    assert_eq!(
        verify_attested_batch(&good, &empty),
        Err(VerifyError::UntrustedObserverKey {
            observer_id: OBSERVER_ID.into(),
            key_version: KEY_V1
        })
    );
}

// ─── §21.16 / §16: key version and rotation ───

#[test]
fn key_version_mismatch_and_rotation_and_revocation() {
    let mut f = fixture();
    let b = batch_of(&mut f, 1, 100, 200, process(42, 1000, 0xb0, 0xe0));
    let v1 = f.signer.attest(b).unwrap();
    assert_eq!(verify_attested_batch(&v1, &f.anchors), Ok(()));

    // An anchor for a different version does not verify v1.
    let wrong_version =
        ObserverTrustAnchors::new().trust(OBSERVER_ID, 2, &f.observer_kp.public_key);
    assert_eq!(
        verify_attested_batch(&v1, &wrong_version),
        Err(VerifyError::UntrustedObserverKey {
            observer_id: OBSERVER_ID.into(),
            key_version: KEY_V1
        })
    );

    // Rotate; history under v1 stays verifiable while its anchor is kept.
    let kp2 = generate_ed25519_keypair();
    f.signer
        .rotate_key(2, &kp2.private_key, &kp2.public_key)
        .unwrap();
    let b2 = batch_of(&mut f, 2, 200, 300, process(42, 1000, 0xb0, 0xe0));
    let v2 = f.signer.attest(b2).unwrap();
    assert_eq!(v2.key_version, 2);

    let both = ObserverTrustAnchors::new()
        .trust(OBSERVER_ID, KEY_V1, &f.observer_kp.public_key)
        .trust(OBSERVER_ID, 2, &kp2.public_key);
    assert_eq!(verify_attested_batch(&v1, &both), Ok(()));
    assert_eq!(verify_attested_batch(&v2, &both), Ok(()));

    // Revocation of v1 leaves v2 verifiable and v1 untrusted.
    let mut revoked = both.clone();
    revoked.revoke(OBSERVER_ID, KEY_V1);
    assert!(verify_attested_batch(&v1, &revoked).is_err());
    assert_eq!(verify_attested_batch(&v2, &revoked), Ok(()));
}

// ─── §22: agent controls input ≠ agent controls signature (I10) ───

#[test]
fn the_observed_agent_cannot_forge_an_accepted_attestation() {
    let mut f = fixture();
    let b = batch_of(&mut f, 1, 100, 200, process(42, 1000, 0xb0, 0xe0));
    let good = f.signer.attest(b).unwrap();

    // The agent rewrites the observation and re-signs with the only key it
    // has: its own. The verifier's anchor is the observer's key.
    let mut forged = good.clone();
    forged.batch.observations[0].observed.exe_content_sha256 = [0xaa; 32];
    let pre = forged.signing_preimage();
    forged.attestation = sign_ed25519(&f.agent_kp.private_key, OBSERVER_ID, &pre).unwrap();
    assert_eq!(
        verify_attested_batch(&forged, &f.anchors),
        Err(VerifyError::SignatureInvalid)
    );

    // The agent stands up its own "observer" identity and signs there.
    let mut own = good.clone();
    own.observer_id = "agent-run-observer".into();
    let pre = own.signing_preimage();
    own.attestation = sign_ed25519(&f.agent_kp.private_key, "agent-run-observer", &pre).unwrap();
    assert_eq!(
        verify_attested_batch(&own, &f.anchors),
        Err(VerifyError::UntrustedObserverKey {
            observer_id: "agent-run-observer".into(),
            key_version: KEY_V1
        })
    );

    // Even if an operator is tricked into anchoring the agent's key as an
    // observer key, the agent-aware verifier refuses it: an observation
    // signed by the observed party is a second self-report, not evidence.
    let tricked =
        ObserverTrustAnchors::new().trust("agent-run-observer", KEY_V1, &f.agent_kp.public_key);
    assert_eq!(
        verify_attested_batch(&own, &tricked),
        Ok(()),
        "the signature itself is valid"
    );
    assert_eq!(
        verify_attested_batch_independent_of_agent(&own, &tricked, &f.agent_kp.public_key),
        Err(VerifyError::ObserverKeyIsAgentKey)
    );
}

#[test]
fn the_probe_holds_no_key_and_cannot_produce_a_signature() {
    let mut f = fixture();
    // Structural: the probe's debug form carries no key material...
    let probe_dbg = format!("{:?}", f.probe);
    assert!(!probe_dbg.contains("private"));
    assert!(!probe_dbg.contains("key"));

    // ...and an unsigned batch has no signature field at all.
    let b = batch_of(&mut f, 1, 1, 2, process(1, 1, 1, 1));
    let json = serde_json::to_string(&b).unwrap();
    for forbidden in ["signature", "attestation", "sig", "key"] {
        assert!(
            !json.contains(forbidden),
            "unsigned batch JSON must not contain `{forbidden}`: {json}"
        );
    }

    // The collector's debug form redacts its own key.
    let dbg = format!("{:?}", f.signer);
    assert!(dbg.contains("<redacted>"));
    assert!(!dbg.contains(&format!("{:?}", f.observer_kp.private_key)));
}

// ─── §21.4–5, §17: sequence rollback and replay ───

#[test]
fn replayed_attestation_is_not_a_new_observation() {
    let mut f = fixture();
    let b1 = batch_of(&mut f, 1, 100, 200, process(42, 1000, 0xb0, 0xe0));
    let a1 = f.signer.attest(b1).unwrap();

    // The replayed record still verifies cryptographically — a signature does
    // not expire — so freshness must come from the ledger, not the signature.
    assert_eq!(verify_attested_batch(&a1, &f.anchors), Ok(()));

    let mut ledger = ObserverLedger::new();
    assert_eq!(
        ledger.admit(a1.sequence, a1.prev_head, a1.head()),
        Ok(Admission::NewEpochUnverified)
    );
    assert_eq!(
        ledger.admit(a1.sequence, a1.prev_head, a1.head()),
        Err(ContinuityFault::Replay {
            sequence: a1.sequence
        }),
        "a replayed batch must not be admitted a second time"
    );
}

#[test]
fn sequence_rollback_is_refused_and_a_fork_quarantines() {
    let mut ledger = ObserverLedger::new();
    ledger.admit(5, [0u8; 32], [5u8; 32]).unwrap();
    ledger.admit(6, [5u8; 32], [6u8; 32]).unwrap();
    assert_eq!(
        ledger.admit(4, [3u8; 32], [4u8; 32]),
        Err(ContinuityFault::Rollback {
            last: 6,
            offered: 4
        })
    );

    // Two different heads at one sequence under one key: arithmetic proof of
    // observer integrity failure.
    let mut forked = ObserverLedger::new();
    forked.admit(1, [0u8; 32], [1u8; 32]).unwrap();
    assert!(matches!(
        forked.admit(1, [0u8; 32], [2u8; 32]),
        Err(ContinuityFault::Fork { .. })
    ));
    assert!(forked.is_quarantined());
    assert_eq!(forked.status(), ContinuityStatus::Broken);
}

#[test]
fn a_quarantined_ledger_refuses_all_later_batches() {
    let mut f = fixture();
    let b = batch_of(&mut f, 1, 100, 200, process(42, 1000, 0xb0, 0xe0));
    let a = f.signer.attest(b).unwrap();

    // A collector that is offered two different attested batches at one
    // sequence under one key has arithmetic proof of integrity failure.
    let mut ledger = ObserverLedger::new();
    ledger.admit(a.sequence, a.prev_head, a.head()).unwrap();
    assert!(ledger.admit(a.sequence, a.prev_head, [0xffu8; 32]).is_err());
    assert!(ledger.is_quarantined());
    assert_eq!(ledger.status(), ContinuityStatus::Broken);

    // Nothing later clears it, however well-formed.
    assert!(ledger.admit(a.sequence + 1, a.head(), [3u8; 32]).is_err());
    assert_eq!(ledger.status(), ContinuityStatus::Broken);
}

// ─── §21.6–9, §22: gaps, restart, stale state, partition ───

#[test]
fn a_sequence_gap_degrades_coverage_and_does_not_backfill() {
    let mut f = fixture();
    let b1 = batch_of(&mut f, 1, 100, 200, process(42, 1000, 0xb0, 0xe0));
    f.signer.attest(b1).unwrap();
    let b2 = batch_of(&mut f, 2, 200, 300, process(42, 1000, 0xb0, 0xe0));
    f.signer.attest(b2).unwrap();
    assert_eq!(f.signer.state(), ObserverState::Active);

    // Coverage begins where the first contiguous batch began — not at the
    // epoch-start batch, whose continuity was never verified.
    let health = f.signer.health(300).unwrap();
    assert_eq!(
        health.health.attested_coverage,
        Some(CoverageWindow {
            from_ms: 200,
            to_ms: 300
        })
    );
    let covered = health.availability_for(
        &CoverageWindow {
            from_ms: 210,
            to_ms: 250,
        },
        300,
        60_000,
    );
    assert!(covered.is_covered());
    let before_epoch = health.availability_for(
        &CoverageWindow {
            from_ms: 150,
            to_ms: 250,
        },
        300,
        60_000,
    );
    assert_eq!(
        before_epoch,
        ObservationAvailability::Unavailable {
            reason: UnavailableReason::WindowNotCovered
        }
    );

    // A gap in the collector's own ledger degrades the observer.
    let mut ledger = ObserverLedger::new();
    ledger.admit(1, [0u8; 32], [1u8; 32]).unwrap();
    assert_eq!(
        ledger.admit(4, [1u8; 32], [4u8; 32]),
        Ok(Admission::AdmittedWithGap { missing: 2 })
    );
    assert_eq!(ledger.status(), ContinuityStatus::GapObserved);
}

#[test]
fn observer_restart_is_not_continuous_coverage() {
    let mut f = fixture();
    let b1 = batch_of(&mut f, 1, 100, 200, process(42, 1000, 0xb0, 0xe0));
    f.signer.attest(b1).unwrap();
    let b2 = batch_of(&mut f, 2, 200, 300, process(42, 1000, 0xb0, 0xe0));
    f.signer.attest(b2).unwrap();
    assert_eq!(f.signer.state(), ObserverState::Active);
    let before = f.signer.health(300).unwrap();
    assert!(before.health.attested_coverage.is_some());

    // The probe restarts. Nothing about the gap is knowable.
    f.signer.note_probe_restart();
    assert_eq!(f.signer.state(), ObserverState::Recovering);
    let during = f.signer.health(400).unwrap();
    assert_eq!(during.health.attested_coverage, None);
    let avail = during.availability_for(
        &CoverageWindow {
            from_ms: 300,
            to_ms: 400,
        },
        400,
        60_000,
    );
    assert_eq!(
        avail,
        ObservationAvailability::Unavailable {
            reason: UnavailableReason::ObserverRecovering
        }
    );

    // The first batch after the restart starts a fresh coverage epoch and
    // does NOT back-fill the interval the observer was down.
    let b3 = batch_of(&mut f, 3, 500, 600, process(42, 1000, 0xb0, 0xe0));
    f.signer.attest(b3).unwrap();
    let after = f.signer.health(600).unwrap();
    let window = after.health.attested_coverage.unwrap();
    assert_eq!(
        window.from_ms, 500,
        "coverage must not reach back over the outage"
    );
    let gap = after.availability_for(
        &CoverageWindow {
            from_ms: 300,
            to_ms: 450,
        },
        600,
        60_000,
    );
    assert_eq!(
        gap,
        ObservationAvailability::Unavailable {
            reason: UnavailableReason::WindowNotCovered
        }
    );
}

#[test]
fn stale_state_restoration_cannot_reconstruct_continuity() {
    // An attacker restores an old host-side state file and re-offers an old
    // position. The collector holds the real position, so the offer is a
    // rollback or a head mismatch — never a silent resumption.
    let mut ledger = ObserverLedger::new();
    ledger.admit(1, [0u8; 32], [1u8; 32]).unwrap();
    ledger.admit(2, [1u8; 32], [2u8; 32]).unwrap();
    ledger.admit(3, [2u8; 32], [3u8; 32]).unwrap();

    assert_eq!(
        ledger.admit(2, [1u8; 32], [2u8; 32]),
        Err(ContinuityFault::Rollback {
            last: 3,
            offered: 2
        })
    );
    assert_eq!(
        ledger.admit(4, [1u8; 32], [4u8; 32]),
        Err(ContinuityFault::HeadMismatch {
            expected: [3u8; 32],
            offered: [1u8; 32]
        })
    );
}

#[test]
fn collector_partition_produces_unavailability_not_a_verdict() {
    let mut f = fixture();
    let b1 = batch_of(&mut f, 1, 100, 200, process(42, 1000, 0xb0, 0xe0));
    f.signer.attest(b1).unwrap();
    let b2 = batch_of(&mut f, 2, 200, 300, process(42, 1000, 0xb0, 0xe0));
    f.signer.attest(b2).unwrap();
    let health = f.signer.health(300).unwrap();

    // The host is partitioned: no new health arrives. Later, a verifier asks
    // about a window after the last health it holds.
    let stale = health.availability_for(
        &CoverageWindow {
            from_ms: 100_000,
            to_ms: 200_000,
        },
        400_000,
        60_000,
    );
    match stale {
        ObservationAvailability::Unavailable {
            reason: UnavailableReason::HealthStale { .. },
        } => {}
        other => panic!("partition must yield HealthStale, got {other:?}"),
    }
    assert!(!stale.is_covered());

    // With no observer at all the answer is still an availability statement.
    assert_eq!(
        no_observer(),
        ObservationAvailability::Unavailable {
            reason: UnavailableReason::NoObserver
        }
    );
}

// ─── §22: observation absence ≠ non-execution (I8) ───

#[test]
fn absence_of_observation_never_becomes_a_claim_about_execution() {
    // Everything this crate can say about an unobserved window is an
    // availability statement about the observer.
    let answers = [
        no_observer(),
        ObservationAvailability::Unavailable {
            reason: UnavailableReason::ObserverDegraded,
        },
        ObservationAvailability::Unavailable {
            reason: UnavailableReason::WindowNotCovered,
        },
    ];
    for a in &answers {
        assert!(!a.is_covered());
        let json = serde_json::to_string(a).unwrap().to_lowercase();
        for forbidden in ["phantom", "did_not", "notexecut", "malicious", "verdict"] {
            assert!(
                !json.contains(forbidden),
                "{json} must not imply {forbidden}"
            );
        }
    }

    // An empty batch is an empty batch, not a negative finding: it attests
    // normally and asserts nothing about what did or did not run.
    let mut f = fixture();
    let empty = f.probe.batch([9u8; 16], 100, 200, vec![]);
    let attested = f.signer.attest(empty).unwrap();
    assert!(attested.batch.observations.is_empty());
    assert_eq!(verify_attested_batch(&attested, &f.anchors), Ok(()));
}

// ─── §19, §22: attestation ≠ authorization (I19, I22) ───

#[test]
fn no_authorization_concept_exists_in_an_observation() {
    let mut f = fixture();
    let b = batch_of(&mut f, 1, 100, 200, process(42, 1000, 0xb0, 0xe0));
    let a = f.signer.attest(b).unwrap();
    let json = serde_json::to_string(&a).unwrap().to_lowercase();
    for forbidden in [
        "permitted",
        "authorized",
        "authorised",
        "allowed",
        "policy",
        "compliant",
        "safe",
        "malicious",
        "verdict",
        "expectedexecution",
    ] {
        assert!(
            !json.contains(forbidden),
            "observation must not carry `{forbidden}`: {json}"
        );
    }
}

#[test]
fn an_injected_decision_id_confers_nothing() {
    let mut f = fixture();
    let claim = AgentClaim {
        agent_id: "aip1agent".into(),
        claim_source: "orchestrator".into(),
        decision_id: Some([0xdd; 16]),
    };
    let obs = f.probe.observation(
        process(42, 1000, 0xb0, 0xe0),
        ObservedEffect::ProcessPresent,
        Some(&claim),
        150,
    );
    let b = f.probe.batch([1u8; 16], 100, 200, vec![obs]);
    let a = f.signer.attest(b).unwrap();
    assert_eq!(verify_attested_batch(&a, &f.anchors), Ok(()));

    let o = &a.batch.observations[0];
    // The decision id is carried for correlation only; the identity remains
    // a claim, and there is no variant that could say otherwise.
    assert_eq!(o.claimed_decision_id, Some([0xdd; 16]));
    assert!(matches!(o.attribution, AgentAttribution::Claimed { .. }));
    assert_eq!(o.attribution.claimed_agent_id(), Some("aip1agent"));
}

// ─── §18, §21.12: attribution uses the Stage 1 identity, never PID alone ───

#[test]
fn pid_reuse_cannot_transfer_an_observation() {
    let expected = binding("aip1agent", 42, 1000, 0xb0, 0xe0);

    let same_instance = process(42, 1000, 0xb0, 0xe0);
    assert!(same_instance.matches_process_of(&expected));

    // Same PID, different start ticks: a different process instance.
    let pid_reused = process(42, 2000, 0xb0, 0xe0);
    assert_eq!(pid_reused.process.pid, expected.process.pid);
    assert!(!pid_reused.matches_process_of(&expected));

    // Same PID and start, different boot.
    let rebooted = process(42, 1000, 0xb1, 0xe0);
    assert!(!rebooted.matches_process_of(&expected));

    // Same instance, replaced binary.
    let replaced = process(42, 1000, 0xb0, 0xe1);
    assert!(!replaced.matches_process_of(&expected));

    // Path spelling is not identity.
    let mut respelled = same_instance.clone();
    respelled.exe_path = "/opt/./agent/bin/payments-agent".into();
    assert!(respelled.matches_process_of(&expected));
    assert_eq!(respelled.identity_digest(), same_instance.identity_digest());
}

#[test]
fn matching_a_process_never_matches_an_agent_identity() {
    // Two bindings that differ ONLY in agent_id have the same process facts.
    // The observer's match is about the process; it cannot and does not
    // distinguish which AIP identity claims it.
    let a = binding("aip1agentA", 42, 1000, 0xb0, 0xe0);
    let b = binding("aip1agentB", 42, 1000, 0xb0, 0xe0);
    let observed = process(42, 1000, 0xb0, 0xe0);
    assert!(observed.matches_process_of(&a));
    assert!(observed.matches_process_of(&b));
    // Which is why attribution is a separate, explicitly-claimed field.
    assert_ne!(a.agent_id, b.agent_id);
}

// ─── §21.14: domain-tag confusion ───

#[test]
fn domain_tags_are_distinct_and_lead_every_preimage() {
    let mut f = fixture();
    let b = batch_of(&mut f, 1, 100, 200, process(42, 1000, 0xb0, 0xe0));
    let a = f.signer.attest(b).unwrap();

    let head_pre = a.signing_preimage();
    let tag = OBSERVER_HEAD_DOMAIN.as_bytes();
    assert_eq!(&head_pre[4..4 + tag.len()], tag);

    let batch_bytes = a.batch.canonical_bytes();
    let btag = OBSERVATION_BATCH_DOMAIN.as_bytes();
    assert_eq!(&batch_bytes[4..4 + btag.len()], btag);

    let obs_bytes = a.batch.observations[0].canonical_bytes();
    let otag = OBSERVED_EXECUTION_DOMAIN.as_bytes();
    assert_eq!(&obs_bytes[4..4 + otag.len()], otag);

    let tags = [
        OBSERVER_HEAD_DOMAIN,
        OBSERVATION_BATCH_DOMAIN,
        OBSERVED_EXECUTION_DOMAIN,
        OBSERVED_PROCESS_DOMAIN,
        OBSERVER_HEALTH_DOMAIN,
        aip_types::EXECUTION_BINDING_DOMAIN,
        aip_types::EXECUTION_IDENTITY_DOMAIN,
        aip_core::capability::SCOPED_TOKEN_DOMAIN,
        aip_core::delegation::DELEGATION_TOKEN_DOMAIN,
    ];
    for (i, t) in tags.iter().enumerate() {
        for u in &tags[i + 1..] {
            assert_ne!(t, u, "domain tags must be pairwise distinct");
        }
    }
}

#[test]
fn a_health_signature_cannot_be_replayed_as_a_batch_attestation() {
    let mut f = fixture();
    let b = batch_of(&mut f, 1, 100, 200, process(42, 1000, 0xb0, 0xe0));
    let a = f.signer.attest(b).unwrap();
    let h = f.signer.health(300).unwrap();
    assert_eq!(verify_signed_health(&h, &f.anchors), Ok(()));

    // Transplant the health signature onto the batch: different domain,
    // different bytes, rejected.
    let mut swapped = a.clone();
    swapped.attestation = h.attestation.clone();
    assert_eq!(
        verify_attested_batch(&swapped, &f.anchors),
        Err(VerifyError::PayloadHashMismatch)
    );

    // And the reverse.
    let mut swapped_h = h.clone();
    swapped_h.attestation = a.attestation.clone();
    assert_eq!(
        verify_signed_health(&swapped_h, &f.anchors),
        Err(VerifyError::PayloadHashMismatch)
    );
}

#[test]
fn health_field_mutation_is_detected() {
    let mut f = fixture();
    let b = batch_of(&mut f, 1, 100, 200, process(42, 1000, 0xb0, 0xe0));
    f.signer.attest(b).unwrap();
    let good = f.signer.health(300).unwrap();

    type HMutation = (&'static str, fn(&mut SignedSensorHealth));
    let cases: Vec<HMutation> = vec![
        ("state", |h| h.health.state = ObserverState::Active),
        ("continuity", |h| {
            h.health.continuity = ContinuityStatus::Verified
        }),
        ("sequence", |h| h.health.sequence += 1),
        ("head", |h| h.health.head[0] ^= 0xff),
        ("coverage", |h| {
            h.health.attested_coverage = Some(CoverageWindow {
                from_ms: 0,
                to_ms: u64::MAX,
            })
        }),
        ("emitted_at", |h| h.health.emitted_at_ms += 1),
        ("key_version", |h| h.health.key_version += 1),
    ];
    for (name, mutate) in cases {
        let mut bad = good.clone();
        mutate(&mut bad);
        if bad == good {
            continue; // mutation was a no-op for this state
        }
        assert!(
            verify_signed_health(&bad, &f.anchors).is_err(),
            "mutating health.{name} was not detected"
        );
    }
}

// ─── §21.15 / protocol version ───

#[test]
fn unsupported_protocol_version_is_refused() {
    let mut f = fixture();
    let b = batch_of(&mut f, 1, 100, 200, process(42, 1000, 0xb0, 0xe0));
    let a = f.signer.attest(b).unwrap();

    let mut bad = a.clone();
    bad.version = 99;
    assert_eq!(
        verify_attested_batch(&bad, &f.anchors),
        Err(VerifyError::UnsupportedVersion(99))
    );

    let mut bad_batch = a.clone();
    bad_batch.batch.version = 99;
    assert_eq!(
        verify_attested_batch(&bad_batch, &f.anchors),
        Err(VerifyError::UnsupportedVersion(OBSERVE_PROTOCOL_VERSION))
    );

    // The collector refuses to attest a batch from an unknown protocol.
    let mut f2 = fixture();
    let mut future = f2.probe.batch([1u8; 16], 1, 2, vec![]);
    future.version = 99;
    assert_eq!(
        f2.signer.attest(future),
        Err(AttestError::UnsupportedVersion(99))
    );
}

#[test]
fn collector_constructor_rejects_bad_material() {
    let kp = generate_ed25519_keypair();
    assert_eq!(
        CollectorSigner::new("", 1, &kp.private_key, &kp.public_key).err(),
        Some(AttestError::EmptyObserverId)
    );
    assert_eq!(
        CollectorSigner::new("o", 1, &kp.private_key[..31], &kp.public_key).err(),
        Some(AttestError::InvalidKeyLength(31))
    );
}

// ─── §21.16 malformed input must not panic ───

#[test]
fn malformed_procfs_input_never_panics() {
    // The probe reuses the Stage 1 parsers; re-assert the property at this
    // layer so a future observer-specific parser cannot regress it.
    for bad in [
        "",
        "1234",
        "1234 (x",
        "1234 (evil) prog) R 1 2 3",
        "1234 (x) R 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 notanumber 21",
    ] {
        let r = std::panic::catch_unwind(|| {
            aip_core::execution_binding::parse_proc_stat_start_time(bad)
        });
        assert!(r.is_ok(), "panicked on {bad:?}");
        assert!(r.unwrap().is_err());
    }
    for bad in ["", "not-a-uuid", "00000000-0000-0000-0000-000000000000"] {
        let r = std::panic::catch_unwind(|| aip_core::execution_binding::parse_boot_id(bad));
        assert!(r.is_ok(), "panicked on {bad:?}");
        assert!(r.unwrap().is_err());
    }
}

#[test]
fn observation_encoding_is_injective_across_adjacent_strings() {
    let mut f = fixture();
    let mut p1 = process(1, 1, 1, 1);
    p1.exe_path = "ab".into();
    let mut p2 = process(1, 1, 1, 1);
    p2.exe_path = "a".into();

    let o1 = f
        .probe
        .observation(p1, ObservedEffect::ProcessPresent, None, 1);
    let o2 = f
        .probe
        .observation(p2, ObservedEffect::ProcessPresent, None, 1);
    assert_ne!(o1.canonical_bytes(), o2.canonical_bytes());

    // ("ab","c") vs ("a","bc") across the two adjacent string fields.
    let c1 = AgentAttribution::Claimed {
        agent_id: "ab".into(),
        claim_source: "c".into(),
    };
    let c2 = AgentAttribution::Claimed {
        agent_id: "a".into(),
        claim_source: "bc".into(),
    };
    let mut a1 = o1.clone();
    a1.attribution = c1;
    let mut a2 = o1.clone();
    a2.attribution = c2;
    assert_ne!(a1.canonical_bytes(), a2.canonical_bytes());
    assert_ne!(a1.digest(), a2.digest());
}

#[test]
fn sha256_of_preimage_is_the_head_and_is_never_carried() {
    let mut f = fixture();
    let b = batch_of(&mut f, 1, 100, 200, process(42, 1000, 0xb0, 0xe0));
    let a = f.signer.attest(b).unwrap();
    assert_eq!(a.head(), sha256(&a.signing_preimage()));
    // There is no `head` field to tamper with: it is recomputed on demand.
    let json = serde_json::to_string(&a).unwrap();
    assert!(!json.contains("\"head\""));
    assert!(json.contains("prev_head"));
}
