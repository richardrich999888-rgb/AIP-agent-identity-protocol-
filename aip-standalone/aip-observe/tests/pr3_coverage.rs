//! PR3 A-3: a verifier must be able to read, from *signed* health, which
//! observation mechanisms covered the attested window. Without that, the
//! reconciler would have to infer kernel coverage from whether kernel events
//! happen to be present — inferring coverage from content is the I8 failure.

use aip_crypto::generate_ed25519_keypair;
use aip_observe::*;
use aip_types::ProcessInstance;

const OBSERVER_ID: &str = "collector";
const PROBE_ID: &str = "probe";

fn collector() -> (CollectorSigner, ObserverTrustAnchors) {
    let kp = generate_ed25519_keypair();
    let mut signer = CollectorSigner::new(OBSERVER_ID, 1, &kp.private_key, &kp.public_key).unwrap();
    signer.register_probe(PROBE_ID, &SourceMechanism::ALL);
    let anchors = ObserverTrustAnchors::new().trust(OBSERVER_ID, 1, &kp.public_key);
    (signer, anchors)
}

fn process() -> ObservedProcess {
    ObservedProcess {
        process: ProcessInstance {
            pid: 42,
            pid_start_time_ticks: 1000,
            boot_id: [0xb0; 16],
        },
        exe_content_sha256: [0xe0; 32],
        exe_path: "/opt/agent".into(),

        container: None,
    }
}

fn exec_event(pid: u32, ts: u64) -> ProcEvent {
    ProcEvent {
        kind: KernelLifecycleKind::Exec { pid, tgid: pid },
        cpu: 0,
        timestamp_ns: ts,
    }
}

/// Two contiguous batches from a probe whose connector was live the whole
/// time. Signed health must say a kernel-pushed mechanism covered the window.
#[test]
fn signed_health_states_which_mechanisms_covered_the_window() {
    let (mut signer, anchors) = collector();
    let mut probe = ProcfsProbe::new(PROBE_ID);
    probe.declare_source(SourceMechanism::ProcConnector);
    probe.declare_source(SourceMechanism::ProcfsPoll);

    probe.ingest_kernel_event(exec_event(42, 100));
    let o = probe.observation(process(), ObservedEffect::ProcessPresent, None, 100);
    signer
        .attest(probe.batch([1u8; 16], 100, 200, vec![o]))
        .unwrap();
    // Second batch: no kernel event happened to occur, but the connector
    // was still live. Coverage must not depend on events happening.
    let o = probe.observation(process(), ObservedEffect::ProcessPresent, None, 200);
    signer
        .attest(probe.batch([2u8; 16], 200, 300, vec![o]))
        .unwrap();

    let h = signer.health(300).unwrap();
    assert_eq!(verify_signed_health(&h, &anchors), Ok(()));
    assert_eq!(h.health.state, ObserverState::Active);
    let json = serde_json::to_string(&h.health).unwrap();
    assert!(
        json.contains("\"covered_by\"") && json.contains("ProcConnector"),
        "signed health must state kernel-pushed coverage: {json}"
    );
    assert!(h.covered_by_kernel_pushed_source());
}

/// A poll-only probe over the same window: health must say the window was
/// covered by polling only, so a reconciler can never treat silence in it as
/// non-execution.
#[test]
fn poll_only_coverage_is_stated_as_poll_only() {
    let (mut signer, anchors) = collector();
    let mut probe = ProcfsProbe::new(PROBE_ID);
    probe.declare_source(SourceMechanism::ProcfsPoll);
    for (id, from, to) in [(1u8, 100u64, 200u64), (2, 200, 300)] {
        let o = probe.observation(process(), ObservedEffect::ProcessPresent, None, from);
        signer
            .attest(probe.batch([id; 16], from, to, vec![o]))
            .unwrap();
    }
    let h = signer.health(300).unwrap();
    assert_eq!(verify_signed_health(&h, &anchors), Ok(()));
    let json = serde_json::to_string(&h.health).unwrap();
    assert!(json.contains("\"covered_by\""), "{json}");
    assert!(!json.contains("ProcConnector"), "{json}");
    assert!(!h.covered_by_kernel_pushed_source());
}

/// Coverage by a mechanism is the *intersection* over the contiguous
/// coverage epoch: a connector that came up part-way through did not cover
/// the epoch. (The epoch begins at the first contiguous batch, per Skill 6 —
/// batch 1 is the unverified epoch start and is not part of the window.)
#[test]
fn a_mechanism_live_for_part_of_the_window_does_not_cover_it() {
    let (mut signer, _anchors) = collector();
    let mut probe = ProcfsProbe::new(PROBE_ID);
    probe.declare_source(SourceMechanism::ProcfsPoll);
    for (id, from, to) in [(1u8, 100u64, 200u64), (2, 200, 300)] {
        let o = probe.observation(process(), ObservedEffect::ProcessPresent, None, from);
        signer
            .attest(probe.batch([id; 16], from, to, vec![o]))
            .unwrap();
    }
    // Coverage epoch is now [200, 300], poll-only.
    let h = signer.health(300).unwrap();
    assert_eq!(
        h.health.attested_coverage,
        Some(CoverageWindow {
            from_ms: 200,
            to_ms: 300
        })
    );
    assert!(!h.covered_by_kernel_pushed_source());

    probe.declare_source(SourceMechanism::ProcConnector); // came up late
    probe.ingest_kernel_event(exec_event(42, 350));
    let o = probe.observation(process(), ObservedEffect::ProcessPresent, None, 300);
    signer
        .attest(probe.batch([3u8; 16], 300, 400, vec![o]))
        .unwrap();

    let h = signer.health(400).unwrap();
    assert_eq!(
        h.health.attested_coverage,
        Some(CoverageWindow {
            from_ms: 200,
            to_ms: 400
        })
    );
    assert!(
        !h.covered_by_kernel_pushed_source(),
        "connector was not live over the whole epoch: {:?}",
        h.health.covered_by
    );
    assert_eq!(h.health.covered_by, vec![SourceMechanism::ProcfsPoll]);
    // Yet the kernel event itself is in the attested record — coverage and
    // content are different questions.
}

/// A probe cannot declare a mechanism it was not provisioned for.
#[test]
fn declared_coverage_is_bounded_by_the_registry() {
    let kp = generate_ed25519_keypair();
    let mut signer = CollectorSigner::new(OBSERVER_ID, 1, &kp.private_key, &kp.public_key).unwrap();
    signer.register_probe(PROBE_ID, &[SourceMechanism::ProcfsPoll]);
    let mut probe = ProcfsProbe::new(PROBE_ID);
    probe.declare_source(SourceMechanism::ProcConnector);
    let o = probe.observation(process(), ObservedEffect::ProcessPresent, None, 1);
    assert_eq!(
        signer.attest(probe.batch([1u8; 16], 1, 2, vec![o])),
        Err(AttestError::MechanismNotProvisioned {
            probe_id: PROBE_ID.into(),
            mechanism: SourceMechanism::ProcConnector
        })
    );
}

/// Restart resets the coverage epoch and its mechanism set: the first batch
/// of the new run opens a fresh epoch (Skill 6 semantics — no back-fill),
/// and the mechanisms covering it are only what the new run declares.
#[test]
fn restart_resets_covering_mechanisms() {
    let (mut signer, _anchors) = collector();
    let mut probe = ProcfsProbe::new(PROBE_ID);
    probe.declare_source(SourceMechanism::ProcConnector);
    for (id, from, to) in [(1u8, 100u64, 200u64), (2, 200, 300)] {
        let o = probe.observation(process(), ObservedEffect::ProcessPresent, None, from);
        signer
            .attest(probe.batch([id; 16], from, to, vec![o]))
            .unwrap();
    }
    assert!(signer
        .health(300)
        .unwrap()
        .covered_by_kernel_pushed_source());

    // New probe run without the connector.
    let mut restarted = ProcfsProbe::new(PROBE_ID);
    restarted.declare_source(SourceMechanism::ProcfsPoll);
    let o = restarted.observation(process(), ObservedEffect::ProcessPresent, None, 500);
    signer
        .attest(restarted.batch([3u8; 16], 500, 600, vec![o]))
        .unwrap();
    let h = signer.health(600).unwrap();
    // Fresh epoch: covers only the new run's window, by the new run's sources.
    assert_eq!(h.health.state, ObserverState::Active);
    assert_eq!(
        h.health.attested_coverage,
        Some(CoverageWindow {
            from_ms: 500,
            to_ms: 600
        }),
        "no back-fill over the outage"
    );
    assert!(!h.covered_by_kernel_pushed_source());
    assert_eq!(h.health.covered_by, vec![SourceMechanism::ProcfsPoll]);
    // And the pre-restart connector coverage cannot be asked about any more.
    let gap = h.availability_for(
        &CoverageWindow {
            from_ms: 100,
            to_ms: 300,
        },
        600,
        60_000,
    );
    assert!(!gap.is_covered());
}

/// The new fields are inside the attested bytes.
#[test]
fn active_mechanisms_mutation_is_detected() {
    let (mut signer, anchors) = collector();
    let mut probe = ProcfsProbe::new(PROBE_ID);
    probe.declare_source(SourceMechanism::ProcConnector);
    let o = probe.observation(process(), ObservedEffect::ProcessPresent, None, 1);
    let good = signer
        .attest(probe.batch([1u8; 16], 1, 2, vec![o]))
        .unwrap();
    assert_eq!(verify_attested_batch(&good, &anchors), Ok(()));
    let mut bad = good.clone();
    bad.batch.active_mechanisms = vec![SourceMechanism::ProcfsPoll];
    assert_eq!(
        verify_attested_batch(&bad, &anchors),
        Err(VerifyError::PayloadHashMismatch)
    );
    let h = signer.health(2).unwrap();
    let mut bad_h = h.clone();
    bad_h.health.covered_by = vec![SourceMechanism::ProcConnector];
    if bad_h != h {
        assert!(verify_signed_health(&bad_h, &anchors).is_err());
    }
}
