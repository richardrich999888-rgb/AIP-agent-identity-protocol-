//! Buffered probe history remains signed historical evidence. Collector
//! startup must not turn a delayed batch into coverage of its interruption.
use aip_crypto::generate_ed25519_keypair;
use aip_observe::*;

#[test]
fn buffered_history_cannot_backfill_a_new_collector_epoch() {
    let key = generate_ed25519_keypair();
    let mut signer =
        CollectorSigner::new("buffered-collector", 1, &key.private_key, &key.public_key).unwrap();
    let anchors = ObserverTrustAnchors::new().trust("buffered-collector", 1, &key.public_key);
    let mut probe = ProcfsProbe::new("buffered-probe");
    probe.declare_source(SourceMechanism::ProcConnector);
    signer.begin_live_coverage_epoch(500);
    for (id, from, to) in [(1, 100, 200), (2, 200, 400)] {
        let original = probe.batch([id; 16], from, to, vec![]);
        let signed = signer.attest_at(original.clone(), 1_000).unwrap();
        assert_eq!(
            signed.batch, original,
            "replay never rewrites the original batch"
        );
        assert_eq!(
            signed.attested_at_ms, 1_000,
            "receipt time remains separately signed"
        );
        verify_attested_batch(&signed, &anchors).unwrap();
        let health = signer.health(1_001).unwrap();
        assert_eq!(health.health.attested_coverage, None);
        assert_eq!(health.health.covered_by, Vec::<SourceMechanism>::new());
        assert_eq!(health.health.state, ObserverState::Recovering);
    }
    let overlap = probe.batch([3; 16], 400, 600, vec![]);
    let signed = signer.attest_at(overlap.clone(), 1_100).unwrap();
    assert_eq!(signed.batch, overlap);
    let health = signer.health(1_101).unwrap();
    assert_eq!(
        health.health.attested_coverage,
        Some(CoverageWindow {
            from_ms: 500,
            to_ms: 600
        })
    );
    assert_eq!(health.health.state, ObserverState::Active);
    // Receipt now is 1100, but observation coverage still ends at the actual
    // original claimed 600. A verifier cannot treat the backlog as fresh.
    assert!(health.health.attested_coverage.unwrap().to_ms < signed.attested_at_ms);
}

#[test]
fn a_later_collector_floor_never_rewinds_or_rewrites_the_evidence_chain() {
    let key = generate_ed25519_keypair();
    let mut signer =
        CollectorSigner::new("buffered-collector", 1, &key.private_key, &key.public_key).unwrap();
    let mut probe = ProcfsProbe::new("buffered-probe");
    probe.declare_source(SourceMechanism::ProcConnector);
    signer.begin_live_coverage_epoch(100);
    signer
        .attest_at(probe.batch([1; 16], 100, 200, vec![]), 210)
        .unwrap();
    signer
        .attest_at(probe.batch([2; 16], 200, 300, vec![]), 310)
        .unwrap();
    let old = signer.snapshot();
    signer.begin_live_coverage_epoch(700);
    signer.begin_live_coverage_epoch(400); // a caller cannot lower the floor
    assert_eq!(signer.snapshot(), old);
    signer
        .attest_at(probe.batch([3; 16], 600, 650, vec![]), 800)
        .unwrap();
    assert_eq!(signer.health(801).unwrap().health.attested_coverage, None);
    let last = signer
        .attest_at(probe.batch([4; 16], 650, 750, vec![]), 900)
        .unwrap();
    assert_eq!(last.sequence, old.sequence.unwrap() + 2);
    assert_eq!(
        signer.health(901).unwrap().health.attested_coverage,
        Some(CoverageWindow {
            from_ms: 700,
            to_ms: 750
        })
    );
}
