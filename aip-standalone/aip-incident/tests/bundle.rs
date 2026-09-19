//! R14 — the incident bundle, over real attested batches.
//!
//! The property under test is the one a six-hour deadline attacks: a bundle
//! must state the coverage it does not have, and must not be editable into
//! looking complete afterwards.

use aip_crypto::generate_ed25519_keypair;
use aip_incident::{
    export, summary_markdown, verify_bundle, verify_coverage, BundleError, Document, DocumentKind,
    Exporter, ExporterAnchors, IncidentBundle, INCIDENT_BUNDLE_VERSION,
};
use aip_observe::{AttestedBatch, CollectorSigner, ObserverAttestor, ProcfsProbe, SourceMechanism};
use aip_types::CoverageWindow;

const AGENT: &str = "aip1LoanAgentXYZ";
const OBSERVER: &str = "collector-t";
const PROBE: &str = "probe-t";
const T0: u64 = 1_700_000_000_000;

struct Collector {
    signer: CollectorSigner,
}

fn collector() -> Collector {
    let kp = generate_ed25519_keypair();
    let mut signer = CollectorSigner::new(OBSERVER, 1, &kp.private_key, &kp.public_key).unwrap();
    signer.register_probe(PROBE, &SourceMechanism::ALL);
    Collector { signer }
}

/// A real attested batch claiming `[from, to]`, with no observations: the
/// coverage summary is about the intervals batches claim, not about what
/// they contain.
fn batch(c: &mut Collector, id: u8, from: u64, to: u64) -> AttestedBatch {
    let mut probe = ProcfsProbe::new(PROBE);
    let b = probe.batch([id; 16], from, to, vec![]);
    c.signer.attest_at(b, to + 1_000).unwrap()
}

fn exporter() -> (Exporter, ExporterAnchors) {
    let kp = generate_ed25519_keypair();
    (
        Exporter::new("incident-desk-1", 2, &kp.private_key).unwrap(),
        ExporterAnchors::new().trust("incident-desk-1", 2, &kp.public_key),
    )
}

fn window(from: u64, to: u64) -> CoverageWindow {
    CoverageWindow {
        from_ms: from,
        to_ms: to,
    }
}

/// Export with the given batches enclosed as documents.
fn bundle_over(batches: &[&AttestedBatch], w: CoverageWindow) -> (IncidentBundle, ExporterAnchors) {
    let (exp, anchors) = exporter();
    let jsons: Vec<String> = batches
        .iter()
        .map(|b| serde_json::to_string(b).unwrap())
        .collect();
    let docs: Vec<Document<'_>> = jsons
        .iter()
        .enumerate()
        .map(|(i, j)| Document {
            name: format!("batches/{i}.json"),
            kind: DocumentKind::AttestedBatch,
            json: j,
        })
        .collect();
    let b = export(&exp, AGENT, w, [0x1B; 16], T0 + 99_000, &docs, batches).unwrap();
    (b, anchors)
}

// ─── Coverage is computed, not claimed ─────────────────────────────────────

/// **The acceptance criterion.** A hole between two batches is stated, with
/// its exact bounds and its size.
#[test]
fn a_hole_between_batches_is_stated_with_its_bounds() {
    let mut c = collector();
    // Covered: [0, 10_000] and [30_001, 60_000]. Missing: [10_001, 30_000].
    let b1 = batch(&mut c, 1, T0, T0 + 10_000);
    let b2 = batch(&mut c, 2, T0 + 30_001, T0 + 60_000);
    let (bundle, _) = bundle_over(&[&b1, &b2], window(T0, T0 + 60_000));

    let cov = &bundle.manifest.coverage;
    assert!(!cov.is_complete());
    assert_eq!(cov.gaps, vec![(T0 + 10_001, T0 + 30_000)]);
    assert_eq!(cov.uncovered_ms, 20_000);
    assert_eq!(
        cov.covered,
        vec![(T0, T0 + 10_000), (T0 + 30_001, T0 + 60_000)]
    );
    assert_eq!(cov.batches, 2);

    // And the person writing the report is told first.
    let md = summary_markdown(&bundle);
    assert!(md.contains("20000 ms of the window is not covered"), "{md}");
    assert!(md.contains("not supported by this bundle"), "{md}");
}

/// Missing time at the start and the end of the window counts too. A bundle
/// that only noticed interior holes would present a late-starting observer
/// as having been there all along.
#[test]
fn missing_time_at_the_edges_of_the_window_is_a_gap() {
    let mut c = collector();
    let b = batch(&mut c, 1, T0 + 5_000, T0 + 50_000);
    let (bundle, _) = bundle_over(&[&b], window(T0, T0 + 60_000));
    let cov = &bundle.manifest.coverage;
    assert_eq!(cov.gaps, vec![(T0, T0 + 4_999), (T0 + 50_001, T0 + 60_000)]);
    assert_eq!(cov.uncovered_ms, 5_000 + 10_000);
}

/// Adjacent and overlapping batches merge, so a continuous stream is not
/// reported as fragmented.
#[test]
fn adjacent_and_overlapping_batches_merge_into_one_interval() {
    let mut c = collector();
    let b1 = batch(&mut c, 1, T0, T0 + 10_000);
    // Starts exactly one millisecond after the first ends.
    let b2 = batch(&mut c, 2, T0 + 10_001, T0 + 20_000);
    // Overlaps the second.
    let b3 = batch(&mut c, 3, T0 + 15_000, T0 + 30_000);
    let (bundle, _) = bundle_over(&[&b1, &b2, &b3], window(T0, T0 + 30_000));
    let cov = &bundle.manifest.coverage;
    assert_eq!(cov.covered, vec![(T0, T0 + 30_000)]);
    assert!(cov.is_complete());
    assert_eq!(cov.uncovered_ms, 0);
}

/// A batch claiming more than the window does not enlarge the window.
#[test]
fn a_batch_wider_than_the_window_is_clipped_to_it() {
    let mut c = collector();
    let b = batch(&mut c, 1, T0 - 50_000, T0 + 500_000);
    let (bundle, _) = bundle_over(&[&b], window(T0, T0 + 60_000));
    assert_eq!(
        bundle.manifest.coverage.covered,
        vec![(T0, T0 + 60_000)],
        "coverage is reported inside the window that was asked for"
    );
}

/// No batches at all: the whole window is a gap, and the bundle says so
/// rather than reporting an empty gap list.
#[test]
fn a_bundle_with_no_batches_reports_the_whole_window_as_missing() {
    let (exp, _) = exporter();
    let w = window(T0, T0 + 60_000);
    let b = export(&exp, AGENT, w, [0x1B; 16], T0, &[], &[]).unwrap();
    let cov = &b.manifest.coverage;
    assert_eq!(cov.gaps, vec![(T0, T0 + 60_000)]);
    assert_eq!(cov.uncovered_ms, 60_001);
    assert!(!cov.is_complete());
}

// ─── The bundle under attack ───────────────────────────────────────────────

#[test]
fn an_honest_bundle_verifies_and_its_coverage_recomputes() {
    let mut c = collector();
    let b1 = batch(&mut c, 1, T0, T0 + 30_000);
    let (bundle, anchors) = bundle_over(&[&b1], window(T0, T0 + 60_000));
    assert_eq!(verify_bundle(&bundle, &anchors), Ok(()));
    assert_eq!(verify_coverage(&bundle, &[&b1]), Ok(()));
}

/// **The attack the gaps field invites.** Editing the stated gaps away is
/// refused, because coverage is inside the signature.
#[test]
fn editing_the_stated_gaps_after_export_is_detected() {
    let mut c = collector();
    let b1 = batch(&mut c, 1, T0, T0 + 10_000);
    let (mut bundle, anchors) = bundle_over(&[&b1], window(T0, T0 + 60_000));
    assert!(!bundle.manifest.coverage.gaps.is_empty());

    bundle.manifest.coverage.gaps.clear();
    bundle.manifest.coverage.uncovered_ms = 0;
    assert_eq!(
        verify_bundle(&bundle, &anchors),
        Err(BundleError::PayloadHashMismatch)
    );
}

/// A bundle re-signed with the gaps removed passes the signature check and
/// fails the recomputation: two independent defences, because an exporter
/// key could be held by whoever wants the bundle to look complete.
#[test]
fn a_resigned_bundle_with_the_gaps_removed_fails_recomputation() {
    let mut c = collector();
    let b1 = batch(&mut c, 1, T0, T0 + 10_000);
    let kp = generate_ed25519_keypair();
    let exp = Exporter::new("incident-desk-1", 2, &kp.private_key).unwrap();
    let anchors = ExporterAnchors::new().trust("incident-desk-1", 2, &kp.public_key);

    let json = serde_json::to_string(&b1).unwrap();
    let docs = vec![Document {
        name: "batches/0.json".into(),
        kind: DocumentKind::AttestedBatch,
        json: &json,
    }];
    // Export against a window the batch *does* cover, then relabel the
    // manifest's requested window to a wider one and re-sign.
    let mut bundle = export(
        &exp,
        AGENT,
        window(T0, T0 + 10_000),
        [0x1B; 16],
        T0,
        &docs,
        &[&b1],
    )
    .unwrap();
    assert!(bundle.manifest.coverage.is_complete());
    bundle.manifest.coverage.requested_to_ms = T0 + 60_000;
    bundle.attestation = aip_crypto::sign_ed25519(
        &kp.private_key,
        "incident-desk-1",
        &bundle.manifest.signing_preimage(),
    )
    .unwrap();

    // The signature is genuine.
    assert_eq!(verify_bundle(&bundle, &anchors), Ok(()));
    // The claim is not: the batch does not cover the window now stated.
    assert_eq!(
        verify_coverage(&bundle, &[&b1]),
        Err(BundleError::CoverageMismatch)
    );
}

#[test]
fn a_document_removed_or_altered_after_export_is_detected() {
    let mut c = collector();
    let b1 = batch(&mut c, 1, T0, T0 + 30_000);
    let (bundle, anchors) = bundle_over(&[&b1], window(T0, T0 + 30_000));

    let mut without = bundle.clone();
    without.files.remove("batches/0.json");
    assert_eq!(
        verify_bundle(&without, &anchors),
        Err(BundleError::FileMissing("batches/0.json".into()))
    );

    let mut altered = bundle.clone();
    altered
        .files
        .insert("batches/0.json".into(), "{}".to_string());
    assert_eq!(
        verify_bundle(&altered, &anchors),
        Err(BundleError::FileDigestMismatch("batches/0.json".into()))
    );
}

/// A document added to the archive that the manifest never vouched for. A
/// reader listing the archive would see it and assume it was part of the
/// evidence.
#[test]
fn an_undeclared_document_added_to_the_bundle_is_refused() {
    let mut c = collector();
    let b1 = batch(&mut c, 1, T0, T0 + 30_000);
    let (mut bundle, anchors) = bundle_over(&[&b1], window(T0, T0 + 30_000));
    bundle
        .files
        .insert("batches/planted.json".into(), "{\"x\":1}".into());
    assert_eq!(
        verify_bundle(&bundle, &anchors),
        Err(BundleError::FileUndeclared("batches/planted.json".into()))
    );
}

#[test]
fn an_unanchored_or_impostor_exporter_establishes_nothing() {
    let mut c = collector();
    let b1 = batch(&mut c, 1, T0, T0 + 30_000);
    let (bundle, _) = bundle_over(&[&b1], window(T0, T0 + 30_000));

    assert!(matches!(
        verify_bundle(&bundle, &ExporterAnchors::new()),
        Err(BundleError::ExporterNotAnchored { .. })
    ));

    let impostor = generate_ed25519_keypair();
    assert_eq!(
        verify_bundle(
            &bundle,
            &ExporterAnchors::new().trust("incident-desk-1", 2, &impostor.public_key)
        ),
        Err(BundleError::SignatureInvalid)
    );

    // A key version the verifier was not provisioned with.
    let (_, real) = exporter();
    let _ = real;
    let mut wrong_version = bundle.clone();
    wrong_version.manifest.key_version = 3;
    assert!(matches!(
        verify_bundle(&wrong_version, &ExporterAnchors::new()),
        Err(BundleError::ExporterNotAnchored { key_version: 3, .. })
    ));
}

#[test]
fn a_version_this_build_does_not_implement_is_refused() {
    let mut c = collector();
    let b1 = batch(&mut c, 1, T0, T0 + 30_000);
    let (mut bundle, anchors) = bundle_over(&[&b1], window(T0, T0 + 30_000));
    bundle.manifest.version = INCIDENT_BUNDLE_VERSION + 1;
    assert_eq!(
        verify_bundle(&bundle, &anchors),
        Err(BundleError::UnsupportedVersion(INCIDENT_BUNDLE_VERSION + 1))
    );
}

#[test]
fn the_bundle_round_trips_through_json_and_still_verifies() {
    let mut c = collector();
    let b1 = batch(&mut c, 1, T0, T0 + 30_000);
    let (bundle, anchors) = bundle_over(&[&b1], window(T0, T0 + 30_000));
    let json = serde_json::to_string(&bundle).unwrap();
    let back: IncidentBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(back, bundle);
    assert_eq!(verify_bundle(&back, &anchors), Ok(()));
}
