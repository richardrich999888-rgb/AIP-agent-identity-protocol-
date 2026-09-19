//! R14 — the `aip-incident` command line, exercised against the compiled
//! binary rather than the library.
//!
//! An incident bundle is assembled by an operator under time pressure, from
//! a shell, at 03:00. What matters is not that the library is correct but
//! that the command an operator actually types produces a bundle that
//! verifies, reports the holes in it, and refuses when it should.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use aip_crypto::generate_ed25519_keypair;
use aip_incident::IncidentBundle;
use aip_observe::{AttestedBatch, CollectorSigner, ObserverAttestor, ProcfsProbe, SourceMechanism};

const AGENT: &str = "aip1LoanAgentXYZ";
const OBSERVER: &str = "collector-t";
const PROBE: &str = "probe-t";
const T0: u64 = 1_700_000_000_000;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_aip-incident")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A scratch directory unique to one test, removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("aip-incident-cli-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// Write `json` to `name` and return the path as a string.
    fn write(&self, name: &str, json: &str) -> String {
        let p = self.path(name);
        std::fs::write(&p, json).unwrap();
        p.to_string_lossy().into_owned()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A real attested batch claiming `[from, to]`, signed by a real collector
/// key. No observations: coverage is about the intervals batches claim.
fn batch_json(id: u8, from: u64, to: u64) -> String {
    let kp = generate_ed25519_keypair();
    let mut signer = CollectorSigner::new(OBSERVER, 1, &kp.private_key, &kp.public_key).unwrap();
    signer.register_probe(PROBE, &SourceMechanism::ALL);
    let mut probe = ProcfsProbe::new(PROBE);
    let b: AttestedBatch = signer
        .attest_at(probe.batch([id; 16], from, to, vec![]), to + 1_000)
        .unwrap();
    serde_json::to_string(&b).unwrap()
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("run aip-incident")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Export a bundle over `batches`, returning (bundle path, public key hex).
fn export_bundle(s: &Scratch, batches: &[(u8, u64, u64)], from: u64, to: u64) -> (String, String) {
    let kp = generate_ed25519_keypair();
    let out = s.path("bundle.json").to_string_lossy().into_owned();
    let from_s = from.to_string();
    let to_s = to.to_string();
    let key = hex(&kp.private_key);
    let mut args: Vec<String> = vec![
        "export".into(),
        "--agent".into(),
        AGENT.into(),
        "--from".into(),
        from_s,
        "--to".into(),
        to_s,
        "--exporter".into(),
        "incident-desk-1:2".into(),
        "--key".into(),
        key,
        "--out".into(),
        out.clone(),
    ];
    let mut paths = Vec::new();
    for (i, (id, f, t)) in batches.iter().enumerate() {
        paths.push(s.write(&format!("b{i}.json"), &batch_json(*id, *f, *t)));
    }
    for p in &paths {
        args.push("--batch".into());
        args.push(p.clone());
    }
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let o = run(&argv);
    assert!(o.status.success(), "export failed: {}", stderr(&o));
    (out, hex(&kp.public_key))
}

/// The ordinary path: a window fully claimed by one batch exports, verifies
/// under the exporter's key, and reports complete coverage.
#[test]
fn a_covered_window_exports_verifies_and_reports_complete() {
    let s = Scratch::new("covered");
    let (path, pubkey) = export_bundle(&s, &[(1, T0, T0 + 60_000)], T0, T0 + 60_000);

    let o = run(&[
        "verify",
        &path,
        "--trust",
        &format!("incident-desk-1:2={pubkey}"),
    ]);
    assert!(o.status.success(), "verify failed: {}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("signature: OK"), "{out}");
    assert!(out.contains("recomputed and matches"), "{out}");
    assert!(
        !out.contains("uncovered"),
        "a complete window must not report uncovered time: {out}"
    );
}

/// **The load-bearing test.** A hole between two batches is reported on
/// stdout at export time with its bounds, not left for a reader to notice.
#[test]
fn a_hole_between_batches_is_reported_with_its_bounds() {
    let s = Scratch::new("hole");
    let (path, pubkey) = export_bundle(
        &s,
        &[(1, T0, T0 + 10_000), (2, T0 + 50_000, T0 + 60_000)],
        T0,
        T0 + 60_000,
    );

    let o = run(&[
        "verify",
        &path,
        "--trust",
        &format!("incident-desk-1:2={pubkey}"),
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    let out = stdout(&o);
    // Intervals are closed at both ends, the convention `CoverageWindow`
    // documents and `contains` implements. The instant T0+10_000 is claimed
    // by the first batch and T0+50_000 by the second, so exactly 39_999
    // milliseconds are claimed by nobody.
    assert!(
        out.contains("39999 ms"),
        "the gap must be quantified: {out}"
    );

    // And the bundle itself carries the bounds, so the number is checkable.
    let b: IncidentBundle = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(b.manifest.coverage.gaps, vec![(T0 + 10_001, T0 + 49_999)]);
    assert_eq!(b.manifest.coverage.uncovered_ms, 39_999);
}

/// An export with no batches is not an error — it is an answer — but the
/// operator is told, and the bundle states the whole window as a gap.
#[test]
fn an_export_with_no_batches_states_the_whole_window_as_a_gap() {
    let s = Scratch::new("empty");
    let (path, _pubkey) = export_bundle(&s, &[], T0, T0 + 60_000);
    let b: IncidentBundle = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(b.manifest.coverage.gaps, vec![(T0, T0 + 60_000)]);
    // Inclusive of both endpoints, as everywhere else in the workspace.
    assert_eq!(b.manifest.coverage.uncovered_ms, 60_001);
}

/// The identifier is derived from the contents, so an operator can re-run
/// the export and show it produced the same artefact.
#[test]
fn the_bundle_identifier_is_reproducible_from_the_same_inputs() {
    let s = Scratch::new("determinism");
    let json = batch_json(1, T0, T0 + 60_000);
    let batch = s.write("b.json", &json);
    let kp = generate_ed25519_keypair();
    let key = hex(&kp.private_key);

    let mut ids = Vec::new();
    for name in ["one.json", "two.json"] {
        let out = s.path(name).to_string_lossy().into_owned();
        let o = run(&[
            "export",
            "--agent",
            AGENT,
            "--from",
            &T0.to_string(),
            "--to",
            &(T0 + 60_000).to_string(),
            "--exporter",
            "incident-desk-1:2",
            "--key",
            &key,
            "--batch",
            &batch,
            "--out",
            &out,
        ]);
        assert!(o.status.success(), "{}", stderr(&o));
        let b: IncidentBundle =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        ids.push((b.manifest.bundle_id, b.manifest.exported_at_ms));
    }
    // Only assert the identifier is a function of the inputs when the two
    // runs landed in the same millisecond-stamped export; otherwise the
    // instant legitimately differs and so must the identifier.
    if ids[0].1 == ids[1].1 {
        assert_eq!(ids[0].0, ids[1].0, "same inputs must yield the same id");
    } else {
        assert_ne!(
            ids[0].0, ids[1].0,
            "a different export instant must yield a different id"
        );
    }
}

/// A bundle verified under the wrong anchors fails, and the failure is a
/// non-zero exit — an operator scripting this must not read a forged bundle
/// as accepted.
#[test]
fn an_untrusted_exporter_fails_with_a_non_zero_exit() {
    let s = Scratch::new("untrusted");
    let (path, _) = export_bundle(&s, &[(1, T0, T0 + 60_000)], T0, T0 + 60_000);
    let impostor = hex(&generate_ed25519_keypair().public_key);

    let o = run(&[
        "verify",
        &path,
        "--trust",
        &format!("incident-desk-1:2={impostor}"),
    ]);
    assert!(!o.status.success(), "a forged bundle must not exit zero");
    assert!(stderr(&o).contains("did not verify"), "{}", stderr(&o));

    // And with no anchors at all: an unanchored bundle is not a valid one.
    let o = run(&["verify", &path]);
    assert!(!o.status.success());
}

/// A document edited inside the bundle after signing is detected.
#[test]
fn an_edited_document_is_detected() {
    let s = Scratch::new("edited");
    let (path, pubkey) = export_bundle(&s, &[(1, T0, T0 + 60_000)], T0, T0 + 60_000);
    let mut b: IncidentBundle =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let name = b.manifest.files[0].name.clone();
    b.files.insert(name, "{}".to_string());
    std::fs::write(&path, serde_json::to_string(&b).unwrap()).unwrap();

    let o = run(&[
        "verify",
        &path,
        "--trust",
        &format!("incident-desk-1:2={pubkey}"),
    ]);
    assert!(!o.status.success(), "an edited document must not verify");
}

/// Coverage widened after signing is caught by recomputation even though
/// the manifest signature is genuine — the second, independent defence.
#[test]
fn a_coverage_claim_that_the_evidence_does_not_support_is_rejected() {
    let s = Scratch::new("coverage");
    let (path, pubkey) = export_bundle(
        &s,
        &[(1, T0, T0 + 10_000), (2, T0 + 50_000, T0 + 60_000)],
        T0,
        T0 + 60_000,
    );
    let mut b: IncidentBundle =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    b.manifest.coverage.gaps.clear();
    b.manifest.coverage.uncovered_ms = 0;
    std::fs::write(&path, serde_json::to_string(&b).unwrap()).unwrap();

    let o = run(&[
        "verify",
        &path,
        "--trust",
        &format!("incident-desk-1:2={pubkey}"),
    ]);
    assert!(!o.status.success(), "an erased gap must not verify");
    let e = stderr(&o);
    assert!(
        e.contains("did not verify") || e.contains("does not match the evidence"),
        "{e}"
    );
}

/// The summary is what goes into the report, so it must lead with what is
/// missing rather than with what is present.
#[test]
fn the_summary_states_the_gap() {
    let s = Scratch::new("summary");
    let (path, _) = export_bundle(
        &s,
        &[(1, T0, T0 + 10_000), (2, T0 + 50_000, T0 + 60_000)],
        T0,
        T0 + 60_000,
    );
    let o = run(&["summary", &path]);
    assert!(o.status.success(), "{}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains(AGENT), "{out}");
    // The summary must carry the bounds of the hole, not just its existence.
    assert!(out.contains(&(T0 + 10_001).to_string()), "{out}");
    assert!(out.contains(&(T0 + 49_999).to_string()), "{out}");
}

/// Bad arguments fail closed, with a usage message, never with a partial
/// bundle on disk.
#[test]
fn malformed_invocations_fail_closed() {
    let s = Scratch::new("malformed");
    let out = s.path("never.json");

    // No subcommand.
    assert!(!run(&[]).status.success());

    // An inverted window.
    let key = hex(&generate_ed25519_keypair().private_key);
    let o = run(&[
        "export",
        "--agent",
        AGENT,
        "--from",
        &(T0 + 1).to_string(),
        "--to",
        &T0.to_string(),
        "--exporter",
        "incident-desk-1:2",
        "--key",
        &key,
        "--out",
        &out.to_string_lossy(),
    ]);
    assert!(!o.status.success());
    assert!(!Path::new(&out).exists(), "no bundle may be written");

    // A key that is not a key.
    let o = run(&[
        "export",
        "--agent",
        AGENT,
        "--from",
        &T0.to_string(),
        "--to",
        &(T0 + 1).to_string(),
        "--exporter",
        "incident-desk-1:2",
        "--key",
        "zz",
        "--out",
        &out.to_string_lossy(),
    ]);
    assert!(!o.status.success());
    assert!(!Path::new(&out).exists());

    // A batch file that is not an attested batch.
    let bad = s.write("bad.json", "{\"nope\":1}");
    let o = run(&[
        "export",
        "--agent",
        AGENT,
        "--from",
        &T0.to_string(),
        "--to",
        &(T0 + 1).to_string(),
        "--exporter",
        "incident-desk-1:2",
        "--key",
        &key,
        "--batch",
        &bad,
        "--out",
        &out.to_string_lossy(),
    ]);
    assert!(!o.status.success());
    assert!(
        stderr(&o).contains("not an AttestedBatch"),
        "say which file and why: {}",
        stderr(&o)
    );
    assert!(!Path::new(&out).exists());
}
