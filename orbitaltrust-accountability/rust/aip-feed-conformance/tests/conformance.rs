//! The join, checked end to end: kernel evidence → effect log → findings.
//!
//! Everything else about this feed is a claim about a JSON shape. These tests
//! are the only place the claim is settled by the consumer itself: the feed's
//! bytes are written to disk, `ot-sentinel`'s own tailer reads them, and its
//! own detector renders the verdict.
//!
//! Four properties, in the order they matter:
//!
//!   1. Every line the feed writes parses — **zero malformed** — against the
//!      real Phase-1 archive, not a fixture. A schema that drifts fails here.
//!   2. An unapproved destination observed by the kernel becomes a finding
//!      that names it and cites the feed's own record id.
//!   3. An approved destination produces **no** finding. Without this, a
//!      detector that fired on everything would pass test 2.
//!   4. The same for an unapproved process spawn.
//!
//! The evidence is never trusted on the way in: each test verifies the archive
//! under the observer's anchor before rendering anything, which is the gate the
//! binary applies in production.

use aip_crypto::{generate_ed25519_keypair, sha256};
use aip_observe::*;
use aip_observe_verify::verify::{parse_jsonl, verify_archives, Parsed};
use aip_sentinel_feed::feed;
use aip_types::ProcessInstance;
use ot_sentinel::sensors::JsonlEffectLog;
use ot_sentinel::{EffectPolicy, FindingKind, Patrol, ResponsePolicy, Sensor};

const OBSERVER_ID: &str = "collector-cf";
const PROBE_ID: &str = "probe-cf";
const SENTINEL: &str = "did:syntriass:sentinel:CF";
const SENSOR: &str = "aip-kernel-observer";
const NOW: &str = "2023-11-14T22:20:00.000Z";
const ANCHOR_BOOT_NS: u64 = 200_000_000_000;
const ANCHOR_REALTIME_MS: u64 = 1_700_000_000_000;
const CLK_TCK: u32 = 100;
const TICK_NS: u64 = 1_000_000_000 / CLK_TCK as u64;
const FORK_NS: u64 = ANCHOR_BOOT_NS + 1_000_000_000;
const PARENT_PID: u32 = 8_100_001;
const CHILD_PID: u32 = 8_100_002;
const SK: u64 = 0x0c0f_fee0;

/// A scratch file path unique to one test, cleaned up by the caller.
fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("aip-feed-conformance-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

fn parent() -> ObservedProcess {
    ObservedProcess {
        process: ProcessInstance {
            pid: PARENT_PID,
            pid_start_time_ticks: 1_000_000,
            boot_id: [0x5e; 16],
        },
        exe_content_sha256: sha256(b"orchestrator binary"),
        exe_path: "/opt/agent/bin/orchestrator".into(),
        container: None,
    }
}

fn child(exe: &[u8], path: &str) -> ObservedProcess {
    ObservedProcess {
        process: ProcessInstance {
            pid: CHILD_PID,
            pid_start_time_ticks: FORK_NS / TICK_NS,
            boot_id: [0x5e; 16],
        },
        exe_content_sha256: sha256(exe),
        exe_path: path.into(),
        container: None,
    }
}

fn event(
    seq: u64,
    ts_ns: u64,
    mechanism: SourceMechanism,
    kind: KernelLifecycleKind,
    bound: Option<ObservedProcess>,
) -> KernelLifecycleEvent {
    KernelLifecycleEvent {
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: PROBE_ID.into(),
        mechanism,
        kind,
        cpu: 0,
        kernel_timestamp_ns: ts_ns,
        probe_seq: seq,
        bound,
        // Deliberately unattributed: the reconciler then reads the subject as
        // anonymous, which is the honest reading of kernel evidence carrying
        // no identity claim, and is also its strongest ghost signal.
        attribution: AgentAttribution::NotEstablished,
        claimed_decision_id: None,
    }
}

fn endpoint(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketEndpoint {
    let mut addr = [0u8; 16];
    addr[..4].copy_from_slice(&[a, b, c, d]);
    SocketEndpoint {
        addr,
        is_v6: false,
        port,
    }
}

/// A fork/exec pair for `path`, plus an established connection to `remote`.
fn kernel_events(path: &str, remote: SocketEndpoint) -> Vec<KernelLifecycleEvent> {
    let sock = |seq, ts, old, new| {
        event(
            seq,
            ts,
            SourceMechanism::SockStateTracepoint,
            KernelLifecycleKind::SocketState {
                protocol: SocketProtocol::Tcp,
                local: endpoint(10, 0, 0, 2, 40_000),
                remote,
                old_state: old,
                new_state: new,
                sk: SK,
                current_pid: PARENT_PID,
            },
            Some(parent()),
        )
    };
    vec![
        event(
            1,
            FORK_NS,
            SourceMechanism::SchedTracepoint,
            KernelLifecycleKind::ProcessSpawn {
                parent_pid: PARENT_PID,
                child_pid: CHILD_PID,
                parent_comm: "orch".into(),
                child_comm: "orch".into(),
            },
            Some(parent()),
        ),
        event(
            2,
            FORK_NS + 3_000_000,
            SourceMechanism::SchedTracepoint,
            KernelLifecycleKind::ProcessExec {
                pid: CHILD_PID,
                old_pid: CHILD_PID,
                filename: path.into(),
            },
            Some(child(b"child image", path)),
        ),
        sock(
            3,
            FORK_NS + 4_000_000,
            tcp_state::CLOSE,
            tcp_state::SYN_SENT,
        ),
        sock(
            4,
            FORK_NS + 5_000_000,
            tcp_state::SYN_SENT,
            tcp_state::ESTABLISHED,
        ),
        event(
            5,
            FORK_NS + 6_000_000,
            SourceMechanism::SockSendTracepoint,
            KernelLifecycleKind::SocketSend {
                protocol: SocketProtocol::Tcp,
                sk: SK,
                bytes: 81_920,
                flags: 0,
                current_pid: PARENT_PID,
            },
            Some(parent()),
        ),
    ]
}

/// Sign a batch and hand back the archive line with the key that verifies it.
fn signed_archive(events: Vec<KernelLifecycleEvent>) -> (String, Vec<u8>) {
    let kp = generate_ed25519_keypair();
    let mut signer = CollectorSigner::new(OBSERVER_ID, 1, &kp.private_key, &kp.public_key).unwrap();
    signer.register_probe(PROBE_ID, &SourceMechanism::ALL);
    let last = events.len() as u64;
    let attested = signer
        .attest_at(
            ObservationBatch {
                version: OBSERVE_PROTOCOL_VERSION,
                probe_id: PROBE_ID.into(),
                batch_id: [9; 16],
                probe_run_id: [0xcf; 16],
                probe_seq_first: 1,
                probe_seq_last: last.max(1),
                dropped_events: Some(0),
                active_mechanisms: SourceMechanism::canonical_set(vec![
                    SourceMechanism::PidFdAnchored,
                    SourceMechanism::SchedTracepoint,
                    SourceMechanism::SockStateTracepoint,
                    SourceMechanism::SockSendTracepoint,
                ]),
                mechanism_integrity: Vec::new(),
                claimed_from_ms: ANCHOR_REALTIME_MS,
                claimed_to_ms: ANCHOR_REALTIME_MS + 2_000,
                observations: vec![],
                kernel_events: events,
                clock_anchor: Some(BootClockAnchor {
                    realtime_ms: ANCHOR_REALTIME_MS,
                    boottime_ns: ANCHOR_BOOT_NS,
                    monotonic_ns: ANCHOR_BOOT_NS,
                    clk_tck: CLK_TCK,
                }),
            },
            ANCHOR_REALTIME_MS + 2_500,
        )
        .unwrap();
    (
        format!("{}\n", serde_json::to_string(&attested).unwrap()),
        kp.public_key.to_vec(),
    )
}

/// Verify an archive under its anchor, then render the feed. Panics if the
/// archive does not verify: in production this is the binary's exit-1 path,
/// and no test here is allowed to skip it.
fn verified_feed(archive: &str, observer_id: &str, public_key: &[u8]) -> String {
    let parsed: Vec<Parsed<AttestedBatch>> = parse_jsonl(archive);
    let batches: Vec<AttestedBatch> = parsed
        .iter()
        .filter_map(|p| match p {
            Parsed::Ok(l) => Some(l.record.clone()),
            Parsed::Failed { .. } => None,
        })
        .collect();
    let report = verify_archives(observer_id, 1, public_key, Some(parsed), None);
    assert!(
        report.ok(),
        "the archive must verify before anything is rendered: {:?}",
        report.findings
    );
    feed(&batches).to_jsonl(observer_id)
}

/// Write a feed to disk and read it back through the consumer's own tailer.
fn observe(path: &std::path::Path, jsonl: &str) -> ot_sentinel::sensors::TailReport {
    std::fs::write(path, jsonl).unwrap();
    JsonlEffectLog::new(path, SENSOR).poll().unwrap()
}

fn patrol_with(policy: EffectPolicy) -> Patrol {
    Patrol::new(SENTINEL)
        .with_policy(ResponsePolicy::autonomous())
        // Vouched for by the operator: a kernel observer whose evidence is
        // collector-signed off-host is exactly what a trusted sensor means
        // here, and only a trusted sensor's observations can carry weight.
        .with_sensor(Sensor::new(SENSOR).trusted())
        .with_effect_policy(policy)
}

// ── 1. The schema claim, settled against real evidence ────────────────────

#[test]
fn cf01_every_line_of_the_real_phase1_feed_parses_with_none_malformed() {
    // The load-bearing test. If the consumer's schema moves, or the feed
    // starts emitting a field it does not understand, this fails — instead of
    // the feed silently producing a log that reconciles against nothing.
    let root = env!("CARGO_MANIFEST_DIR");
    let base = format!("{root}/../../../integrations/agents/results/sealed");
    let archive = std::fs::read_to_string(format!("{base}/attested.archive.jsonl"))
        .expect("the committed Phase-1 attested archive must be present");
    let pubkey = hex_decode(
        std::fs::read_to_string(format!("{base}/observer.pub"))
            .expect("the committed observer public key must be present")
            .trim(),
    );

    let jsonl = verified_feed(&archive, "collector.phase1", &pubkey);
    let lines = jsonl.lines().count();
    assert!(lines > 0, "the real agent run produced observable effects");

    let path = scratch("phase1-effects.jsonl");
    let report = observe(&path, &jsonl);

    assert_eq!(
        report.malformed, 0,
        "the consumer could not parse {} of {lines} lines the feed wrote",
        report.malformed
    );
    assert_eq!(
        report.observations.len(),
        lines,
        "every line must become exactly one observation"
    );
    // And they are the effect kinds the detector acts on, not a third thing
    // that parses but means nothing.
    for observation in &report.observations {
        assert!(
            matches!(
                observation.effect,
                ot_sentinel::Effect::ProcessSpawn { .. }
                    | ot_sentinel::Effect::NetworkEgress { .. }
            ),
            "unexpected effect: {:?}",
            observation.effect
        );
    }
    let _ = std::fs::remove_file(&path);
}

// ── 2. An unapproved destination becomes a finding ────────────────────────

#[test]
fn cf02_an_unapproved_destination_seen_by_the_kernel_becomes_a_finding() {
    let (archive, pubkey) = signed_archive(kernel_events(
        "/usr/bin/otctl",
        endpoint(203, 0, 113, 9, 443),
    ));
    let jsonl = verified_feed(&archive, OBSERVER_ID, &pubkey);
    let path = scratch("unapproved-egress.jsonl");
    let report = observe(&path, &jsonl);
    assert_eq!(report.malformed, 0);

    let policy = EffectPolicy::governing_egress()
        .allow_destination("10.0.0.7")
        .allow_command("/usr/bin/otctl");
    let found = patrol_with(policy).patrol(&[], &[], &report.observations, NOW);

    let egress: Vec<_> = found
        .findings
        .iter()
        .filter(|f| f.kind == FindingKind::UnauthorizedEgress)
        .collect();
    assert_eq!(
        egress.len(),
        1,
        "expected exactly the unapproved destination: {:?}",
        found.findings
    );
    assert!(
        egress[0].summary.contains("203.0.113.9"),
        "the finding must name the destination: {}",
        egress[0].summary
    );
    // The citation is the feed's own record id, so an auditor reading the
    // finding can go straight to the event in the signed archive.
    assert!(
        egress[0]
            .evidence
            .iter()
            .any(|e| e.starts_with("observation:aip-eg-")),
        "the finding must cite the feed's record id: {:?}",
        egress[0].evidence
    );
    // The byte count survived the round trip, from the kernel's send to the
    // finding's summary.
    assert!(
        egress[0].summary.contains("81920"),
        "the measured volume is lost: {}",
        egress[0].summary
    );
    let _ = std::fs::remove_file(&path);
}

// ── 3. The soundness control: not always red ──────────────────────────────

#[test]
fn cf03_an_approved_destination_produces_no_egress_finding() {
    // Without this, a detector that fired on every record would pass cf02 and
    // the join would look like it worked while meaning nothing.
    let (archive, pubkey) =
        signed_archive(kernel_events("/usr/bin/otctl", endpoint(10, 0, 0, 7, 443)));
    let jsonl = verified_feed(&archive, OBSERVER_ID, &pubkey);
    let path = scratch("approved-egress.jsonl");
    let report = observe(&path, &jsonl);
    assert_eq!(report.malformed, 0);
    assert_eq!(report.observations.len(), 2, "one spawn and one connection");

    let policy = EffectPolicy::governing_egress()
        .allow_destination("10.0.0.7")
        .allow_command("/usr/bin/otctl");
    let found = patrol_with(policy).patrol(&[], &[], &report.observations, NOW);

    assert!(
        !found
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::UnauthorizedEgress),
        "an approved destination was flagged: {:?}",
        found.findings
    );
    assert!(
        !found
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::UnauthorizedProcessSpawn),
        "an approved command was flagged: {:?}",
        found.findings
    );
    let _ = std::fs::remove_file(&path);
}

// ── 4. An unapproved image becomes a finding ──────────────────────────────

#[test]
fn cf04_an_unapproved_process_image_becomes_a_finding() {
    let (archive, pubkey) = signed_archive(kernel_events("/bin/sh", endpoint(10, 0, 0, 7, 443)));
    let jsonl = verified_feed(&archive, OBSERVER_ID, &pubkey);
    let path = scratch("unapproved-spawn.jsonl");
    let report = observe(&path, &jsonl);
    assert_eq!(report.malformed, 0);

    let policy = EffectPolicy::governing_egress()
        .allow_destination("10.0.0.7")
        .allow_command("/usr/bin/otctl");
    let found = patrol_with(policy).patrol(&[], &[], &report.observations, NOW);

    let spawns: Vec<_> = found
        .findings
        .iter()
        .filter(|f| f.kind == FindingKind::UnauthorizedProcessSpawn)
        .collect();
    assert_eq!(
        spawns.len(),
        1,
        "the unsanctioned image was not flagged: {:?}",
        found.findings
    );
    assert!(
        spawns[0].summary.contains("/bin/sh"),
        "the finding must name the image: {}",
        spawns[0].summary
    );
    assert!(
        spawns[0]
            .evidence
            .iter()
            .any(|e| e.starts_with("observation:aip-sp-")),
        "the finding must cite the feed's record id: {:?}",
        spawns[0].evidence
    );
    let _ = std::fs::remove_file(&path);
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex key must be even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}
