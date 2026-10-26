//! Exit gate for the effect feed: what it renders, and — the part that
//! matters — what it refuses to render.
//!
//! The feed hands kernel-derived evidence to a detector that raises critical
//! findings from it. Every false record here becomes a false accusation
//! there, so each drop rule gets a test that fails if the rule is relaxed:
//!
//!   1. A fork with no observed image is no record (nothing to name).
//!   2. An unbound exec is no record (no instance to attribute).
//!   3. An exec whose child start could not be anchored is no record.
//!   4. A `connect()` the kernel never reported completing is not egress.
//!   5. A batch with no clock anchor yields no timestamped record.
//!   6. Byte counts follow a socket's lifetime, not its reused `sk`.
//!
//! and, tying it to real evidence rather than only to fixtures:
//!
//!   7. Phase 1's genuine collector-signed LangGraph archive verifies under
//!      its published key and renders a non-empty, well-formed effect log.
//!   8. The binary refuses an archive that does not verify, and writes
//!      nothing at all when it does.

use aip_crypto::{generate_ed25519_keypair, sha256};
use aip_observe::*;
use aip_sentinel_feed::{feed, EffectDetail, EffectKind};
use aip_types::ProcessInstance;

const OBSERVER_ID: &str = "collector-sf";
const PROBE_ID: &str = "probe-sf";
const RUN: [u8; 16] = [0x5f; 16];
const PARENT_PID: u32 = 7_100_001;
const CHILD_PID: u32 = 7_100_002;
const ANCHOR_BOOT_NS: u64 = 200_000_000_000;
const CLK_TCK: u32 = 100;
const TICK_NS: u64 = 1_000_000_000 / CLK_TCK as u64;
/// Anchor wall clock. 1_700_000_000_000 ms is 2023-11-14T22:13:20.000Z.
const ANCHOR_REALTIME_MS: u64 = 1_700_000_000_000;
const FORK_NS: u64 = ANCHOR_BOOT_NS + 1_000_000_000;
const SK: u64 = 0xdead_beef;

fn signer() -> CollectorSigner {
    let kp = generate_ed25519_keypair();
    let mut s = CollectorSigner::new(OBSERVER_ID, 1, &kp.private_key, &kp.public_key).unwrap();
    s.register_probe(PROBE_ID, &SourceMechanism::ALL);
    s
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

fn child() -> ObservedProcess {
    ObservedProcess {
        process: ProcessInstance {
            pid: CHILD_PID,
            // Maps back to the fork instant through the anchor, so the
            // start-tick check passes and the pairing is start-verified.
            pid_start_time_ticks: FORK_NS / TICK_NS,
            boot_id: [0x5e; 16],
        },
        exe_content_sha256: sha256(b"worker binary"),
        exe_path: "/opt/agent/bin/worker".into(),
        container: None,
    }
}

fn claimed() -> AgentAttribution {
    AgentAttribution::Claimed {
        agent_id: "did:aip:agent:A1".into(),
        claim_source: "orchestrator".into(),
    }
}

fn event(
    seq: u64,
    ts_ns: u64,
    mechanism: SourceMechanism,
    kind: KernelLifecycleKind,
    bound: Option<ObservedProcess>,
    attribution: AgentAttribution,
) -> KernelLifecycleEvent {
    KernelLifecycleEvent {
        cgroup: aip_observe::CgroupSample::NotSampled,
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: PROBE_ID.into(),
        mechanism,
        kind,
        cpu: 0,
        kernel_timestamp_ns: ts_ns,
        probe_seq: seq,
        bound,
        attribution,
        claimed_decision_id: None,
    }
}

fn fork_event(seq: u64, ts_ns: u64, bound: Option<ObservedProcess>) -> KernelLifecycleEvent {
    event(
        seq,
        ts_ns,
        SourceMechanism::SchedTracepoint,
        KernelLifecycleKind::ProcessSpawn {
            parent_pid: PARENT_PID,
            child_pid: CHILD_PID,
            parent_comm: "orch".into(),
            child_comm: "orch".into(),
        },
        bound,
        claimed(),
    )
}

fn exec_event(seq: u64, ts_ns: u64, bound: Option<ObservedProcess>) -> KernelLifecycleEvent {
    event(
        seq,
        ts_ns,
        SourceMechanism::SchedTracepoint,
        KernelLifecycleKind::ProcessExec {
            pid: CHILD_PID,
            old_pid: CHILD_PID,
            filename: "/opt/agent/bin/worker".into(),
        },
        bound,
        claimed(),
    )
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

fn sock_event(
    seq: u64,
    ts_ns: u64,
    sk: u64,
    old_state: u8,
    new_state: u8,
    remote: SocketEndpoint,
    bound: Option<ObservedProcess>,
) -> KernelLifecycleEvent {
    event(
        seq,
        ts_ns,
        SourceMechanism::SockStateTracepoint,
        KernelLifecycleKind::SocketState {
            protocol: SocketProtocol::Tcp,
            local: endpoint(10, 0, 0, 2, 40_000),
            remote,
            old_state,
            new_state,
            sk,
            current_pid: PARENT_PID,
        },
        bound,
        claimed(),
    )
}

fn send_event(seq: u64, ts_ns: u64, sk: u64, bytes: u32) -> KernelLifecycleEvent {
    event(
        seq,
        ts_ns,
        SourceMechanism::SockSendTracepoint,
        KernelLifecycleKind::SocketSend {
            protocol: SocketProtocol::Tcp,
            sk,
            bytes,
            flags: 0,
            current_pid: PARENT_PID,
        },
        Some(parent()),
        claimed(),
    )
}

fn anchor() -> BootClockAnchor {
    BootClockAnchor {
        realtime_ms: ANCHOR_REALTIME_MS,
        boottime_ns: ANCHOR_BOOT_NS,
        monotonic_ns: ANCHOR_BOOT_NS,
        clk_tck: CLK_TCK,
    }
}

fn batch_with(
    events: Vec<KernelLifecycleEvent>,
    clock_anchor: Option<BootClockAnchor>,
) -> AttestedBatch {
    let last = events.len() as u64;
    signer()
        .attest_at(
            ObservationBatch {
                version: OBSERVE_PROTOCOL_VERSION,
                probe_id: PROBE_ID.into(),
                batch_id: [7; 16],
                probe_run_id: RUN,
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
                clock_anchor,
            },
            ANCHOR_REALTIME_MS + 2_500,
        )
        .unwrap()
}

/// A batch plus the hex public key that verifies it, for the tests that drive
/// the binary and therefore need the key the way an auditor receives it.
fn signed_batch(events: Vec<KernelLifecycleEvent>) -> (AttestedBatch, String) {
    let kp = generate_ed25519_keypair();
    let mut s = CollectorSigner::new(OBSERVER_ID, 1, &kp.private_key, &kp.public_key).unwrap();
    s.register_probe(PROBE_ID, &SourceMechanism::ALL);
    let last = events.len() as u64;
    let attested = s
        .attest_at(
            ObservationBatch {
                version: OBSERVE_PROTOCOL_VERSION,
                probe_id: PROBE_ID.into(),
                batch_id: [7; 16],
                probe_run_id: RUN,
                probe_seq_first: 1,
                probe_seq_last: last.max(1),
                dropped_events: Some(0),
                active_mechanisms: SourceMechanism::canonical_set(vec![
                    SourceMechanism::PidFdAnchored,
                    SourceMechanism::SchedTracepoint,
                ]),
                mechanism_integrity: Vec::new(),
                claimed_from_ms: ANCHOR_REALTIME_MS,
                claimed_to_ms: ANCHOR_REALTIME_MS + 2_000,
                observations: vec![],
                kernel_events: events,
                clock_anchor: Some(anchor()),
            },
            ANCHOR_REALTIME_MS + 2_500,
        )
        .unwrap();
    (attested, hex::encode(&kp.public_key))
}

fn batch(events: Vec<KernelLifecycleEvent>) -> AttestedBatch {
    batch_with(events, Some(anchor()))
}

// ── 1. A bound, start-verified fork+exec is one spawn record ──────────────

#[test]
fn sf01_an_observed_execution_becomes_one_spawn_record() {
    let b = batch(vec![
        fork_event(1, FORK_NS, Some(parent())),
        exec_event(2, FORK_NS + 3_000_000, Some(child())),
    ]);
    let produced = feed(&[b]);

    assert_eq!(produced.scope.spawns_emitted, 1);
    assert_eq!(produced.records.len(), 1);
    let r = &produced.records[0];
    assert_eq!(r.kind, EffectKind::Spawn);
    assert_eq!(
        r.agent_did.as_deref(),
        Some("did:aip:agent:A1"),
        "a claimed identity is passed through as a claim"
    );
    match &r.detail {
        EffectDetail::Spawn { path, exe_sha256 } => {
            assert_eq!(path, "/opt/agent/bin/worker");
            assert_eq!(
                *exe_sha256,
                hex::encode(sha256(b"worker binary")),
                "the record carries the measured image, not only its path"
            );
        }
        other => panic!("expected a spawn, got {other:?}"),
    }
    // The fork is 1 s after the anchor's monotonic base, the exec 3 ms later.
    assert_eq!(r.timestamp_utc, "2023-11-14T22:13:21.003Z");
}

// ── 2. Nothing is invented when the evidence is incomplete ────────────────

#[test]
fn sf02_a_fork_with_no_observed_image_names_no_command() {
    // The kernel showed a process being created and nothing showed what it
    // ran. There is no command, so there is no record — the same discipline
    // that stops the lineage engine inventing a parent.
    let produced = feed(&[batch(vec![fork_event(1, FORK_NS, Some(parent()))])]);
    assert!(produced.records.is_empty(), "{:?}", produced.records);
    assert_eq!(produced.scope.fork_without_bound_execution, 1);
    assert_eq!(
        produced.scope.dropped(),
        1,
        "the drop is counted, not silent"
    );
}

#[test]
fn sf03_an_unbound_exec_is_not_attributed_to_anything() {
    // `bound: null` is the probe saying it saw the exec and could not measure
    // it. A record here would name an image nobody measured.
    let produced = feed(&[batch(vec![
        fork_event(1, FORK_NS, Some(parent())),
        exec_event(2, FORK_NS + 3_000_000, None),
    ])]);
    assert!(produced.records.is_empty(), "{:?}", produced.records);
    assert_eq!(produced.scope.fork_without_bound_execution, 1);
}

#[test]
fn sf04_an_exec_whose_child_start_is_unanchored_is_refused() {
    // Without a clock anchor the child's start tick cannot be checked against
    // the fork, so a recycled pid could pose as the forked child.
    let produced = feed(&[batch_with(
        vec![
            fork_event(1, FORK_NS, Some(parent())),
            exec_event(2, FORK_NS + 3_000_000, Some(child())),
        ],
        None,
    )]);
    assert!(produced.records.is_empty(), "{:?}", produced.records);
    assert_eq!(produced.scope.exec_start_unverified, 1);
}

// ── 3. A connection attempt is not egress ─────────────────────────────────

#[test]
fn sf05_a_connect_that_never_completed_is_not_rendered_as_egress() {
    // The consumer judges `destination` against an allow-list at critical
    // severity. A refused connection moved nothing; rendering it would
    // manufacture a critical finding out of a failed syscall — the same
    // defect as counting failed execve attempts as observation gaps.
    let produced = feed(&[batch(vec![sock_event(
        1,
        FORK_NS,
        SK,
        tcp_state::CLOSE,
        tcp_state::SYN_SENT,
        endpoint(203, 0, 113, 9, 443),
        Some(parent()),
    )])]);
    assert!(produced.records.is_empty(), "{:?}", produced.records);
    assert_eq!(produced.scope.connect_attempt_not_established, 1);
}

#[test]
fn sf06_an_established_connection_is_one_egress_record_with_its_destination() {
    let remote = endpoint(203, 0, 113, 9, 443);
    let produced = feed(&[batch(vec![
        sock_event(
            1,
            FORK_NS,
            SK,
            tcp_state::CLOSE,
            tcp_state::SYN_SENT,
            remote,
            Some(parent()),
        ),
        sock_event(
            2,
            FORK_NS + 5_000_000,
            SK,
            tcp_state::SYN_SENT,
            tcp_state::ESTABLISHED,
            remote,
            Some(parent()),
        ),
    ])]);
    assert_eq!(produced.scope.egress_emitted, 1);
    let r = &produced.records[0];
    assert_eq!(r.kind, EffectKind::Egress);
    match &r.detail {
        EffectDetail::Egress { destination, bytes } => {
            assert_eq!(destination, "203.0.113.9:443");
            assert_eq!(
                *bytes, None,
                "no send was observed, so the volume is unmeasured — not zero"
            );
        }
        other => panic!("expected egress, got {other:?}"),
    }
    // Timestamped at establishment, not at the attempt.
    assert_eq!(r.timestamp_utc, "2023-11-14T22:13:21.005Z");
    assert_eq!(produced.scope.egress_with_measured_bytes, 0);
}

#[test]
fn sf07_observed_sends_supply_the_byte_count() {
    let remote = endpoint(203, 0, 113, 9, 443);
    let produced = feed(&[batch(vec![
        sock_event(
            1,
            FORK_NS,
            SK,
            tcp_state::CLOSE,
            tcp_state::SYN_SENT,
            remote,
            Some(parent()),
        ),
        sock_event(
            2,
            FORK_NS + 5_000_000,
            SK,
            tcp_state::SYN_SENT,
            tcp_state::ESTABLISHED,
            remote,
            Some(parent()),
        ),
        send_event(3, FORK_NS + 6_000_000, SK, 40_000),
        send_event(4, FORK_NS + 7_000_000, SK, 41_920),
    ])]);
    assert_eq!(produced.scope.egress_emitted, 1);
    assert_eq!(produced.scope.egress_with_measured_bytes, 1);
    match &produced.records[0].detail {
        EffectDetail::Egress { bytes, .. } => assert_eq!(*bytes, Some(81_920)),
        other => panic!("expected egress, got {other:?}"),
    }
}

#[test]
fn sf08_a_reused_socket_key_does_not_credit_one_connection_with_anothers_traffic() {
    // The kernel reuses `sk`. Summing by key alone would attribute the second
    // connection's bytes to the first, which is a false accusation against
    // whichever destination the first one reached.
    let first = endpoint(203, 0, 113, 9, 443);
    let second = endpoint(198, 51, 100, 4, 8443);
    let produced = feed(&[batch(vec![
        sock_event(
            1,
            FORK_NS,
            SK,
            tcp_state::CLOSE,
            tcp_state::SYN_SENT,
            first,
            Some(parent()),
        ),
        sock_event(
            2,
            FORK_NS + 1_000_000,
            SK,
            tcp_state::SYN_SENT,
            tcp_state::ESTABLISHED,
            first,
            Some(parent()),
        ),
        // Same `sk`, a new connection to a different destination.
        sock_event(
            3,
            FORK_NS + 9_000_000,
            SK,
            tcp_state::CLOSE,
            tcp_state::SYN_SENT,
            second,
            Some(parent()),
        ),
        sock_event(
            4,
            FORK_NS + 10_000_000,
            SK,
            tcp_state::SYN_SENT,
            tcp_state::ESTABLISHED,
            second,
            Some(parent()),
        ),
        // Sent after the second connection started: it belongs to that one.
        send_event(5, FORK_NS + 11_000_000, SK, 7_000),
    ])]);

    assert_eq!(produced.scope.egress_emitted, 2);
    let bytes_for = |dest: &str| {
        produced
            .records
            .iter()
            .find_map(|r| match &r.detail {
                EffectDetail::Egress { destination, bytes } if destination == dest => Some(*bytes),
                _ => None,
            })
            .expect("record present")
    };
    assert_eq!(
        bytes_for("203.0.113.9:443"),
        None,
        "the earlier connection observed no send of its own"
    );
    assert_eq!(bytes_for("198.51.100.4:8443"), Some(7_000));
}

// ── 4. No anchor, no timestamp, no record ─────────────────────────────────

#[test]
fn sf09_a_batch_without_a_clock_anchor_yields_no_timestamped_record() {
    // The consumer's schema is wall time. A guessed timestamp reconciles
    // against the wrong window and does so silently.
    let remote = endpoint(203, 0, 113, 9, 443);
    let produced = feed(&[batch_with(
        vec![
            sock_event(
                1,
                FORK_NS,
                SK,
                tcp_state::CLOSE,
                tcp_state::SYN_SENT,
                remote,
                Some(parent()),
            ),
            sock_event(
                2,
                FORK_NS + 5_000_000,
                SK,
                tcp_state::SYN_SENT,
                tcp_state::ESTABLISHED,
                remote,
                Some(parent()),
            ),
        ],
        None,
    )]);
    assert!(produced.records.is_empty(), "{:?}", produced.records);
    assert_eq!(produced.scope.dropped_no_clock_anchor, 1);
}

// ── 5. Determinism ────────────────────────────────────────────────────────

#[test]
fn sf10_the_same_evidence_renders_the_same_bytes() {
    let remote = endpoint(203, 0, 113, 9, 443);
    let events = || {
        vec![
            fork_event(1, FORK_NS, Some(parent())),
            exec_event(2, FORK_NS + 3_000_000, Some(child())),
            sock_event(
                3,
                FORK_NS + 4_000_000,
                SK,
                tcp_state::CLOSE,
                tcp_state::SYN_SENT,
                remote,
                Some(parent()),
            ),
            sock_event(
                4,
                FORK_NS + 5_000_000,
                SK,
                tcp_state::SYN_SENT,
                tcp_state::ESTABLISHED,
                remote,
                Some(parent()),
            ),
        ]
    };
    let a = feed(&[batch(events())]).to_jsonl(OBSERVER_ID);
    let b = feed(&[batch(events())]).to_jsonl(OBSERVER_ID);
    assert_eq!(a, b, "the feed must be reproducible");
    assert_eq!(a.lines().count(), 2);

    // Evidence order, not timestamp order: the exec is at index 1, the
    // connection's initiation at index 2.
    let kinds: Vec<&str> = a
        .lines()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            if v["kind"] == "spawn" {
                "spawn"
            } else {
                "egress"
            }
        })
        .collect();
    assert_eq!(kinds, ["spawn", "egress"]);
}

// ── 6. Against Phase 1's real, collector-signed evidence ──────────────────

#[test]
fn sf11_the_real_langgraph_archive_renders_a_well_formed_effect_log() {
    use aip_observe_verify::verify::{parse_jsonl, verify_archives, Parsed};

    let root = env!("CARGO_MANIFEST_DIR");
    let base = format!("{root}/../../integrations/agents/results/sealed");
    let archive = std::fs::read_to_string(format!("{base}/attested.archive.jsonl"))
        .expect("the committed Phase-1 attested archive must be present");
    let pubkey_hex = std::fs::read_to_string(format!("{base}/observer.pub"))
        .expect("the committed observer public key must be present");
    let pubkey = hex::decode(pubkey_hex.trim()).expect("the published key is hex");

    let parsed: Vec<Parsed<AttestedBatch>> = parse_jsonl(&archive);
    let verified: Vec<AttestedBatch> = parsed
        .iter()
        .filter_map(|p| match p {
            Parsed::Ok(l) => Some(l.record.clone()),
            Parsed::Failed { .. } => None,
        })
        .collect();

    // Fail closed: render nothing unless the archive verifies under its anchor.
    let report = verify_archives("collector.phase1", 1, &pubkey, Some(parsed), None);
    assert!(
        report.ok(),
        "the committed archive must verify under its published key: {:?}",
        report.findings
    );

    let produced = feed(&verified);
    assert!(
        produced.scope.spawns_emitted > 0,
        "the real agent run executed processes: {:?}",
        produced.scope
    );

    let jsonl = produced.to_jsonl("collector.phase1");
    assert_eq!(jsonl.lines().count(), produced.records.len());
    for line in jsonl.lines() {
        let v: serde_json::Value = serde_json::from_str(line).expect("each line is JSON");
        // The consumer's parser requires all three or it discards the line.
        for field in ["id", "timestampUtc", "kind"] {
            assert!(v.get(field).and_then(|f| f.as_str()).is_some(), "{line}");
        }
        match v["kind"].as_str().unwrap() {
            "spawn" => assert!(v["command"].as_str().is_some(), "{line}"),
            "egress" => assert!(v["destination"].as_str().is_some(), "{line}"),
            other => panic!("unexpected kind {other}: {line}"),
        }
        // Timestamps are wall clock, not kernel monotonic dressed up as one.
        let ts = v["timestampUtc"].as_str().unwrap();
        assert!(ts.starts_with("20") && ts.ends_with('Z'), "{line}");
    }

    // Ids are unique: the consumer cites them to locate a raw record, and two
    // records sharing one would send an auditor to the wrong event.
    let mut ids: Vec<&str> = produced.records.iter().map(|r| r.id.as_str()).collect();
    let total = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), total, "record ids must be unique");
}

// ── 7. The binary's verification gate ─────────────────────────────────────

#[test]
fn sf12_the_binary_renders_nothing_from_an_archive_that_does_not_verify() {
    use std::process::Command;

    let dir = std::env::temp_dir().join(format!("aip-sentinel-feed-sf12-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("archive.jsonl");
    let pubkey_path = dir.join("observer.pub");
    let out_path = dir.join("effects.jsonl");

    // A genuine archive, then one byte of its payload changed. The signature
    // no longer covers the bytes, which is exactly the tamper the gate is for.
    let (good, public_key) = signed_batch(vec![
        fork_event(1, FORK_NS, Some(parent())),
        exec_event(2, FORK_NS + 3_000_000, Some(child())),
    ]);
    let mut line = serde_json::to_string(&good).unwrap();
    line = line.replace("/opt/agent/bin/worker", "/opt/agent/bin/worXer");
    assert!(line.contains("worXer"), "the tamper must have landed");

    std::fs::write(&archive_path, format!("{line}\n")).unwrap();
    std::fs::write(&pubkey_path, &public_key).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_aip-sentinel-feed"))
        .args([
            "--observer-id",
            OBSERVER_ID,
            "--key-version",
            "1",
            "--pubkey-file",
            pubkey_path.to_str().unwrap(),
            "--batches",
            archive_path.to_str().unwrap(),
            "--out",
            out_path.to_str().unwrap(),
        ])
        .output()
        .expect("the binary runs");

    assert_eq!(
        output.status.code(),
        Some(1),
        "a tampered archive must exit 1: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !out_path.exists(),
        "no effect log may be written from evidence that did not verify"
    );
    assert!(
        output.stdout.is_empty(),
        "nothing is written to stdout either"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sf13_the_binary_writes_a_feed_for_an_archive_that_does_verify() {
    use std::process::Command;

    // The companion to sf12: without this, a binary that refused everything
    // would pass the gate test and be useless.
    let dir = std::env::temp_dir().join(format!("aip-sentinel-feed-sf13-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("archive.jsonl");
    let pubkey_path = dir.join("observer.pub");
    let out_path = dir.join("effects.jsonl");

    let (good, public_key) = signed_batch(vec![
        fork_event(1, FORK_NS, Some(parent())),
        exec_event(2, FORK_NS + 3_000_000, Some(child())),
    ]);
    std::fs::write(&pubkey_path, &public_key).unwrap();
    std::fs::write(
        &archive_path,
        format!("{}\n", serde_json::to_string(&good).unwrap()),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_aip-sentinel-feed"))
        .args([
            "--observer-id",
            OBSERVER_ID,
            "--key-version",
            "1",
            "--pubkey-file",
            pubkey_path.to_str().unwrap(),
            "--batches",
            archive_path.to_str().unwrap(),
            "--out",
            out_path.to_str().unwrap(),
        ])
        .output()
        .expect("the binary runs");

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let written = std::fs::read_to_string(&out_path).unwrap();
    assert_eq!(written.lines().count(), 1, "{written}");
    assert!(written.contains(r#""kind":"spawn""#), "{written}");
    // The scope report is not optional: a reader who sees only records cannot
    // tell an empty window from a blinded one.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("emitted 1 records"), "{stderr}");

    let _ = std::fs::remove_dir_all(&dir);
}

// ── 8. The scan that keeps the scope report honest ────────────────────────

#[test]
fn sf14_unbound_events_are_counted_even_though_derivation_never_sees_them() {
    // Regression. The first version of the scope report was built only from
    // derived values, and `aip-reconcile` discards an unbound event before
    // derivation — correctly, since an unbound event is not evidence of an
    // instance. The consequence was silent: on Phase 1's real archive eight
    // `connect()` initiations were unbound and the report said zero attempts
    // were unaccounted for, while nine had been observed. A report that
    // undercounts what it could not see is worse than no report, because a
    // reader takes its silence for coverage.
    let remote = endpoint(203, 0, 113, 9, 443);
    let produced = feed(&[batch(vec![
        fork_event(1, FORK_NS, None),
        exec_event(2, FORK_NS + 1_000_000, None),
        sock_event(
            3,
            FORK_NS + 2_000_000,
            SK,
            tcp_state::CLOSE,
            tcp_state::SYN_SENT,
            remote,
            None,
        ),
    ])]);

    assert!(produced.records.is_empty(), "{:?}", produced.records);
    assert_eq!(produced.scope.spawn_unbound, 1);
    assert_eq!(produced.scope.exec_unbound, 1);
    assert_eq!(produced.scope.connect_initiation_unbound, 1);
    assert_eq!(
        produced.scope.dropped(),
        3,
        "every observed event is accounted for somewhere: {:?}",
        produced.scope
    );
    // The derivation-side counters stay at zero: these events never reached
    // them, and double-counting would be its own kind of dishonesty.
    assert_eq!(produced.scope.fork_without_bound_execution, 0);
    assert_eq!(produced.scope.connect_attempt_not_established, 0);
}

#[test]
fn sf15_every_event_of_a_kind_the_feed_covers_is_either_rendered_or_counted() {
    // The completeness property stated as an equation over the real archive,
    // so a future change that starts silently discarding a class of event
    // fails here rather than in an audit.
    use aip_observe_verify::verify::{parse_jsonl, Parsed};

    let root = env!("CARGO_MANIFEST_DIR");
    let base = format!("{root}/../../integrations/agents/results/sealed");
    let archive = std::fs::read_to_string(format!("{base}/attested.archive.jsonl")).unwrap();
    let batches: Vec<AttestedBatch> = parse_jsonl(&archive)
        .into_iter()
        .filter_map(|p: Parsed<AttestedBatch>| match p {
            Parsed::Ok(l) => Some(l.record),
            Parsed::Failed { .. } => None,
        })
        .collect();

    // Ground truth, counted straight off the evidence.
    let mut forks = 0usize;
    let mut connect_initiations = 0usize;
    for b in &batches {
        for e in &b.batch.kernel_events {
            match (&e.mechanism, &e.kind) {
                (SourceMechanism::SchedTracepoint, KernelLifecycleKind::ProcessSpawn { .. }) => {
                    forks += 1
                }
                (SourceMechanism::SockStateTracepoint, k) if k.is_connect_initiation() => {
                    connect_initiations += 1
                }
                _ => {}
            }
        }
    }

    let scope = feed(&batches).scope;
    assert_eq!(
        scope.spawns_emitted
            + scope.fork_without_bound_execution
            + scope.exec_start_unverified
            + scope.spawn_unbound,
        forks,
        "every fork is rendered, refused with a reason, or counted unbound: {scope:?}"
    );
    assert_eq!(
        scope.egress_emitted
            + scope.connect_attempt_not_established
            + scope.connect_initiation_unbound,
        connect_initiations,
        "every connection attempt is accounted for: {scope:?}"
    );
}
