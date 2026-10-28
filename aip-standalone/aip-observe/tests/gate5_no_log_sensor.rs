//! Gate 5 / Phase H — the fence around application, database and proxy
//! records (`APPLICATION_LOG_SENSOR_DECISION.md`).
//!
//! Such records are statements written by host-side processes, not
//! observation. This suite pins that the observer's vocabulary cannot
//! represent them, that a writer's word confers no identity, and that
//! nothing below `Attested` can move the warrant engine past `Alert`. If a
//! supporting tier is ever admitted these tests are extended, never
//! weakened. g5d (the `Correlated` ceiling) lives in `aip-warrant`, which
//! is the crate that enforces it.

use aip_observe::*;

/// g5a — every mechanism is the kernel's own state, pushed or read under
/// an anchor; none is a log, a proxy or a database.
#[test]
fn g5a_every_source_mechanism_is_kernel_authored() {
    for m in SourceMechanism::ALL {
        let kernel_table_or_procfs = matches!(
            m,
            SourceMechanism::ProcfsPoll
                | SourceMechanism::PidFdAnchored
                | SourceMechanism::ProcNetTable
        );
        assert!(
            m.is_kernel_pushed() || kernel_table_or_procfs,
            "{m:?} is neither kernel-pushed nor a kernel table / procfs read"
        );
        let name = format!("{m:?}").to_lowercase();
        for forbidden in ["log", "proxy", "db", "database", "app", "journal", "audit"] {
            assert!(
                !name.contains(forbidden),
                "{m:?} is named like an application-layer source"
            );
        }
    }
}

/// g5b — the event and effect vocabularies carry kernel state only.
#[test]
fn g5b_events_and_effects_cannot_represent_a_log_record() {
    let ep = SocketEndpoint {
        addr: [0; 16],
        is_v6: false,
        port: 1,
    };
    let kinds = [
        KernelLifecycleKind::Fork {
            parent_pid: 1,
            parent_tgid: 1,
            child_pid: 2,
            child_tgid: 2,
        },
        KernelLifecycleKind::Exec { pid: 2, tgid: 2 },
        KernelLifecycleKind::Exit {
            pid: 2,
            tgid: 2,
            exit_code: 0,
            exit_signal: 0,
        },
        KernelLifecycleKind::Other { what: 9 },
        KernelLifecycleKind::SocketState {
            protocol: SocketProtocol::Tcp,
            local: ep,
            remote: ep,
            old_state: 7,
            new_state: 2,
            sk: 1,
            current_pid: 1,
        },
        KernelLifecycleKind::ProcessSpawn {
            parent_pid: 1,
            child_pid: 2,
            parent_comm: String::new(),
            child_comm: String::new(),
        },
        KernelLifecycleKind::ProcessExec {
            pid: 2,
            old_pid: 2,
            filename: String::new(),
        },
        KernelLifecycleKind::WireSegment {
            ifindex: 1,
            direction: WireDirection::Outgoing,
            protocol: SocketProtocol::Tcp,
            src: ep,
            dst: ep,
            flags: 2,
            seq: 0,
            ack: 0,
            payload_len: 0,
            frame_len: 40,
            kernel_realtime_ns: 1,
        },
        KernelLifecycleKind::SocketSend {
            protocol: SocketProtocol::Tcp,
            sk: 1,
            bytes: 1,
            flags: 0,
            current_pid: 1,
        },
        KernelLifecycleKind::FileEvent {
            mask: 8,
            pid: 1,
            path: "/x".into(),
            deleted: false,
            dev: 1,
            ino: 1,
        },
    ];
    // Every kind serialises without any key that could carry a writer's
    // statement: no free-text message, no tool name, no argument digest,
    // no request line, no statement text, no content. (`payload_len` on a
    // wire segment is a length, which is exactly what the kernel path may
    // know about a payload.)
    const FORBIDDEN_KEYS: [&str; 12] = [
        "message",
        "tool",
        "arguments",
        "params_digest",
        "request",
        "statement",
        "query",
        "log",
        "payload",
        "body",
        "content",
        "record",
    ];
    fn keys(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, v) in m {
                    out.push(k.clone());
                    keys(v, out);
                }
            }
            serde_json::Value::Array(a) => a.iter().for_each(|v| keys(v, out)),
            _ => {}
        }
    }
    for k in &kinds {
        let mut ks = Vec::new();
        keys(&serde_json::to_value(k).unwrap(), &mut ks);
        for key in &ks {
            assert!(!FORBIDDEN_KEYS.contains(&key.as_str()), "{key} in {k:?}");
        }
    }
    let effects = [
        ObservedEffect::ProcessPresent,
        ObservedEffect::ProcessNoLongerPresent,
        ObservedEffect::SocketObserved {
            protocol: SocketProtocol::Tcp,
            local: ep,
            remote: ep,
            state: 1,
            inode: 1,
        },
    ];
    for e in &effects {
        let mut ks = Vec::new();
        keys(&serde_json::to_value(e).unwrap(), &mut ks);
        for key in &ks {
            assert!(!FORBIDDEN_KEYS.contains(&key.as_str()), "{key} in {e:?}");
        }
    }
}

/// g5c — a claim is a claim: it never yields identity on its own.
#[test]
fn g5c_a_writers_word_confers_no_identity() {
    let e = KernelLifecycleEvent {
        cgroup: aip_observe::CgroupSample::NotSampled,
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: "p".into(),
        mechanism: SourceMechanism::Fanotify,
        kind: KernelLifecycleKind::FileEvent {
            mask: 8,
            pid: 1,
            path: "/x".into(),
            deleted: false,
            dev: 1,
            ino: 1,
        },
        cpu: 0,
        kernel_timestamp_ns: 1,
        probe_seq: 1,
        bound: None,
        attribution: AgentAttribution::Claimed {
            agent_id: "aip1someone".into(),
            claim_source: "tool-server-log".into(),
        },
        claimed_decision_id: Some([1u8; 16]),
    };
    assert_eq!(e.subject_identity_digest(), None);
    assert!(matches!(e.attribution, AgentAttribution::Claimed { .. }));
    // The attribution type has no variant that could state verification.
    let json = serde_json::to_string(&e.attribution)
        .unwrap()
        .to_lowercase();
    assert!(!json.contains("verified"));
    assert!(!json.contains("trusted"));
}
