//! Gate 3 — action-level network evidence beyond `connect()`, RED.
//!
//! The source: `sock:sock_send_length`, the tracepoint the kernel fires in
//! `sock_sendmsg` **in the sending task's context**, carrying the socket's
//! kernel identity (`sk`), family, protocol, the byte count the kernel
//! accepted (`ret`) and the send flags. Measured on this host before any
//! code: a 19-byte send on loopback produced one record under the sender's
//! pid with `length = 19`.
//!
//! What it carries and what it never carries: the **count** of bytes the
//! kernel accepted for send on a socket, in the caller's context — never the
//! bytes, never a hash of them. A payload digest could only come from a
//! party that holds the plaintext (the agent, or an in-path proxy), which is
//! Gate 5's decision, not this gate's evidence.

use aip_observe::*;

const SEND_FMT: &str = "name: sock_send_length
ID: 1424
format:
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;
\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;
\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;

\tfield:void * sk;\toffset:8;\tsize:8;\tsigned:0;
\tfield:__u16 family;\toffset:16;\tsize:2;\tsigned:0;
\tfield:__u16 protocol;\toffset:18;\tsize:2;\tsigned:0;
\tfield:int ret;\toffset:20;\tsize:4;\tsigned:1;
\tfield:int flags;\toffset:24;\tsize:4;\tsigned:1;
";

const SK: u64 = 0xffff_9a0b_1234_5678;

fn record(family: u16, proto: u16, ret: i32, flags: i32) -> Vec<u8> {
    let mut r = vec![0u8; 28];
    r[8..16].copy_from_slice(&SK.to_ne_bytes());
    r[16..18].copy_from_slice(&family.to_ne_bytes());
    r[18..20].copy_from_slice(&proto.to_ne_bytes());
    r[20..24].copy_from_slice(&ret.to_ne_bytes());
    r[24..28].copy_from_slice(&flags.to_ne_bytes());
    r
}

fn fmt() -> RawFormat {
    RawFormat::parse(1424, SOCK_SEND_TRACEPOINT, SEND_FMT).unwrap()
}

#[test]
fn sk01_a_tcp_send_decodes_to_the_socket_the_count_and_the_caller() {
    let k = parse_sock_send_record(&fmt(), &record(2, 6, 19, 0), 4242).unwrap();
    assert_eq!(
        k,
        KernelLifecycleKind::SocketSend {
            protocol: SocketProtocol::Tcp,
            sk: SK,
            bytes: 19,
            flags: 0,
            current_pid: 4242,
        }
    );
    assert_eq!(k.subject_pid(), Some(4242), "sendmsg runs in the caller");
    let k6 = parse_sock_send_record(&fmt(), &record(10, 6, 7, 0x40), 1).unwrap();
    assert!(matches!(
        k6,
        KernelLifecycleKind::SocketSend {
            protocol: SocketProtocol::Tcp6,
            bytes: 7,
            flags: 0x40,
            ..
        }
    ));
}

#[test]
fn sk02_errors_non_tcp_unknown_family_and_short_records_are_refused_not_guessed() {
    let f = fmt();
    // A failed send accepted nothing: not a send.
    assert!(parse_sock_send_record(&f, &record(2, 6, -11, 0), 1).is_err());
    assert!(parse_sock_send_record(&f, &record(2, 6, 0, 0), 1).is_err());
    // UDP, SCTP, AF_UNIX.
    assert!(parse_sock_send_record(&f, &record(2, 17, 5, 0), 1).is_err());
    assert!(parse_sock_send_record(&f, &record(2, 132, 5, 0), 1).is_err());
    assert!(parse_sock_send_record(&f, &record(1, 6, 5, 0), 1).is_err());
    // Truncated.
    assert!(parse_sock_send_record(&f, &record(2, 6, 5, 0)[..20], 1).is_err());
    // A layout missing an interpreted field is refused at parse time.
    let broken = SEND_FMT.replace("field:int ret;", "field:int len;");
    let bf = RawFormat::parse(1424, SOCK_SEND_TRACEPOINT, &broken).unwrap();
    assert!(parse_sock_send_record(&bf, &record(2, 6, 5, 0), 1).is_err());
}

#[test]
fn sk03_the_mechanism_is_kernel_pushed_and_covers_no_lifecycle() {
    let m = SourceMechanism::SockSendTracepoint;
    assert_eq!(m.code(), 0x08);
    assert!(SourceMechanism::ALL.contains(&m));
    // Eight mechanisms at Gate 3; later gates add their own.
    assert!(SourceMechanism::ALL.len() >= 8);
    let mut codes: Vec<u8> = SourceMechanism::ALL.iter().map(|m| m.code()).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), SourceMechanism::ALL.len());
    assert!(m.is_kernel_pushed());
    assert!(!m.covers_process_lifecycle());
    assert!(!m.is_instance_anchored());
}

#[test]
fn sk04_a_send_event_encodes_injectively_and_carries_no_payload_field() {
    let ev = |kind: KernelLifecycleKind| KernelLifecycleEvent {
        cgroup: aip_observe::CgroupSample::NotSampled,
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: "p".into(),
        mechanism: SourceMechanism::SockSendTracepoint,
        kind,
        cpu: 0,
        kernel_timestamp_ns: 1,
        probe_seq: 1,
        bound: None,
        attribution: AgentAttribution::NotEstablished,
        claimed_decision_id: None,
    };
    let base = parse_sock_send_record(&fmt(), &record(2, 6, 19, 0), 4242).unwrap();
    let d0 = ev(base.clone()).digest();
    let mut more = ev(parse_sock_send_record(&fmt(), &record(2, 6, 20, 0), 4242).unwrap()).digest();
    assert_ne!(more, d0, "the byte count is inside the signed bytes");
    more = ev(parse_sock_send_record(&fmt(), &record(2, 6, 19, 0), 4243).unwrap()).digest();
    assert_ne!(more, d0);
    // Same sk in a state transition is a different fact.
    let state = ev(KernelLifecycleKind::SocketState {
        protocol: SocketProtocol::Tcp,
        local: SocketEndpoint {
            addr: [0; 16],
            is_v6: false,
            port: 0,
        },
        remote: SocketEndpoint {
            addr: [0; 16],
            is_v6: false,
            port: 0,
        },
        old_state: 0,
        new_state: 0,
        sk: SK,
        current_pid: 4242,
    });
    assert_ne!(state.digest(), d0);
    let json = serde_json::to_string(&base).unwrap().to_lowercase();
    for forbidden in ["payload", "hash", "digest", "data", "buf"] {
        assert!(!json.contains(forbidden), "{forbidden} in {json}");
    }
    assert!(json.contains("bytes"));
}

#[cfg(target_os = "linux")]
#[test]
fn sk05_the_probe_anchors_the_sending_task_under_the_start_tick_rule() {
    let mut probe = ProcfsProbe::new("probe-s");
    probe.declare_source(SourceMechanism::SockSendTracepoint);
    probe.declare_clock_anchor(boot_clock_anchor().unwrap());
    let me = std::process::id();
    let now_ns = {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: valid timespec.
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    };
    let kind = parse_sock_send_record(&fmt(), &record(2, 6, 19, 0), me).unwrap();
    let e = probe
        .ingest_send_event(ProcEvent {
            kind: kind.clone(),
            cpu: 0,
            timestamp_ns: now_ns,
        })
        .clone();
    assert_eq!(e.mechanism, SourceMechanism::SockSendTracepoint);
    let bound = e
        .bound
        .expect("this process is alive and started before now");
    assert_eq!(bound.process.pid, me);
    // An event stamped before this process started cannot be its send.
    let e2 = probe
        .ingest_send_event(ProcEvent {
            kind,
            cpu: 0,
            timestamp_ns: 1,
        })
        .clone();
    assert_eq!(e2.bound, None, "pid reuse is not attribution");
}

#[test]
fn sk06_the_collector_refuses_send_provenance_from_a_probe_not_provisioned_for_it() {
    let kp = aip_crypto::generate_ed25519_keypair();
    let mut signer = CollectorSigner::new("c", 1, &kp.private_key, &kp.public_key).unwrap();
    signer.register_probe(
        "probe-s",
        &[
            SourceMechanism::PidFdAnchored,
            SourceMechanism::SockStateTracepoint,
        ],
    );
    let mut probe = ProcfsProbe::new("probe-s");
    let kind = parse_sock_send_record(&fmt(), &record(2, 6, 19, 0), u32::MAX).unwrap();
    probe.ingest_send_event(ProcEvent {
        kind,
        cpu: 0,
        timestamp_ns: 5,
    });
    let b = probe.batch([1u8; 16], 1, 2, vec![]);
    assert!(signer.attest(b).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn sk07_live_a_loopback_send_is_reported_under_the_senders_pid_with_its_count() {
    use std::io::Write;
    use std::net::{Ipv4Addr, TcpListener, TcpStream};

    let mut tracer = match SockSendTracer::open() {
        Ok(t) => t,
        Err(SourceError::Unavailable(why)) => {
            eprintln!("sk07: SKIPPED — send tracepoint unavailable: {why}");
            return;
        }
        Err(e) => panic!("{e}"),
    };
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    let (_server, _) = listener.accept().unwrap();
    client.write_all(b"nineteen bytes here").unwrap();
    let me = std::process::id();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let mut seen = None;
    while std::time::Instant::now() < deadline && seen.is_none() {
        if let Some(ev) = tracer.next_event(50).unwrap() {
            if let KernelLifecycleKind::SocketSend {
                current_pid,
                bytes,
                protocol,
                sk,
                ..
            } = ev.kind
            {
                if current_pid == me && bytes == 19 {
                    assert_eq!(protocol, SocketProtocol::Tcp);
                    assert_ne!(sk, 0);
                    assert!(ev.timestamp_ns > 0);
                    seen = Some(sk);
                }
            }
        }
    }
    assert!(
        seen.is_some(),
        "the kernel reported this process's 19-byte send"
    );
    assert_eq!(tracer.take_lost(), 0);
}
