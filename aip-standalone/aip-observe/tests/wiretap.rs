//! Gate 2 — wire-level network observation, RED.
//!
//! The mechanism: an `AF_PACKET` socket receives a copy of every frame the
//! kernel hands to, or takes from, a network device (`packet_rcv` on
//! receive, `dev_queue_xmit_nit` on transmit), stamped by the kernel
//! (`SO_TIMESTAMPNS`, `CLOCK_REALTIME`) and counted for loss
//! (`PACKET_STATISTICS`). The probe keeps **headers only**: IP addresses,
//! TCP ports, flags, sequence numbers and the payload *length*. It never
//! copies, hashes or records payload bytes (I23), and it never learns which
//! process owns a socket — a wire segment carries no pid and is never bound.
//!
//! What this adds over the socket-state tracepoint: a second, independent
//! kernel path (the device layer, not the socket layer) whose evidence can
//! be produced by the same code running on a mirror port or TAP host that
//! the observed host's root does not control. On the observed host itself it
//! is as root-forgeable as every other source here, and no strength above
//! `Attested` may ever be derived from it.
//!
//! Frames here are constructed so every header field can be controlled; the
//! live capture runs at the end and skips itself where `CAP_NET_RAW` is
//! absent — nothing is simulated in that case.

use aip_observe::*;

const IF_LO: u32 = 1;
const T0_RT_NS: u64 = 1_788_000_000_000_000_000;

const PACKET_HOST: u8 = 0;
const PACKET_OUTGOING: u8 = 4;
const PACKET_OTHERHOST: u8 = 3;

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const PSH: u8 = 0x08;

/// An IPv4 + TCP frame as `SOCK_DGRAM` on `AF_PACKET` presents it: the link
/// header stripped, the IP header first.
fn v4_tcp(
    src: [u8; 4],
    sport: u16,
    dst: [u8; 4],
    dport: u16,
    flags: u8,
    seq: u32,
    ack: u32,
    payload: &[u8],
) -> Vec<u8> {
    let total = 20 + 20 + payload.len();
    let mut f = Vec::with_capacity(total);
    f.push(0x45);
    f.push(0);
    f.extend_from_slice(&(total as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0, 0x40, 0]); // id, flags/frag
    f.push(64); // ttl
    f.push(6); // TCP
    f.extend_from_slice(&[0, 0]); // checksum (unchecked)
    f.extend_from_slice(&src);
    f.extend_from_slice(&dst);
    f.extend_from_slice(&sport.to_be_bytes());
    f.extend_from_slice(&dport.to_be_bytes());
    f.extend_from_slice(&seq.to_be_bytes());
    f.extend_from_slice(&ack.to_be_bytes());
    f.push(5 << 4); // data offset 5 words
    f.push(flags);
    f.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]); // window, csum, urg
    f.extend_from_slice(payload);
    f
}

fn v6_tcp(src: [u8; 16], sport: u16, dst: [u8; 16], dport: u16, flags: u8) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x60, 0, 0, 0]);
    f.extend_from_slice(&20u16.to_be_bytes()); // payload length: TCP header only
    f.push(6); // next header TCP
    f.push(64);
    f.extend_from_slice(&src);
    f.extend_from_slice(&dst);
    f.extend_from_slice(&sport.to_be_bytes());
    f.extend_from_slice(&dport.to_be_bytes());
    f.extend_from_slice(&7u32.to_be_bytes());
    f.extend_from_slice(&0u32.to_be_bytes());
    f.push(5 << 4);
    f.push(flags);
    f.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
    f
}

fn ep4(addr: [u8; 4], port: u16) -> SocketEndpoint {
    let mut a = [0u8; 16];
    a[..4].copy_from_slice(&addr);
    SocketEndpoint {
        addr: a,
        is_v6: false,
        port,
    }
}

const LOCAL: [u8; 4] = [127, 0, 0, 1];
const REMOTE: [u8; 4] = [10, 0, 0, 5];

// ═══ Pure decoding ═══

#[test]
fn wt01_ipv4_syn_decodes_to_a_header_only_segment() {
    let frame = v4_tcp(LOCAL, 51_000, REMOTE, 443, SYN, 1_000, 0, &[]);
    let k = parse_wire_frame(&frame, PACKET_OUTGOING, IF_LO, T0_RT_NS).unwrap();
    let KernelLifecycleKind::WireSegment {
        ifindex,
        direction,
        protocol,
        src,
        dst,
        flags,
        seq,
        ack,
        payload_len,
        frame_len,
        kernel_realtime_ns,
    } = k
    else {
        panic!("not a wire segment: {k:?}");
    };
    assert_eq!(ifindex, IF_LO);
    assert_eq!(direction, WireDirection::Outgoing);
    assert_eq!(protocol, SocketProtocol::Tcp);
    assert_eq!(src, ep4(LOCAL, 51_000));
    assert_eq!(dst, ep4(REMOTE, 443));
    assert_eq!(flags, SYN);
    assert_eq!(seq, 1_000);
    assert_eq!(ack, 0);
    assert_eq!(payload_len, 0);
    assert_eq!(frame_len, frame.len() as u32);
    assert_eq!(kernel_realtime_ns, T0_RT_NS);
}

#[test]
fn wt02_ipv6_decodes_with_v6_endpoints() {
    let src = [0xfe; 16];
    let dst = [0xfd; 16];
    let k = parse_wire_frame(&v6_tcp(src, 1, dst, 2, SYN | ACK), PACKET_HOST, 7, 1).unwrap();
    let KernelLifecycleKind::WireSegment {
        protocol,
        src: s,
        dst: d,
        direction,
        ..
    } = k
    else {
        panic!()
    };
    assert_eq!(protocol, SocketProtocol::Tcp6);
    assert!(s.is_v6 && d.is_v6);
    assert_eq!(s.addr, src);
    assert_eq!(d.addr, dst);
    assert_eq!(direction, WireDirection::Incoming);
}

#[test]
fn wt03_non_tcp_non_ip_truncated_and_inconsistent_frames_are_refused_not_guessed() {
    // UDP.
    let mut udp = v4_tcp(LOCAL, 1, REMOTE, 2, 0, 0, 0, &[]);
    udp[9] = 17;
    assert!(matches!(
        parse_wire_frame(&udp, PACKET_HOST, IF_LO, 1),
        Err(SourceError::Malformed(_))
    ));
    // ARP-ish: not an IP version.
    assert!(matches!(
        parse_wire_frame(&[0x00, 0x01, 0x08, 0x00, 6, 4, 0, 1], PACKET_HOST, IF_LO, 1),
        Err(SourceError::Malformed(_))
    ));
    // Truncated IP header, truncated TCP header.
    let ok = v4_tcp(LOCAL, 1, REMOTE, 2, SYN, 0, 0, &[]);
    assert!(parse_wire_frame(&ok[..12], PACKET_HOST, IF_LO, 1).is_err());
    assert!(parse_wire_frame(&ok[..30], PACKET_HOST, IF_LO, 1).is_err());
    // IP total length shorter than the headers it claims.
    let mut short = ok.clone();
    short[2..4].copy_from_slice(&16u16.to_be_bytes());
    assert!(parse_wire_frame(&short, PACKET_HOST, IF_LO, 1).is_err());
    // IPv6 with an extension header: not interpreted, refused.
    let mut v6 = v6_tcp([1; 16], 1, [2; 16], 2, SYN);
    v6[6] = 0; // hop-by-hop
    assert!(parse_wire_frame(&v6, PACKET_HOST, IF_LO, 1).is_err());
    // Other-host frames (promiscuous noise) are still decoded, as `Other`.
    let k = parse_wire_frame(&ok, PACKET_OTHERHOST, IF_LO, 1).unwrap();
    assert!(matches!(
        k,
        KernelLifecycleKind::WireSegment {
            direction: WireDirection::Other,
            ..
        }
    ));
}

#[test]
fn wt04_payload_is_measured_by_length_never_carried_or_hashed() {
    let secret = b"POST /transfer amount=1000000";
    let frame = v4_tcp(LOCAL, 51_000, REMOTE, 443, PSH | ACK, 5, 9, secret);
    let k = parse_wire_frame(&frame, PACKET_OUTGOING, IF_LO, 1).unwrap();
    let KernelLifecycleKind::WireSegment {
        payload_len,
        frame_len,
        ..
    } = &k
    else {
        panic!()
    };
    assert_eq!(*payload_len, secret.len() as u32);
    assert_eq!(*frame_len, frame.len() as u32);
    // Nothing of the payload survives into the event or its encoding.
    let json = serde_json::to_string(&k).unwrap();
    assert!(!json.contains("transfer"));
    let event = KernelLifecycleEvent {
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: "p".into(),
        mechanism: SourceMechanism::WireTapAfPacket,
        kind: k,
        cpu: 0,
        kernel_timestamp_ns: 1,
        probe_seq: 1,
        bound: None,
        attribution: AgentAttribution::NotEstablished,
        claimed_decision_id: None,
    };
    let bytes = event.canonical_bytes();
    assert!(!bytes.windows(8).any(|w| w == b"transfer"));
    assert!(!bytes.windows(5).any(|w| w == b"POST "));
}

// ═══ Mechanism and event semantics ═══

#[test]
fn wt05_the_tap_is_a_kernel_pushed_mechanism_that_covers_no_process_lifecycle() {
    let m = SourceMechanism::WireTapAfPacket;
    assert_eq!(m.code(), 0x07);
    assert!(SourceMechanism::ALL.contains(&m));
    assert_eq!(SourceMechanism::ALL.len(), 7);
    let mut codes: Vec<u8> = SourceMechanism::ALL.iter().map(|m| m.code()).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), 7, "codes stay distinct");
    assert!(m.is_kernel_pushed());
    assert!(!m.covers_process_lifecycle());
    assert!(!m.is_instance_anchored());
}

#[test]
fn wt06_a_wire_segment_names_no_process_and_encodes_injectively() {
    let base = parse_wire_frame(
        &v4_tcp(LOCAL, 51_000, REMOTE, 443, SYN, 1_000, 0, &[]),
        PACKET_OUTGOING,
        IF_LO,
        T0_RT_NS,
    )
    .unwrap();
    assert_eq!(
        base.subject_pid(),
        None,
        "no task context exists on the wire"
    );
    assert_eq!(base.spawned_child_pid(), None);
    assert!(!base.is_connect_initiation());
    assert!(!base.is_connect_established());

    let ev = |kind: KernelLifecycleKind| KernelLifecycleEvent {
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: "p".into(),
        mechanism: SourceMechanism::WireTapAfPacket,
        kind,
        cpu: 0,
        kernel_timestamp_ns: 1,
        probe_seq: 1,
        bound: None,
        attribution: AgentAttribution::NotEstablished,
        claimed_decision_id: None,
    };
    let d0 = ev(base.clone()).digest();
    let mut variants = Vec::new();
    for (pkt, ifi, rt, flags, seq) in [
        (PACKET_HOST, IF_LO, T0_RT_NS, SYN, 1_000u32),
        (PACKET_OUTGOING, 2, T0_RT_NS, SYN, 1_000),
        (PACKET_OUTGOING, IF_LO, T0_RT_NS + 1, SYN, 1_000),
        (PACKET_OUTGOING, IF_LO, T0_RT_NS, SYN | ACK, 1_000),
        (PACKET_OUTGOING, IF_LO, T0_RT_NS, SYN, 1_001),
    ] {
        let k = parse_wire_frame(
            &v4_tcp(LOCAL, 51_000, REMOTE, 443, flags, seq, 0, &[]),
            pkt,
            ifi,
            rt,
        )
        .unwrap();
        variants.push(ev(k).digest());
    }
    for v in &variants {
        assert_ne!(*v, d0);
    }
    variants.sort_unstable();
    variants.dedup();
    assert_eq!(variants.len(), 5);

    // A socket-state event with the same endpoints is a different fact.
    let sock = ev(KernelLifecycleKind::SocketState {
        protocol: SocketProtocol::Tcp,
        local: ep4(LOCAL, 51_000),
        remote: ep4(REMOTE, 443),
        old_state: tcp_state::CLOSE,
        new_state: tcp_state::SYN_SENT,
        sk: 1,
        current_pid: 1,
    });
    assert_ne!(sock.digest(), d0);
}

#[test]
fn wt07_the_probe_ingests_a_segment_unbound_with_no_attribution() {
    let mut probe = ProcfsProbe::new("probe-w");
    probe.declare_source(SourceMechanism::WireTapAfPacket);
    // A claim for some pid exists; the wire cannot know it applies.
    probe.register_claim(
        std::process::id(),
        AgentClaim {
            agent_id: "aip1agent".into(),
            claim_source: "orchestrator".into(),
            decision_id: Some([9u8; 16]),
        },
    );
    let kind = parse_wire_frame(
        &v4_tcp(LOCAL, 51_000, REMOTE, 443, SYN, 1, 0, &[]),
        PACKET_OUTGOING,
        IF_LO,
        T0_RT_NS,
    )
    .unwrap();
    let e = probe
        .ingest_wire_event(ProcEvent {
            kind,
            cpu: 0,
            timestamp_ns: 5,
        })
        .clone();
    assert_eq!(e.mechanism, SourceMechanism::WireTapAfPacket);
    assert_eq!(e.bound, None);
    assert_eq!(e.subject_identity_digest(), None);
    assert_eq!(e.attribution, AgentAttribution::NotEstablished);
    assert_eq!(e.claimed_decision_id, None);
    let b = probe.batch([1u8; 16], 1, 2, vec![]);
    assert!(b
        .active_mechanisms
        .contains(&SourceMechanism::WireTapAfPacket));
    assert_eq!(b.kernel_events.len(), 1);
}

#[test]
fn wt08_the_collector_refuses_wire_provenance_from_a_probe_not_provisioned_for_it() {
    let kp = aip_crypto::generate_ed25519_keypair();
    let mut signer = CollectorSigner::new("c", 1, &kp.private_key, &kp.public_key).unwrap();
    signer.register_probe(
        "probe-w",
        &[
            SourceMechanism::PidFdAnchored,
            SourceMechanism::SockStateTracepoint,
        ],
    );
    let mut probe = ProcfsProbe::new("probe-w");
    let kind = parse_wire_frame(
        &v4_tcp(LOCAL, 51_000, REMOTE, 443, SYN, 1, 0, &[]),
        PACKET_OUTGOING,
        IF_LO,
        T0_RT_NS,
    )
    .unwrap();
    probe.ingest_wire_event(ProcEvent {
        kind,
        cpu: 0,
        timestamp_ns: 5,
    });
    let b = probe.batch([1u8; 16], 1, 2, vec![]);
    assert!(
        signer.attest(b).is_err(),
        "a host cannot label its own report as wire provenance"
    );
}

#[test]
fn wt09_the_clock_anchor_places_a_realtime_capture_stamp_on_the_monotonic_clock() {
    let a = BootClockAnchor {
        realtime_ms: 1_000_000,
        boottime_ns: 5_000_000_000,
        monotonic_ns: 5_000_000_000,
        clk_tck: 100,
    };
    // 1.5 s after the anchor in realtime is 1.5 s after it in monotonic.
    assert_eq!(a.realtime_ns_to_monotonic(1_001_500_000_000), 6_500_000_000);
    // Before the anchor: subtracted, saturating.
    assert_eq!(a.realtime_ns_to_monotonic(999_000_000_000), 4_000_000_000);
    assert_eq!(a.realtime_ns_to_monotonic(0), 0);
    // Round trip through wall_ms at millisecond resolution.
    assert_eq!(
        a.wall_ms(a.realtime_ns_to_monotonic(1_001_500_000_000)),
        1_001_500
    );
}

// ═══ Live: the real device path ═══

#[cfg(target_os = "linux")]
#[test]
fn wt10_live_loopback_handshake_is_captured_with_kernel_stamps_and_counted_loss() {
    use std::io::Write;
    use std::net::{Ipv4Addr, TcpListener, TcpStream};

    let mut tap = match WireTap::open(Some("lo")) {
        Ok(t) => t,
        Err(SourceError::Unavailable(why)) => {
            eprintln!("wt10: SKIPPED — wire tap unavailable on this host: {why}");
            return;
        }
        Err(e) => panic!("{e}"),
    };
    assert_eq!(tap.ifindex(), IF_LO);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    client.write_all(b"hello over the wire").unwrap();
    server.write_all(b"ok").unwrap();
    drop(client);
    drop(server);

    let now_rt = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let (mut syn_out, mut syn_ack_in, mut data_len) = (0u32, 0u32, 0u32);
    while std::time::Instant::now() < deadline {
        let Some(ev) = tap.next_event(50).unwrap() else {
            continue;
        };
        let KernelLifecycleKind::WireSegment {
            ifindex,
            direction,
            src,
            dst,
            flags,
            payload_len,
            kernel_realtime_ns,
            ..
        } = ev.kind
        else {
            panic!("the tap yields wire segments only");
        };
        assert_eq!(ifindex, IF_LO);
        assert!(
            kernel_realtime_ns.abs_diff(now_rt) < 10_000_000_000,
            "kernel capture stamp is on the realtime clock, near now"
        );
        assert!(ev.timestamp_ns > 0, "probe monotonic dequeue stamp");
        if dst.port == port && flags & (SYN | ACK) == SYN && direction == WireDirection::Outgoing {
            syn_out += 1;
        }
        if src.port == port
            && flags & (SYN | ACK) == SYN | ACK
            && direction == WireDirection::Incoming
        {
            syn_ack_in += 1;
        }
        if dst.port == port && payload_len > 0 {
            data_len += payload_len;
        }
        if syn_out > 0 && syn_ack_in > 0 && data_len >= 19 {
            break;
        }
    }
    assert!(syn_out >= 1, "the client's SYN left through lo");
    assert!(syn_ack_in >= 1, "the server's SYN-ACK arrived through lo");
    assert_eq!(data_len, 19, "payload measured by length only");
    assert_eq!(
        tap.take_lost(),
        0,
        "PACKET_STATISTICS reports a counted zero"
    );
}
