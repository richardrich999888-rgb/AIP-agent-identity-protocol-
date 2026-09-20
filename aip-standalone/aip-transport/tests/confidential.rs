//! R9 — what a network observer sees of a probe→collector session.
//!
//! The acceptance criterion in the coverage matrix is "capture shows no
//! plaintext metadata". So the test *is* a capture: a tap on the client's
//! socket records every byte written and read, a full authenticated session
//! runs through it, and the recording is searched for the things the
//! plaintext protocol sends — the probe id, its transport public key, the
//! JSON field names of the wire messages, and distinctive strings planted in
//! the batch. A control test runs the same session without the confidential
//! layer and finds all of them, which is what makes the negative assertion
//! worth anything.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use aip_crypto::generate_ed25519_keypair;
use aip_transport::{
    run_server_session, BatchAckData, BatchSink, ConfidentialError, ConfidentialStream,
    ProbeAuthority, ServerError, SinkError, StaticKeypair, TransportClient,
};

const PROBE_ID: &str = "probe-capture-test-7f3a";
const PLANTED: &[&str] = &[
    "agent:loan-officer-bot",
    "/opt/bank/bin/ledger-sync",
    "10.42.7.19:5432",
    "pid=48213",
];

/// A stream wrapper that records everything in both directions: the
/// vantage point of a passive observer on the wire.
struct Tap<S> {
    inner: S,
    log: Arc<Mutex<Vec<u8>>>,
}

impl<S: Read> Read for Tap<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.log.lock().unwrap().extend_from_slice(&buf[..n]);
        Ok(n)
    }
}

impl<S: Write> Write for Tap<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.log.lock().unwrap().extend_from_slice(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

struct AllowOne {
    probe_id: String,
    key: [u8; 32],
}

impl ProbeAuthority for AllowOne {
    fn is_authorized(&self, probe_id: &str, transport_pubkey: &[u8; 32]) -> bool {
        probe_id == self.probe_id && *transport_pubkey == self.key
    }
}

/// Records what the collector side received, so the test can prove the
/// plaintext arrived intact through the tunnel.
struct Recording(Arc<Mutex<Vec<Vec<u8>>>>);

impl BatchSink for Recording {
    fn accept_batch(
        &mut self,
        _probe_id: &str,
        _seq: u64,
        batch_bytes: &[u8],
    ) -> Result<BatchAckData, SinkError> {
        self.0.lock().unwrap().push(batch_bytes.to_vec());
        Ok(BatchAckData {
            attested_sequence: self.0.lock().unwrap().len() as u64,
            head: [7u8; 32],
        })
    }
}

fn batch() -> Vec<u8> {
    format!(
        "{{\"probe\":\"{PROBE_ID}\",\"entries\":[\"{}\",\"{}\",\"{}\",\"{}\"]}}",
        PLANTED[0], PLANTED[1], PLANTED[2], PLANTED[3]
    )
    .into_bytes()
}

/// What the plaintext protocol puts on the wire, in the exact bytes it
/// uses. The wire format is JSON: strings appear verbatim, but `[u8; 32]`
/// and `Vec<u8>` fields serialise as arrays of numbers, so the batch and the
/// public key are searched for in that form. (A first draft of this test
/// searched for the hex form and the raw batch text; the control test
/// caught it, which is what the control test is for.)
fn wire_markers(transport_pub: &[u8; 32]) -> Vec<String> {
    let mut v = vec![PROBE_ID.to_string()];
    for field in [
        "probe_id",
        "transport_pubkey",
        "batch_bytes",
        "protocol_version",
        "nonce",
    ] {
        v.push(format!("\"{field}\""));
    }
    v.push(serde_json::to_string(&batch()).unwrap());
    v.push(serde_json::to_string(&transport_pub.to_vec()).unwrap());
    v
}

/// What an observer would reconstruct from the batch once decoded: the
/// planted strings. Never on the wire verbatim in either mode (the batch is
/// a byte array in JSON), but a confidential capture must not contain them
/// in any form either, and this is the cheap check for the obvious one.
fn planted() -> Vec<String> {
    PLANTED.iter().map(|s| s.to_string()).collect()
}

fn found_in(log: &[u8], needle: &str) -> bool {
    log.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// Run one session. `confidential` selects the layer under test. Returns
/// the wire capture from the client's vantage point and what the sink got.
fn session(confidential: bool) -> (Vec<u8>, Vec<Vec<u8>>, [u8; 32]) {
    let collector_static = Arc::new(StaticKeypair::generate().unwrap());
    let probe_kp = generate_ed25519_keypair();
    let probe_pub: [u8; 32] = probe_kp.public_key.as_slice().try_into().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let received_server = received.clone();
    let static_server = collector_static.clone();
    let authority = AllowOne {
        probe_id: PROBE_ID.into(),
        key: probe_pub,
    };
    let server = thread::spawn(move || -> Result<(), ServerError> {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut sink = Recording(received_server);
        if confidential {
            let mut s = ConfidentialStream::respond(stream, &static_server)
                .map_err(ServerError::Confidential)?;
            run_server_session(&mut s, [9u8; 32], &authority, &mut sink)
        } else {
            let mut s = stream;
            run_server_session(&mut s, [9u8; 32], &authority, &mut sink)
        }
    });

    let log = Arc::new(Mutex::new(Vec::new()));
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let tap = Tap {
        inner: tcp,
        log: log.clone(),
    };
    if confidential {
        let s = ConfidentialStream::initiate(tap, collector_static.public()).unwrap();
        let mut client =
            TransportClient::handshake(s, PROBE_ID, &probe_kp.private_key, &probe_pub).unwrap();
        client.send_batch(&batch()).unwrap();
        client.send_batch(&batch()).unwrap();
    } else {
        let mut client =
            TransportClient::handshake(tap, PROBE_ID, &probe_kp.private_key, &probe_pub).unwrap();
        client.send_batch(&batch()).unwrap();
        client.send_batch(&batch()).unwrap();
    }
    // Drop the client so the server sees a clean EOF.
    server.join().unwrap().unwrap();
    let captured = log.lock().unwrap().clone();
    let got = received.lock().unwrap().clone();
    (captured, got, probe_pub)
}

/// **The acceptance test.** Nothing the plaintext protocol sends appears
/// in a capture of the confidential session, and the collector still
/// received the batches byte for byte.
#[test]
fn a_capture_of_a_confidential_session_shows_no_metadata() {
    let (captured, got, probe_pub) = session(true);
    assert!(!captured.is_empty());
    for s in wire_markers(&probe_pub).into_iter().chain(planted()) {
        assert!(!found_in(&captured, &s), "`{s}` is visible on the wire");
    }
    // A stricter form of the same claim: not one byte of the probe's public
    // key appears in sequence, in any encoding a 32-byte value has.
    assert!(!captured.windows(32).any(|w| w == probe_pub));
    assert_eq!(got.len(), 2);
    assert_eq!(
        got[0],
        batch(),
        "the tunnel must deliver the plaintext intact"
    );
}

/// **The control.** The same search over a plaintext session finds every
/// wire marker, so the negative result above is not the search failing.
#[test]
fn the_same_capture_of_a_plaintext_session_shows_everything() {
    let (captured, got, probe_pub) = session(false);
    for s in wire_markers(&probe_pub) {
        assert!(
            found_in(&captured, &s),
            "`{s}` should be visible in plaintext"
        );
    }
    assert_eq!(got.len(), 2);
}

/// An initiator that pinned the wrong static key cannot complete the
/// handshake, and the responder sees a failed handshake rather than an
/// authenticated peer. This is the active-attacker case: someone in the
/// middle who is not the collector.
#[test]
fn a_wrong_pinned_key_fails_the_handshake_before_any_authentication() {
    let real = StaticKeypair::generate().unwrap();
    let impostor = StaticKeypair::generate().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        ConfidentialStream::respond(stream, &real).map(|_| ())
    });
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let client = ConfidentialStream::initiate(tcp, impostor.public());
    assert!(
        matches!(client, Err(ConfidentialError::HandshakeFailed(_))),
        "{client:?}"
    );
    let server = server.join().unwrap();
    assert!(server.is_err(), "the responder must not report a session");
}

/// A message altered in flight fails authentication, and the stream
/// delivers nothing after it.
#[test]
fn a_tampered_message_is_refused_and_poisons_the_stream() {
    let key = Arc::new(StaticKeypair::generate().unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let key_server = key.clone();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut s = ConfidentialStream::respond(stream, &key_server).unwrap();
        s.write_all(b"first message").unwrap();
        s.write_all(b"second message").unwrap();
        s.flush().unwrap();
        // Keep the connection open until the client is done reading.
        let mut sink = [0u8; 1];
        let _ = s.read(&mut sink);
    });

    // A tap that flips one byte of the *second* message body as it is read.
    struct Flip<S> {
        inner: S,
        seen: usize,
        target: usize,
    }
    impl<S: Read> Read for Flip<S> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            let start = self.seen;
            if self.target >= start && self.target < start + n {
                buf[self.target - start] ^= 0x01;
            }
            self.seen += n;
            Ok(n)
        }
    }
    impl<S: Write> Write for Flip<S> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.inner.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }

    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    // The handshake's second message from the responder is the first thing
    // read: 2 + 48 bytes (e + empty payload + tag). The first transport
    // message is 2 + 13 + 16. So the second transport message's body starts
    // at 50 + 31 + 2 = 83; flip its first byte.
    let flip = Flip {
        inner: tcp,
        seen: 0,
        target: 83,
    };
    let mut s = ConfidentialStream::initiate(flip, key.public()).unwrap();
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"first message");
    let err = s.read(&mut buf).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
    assert!(err.to_string().contains("failed authentication"), "{err}");
    // Poisoned: nothing more, ever.
    let again = s.read(&mut buf).unwrap_err();
    assert!(again.to_string().contains("poisoned"), "{again}");
    assert!(s.write_all(b"x").is_err());
    drop(s);
    server.join().unwrap();
}

/// A payload larger than one Noise message is split and reassembled
/// exactly — a 4 MiB batch is the transport's frame ceiling and crosses
/// about 65 messages.
#[test]
fn a_payload_across_many_messages_round_trips_exactly() {
    let key = Arc::new(StaticKeypair::generate().unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let key_server = key.clone();
    let payload: Vec<u8> = (0..4 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut s = ConfidentialStream::respond(stream, &key_server).unwrap();
        let mut got = vec![0u8; expected.len()];
        s.read_exact(&mut got).unwrap();
        assert_eq!(got, expected);
        s.write_all(b"ok").unwrap();
        s.flush().unwrap();
    });
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut s = ConfidentialStream::initiate(tcp, key.public()).unwrap();
    s.write_all(&payload).unwrap();
    s.flush().unwrap();
    let mut ack = [0u8; 2];
    s.read_exact(&mut ack).unwrap();
    assert_eq!(&ack, b"ok");
    server.join().unwrap();
}

/// A clean close between messages is EOF, not an error: the server loop
/// treats it as a normal disconnect.
#[test]
fn a_clean_close_between_messages_is_eof() {
    let key = Arc::new(StaticKeypair::generate().unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let key_server = key.clone();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut s = ConfidentialStream::respond(stream, &key_server).unwrap();
        let mut buf = [0u8; 16];
        let n = s.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"bye");
        assert_eq!(s.read(&mut buf).unwrap(), 0, "clean EOF");
    });
    let tcp = TcpStream::connect(addr).unwrap();
    let mut s = ConfidentialStream::initiate(tcp, key.public()).unwrap();
    s.write_all(b"bye").unwrap();
    s.flush().unwrap();
    drop(s);
    server.join().unwrap();
}

/// Two sessions to one collector never share keys: the same plaintext
/// encrypts differently, so a capture of one session says nothing about
/// another.
#[test]
fn two_sessions_produce_different_ciphertext_for_the_same_plaintext() {
    let mut captures = Vec::new();
    for _ in 0..2 {
        let (captured, _, _) = session(true);
        captures.push(captured);
    }
    assert_ne!(captures[0], captures[1]);
}
