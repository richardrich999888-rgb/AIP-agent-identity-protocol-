//! Full-session tests over a real in-memory socket pair (`UnixStream::pair`),
//! exercising the generic protocol drivers end to end. Crypto-level tamper,
//! replay and oversize cases are unit-tested in `auth`/`codec`; these cover the
//! session logic: a clean round trip, allow-list rejection, and the server's
//! sequence-ordering refusal.
#![cfg(unix)]

use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::thread;

use aip_crypto::generate_ed25519_keypair;
use aip_transport::wire::{AuthMsg, BatchFrame, Message};
use aip_transport::{
    auth::sign_frame,
    codec::{read_frame, write_frame},
    run_server_session, BatchAckData, BatchSink, ProbeAuthority, ServerError, SinkError,
    TransportClient,
};

fn key32(v: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 32];
    k.copy_from_slice(v);
    k
}

/// Allows exactly one (probe_id, transport_pubkey) pair.
struct OneProbe {
    probe_id: String,
    pubkey: [u8; 32],
}
impl ProbeAuthority for OneProbe {
    fn is_authorized(&self, probe_id: &str, transport_pubkey: &[u8; 32]) -> bool {
        probe_id == self.probe_id && transport_pubkey == &self.pubkey
    }
}

/// One recorded batch: (authenticated probe id, frame seq, opaque bytes).
type Accepted = Arc<Mutex<Vec<(String, u64, Vec<u8>)>>>;

/// Records accepted batches; returns a fixed ack.
#[derive(Clone, Default)]
struct RecordingSink {
    accepted: Accepted,
}
impl BatchSink for RecordingSink {
    fn accept_batch(
        &mut self,
        probe_id: &str,
        seq: u64,
        batch_bytes: &[u8],
    ) -> Result<BatchAckData, SinkError> {
        self.accepted
            .lock()
            .unwrap()
            .push((probe_id.to_string(), seq, batch_bytes.to_vec()));
        Ok(BatchAckData {
            attested_sequence: seq,
            head: [seq as u8; 32],
        })
    }
}

const NONCE: [u8; 32] = [0x5a; 32];

#[test]
fn happy_path_round_trip() {
    let kp = generate_ed25519_keypair();
    let pubkey = key32(&kp.public_key);
    let authority = OneProbe {
        probe_id: "probe-1".into(),
        pubkey,
    };
    let sink = RecordingSink::default();
    let accepted = sink.accepted.clone();

    let (srv, cli) = UnixStream::pair().unwrap();
    let server = thread::spawn(move || {
        let mut sink = sink;
        let mut srv = srv;
        run_server_session(&mut srv, NONCE, &authority, &mut sink)
    });

    let mut client = TransportClient::handshake(cli, "probe-1", &kp.private_key, &pubkey).unwrap();
    let ack1 = client.send_batch(b"batch-one").unwrap();
    let ack2 = client.send_batch(b"batch-two").unwrap();
    assert_eq!((ack1.seq, ack1.attested_sequence), (1, 1));
    assert_eq!((ack2.seq, ack2.attested_sequence), (2, 2));
    drop(client); // clean disconnect

    assert!(server.join().unwrap().is_ok());
    let got = accepted.lock().unwrap().clone();
    assert_eq!(
        got,
        vec![
            ("probe-1".to_string(), 1, b"batch-one".to_vec()),
            ("probe-1".to_string(), 2, b"batch-two".to_vec()),
        ]
    );
}

#[test]
fn a_key_not_in_the_allow_list_is_rejected() {
    // The authority only trusts a different key than the one the client holds.
    let client_kp = generate_ed25519_keypair();
    let client_pub = key32(&client_kp.public_key);
    let trusted = generate_ed25519_keypair();
    let authority = OneProbe {
        probe_id: "probe-1".into(),
        pubkey: key32(&trusted.public_key),
    };
    let mut sink = RecordingSink::default();

    let (srv, cli) = UnixStream::pair().unwrap();
    let server = thread::spawn(move || {
        let mut srv = srv;
        run_server_session(&mut srv, NONCE, &authority, &mut sink)
    });

    // The client's own signature verifies (it signs with its real key), but the
    // pair is not in the allow-list, so the collector refuses.
    let err = TransportClient::handshake(cli, "probe-1", &client_kp.private_key, &client_pub)
        .err()
        .expect("handshake must be rejected");
    assert!(
        matches!(err, aip_transport::ClientError::Rejected { .. }),
        "{err}"
    );

    assert!(matches!(
        server.join().unwrap(),
        Err(ServerError::Unauthorized { .. })
    ));
}

#[test]
fn a_replayed_batch_sequence_is_refused() {
    // Drive the client side by hand so we can resend seq=1 after it was already
    // consumed. The server expects seq=2 next and refuses the replay.
    let kp = generate_ed25519_keypair();
    let pubkey = key32(&kp.public_key);
    let authority = OneProbe {
        probe_id: "probe-1".into(),
        pubkey,
    };
    let mut sink = RecordingSink::default();

    let (srv, mut cli) = UnixStream::pair().unwrap();
    let server = thread::spawn(move || {
        let mut srv = srv;
        run_server_session(&mut srv, NONCE, &authority, &mut sink)
    });

    // Handshake by hand.
    let challenge = match read_frame(&mut cli).unwrap() {
        Message::Challenge(c) => c,
        other => panic!("expected Challenge, got {other:?}"),
    };
    let sig = aip_transport::auth::sign_auth(
        &kp.private_key,
        challenge.protocol_version,
        &challenge.nonce,
        "probe-1",
    )
    .unwrap();
    write_frame(
        &mut cli,
        &Message::Auth(AuthMsg {
            probe_id: "probe-1".into(),
            transport_pubkey: pubkey,
            signature: sig.to_vec(),
        }),
    )
    .unwrap();
    assert!(matches!(
        read_frame(&mut cli).unwrap(),
        Message::AuthResult(r) if r.accepted
    ));

    // seq=1 accepted.
    let frame1 = BatchFrame {
        seq: 1,
        batch_bytes: b"one".to_vec(),
        signature: sign_frame(&kp.private_key, &challenge.nonce, 1, b"one")
            .unwrap()
            .to_vec(),
    };
    write_frame(&mut cli, &Message::Batch(frame1.clone())).unwrap();
    assert!(matches!(read_frame(&mut cli).unwrap(), Message::Ack(a) if a.seq == 1));

    // Replay seq=1: server expects seq=2 → Protocol error, connection closes.
    write_frame(&mut cli, &Message::Batch(frame1)).unwrap();

    assert!(matches!(
        server.join().unwrap(),
        Err(ServerError::Protocol(_))
    ));
}
