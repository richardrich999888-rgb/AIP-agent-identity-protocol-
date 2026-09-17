//! End-to-end Phase 1 proof over a real TCP loopback: a probe client ships an
//! observation batch through the authenticated transport to a collector whose
//! signing key is wrapped at rest; the resulting `AttestedBatch` verifies
//! offline against the collector's public key. Adversarial: a probe whose
//! transport key is not in the allow-list is refused, and no attestation is
//! produced.

use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use aip_crypto::generate_ed25519_keypair;
use aip_observe::{
    verify_attested_batch, AttestedBatch, CollectorKey, CollectorRuntime, CollectorStore,
    ContinuityPolicy, ObservationBatch, ObserverTrustAnchors, ProcfsProbe, Started,
};
use aip_transport::{
    serve_connection, BatchAckData, BatchSink, ProbeAuthority, ServerError, SinkError,
    TransportClient,
};

use aip_collector::authority::AllowList;

const OBSERVER_ID: &str = "collector.e2e.example";
const PROBE_ID: &str = "probe-e2e";
const KEY_VERSION: u32 = 1;
const TIMEOUT: Duration = Duration::from_secs(5);

/// A collector runtime under wrapped (production) custody, plus its public key
/// for the verifier's anchors.
struct Collector {
    runtime: Arc<Mutex<CollectorRuntime>>,
    public_key: Vec<u8>,
    _dir: std::path::PathBuf,
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aip-e2e-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn build_collector(tag: &str) -> Collector {
    let dir = scratch(tag);
    let store = CollectorStore::open(&dir).unwrap();
    let key = CollectorKey::production(dir.join("collector.key.wrapped"), b"pw").unwrap();
    let public_key = key.public_key().to_vec();
    let custodian = key.into_custodian();
    let started = CollectorRuntime::start_with_custodian(
        store,
        OBSERVER_ID,
        KEY_VERSION,
        custodian,
        ContinuityPolicy::Strict,
    )
    .unwrap();
    let rt = match started {
        Started::Running(rt, _) => rt,
        Started::Refused(brk) => panic!("fresh start refused: {brk:?}"),
    };
    Collector {
        runtime: Arc::new(Mutex::new(rt)),
        public_key,
        _dir: dir,
    }
}

/// Write a one-entry allow-list file and load it.
fn allow_list(probe_id: &str, transport_pub: &[u8; 32]) -> (AllowList, std::path::PathBuf) {
    let dir = scratch("allow");
    let path = dir.join("probes.json");
    let json = format!(
        r#"[{{"probe_id":"{probe_id}","transport_pubkey_hex":"{}"}}]"#,
        hex::encode(transport_pub)
    );
    std::fs::write(&path, json).unwrap();
    (AllowList::load(&path).unwrap(), dir)
}

/// A sink that attests and captures the `AttestedBatch` so the test can verify
/// it. Mirrors the daemon's `RuntimeSink` and additionally retains the output.
struct CapturingSink {
    runtime: Arc<Mutex<CollectorRuntime>>,
    captured: Arc<Mutex<Vec<AttestedBatch>>>,
}
impl BatchSink for CapturingSink {
    fn accept_batch(
        &mut self,
        probe_id: &str,
        _seq: u64,
        batch_bytes: &[u8],
    ) -> Result<BatchAckData, SinkError> {
        let batch: ObservationBatch =
            serde_json::from_slice(batch_bytes).map_err(|e| SinkError(e.to_string()))?;
        if batch.probe_id != probe_id {
            return Err(SinkError("probe_id mismatch".into()));
        }
        let mut rt = self.runtime.lock().unwrap();
        let attested = rt.attest(batch).map_err(|e| SinkError(format!("{e:?}")))?;
        let head = rt.snapshot().head.unwrap_or([0u8; 32]);
        let seq = attested.sequence;
        self.captured.lock().unwrap().push(attested);
        Ok(BatchAckData {
            attested_sequence: seq,
            head,
        })
    }
}

fn a_batch(probe_id: &str) -> Vec<u8> {
    let mut probe = ProcfsProbe::new(probe_id);
    serde_json::to_vec(&probe.batch([7u8; 16], 100, 200, vec![])).unwrap()
}

#[test]
fn a_shipped_batch_is_attested_off_host_and_verifies_offline() {
    let collector = build_collector("happy");
    let probe_kp = generate_ed25519_keypair();
    let probe_pub: [u8; 32] = probe_kp.public_key.as_slice().try_into().unwrap();
    let (allow, _allow_dir) = allow_list(PROBE_ID, &probe_pub);

    let captured = Arc::new(Mutex::new(Vec::new()));
    let mut sink = CapturingSink {
        runtime: collector.runtime.clone(),
        captured: captured.clone(),
    };

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || -> Result<(), ServerError> {
        let (stream, _) = listener.accept().unwrap();
        serve_connection(stream, TIMEOUT, &allow, &mut sink)
    });

    let mut client =
        TransportClient::connect(addr, PROBE_ID, &probe_kp.private_key, &probe_pub, TIMEOUT)
            .unwrap();
    let ack = client.send_batch(&a_batch(PROBE_ID)).unwrap();
    assert_eq!(ack.seq, 1);
    drop(client); // clean disconnect
    server.join().unwrap().unwrap();

    // The attested batch verifies against anchors the verifier supplies — the
    // collector's public key, never a key shipped inside the artifact.
    let batches = captured.lock().unwrap();
    assert_eq!(batches.len(), 1);
    let anchors =
        ObserverTrustAnchors::new().trust(OBSERVER_ID, KEY_VERSION, &collector.public_key);
    assert_eq!(
        verify_attested_batch(&batches[0], &anchors),
        Ok(()),
        "the off-host-signed batch must verify offline"
    );
    assert_eq!(batches[0].observer_id, OBSERVER_ID);
}

#[test]
fn a_probe_key_not_in_the_allow_list_is_refused_and_nothing_is_attested() {
    let collector = build_collector("reject");
    // The allow-list trusts a different key than the probe actually holds.
    let trusted = generate_ed25519_keypair();
    let trusted_pub: [u8; 32] = trusted.public_key.as_slice().try_into().unwrap();
    let (allow, _allow_dir) = allow_list(PROBE_ID, &trusted_pub);

    let captured = Arc::new(Mutex::new(Vec::new()));
    let mut sink = CapturingSink {
        runtime: collector.runtime.clone(),
        captured: captured.clone(),
    };

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || -> Result<(), ServerError> {
        let (stream, _) = listener.accept().unwrap();
        serve_connection(stream, TIMEOUT, &allow, &mut sink)
    });

    let impostor = generate_ed25519_keypair();
    let impostor_pub: [u8; 32] = impostor.public_key.as_slice().try_into().unwrap();
    let err = TransportClient::connect(
        addr,
        PROBE_ID,
        &impostor.private_key,
        &impostor_pub,
        TIMEOUT,
    )
    .err()
    .expect("connect must be rejected");
    assert!(
        matches!(err, aip_transport::ClientError::Rejected { .. }),
        "{err}"
    );

    assert!(matches!(
        server.join().unwrap(),
        Err(ServerError::Unauthorized { .. })
    ));
    assert!(
        captured.lock().unwrap().is_empty(),
        "nothing must be attested"
    );
}

/// A minimal authority check independent of the file loader, documenting the
/// exact-match rule the server relies on.
#[test]
fn allow_list_is_exact_match() {
    let kp = generate_ed25519_keypair();
    let pk: [u8; 32] = kp.public_key.as_slice().try_into().unwrap();
    let (allow, _dir) = allow_list("probe-x", &pk);
    assert!(allow.is_authorized("probe-x", &pk));
    assert!(!allow.is_authorized("probe-y", &pk));
    assert!(!allow.is_authorized("probe-x", &[0u8; 32]));
}
