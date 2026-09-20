//! `aip-collector` — the off-host collector daemon (Phase 1).
//!
//! Holds the only evidence-signing key, wrapped at rest, and never as raw bytes
//! (`CollectorKey::production`). Accepts authenticated observation batches over
//! [`aip_transport`], attests them under [`aip_observe::CollectorRuntime`],
//! persists the chain position, and keeps a fresh signed health record in the
//! store. It is the trust anchor: a compromised probe host can submit false
//! observations, but only this daemon can vouch for one.
//!
//! Fail closed: if it cannot prove its own continuity at start (amnesia,
//! rollback or fork under the strict policy) it writes a signed continuity
//! report and exits without serving. A collector that cannot prove continuity
//! does not sign.

use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aip_observe::{CollectorKey, CollectorRuntime, CollectorStore, SourceMechanism, Started};
use aip_transport::serve_connection_confidential;

use aip_collector::authority::AllowList;
use aip_collector::config::Config;
use aip_collector::noise_key::NoiseKeyFile;
use aip_collector::sink::RuntimeSink;

/// Per-connection read timeout: a stalled peer cannot pin a worker thread.
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// How often the collector refreshes its signed health record in the store.
const HEALTH_INTERVAL: Duration = Duration::from_secs(30);

fn main() {
    std::process::exit(match run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("aip-collector: {e}");
            1
        }
    });
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn run() -> Result<(), String> {
    let cfg = Config::from_env()?;
    let store = CollectorStore::open(&cfg.state_dir).map_err(|e| format!("open store: {e:?}"))?;

    // Load the wrapped signing key on the collector host. `production` refuses a
    // development backend; the raw key is never exposed.
    let key = CollectorKey::production(&cfg.key_path, &cfg.passphrase)
        .map_err(|e| format!("load collector key: {e}"))?;
    let custodian = key.into_custodian();

    let started = CollectorRuntime::start_with_custodian(
        store,
        &cfg.observer_id,
        cfg.key_version,
        custodian,
        cfg.continuity,
    )
    .map_err(|e| format!("start runtime: {e:?}"))?;

    let mut rt = match started {
        Started::Running(rt, outcome) => {
            eprintln!("aip-collector: started ({outcome:?})");
            rt
        }
        Started::Refused(brk) => {
            return Err(format!(
                "continuity refused ({brk:?}); a signed report is in {}. The collector will not \
                 sign until an operator acts.",
                cfg.state_dir.display()
            ));
        }
    };

    // Register the allowed probes. This tightens the collector's probe policy to
    // RegisteredOnly, so a batch may only claim mechanisms a registered probe
    // was provisioned for.
    let allow = AllowList::load(&cfg.probes_path)?;
    for probe_id in allow.probe_ids() {
        rt.signer_mut()
            .register_probe(probe_id, &SourceMechanism::ALL);
    }
    eprintln!(
        "aip-collector: {} probe(s) registered; observer {:?}",
        allow.len(),
        cfg.observer_id
    );

    let runtime = Arc::new(Mutex::new(rt));
    let authority = Arc::new(allow);

    // R9: the link is confidential, unconditionally. Every probe pins this
    // public key; announce it at every start so an operator can find it
    // without reading the key file.
    let noise_key = Arc::new(NoiseKeyFile::load_or_generate(&cfg.noise_key_path)?);
    eprintln!(
        "aip-collector: noise static public key (pin in AIP_PROBE_COLLECTOR_NOISE_PUBKEY): {}",
        hex::encode(noise_key.public())
    );

    // Emit an initial signed health record, then keep it fresh on a timer so a
    // verifier can bound coverage against a recent, signed statement.
    emit_health(&runtime)?;
    spawn_health_loop(runtime.clone());

    let listener =
        TcpListener::bind(&cfg.listen).map_err(|e| format!("bind {}: {e}", cfg.listen))?;
    eprintln!("aip-collector: listening on {}", cfg.listen);

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let runtime = runtime.clone();
                let authority = authority.clone();
                let noise_key = noise_key.clone();
                std::thread::spawn(move || {
                    let peer = stream
                        .peer_addr()
                        .map(|a| a.to_string())
                        .unwrap_or_else(|_| "<unknown>".into());
                    let mut sink = RuntimeSink::new(runtime);
                    match serve_connection_confidential(
                        stream,
                        READ_TIMEOUT,
                        &noise_key,
                        authority.as_ref(),
                        &mut sink,
                    ) {
                        Ok(()) => {}
                        Err(e) => eprintln!("aip-collector: session with {peer} ended: {e}"),
                    }
                });
            }
            Err(e) => eprintln!("aip-collector: accept error: {e}"),
        }
    }
    Ok(())
}

/// Emit and persist one signed health record.
fn emit_health(runtime: &Arc<Mutex<CollectorRuntime>>) -> Result<(), String> {
    let rt = runtime
        .lock()
        .map_err(|_| "runtime lock poisoned".to_string())?;
    rt.health(now_ms())
        .map(|_| ())
        .map_err(|e| format!("emit health: {e:?}"))
}

/// Background thread that refreshes the signed health record on a timer.
fn spawn_health_loop(runtime: Arc<Mutex<CollectorRuntime>>) {
    std::thread::spawn(move || loop {
        std::thread::sleep(HEALTH_INTERVAL);
        if let Err(e) = emit_health(&runtime) {
            eprintln!("aip-collector: {e}");
        }
    });
}
