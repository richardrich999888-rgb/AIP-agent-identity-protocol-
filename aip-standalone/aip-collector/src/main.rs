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
    // E4: the clock gate, before anything is signed. The collector stamps
    // every attested batch, so starting with an undisciplined clock does not
    // produce one wrong timestamp -- it produces an archive that is wrong
    // together and self-consistent, which nothing in the sealed bytes
    // afterwards reveals. Fail closed; the override is explicit.
    match aip_observe::clock::clock_discipline() {
        Ok(d) => {
            eprintln!("aip-collector: {}", d.summary());
            if cfg.clock.required && !d.within(cfg.clock.max_error_ms) {
                return Err(format!(
                    "refusing to start: {}, which exceeds the {} ms budget. This host stamps \
                     and signs every attested batch, so its clock discipline is the accuracy \
                     of all of it (CERT-In Direction 20(3)/2022 requires NTP-synchronised \
                     clocks; see deploy/pilot/chrony-cert-in.conf). Fix the time daemon, \
                     widen AIP_COLLECTOR_CLOCK_MAX_ERROR_MS, or set \
                     AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=0 to accept the consequence \
                     deliberately.",
                    d.summary(),
                    cfg.clock.max_error_ms
                ));
            }
        }
        Err(e) => {
            // Unreadable is not the same as unsynchronised, and is not
            // treated as one: it is reported, and the policy decides.
            eprintln!("aip-collector: clock discipline unreadable: {e}");
            if cfg.clock.required {
                return Err(format!(
                    "refusing to start: the clock's discipline could not be read ({e}), so it \
                     cannot be shown to meet the {} ms budget. Set \
                     AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=0 to proceed without the check.",
                    cfg.clock.max_error_ms
                ));
            }
        }
    }

    let store = CollectorStore::open(&cfg.state_dir).map_err(|e| format!("open store: {e:?}"))?;

    // Load the wrapped signing key on the collector host. `production` refuses a
    // development backend; the raw key is never exposed.
    let key = CollectorKey::production(&cfg.key_path, &cfg.passphrase)
        .map_err(|e| format!("load collector key: {e}"))?;

    // Publish the evidence PUBLIC key. A verifier checks an attested batch
    // against anchors the institution holds, so somebody has to be able to
    // hand the auditor this value -- and until now the only way to obtain it
    // was to unwrap the private key with the passphrase, which is precisely
    // what custody exists to prevent. It is written beside the state and
    // echoed at every start; it is public, and nothing about it is sensitive.
    let evidence_pub = publish_public_value(&cfg.state_dir, "observer.pub", key.public_key());
    eprintln!(
        "aip-collector: evidence public key ({} v{}), give this to the auditor: {}",
        cfg.observer_id, cfg.key_version, evidence_pub
    );

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
    // Written to a file as well as the log. Scraping a log for "the 64 hex
    // characters" is how an operator ends up pinning whichever public value
    // the daemon happened to print first; a named file cannot be confused
    // with another key.
    let noise_pub = publish_public_value(&cfg.state_dir, "noise.pub", noise_key.public());
    eprintln!(
        "aip-collector: noise static public key (pin in AIP_PROBE_COLLECTOR_NOISE_PUBKEY): {noise_pub}"
    );

    // Emit an initial signed health record, then keep it fresh on a timer so a
    // verifier can bound coverage against a recent, signed statement.
    emit_health(&runtime)?;
    spawn_health_loop(runtime.clone());

    let listener =
        TcpListener::bind(&cfg.listen).map_err(|e| format!("bind {}: {e}", cfg.listen))?;
    eprintln!(
        "aip-collector: attested batches are appended to {}",
        cfg.attested_archive_path.display()
    );
    eprintln!("aip-collector: listening on {}", cfg.listen);

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let runtime = runtime.clone();
                let authority = authority.clone();
                let noise_key = noise_key.clone();
                let archive_path = cfg.attested_archive_path.clone();
                std::thread::spawn(move || {
                    let peer = stream
                        .peer_addr()
                        .map(|a| a.to_string())
                        .unwrap_or_else(|_| "<unknown>".into());
                    let mut sink = RuntimeSink::with_archive(runtime, &archive_path);
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

/// Write a public key beside the collector's state and return it as hex.
///
/// These values are public by construction: the evidence-verification anchor
/// and the Noise static public key a probe pins. Publishing them as files is
/// an operational control, not a convenience. Before this existed the only
/// way to obtain the evidence anchor was to unwrap the private key with the
/// passphrase -- precisely what custody exists to prevent -- and the only way
/// to obtain the Noise key was to parse it out of a log line.
///
/// A write failure is a warning, not a fatal error: the value is also printed,
/// and a collector that can attest should not refuse to serve because a
/// convenience file could not be created. Nothing downstream reads these
/// files as authority; they are a copy of what the daemon already announced.
fn publish_public_value(state_dir: &std::path::Path, name: &str, key: &[u8]) -> String {
    let hex_text = hex::encode(key);
    let path = state_dir.join(name);
    if let Err(e) = std::fs::write(&path, format!("{hex_text}\n")) {
        eprintln!(
            "aip-collector: warning: could not write {}: {e}",
            path.display()
        );
    }
    hex_text
}

/// Emit and persist one signed health record.
/// Report clock discipline alongside health. A clock that was disciplined
/// at start and has since lost its daemon is exactly the case a start-only
/// check misses.
fn report_clock() {
    match aip_observe::clock::clock_discipline() {
        Ok(d) => eprintln!("aip-collector: {}", d.summary()),
        Err(e) => eprintln!("aip-collector: clock discipline unreadable: {e}"),
    }
}

fn emit_health(runtime: &Arc<Mutex<CollectorRuntime>>) -> Result<(), String> {
    // Read the clock HERE, at the daemon boundary, and hand the reading to
    // the signer. The signing crate performs no syscalls on this path, so
    // what it signs is exactly what this process observed and nothing it
    // went and fetched for itself.
    //
    // A failed read becomes `None`, which a verifier reads as "the collector
    // said nothing about its clock" -- never as "the clock was fine". The
    // policy decision about an undisciplined clock belongs to the startup
    // gate and to the operator, not to the health emitter, which must keep
    // emitting: a collector that stops signing health because it could not
    // read its clock would withdraw coverage for a reason unrelated to
    // coverage.
    let clock = aip_observe::clock::clock_discipline()
        .ok()
        .map(aip_observe::AttestedClock::from);
    let rt = runtime
        .lock()
        .map_err(|_| "runtime lock poisoned".to_string())?;
    rt.health_with_clock(now_ms(), clock)
        .map(|_| ())
        .map_err(|e| format!("emit health: {e:?}"))
}

/// Background thread that refreshes the signed health record on a timer.
fn spawn_health_loop(runtime: Arc<Mutex<CollectorRuntime>>) {
    std::thread::spawn(move || loop {
        std::thread::sleep(HEALTH_INTERVAL);
        report_clock();
        if let Err(e) = emit_health(&runtime) {
            eprintln!("aip-collector: {e}");
        }
    });
}
