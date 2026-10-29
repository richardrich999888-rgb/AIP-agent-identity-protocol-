//! `aip-probe` — the host-side observation probe daemon (Phase 1).
//!
//! Runs on each observed agent host. It drives `aip-observe`'s kernel-mediated
//! sensors, builds an [`aip_observe::ObservationBatch`] each cycle, and ships it
//! to the off-host collector over the authenticated [`aip_transport`] channel.
//!
//! It holds a **transport-auth** key only. It holds **no** evidence-signing key
//! and has no method to attest an observation — the collector does that,
//! off-host. A compromise of this daemon can submit false observations (which
//! the collector's registry and the reconciler's `CANNOT_PROVE` default bound);
//! it cannot forge an attestation.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aip_transport::TransportClient;

use aip_probe::config::Config;
use aip_probe::keyfile::TransportKey;
use aip_probe::sensors::SensorSet;

/// Handshake/read/write timeout for the collector connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Wait before reconnecting after a transport failure.
const RECONNECT_BACKOFF: Duration = Duration::from_secs(3);

fn main() {
    std::process::exit(match run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("aip-probe: {e}");
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
    let key = TransportKey::load_or_generate(&cfg.key_path)?;
    // Opening the sensors is fail-closed: a requested-but-unavailable sensor
    // aborts startup rather than running blind.
    let mut sensors = SensorSet::open(&cfg.probe_id, cfg.sensors)?;
    eprintln!(
        "aip-probe: {:?} sensors open; shipping to {} every {} ms",
        cfg.probe_id, cfg.collector_endpoint, cfg.batch_interval_ms
    );
    let interval = Duration::from_millis(cfg.batch_interval_ms);
    let drain_interval = Duration::from_millis(cfg.drain_interval_ms);

    // Outer loop: (re)connect. Inner loop: ship batches until a transport error.
    loop {
        let mut client = match TransportClient::connect_confidential(
            &cfg.collector_endpoint,
            &cfg.collector_noise_pubkey,
            &cfg.probe_id,
            &key.private,
            &key.public,
            CONNECT_TIMEOUT,
        ) {
            Ok(c) => {
                eprintln!("aip-probe: connected to {}", cfg.collector_endpoint);
                c
            }
            Err(e) => {
                eprintln!("aip-probe: connect failed: {e}; retrying in {RECONNECT_BACKOFF:?}");
                std::thread::sleep(RECONNECT_BACKOFF);
                continue;
            }
        };

        let mut window_open = now_ms();
        loop {
            // Drain between batches so identity is bound while processes
            // still exist (see `SensorSet::drain`); ship once per interval.
            let deadline = std::time::Instant::now() + interval;
            while std::time::Instant::now() + drain_interval < deadline {
                std::thread::sleep(drain_interval);
                sensors.drain();
            }
            std::thread::sleep(deadline.saturating_duration_since(std::time::Instant::now()));
            let window_close = now_ms();
            let batch = sensors.collect_batch(window_open, window_close);
            let bytes = match serde_json::to_vec(&batch) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("aip-probe: encode batch failed: {e}; skipping this cycle");
                    continue;
                }
            };
            match client.send_batch(&bytes) {
                Ok(ack) => {
                    // Advance the window only on a confirmed attestation. A
                    // failed cycle's events are not re-sent in this cut; the
                    // collector sees the gap and reports it (never a
                    // fabrication). Durable buffering is Phase 1.x.
                    window_open = window_close;
                    eprintln!(
                        "aip-probe: batch acked (frame seq {}, attested_sequence {})",
                        ack.seq, ack.attested_sequence
                    );
                }
                Err(e) => {
                    eprintln!("aip-probe: send failed: {e}; reconnecting");
                    break;
                }
            }
        }
        std::thread::sleep(RECONNECT_BACKOFF);
    }
}
