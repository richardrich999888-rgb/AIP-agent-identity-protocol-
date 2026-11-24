//! The Linux probe retains unsigned observations durably before delivery.
//! Only the separately managed collector holds an evidence-signing key.

use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aip_probe::config::Config;
use aip_probe::filter::AgentFilter;
use aip_probe::keyfile::TransportKey;
use aip_probe::sensors::SensorSet;
use aip_probe::spool::DurableSpool;
use aip_transport::TransportClient;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RECONNECT_BACKOFF: Duration = Duration::from_secs(3);

fn main() {
    std::process::exit(match run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("aip-probe: stopped: {e}; unsent durable records are retained; observation coverage must not be inferred across this stop");
            1
        }
    });
}

fn now_ms() -> Result<u64, String> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("host wall clock is before the epoch: {e}"))?;
    u64::try_from(elapsed.as_millis()).map_err(|_| "host wall clock overflow".into())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !args.is_empty() {
        if args.len() == 2 && args[0] == "init-transport-key" {
            let key = TransportKey::load_or_generate(std::path::Path::new(&args[1]))?;
            println!("{}", hex::encode(key.public));
            return Ok(());
        }
        if args.len() == 2 && args[0] == "validate-filter" {
            AgentFilter::load(std::path::Path::new(&args[1]))?;
            println!("filter valid: immutable process-instance selection; no host-wide completeness claim");
            return Ok(());
        }
        if args.len() == 3 && args[0] == "enroll-filter" {
            let pid = args[2]
                .parse::<u32>()
                .map_err(|_| "PID must be an unsigned integer")?;
            println!("{}", AgentFilter::enroll(&args[1], pid)?.to_json()?);
            return Ok(());
        }
        return Err(
            "usage: aip-probe [init-transport-key PATH | enroll-filter AGENT_LABEL PID | validate-filter PATH]".into(),
        );
    }
    let cfg = Config::from_env()?;
    let filter = cfg
        .filter_path
        .as_ref()
        .map(|path| AgentFilter::load(path))
        .transpose()?;
    let key = TransportKey::load_or_generate(&cfg.key_path)?;
    let spool = Arc::new(Mutex::new(DurableSpool::open_bound(
        &cfg.spool_dir,
        cfg.spool_max_bytes,
        cfg.spool_max_batches,
        &cfg.probe_id,
        &cfg.collector_noise_pubkey,
    )?));
    // All requested sensors must open. A fresh run ID records restarts even
    // while earlier runs still have queued batches; none are relabelled.
    let mut sensors = SensorSet::open(&cfg.probe_id, cfg.sensors)?;
    let mut window_open = now_ms()?;
    let interval = Duration::from_millis(cfg.batch_interval_ms);
    eprintln!(
        "aip-probe: sensors open; filter={}; durable queue limits {} bytes / {} batches",
        if filter.is_some() {
            "approved process instances"
        } else {
            "host scope"
        },
        cfg.spool_max_bytes,
        cfg.spool_max_batches
    );
    let (fatal_tx, fatal_rx) = mpsc::channel::<String>();
    let sending_spool = Arc::clone(&spool);
    // Network calls never hold the queue lock or stop the sensor collection
    // loop. A full or damaged queue stops the daemon, never evicts evidence.
    std::thread::Builder::new()
        .name("collector-delivery".into())
        .spawn(move || {
            let result = deliver(
                sending_spool,
                &cfg.collector_endpoint,
                &cfg.collector_noise_pubkey,
                &cfg.probe_id,
                &key.private,
                &key.public,
            );
            let message = result
                .err()
                .unwrap_or_else(|| "delivery worker unexpectedly exited".into());
            let _ = fatal_tx.send(message);
        })
        .map_err(|e| format!("cannot start delivery worker: {e}"))?;

    loop {
        // Worker failures wake collection immediately, even at the largest
        // permitted sampling interval.
        match fatal_rx.recv_timeout(interval) {
            Ok(error) => return Err(error),
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err("delivery worker lost".into()),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        let window_close = now_ms()?;
        if window_close < window_open {
            return Err("host wall clock moved backwards during collection".into());
        }
        let batch = sensors.collect_batch(window_open, window_close)?;
        let batch = match &filter {
            Some(f) => f.apply(batch)?,
            None => batch,
        };
        let bytes = serde_json::to_vec(&batch).map_err(|e| format!("encode batch: {e}"))?;
        let mut pending = spool.lock().map_err(|_| "durable queue lock poisoned")?;
        pending.enqueue(&bytes)?;
        eprintln!(
            "aip-probe: durably queued; pending {} batches / {} bytes",
            pending.len(),
            pending.pending_bytes()
        );
        drop(pending);
        // The next interval follows actual collection, never collector ACK
        // time. Replays preserve the original claimed windows and sequences.
        window_open = window_close;
    }
}

fn deliver(
    spool: Arc<Mutex<DurableSpool>>,
    endpoint: &str,
    collector_key: &[u8; 32],
    probe_id: &str,
    private: &[u8],
    public: &[u8; 32],
) -> Result<(), String> {
    loop {
        let mut client = match TransportClient::connect_confidential(
            endpoint,
            collector_key,
            probe_id,
            private,
            public,
            CONNECT_TIMEOUT,
        ) {
            Ok(client) => client,
            Err(error) => {
                eprintln!("aip-probe: collector unavailable: {error}; collection continues into durable queue");
                std::thread::sleep(RECONNECT_BACKOFF);
                continue;
            }
        };
        loop {
            let entry = spool
                .lock()
                .map_err(|_| "durable queue lock poisoned")?
                .front()?;
            let Some(entry) = entry else {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            };
            match client.send_batch(&entry.bytes) {
                Ok(ack) => {
                    // Noise authenticates the collector ACK; the collector
                    // issues it only after archive and continuity persistence.
                    spool
                        .lock()
                        .map_err(|_| "durable queue lock poisoned")?
                        .acknowledge(&entry)?;
                    eprintln!(
                        "aip-probe: batch acked (frame seq {}, attested_sequence {})",
                        ack.seq, ack.attested_sequence
                    );
                }
                Err(error) => {
                    eprintln!("aip-probe: delivery unconfirmed: {error}; retaining original batch for replay");
                    break;
                }
            }
        }
        std::thread::sleep(RECONNECT_BACKOFF);
    }
}
