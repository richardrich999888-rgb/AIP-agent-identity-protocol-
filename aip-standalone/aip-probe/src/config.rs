//! Probe configuration from the environment, validated at startup.

use std::path::PathBuf;

/// Which kernel-mediated sensors this probe opens. Phase 1 drives the three
/// perf-tracepoint sensors and the netlink process-event connector. The
/// connector matters beyond what it observes: it is the only mechanism whose
/// coverage the reconciler accepts for a statement about process lifecycle
/// (`SourceMechanism::covers_process_lifecycle`), and it is
/// **gate-independent** — a foreign eBPF program on a tracepoint cannot
/// silence it — so without it the pilot's observer can never license a
/// non-occurrence claim and `PHANTOM_CLAIM` is unreachable. It needs
/// `CAP_NET_ADMIN` in the initial network namespace (see the systemd unit).
///
/// fanotify and AF_PACKET remain Phase 1.x: requesting one is a startup error
/// rather than a silent no-op.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SensorConfig {
    pub sched: bool,
    pub sockstate: bool,
    pub socksend: bool,
    pub connector: bool,
}

impl SensorConfig {
    fn parse(csv: &str) -> Result<Self, String> {
        let mut c = SensorConfig::default();
        for item in csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            match item {
                "sched" => c.sched = true,
                "sockstate" => c.sockstate = true,
                "socksend" => c.socksend = true,
                "connector" => c.connector = true,
                "fanotify" | "afpacket" => {
                    return Err(format!(
                        "sensor {item:?} is part of the pilot design but not yet driven by \
                         aip-probe (Phase 1.x); remove it from AIP_PROBE_SENSORS for now"
                    ))
                }
                other => return Err(format!("unknown sensor {other:?} in AIP_PROBE_SENSORS")),
            }
        }
        if !(c.sched || c.sockstate || c.socksend || c.connector) {
            return Err("AIP_PROBE_SENSORS selected no supported sensor".into());
        }
        Ok(c)
    }
}

/// Fully validated probe configuration.
pub struct Config {
    pub probe_id: String,
    pub collector_endpoint: String,
    /// The collector's Noise static public key, pinned (R9). Without it the
    /// probe does not start: there is no plaintext mode in the daemon.
    pub collector_noise_pubkey: [u8; 32],
    pub key_path: PathBuf,
    pub sensors: SensorConfig,
    pub batch_interval_ms: u64,
}

fn require(key: &str) -> Result<String, String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err(format!("{key} is required and must be non-empty")),
    }
}

/// Exactly 32 bytes of hex, or a named error. The collector prints this value
/// at every start; a truncated paste is the likely failure and is named.
fn parse_pubkey_hex(key: &str, value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value.trim()).map_err(|e| format!("{key}: not hex: {e}"))?;
    bytes.as_slice().try_into().map_err(|_| {
        format!(
            "{key}: expected 32 bytes (64 hex digits), got {} bytes; copy the full value the \
             collector prints at start",
            bytes.len()
        )
    })
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let batch_interval_ms = match std::env::var("AIP_PROBE_BATCH_INTERVAL_MS") {
            Ok(v) if !v.is_empty() => v
                .parse::<u64>()
                .map_err(|e| format!("AIP_PROBE_BATCH_INTERVAL_MS: {e}"))?
                .max(100),
            _ => 2000,
        };
        Ok(Self {
            probe_id: require("AIP_PROBE_ID")?,
            collector_endpoint: require("AIP_PROBE_COLLECTOR_ENDPOINT")?,
            collector_noise_pubkey: parse_pubkey_hex(
                "AIP_PROBE_COLLECTOR_NOISE_PUBKEY",
                &require("AIP_PROBE_COLLECTOR_NOISE_PUBKEY")?,
            )?,
            key_path: PathBuf::from(require("AIP_PROBE_KEY_PATH")?),
            sensors: SensorConfig::parse(&require("AIP_PROBE_SENSORS")?)?,
            batch_interval_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pinned_collector_key_must_be_exactly_32_bytes_of_hex() {
        let ok = "ab".repeat(32);
        assert_eq!(parse_pubkey_hex("K", &ok).unwrap(), [0xab; 32]);
        assert!(parse_pubkey_hex("K", &"ab".repeat(31))
            .unwrap_err()
            .contains("got 31 bytes"));
        assert!(parse_pubkey_hex("K", "zz").unwrap_err().contains("not hex"));
    }

    #[test]
    fn parses_supported_sensors() {
        let c = SensorConfig::parse("sched, sockstate").unwrap();
        assert_eq!(
            c,
            SensorConfig {
                sched: true,
                sockstate: true,
                socksend: false,
                connector: false,
            }
        );
    }

    #[test]
    fn the_connector_is_a_supported_sensor_on_its_own_or_with_tracepoints() {
        let alone = SensorConfig::parse("connector").unwrap();
        assert!(alone.connector && !alone.sched && !alone.sockstate && !alone.socksend);
        let with = SensorConfig::parse("sched,sockstate,connector").unwrap();
        assert!(with.connector && with.sched && with.sockstate);
    }

    #[test]
    fn rejects_unsupported_and_unknown_sensors() {
        assert!(SensorConfig::parse("sched,fanotify").is_err());
        assert!(SensorConfig::parse("connector,afpacket").is_err());
        assert!(SensorConfig::parse("bogus").is_err());
        assert!(SensorConfig::parse("").is_err());
    }
}
