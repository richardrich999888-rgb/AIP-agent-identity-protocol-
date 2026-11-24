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
/// # Gate independence, which is why the last three matter
///
/// A foreign eBPF program attached to a perf tracepoint suppresses that
/// tracepoint's submission host-wide, for every consumer, with no loss
/// accounting (`docs/OBSERVATION_INTEGRITY_REQUIREMENTS.md`). The three
/// tracepoint sensors — `sched`, `sockstate`, `socksend` — all share that
/// one gate, so they are not independent observers of one another.
///
/// `connector`, `fanotify` and `afpacket` each reach the probe by a
/// different kernel facility (netlink, the fanotify queue, an `AF_PACKET`
/// device tap) that a per-tracepoint eBPF program array does not gate.
/// They are what `SourceMechanism::is_gate_independent_kernel_pushed`
/// selects, and they are the coverage the reconciler needs before it will
/// treat silence as evidence of non-occurrence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SensorConfig {
    pub sched: bool,
    /// Cgroup placement events — `cgroup:cgroup_{mkdir,rmdir,attach_task}`
    /// with the acting task's cgroup id (ADR-019). Another perf tracepoint
    /// sensor behind the same eBPF gate as `sched`.
    pub cgroup: bool,
    pub sockstate: bool,
    pub socksend: bool,
    pub connector: bool,
    /// Filesystem events from the fanotify queue (`CAP_SYS_ADMIN`).
    pub fanotify: bool,
    /// Frame headers from an `AF_PACKET` device tap (`CAP_NET_RAW`).
    pub afpacket: bool,
    /// The mount to mark for `fanotify`. Required when `fanotify` is on:
    /// the mark is `FAN_MARK_MOUNT`, so this choice decides how much of the
    /// host the probe watches, and defaulting it would either watch `/` (a
    /// firehose on a busy host) or watch nothing while appearing to work.
    /// From `AIP_PROBE_FANOTIFY_PATH`.
    pub fanotify_path: Option<String>,
    /// The interface to bind the `AF_PACKET` tap to. `None` binds every
    /// device, which is the documented default because a host whose
    /// interfaces change (a container host, a bonded NIC) would otherwise
    /// silently stop seeing the traffic it was configured for. From
    /// `AIP_PROBE_AFPACKET_INTERFACE`.
    pub afpacket_interface: Option<String>,
}

impl SensorConfig {
    /// Any sensor at all is selected.
    fn any(&self) -> bool {
        self.sched
            || self.cgroup
            || self.sockstate
            || self.socksend
            || self.connector
            || self.fanotify
            || self.afpacket
    }

    fn parse(csv: &str) -> Result<Self, String> {
        let mut c = SensorConfig::default();
        for item in csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            match item {
                "sched" => c.sched = true,
                "cgroup" => c.cgroup = true,
                "sockstate" => c.sockstate = true,
                "socksend" => c.socksend = true,
                "connector" => c.connector = true,
                "fanotify" => c.fanotify = true,
                "afpacket" => c.afpacket = true,
                other => return Err(format!("unknown sensor {other:?} in AIP_PROBE_SENSORS")),
            }
        }
        if !c.any() {
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
    /// Immutable approved process-instance filter; absence retains host scope.
    pub filter_path: Option<PathBuf>,
    /// Durable queue, separate from credentials and collector evidence.
    pub spool_dir: PathBuf,
    pub spool_max_bytes: u64,
    pub spool_max_batches: usize,
}

/// An optional, non-empty environment value. An empty string is treated as
/// unset: a variable set to "" in a unit file is an operator leaving it
/// blank, not a request to watch a path named "".
fn optional(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.trim().is_empty() => Some(v.trim().to_string()),
        _ => None,
    }
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

fn validate_probe_id(value: String) -> Result<String, String> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err("AIP_PROBE_ID must be 1..=256 bytes without control characters or surrounding whitespace".into());
    }
    Ok(value)
}

fn parse_interval(value: Option<&str>) -> Result<u64, String> {
    let interval = positive_limit("AIP_PROBE_BATCH_INTERVAL_MS", value, 2000)?;
    if !(100..=60_000).contains(&interval) {
        return Err("AIP_PROBE_BATCH_INTERVAL_MS must be between 100 and 60000 ms".into());
    }
    Ok(interval)
}

fn positive_limit(key: &str, value: Option<&str>, default: u64) -> Result<u64, String> {
    match value {
        None => Ok(default),
        Some(v) => match v.parse::<u64>() {
            Ok(n) if n > 0 => Ok(n),
            _ => Err(format!("{key} must be a positive integer")),
        },
    }
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let batch_interval_ms = parse_interval(optional("AIP_PROBE_BATCH_INTERVAL_MS").as_deref())?;
        let mut sensors = SensorConfig::parse(&require("AIP_PROBE_SENSORS")?)?;
        sensors.fanotify_path = optional("AIP_PROBE_FANOTIFY_PATH");
        sensors.afpacket_interface = optional("AIP_PROBE_AFPACKET_INTERFACE");
        // Fail closed on a fanotify sensor with no mount to mark. The mark is
        // FAN_MARK_MOUNT; without an explicit path the probe would either
        // watch `/` or watch nothing, and both are worse than refusing to
        // start with the reason named.
        if sensors.fanotify && sensors.fanotify_path.is_none() {
            return Err(
                "sensor \"fanotify\" requires AIP_PROBE_FANOTIFY_PATH: the mount \
                        holding this path is marked (FAN_MARK_MOUNT), so it decides how much \
                        of the host the probe watches and has no safe default"
                    .into(),
            );
        }

        let key_path = PathBuf::from(require("AIP_PROBE_KEY_PATH")?);
        let spool_dir = optional("AIP_PROBE_SPOOL_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                key_path
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .join("spool")
            });
        let spool_dir = if spool_dir.is_absolute() {
            spool_dir
        } else {
            std::env::current_dir()
                .map_err(|e| format!("cannot resolve spool directory: {e}"))?
                .join(spool_dir)
        };
        let spool_max_bytes = positive_limit(
            "AIP_PROBE_SPOOL_MAX_BYTES",
            optional("AIP_PROBE_SPOOL_MAX_BYTES").as_deref(),
            256 * 1024 * 1024,
        )?;
        let spool_max_batches = usize::try_from(positive_limit(
            "AIP_PROBE_SPOOL_MAX_BATCHES",
            optional("AIP_PROBE_SPOOL_MAX_BATCHES").as_deref(),
            10_000,
        )?)
        .map_err(|_| "AIP_PROBE_SPOOL_MAX_BATCHES exceeds this platform's capacity")?;

        Ok(Self {
            probe_id: validate_probe_id(require("AIP_PROBE_ID")?)?,
            collector_endpoint: require("AIP_PROBE_COLLECTOR_ENDPOINT")?,
            collector_noise_pubkey: parse_pubkey_hex(
                "AIP_PROBE_COLLECTOR_NOISE_PUBKEY",
                &require("AIP_PROBE_COLLECTOR_NOISE_PUBKEY")?,
            )?,
            key_path,
            sensors,
            batch_interval_ms,
            filter_path: optional("AIP_PROBE_FILTER_PATH").map(PathBuf::from),
            spool_dir,
            spool_max_bytes,
            spool_max_batches,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collection_interval_cannot_disable_draining_with_an_unbounded_sleep() {
        for invalid in ["0", "99", "60001", "18446744073709551615", "garbage"] {
            assert!(parse_interval(Some(invalid)).is_err());
        }
        assert_eq!(parse_interval(None).unwrap(), 2000);
        assert_eq!(parse_interval(Some("100")).unwrap(), 100);
        assert_eq!(parse_interval(Some("60000")).unwrap(), 60000);
    }

    #[test]
    fn probe_identity_is_bounded_for_authenticated_frame_size_and_safe_diagnostics() {
        for invalid in [
            String::new(),
            "x".repeat(257),
            "probe\nother".into(),
            " probe".into(),
        ] {
            assert!(validate_probe_id(invalid).is_err());
        }
        assert_eq!(validate_probe_id("x".repeat(256)).unwrap().len(), 256);
        assert!(validate_probe_id("customer.agent-1".into()).is_ok());
    }

    #[test]
    fn buffering_cannot_be_unbounded_or_silently_disabled_by_invalid_limits() {
        for invalid in ["0", "-1", "", "1.5", "18446744073709551616"] {
            assert!(positive_limit("limit", Some(invalid), 10).is_err());
        }
        assert_eq!(positive_limit("limit", None, 10).unwrap(), 10);
        assert_eq!(positive_limit("limit", Some("2"), 10).unwrap(), 2);
    }

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
                ..SensorConfig::default()
            }
        );
    }

    /// The file and wire sensors parse, and carry their own configuration.
    /// They were a startup error before R8; accepting them is the change.
    #[test]
    fn the_file_and_wire_sensors_are_supported() {
        let c = SensorConfig::parse("fanotify,afpacket").unwrap();
        assert!(c.fanotify && c.afpacket);
        assert!(!c.sched && !c.sockstate && !c.socksend && !c.connector);
        // They can be selected alongside the rest.
        let all =
            SensorConfig::parse("sched,sockstate,socksend,connector,fanotify,afpacket").unwrap();
        assert!(all.any() && all.fanotify && all.afpacket && all.connector);
    }

    /// The placement sensor parses on its own and alongside `sched`.
    #[test]
    fn the_cgroup_placement_sensor_is_supported() {
        let alone = SensorConfig::parse("cgroup").unwrap();
        assert!(alone.cgroup && !alone.sched && alone.any());
        let with = SensorConfig::parse("sched,cgroup").unwrap();
        assert!(with.cgroup && with.sched);
    }

    /// An unknown sensor is still refused — accepting two new names must not
    /// turn the parser permissive.
    #[test]
    fn an_unknown_sensor_is_still_refused() {
        assert!(SensorConfig::parse("fanotify,ebpf")
            .unwrap_err()
            .contains("ebpf"));
    }

    #[test]
    fn the_connector_is_a_supported_sensor_on_its_own_or_with_tracepoints() {
        let alone = SensorConfig::parse("connector").unwrap();
        assert!(alone.connector && !alone.sched && !alone.sockstate && !alone.socksend);
        let with = SensorConfig::parse("sched,sockstate,connector").unwrap();
        assert!(with.connector && with.sched && with.sockstate);
    }

    /// `fanotify` and `afpacket` used to be refused here as Phase 1.x. R8
    /// drives them, so they parse (see `the_file_and_wire_sensors_are_supported`);
    /// what must still be refused is a name the probe cannot drive at all,
    /// and an empty selection.
    #[test]
    fn rejects_unknown_and_empty_sensor_selections() {
        assert!(SensorConfig::parse("sched,fanotify").is_ok());
        assert!(SensorConfig::parse("connector,afpacket").is_ok());
        assert!(SensorConfig::parse("bogus").is_err());
        assert!(SensorConfig::parse("").is_err());
        assert!(SensorConfig::parse("  ,  ").is_err());
    }
}
