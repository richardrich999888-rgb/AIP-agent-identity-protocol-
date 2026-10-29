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
    /// Receive-buffer size requested for the netlink process connector, in
    /// bytes. `None` leaves the kernel default (`net.core.rmem_default`,
    /// typically 208 KiB).
    ///
    /// The connector has no ring and no LOST record: when its socket queue
    /// overflows between two drains the kernel returns `ENOBUFS`, which is
    /// counted loss and degrades the whole epoch. At the kernel default a
    /// burst of a few hundred process events inside one batch interval
    /// overflows it — measured: every pilot run lost an event in its first
    /// batch, so the honest path could never reach `Active`. From
    /// `AIP_PROBE_CONNECTOR_RCVBUF_BYTES`; unset means
    /// [`DEFAULT_CONNECTOR_RCVBUF_BYTES`], `0` means the kernel default.
    pub connector_rcvbuf_bytes: Option<u32>,
}

/// Production default connector receive buffer: 8 MiB. Requested with
/// `SO_RCVBUFFORCE` (the probe already holds `CAP_NET_ADMIN` to open the
/// connector), so it is not clamped by `net.core.rmem_max`. Loss is still
/// counted if it still occurs; this only makes genuine overflow rarer.
pub const DEFAULT_CONNECTOR_RCVBUF_BYTES: u32 = 8 * 1024 * 1024;

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

/// `AIP_PROBE_CONNECTOR_RCVBUF_BYTES`: unset → the production default, `0` →
/// the kernel default (kept so the old behavior can be reproduced), any other
/// value → that many bytes. Not a number, or above `i32::MAX` (the socket
/// option's type), refuses to start.
fn parse_connector_rcvbuf(value: Option<&str>) -> Result<Option<u32>, String> {
    match value {
        None => Ok(Some(DEFAULT_CONNECTOR_RCVBUF_BYTES)),
        Some(v) => {
            let n = v
                .parse::<u32>()
                .map_err(|e| format!("AIP_PROBE_CONNECTOR_RCVBUF_BYTES: {e}"))?;
            if n > i32::MAX as u32 {
                return Err(format!(
                    "AIP_PROBE_CONNECTOR_RCVBUF_BYTES: {n} exceeds {}",
                    i32::MAX
                ));
            }
            Ok((n != 0).then_some(n))
        }
    }
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
        let mut sensors = SensorConfig::parse(&require("AIP_PROBE_SENSORS")?)?;
        sensors.fanotify_path = optional("AIP_PROBE_FANOTIFY_PATH");
        sensors.afpacket_interface = optional("AIP_PROBE_AFPACKET_INTERFACE");
        sensors.connector_rcvbuf_bytes =
            parse_connector_rcvbuf(optional("AIP_PROBE_CONNECTOR_RCVBUF_BYTES").as_deref())?;
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

        Ok(Self {
            probe_id: require("AIP_PROBE_ID")?,
            collector_endpoint: require("AIP_PROBE_COLLECTOR_ENDPOINT")?,
            collector_noise_pubkey: parse_pubkey_hex(
                "AIP_PROBE_COLLECTOR_NOISE_PUBKEY",
                &require("AIP_PROBE_COLLECTOR_NOISE_PUBKEY")?,
            )?,
            key_path: PathBuf::from(require("AIP_PROBE_KEY_PATH")?),
            sensors,
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
    fn the_connector_receive_buffer_defaults_large_and_zero_means_kernel_default() {
        assert_eq!(
            parse_connector_rcvbuf(None).unwrap(),
            Some(DEFAULT_CONNECTOR_RCVBUF_BYTES)
        );
        assert_eq!(parse_connector_rcvbuf(Some("0")).unwrap(), None);
        assert_eq!(
            parse_connector_rcvbuf(Some("1048576")).unwrap(),
            Some(1_048_576)
        );
        assert!(parse_connector_rcvbuf(Some("big")).is_err());
        assert!(parse_connector_rcvbuf(Some("-1")).is_err());
        assert!(parse_connector_rcvbuf(Some("3000000000")).is_err());
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
