//! Collector configuration, parsed from the environment. Every value is
//! validated here so the daemon fails at startup with a clear message rather
//! than deep in the serve loop. No default is silently permissive: the
//! passphrase and key path have no defaults, and the continuity policy defaults
//! to the safe (strict) value.

use std::path::PathBuf;

use aip_observe::ContinuityPolicy;

/// What the collector requires of its own clock before it will sign (E4).
///
/// CERT-In Direction 20(3)/2022 requires NTP-synchronised clocks. The
/// collector is the host that stamps and signs, so an undisciplined clock
/// here does not produce one wrong timestamp — it produces a whole archive
/// of evidence that is wrong together and self-consistent, which is worse
/// than an obvious gap because nothing in the sealed bytes reveals it.
///
/// So the default is to refuse to start. `required: false` is the explicit
/// opt-out for a lab or a container with no time daemon, and it is a
/// deliberate act rather than a silent fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockPolicy {
    /// Refuse to start when the clock is outside the budget. Default true.
    pub required: bool,
    /// Maximum acceptable kernel error bound, in milliseconds.
    pub max_error_ms: i64,
}

impl Default for ClockPolicy {
    fn default() -> Self {
        // One second: far wider than a working NTP client needs (tens of
        // milliseconds) and far tighter than the multi-second drift of a
        // host nothing is steering.
        Self {
            required: true,
            max_error_ms: 1000,
        }
    }
}

impl ClockPolicy {
    pub fn from_env() -> Result<Self, String> {
        let d = Self::default();
        let required = match std::env::var("AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK").as_deref() {
            Ok("0") | Ok("false") => false,
            Ok("1") | Ok("true") | Err(_) => true,
            Ok(other) => {
                return Err(format!(
                    "AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK={other:?} is not a boolean; \
                     use 1/true or 0/false. A clock control disabled by a typo is worse \
                     than none, because it reads as present"
                ))
            }
        };
        let max_error_ms = match std::env::var("AIP_COLLECTOR_CLOCK_MAX_ERROR_MS") {
            Ok(v) if !v.trim().is_empty() => v
                .trim()
                .parse::<i64>()
                .map_err(|e| format!("AIP_COLLECTOR_CLOCK_MAX_ERROR_MS={v:?}: {e}"))
                .and_then(|n| {
                    if n > 0 {
                        Ok(n)
                    } else {
                        Err("AIP_COLLECTOR_CLOCK_MAX_ERROR_MS must be positive".to_string())
                    }
                })?,
            _ => d.max_error_ms,
        };
        Ok(Self {
            required,
            max_error_ms,
        })
    }
}

/// Fully validated collector configuration.
pub struct Config {
    pub observer_id: String,
    pub key_version: u32,
    pub key_path: PathBuf,
    pub passphrase: Vec<u8>,
    pub continuity: ContinuityPolicy,
    pub state_dir: PathBuf,
    pub listen: String,
    pub probes_path: PathBuf,
    /// The Noise static keypair file (R9). Generated 0600 on first start.
    pub noise_key_path: PathBuf,
    /// Where attested batches are appended (`attested.archive.jsonl` in the
    /// state directory unless overridden). This file is the evidence an
    /// auditor verifies offline; without it the Phase 1 exit gate cannot be
    /// met, because nothing signed survives the acknowledgement.
    pub attested_archive_path: PathBuf,
    /// Clock-discipline policy (E4). The collector stamps and signs, so an
    /// undisciplined clock here poisons every `host_wall_clock_ms` it
    /// attests — together, and invisibly.
    pub clock: ClockPolicy,
}

fn require(key: &str) -> Result<String, String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err(format!("{key} is required and must be non-empty")),
    }
}

/// Load the wrapped-key passphrase from a credential file. Two sources, in
/// order: `AIP_COLLECTOR_PASSPHRASE_FILE`, then a systemd credential named
/// `collector-passphrase` under `$CREDENTIALS_DIRECTORY`. Never from a plain
/// environment variable (it would persist in `/proc/<pid>/environ`) and never
/// with a default (fail closed). A single trailing newline is trimmed.
fn load_passphrase() -> Result<Vec<u8>, String> {
    let path = if let Ok(p) = std::env::var("AIP_COLLECTOR_PASSPHRASE_FILE") {
        PathBuf::from(p)
    } else if let Ok(dir) = std::env::var("CREDENTIALS_DIRECTORY") {
        PathBuf::from(dir).join("collector-passphrase")
    } else {
        return Err(
            "no passphrase source: set AIP_COLLECTOR_PASSPHRASE_FILE or run with a systemd \
             LoadCredential=collector-passphrase"
                .into(),
        );
    };
    let mut bytes = std::fs::read(&path)
        .map_err(|e| format!("cannot read passphrase file {}: {e}", path.display()))?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Err(format!("passphrase file {} is empty", path.display()));
    }
    Ok(bytes)
}

fn parse_continuity(v: &str) -> Result<ContinuityPolicy, String> {
    match v {
        "strict" => Ok(ContinuityPolicy::Strict),
        "advisory" => Ok(ContinuityPolicy::Advisory),
        other => Err(format!(
            "AIP_COLLECTOR_CONTINUITY must be 'strict' or 'advisory', got {other:?}"
        )),
    }
}

impl Config {
    /// Read and validate the whole configuration from the environment.
    pub fn from_env() -> Result<Self, String> {
        let key_version = match std::env::var("AIP_COLLECTOR_KEY_VERSION") {
            Ok(v) if !v.is_empty() => v
                .parse::<u32>()
                .map_err(|e| format!("AIP_COLLECTOR_KEY_VERSION: {e}"))?,
            _ => 1,
        };
        let continuity = match std::env::var("AIP_COLLECTOR_CONTINUITY") {
            Ok(v) if !v.is_empty() => parse_continuity(&v)?,
            _ => ContinuityPolicy::Strict,
        };
        Ok(Self {
            observer_id: require("AIP_COLLECTOR_OBSERVER_ID")?,
            key_version,
            key_path: PathBuf::from(require("AIP_COLLECTOR_KEY_PATH")?),
            passphrase: load_passphrase()?,
            continuity,
            state_dir: PathBuf::from(require("AIP_COLLECTOR_STATE_DIR")?),
            listen: require("AIP_COLLECTOR_LISTEN")?,
            probes_path: PathBuf::from(require("AIP_COLLECTOR_PROBES_PATH")?),
            noise_key_path: PathBuf::from(require("AIP_COLLECTOR_NOISE_KEY_PATH")?),
            attested_archive_path: match std::env::var("AIP_COLLECTOR_ATTESTED_ARCHIVE_PATH") {
                Ok(v) if !v.trim().is_empty() => PathBuf::from(v.trim()),
                _ => PathBuf::from(require("AIP_COLLECTOR_STATE_DIR")?)
                    .join("attested.archive.jsonl"),
            },
            clock: ClockPolicy::from_env()?,
        })
    }
}
