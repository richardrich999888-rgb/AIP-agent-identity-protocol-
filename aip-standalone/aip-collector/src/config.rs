//! Collector configuration, parsed from the environment. Every value is
//! validated here so the daemon fails at startup with a clear message rather
//! than deep in the serve loop. No default is silently permissive: the
//! passphrase and key path have no defaults, and the continuity policy defaults
//! to the safe (strict) value.

use std::path::PathBuf;

use aip_observe::ContinuityPolicy;

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
        })
    }
}
