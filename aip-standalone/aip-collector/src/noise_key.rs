//! The collector's **Noise static keypair** (R9): the X25519 key every probe
//! pins to open a confidential session. Load it, or generate it on first
//! run.
//!
//! It is the collector's third key and must not be confused with the other
//! two. The evidence-signing key attests observations; the probe's
//! transport-auth key says which host may submit. This one makes the link
//! unreadable to a network observer. Compromising it lets an attacker who
//! is also on the network path read future sessions' metadata; it does not
//! let them forge an attestation or submit as a probe.

use std::path::Path;

use aip_transport::StaticKeypair;
use serde::{Deserialize, Serialize};

/// On-disk form, hex-encoded, written `0600`.
#[derive(Debug, Serialize, Deserialize)]
pub struct NoiseKeyFile {
    pub private_hex: String,
    pub public_hex: String,
}

impl NoiseKeyFile {
    /// Load the keypair at `path`, or generate and persist one on first run.
    ///
    /// The public key is announced so the operator can pin it in each
    /// probe's `AIP_PROBE_COLLECTOR_NOISE_PUBKEY`. A loaded pair is
    /// **proven** to be a pair before it is used — a file whose halves were
    /// edited or swapped is refused here with a named error, not discovered
    /// as every probe failing to connect.
    pub fn load_or_generate(path: &Path) -> Result<StaticKeypair, String> {
        if path.exists() {
            let bytes = std::fs::read(path)
                .map_err(|e| format!("cannot read noise key {}: {e}", path.display()))?;
            let file: NoiseKeyFile = serde_json::from_slice(&bytes)
                .map_err(|e| format!("noise key {} is not valid JSON: {e}", path.display()))?;
            file.decode()
        } else {
            let (private, public) =
                StaticKeypair::generate_parts().map_err(|e| format!("generate noise key: {e}"))?;
            let file = NoiseKeyFile {
                private_hex: hex::encode(private.as_slice()),
                public_hex: hex::encode(public),
            };
            drop(private);
            let json = serde_json::to_vec_pretty(&file).map_err(|e| format!("encode key: {e}"))?;
            write_private(path, &json)?;
            eprintln!(
                "aip-collector: generated a new noise static key at {}. Pin this public key in \
                 every probe's AIP_PROBE_COLLECTOR_NOISE_PUBKEY:\n  {}",
                path.display(),
                file.public_hex
            );
            file.decode()
        }
    }

    fn decode(&self) -> Result<StaticKeypair, String> {
        let private = hex::decode(&self.private_hex)
            .map_err(|e| format!("noise private key is not hex: {e}"))?;
        let public = hex::decode(&self.public_hex)
            .map_err(|e| format!("noise public key is not hex: {e}"))?;
        StaticKeypair::from_parts(&private, &public).map_err(|e| format!("noise key: {e}"))
    }
}

/// Write a file with `0600` permissions where the platform supports it. The
/// key is a credential; it is never world-readable.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes)
        .map_err(|e| format!("cannot write noise key {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("cannot chmod noise key {}: {e}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("aip-collector-noise-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn generate_then_load_returns_the_same_public_key() {
        let path = scratch("noise.key.json");
        let _ = std::fs::remove_file(&path);
        let first = NoiseKeyFile::load_or_generate(&path).unwrap();
        let second = NoiseKeyFile::load_or_generate(&path).unwrap();
        assert_eq!(first.public(), second.public());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    /// A file whose halves do not match is refused at load.
    #[test]
    fn a_file_with_mismatched_halves_is_refused() {
        let path = scratch("bad.key.json");
        let a = StaticKeypair::generate_parts().unwrap();
        let b = StaticKeypair::generate_parts().unwrap();
        let file = NoiseKeyFile {
            private_hex: hex::encode(a.0.as_slice()),
            public_hex: hex::encode(b.1),
        };
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        let err = NoiseKeyFile::load_or_generate(&path).unwrap_err();
        assert!(err.contains("not a pair"), "{err}");
    }
}
