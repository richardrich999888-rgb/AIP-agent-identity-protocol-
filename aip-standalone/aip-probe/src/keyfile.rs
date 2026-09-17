//! The probe's **transport-auth** keypair: load it, or generate it on first
//! run. This key authenticates the channel to the collector. It is emphatically
//! **not** an evidence-signing key — the probe holds no such key and cannot
//! attest an observation. Compromising this key lets a host connect and submit
//! observations (which the collector's registry and the reconciler's
//! `CANNOT_PROVE` default already bound); it does not let the host forge an
//! attestation.

use std::path::Path;

use serde::{Deserialize, Serialize};

use aip_crypto::generate_ed25519_keypair;

/// A transport-auth keypair on disk, hex-encoded. Written `0600` on generation.
#[derive(Debug, Serialize, Deserialize)]
pub struct TransportKey {
    pub private_hex: String,
    pub public_hex: String,
}

/// The 32-byte private and public halves, decoded and validated.
pub struct LoadedKey {
    pub private: Vec<u8>,
    pub public: [u8; 32],
}

impl TransportKey {
    /// Load the key at `path`, or generate and persist one on first run. The
    /// public key is announced to the operator so it can be added to the
    /// collector's allow-list.
    pub fn load_or_generate(path: &Path) -> Result<LoadedKey, String> {
        if path.exists() {
            let bytes = std::fs::read(path)
                .map_err(|e| format!("cannot read transport key {}: {e}", path.display()))?;
            let key: TransportKey = serde_json::from_slice(&bytes)
                .map_err(|e| format!("transport key {} is not valid JSON: {e}", path.display()))?;
            key.decode()
        } else {
            let kp = generate_ed25519_keypair();
            let key = TransportKey {
                private_hex: hex::encode(&kp.private_key),
                public_hex: hex::encode(&kp.public_key),
            };
            let json = serde_json::to_vec_pretty(&key).map_err(|e| format!("encode key: {e}"))?;
            write_private(path, &json)?;
            eprintln!(
                "aip-probe: generated a new transport key at {}. Add this public key to the \
                 collector's allow-list:\n  {}",
                path.display(),
                key.public_hex
            );
            key.decode()
        }
    }

    fn decode(&self) -> Result<LoadedKey, String> {
        let private = hex::decode(&self.private_hex)
            .map_err(|e| format!("transport private key is not hex: {e}"))?;
        if private.len() != 32 {
            return Err(format!(
                "transport private key must be 32 bytes, got {}",
                private.len()
            ));
        }
        let public_raw = hex::decode(&self.public_hex)
            .map_err(|e| format!("transport public key is not hex: {e}"))?;
        let public: [u8; 32] = public_raw.as_slice().try_into().map_err(|_| {
            format!(
                "transport public key must be 32 bytes, got {}",
                public_raw.len()
            )
        })?;
        Ok(LoadedKey { private, public })
    }
}

/// Write a file with `0600` permissions where the platform supports it. The key
/// is a credential; it is never world-readable.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes)
        .map_err(|e| format!("cannot write transport key {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("cannot chmod transport key {}: {e}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_then_load_is_stable() {
        let dir = std::env::temp_dir().join(format!("aip-probe-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("transport.key.json");

        let first = TransportKey::load_or_generate(&path).unwrap();
        let second = TransportKey::load_or_generate(&path).unwrap();
        assert_eq!(first.private, second.private);
        assert_eq!(first.public, second.public);
        assert_eq!(first.private.len(), 32);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
