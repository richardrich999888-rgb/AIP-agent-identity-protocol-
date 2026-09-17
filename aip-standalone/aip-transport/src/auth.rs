//! Signing and verification for the handshake and per-batch frames. Pure
//! functions over [`crate::wire`]'s preimages, using `aip-crypto`'s raw
//! Ed25519 helpers. No IO.

use aip_crypto::{sign_ed25519_raw, verify_ed25519_raw};

use crate::wire::{auth_preimage, frame_preimage, PROTOCOL_VERSION};

/// Why an authentication check failed. Distinguished so the caller can log the
/// cause; none of these are ever "accepted with a warning" — each closes the
/// connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// The signing key was not 32 bytes.
    BadKeyLength(usize),
    /// The Ed25519 signature did not verify against the preimage.
    BadSignature,
    /// The handshake advertised a protocol version this end does not speak.
    VersionMismatch { theirs: u16, ours: u16 },
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::BadKeyLength(n) => write!(f, "signing key is {n} bytes, expected 32"),
            AuthError::BadSignature => write!(f, "signature did not verify"),
            AuthError::VersionMismatch { theirs, ours } => {
                write!(f, "peer protocol version {theirs}, this end speaks {ours}")
            }
        }
    }
}

impl std::error::Error for AuthError {}

/// Probe side: sign the handshake challenge with the transport-auth private
/// key. Returns the 64-byte detached signature.
pub fn sign_auth(
    private_key: &[u8],
    version: u16,
    nonce: &[u8; 32],
    probe_id: &str,
) -> Result<[u8; 64], AuthError> {
    let preimage = auth_preimage(version, nonce, probe_id);
    sign_ed25519_raw(private_key, &preimage).map_err(|_| AuthError::BadKeyLength(private_key.len()))
}

/// Collector side: verify a probe's handshake signature against its advertised
/// transport public key. Also enforces the protocol version, so a version skew
/// is refused at the handshake rather than misinterpreted later.
pub fn verify_auth(
    transport_pubkey: &[u8; 32],
    version: u16,
    nonce: &[u8; 32],
    probe_id: &str,
    signature: &[u8],
) -> Result<(), AuthError> {
    if version != PROTOCOL_VERSION {
        return Err(AuthError::VersionMismatch {
            theirs: version,
            ours: PROTOCOL_VERSION,
        });
    }
    let sig = to_sig64(signature)?;
    let preimage = auth_preimage(version, nonce, probe_id);
    if verify_ed25519_raw(transport_pubkey, &preimage, &sig) {
        Ok(())
    } else {
        Err(AuthError::BadSignature)
    }
}

/// A signature on the wire is a `Vec<u8>` (serde does not derive `[u8; 64]`);
/// a wrong length is a malformed signature, refused as such.
fn to_sig64(signature: &[u8]) -> Result<[u8; 64], AuthError> {
    signature.try_into().map_err(|_| AuthError::BadSignature)
}

/// Probe side: sign one batch frame.
pub fn sign_frame(
    private_key: &[u8],
    nonce: &[u8; 32],
    seq: u64,
    batch_bytes: &[u8],
) -> Result<[u8; 64], AuthError> {
    let preimage = frame_preimage(nonce, seq, batch_bytes);
    sign_ed25519_raw(private_key, &preimage).map_err(|_| AuthError::BadKeyLength(private_key.len()))
}

/// Collector side: verify one batch frame against the session's authenticated
/// transport public key.
pub fn verify_frame(
    transport_pubkey: &[u8; 32],
    nonce: &[u8; 32],
    seq: u64,
    batch_bytes: &[u8],
    signature: &[u8],
) -> Result<(), AuthError> {
    let sig = to_sig64(signature)?;
    let preimage = frame_preimage(nonce, seq, batch_bytes);
    if verify_ed25519_raw(transport_pubkey, &preimage, &sig) {
        Ok(())
    } else {
        Err(AuthError::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_crypto::generate_ed25519_keypair;

    fn key32(v: &[u8]) -> [u8; 32] {
        let mut k = [0u8; 32];
        k.copy_from_slice(v);
        k
    }

    #[test]
    fn auth_roundtrip_accepts_the_holder_and_rejects_everyone_else() {
        let kp = generate_ed25519_keypair();
        let pk = key32(&kp.public_key);
        let nonce = [3u8; 32];
        let sig = sign_auth(&kp.private_key, PROTOCOL_VERSION, &nonce, "probe-a").unwrap();
        assert_eq!(
            verify_auth(&pk, PROTOCOL_VERSION, &nonce, "probe-a", &sig),
            Ok(())
        );
        // A different probe key does not verify this signature.
        let other = generate_ed25519_keypair();
        assert_eq!(
            verify_auth(
                &key32(&other.public_key),
                PROTOCOL_VERSION,
                &nonce,
                "probe-a",
                &sig
            ),
            Err(AuthError::BadSignature)
        );
        // A different nonce (replay into another session) does not verify.
        assert_eq!(
            verify_auth(&pk, PROTOCOL_VERSION, &[4u8; 32], "probe-a", &sig),
            Err(AuthError::BadSignature)
        );
        // A different claimed id does not verify.
        assert_eq!(
            verify_auth(&pk, PROTOCOL_VERSION, &nonce, "probe-b", &sig),
            Err(AuthError::BadSignature)
        );
    }

    #[test]
    fn version_skew_is_refused_at_the_handshake() {
        let kp = generate_ed25519_keypair();
        let pk = key32(&kp.public_key);
        let nonce = [1u8; 32];
        let sig = sign_auth(&kp.private_key, 999, &nonce, "p").unwrap();
        assert_eq!(
            verify_auth(&pk, 999, &nonce, "p", &sig),
            Err(AuthError::VersionMismatch {
                theirs: 999,
                ours: PROTOCOL_VERSION
            })
        );
    }

    #[test]
    fn frame_roundtrip_and_tamper_detection() {
        let kp = generate_ed25519_keypair();
        let pk = key32(&kp.public_key);
        let nonce = [5u8; 32];
        let sig = sign_frame(&kp.private_key, &nonce, 1, b"batch-one").unwrap();
        assert_eq!(verify_frame(&pk, &nonce, 1, b"batch-one", &sig), Ok(()));
        // Altered bytes → different preimage → rejected.
        assert_eq!(
            verify_frame(&pk, &nonce, 1, b"batch-two", &sig),
            Err(AuthError::BadSignature)
        );
        // Replayed under a different seq → rejected.
        assert_eq!(
            verify_frame(&pk, &nonce, 2, b"batch-one", &sig),
            Err(AuthError::BadSignature)
        );
        // Replayed into a different session (nonce) → rejected.
        assert_eq!(
            verify_frame(&pk, &[6u8; 32], 1, b"batch-one", &sig),
            Err(AuthError::BadSignature)
        );
    }
}
