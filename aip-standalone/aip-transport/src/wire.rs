//! Wire messages, protocol constants, and the domain-separated signing
//! preimages. Pure: no IO, no sockets, no crypto — only the byte layout the
//! two ends agree on.

use serde::{Deserialize, Serialize};

use aip_crypto::sha256;

/// Wire protocol version. Bumped only on an incompatible framing/handshake
/// change; the evidence formats it carries version themselves and are
/// unaffected.
pub const PROTOCOL_VERSION: u16 = 1;

/// Hard ceiling on a single frame's byte length. Untrusted input is bounded
/// **before** allocation: a declared length above this closes the connection
/// rather than reserving the buffer. An observation batch is kilobytes; 4 MiB
/// is generous headroom without letting a peer name a huge allocation.
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Domain tag for the handshake authentication signature. Distinct from
/// [`DOMAIN_FRAME`] so an auth signature can never be replayed as a frame
/// signature.
const DOMAIN_AUTH: &[u8] = b"AIP/TRANSPORT/AUTH/v1";

/// Domain tag for a per-batch frame signature.
const DOMAIN_FRAME: &[u8] = b"AIP/TRANSPORT/FRAME/v1";

/// The bytes a probe signs with its transport-auth key during the handshake.
///
/// `DOMAIN_AUTH ‖ version ‖ nonce ‖ sha256(probe_id)`. Every component after
/// the constant domain is fixed length (`u16`, 32-byte nonce, 32-byte hash),
/// so the concatenation is injective — no two distinct inputs share a preimage.
/// Binding `sha256(probe_id)` ties the signature to the claimed identity;
/// binding `nonce` (a fresh per-session challenge) makes it non-replayable
/// across sessions.
pub fn auth_preimage(version: u16, nonce: &[u8; 32], probe_id: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(DOMAIN_AUTH.len() + 2 + 32 + 32);
    p.extend_from_slice(DOMAIN_AUTH);
    p.extend_from_slice(&version.to_be_bytes());
    p.extend_from_slice(nonce);
    p.extend_from_slice(&sha256(probe_id.as_bytes()));
    p
}

/// The bytes a probe signs for each batch frame.
///
/// `DOMAIN_FRAME ‖ nonce ‖ seq ‖ sha256(batch_bytes)`. The session `nonce`
/// binds the frame to this authenticated session; the strictly increasing
/// `seq` orders it; `sha256(batch_bytes)` commits to the exact opaque bytes.
/// All fixed length after the domain, so injective. The collector re-hashes the
/// bytes it parsed before verifying — it never trusts a hash supplied beside the
/// data.
pub fn frame_preimage(nonce: &[u8; 32], seq: u64, batch_bytes: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(DOMAIN_FRAME.len() + 32 + 8 + 32);
    p.extend_from_slice(DOMAIN_FRAME);
    p.extend_from_slice(nonce);
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&sha256(batch_bytes));
    p
}

/// One protocol message. Serialized as JSON inside a length-prefixed frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Message {
    /// Collector → probe: the fresh session challenge.
    Challenge(Challenge),
    /// Probe → collector: proof of possession of the transport-auth key.
    Auth(AuthMsg),
    /// Collector → probe: whether the probe was accepted.
    AuthResult(AuthResult),
    /// Probe → collector: one signed observation batch (opaque bytes).
    Batch(BatchFrame),
    /// Collector → probe: acknowledgement with the attested chain position.
    Ack(BatchAck),
}

/// Collector → probe: `protocol_version` and a random 32-byte session nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    pub protocol_version: u16,
    pub nonce: [u8; 32],
}

/// Probe → collector: the probe's claimed id, its transport-auth public key,
/// and a signature over [`auth_preimage`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthMsg {
    pub probe_id: String,
    pub transport_pubkey: [u8; 32],
    pub signature: Vec<u8>,
}

/// Collector → probe: the handshake outcome. `reason` is diagnostic only and
/// is never security-load-bearing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthResult {
    pub accepted: bool,
    pub reason: Option<String>,
}

/// Probe → collector: one batch. `batch_bytes` is opaque to this crate (the
/// collector deserializes it into an `ObservationBatch`). `signature` is over
/// [`frame_preimage`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchFrame {
    /// Strictly increasing from 1 within a session.
    pub seq: u64,
    pub batch_bytes: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Collector → probe: the batch was attested. Carries the collector-assigned
/// chain position so the probe can log/confirm; the probe never chooses it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchAck {
    pub seq: u64,
    pub attested_sequence: u64,
    pub head: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_and_frame_preimages_are_domain_separated() {
        let nonce = [7u8; 32];
        // A frame preimage and an auth preimage can never collide, because
        // their constant domain prefixes differ.
        let a = auth_preimage(PROTOCOL_VERSION, &nonce, "probe-1");
        let f = frame_preimage(&nonce, 1, b"probe-1");
        assert_ne!(a, f);
    }

    #[test]
    fn auth_preimage_binds_version_nonce_and_id() {
        let n1 = [1u8; 32];
        let n2 = [2u8; 32];
        assert_ne!(auth_preimage(1, &n1, "p"), auth_preimage(1, &n2, "p"));
        assert_ne!(auth_preimage(1, &n1, "p"), auth_preimage(2, &n1, "p"));
        assert_ne!(auth_preimage(1, &n1, "p"), auth_preimage(1, &n1, "q"));
    }

    #[test]
    fn frame_preimage_binds_nonce_seq_and_bytes() {
        let n = [9u8; 32];
        assert_ne!(frame_preimage(&n, 1, b"a"), frame_preimage(&n, 2, b"a"));
        assert_ne!(frame_preimage(&n, 1, b"a"), frame_preimage(&n, 1, b"b"));
        assert_ne!(
            frame_preimage(&[8u8; 32], 1, b"a"),
            frame_preimage(&n, 1, b"a")
        );
    }
}
