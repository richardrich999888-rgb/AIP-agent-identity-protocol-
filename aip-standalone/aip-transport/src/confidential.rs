//! Confidentiality for the probe→collector channel (R9).
//!
//! # What the authenticated channel leaked, and what this closes
//!
//! [`crate::client`] and [`crate::server`] authenticate *which host may
//! submit* and make every frame unforgeable and unreplayable. They send
//! the bytes in the clear. An observation batch carries no payload content
//! (invariant I23), but its metadata — probe identifiers, process ids,
//! executable paths, socket endpoints, timestamps — is a map of what ran
//! where, and under DPDP and an institution's own classification that map
//! is not something to hand a network observer.
//!
//! This module wraps the authenticated channel in a Noise session. The
//! authenticated protocol runs **inside** it unchanged: the challenge, the
//! probe's identity, its transport public key and every batch frame are
//! encrypted, so a capture of the session shows none of them. The test in
//! `tests/confidential.rs` captures a session and asserts exactly that.
//!
//! # The pattern, and why
//!
//! `Noise_NK_25519_ChaChaPoly_SHA256`.
//!
//! * **NK**: the initiator (probe) knows the responder's (collector's)
//!   static public key in advance and pins it. An active attacker without
//!   the collector's static private key cannot complete the handshake as
//!   the collector, so cannot read the probe's traffic. The initiator is
//!   anonymous at this layer, which is correct: the probe's identity is
//!   established by the Ed25519 challenge inside the tunnel, where it is
//!   also confidential. Forward secrecy comes from the ephemeral–ephemeral
//!   step, so a later compromise of the collector's static key does not
//!   open past sessions.
//! * **25519 / ChaChaPoly / SHA256**: the primitives the workspace already
//!   uses. No AES, no BLAKE2, no `ring`.
//!
//! The collector's static key is a **second** key, separate from its
//! Ed25519 evidence key and from the probe's Ed25519 transport-auth key.
//! Reusing a signing key for Diffie–Hellman is key reuse across primitives,
//! and the birational map from Ed25519 to X25519 is exactly the kind of
//! cleverness a custody design should not rest on.
//!
//! # Framing
//!
//! Each Noise message is at most 65 535 bytes and is preceded on the wire
//! by a two-byte big-endian length. A write larger than one message's
//! plaintext capacity is split across messages; a read returns plaintext
//! from the current message until it is drained, then fetches the next.
//! A clean EOF between messages is `Ok(0)`; a truncated message is an
//! error; an authentication-tag failure is an error **and poisons the
//! stream**, so nothing after a tampered message is ever delivered.

use std::io::{self, Read, Write};

use snow::{Builder, HandshakeState, TransportState};
use zeroize::Zeroizing;

/// The Noise protocol name. Fixed: a negotiable cipher suite is a downgrade
/// surface, and both ends are this crate.
pub const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_SHA256";

/// A Noise message, including its 16-byte tag, is at most this long.
const MAX_NOISE_MESSAGE: usize = 65_535;
const TAG_LEN: usize = 16;
/// Plaintext that fits in one message.
const MAX_PLAINTEXT_PER_MESSAGE: usize = MAX_NOISE_MESSAGE - TAG_LEN;
/// X25519 keys are 32 bytes.
const KEY_LEN: usize = 32;

/// Why a confidential session could not be established or continued.
#[derive(Debug)]
pub enum ConfidentialError {
    /// A key of the wrong length was supplied.
    BadKeyLength(usize),
    /// The private and public halves supplied do not form a pair. Detected
    /// by running a local handshake between them, so a key file whose
    /// halves were mixed up is refused at load rather than at the first
    /// probe that cannot connect.
    KeyPairMismatch,
    /// The Noise library refused: pattern, key, or handshake state.
    Noise(String),
    /// The handshake did not reach transport mode. Almost always the
    /// initiator pinned a public key that is not the responder's.
    HandshakeFailed(String),
    Io(io::Error),
}

impl std::fmt::Display for ConfidentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadKeyLength(n) => write!(f, "a Noise static key must be 32 bytes, got {n}"),
            Self::KeyPairMismatch => write!(
                f,
                "the Noise static private and public keys supplied are not a pair"
            ),
            Self::Noise(e) => write!(f, "noise: {e}"),
            Self::HandshakeFailed(e) => write!(
                f,
                "the confidential handshake failed ({e}); the peer is not the collector whose \
                 static key is pinned, or the link is not carrying this protocol"
            ),
            Self::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for ConfidentialError {}

impl From<snow::Error> for ConfidentialError {
    fn from(e: snow::Error) -> Self {
        Self::Noise(e.to_string())
    }
}

impl From<io::Error> for ConfidentialError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

fn params() -> snow::params::NoiseParams {
    // The pattern string is a compile-time constant this crate owns; a
    // parse failure would be a build defect, not a runtime condition.
    NOISE_PATTERN
        .parse()
        .expect("NOISE_PATTERN is a valid Noise protocol name")
}

/// The responder's long-term X25519 keypair. The private half is zeroed on
/// drop and is never returned by any method.
pub struct StaticKeypair {
    private: Zeroizing<Vec<u8>>,
    public: [u8; KEY_LEN],
}

impl std::fmt::Debug for StaticKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticKeypair")
            .field("public", &hex_prefix(&self.public))
            .field("private", &"<redacted>")
            .finish()
    }
}

impl StaticKeypair {
    /// A fresh keypair from the OS CSPRNG.
    pub fn generate() -> Result<Self, ConfidentialError> {
        let (private, public) = Self::generate_parts()?;
        Ok(Self { private, public })
    }

    /// A fresh keypair as raw halves, for the one caller that has to write
    /// them down: the collector's key file at first start.
    ///
    /// This is the only way private bytes leave this module, and it exists
    /// because an X25519 static key has to be persisted somewhere and this
    /// crate holds no custodian for it. A `StaticKeypair` built from the
    /// result exposes no private accessor; persistence happens before
    /// construction, or not at all.
    pub fn generate_parts() -> Result<(Zeroizing<Vec<u8>>, [u8; KEY_LEN]), ConfidentialError> {
        let kp = Builder::new(params()).generate_keypair()?;
        let public: [u8; KEY_LEN] = kp
            .public
            .as_slice()
            .try_into()
            .map_err(|_| ConfidentialError::BadKeyLength(kp.public.len()))?;
        Ok((Zeroizing::new(kp.private), public))
    }

    /// Rebuild a keypair from stored halves, **proving they are a pair**.
    ///
    /// The Noise library does not expose scalar-to-point derivation, and
    /// adding a curve dependency for one call is not worth it. Instead a
    /// local NK handshake is run between an initiator pinned to `public`
    /// and a responder holding `private`: it completes only if they match.
    /// A key file whose halves were edited or swapped is therefore refused
    /// here, at load, with a named error.
    pub fn from_parts(private: &[u8], public: &[u8]) -> Result<Self, ConfidentialError> {
        if private.len() != KEY_LEN {
            return Err(ConfidentialError::BadKeyLength(private.len()));
        }
        let public: [u8; KEY_LEN] = public
            .try_into()
            .map_err(|_| ConfidentialError::BadKeyLength(public.len()))?;
        let kp = Self {
            private: Zeroizing::new(private.to_vec()),
            public,
        };
        kp.prove_pair()?;
        Ok(kp)
    }

    pub fn public(&self) -> &[u8; KEY_LEN] {
        &self.public
    }

    pub(crate) fn private(&self) -> &[u8] {
        &self.private
    }

    /// Complete an NK handshake against ourselves, in memory.
    fn prove_pair(&self) -> Result<(), ConfidentialError> {
        let mut initiator = Builder::new(params())
            .remote_public_key(&self.public)?
            .build_initiator()?;
        let mut responder = Builder::new(params())
            .local_private_key(&self.private)?
            .build_responder()?;
        let mut m1 = vec![0u8; MAX_NOISE_MESSAGE];
        let mut m2 = vec![0u8; MAX_NOISE_MESSAGE];
        let mut scratch = vec![0u8; MAX_NOISE_MESSAGE];
        let n1 = initiator.write_message(&[], &mut m1)?;
        responder
            .read_message(&m1[..n1], &mut scratch)
            .map_err(|_| ConfidentialError::KeyPairMismatch)?;
        let n2 = responder.write_message(&[], &mut m2)?;
        initiator
            .read_message(&m2[..n2], &mut scratch)
            .map_err(|_| ConfidentialError::KeyPairMismatch)?;
        if initiator.is_handshake_finished() && responder.is_handshake_finished() {
            Ok(())
        } else {
            Err(ConfidentialError::KeyPairMismatch)
        }
    }
}

/// A stream whose every byte is inside a Noise session.
pub struct ConfidentialStream<S> {
    inner: S,
    state: TransportState,
    /// Plaintext of the current message not yet handed to the reader.
    read_buf: Vec<u8>,
    read_pos: usize,
    /// Scratch for one wire message, reused so a write does not allocate.
    msg_buf: Vec<u8>,
    /// Set on any decryption or protocol failure. Once set, every read and
    /// write fails: a stream that has seen a forged message is not a
    /// stream to keep talking on.
    poisoned: bool,
}

impl<S> std::fmt::Debug for ConfidentialStream<S> {
    /// Names the state of the stream and nothing of its keys or buffers: a
    /// log line must not become a second copy of the plaintext.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfidentialStream")
            .field("pattern", &NOISE_PATTERN)
            .field("poisoned", &self.poisoned)
            .field("buffered_plaintext", &(self.read_buf.len() - self.read_pos))
            .finish()
    }
}

impl<S: Read + Write> ConfidentialStream<S> {
    /// Open a session as the initiator (the probe), pinned to the
    /// responder's static public key.
    pub fn initiate(
        mut inner: S,
        responder_static_public: &[u8; KEY_LEN],
    ) -> Result<Self, ConfidentialError> {
        let mut hs = Builder::new(params())
            .remote_public_key(responder_static_public)?
            .build_initiator()?;
        let mut buf = vec![0u8; MAX_NOISE_MESSAGE];
        let mut scratch = vec![0u8; MAX_NOISE_MESSAGE];

        // -> e, es
        let n = hs.write_message(&[], &mut buf)?;
        write_message(&mut inner, &buf[..n])?;
        // <- e, ee
        let m = read_message(&mut inner)?.ok_or_else(|| {
            ConfidentialError::HandshakeFailed("peer closed during the handshake".into())
        })?;
        hs.read_message(&m, &mut scratch)
            .map_err(|e| ConfidentialError::HandshakeFailed(e.to_string()))?;
        Self::finish(inner, hs)
    }

    /// Open a session as the responder (the collector), holding the static
    /// private key the initiators have pinned.
    pub fn respond(mut inner: S, static_key: &StaticKeypair) -> Result<Self, ConfidentialError> {
        let mut hs = Builder::new(params())
            .local_private_key(static_key.private())?
            .build_responder()?;
        let mut buf = vec![0u8; MAX_NOISE_MESSAGE];
        let mut scratch = vec![0u8; MAX_NOISE_MESSAGE];

        // -> e, es
        let m = read_message(&mut inner)?.ok_or_else(|| {
            ConfidentialError::HandshakeFailed("peer closed before the handshake".into())
        })?;
        hs.read_message(&m, &mut scratch)
            .map_err(|e| ConfidentialError::HandshakeFailed(e.to_string()))?;
        // <- e, ee
        let n = hs.write_message(&[], &mut buf)?;
        write_message(&mut inner, &buf[..n])?;
        Self::finish(inner, hs)
    }

    fn finish(inner: S, hs: HandshakeState) -> Result<Self, ConfidentialError> {
        if !hs.is_handshake_finished() {
            return Err(ConfidentialError::HandshakeFailed(
                "handshake did not complete".into(),
            ));
        }
        Ok(Self {
            inner,
            state: hs.into_transport_mode()?,
            read_buf: Vec::new(),
            read_pos: 0,
            msg_buf: vec![0u8; MAX_NOISE_MESSAGE],
            poisoned: false,
        })
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    fn poison<T>(&mut self, e: io::Error) -> io::Result<T> {
        self.poisoned = true;
        Err(e)
    }

    fn poisoned_error() -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "confidential stream is poisoned after a failed message; refusing further IO",
        )
    }
}

impl<S: Read + Write> Read for ConfidentialStream<S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.poisoned {
            return Err(Self::poisoned_error());
        }
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            // Drain the current message first.
            if self.read_pos < self.read_buf.len() {
                let n = (self.read_buf.len() - self.read_pos).min(out.len());
                out[..n].copy_from_slice(&self.read_buf[self.read_pos..self.read_pos + n]);
                self.read_pos += n;
                return Ok(n);
            }
            // Fetch the next one.
            let wire = match read_message(&mut self.inner) {
                Ok(Some(m)) => m,
                Ok(None) => return Ok(0),
                Err(ConfidentialError::Io(e)) => return self.poison(e),
                Err(e) => {
                    return self.poison(io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
                }
            };
            self.read_buf.clear();
            self.read_buf.resize(wire.len(), 0);
            match self.state.read_message(&wire, &mut self.read_buf) {
                Ok(n) => {
                    self.read_buf.truncate(n);
                    self.read_pos = 0;
                }
                Err(e) => {
                    return self.poison(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("message failed authentication: {e}"),
                    ))
                }
            }
        }
    }
}

impl<S: Read + Write> Write for ConfidentialStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.poisoned {
            return Err(Self::poisoned_error());
        }
        for chunk in buf.chunks(MAX_PLAINTEXT_PER_MESSAGE) {
            let n = match self.state.write_message(chunk, &mut self.msg_buf) {
                Ok(n) => n,
                Err(e) => return self.poison(io::Error::other(format!("encrypt: {e}"))),
            };
            let msg = self.msg_buf[..n].to_vec();
            if let Err(e) = write_message(&mut self.inner, &msg) {
                let e = match e {
                    ConfidentialError::Io(e) => e,
                    other => io::Error::other(other.to_string()),
                };
                return self.poison(e);
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Write one length-prefixed Noise message.
fn write_message<W: Write>(w: &mut W, msg: &[u8]) -> Result<(), ConfidentialError> {
    debug_assert!(msg.len() <= MAX_NOISE_MESSAGE);
    let len = (msg.len() as u16).to_be_bytes();
    w.write_all(&len)?;
    w.write_all(msg)?;
    Ok(())
}

/// Read one length-prefixed Noise message. `Ok(None)` is a clean EOF at a
/// message boundary; EOF anywhere else is an error.
fn read_message<R: Read>(r: &mut R) -> Result<Option<Vec<u8>>, ConfidentialError> {
    let mut first = [0u8; 1];
    loop {
        match r.read(&mut first) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    let mut second = [0u8; 1];
    r.read_exact(&mut second)?;
    let len = u16::from_be_bytes([first[0], second[0]]) as usize;
    if len == 0 {
        return Err(ConfidentialError::Noise("zero-length message".into()));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(Some(body))
}

fn hex_prefix(b: &[u8]) -> String {
    b.iter()
        .take(4)
        .map(|x| format!("{x:02x}"))
        .collect::<String>()
        + "…"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_pair_proves_itself_and_mixed_halves_are_refused() {
        let a = StaticKeypair::generate().unwrap();
        let b = StaticKeypair::generate().unwrap();
        StaticKeypair::from_parts(a.private(), a.public()).unwrap();
        assert!(matches!(
            StaticKeypair::from_parts(a.private(), b.public()),
            Err(ConfidentialError::KeyPairMismatch)
        ));
        assert!(matches!(
            StaticKeypair::from_parts(&[0u8; 31], a.public()),
            Err(ConfidentialError::BadKeyLength(31))
        ));
    }

    #[test]
    fn debug_never_shows_the_private_key() {
        let a = StaticKeypair::generate().unwrap();
        let d = format!("{a:?}");
        assert!(d.contains("<redacted>"), "{d}");
        let private_hex: String = a.private().iter().map(|b| format!("{b:02x}")).collect();
        assert!(!d.contains(&private_hex[..16]), "{d}");
    }

    #[test]
    fn message_framing_round_trips_and_refuses_empty_and_truncated() {
        let mut buf = Vec::new();
        write_message(&mut buf, b"hello").unwrap();
        assert_eq!(&buf[..2], &[0, 5]);
        let mut cur = io::Cursor::new(buf.clone());
        assert_eq!(read_message(&mut cur).unwrap().unwrap(), b"hello");
        // Clean EOF at the boundary.
        assert!(read_message(&mut cur).unwrap().is_none());
        // Truncated body.
        let mut cur = io::Cursor::new(buf[..4].to_vec());
        assert!(matches!(
            read_message(&mut cur),
            Err(ConfidentialError::Io(_))
        ));
        // Zero length is not a message.
        let mut cur = io::Cursor::new(vec![0u8, 0u8]);
        assert!(matches!(
            read_message(&mut cur),
            Err(ConfidentialError::Noise(_))
        ));
    }
}
