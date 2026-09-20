//! Probe side of the channel. [`TransportClient`] is generic over the stream so
//! it is tested over an in-memory socket pair; [`TransportClient::connect`] is
//! the blocking-TCP wrapper.
//!
//! The client holds the probe's **transport-auth** key. It never holds an
//! evidence-signing key and cannot produce an attestation.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::auth::{sign_auth, sign_frame, AuthError};
use crate::codec::{read_frame, write_frame, CodecError};
use crate::wire::{AuthMsg, BatchAck, BatchFrame, Message, PROTOCOL_VERSION};

/// Why a client operation failed.
#[derive(Debug)]
pub enum ClientError {
    Codec(CodecError),
    Auth(AuthError),
    /// The collector advertised a protocol version this probe does not speak.
    VersionMismatch {
        theirs: u16,
        ours: u16,
    },
    /// The collector rejected the handshake.
    Rejected {
        reason: Option<String>,
    },
    /// A message arrived out of the expected order.
    Protocol(String),
    /// The collector acked a different sequence than the one just sent.
    AckMismatch {
        sent: u64,
        acked: u64,
    },
    /// The configured transport key was not 32 bytes.
    BadKeyLength(usize),
    /// The confidential session could not be opened or was broken (R9).
    Confidential(crate::confidential::ConfidentialError),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Confidential(e) => write!(f, "confidential session: {e}"),
            ClientError::Codec(e) => write!(f, "codec: {e}"),
            ClientError::Auth(e) => write!(f, "auth: {e}"),
            ClientError::VersionMismatch { theirs, ours } => {
                write!(f, "collector speaks v{theirs}, this probe speaks v{ours}")
            }
            ClientError::Rejected { reason } => {
                write!(
                    f,
                    "handshake rejected: {}",
                    reason.as_deref().unwrap_or("(no reason)")
                )
            }
            ClientError::Protocol(m) => write!(f, "protocol: {m}"),
            ClientError::AckMismatch { sent, acked } => {
                write!(f, "ack for seq {acked}, expected {sent}")
            }
            ClientError::BadKeyLength(n) => write!(f, "transport key is {n} bytes, expected 32"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<CodecError> for ClientError {
    fn from(e: CodecError) -> Self {
        ClientError::Codec(e)
    }
}

/// An authenticated probe→collector session. After [`handshake`](Self::handshake)
/// it ships batches with a strictly increasing sequence.
pub struct TransportClient<S> {
    stream: S,
    probe_id: String,
    transport_priv: Vec<u8>,
    session_nonce: [u8; 32],
    next_seq: u64,
}

impl<S: Read + Write> TransportClient<S> {
    /// Perform the handshake over an already-connected stream. Reads the
    /// challenge, checks the protocol version, signs it with the transport key,
    /// and confirms acceptance.
    pub fn handshake(
        mut stream: S,
        probe_id: impl Into<String>,
        transport_priv: &[u8],
        transport_pub: &[u8; 32],
    ) -> Result<Self, ClientError> {
        if transport_priv.len() != 32 {
            return Err(ClientError::BadKeyLength(transport_priv.len()));
        }
        let probe_id = probe_id.into();

        let challenge = match read_frame(&mut stream)? {
            Message::Challenge(c) => c,
            other => {
                return Err(ClientError::Protocol(format!(
                    "expected Challenge, got {}",
                    variant_name(&other)
                )))
            }
        };
        if challenge.protocol_version != PROTOCOL_VERSION {
            return Err(ClientError::VersionMismatch {
                theirs: challenge.protocol_version,
                ours: PROTOCOL_VERSION,
            });
        }

        let signature = sign_auth(
            transport_priv,
            PROTOCOL_VERSION,
            &challenge.nonce,
            &probe_id,
        )
        .map_err(ClientError::Auth)?;
        write_frame(
            &mut stream,
            &Message::Auth(AuthMsg {
                probe_id: probe_id.clone(),
                transport_pubkey: *transport_pub,
                signature: signature.to_vec(),
            }),
        )?;

        match read_frame(&mut stream)? {
            Message::AuthResult(r) if r.accepted => {}
            Message::AuthResult(r) => return Err(ClientError::Rejected { reason: r.reason }),
            other => {
                return Err(ClientError::Protocol(format!(
                    "expected AuthResult, got {}",
                    variant_name(&other)
                )))
            }
        }

        Ok(Self {
            stream,
            probe_id,
            transport_priv: transport_priv.to_vec(),
            session_nonce: challenge.nonce,
            next_seq: 1,
        })
    }

    /// Ship one opaque observation-batch payload; block for the collector's ack.
    pub fn send_batch(&mut self, batch_bytes: &[u8]) -> Result<BatchAck, ClientError> {
        let seq = self.next_seq;
        let signature = sign_frame(&self.transport_priv, &self.session_nonce, seq, batch_bytes)
            .map_err(ClientError::Auth)?;
        write_frame(
            &mut self.stream,
            &Message::Batch(BatchFrame {
                seq,
                batch_bytes: batch_bytes.to_vec(),
                signature: signature.to_vec(),
            }),
        )?;
        let ack = match read_frame(&mut self.stream)? {
            Message::Ack(a) => a,
            other => {
                return Err(ClientError::Protocol(format!(
                    "expected Ack, got {}",
                    variant_name(&other)
                )))
            }
        };
        if ack.seq != seq {
            return Err(ClientError::AckMismatch {
                sent: seq,
                acked: ack.seq,
            });
        }
        self.next_seq += 1;
        Ok(ack)
    }

    /// The probe id this session authenticated as.
    pub fn probe_id(&self) -> &str {
        &self.probe_id
    }
}

impl TransportClient<TcpStream> {
    /// Connect over TCP and perform the handshake.
    pub fn connect(
        addr: impl ToSocketAddrs,
        probe_id: impl Into<String>,
        transport_priv: &[u8],
        transport_pub: &[u8; 32],
        timeout: Duration,
    ) -> Result<Self, ClientError> {
        let stream = TcpStream::connect(addr).map_err(|e| ClientError::Codec(CodecError::Io(e)))?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| ClientError::Codec(CodecError::Io(e)))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|e| ClientError::Codec(CodecError::Io(e)))?;
        Self::handshake(stream, probe_id, transport_priv, transport_pub)
    }
}

impl TransportClient<crate::confidential::ConfidentialStream<TcpStream>> {
    /// Connect over TCP, open a confidential session pinned to the
    /// collector's static public key, and perform the authenticated
    /// handshake inside it (R9).
    ///
    /// Every byte of the authenticated protocol — challenge, probe id,
    /// transport public key, frames — is inside the session. The pilot
    /// daemons use only this constructor.
    pub fn connect_confidential(
        addr: impl ToSocketAddrs,
        collector_static_public: &[u8; 32],
        probe_id: impl Into<String>,
        transport_priv: &[u8],
        transport_pub: &[u8; 32],
        timeout: Duration,
    ) -> Result<Self, ClientError> {
        let stream = TcpStream::connect(addr).map_err(|e| ClientError::Codec(CodecError::Io(e)))?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| ClientError::Codec(CodecError::Io(e)))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|e| ClientError::Codec(CodecError::Io(e)))?;
        let confidential =
            crate::confidential::ConfidentialStream::initiate(stream, collector_static_public)
                .map_err(ClientError::Confidential)?;
        Self::handshake(confidential, probe_id, transport_priv, transport_pub)
    }
}

fn variant_name(m: &Message) -> &'static str {
    match m {
        Message::Challenge(_) => "Challenge",
        Message::Auth(_) => "Auth",
        Message::AuthResult(_) => "AuthResult",
        Message::Batch(_) => "Batch",
        Message::Ack(_) => "Ack",
    }
}
