//! Collector side of the channel: the handshake and batch loop, plus the
//! blocking-TCP adapter. The protocol driver [`run_server_session`] is generic
//! over the stream so it is exercised over an in-memory socket pair in tests;
//! [`serve_connection`] is the `TcpStream` wrapper.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use rand::RngCore;

use crate::auth::{verify_auth, AuthError};
use crate::codec::{read_frame, write_frame, CodecError};
use crate::wire::{AuthResult, BatchAck, Challenge, Message, PROTOCOL_VERSION};

/// The collector's allow-list: is this transport public key permitted to submit
/// as this probe id? A host-side party cannot label its own report with a probe
/// id it does not hold the transport key for.
pub trait ProbeAuthority {
    fn is_authorized(&self, probe_id: &str, transport_pubkey: &[u8; 32]) -> bool;
}

/// What the collector's evidence layer returns after attesting a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchAckData {
    pub attested_sequence: u64,
    pub head: [u8; 32],
}

/// An error from the evidence layer (e.g. the collector is quarantined, or the
/// opaque bytes did not deserialize into a batch). Opaque to the transport;
/// carried back only as a diagnostic reason and by closing the connection.
#[derive(Debug, Clone)]
pub struct SinkError(pub String);

impl std::fmt::Display for SinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The evidence layer the server hands authenticated, in-order batches to. The
/// collector implements this over its `CollectorRuntime`.
pub trait BatchSink {
    /// Handle one authenticated batch that passed frame verification and the
    /// sequence check. `batch_bytes` is the opaque payload the probe sent.
    fn accept_batch(
        &mut self,
        probe_id: &str,
        seq: u64,
        batch_bytes: &[u8],
    ) -> Result<BatchAckData, SinkError>;
}

/// Why a server session ended abnormally. A clean probe disconnect is `Ok(())`,
/// not an error.
#[derive(Debug)]
pub enum ServerError {
    Codec(CodecError),
    Auth(AuthError),
    /// The probe authenticated but its (id, key) pair is not in the allow-list.
    Unauthorized {
        probe_id: String,
    },
    /// A message arrived out of the expected order, or a batch sequence was not
    /// exactly one greater than the previous.
    Protocol(String),
    /// The evidence layer refused the batch.
    Sink(SinkError),
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerError::Codec(e) => write!(f, "codec: {e}"),
            ServerError::Auth(e) => write!(f, "auth: {e}"),
            ServerError::Unauthorized { probe_id } => {
                write!(f, "probe {probe_id:?} is not authorized")
            }
            ServerError::Protocol(m) => write!(f, "protocol: {m}"),
            ServerError::Sink(e) => write!(f, "sink: {e}"),
        }
    }
}

impl std::error::Error for ServerError {}

impl From<CodecError> for ServerError {
    fn from(e: CodecError) -> Self {
        ServerError::Codec(e)
    }
}

/// Was a codec error a clean end-of-stream at a frame boundary (the probe
/// closed the connection between batches)? That is a normal session end.
fn is_clean_eof(e: &CodecError) -> bool {
    matches!(e, CodecError::Io(io) if io.kind() == std::io::ErrorKind::UnexpectedEof)
}

/// Drive one server session to completion over `stream`, using `nonce` as the
/// session challenge. Deterministic given `nonce`, so tests can pin it.
///
/// Fail-closed: any authentication, ordering, or codec fault returns `Err` and
/// the caller closes the connection with no partial state committed. A clean
/// disconnect between batches is `Ok(())`.
pub fn run_server_session<S: Read + Write>(
    stream: &mut S,
    nonce: [u8; 32],
    authority: &dyn ProbeAuthority,
    sink: &mut dyn BatchSink,
) -> Result<(), ServerError> {
    // 1. Challenge.
    write_frame(
        stream,
        &Message::Challenge(Challenge {
            protocol_version: PROTOCOL_VERSION,
            nonce,
        }),
    )?;

    // 2. Auth.
    let auth = match read_frame(stream)? {
        Message::Auth(a) => a,
        other => {
            return Err(ServerError::Protocol(format!(
                "expected Auth, got {}",
                variant_name(&other)
            )))
        }
    };
    if let Err(e) = verify_auth(
        &auth.transport_pubkey,
        PROTOCOL_VERSION,
        &nonce,
        &auth.probe_id,
        &auth.signature,
    ) {
        // Best-effort rejection notice; the security decision is the close.
        let _ = write_frame(
            stream,
            &Message::AuthResult(AuthResult {
                accepted: false,
                reason: Some(e.to_string()),
            }),
        );
        return Err(ServerError::Auth(e));
    }
    if !authority.is_authorized(&auth.probe_id, &auth.transport_pubkey) {
        let _ = write_frame(
            stream,
            &Message::AuthResult(AuthResult {
                accepted: false,
                reason: Some("probe key not in allow-list".into()),
            }),
        );
        return Err(ServerError::Unauthorized {
            probe_id: auth.probe_id,
        });
    }
    write_frame(
        stream,
        &Message::AuthResult(AuthResult {
            accepted: true,
            reason: None,
        }),
    )?;

    // 3. Batch loop. Sequence starts at 1 and increases by exactly 1.
    let mut expected_seq: u64 = 1;
    loop {
        let frame = match read_frame(stream) {
            Ok(Message::Batch(b)) => b,
            Ok(other) => {
                return Err(ServerError::Protocol(format!(
                    "expected Batch, got {}",
                    variant_name(&other)
                )))
            }
            Err(e) if is_clean_eof(&e) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        if frame.seq != expected_seq {
            return Err(ServerError::Protocol(format!(
                "batch seq {} out of order, expected {expected_seq}",
                frame.seq
            )));
        }
        crate::auth::verify_frame(
            &auth.transport_pubkey,
            &nonce,
            frame.seq,
            &frame.batch_bytes,
            &frame.signature,
        )
        .map_err(ServerError::Auth)?;

        let ack = sink
            .accept_batch(&auth.probe_id, frame.seq, &frame.batch_bytes)
            .map_err(ServerError::Sink)?;

        write_frame(
            stream,
            &Message::Ack(BatchAck {
                seq: frame.seq,
                attested_sequence: ack.attested_sequence,
                head: ack.head,
            }),
        )?;
        expected_seq += 1;
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

/// Serve one accepted TCP connection. Generates a fresh session nonce from the
/// OS CSPRNG and applies a read timeout so a stalled peer cannot pin a thread
/// forever.
pub fn serve_connection(
    mut stream: TcpStream,
    read_timeout: Duration,
    authority: &dyn ProbeAuthority,
    sink: &mut dyn BatchSink,
) -> Result<(), ServerError> {
    stream
        .set_read_timeout(Some(read_timeout))
        .map_err(|e| ServerError::Codec(CodecError::Io(e)))?;
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    run_server_session(&mut stream, nonce, authority, sink)
}
