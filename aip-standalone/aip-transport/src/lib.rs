//! `aip-transport` — the authenticated probe↔collector channel for the Phase 1
//! two-host pilot.
//!
//! # What this crate is, and is not
//!
//! It is a framed, authenticated, replay-resistant channel over blocking TCP.
//! It carries **opaque** observation-batch bytes; it has no dependency on
//! `aip-observe` and no knowledge of what an observation means. The collector,
//! not this crate, deserializes and signs.
//!
//! It is **not** the trust root. The security of an attestation rests on the
//! collector's evidence-signing key, which lives only on the collector host.
//! This channel authenticates *which host may submit* an observation, not
//! *whether the observation is true* — a distinction spelled out in
//! `docs/pilot/PHASE1_DAEMONS.md`. A probe holds a **transport-auth** key here;
//! it never holds an evidence-signing key.
//!
//! # Layering (hexagonal)
//!
//! - [`wire`] — message types, protocol constants, and the domain-separated
//!   signing preimages. Pure.
//! - [`auth`] — sign/verify over those preimages using `aip-crypto`'s raw
//!   Ed25519 helpers. Pure.
//! - [`codec`] — length-prefixed frame read/write over any [`std::io::Read`]/
//!   [`std::io::Write`], with an up-front size bound. IO over traits, no
//!   sockets.
//! - [`client`] / [`server`] — thin blocking-TCP adapters that drive the
//!   handshake and batch loop through the pure layers above.
//! - [`confidential`] — a Noise `NK` session (R9) that the authenticated
//!   protocol runs *inside*, so a capture of the link shows neither the
//!   probe's identity nor any batch metadata. The pilot daemons use it
//!   unconditionally; the plaintext adapters remain for tests and for a
//!   deployment that terminates confidentiality elsewhere and says so.

pub mod auth;
pub mod client;
pub mod codec;
pub mod confidential;
pub mod server;
pub mod wire;

pub use auth::AuthError;
pub use client::{ClientError, TransportClient};
pub use codec::{read_frame, write_frame, CodecError};
pub use confidential::{ConfidentialError, ConfidentialStream, StaticKeypair, NOISE_PATTERN};
pub use server::{
    run_server_session, serve_connection, serve_connection_confidential, BatchAckData, BatchSink,
    ProbeAuthority, ServerError, SinkError,
};
pub use wire::{
    auth_preimage, frame_preimage, AuthResult, BatchAck, BatchFrame, Challenge, Message,
    MAX_FRAME_BYTES, PROTOCOL_VERSION,
};
