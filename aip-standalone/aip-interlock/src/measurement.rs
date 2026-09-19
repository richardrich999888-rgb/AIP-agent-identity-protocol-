//! A signed reading from the interlock board's own sensing channel.
//!
//! This is the piece that turns a relay into an observer. The board is
//! outside the machine's software, holds its own key, and is wired into the
//! actuator path; a current or encoder reading it signs is an
//! **off-machine, independently keyed measurement of a physical quantity**.
//!
//! It is deliberately **not** an `aip_observation::ObservationRecord`. That
//! type's only constructor takes an attested batch carrying a
//! `SourceMechanism`, and no mechanism for a physical sense channel exists.
//! Adding one is Stage 4 of the physical validation roadmap and is a change
//! to `aip-observation`, not to this crate — which is why `aip-observation`
//! is not a dependency here, and a test pins that it stays that way.

use aip_crypto::{sha256, sign_ed25519, verify_ed25519};
use aip_types::canonical::*;
use aip_types::{AipError, Signature};
use serde::{Deserialize, Serialize};

use crate::heartbeat::InterlockAnchors;

pub const INTERLOCK_MEASUREMENT_DOMAIN: &str = "SYNTRIASS/GHOST/INTERLOCK_MEASUREMENT/v1";
pub const INTERLOCK_MEASUREMENT_VERSION: u16 = 1;

/// What the board measured. Each channel names its unit in the variant so a
/// value cannot be re-read in another unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SenseChannel {
    /// Current on the actuator supply line, in milliamps.
    CurrentMilliamps,
    /// Ticks from an encoder wired to the board — not to the machine's own
    /// controller.
    EncoderTicks,
    /// The relay's own contact state as read back, not as commanded:
    /// 1 closed, 0 open.
    RelayContactState,
}

impl SenseChannel {
    fn code(&self) -> u8 {
        match self {
            SenseChannel::CurrentMilliamps => 0x01,
            SenseChannel::EncoderTicks => 0x02,
            SenseChannel::RelayContactState => 0x03,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterlockMeasurement {
    pub version: u16,
    pub interlock_id: String,
    pub actuator_id: String,
    pub channel: SenseChannel,
    pub value: i64,
    /// The heartbeat counter the board had most recently accepted when it
    /// sampled. Places the reading relative to the host's vouching, without
    /// trusting the host's clock.
    pub at_counter: u64,
    /// The board's own clock.
    pub sampled_at_ms: u64,
}

impl InterlockMeasurement {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, INTERLOCK_MEASUREMENT_DOMAIN);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, &self.interlock_id);
        put_str(&mut buf, &self.actuator_id);
        put_u8(&mut buf, self.channel.code());
        put_u64(&mut buf, self.value as u64);
        put_u64(&mut buf, self.at_counter);
        put_u64(&mut buf, self.sampled_at_ms);
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedInterlockMeasurement {
    pub measurement: InterlockMeasurement,
    pub attestation: Signature,
}

impl SignedInterlockMeasurement {
    /// Sign with the *board's* key. The signer is the interlock, never the
    /// host — the reading's value is that the host did not produce it.
    pub fn sign(
        measurement: InterlockMeasurement,
        board_private_key: &[u8],
    ) -> Result<Self, AipError> {
        let attestation = sign_ed25519(
            board_private_key,
            &measurement.interlock_id,
            &measurement.canonical_bytes(),
        )?;
        Ok(Self {
            measurement,
            attestation,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeasurementError {
    UnsupportedVersion(u16),
    BoardNotAnchored(String),
    SignerIsNotBoard,
    PayloadHashMismatch,
    SignatureInvalid,
    Crypto(AipError),
}

/// Verify a measurement against anchors that map interlock ids to board
/// keys. Establishes authorship and integrity of the reading — **not** that
/// the reading is true, and not that it is an observation in the Vanian
/// sense (see module docs).
pub fn verify_measurement<'a>(
    signed: &'a SignedInterlockMeasurement,
    anchors: &InterlockAnchors,
) -> Result<&'a InterlockMeasurement, MeasurementError> {
    let m = &signed.measurement;
    if m.version != INTERLOCK_MEASUREMENT_VERSION {
        return Err(MeasurementError::UnsupportedVersion(m.version));
    }
    let key = anchors
        .get(&m.interlock_id)
        .ok_or_else(|| MeasurementError::BoardNotAnchored(m.interlock_id.clone()))?;
    if signed.attestation.signer_id != m.interlock_id {
        return Err(MeasurementError::SignerIsNotBoard);
    }
    if signed.attestation.payload_hash != m.digest() {
        return Err(MeasurementError::PayloadHashMismatch);
    }
    match verify_ed25519(key, &signed.attestation) {
        Ok(true) => Ok(m),
        Ok(false) => Err(MeasurementError::SignatureInvalid),
        Err(e) => Err(MeasurementError::Crypto(e)),
    }
}
