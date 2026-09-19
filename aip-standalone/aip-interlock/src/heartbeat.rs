//! The signed dead-man heartbeat: what the host sends, what the interlock
//! verifies, and the one type only verification can produce.

use aip_crypto::{sha256, sign_ed25519, verify_ed25519};
use aip_types::canonical::*;
use aip_types::{AipError, Signature};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Domain tag leading the canonical encoding of a [`Heartbeat`]. Distinct
/// from every other tag in the workspace, so a heartbeat signature cannot be
/// presented as an observer head, a warrant, or anything else.
pub const INTERLOCK_HEARTBEAT_DOMAIN: &str = "SYNTRIASS/GHOST/INTERLOCK_HEARTBEAT/v1";

/// Structure version. A verifier refuses any other value rather than
/// interpreting it.
pub const INTERLOCK_HEARTBEAT_VERSION: u16 = 1;

/// Why a host declines to vouch for actuation while still able to sign.
///
/// The interlock treats every variant identically — trip — so the reason is
/// forensic, not load-bearing. It is inside the signed bytes so a relay
/// cannot rewrite "observer blind" into "operator hold".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WithholdReason {
    /// The observer is not `Active`. Carries the observer state's own code so
    /// the record says *which* non-active state it was.
    ObserverNotActive { state_code: u8 },
    /// The enforcement tier reported itself degraded (ADR-015 §5.4).
    EnforcementDegraded,
    /// A human said stop.
    OperatorHold,
}

impl WithholdReason {
    fn code(&self) -> (u8, u8) {
        match self {
            WithholdReason::ObserverNotActive { state_code } => (0x01, *state_code),
            WithholdReason::EnforcementDegraded => (0x02, 0),
            WithholdReason::OperatorHold => (0x03, 0),
        }
    }
}

/// The host's statement about whether actuation may continue.
///
/// Only `Nominal` keeps the interlock armed. `Withheld` is a *positive*
/// statement that it may not — stronger than silence, because silence is
/// indistinguishable from a broken link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostCondition {
    Nominal,
    Withheld(WithholdReason),
}

impl HostCondition {
    fn codes(&self) -> (u8, u8, u8) {
        match self {
            HostCondition::Nominal => (0x01, 0, 0),
            HostCondition::Withheld(r) => {
                let (a, b) = r.code();
                (0x02, a, b)
            }
        }
    }
}

/// Where the heartbeat's counter came from. Named in the signed bytes so a
/// verifier knows whether the replay bound is hardware-backed.
///
/// `Atecc608b` is wire vocabulary: **no implementation in this repository
/// produces it.** The only counter source shipped is
/// [`crate::sender::SoftwareCounter`], and a heartbeat it produced says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CounterSource {
    /// A process-local counter. Survives nothing the process does not.
    Software,
    /// A hardware monotonic counter in an ATECC608B. Not implemented here.
    Atecc608b,
}

impl CounterSource {
    fn code(&self) -> u8 {
        match self {
            CounterSource::Software => 0x01,
            CounterSource::Atecc608b => 0x02,
        }
    }
}

/// One heartbeat, before signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    pub version: u16,
    /// The interlock this heartbeat is addressed to.
    pub interlock_id: String,
    /// The host-side sender; the verifier maps it to an anchored key.
    pub sender_id: String,
    /// The arming epoch. A heartbeat for another epoch trips the watchdog.
    pub epoch: [u8; 16],
    /// Strictly increasing per sender. Equal or lower trips the watchdog.
    pub counter: u64,
    pub counter_source: CounterSource,
    pub condition: HostCondition,
    /// The sender's clock. Carried for forensics; never used by the watchdog,
    /// which keeps its own time.
    pub emitted_at_ms: u64,
}

impl Heartbeat {
    /// The exact bytes the signature covers. Prefix-free: every variable
    /// field is length-prefixed, every enum is a fixed code.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, INTERLOCK_HEARTBEAT_DOMAIN);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, &self.interlock_id);
        put_str(&mut buf, &self.sender_id);
        buf.extend_from_slice(&self.epoch);
        put_u64(&mut buf, self.counter);
        put_u8(&mut buf, self.counter_source.code());
        let (c0, c1, c2) = self.condition.codes();
        put_u8(&mut buf, c0);
        put_u8(&mut buf, c1);
        put_u8(&mut buf, c2);
        put_u64(&mut buf, self.emitted_at_ms);
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }
}

/// A heartbeat plus the sender's signature over its canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedHeartbeat {
    pub heartbeat: Heartbeat,
    pub attestation: Signature,
}

impl SignedHeartbeat {
    /// Sign `heartbeat` with the sender's key. `signer_id` must equal
    /// `heartbeat.sender_id`; a heartbeat signed for someone else is refused
    /// at the source rather than at the interlock.
    pub fn sign(heartbeat: Heartbeat, private_key: &[u8]) -> Result<Self, AipError> {
        let attestation = sign_ed25519(
            private_key,
            &heartbeat.sender_id,
            &heartbeat.canonical_bytes(),
        )?;
        Ok(Self {
            heartbeat,
            attestation,
        })
    }
}

/// The interlock's trust decision: which sender identifiers map to which
/// public keys. Supplied by whoever provisions the interlock — never by the
/// heartbeat.
#[derive(Debug, Clone, Default)]
pub struct InterlockAnchors {
    keys: BTreeMap<String, Vec<u8>>,
}

impl InterlockAnchors {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn trust(mut self, sender_id: &str, public_key: &[u8]) -> Self {
        self.keys.insert(sender_id.to_string(), public_key.to_vec());
        self
    }

    pub fn get(&self, sender_id: &str) -> Option<&[u8]> {
        self.keys.get(sender_id).map(|k| k.as_slice())
    }
}

/// Why a heartbeat was not accepted. Every variant means the same thing to
/// the watchdog — *no heartbeat arrived* — and the distinction is forensic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeartbeatError {
    UnsupportedVersion(u16),
    /// The sender is not anchored. Not "unknown sender": the interlock has
    /// no opinion about senders it was not provisioned for.
    SenderNotAnchored(String),
    /// `attestation.signer_id` is not the heartbeat's `sender_id`.
    SignerIsNotSender,
    /// The signature's payload hash is not the hash of these bytes.
    PayloadHashMismatch,
    SignatureInvalid,
    /// The key was malformed, or the algorithm was not one this verifier
    /// implements.
    Crypto(AipError),
}

/// A heartbeat that verified against the interlock's own anchors.
///
/// The field is private and there is no constructor: the only way to obtain
/// one is [`verify_heartbeat`], so the watchdog cannot be handed a heartbeat
/// nobody checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedHeartbeat(Heartbeat);

impl VerifiedHeartbeat {
    pub fn heartbeat(&self) -> &Heartbeat {
        &self.0
    }
}

/// Verify a heartbeat against `anchors`. The verifier's anchors win: a
/// heartbeat cannot name the key it is judged against.
pub fn verify_heartbeat(
    signed: &SignedHeartbeat,
    anchors: &InterlockAnchors,
) -> Result<VerifiedHeartbeat, HeartbeatError> {
    let hb = &signed.heartbeat;
    if hb.version != INTERLOCK_HEARTBEAT_VERSION {
        return Err(HeartbeatError::UnsupportedVersion(hb.version));
    }
    let key = anchors
        .get(&hb.sender_id)
        .ok_or_else(|| HeartbeatError::SenderNotAnchored(hb.sender_id.clone()))?;
    if signed.attestation.signer_id != hb.sender_id {
        return Err(HeartbeatError::SignerIsNotSender);
    }
    if signed.attestation.payload_hash != hb.digest() {
        return Err(HeartbeatError::PayloadHashMismatch);
    }
    match verify_ed25519(key, &signed.attestation) {
        Ok(true) => Ok(VerifiedHeartbeat(hb.clone())),
        Ok(false) => Err(HeartbeatError::SignatureInvalid),
        Err(e) => Err(HeartbeatError::Crypto(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hb(counter: u64, condition: HostCondition) -> Heartbeat {
        Heartbeat {
            version: INTERLOCK_HEARTBEAT_VERSION,
            interlock_id: "interlock:bench-1".into(),
            sender_id: "host:cc-1".into(),
            epoch: [7u8; 16],
            counter,
            counter_source: CounterSource::Software,
            condition,
            emitted_at_ms: 1_000,
        }
    }

    #[test]
    fn canonical_bytes_lead_with_the_domain_tag() {
        let bytes = hb(1, HostCondition::Nominal).canonical_bytes();
        let tag = INTERLOCK_HEARTBEAT_DOMAIN.as_bytes();
        assert_eq!(&bytes[4..4 + tag.len()], tag);
    }

    #[test]
    fn every_field_is_inside_the_preimage() {
        let base = hb(1, HostCondition::Nominal);
        let mut variants = vec![base.clone()];
        variants.push({
            let mut h = base.clone();
            h.interlock_id.push('x');
            h
        });
        variants.push({
            let mut h = base.clone();
            h.sender_id.push('x');
            h
        });
        variants.push({
            let mut h = base.clone();
            h.epoch[0] ^= 1;
            h
        });
        variants.push({
            let mut h = base.clone();
            h.counter += 1;
            h
        });
        variants.push({
            let mut h = base.clone();
            h.counter_source = CounterSource::Atecc608b;
            h
        });
        variants.push({
            let mut h = base.clone();
            h.condition = HostCondition::Withheld(WithholdReason::OperatorHold);
            h
        });
        variants.push({
            let mut h = base.clone();
            h.condition =
                HostCondition::Withheld(WithholdReason::ObserverNotActive { state_code: 6 });
            h
        });
        variants.push({
            let mut h = base.clone();
            h.emitted_at_ms += 1;
            h
        });
        let digests: std::collections::BTreeSet<[u8; 32]> =
            variants.iter().map(|h| h.digest()).collect();
        assert_eq!(
            digests.len(),
            variants.len(),
            "a field mutation left the digest unchanged"
        );
    }

    #[test]
    fn the_preimage_is_injective_across_adjacent_string_fields() {
        let mut a = hb(1, HostCondition::Nominal);
        a.interlock_id = "ab".into();
        a.sender_id = "c".into();
        let mut b = a.clone();
        b.interlock_id = "a".into();
        b.sender_id = "bc".into();
        assert_ne!(a.digest(), b.digest());
    }
}
