//! `ObservationRecord` — one verified observation, bound to what it describes.
//!
//! # Why it cannot be manufactured
//!
//! The core architectural principle is that the subject being judged must not
//! control the evidence used to judge it. Here that is enforced by
//! construction: the only constructor takes an [`AttestedBatch`] and the
//! verifier's own [`ObserverTrustAnchors`], and verifies the batch before
//! reading anything out of it. There is no `new`, no `from_parts`, and no
//! constructor that accepts an `AiriEvent`, a self-reported binding, or an
//! attestation.
//!
//! A compromised agent going through the normal SDK path produces AIRI events.
//! There is no function here that turns one into an `ObservationRecord`.
//!
//! # Why it must be correlated
//!
//! An observation that is not bound to an execution is evidence for *any*
//! execution. The record therefore carries the system, execution and host-boot
//! it describes, all inside its canonical preimage, and
//! [`ObservationRecord::describes`] answers whether it may be used for a given
//! execution at all.
//!
//! # What it does not carry
//!
//! No observer key, no signature of its own, and no `EvidenceStrength`.
//! Observer key custody stays in `aip-observe`; strength stays in
//! `aip-reconcile`. This record is an input to both, and authority in neither.

use aip_observe::{verify_attested_batch, AttestedBatch, ObserverTrustAnchors, SourceMechanism};
use aip_system::SystemId;
use aip_types::canonical::{put_bytes, put_domain, put_str, put_u16, put_u32, put_u64, put_u8};
use serde::{Deserialize, Serialize};

use crate::class::{class_of, EvidenceCeiling, ObservationClass};
use crate::completeness::Completeness;
use crate::error::ObservationError;

/// Domain tag leading every `ObservationRecord` canonical encoding.
pub const OBSERVATION_RECORD_DOMAIN: &str = "SYNTRIASS/AUTONOMY/OBSERVATION_RECORD/v1";

/// Structure version. Unknown versions are refused, never guessed.
pub const OBSERVATION_RECORD_VERSION: u16 = 1;

/// What an observation claims to be about.
///
/// All three identities are inside the record's preimage, so none can be
/// exchanged for another without changing the digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationCorrelation {
    /// The autonomous system. Reused from `aip-system`; no new identifier.
    pub system_id: SystemId,
    /// The execution instance. Reused from `aip-airi`'s width and meaning.
    pub execution_id: [u8; 16],
    /// The host-boot the observation was measured on.
    ///
    /// Measured by the probe from `/proc/sys/kernel/random/boot_id` and
    /// carried inside the signed batch — never claimed by the agent.
    pub boot_id: [u8; 16],
    /// The decision this execution claims, when it claims one. `None` is a
    /// statement a verifier can act on, and more honest than a fabricated id.
    pub decision_id: Option<[u8; 16]>,
}

impl ObservationCorrelation {
    fn encode(&self, buf: &mut Vec<u8>) {
        put_str(buf, self.system_id.as_str());
        put_bytes(buf, &self.execution_id);
        put_bytes(buf, &self.boot_id);
        match &self.decision_id {
            Some(d) => {
                put_u8(buf, 1);
                put_bytes(buf, d);
            }
            None => put_u8(buf, 0),
        }
    }
}

/// One verified observation of one class, bound to one execution.
///
/// # Why this type is `Serialize` but not `Deserialize`
///
/// [`Self::from_attested`] is documented as the only constructor, and the
/// Skill 20 suite states the property as "it cannot be constructed at all
/// without a batch that verifies against the verifier's own anchors".
///
/// A derived `Deserialize` **was** such a construction path, and it was
/// reachable: `serde_json::from_str::<ObservationRecord>(..)` built a record
/// naming an observer the verifier never anchored, with a sequence, a
/// mechanism and a completeness of the writer's choosing, having consulted no
/// batch and no anchors. Every downstream consumer — `describes`,
/// `measured_on`, `ceiling_under`, and everything Skill 21 builds on them —
/// treats a record as already verified, so a forged one is indistinguishable
/// from a real one at the point of use.
///
/// The derive is therefore removed rather than guarded. `#[serde(try_from)]`
/// is the pattern used elsewhere in this workspace (`EffectEvidence`,
/// `aip-system`'s identifiers) and it is the wrong tool here: a `TryFrom` at
/// deserialization has no batch and no anchors, so it cannot perform the one
/// check that matters, and would launder the bypass behind a validating name.
///
/// Writing a record out stays supported. Reading one back is not a gap to be
/// filled later with a permissive parse — a record that crossed a wire has
/// lost the thing that made it evidence, and the correct move on the far side
/// is to re-derive it from the attested batch, which is what `from_attested`
/// is for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObservationRecord {
    pub version: u16,
    /// Which observer attested it. A reference the existing anchor model
    /// resolves; naming an observer grants nothing.
    observer_id: String,
    /// Which of that observer's keys signed the batch. Carried so revocation
    /// of one key version does not invalidate history under another.
    key_version: u32,
    /// The collector's chain position for the batch this came from. Assigned
    /// off-host, so a wiped host cannot re-assert a place in history.
    sequence: u64,
    /// The mechanism that produced it, and hence its class.
    mechanism: SourceMechanism,
    /// What the observation is about.
    pub correlation: ObservationCorrelation,
    /// The collector's own clock when it signed the batch. Off-host and
    /// signed, so an event inside cannot have happened after this moment.
    attested_at_ms: u64,
    completeness: Completeness,
}

impl ObservationRecord {
    /// Build a record from a batch this function verifies first.
    ///
    /// The **only** constructor. `anchors` is the verifier's own; a batch that
    /// does not verify against them yields an error and no record, so a caller
    /// cannot proceed with evidence it did not earn.
    ///
    /// `index` selects the observation within the batch — typically the one
    /// the reconciler matched. `correlation.boot_id` is checked against the
    /// measured boot of that observation: a record may not claim a host the
    /// observer did not measure.
    pub fn from_attested(
        batch: &AttestedBatch,
        anchors: &ObserverTrustAnchors,
        index: usize,
        correlation: ObservationCorrelation,
    ) -> Result<Self, ObservationError> {
        verify_attested_batch(batch, anchors).map_err(|_| {
            ObservationError::ObserverNotTrusted {
                observer_id: batch.observer_id.clone(),
            }
        })?;

        let obs = batch.batch.observations.get(index).ok_or({
            ObservationError::Malformed {
                reason: "no observation at that index in the batch",
            }
        })?;

        // The record may not claim a host the observer did not measure.
        // Without this, a correctly verified batch could be relabelled onto
        // another platform — the observation would be real and the binding a
        // fiction.
        if obs.observed.process.boot_id != correlation.boot_id {
            return Err(ObservationError::Malformed {
                reason: "correlation boot id does not match the measured boot id",
            });
        }

        Ok(Self {
            version: OBSERVATION_RECORD_VERSION,
            observer_id: batch.observer_id.clone(),
            key_version: batch.key_version,
            sequence: batch.sequence,
            mechanism: obs.mechanism,
            correlation,
            attested_at_ms: batch.attested_at_ms,
            completeness: Completeness::Observed,
        })
    }

    pub fn observer_id(&self) -> &str {
        &self.observer_id
    }
    pub fn key_version(&self) -> u32 {
        self.key_version
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn mechanism(&self) -> SourceMechanism {
        self.mechanism
    }
    pub fn attested_at_ms(&self) -> u64 {
        self.attested_at_ms
    }
    pub fn completeness(&self) -> Completeness {
        self.completeness
    }

    /// The class of what was observed.
    pub fn class(&self) -> ObservationClass {
        class_of(self.mechanism)
    }

    /// The strongest evidence this record could contribute, given its class
    /// and the deployment's declared capability.
    ///
    /// The **minimum** of the two, so a profile can be more conservative than
    /// the architecture and never less. This is a ceiling, not a strength:
    /// `aip-reconcile` decides what a record actually contributes, and this
    /// crate never computes an `EvidenceStrength`.
    pub fn ceiling_under(&self, profile: &crate::profile::ObservationProfile) -> EvidenceCeiling {
        self.class()
            .ceiling()
            .min(profile.capability(self.class()).ceiling())
    }

    /// Whether this record may be used as evidence about `(system, execution)`.
    ///
    /// The property that stops an arbitrary observation becoming evidence for
    /// a different execution. Both identities must match; a record that
    /// describes something else is not weaker evidence, it is evidence about
    /// another subject.
    pub fn describes(&self, system_id: &SystemId, execution_id: &[u8; 16]) -> bool {
        &self.correlation.system_id == system_id && &self.correlation.execution_id == execution_id
    }

    /// Whether this record was measured on `boot_id`.
    pub fn measured_on(&self, boot_id: &[u8; 16]) -> bool {
        &self.correlation.boot_id == boot_id
    }

    pub fn check_version(&self) -> Result<(), ObservationError> {
        if self.version != OBSERVATION_RECORD_VERSION {
            return Err(ObservationError::UnsupportedVersion {
                found: self.version,
                supported: OBSERVATION_RECORD_VERSION,
            });
        }
        Ok(())
    }

    /// Domain-tagged, injective canonical bytes.
    ///
    /// Every field that distinguishes one record from another is inside them:
    /// the observer and key version, the chain position, the mechanism, all
    /// three correlated identities, the collector clock and the completeness.
    /// Length-prefixed with presence bytes on optionals.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, OBSERVATION_RECORD_DOMAIN);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, &self.observer_id);
        put_u32(&mut buf, self.key_version);
        put_u64(&mut buf, self.sequence);
        put_u8(&mut buf, self.mechanism.code());
        self.class().encode(&mut buf);
        self.correlation.encode(&mut buf);
        put_u64(&mut buf, self.attested_at_ms);
        self.completeness.encode(&mut buf);
        buf
    }

    /// SHA-256 over the canonical bytes, for embedding in a signed artifact.
    ///
    /// This crate signs nothing. As with Skills 17-19, integrity comes from a
    /// consumer committing to these bytes inside something already signed —
    /// never from a signer added here.
    pub fn digest(&self) -> [u8; 32] {
        aip_crypto::sha256(&self.canonical_bytes())
    }
}
