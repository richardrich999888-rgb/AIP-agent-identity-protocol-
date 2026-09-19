//! Store-and-forward: collecting evidence with no link, and moving it later.
//!
//! # What a bundle is
//!
//! A container for **one contiguous run of attested segments** collected while
//! the vehicle could not send them. It is not evidence. It carries evidence,
//! commits to what it carries, and is refused if what it carries does not match
//! what it says.
//!
//! The contiguity requirement is load-bearing. A bundle with a hole in it is
//! two bundles pretending to be one, and accepting it would let the sender
//! choose which gaps a verifier notices — the sender being the party under
//! scrutiny.
//!
//! # A bundle is a container, and containers are not leaves
//!
//! NEXORA's nine leaf kinds are frozen. The contents of a bundle are already
//! committable as `AttestedBatch`, `SignedHealth`, `Expectation` and
//! `Reconciliation` leaves; the bundle itself commits to those contents by
//! digest and adds no leaf kind. A verifier reconstructs from the contents
//! through the existing verifier, not from the container.
//!
//! # Replay across contacts
//!
//! A bundle presented at a second contact is the same bundle. [`BundleLedger`]
//! keys on the bundle digest, so re-presenting one after reconnection is
//! refused — the same discipline `aip-nexora::ProofLedger` applies to proofs,
//! and for the same reason: being seen twice is a fact about submissions, not
//! about evidence.

use std::collections::BTreeSet;

use aip_crypto::sha256;
use aip_types::canonical::{put_bytes, put_domain, put_str, put_u16, put_u32, put_u64, put_u8};
use serde::{Deserialize, Serialize};

use crate::error::SpaceError;
use crate::link::LinkState;
use crate::{SPACE_PROFILE_DOMAIN, SPACE_PROFILE_VERSION};

/// One attested segment's position and content commitment.
///
/// Mirrors the triple `ObserverLedger::admit` consumes — sequence, `prev_head`,
/// `head` — because that ledger is the continuity authority and this struct
/// exists to feed it, not to second-guess it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleSegment {
    /// The collector's chain position.
    pub sequence: u64,
    /// The head this segment declares it follows.
    pub prev_head: [u8; 32],
    /// This segment's head.
    pub head: [u8; 32],
    /// The onboard collector's clock when it attested. The only clock in the
    /// bundle that bounds an event.
    pub attested_at_ms: u64,
    /// Digest of the evidence bytes this segment stands for — an attested
    /// batch, a signed health record. The bytes travel beside the bundle;
    /// the bundle commits to them.
    pub payload_digest: [u8; 32],
}

impl BundleSegment {
    fn encode(&self, buf: &mut Vec<u8>) {
        put_u64(buf, self.sequence);
        put_bytes(buf, &self.prev_head);
        put_bytes(buf, &self.head);
        put_u64(buf, self.attested_at_ms);
        put_bytes(buf, &self.payload_digest);
    }
}

/// Evidence collected offline, packaged for a later contact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreAndForwardBundle {
    pub version: u16,
    system_id: aip_system::SystemId,
    mission_id: aip_system::MissionId,
    /// The collector whose chain these segments belong to.
    observer_id: String,
    /// Declared first and last sequence. Checked against the contents.
    pub first_sequence: u64,
    pub last_sequence: u64,
    segments: Vec<BundleSegment>,
    /// The interval the vehicle says the collection covers. Onboard clock.
    pub collected_from_ms: u64,
    pub collected_until_ms: u64,
    /// The link state when the bundle was closed. Self-reported context.
    pub link_state_at_close: LinkState,
}

impl StoreAndForwardBundle {
    /// Build a bundle, refusing anything that is not one contiguous run.
    ///
    /// Every check here can only refuse. There is no repair path: a bundle that
    /// does not describe itself correctly is returned to the sender, because
    /// the alternative is a verifier deciding what the sender meant.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        system_id: aip_system::SystemId,
        mission_id: aip_system::MissionId,
        observer_id: &str,
        segments: Vec<BundleSegment>,
        collected_from_ms: u64,
        collected_until_ms: u64,
        link_state_at_close: LinkState,
    ) -> Result<Self, SpaceError> {
        if observer_id.is_empty() || observer_id.len() > 128 {
            return Err(SpaceError::Malformed {
                reason: "observer id must be 1-128 bytes",
            });
        }
        if segments.is_empty() {
            return Err(SpaceError::Malformed {
                reason: "an empty bundle is not a bundle",
            });
        }
        if collected_until_ms < collected_from_ms {
            return Err(SpaceError::Malformed {
                reason: "a collection interval must not run backwards",
            });
        }

        let first = segments[0].sequence;
        let last = segments[segments.len() - 1].sequence;

        // Contiguity, and the internal chain. Both are refusals, never repairs.
        for pair in segments.windows(2) {
            let expected = pair[0].sequence + 1;
            if pair[1].sequence != expected {
                return Err(SpaceError::BundleNotContiguous {
                    expected,
                    found: pair[1].sequence,
                });
            }
            if pair[1].prev_head != pair[0].head {
                return Err(SpaceError::Malformed {
                    reason: "a segment does not chain to its predecessor inside the bundle",
                });
            }
        }

        // No span check here: contiguity above already forces
        // `last - first + 1 == segments.len()`, so a range check at this point
        // could never fire. The truncation defence belongs where the *declared*
        // fields can disagree with the contents, which is `check`.

        Ok(Self {
            version: SPACE_PROFILE_VERSION,
            system_id,
            mission_id,
            observer_id: observer_id.to_owned(),
            first_sequence: first,
            last_sequence: last,
            segments,
            collected_from_ms,
            collected_until_ms,
            link_state_at_close,
        })
    }

    pub fn system_id(&self) -> &aip_system::SystemId {
        &self.system_id
    }
    pub fn mission_id(&self) -> &aip_system::MissionId {
        &self.mission_id
    }
    pub fn observer_id(&self) -> &str {
        &self.observer_id
    }
    pub fn segments(&self) -> &[BundleSegment] {
        &self.segments
    }
    pub fn len(&self) -> usize {
        self.segments.len()
    }
    pub fn is_empty(&self) -> bool {
        false // refused at construction
    }

    /// Re-check the invariants a deserialised bundle claims.
    ///
    /// `new` enforces contiguity at construction, but a bundle arriving over a
    /// link was not constructed here, and its **declared** `first_sequence` and
    /// `last_sequence` can disagree with the segments it actually carries. That
    /// is what a truncated bundle looks like, and this is the only place the
    /// disagreement is detected. This is the function a receiving ground
    /// station calls.
    pub fn check(&self) -> Result<(), SpaceError> {
        Self::new(
            self.system_id.clone(),
            self.mission_id.clone(),
            &self.observer_id,
            self.segments.clone(),
            self.collected_from_ms,
            self.collected_until_ms,
            self.link_state_at_close,
        )
        .and_then(|rebuilt| {
            if rebuilt.first_sequence == self.first_sequence
                && rebuilt.last_sequence == self.last_sequence
            {
                Ok(())
            } else {
                Err(SpaceError::BundleRangeMismatch {
                    declared_first: self.first_sequence,
                    declared_last: self.last_sequence,
                    actual_len: self.segments.len(),
                })
            }
        })
    }

    pub fn check_version(&self) -> Result<(), SpaceError> {
        if self.version != SPACE_PROFILE_VERSION {
            return Err(SpaceError::UnsupportedVersion {
                found: self.version,
                supported: SPACE_PROFILE_VERSION,
            });
        }
        Ok(())
    }

    /// Domain-tagged, injective canonical bytes over **every** field.
    ///
    /// Every field, so forged metadata changes the digest: a bundle relabelled
    /// with a different mission, observer, interval or link state is a
    /// different bundle.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, SPACE_PROFILE_DOMAIN);
        // Structure discriminant inside the shared domain: 0x03 is a bundle.
        put_u8(&mut buf, 0x03);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, self.system_id.as_str());
        put_str(&mut buf, self.mission_id.as_str());
        put_str(&mut buf, &self.observer_id);
        put_u64(&mut buf, self.first_sequence);
        put_u64(&mut buf, self.last_sequence);
        put_u64(&mut buf, self.collected_from_ms);
        put_u64(&mut buf, self.collected_until_ms);
        put_u8(&mut buf, self.link_state_at_close.code());
        put_u32(&mut buf, self.segments.len() as u32);
        for s in &self.segments {
            s.encode(&mut buf);
        }
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }
}

/// Which bundles a ground station has already admitted.
///
/// Deliberately outside any verification function: verification is a pure
/// function of bytes and anchors, and duplicate detection is inherently
/// stateful. The same separation `aip-nexora::ProofLedger` makes, applied one
/// layer down.
#[derive(Debug, Clone, Default)]
pub struct BundleLedger {
    seen: BTreeSet<[u8; 32]>,
}

impl BundleLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether this exact bundle has been admitted before.
    pub fn has_seen(&self, bundle: &StoreAndForwardBundle) -> bool {
        self.seen.contains(&bundle.digest())
    }

    /// Admit a bundle once.
    ///
    /// Refuses the second presentation. Being presented after a reconnection
    /// does not make a bundle fresh.
    pub fn admit(&mut self, bundle: &StoreAndForwardBundle) -> Result<(), SpaceError> {
        bundle.check_version()?;
        bundle.check()?;
        let d = bundle.digest();
        if !self.seen.insert(d) {
            return Err(SpaceError::BundleAlreadySeen { digest: d });
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(sequence: u64) -> BundleSegment {
        BundleSegment {
            sequence,
            prev_head: [sequence as u8; 32],
            head: [(sequence + 1) as u8; 32],
            attested_at_ms: 1_000 + sequence,
            payload_digest: [0xAB; 32],
        }
    }

    fn bundle_of(
        range: std::ops::RangeInclusive<u64>,
    ) -> Result<StoreAndForwardBundle, SpaceError> {
        StoreAndForwardBundle::new(
            aip_system::SystemId::parse("space:sat-7").unwrap(),
            aip_system::MissionId::parse("mission:pass-114").unwrap(),
            "onboard-collector",
            range.map(seg).collect(),
            1_000,
            9_000,
            LinkState::Reconnected,
        )
    }

    #[test]
    fn a_contiguous_bundle_is_accepted_and_describes_itself() {
        let b = bundle_of(5..=9).unwrap();
        assert_eq!(b.first_sequence, 5);
        assert_eq!(b.last_sequence, 9);
        assert_eq!(b.len(), 5);
        assert!(b.check().is_ok());
        assert!(b.check_version().is_ok());
    }

    #[test]
    fn a_bundle_with_a_hole_is_refused() {
        let segments = vec![seg(5), seg(6), seg(9)];
        let e = StoreAndForwardBundle::new(
            aip_system::SystemId::parse("space:sat-7").unwrap(),
            aip_system::MissionId::parse("mission:pass-114").unwrap(),
            "obs",
            segments,
            1_000,
            9_000,
            LinkState::Reconnected,
        )
        .unwrap_err();
        assert!(matches!(
            e,
            SpaceError::BundleNotContiguous {
                expected: 7,
                found: 9
            }
        ));
    }

    #[test]
    fn a_bundle_whose_internal_chain_breaks_is_refused() {
        let mut segments = vec![seg(5), seg(6)];
        segments[1].prev_head = [0xFF; 32];
        assert!(StoreAndForwardBundle::new(
            aip_system::SystemId::parse("space:sat-7").unwrap(),
            aip_system::MissionId::parse("mission:pass-114").unwrap(),
            "obs",
            segments,
            1_000,
            9_000,
            LinkState::Reconnected,
        )
        .is_err());
    }

    #[test]
    fn an_empty_or_malformed_bundle_is_refused() {
        // An empty segment list, stated directly rather than as an empty
        // range: clippy is right that `5..=4` yields nothing, and what the
        // test means is "a bundle carrying no segments".
        assert!(
            StoreAndForwardBundle::new(
                aip_system::SystemId::parse("space:sat-7").unwrap(),
                aip_system::MissionId::parse("mission:pass-114").unwrap(),
                "obs",
                Vec::new(),
                1_000,
                9_000,
                LinkState::Connected,
            )
            .is_err(),
            "a bundle carrying no segments is not a bundle"
        );
        assert!(StoreAndForwardBundle::new(
            aip_system::SystemId::parse("space:sat-7").unwrap(),
            aip_system::MissionId::parse("mission:pass-114").unwrap(),
            "",
            vec![seg(1)],
            1_000,
            9_000,
            LinkState::Connected,
        )
        .is_err());
        assert!(
            StoreAndForwardBundle::new(
                aip_system::SystemId::parse("space:sat-7").unwrap(),
                aip_system::MissionId::parse("mission:pass-114").unwrap(),
                "obs",
                vec![seg(1)],
                9_000,
                1_000,
                LinkState::Connected,
            )
            .is_err(),
            "interval runs backwards"
        );
    }

    #[test]
    fn a_truncated_bundle_fails_its_own_range_check() {
        // The tail is cut off in transit: the struct still declares 5..=9 and
        // carries three segments.
        let good = bundle_of(5..=9).unwrap();
        let mut json = serde_json::to_value(&good).unwrap();
        let segs = json["segments"].as_array().unwrap()[..3].to_vec();
        json["segments"] = serde_json::Value::Array(segs);
        let truncated: StoreAndForwardBundle = serde_json::from_value(json).unwrap();
        assert!(matches!(
            truncated.check(),
            Err(SpaceError::BundleRangeMismatch { .. })
        ));
    }

    #[test]
    fn forged_metadata_changes_the_digest() {
        let base = bundle_of(5..=9).unwrap();
        let other_mission = StoreAndForwardBundle::new(
            aip_system::SystemId::parse("space:sat-7").unwrap(),
            aip_system::MissionId::parse("mission:pass-115").unwrap(),
            "onboard-collector",
            (5..=9).map(seg).collect(),
            1_000,
            9_000,
            LinkState::Reconnected,
        )
        .unwrap();
        let other_observer = StoreAndForwardBundle::new(
            aip_system::SystemId::parse("space:sat-7").unwrap(),
            aip_system::MissionId::parse("mission:pass-114").unwrap(),
            "other-collector",
            (5..=9).map(seg).collect(),
            1_000,
            9_000,
            LinkState::Reconnected,
        )
        .unwrap();
        let other_window = StoreAndForwardBundle::new(
            aip_system::SystemId::parse("space:sat-7").unwrap(),
            aip_system::MissionId::parse("mission:pass-114").unwrap(),
            "onboard-collector",
            (5..=9).map(seg).collect(),
            1_001,
            9_000,
            LinkState::Reconnected,
        )
        .unwrap();
        let other_link = StoreAndForwardBundle::new(
            aip_system::SystemId::parse("space:sat-7").unwrap(),
            aip_system::MissionId::parse("mission:pass-114").unwrap(),
            "onboard-collector",
            (5..=9).map(seg).collect(),
            1_000,
            9_000,
            LinkState::Connected,
        )
        .unwrap();
        for other in [other_mission, other_observer, other_window, other_link] {
            assert_ne!(base.digest(), other.digest());
        }
    }

    #[test]
    fn a_changed_payload_digest_changes_the_bundle_digest() {
        let base = bundle_of(5..=5).unwrap();
        let mut tampered_seg = seg(5);
        tampered_seg.payload_digest = [0xCD; 32];
        let tampered = StoreAndForwardBundle::new(
            aip_system::SystemId::parse("space:sat-7").unwrap(),
            aip_system::MissionId::parse("mission:pass-114").unwrap(),
            "onboard-collector",
            vec![tampered_seg],
            1_000,
            9_000,
            LinkState::Reconnected,
        )
        .unwrap();
        assert_ne!(base.digest(), tampered.digest());
    }

    #[test]
    fn a_duplicate_bundle_is_refused_at_the_second_contact() {
        let mut ledger = BundleLedger::new();
        let b = bundle_of(5..=9).unwrap();
        assert!(!ledger.has_seen(&b));
        assert!(ledger.admit(&b).is_ok());
        assert!(ledger.has_seen(&b));
        assert!(matches!(
            ledger.admit(&b),
            Err(SpaceError::BundleAlreadySeen { .. })
        ));
        assert_eq!(
            ledger.len(),
            1,
            "a refused duplicate must not grow the ledger"
        );
    }

    #[test]
    fn a_different_bundle_is_not_a_duplicate() {
        let mut ledger = BundleLedger::new();
        assert!(ledger.admit(&bundle_of(5..=9).unwrap()).is_ok());
        assert!(ledger.admit(&bundle_of(10..=12).unwrap()).is_ok());
        assert_eq!(ledger.len(), 2);
    }
}
