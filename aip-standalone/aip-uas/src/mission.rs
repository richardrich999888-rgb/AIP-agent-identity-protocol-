//! What a mission is, and what makes one authoritative.
//!
//! # The mistake this module exists to prevent
//!
//! An aircraft carrying a mission plan is not evidence that the plan is
//! authorized. It is evidence that the aircraft has a file. Every UAS ground
//! station uploads plans, and an upload path is a write path: the plan aboard
//! is exactly as trustworthy as the party that last wrote to the vehicle.
//!
//! So a [`MissionPlan`] here is **not** authority. It becomes authoritative in
//! one way and no other: its digest is committed into `ActionParameters`, and
//! a decision point signs that parameter set as
//! `ExpectedExecution.parameter_digest`. After that the mission cannot be
//! swapped without breaking the decision point's signature.
//!
//! That is the same mechanism `ExecutionProfile::authorization_parameter` uses
//! for Skill 18's binding, and it is deliberate: **no new authority system, no
//! new signer, no new trust anchor.** The decision point is also the right
//! authority — it already decides what an agent may do, and "for this mission,
//! in this region, in this window" is part of that decision.
//!
//! # What a commitment does and does not establish
//!
//! It establishes that the mission was *authorized*. It does not establish
//! that the aircraft flew it, that the aircraft had this version aboard, or
//! that the mission was achievable. Authorized is not attested and is not
//! achieved.
//!
//! # Cancellation
//!
//! There is no revocation list here, because there does not need to be one. An
//! expectation is bounded — `ExpectedExecution.valid_until` is mandatory — so
//! a mission stops being authorized when the last expectation committing to it
//! expires and no further one is issued. Cancelling a mission is declining to
//! authorize it, which is a decision point's existing power. Adding a separate
//! mission-revocation channel would create a second place for authority to
//! live and a second place for it to be wrong.

use aip_crypto::sha256;
use aip_types::canonical::{put_bytes, put_domain, put_str, put_u16, put_u32, put_u64, put_u8};
use serde::{Deserialize, Serialize};

use crate::action::UasAction;
use crate::error::UasError;
use crate::geofence::GeofenceRegion;
use crate::{UAS_PROFILE_DOMAIN, UAS_PROFILE_VERSION};

/// The reserved `ActionParameters` key carrying the mission commitment.
///
/// Versioned in the key itself, exactly as `BINDING_PARAMETER_KEY` is: a v2
/// mission would use a different key, so a decision point that signed a v1
/// mission can never be read as having signed a v2 one. That is cheaper and
/// safer than versioning inside the value, where a reader has to remember to
/// look.
pub const MISSION_PARAMETER_KEY: &str = "aip.uas.mission.v1";

/// The interval a mission is authorized for.
///
/// Half-open `[from, until)`, so two consecutive authorizations of the same
/// mission cannot both apply at the instant of handover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissionWindow {
    pub from_ms: u64,
    pub until_ms: u64,
}

impl MissionWindow {
    pub fn contains(&self, t_ms: u64) -> bool {
        t_ms >= self.from_ms && t_ms < self.until_ms
    }

    pub fn is_valid(&self) -> bool {
        self.until_ms > self.from_ms
    }
}

/// One mission, as a document a decision point can commit to.
///
/// Carries no key, no signature and no authority. It is a description, and it
/// becomes meaningful only through [`Self::authorization_parameter`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissionPlan {
    pub version: u16,
    /// The mission, reusing `aip-system`'s identifier. This crate mints none.
    mission_id: aip_system::MissionId,
    /// The plan's own version. Two revisions of one mission are two documents
    /// with two digests, so an authorization of revision 3 is not an
    /// authorization of revision 4.
    pub revision: u32,
    /// The system the mission is for. Reused; not a new identity.
    system_id: aip_system::SystemId,
    /// The airframe the mission is planned for, when the deployment names one.
    ///
    /// `None` is correct for a mission that any airframe of a type may fly,
    /// and inventing one would make a fact out of nothing.
    pub platform_id: Option<aip_system::PlatformId>,
    /// When the mission is authorized to run.
    pub window: MissionWindow,
    /// The boundary the mission is authorized to operate inside.
    pub region: GeofenceRegion,
    /// The actions the mission is authorized to perform.
    ///
    /// Sorted and deduplicated on construction, so two plans authorizing the
    /// same set encode identically whatever order they were written in.
    authorized_actions: Vec<UasAction>,
}

impl MissionPlan {
    /// Build a plan, validating what participates in a security decision.
    ///
    /// Refuses an empty or inverted window: a mission authorized at no instant
    /// is not a mission, and storing one silently would produce a plan that is
    /// committed and never applies.
    ///
    /// Refuses an empty action set for the same reason — a mission that
    /// authorizes nothing would commit a decision point to a document with no
    /// content, which is a signature over an assumption.
    pub fn new(
        mission_id: aip_system::MissionId,
        revision: u32,
        system_id: aip_system::SystemId,
        window: MissionWindow,
        region: GeofenceRegion,
        authorized_actions: &[UasAction],
    ) -> Result<Self, UasError> {
        if !window.is_valid() {
            return Err(UasError::Malformed {
                reason: "a mission window must be non-empty and forward in time",
            });
        }
        if authorized_actions.is_empty() {
            return Err(UasError::Malformed {
                reason: "a mission must authorize at least one action",
            });
        }
        let mut actions = authorized_actions.to_vec();
        actions.sort_unstable();
        actions.dedup();
        Ok(Self {
            version: UAS_PROFILE_VERSION,
            mission_id,
            revision,
            system_id,
            platform_id: None,
            window,
            region,
            authorized_actions: actions,
        })
    }

    pub fn on_platform(mut self, platform: aip_system::PlatformId) -> Self {
        self.platform_id = Some(platform);
        self
    }

    /// Read-only: the fields are private so a caller cannot swap an identity
    /// in after the digest was computed and committed.
    pub fn mission_id(&self) -> &aip_system::MissionId {
        &self.mission_id
    }
    pub fn system_id(&self) -> &aip_system::SystemId {
        &self.system_id
    }
    pub fn authorized_actions(&self) -> &[UasAction] {
        &self.authorized_actions
    }

    /// Whether the plan authorizes `action`.
    ///
    /// A plain set membership test, deliberately. There is no inference here —
    /// authorizing `Takeoff` does not imply `Land`, and a profile that
    /// inferred one action from another would be a policy engine.
    pub fn authorizes(&self, action: UasAction) -> bool {
        self.authorized_actions.contains(&action)
    }

    /// Whether the plan applies at `t_ms`. Not whether it was authorized —
    /// that is the decision point's signature, checked elsewhere.
    pub fn applies_at(&self, t_ms: u64) -> bool {
        self.window.contains(t_ms)
    }

    pub fn check_version(&self) -> Result<(), UasError> {
        if self.version != UAS_PROFILE_VERSION {
            return Err(UasError::UnsupportedVersion {
                found: self.version,
                supported: UAS_PROFILE_VERSION,
            });
        }
        Ok(())
    }

    /// Domain-tagged, injective canonical bytes.
    ///
    /// Every field that distinguishes one plan from another is inside them,
    /// including the revision and every authorized action, counted and in
    /// sorted order. A truncated action list is not a valid prefix of a longer
    /// one, so a plan cannot be trimmed after signing without changing the
    /// digest.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, UAS_PROFILE_DOMAIN);
        // A structure discriminant inside the shared domain, so a mission
        // plan's preimage can never collide with another profile structure's.
        put_u8(&mut buf, 0x01);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, self.mission_id.as_str());
        put_u32(&mut buf, self.revision);
        put_str(&mut buf, self.system_id.as_str());
        match &self.platform_id {
            Some(p) => {
                put_u8(&mut buf, 1);
                put_str(&mut buf, p.as_str());
            }
            None => put_u8(&mut buf, 0),
        }
        put_u64(&mut buf, self.window.from_ms);
        put_u64(&mut buf, self.window.until_ms);
        put_u8(&mut buf, self.region.frame.code());
        put_u8(&mut buf, self.region.altitude_reference.code());
        for v in [
            self.region.min_lat_udeg,
            self.region.max_lat_udeg,
            self.region.min_lon_udeg,
            self.region.max_lon_udeg,
            self.region.min_alt_cm,
            self.region.max_alt_cm,
        ] {
            // Two's-complement little-endian, fixed width: a negative bound is
            // as encodable as a positive one and neither can be a prefix of
            // the other.
            put_bytes(&mut buf, &v.to_le_bytes());
        }
        put_u32(&mut buf, self.authorized_actions.len() as u32);
        for a in &self.authorized_actions {
            put_u8(&mut buf, a.code());
        }
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }

    /// The `(key, value)` pair to add to `ActionParameters` so a decision
    /// point signs this mission.
    ///
    /// The value is the plan's digest, not the plan: `ActionParameters` carries
    /// byte strings, and a digest is a complete commitment to a
    /// domain-separated prefix-free encoding — not a bare hash standing in for
    /// one.
    pub fn authorization_parameter(&self) -> (String, Vec<u8>) {
        (MISSION_PARAMETER_KEY.to_owned(), self.digest().to_vec())
    }

    /// Whether `parameter_value` commits to this exact plan.
    ///
    /// Takes the key's value as the caller read it from a **verified**
    /// `ActionParameters`. This function verifies nothing about the signature:
    /// comparing a digest against unverified parameters proves only that two
    /// untrusted things agree, and the caller must already have verified the
    /// `ExpectedExecution` that carries the parameter digest.
    ///
    /// Returns `false` for a missing key rather than erroring: a decision point
    /// that committed to no mission is a fact to report, not an exception.
    pub fn is_committed_by(&self, parameter_value: Option<&[u8]>) -> bool {
        match parameter_value {
            Some(v) => v == self.digest(),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geofence::{AltitudeReference, CoordinateFrame};

    fn region() -> GeofenceRegion {
        GeofenceRegion {
            frame: CoordinateFrame::Wgs84Geodetic,
            altitude_reference: AltitudeReference::GeoidMsl,
            min_lat_udeg: 51_000_000,
            max_lat_udeg: 52_000_000,
            min_lon_udeg: -1_000_000,
            max_lon_udeg: 1_000_000,
            min_alt_cm: 0,
            max_alt_cm: 12_000,
        }
    }

    fn plan(revision: u32, actions: &[UasAction]) -> MissionPlan {
        MissionPlan::new(
            aip_system::MissionId::parse("op:survey-17").unwrap(),
            revision,
            aip_system::SystemId::parse("uas:tail-07").unwrap(),
            MissionWindow {
                from_ms: 1_000,
                until_ms: 100_000,
            },
            region(),
            actions,
        )
        .unwrap()
    }

    #[test]
    fn a_plan_carries_no_authority_until_a_decision_point_commits_to_it() {
        let p = plan(1, &[UasAction::WaypointNavigate]);
        // Nothing supplied: not committed.
        assert!(!p.is_committed_by(None));
        // The right digest: committed.
        assert!(p.is_committed_by(Some(&p.digest())));
        // Someone else's digest: not.
        let other = plan(2, &[UasAction::WaypointNavigate]);
        assert!(!p.is_committed_by(Some(&other.digest())));
    }

    #[test]
    fn a_revision_change_is_a_different_document() {
        assert_ne!(
            plan(1, &[UasAction::Takeoff]).digest(),
            plan(2, &[UasAction::Takeoff]).digest()
        );
    }

    #[test]
    fn the_action_set_is_order_independent_and_content_sensitive() {
        let a = plan(1, &[UasAction::Takeoff, UasAction::Land]);
        let b = plan(1, &[UasAction::Land, UasAction::Takeoff]);
        assert_eq!(a.digest(), b.digest(), "order must not change the document");
        let c = plan(1, &[UasAction::Takeoff]);
        assert_ne!(a.digest(), c.digest(), "content must");
    }

    #[test]
    fn a_duplicated_action_does_not_change_the_document() {
        let a = plan(1, &[UasAction::Takeoff]);
        let b = plan(1, &[UasAction::Takeoff, UasAction::Takeoff]);
        assert_eq!(a.digest(), b.digest());
        assert_eq!(b.authorized_actions().len(), 1);
    }

    #[test]
    fn authorizing_one_action_never_implies_another() {
        let p = plan(1, &[UasAction::Takeoff]);
        assert!(p.authorizes(UasAction::Takeoff));
        assert!(
            !p.authorizes(UasAction::Land),
            "inferring one action from another would make this a policy engine"
        );
        assert!(!p.authorizes(UasAction::PayloadRelease));
    }

    #[test]
    fn an_empty_or_inverted_window_is_refused() {
        for (from, until) in [(10u64, 10u64), (10, 5)] {
            let r = MissionPlan::new(
                aip_system::MissionId::parse("op:x").unwrap(),
                1,
                aip_system::SystemId::parse("uas:y").unwrap(),
                MissionWindow {
                    from_ms: from,
                    until_ms: until,
                },
                region(),
                &[UasAction::Takeoff],
            );
            assert!(r.is_err(), "window [{from}, {until}) must be refused");
        }
    }

    #[test]
    fn a_mission_authorizing_nothing_is_refused() {
        assert!(MissionPlan::new(
            aip_system::MissionId::parse("op:x").unwrap(),
            1,
            aip_system::SystemId::parse("uas:y").unwrap(),
            MissionWindow {
                from_ms: 1,
                until_ms: 2
            },
            region(),
            &[],
        )
        .is_err());
    }

    #[test]
    fn the_window_is_half_open() {
        let p = plan(1, &[UasAction::Takeoff]);
        assert!(!p.applies_at(999));
        assert!(p.applies_at(1_000));
        assert!(p.applies_at(99_999));
        assert!(
            !p.applies_at(100_000),
            "half-open so two consecutive authorizations cannot both apply at handover"
        );
    }

    #[test]
    fn a_region_change_changes_the_document() {
        let a = plan(1, &[UasAction::Takeoff]);
        let mut wider = region();
        wider.max_alt_cm += 1;
        let b = MissionPlan::new(
            aip_system::MissionId::parse("op:survey-17").unwrap(),
            1,
            aip_system::SystemId::parse("uas:tail-07").unwrap(),
            MissionWindow {
                from_ms: 1_000,
                until_ms: 100_000,
            },
            wider,
            &[UasAction::Takeoff],
        )
        .unwrap();
        assert_ne!(a.digest(), b.digest(), "the fence is part of the mission");
    }

    #[test]
    fn the_parameter_key_is_versioned_in_the_key_itself() {
        let (k, v) = plan(1, &[UasAction::Takeoff]).authorization_parameter();
        assert_eq!(k, "aip.uas.mission.v1");
        assert_eq!(v.len(), 32);
    }

    #[test]
    fn the_encoding_is_deterministic() {
        let p = plan(1, &[UasAction::Takeoff, UasAction::Land]);
        assert_eq!(p.canonical_bytes(), p.canonical_bytes());
        assert_eq!(p.digest(), p.digest());
    }
}
