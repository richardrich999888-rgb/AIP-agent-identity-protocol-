//! Autonomy modes, and the transitions between them.
//!
//! # What a transition record is
//!
//! A declaration by the subject that it changed how it was operating, committed
//! so that a later claim about *when* it changed cannot be revised. It is not
//! an observation: nothing outside the vehicle saw the mode change, and on a
//! disconnected vehicle nothing could have.
//!
//! So a transition establishes that the subject *said* it changed mode, and —
//! once the commitment is signed into an expectation — that it said so before
//! the evidence arrived rather than after. That second property is the useful
//! one, and it is the only one this module claims.
//!
//! # Why the cause is not modelled
//!
//! The obvious next field is "why": loss of signal, a fault, a planned
//! manoeuvre, ground command. Every one of those is the subject's account of
//! its own reasons, and a vehicle that entered autonomous mode because it was
//! compromised reports exactly the same field as one that lost the link. The
//! record carries a deployment-supplied reason string that is committed and
//! never interpreted, and [`AutonomyModeTransition::cause_established`] is
//! `false`.

use aip_crypto::sha256;
use aip_types::canonical::{put_domain, put_str, put_u16, put_u32, put_u64, put_u8};
use serde::{Deserialize, Serialize};

use crate::error::SpaceError;
use crate::link::LinkState;
use crate::{SPACE_PROFILE_DOMAIN, SPACE_PROFILE_VERSION};

/// The reserved action-parameter key carrying a mode-transition commitment.
pub const MODE_TRANSITION_PARAMETER_KEY: &str = "aip.space.mode_transition.v1";

/// How the vehicle is operating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AutonomyMode {
    /// Ground is in the loop for each action.
    GroundCommanded,
    /// Executing a ground-uploaded sequence, with ground reachable.
    SupervisedSequence,
    /// Executing a ground-uploaded sequence with no ground contact.
    UnsupervisedSequence,
    /// Deciding onboard, within a ground-authorized envelope.
    OnboardAutonomous,
    /// A safe mode entered on fault. Minimal function, awaiting ground.
    SafeMode,
    /// Loss of signal handling: a pre-agreed behaviour on link timeout.
    LinkLossContingency,
}

impl AutonomyMode {
    pub const ALL: [AutonomyMode; 6] = [
        Self::GroundCommanded,
        Self::SupervisedSequence,
        Self::UnsupervisedSequence,
        Self::OnboardAutonomous,
        Self::SafeMode,
        Self::LinkLossContingency,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::GroundCommanded => 0x01,
            Self::SupervisedSequence => 0x02,
            Self::UnsupervisedSequence => 0x03,
            Self::OnboardAutonomous => 0x04,
            Self::SafeMode => 0x05,
            Self::LinkLossContingency => 0x06,
        }
    }

    /// Whether ground authority is contemporaneous with the action in this
    /// mode.
    ///
    /// True for two of six. In the other four the authorization predates the
    /// action by however long the outage lasted, which is precisely why
    /// `ExpectedExecution`'s bounded window and `AuthorityStanding` matter more
    /// here than anywhere else in the system.
    pub fn ground_authority_is_contemporaneous(self) -> bool {
        matches!(self, Self::GroundCommanded | Self::SupervisedSequence)
    }

    /// Whether the mode can be entered without ground involvement.
    pub fn entered_autonomously(self) -> bool {
        matches!(
            self,
            Self::SafeMode | Self::LinkLossContingency | Self::OnboardAutonomous
        )
    }

    /// What a report of this mode establishes.
    pub fn statement(self) -> &'static str {
        match self {
            Self::GroundCommanded => {
                "ground issued each action; the authorization is contemporaneous and the \
                 execution is still only what an observer measured"
            }
            Self::SupervisedSequence => {
                "a ground-uploaded sequence was running with ground reachable; that ground could \
                 have intervened is not that it did"
            }
            Self::UnsupervisedSequence => {
                "a sequence was running with no contact; every claim about it rests on evidence \
                 collected onboard and delivered later"
            }
            Self::OnboardAutonomous => {
                "the vehicle decided onboard within a declared envelope; that it stayed inside \
                 the envelope is a claim about the vehicle, made by the vehicle"
            }
            Self::SafeMode => {
                "the vehicle reported entering safe mode; that a fault occurred, and which, is \
                 the vehicle's account of itself"
            }
            Self::LinkLossContingency => {
                "the vehicle reported acting on link timeout; the timeout is measured by the \
                 vehicle's own clock"
            }
        }
    }
}

/// One declared change of autonomy mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutonomyModeTransition {
    pub version: u16,
    system_id: aip_system::SystemId,
    /// The mission or activity this transition belongs to.
    mission_id: aip_system::MissionId,
    /// Monotonic index of this transition within the mission. Two transitions
    /// at one index under one mission are a fork, exactly as for segments.
    pub index: u32,
    pub from_mode: AutonomyMode,
    pub to_mode: AutonomyMode,
    /// The link state the vehicle believed it was in. Self-reported.
    pub link_state: LinkState,
    /// The vehicle's own clock at the transition. Self-reported: on a
    /// disconnected vehicle there is nothing else it could be.
    pub onboard_at_ms: u64,
    /// A deployment-supplied reason. Committed, never interpreted.
    reason: String,
}

impl AutonomyModeTransition {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        system_id: aip_system::SystemId,
        mission_id: aip_system::MissionId,
        index: u32,
        from_mode: AutonomyMode,
        to_mode: AutonomyMode,
        link_state: LinkState,
        onboard_at_ms: u64,
        reason: &str,
    ) -> Result<Self, SpaceError> {
        if from_mode == to_mode {
            return Err(SpaceError::Malformed {
                reason: "a transition must change the mode; a repeated mode is not a transition",
            });
        }
        if reason.is_empty() || reason.len() > 256 {
            return Err(SpaceError::Malformed {
                reason: "a transition reason must be 1-256 bytes",
            });
        }
        Ok(Self {
            version: SPACE_PROFILE_VERSION,
            system_id,
            mission_id,
            index,
            from_mode,
            to_mode,
            link_state,
            onboard_at_ms,
            reason: reason.to_owned(),
        })
    }

    pub fn system_id(&self) -> &aip_system::SystemId {
        &self.system_id
    }
    pub fn mission_id(&self) -> &aip_system::MissionId {
        &self.mission_id
    }
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Whether the *cause* of the transition is established by anything here.
    ///
    /// **`false`, unconditionally.** The reason is the subject's account of its
    /// own reasons, and a vehicle that entered autonomous mode because it was
    /// compromised writes the same field as one that lost the link.
    pub fn cause_established(&self) -> bool {
        false
    }

    /// Whether the transition itself was independently observed.
    ///
    /// **`false`.** Nothing outside the vehicle saw it, and on a disconnected
    /// vehicle nothing could have. Computed from the class table so that a
    /// future mechanism has to change the table rather than leave a stale
    /// literal.
    pub fn independently_observed(&self) -> bool {
        aip_observation::ObservationClass::PhysicalEffect.is_implemented()
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

    /// Domain-tagged, injective canonical bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, SPACE_PROFILE_DOMAIN);
        // Structure discriminant inside the shared domain: 0x02 is a mode
        // transition.
        put_u8(&mut buf, 0x02);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, self.system_id.as_str());
        put_str(&mut buf, self.mission_id.as_str());
        put_u32(&mut buf, self.index);
        put_u8(&mut buf, self.from_mode.code());
        put_u8(&mut buf, self.to_mode.code());
        put_u8(&mut buf, self.link_state.code());
        put_u64(&mut buf, self.onboard_at_ms);
        put_str(&mut buf, &self.reason);
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }

    /// The `(key, value)` pair committing this transition into action
    /// parameters, which a decision point then signs.
    pub fn authorization_parameter(&self) -> (String, Vec<u8>) {
        (
            MODE_TRANSITION_PARAMETER_KEY.to_owned(),
            self.digest().to_vec(),
        )
    }

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

    fn sys() -> aip_system::SystemId {
        aip_system::SystemId::parse("space:sat-7").unwrap()
    }
    fn mission() -> aip_system::MissionId {
        aip_system::MissionId::parse("mission:pass-114").unwrap()
    }

    fn transition(index: u32, to: AutonomyMode, reason: &str) -> AutonomyModeTransition {
        AutonomyModeTransition::new(
            sys(),
            mission(),
            index,
            AutonomyMode::SupervisedSequence,
            to,
            LinkState::Disconnected,
            10_000,
            reason,
        )
        .unwrap()
    }

    #[test]
    fn no_transition_establishes_its_own_cause_or_is_observed() {
        for to in AutonomyMode::ALL
            .iter()
            .filter(|m| **m != AutonomyMode::SupervisedSequence)
        {
            let t = transition(1, *to, "loss of signal");
            assert!(!t.cause_established(), "{to:?}");
            assert!(!t.independently_observed(), "{to:?}");
        }
    }

    #[test]
    fn only_two_modes_have_contemporaneous_ground_authority() {
        let contemporaneous: Vec<AutonomyMode> = AutonomyMode::ALL
            .iter()
            .copied()
            .filter(|m| m.ground_authority_is_contemporaneous())
            .collect();
        assert_eq!(
            contemporaneous,
            vec![
                AutonomyMode::GroundCommanded,
                AutonomyMode::SupervisedSequence
            ]
        );
    }

    #[test]
    fn a_repeated_mode_is_not_a_transition() {
        assert!(AutonomyModeTransition::new(
            sys(),
            mission(),
            1,
            AutonomyMode::SafeMode,
            AutonomyMode::SafeMode,
            LinkState::Disconnected,
            1,
            "why"
        )
        .is_err());
    }

    #[test]
    fn the_reason_is_committed_and_changes_the_digest() {
        let a = transition(1, AutonomyMode::SafeMode, "loss of signal");
        let b = transition(1, AutonomyMode::SafeMode, "planned manoeuvre");
        assert_ne!(
            a.digest(),
            b.digest(),
            "a different stated reason is a different declaration"
        );
        // And committing to one does not commit to the other.
        assert!(a.is_committed_by(Some(&a.digest())));
        assert!(!a.is_committed_by(Some(&b.digest())));
        assert!(!a.is_committed_by(None));
    }

    #[test]
    fn every_committed_field_moves_the_digest() {
        let base = transition(1, AutonomyMode::SafeMode, "r");
        let other_index = transition(2, AutonomyMode::SafeMode, "r");
        let other_mode = transition(1, AutonomyMode::OnboardAutonomous, "r");
        let other_link = AutonomyModeTransition::new(
            sys(),
            mission(),
            1,
            AutonomyMode::SupervisedSequence,
            AutonomyMode::SafeMode,
            LinkState::Connected,
            10_000,
            "r",
        )
        .unwrap();
        let other_time = AutonomyModeTransition::new(
            sys(),
            mission(),
            1,
            AutonomyMode::SupervisedSequence,
            AutonomyMode::SafeMode,
            LinkState::Disconnected,
            10_001,
            "r",
        )
        .unwrap();
        for other in [other_index, other_mode, other_link, other_time] {
            assert_ne!(base.digest(), other.digest());
        }
    }

    #[test]
    fn a_transition_for_one_vehicle_does_not_commit_for_another() {
        let a = transition(1, AutonomyMode::SafeMode, "r");
        let b = AutonomyModeTransition::new(
            aip_system::SystemId::parse("space:sat-9").unwrap(),
            mission(),
            1,
            AutonomyMode::SupervisedSequence,
            AutonomyMode::SafeMode,
            LinkState::Disconnected,
            10_000,
            "r",
        )
        .unwrap();
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn bounds_and_versions_are_checked() {
        assert!(AutonomyModeTransition::new(
            sys(),
            mission(),
            1,
            AutonomyMode::GroundCommanded,
            AutonomyMode::SafeMode,
            LinkState::Connected,
            1,
            ""
        )
        .is_err());
        assert!(AutonomyModeTransition::new(
            sys(),
            mission(),
            1,
            AutonomyMode::GroundCommanded,
            AutonomyMode::SafeMode,
            LinkState::Connected,
            1,
            &"x".repeat(257)
        )
        .is_err());
        assert!(transition(1, AutonomyMode::SafeMode, "r")
            .check_version()
            .is_ok());
    }

    #[test]
    fn every_mode_states_what_it_establishes_and_codes_are_unique() {
        let mut codes: Vec<u8> = AutonomyMode::ALL.iter().map(|m| m.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), AutonomyMode::ALL.len());
        for m in AutonomyMode::ALL {
            assert!(!m.statement().is_empty(), "{m:?}");
        }
    }
}
