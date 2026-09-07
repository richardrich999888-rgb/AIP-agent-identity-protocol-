//! Six identities a robot has, and what survives what.
//!
//! # Why six and not one
//!
//! A robot is not one thing. It is a chassis, a controller, a companion
//! computer, some sensors, and a piece of software, assembled by an integrator
//! and maintained by replacing parts. "Is it the same robot?" has six answers
//! and they diverge in the field: a controller swapped after a fault leaves the
//! chassis identity untouched, and a chassis retired leaves the *system*
//! identity intact if the operator says it does.
//!
//! The failure mode is not that anyone confuses them deliberately. It is that a
//! fleet dashboard has one column called "robot", and continuity gets
//! manufactured by a join.
//!
//! # Software continuity is not physical continuity
//!
//! The rule this module exists for. A companion computer that did not reboot
//! establishes that a *process* continued. It establishes nothing about
//! whether the arm was re-cabled, the gripper replaced or the whole chassis
//! swapped underneath it — all of which happen, and none of which the software
//! notices.

use serde::{Deserialize, Serialize};

/// One of the six subjects a robot "identity" can be about.
///
/// Ordered from the most ephemeral to the most durable; the `Ord` derive
/// follows that deliberately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RobotIdentityKind {
    /// A process instance on the companion computer: `(pid, start ticks,
    /// boot id)`, measured under a pidfd anchor.
    Process,
    /// A container, as Linux implements one. **Not established**: no mechanism
    /// measures a namespace set or a cgroup as an identity, and a namespace
    /// inode is reused after it is freed.
    Container,
    /// The motion or motor controller. Expressed as a `HardwareId` in a
    /// controller namespace.
    ///
    /// **Not established**: no mechanism measures it. A controller announces
    /// its serial number over a bus the subject owns, which is the subject
    /// announcing it.
    Controller,
    /// The companion computer's host-boot, from
    /// `/proc/sys/kernel/random/boot_id` inside a signed batch.
    CompanionBoot,
    /// The chassis, cell or arm: the physical platform. A `PlatformId`.
    ///
    /// **Not established** by any mechanism here; it is a verifier assertion
    /// keyed on the companion computer's boot id, which is a statement about
    /// the computer and inherited by the chassis only by the operator's word.
    Platform,
    /// The durable robot as an operational thing: a `SystemId`, plus the AIRI
    /// `execution_id` for one run of its autonomy.
    ///
    /// Declared by the deployment, not measured. It survives every restart and
    /// every part replacement, because those are things that happen *to* it.
    System,
}

/// What a kind survives.
///
/// Three states, not a boolean: "this build cannot tell" and "this build can
/// tell and the answer is no" are different facts, and summing them turns a
/// blind spot into a clean bill of health.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RobotIdentityStability {
    Survives,
    Changes,
    NotEstablished,
}

impl RobotIdentityStability {
    pub fn code(self) -> u8 {
        match self {
            Self::Survives => 0x01,
            Self::Changes => 0x02,
            Self::NotEstablished => 0x03,
        }
    }

    /// Whether continuity may be asserted from this state. True for `Survives`
    /// alone: the module exists to stop "we cannot tell" being read as "it is
    /// the same one".
    pub fn asserts_continuity(self) -> bool {
        matches!(self, Self::Survives)
    }
}

impl RobotIdentityKind {
    pub const ALL: [RobotIdentityKind; 6] = [
        Self::Process,
        Self::Container,
        Self::Controller,
        Self::CompanionBoot,
        Self::Platform,
        Self::System,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::Process => 0x01,
            Self::Container => 0x02,
            Self::Controller => 0x03,
            Self::CompanionBoot => 0x04,
            Self::Platform => 0x05,
            Self::System => 0x06,
        }
    }

    pub fn derived_from(self) -> &'static str {
        match self {
            Self::Process => {
                "probe measurement of (pid, start ticks, boot id) under a pidfd anchor"
            }
            Self::Container => "nothing: no mechanism measures a container",
            Self::Controller => {
                "nothing: a controller's serial arrives over a bus the subject owns"
            }
            Self::CompanionBoot => {
                "probe measurement of /proc/sys/kernel/random/boot_id, inside a signed batch"
            }
            Self::Platform => "a verifier assertion keyed on the companion computer's boot id",
            Self::System => "the deployment's declaration, plus the AIRI execution id",
        }
    }

    /// Whether this reference establishes the identity independently of the
    /// subject.
    ///
    /// Two of six. Note that `Platform` is `false`: the registry resolves a
    /// *boot* to a platform, so what is measured is the computer and the
    /// chassis is inherited by assertion. That is honest and it is weaker than
    /// it sounds, which is why it is stated here rather than assumed.
    pub fn independently_established(self) -> bool {
        matches!(self, Self::Process | Self::CompanionBoot)
    }

    /// The autonomy process restarts on the same companion computer.
    pub fn across_process_restart(self) -> RobotIdentityStability {
        match self {
            Self::Process => RobotIdentityStability::Changes,
            Self::Container | Self::Controller => RobotIdentityStability::NotEstablished,
            Self::CompanionBoot | Self::Platform | Self::System => RobotIdentityStability::Survives,
        }
    }

    /// The motion controller restarts or is power-cycled.
    ///
    /// Nothing the companion computer measures changes, which is the finding: a
    /// controller restart is invisible to every mechanism this build has, and a
    /// controller *replacement* is invisible in exactly the same way.
    pub fn across_controller_restart(self) -> RobotIdentityStability {
        match self {
            Self::Controller | Self::Container => RobotIdentityStability::NotEstablished,
            Self::Process | Self::CompanionBoot | Self::Platform | Self::System => {
                RobotIdentityStability::Survives
            }
        }
    }

    /// The companion computer reboots.
    pub fn across_companion_reboot(self) -> RobotIdentityStability {
        match self {
            Self::Process | Self::CompanionBoot => RobotIdentityStability::Changes,
            // The registry entry for the old boot legitimately stops applying;
            // registering the new one is a deliberate act by the verifier,
            // which is what stops old trust surviving new hardware silently.
            Self::Platform => RobotIdentityStability::Changes,
            Self::Container | Self::Controller => RobotIdentityStability::NotEstablished,
            Self::System => RobotIdentityStability::Survives,
        }
    }

    /// A part is replaced — controller, gripper, arm, or the whole chassis.
    ///
    /// The case that matters most and that this build handles worst. Only the
    /// declared system identity has an answer, and the answer is that the
    /// operator decides.
    pub fn across_component_replacement(self) -> RobotIdentityStability {
        match self {
            // The software did not notice. That is not continuity of the
            // machine; it is absence of a mechanism.
            Self::Process | Self::CompanionBoot => RobotIdentityStability::NotEstablished,
            Self::Container | Self::Controller | Self::Platform => {
                RobotIdentityStability::NotEstablished
            }
            Self::System => RobotIdentityStability::Survives,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_companion_computer_is_independently_established() {
        let established: Vec<RobotIdentityKind> = RobotIdentityKind::ALL
            .iter()
            .copied()
            .filter(|k| k.independently_established())
            .collect();
        assert_eq!(
            established,
            vec![RobotIdentityKind::Process, RobotIdentityKind::CompanionBoot],
            "everything measured is measured about the computer, not the machine"
        );
    }

    #[test]
    fn the_controller_identity_is_never_established() {
        let k = RobotIdentityKind::Controller;
        assert!(!k.independently_established());
        for s in [
            k.across_process_restart(),
            k.across_controller_restart(),
            k.across_companion_reboot(),
            k.across_component_replacement(),
        ] {
            assert_eq!(s, RobotIdentityStability::NotEstablished);
            assert!(!s.asserts_continuity());
        }
    }

    #[test]
    fn software_continuity_is_not_physical_continuity() {
        // The rule. A component replacement leaves the process and the boot
        // untouched, and this build must report that as `NotEstablished` rather
        // than as continuity of the robot.
        for k in [RobotIdentityKind::Process, RobotIdentityKind::CompanionBoot] {
            assert_eq!(
                k.across_component_replacement(),
                RobotIdentityStability::NotEstablished,
                "{k:?}: an unchanged process must not imply an unchanged machine"
            );
        }
    }

    #[test]
    fn a_controller_restart_is_invisible_and_says_so() {
        assert_eq!(
            RobotIdentityKind::Controller.across_controller_restart(),
            RobotIdentityStability::NotEstablished
        );
    }

    #[test]
    fn a_companion_reboot_changes_the_boot_and_the_platform_binding() {
        assert_eq!(
            RobotIdentityKind::CompanionBoot.across_companion_reboot(),
            RobotIdentityStability::Changes
        );
        assert_eq!(
            RobotIdentityKind::Platform.across_companion_reboot(),
            RobotIdentityStability::Changes
        );
        assert_eq!(
            RobotIdentityKind::System.across_companion_reboot(),
            RobotIdentityStability::Survives
        );
    }

    #[test]
    fn a_kind_no_mechanism_measures_reports_neither_survival_nor_change() {
        // The property worth enforcing, and it is narrower than "anything not
        // independently established must never assert continuity". `Platform`
        // legitimately survives a process restart: what survives is a *verifier
        // assertion* keyed on a boot id that did not change, which is a real
        // statement even though the chassis itself was never measured.
        //
        // `Container` and `Controller` are different. Nothing measures them at
        // all, so every event must answer `NotEstablished` — neither `Survives`
        // nor `Changes`, because both would be inventing an observation.
        for k in [RobotIdentityKind::Container, RobotIdentityKind::Controller] {
            for s in [
                k.across_process_restart(),
                k.across_controller_restart(),
                k.across_companion_reboot(),
                k.across_component_replacement(),
            ] {
                assert_eq!(s, RobotIdentityStability::NotEstablished, "{k:?}");
                assert!(!s.asserts_continuity(), "{k:?}");
            }
        }
    }

    #[test]
    fn platform_continuity_is_continuity_of_an_assertion_not_of_a_chassis() {
        // Survives a process restart, because the boot the assertion is keyed
        // on did not change. Does NOT survive a component replacement, because
        // nothing measured the chassis and the assertion cannot speak to it.
        assert_eq!(
            RobotIdentityKind::Platform.across_process_restart(),
            RobotIdentityStability::Survives
        );
        assert_eq!(
            RobotIdentityKind::Platform.across_component_replacement(),
            RobotIdentityStability::NotEstablished,
            "an unchanged boot must not imply an unchanged machine"
        );
        assert!(
            !RobotIdentityKind::Platform.independently_established(),
            "what is measured is the computer; the chassis is inherited by assertion"
        );
    }

    #[test]
    fn every_kind_states_where_it_comes_from() {
        let mut codes: Vec<u8> = RobotIdentityKind::ALL.iter().map(|k| k.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), 6);
        for k in RobotIdentityKind::ALL {
            assert!(!k.derived_from().is_empty(), "{k:?}");
        }
    }
}
