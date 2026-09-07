//! The five identities the reference keeps apart, and what survives what.
//!
//! # Why this module exists
//!
//! Every incident review of an autonomous system eventually asks "was it the
//! same thing?" — and the honest answer depends entirely on which *thing* is
//! meant. A container id, a pid, a boot id, a platform and an autonomous
//! system are five different subjects with five different lifetimes, and the
//! failure mode is not that someone confuses them deliberately. It is that a
//! dashboard has one column called "id", and continuity gets manufactured by a
//! join.
//!
//! This module states the five, states what each one is derived from, and
//! states what changes it survives. It computes nothing about a live system:
//! it is a table, and the reference prints it next to the run so a reader can
//! check the run's behaviour against it instead of against an intuition.
//!
//! # The table is not a claim about the reference's competence
//!
//! Where a row says a kind is `NotEstablished`, that is a statement that this
//! build has no mechanism for it, and it is the reason the corresponding
//! question comes back `CANNOT_PROVE` rather than `false`. Hardware identity
//! is the standing example: ADR-002 is PROPOSED, `BindingMethod::HardwareAttested`
//! is unreachable, and no amount of observation here reaches it.

use serde::{Deserialize, Serialize};

/// One of the five subjects an "identity" in this reference can be about.
///
/// Ordered from the most ephemeral to the most durable. The `Ord` derive
/// follows that ordering deliberately, so a caller can ask whether one kind
/// outlives another rather than remembering the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IdentityKind {
    /// A process instance: `(pid, pid_start_time_ticks, boot_id)`.
    ///
    /// Measured by the probe. Dies with the process; a new process of the same
    /// binary is a different instance, and that is the point — `aip_types`
    /// compares all three fields precisely so pid reuse cannot impersonate it.
    Process,
    /// A container, as Linux actually implements one: a set of namespaces and
    /// a cgroup, named by whatever the runtime chose.
    ///
    /// **Not established by this reference, and deliberately not derived.**
    /// A container id is an orchestrator's label, a namespace inode number is
    /// reused after the namespace is freed, and neither is measured by any
    /// mechanism in `aip-observe`. Treating either as an identity would import
    /// a self-reported name into a signed record.
    Container,
    /// A host-boot, named by `/proc/sys/kernel/random/boot_id`.
    ///
    /// The only value in the system that distinguishes one machine-boot from
    /// another *and* is produced by something other than the subject: the
    /// probe reads it and the collector signs the batch containing it. A
    /// reboot produces a new one, so a registration legitimately stops
    /// applying — fail-closed, and the reason hardware replacement cannot be
    /// detected here (ADR-002, gap G1).
    Platform,
    /// The physical compute element.
    ///
    /// **Not established.** ADR-002 is PROPOSED. `PlatformRegistry` may carry
    /// a `HardwareId`, but that is a *verifier assertion* about a boot id, not
    /// a measurement of silicon, and `BindingMethod::HardwareAttested` has no
    /// constructor in this build.
    Hardware,
    /// The durable autonomous system: `SystemId`, plus the AIRI
    /// `execution_id` for one run of it.
    ///
    /// Declared by the deployment, not measured. It survives every restart,
    /// every reboot and every hardware replacement, because it is the thing
    /// those events happen *to*.
    System,
}

/// What a kind survives.
///
/// Three states rather than a boolean, because "this build cannot tell" and
/// "this build can tell and the answer is no" are different facts and summing
/// them is how a blind spot becomes a clean bill of health — the same
/// distinction `Completeness` draws one layer down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IdentityStability {
    /// The identity is the same value after the event.
    Survives,
    /// The identity is a different value after the event, detectably.
    Changes,
    /// This build has no mechanism that would establish the identity at all,
    /// so it cannot say whether it changed. Never read as `Survives`.
    NotEstablished,
}

impl IdentityKind {
    /// Every kind, for exhaustive sweeps.
    pub const ALL: [IdentityKind; 5] = [
        Self::Process,
        Self::Container,
        Self::Platform,
        Self::Hardware,
        Self::System,
    ];

    /// Stable wire code, assigned explicitly so reordering cannot change what
    /// previously encoded bytes mean.
    pub fn code(self) -> u8 {
        match self {
            Self::Process => 0x01,
            Self::Container => 0x02,
            Self::Platform => 0x03,
            Self::Hardware => 0x04,
            Self::System => 0x05,
        }
    }

    /// Where the value comes from, in one line, for the reference's output.
    pub fn derived_from(self) -> &'static str {
        match self {
            Self::Process => "probe measurement of (pid, start ticks, boot id) under a pidfd anchor",
            Self::Container => "nothing: no mechanism in this build measures a container",
            Self::Platform => "probe measurement of /proc/sys/kernel/random/boot_id, inside a signed batch",
            Self::Hardware => "nothing: ADR-002 is PROPOSED and HardwareAttested is unreachable",
            Self::System => "the deployment's declaration, plus the AIRI execution id",
        }
    }

    /// Whether this reference establishes the identity independently of the
    /// subject.
    ///
    /// `Process` and `Platform` are `true` because an anchored observer
    /// measures them. `System` is `false` not because it is untrustworthy but
    /// because it is *declared* — a verifier asserts it, exactly as it asserts
    /// which observer keys it trusts.
    pub fn independently_established(self) -> bool {
        matches!(self, Self::Process | Self::Platform)
    }

    /// What happens to this identity when the **workload process restarts**
    /// on the same host-boot.
    pub fn across_workload_restart(self) -> IdentityStability {
        match self {
            // A new instance: new pid, or the same pid with different start
            // ticks. Either way the tuple differs and the difference is
            // measured, not inferred.
            Self::Process => IdentityStability::Changes,
            Self::Container | Self::Hardware => IdentityStability::NotEstablished,
            // Same boot.
            Self::Platform => IdentityStability::Survives,
            // The system is what restarted; it did not become another system.
            // The AIRI execution id, however, is per-run: a restart is a new
            // execution, and the reference must not carry the old one across.
            Self::System => IdentityStability::Survives,
        }
    }

    /// What happens when the **observer process restarts**.
    ///
    /// Nothing about the workload changes, which is the point: an observer
    /// restart is a coverage event, not an identity event. What it does cost
    /// is the collector's chain continuity, and `aip-observe` already refuses
    /// to extend coverage across the gap.
    pub fn across_observer_restart(self) -> IdentityStability {
        match self {
            Self::Process | Self::Platform | Self::System => IdentityStability::Survives,
            Self::Container | Self::Hardware => IdentityStability::NotEstablished,
        }
    }

    /// What happens when the workload is re-entered in **new namespaces**
    /// (the `unshare(2)` reference case).
    ///
    /// The pid the workload sees changes; the pid the observer sees, from the
    /// initial pid namespace, is a different number again. The instance tuple
    /// the observer measures is the one that counts, and it is a new instance
    /// because it is a new process — not because the namespace changed.
    pub fn across_namespace_change(self) -> IdentityStability {
        match self {
            Self::Process => IdentityStability::Changes,
            // Still nothing: a new namespace set is not a measured identity,
            // and inventing one from its inode numbers would be exactly the
            // manufactured continuity this module exists to refuse.
            Self::Container | Self::Hardware => IdentityStability::NotEstablished,
            Self::Platform | Self::System => IdentityStability::Survives,
        }
    }

    /// What happens across a **host reboot**.
    pub fn across_host_reboot(self) -> IdentityStability {
        match self {
            Self::Process => IdentityStability::Changes,
            // A new boot id. The registry entry for the old one legitimately
            // stops applying, and a new registration is a deliberate act by
            // the verifier — which is what stops old trust surviving new
            // hardware silently.
            Self::Platform => IdentityStability::Changes,
            Self::Container | Self::Hardware => IdentityStability::NotEstablished,
            Self::System => IdentityStability::Survives,
        }
    }
}

impl IdentityStability {
    pub fn code(self) -> u8 {
        match self {
            Self::Survives => 0x01,
            Self::Changes => 0x02,
            Self::NotEstablished => 0x03,
        }
    }

    /// Whether continuity may be asserted from this state.
    ///
    /// True for `Survives` alone. `NotEstablished` is deliberately false: the
    /// whole module exists to stop "we cannot tell" being read as "it is the
    /// same one".
    pub fn asserts_continuity(self) -> bool {
        matches!(self, Self::Survives)
    }
}
