//! `ObservationClass` — the environment-neutral layer above `SourceMechanism`.
//!
//! # Why this layer exists (ADR-003, decision 1)
//!
//! `SourceMechanism` is a closed enum of nine Linux mechanisms, each mapped to
//! a real kernel facility and each documented precisely. That precision is
//! what makes it trustworthy and what makes it unusable as a vocabulary for
//! other environments.
//!
//! A UAS altimeter, a UGV wheel encoder, an industrial flow meter and a
//! spacecraft attitude sensor are all observation sources, and none is a Linux
//! mechanism. Representing one by adding a variant to `SourceMechanism` would
//! put a device-specific value into signed bytes that every verifier must
//! understand — a schema fork of the accountability core, per vertical.
//!
//! A class says *what kind of thing was observed*. A mechanism says *how, on
//! this operating system*. A future environment adds an implementation of a
//! class, never a variant of a Linux enum.
//!
//! # The ceiling
//!
//! Each class declares the strongest evidence it could ever contribute. This
//! is **declared, not computed**: it is a static property of the class, an
//! upper bound only, and it is not an `EvidenceStrength` — the reconciler
//! remains the only thing that assigns one. `tests/ceiling.rs` asserts the
//! declared table stays consistent with what `precondition_holds` enforces, so
//! the declaration cannot drift above the enforcement.

use aip_observe::SourceMechanism;
use aip_types::canonical::put_u8;
use serde::{Deserialize, Serialize};

/// The strongest evidence an observation class could ever contribute.
///
/// **Not `EvidenceStrength`.** That type is per-record, is computed, and
/// belongs to `aip-reconcile`. This is a declared ceiling on a *class*, it is
/// never computed from a record, and a value here asserts nothing about any
/// particular observation — only what the class could at best support.
///
/// Ordered so a caller can compare ceilings; ordering is the only operation
/// that makes sense on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EvidenceCeiling {
    /// Nothing this class produces can support a positive finding on its own.
    Corroborative,
    /// Content measured from the observed host. Root-forgeable there, so it
    /// can corroborate but can never be recomputed by a third party.
    Attested,
    /// Facts a third party recomputes from held bytes — signature and chain
    /// arithmetic. The only ceiling above `Attested`, and reachable by exactly
    /// one class.
    Proven,
}

impl EvidenceCeiling {
    pub fn code(self) -> u8 {
        match self {
            Self::Corroborative => 0x01,
            Self::Attested => 0x02,
            Self::Proven => 0x03,
        }
    }
}

/// What kind of thing was observed.
///
/// Closed on purpose. An open vocabulary could not carry a ceiling, and two
/// deployments would spell the same class differently. Adding a class is an
/// ADR-level change, which is the intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ObservationClass {
    /// A process instance existed, forked, exec'd or exited.
    ProcessLifecycle,
    /// Which executable content an instance was running.
    ProcessIdentity,
    /// A socket existed or changed state, and its endpoints.
    NetworkSocket,
    /// A frame crossed a network device. Headers only.
    NetworkWire,
    /// A count of bytes the kernel accepted for a socket.
    DataTransfer,
    /// A marked path was modified or closed for write.
    FilesystemEffect,
    /// Which host-boot an execution ran on.
    PlatformBinding,
    /// The observer's own signatures and chain arithmetic.
    ObserverIntegrity,
    /// An effect in the physical world.
    ///
    /// **Representable, with no mechanism** (ADR-003, decision 2). Present so
    /// a deployment can state that it cannot observe physical effect, rather
    /// than leaving a silent hole. Its ceiling is `Attested` and is unreachable
    /// in this build.
    PhysicalEffect,
}

impl ObservationClass {
    /// Stable wire code, assigned explicitly so reordering the variants cannot
    /// change what previously encoded bytes mean.
    pub fn code(self) -> u8 {
        match self {
            Self::ProcessLifecycle => 0x01,
            Self::ProcessIdentity => 0x02,
            Self::NetworkSocket => 0x03,
            Self::NetworkWire => 0x04,
            Self::DataTransfer => 0x05,
            Self::FilesystemEffect => 0x06,
            Self::PlatformBinding => 0x07,
            Self::ObserverIntegrity => 0x08,
            Self::PhysicalEffect => 0x09,
        }
    }

    /// Every class, for exhaustive sweeps.
    pub const ALL: [ObservationClass; 9] = [
        Self::ProcessLifecycle,
        Self::ProcessIdentity,
        Self::NetworkSocket,
        Self::NetworkWire,
        Self::DataTransfer,
        Self::FilesystemEffect,
        Self::PlatformBinding,
        Self::ObserverIntegrity,
        Self::PhysicalEffect,
    ];

    /// The strongest evidence this class could ever contribute.
    ///
    /// Every class that rests on **content measured from the observed host**
    /// is capped at `Attested`, because host root can forge that content
    /// (threat T8). That is not conservatism about sensor quality; it is the
    /// same reason procfs content is capped, applied consistently.
    ///
    /// `ObserverIntegrity` is the sole exception and matches ADR-001 exactly:
    /// a signature that does not verify, or a chain that does not link, is
    /// recomputable from bytes a third party holds.
    pub fn ceiling(self) -> EvidenceCeiling {
        match self {
            // Recomputable from held bytes: the only class above Attested.
            Self::ObserverIntegrity => EvidenceCeiling::Proven,
            // Everything measured from the observed host.
            Self::ProcessLifecycle
            | Self::ProcessIdentity
            | Self::NetworkSocket
            | Self::DataTransfer
            | Self::FilesystemEffect
            | Self::PlatformBinding
            // A sensor reading is content read from a device — root-forgeable
            // on the observed host exactly as procfs is (ADR-003 §2).
            | Self::PhysicalEffect => EvidenceCeiling::Attested,
            // The device layer knows no process, so a wire frame is never
            // bound to an instance and cannot carry a positive finding alone.
            Self::NetworkWire => EvidenceCeiling::Corroborative,
        }
    }

    /// What an observation of this class **cannot** establish.
    ///
    /// Carried as text because it is read by humans reviewing a profile, and
    /// because writing it next to the ceiling is what stops the ceiling being
    /// read as a capability.
    pub fn cannot_establish(self) -> &'static str {
        match self {
            Self::ProcessLifecycle => "what the process did, or any effect it had",
            Self::ProcessIdentity => "that the code behaved correctly",
            Self::NetworkSocket => "that a remote system acted on anything",
            Self::NetworkWire => "which process sent the frame, its payload, or any remote effect",
            Self::DataTransfer => "what the bytes were, or that they arrived",
            Self::FilesystemEffect => "the file's contents, or that the write was correct",
            Self::PlatformBinding => "which physical platform, absent a verifier registry",
            Self::ObserverIntegrity => "anything at all about the workload",
            Self::PhysicalEffect => "anything: no mechanism implements this class",
        }
    }

    /// Whether any mechanism in this build can produce this class.
    ///
    /// `false` for `PhysicalEffect` and must stay so until an ADR revising
    /// ADR-003 says otherwise. Declared is not implemented.
    pub fn is_implemented(self) -> bool {
        !matches!(self, Self::PhysicalEffect)
    }

    pub fn encode(self, buf: &mut Vec<u8>) {
        put_u8(buf, self.code());
    }
}

/// The class a Linux mechanism belongs to.
///
/// Total over `SourceMechanism::ALL` — a mechanism added later cannot silently
/// lack a class, because this match is exhaustive and the compiler enforces
/// it. Nothing maps to [`ObservationClass::PhysicalEffect`], which is the
/// property that keeps "declared" from being mistaken for "implemented".
pub fn class_of(mechanism: SourceMechanism) -> ObservationClass {
    match mechanism {
        // ExecPermission measures the content of an image the kernel held
        // at exec (ADR-019 §5): identity of what ran, like the pidfd read.
        SourceMechanism::ProcfsPoll
        | SourceMechanism::PidFdAnchored
        | SourceMechanism::ExecPermission => ObservationClass::ProcessIdentity,
        SourceMechanism::ProcConnector | SourceMechanism::SchedTracepoint => {
            ObservationClass::ProcessLifecycle
        }
        SourceMechanism::ProcNetTable | SourceMechanism::SockStateTracepoint => {
            ObservationClass::NetworkSocket
        }
        SourceMechanism::WireTapAfPacket => ObservationClass::NetworkWire,
        SourceMechanism::SockSendTracepoint => ObservationClass::DataTransfer,
        SourceMechanism::Fanotify => ObservationClass::FilesystemEffect,
    }
}
