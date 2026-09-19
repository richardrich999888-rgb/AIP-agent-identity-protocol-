//! The pure decision. No I/O, no clock, no kernel: a request, a cache and a
//! moment go in; allow or deny comes out. Everything that can go wrong
//! resolves to deny.

use serde::{Deserialize, Serialize};

use crate::cache::{EpochCache, EpochStatus};
use crate::epoch::Egress;

/// Why a program could not be identified by content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnhashableReason {
    /// The path was relative. Resolving it against the target's cwd is a
    /// second TOCTOU window the supervisor declines to open.
    RelativePath,
    /// The target's memory could not be read to obtain the path.
    TargetMemoryUnreadable,
    /// The path was not valid UTF-8 or contained a NUL where none may be.
    PathMalformed,
    /// The file could not be opened or read for hashing.
    ReadFailed,
    /// `execveat` with a directory fd other than `AT_FDCWD`, or with
    /// `AT_EMPTY_PATH`; the supervisor cannot see what the fd names.
    ExecveatUnsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProgramIdentity {
    /// SHA-256 of the file's contents as the supervisor read them.
    ContentHash([u8; 32]),
    Unhashable(UnhashableReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyscallRequest {
    Exec { program: ProgramIdentity },
    Connect { egress: Egress },
}

/// Why the enforcer is not in a condition to permit anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DegradedReason {
    /// The seccomp listener returned an error the supervisor does not
    /// understand. It stops serving; the kernel fails the target's pending
    /// syscalls with `ENOSYS`.
    ListenerLost,
    /// The supervisor could not obtain a clock.
    ClockUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnforcerHealth {
    Nominal,
    Degraded(DegradedReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenyReason {
    EnforcerDegraded(DegradedReason),
    NoEpoch,
    EpochNotYetValid,
    EpochExpired,
    ProgramNotAuthorised,
    ProgramUnhashable(UnhashableReason),
    EgressNotAuthorised,
}

impl DenyReason {
    /// Two fixed codes for the signed record. Exhaustive so a new reason
    /// cannot be recorded as some other reason.
    pub fn codes(&self) -> (u8, u8) {
        match self {
            DenyReason::EnforcerDegraded(DegradedReason::ListenerLost) => (0x01, 0x01),
            DenyReason::EnforcerDegraded(DegradedReason::ClockUnavailable) => (0x01, 0x02),
            DenyReason::NoEpoch => (0x02, 0),
            DenyReason::EpochNotYetValid => (0x03, 0),
            DenyReason::EpochExpired => (0x04, 0),
            DenyReason::ProgramNotAuthorised => (0x05, 0),
            DenyReason::ProgramUnhashable(r) => (
                0x06,
                match r {
                    UnhashableReason::RelativePath => 0x01,
                    UnhashableReason::TargetMemoryUnreadable => 0x02,
                    UnhashableReason::PathMalformed => 0x03,
                    UnhashableReason::ReadFailed => 0x04,
                    UnhashableReason::ExecveatUnsupported => 0x05,
                },
            ),
            DenyReason::EgressNotAuthorised => (0x07, 0),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Allow,
    Deny(DenyReason),
}

impl Decision {
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow)
    }
}

/// The decision. Order of checks is the order of the enum: a degraded
/// enforcer denies before it looks at anything, and an absent epoch denies
/// before the request is examined.
pub fn decide(
    health: EnforcerHealth,
    cache: &EpochCache,
    request: &SyscallRequest,
    now_ms: u64,
) -> Decision {
    if let EnforcerHealth::Degraded(reason) = health {
        return Decision::Deny(DenyReason::EnforcerDegraded(reason));
    }
    let epoch = match cache.status(now_ms) {
        EpochStatus::Active(v) => v.epoch(),
        EpochStatus::None => return Decision::Deny(DenyReason::NoEpoch),
        EpochStatus::NotYetValid => return Decision::Deny(DenyReason::EpochNotYetValid),
        EpochStatus::Expired => return Decision::Deny(DenyReason::EpochExpired),
    };
    match request {
        SyscallRequest::Exec { program } => match program {
            ProgramIdentity::Unhashable(r) => Decision::Deny(DenyReason::ProgramUnhashable(*r)),
            ProgramIdentity::ContentHash(h) => {
                if epoch.permits_program(h) {
                    Decision::Allow
                } else {
                    Decision::Deny(DenyReason::ProgramNotAuthorised)
                }
            }
        },
        SyscallRequest::Connect { egress } => {
            if epoch.permits_egress(egress) {
                Decision::Allow
            } else {
                Decision::Deny(DenyReason::EgressNotAuthorised)
            }
        }
    }
}
