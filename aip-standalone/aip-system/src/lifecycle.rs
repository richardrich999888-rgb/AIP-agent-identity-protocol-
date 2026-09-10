//! Where a system is in its life — and why that is a record, not a gate.
//!
//! # Lifecycle state is not a trust anchor
//!
//! This is the one thing about this module that matters. A lifecycle is an
//! attractive place to put a shortcut: *registered systems may act*,
//! *authorized systems may act*. Both are wrong, and both are the kind of
//! wrong that looks like a feature.
//!
//! `Authorized` here means "a record exists that an authorization was
//! obtained". The authorization itself is a signed token chain adjudicated by
//! a decision point, and it is that chain — never this enum — that permits
//! anything. If the two ever disagree, the chain is right.
//!
//! Accordingly nothing in this crate reads `LifecycleState` to decide
//! anything, and `aip-system` is not in the dependency graph of any crate
//! that decides anything (D17-6). Both facts are asserted by test.

use aip_types::canonical::put_u8;
use serde::{Deserialize, Serialize};

/// The states a system passes through. Closed on purpose: an unknown state
/// from a future version must be refused by the version check, not absorbed
/// by an `Other` variant that a reader would then have to interpret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LifecycleState {
    /// The system exists as a described thing. Creating a record creates
    /// nothing else — in particular, not permission.
    Created,
    /// Enrolled in an inventory. Being known is not being allowed.
    Registered,
    /// An authorization was obtained *elsewhere*, and this records that it
    /// was. See the module note.
    Authorized,
    /// Allocated to a mission or task. Allocation is not authorization: being
    /// given a job does not grant the rights to do it.
    Assigned,
    /// Currently running one or more executions.
    Executing,
    /// Running with reduced capability or reduced observation. Explicitly a
    /// state of its own, so degradation is never silently equated with normal
    /// operation.
    Degraded,
    /// Subject to an applied containment effect.
    Contained,
    /// Administratively stopped, reversibly.
    Suspended,
    /// Stopped, not expected to resume in this deployment.
    Terminated,
    /// Withdrawn from service permanently.
    Retired,
}

impl LifecycleState {
    /// Stable wire code. Assigned explicitly rather than derived from
    /// declaration order, so reordering the variants cannot silently change
    /// what previously encoded bytes mean.
    pub fn code(self) -> u8 {
        match self {
            Self::Created => 0x01,
            Self::Registered => 0x02,
            Self::Authorized => 0x03,
            Self::Assigned => 0x04,
            Self::Executing => 0x05,
            Self::Degraded => 0x06,
            Self::Contained => 0x07,
            Self::Suspended => 0x08,
            Self::Terminated => 0x09,
            Self::Retired => 0x0A,
        }
    }

    /// Whether `self → next` is a transition this model describes.
    ///
    /// Descriptive, not enforcing. Nothing in this crate calls it to reject a
    /// value: a system that reached an odd state by an odd route still needs
    /// describing, and a model that refuses to represent what happened is a
    /// model that gets bypassed. It exists so a caller that *wants* to check
    /// its own bookkeeping can, and so the intended shape is written down
    /// somewhere executable.
    pub fn may_precede(self, next: LifecycleState) -> bool {
        use LifecycleState::*;
        match self {
            Created => matches!(next, Registered | Terminated | Retired),
            Registered => matches!(next, Authorized | Suspended | Terminated | Retired),
            Authorized => matches!(next, Assigned | Suspended | Terminated | Retired),
            Assigned => matches!(next, Executing | Suspended | Terminated | Retired),
            Executing => matches!(
                next,
                Degraded | Contained | Suspended | Terminated | Executing
            ),
            Degraded => matches!(next, Executing | Contained | Suspended | Terminated),
            Contained => matches!(next, Suspended | Terminated | Retired),
            // Re-entering service goes back through authorization: a
            // suspension does not preserve the rights that preceded it.
            Suspended => matches!(next, Authorized | Terminated | Retired),
            Terminated => matches!(next, Retired),
            Retired => false,
        }
    }

    /// Append to a canonical encoding.
    pub fn encode(self, buf: &mut Vec<u8>) {
        put_u8(buf, self.code());
    }
}
