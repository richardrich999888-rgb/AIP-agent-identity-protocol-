//! Platform and hardware binding for observed executions.
//!
//! # The question this crate answers
//!
//! > What establishes that a `SystemExecution` executed on Platform P?
//!
//! And, as importantly, what does not.
//!
//! # What was already true
//!
//! The host-level case of T13 — *authorized on P, executed on Q* — was
//! **already closed** before this crate existed. `ProcessInstance` derives
//! equality over `{pid, pid_start_time_ticks, boot_id}`, the reconciler
//! compares the whole tuple, and `boot_id` is host-scoped and measured by the
//! probe rather than claimed by the agent. An execution measured on a
//! different host-boot than the one authorized yields `IdentityDivergence`.
//!
//! That property was undocumented and untested, which is indistinguishable
//! from absent. `tests/t13.rs` exercises it against the real engine.
//!
//! # What this crate adds
//!
//! The missing link between the *measured* `boot_id` and the *declared*
//! [`aip_system::PlatformId`] / [`aip_system::HardwareId`]: a
//! [`PlatformRegistry`], supplied by the verifier, in the same shape as
//! `ObserverTrustAnchors`.
//!
//! **No new trust anchor.** The verifier already decides which observer keys
//! it trusts; deciding which platform a covered host is, is a statement of the
//! same kind by the same party. It is portable data, so it works offline.
//!
//! The observed boot id is an [`ObservedBoot`], constructible only by
//! verifying an attested batch against the verifier's own anchors. A caller
//! holding a self-reported boot id has nothing to call — which is what stops a
//! self-reported platform identity from silently establishing a binding.
//!
//! # What it is worth
//!
//! A [`PlatformDisposition::Bound`] means:
//!
//! > An anchored observer measured this execution on a host-boot the verifier
//! > has registered as this platform.
//!
//! It does **not** mean the host is physically that platform, that the
//! registry is correct, that anything survives a reboot, or that the software
//! on it behaved. Hardware identity is not proof that an action occurred, and
//! nothing here changes that.
//!
//! # What is deliberately absent
//!
//! Hardware-rooted attestation. It is required to close durable hardware
//! identity across reboots, it is a new trust anchor, and
//! `docs/architecture/ADR-002-HARDWARE-ATTESTATION.md` records the stop.
//! [`BindingMethod::HardwareAttested`] exists in the enum and is
//! unconstructible, so its absence is visible in the model rather than
//! silently missing.

pub mod binding;
pub mod error;
pub mod method;
pub mod observed;
pub mod registry;

pub use binding::{
    PlatformBinding, PlatformDisposition, PLATFORM_BINDING_DOMAIN, PLATFORM_BINDING_VERSION,
};
pub use error::PlatformError;
pub use method::BindingMethod;
pub use observed::ObservedBoot;
pub use registry::{HostRegistration, PlatformRegistry};
