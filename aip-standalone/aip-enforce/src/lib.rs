//! The enforcement tier of Sniffer Dog 3.0.
//!
//! # What this crate is
//!
//! A supervisor that sits in a workload's syscall path — via seccomp
//! user-notify — and permits an `execve` only while a **capability epoch**
//! is in force that names the program's content hash. The epoch is signed
//! by an issuer the enforcer anchors and carries a strictly increasing
//! counter, so an expired or captured epoch cannot be re-presented.
//!
//! ```text
//!   decision point ──► ExpectedExecution (signed)
//!                          │ digest
//!                          ▼
//!   epoch issuer ───────► CapabilityEpoch { programs, egress, counter, window }
//!   (software key, or                 │ signed, once per epoch
//!    ATECC608B — not here)            ▼
//!                             EpochCache::admit   (verify · counter must rise)
//!                                      │
//!   workload ─ execve ─► seccomp ─► Supervisor ─► decide()  O(1), no I/O to hardware
//!                                      │
//!                            allow (CONTINUE) / deny (-EPERM)
//!                                      │
//!                             EnforcementDecision (signed claim)
//! ```
//!
//! # What this crate is not — ADR-008
//!
//! - **Not an observer.** It cannot name `aip-observe`, `aip-observation` or
//!   `aip-reconcile`, and a test pins the manifest. An
//!   [`record::EnforcementDecision`] is a *claim by the enforcer*. Whether the
//!   execution occurred is still the observer's finding to make or withhold.
//! - **Not the containment path.** B-3 stays ACCEPTED/JUSTIFIED. Denying a
//!   syscall before a verdict exists is prevention; it does not make
//!   `ResponseClass::Contain` emittable.
//! - **Not unbypassable.** An adversary who already has root detaches the
//!   supervisor. This raises the cost of forging *permission*; it does not
//!   bind *execution* to hardware.
//!
//! # Why the two components are separate (ADR-008 §2)
//!
//! Keeping the enforcer out of the observer creates the one case that
//! matters: *enforcer says denied, observer saw execution* — the enforcer was
//! bypassed. [`record::standing`] is that table. It is only expressible
//! because neither component can write into the other.
//!
//! # Fail-closed by construction
//!
//! - No epoch, an expired epoch, a not-yet-valid epoch, an unhashable
//!   program, or a degraded enforcer: **deny**.
//! - An epoch whose counter does not exceed the last admitted one is
//!   refused at admission — a replay never becomes active.
//! - An epoch naming a root of trust its issuer was not anchored for is
//!   refused. A software key cannot be presented as an ATECC608B.
//! - If the supervisor dies, the kernel fails the pending syscalls with
//!   `ENOSYS`. That is the kernel's behaviour, not this crate's, and the live
//!   test pins it because it is the property everything else rests on.
//!
//! # The mechanism, and why not BPF-LSM
//!
//! `CONFIG_BPF_LSM` is not set on the validation kernel; and independent of
//! that, an eBPF program cannot perform I2C/SPI or sleep on a device, so a
//! hardware root of trust can never sit on the per-syscall path. seccomp
//! user-notify is the only available primitive that both denies a syscall
//! and blocks in sleepable userspace. The hardware round trip therefore
//! happens once per epoch, in [`epoch::EpochIssuer`], and never per call.

pub mod cache;
pub mod decision;
pub mod epoch;
pub mod record;

#[cfg(target_os = "linux")]
pub mod linux;

pub use cache::{AdmitError, EpochCache, EpochStatus};
pub use decision::{
    decide, Decision, DegradedReason, DenyReason, EnforcerHealth, ProgramIdentity, SyscallRequest,
    UnhashableReason,
};
pub use epoch::{
    verify_epoch, CapabilityEpoch, Egress, EpochAnchors, EpochDraft, EpochError, EpochIssuer,
    IssueError, RootOfTrust, SignedCapabilityEpoch, SoftwareIssuer, VerifiedEpoch,
    CAPABILITY_EPOCH_DOMAIN, CAPABILITY_EPOCH_VERSION,
};
pub use record::{
    standing, verify_decision, EnforcementDecision, EnforcementStanding, EnforcerAnchors,
    EnforcerClaim, ObserverFinding, RecordError, RequestKind, SignedEnforcementDecision,
    ENFORCEMENT_DECISION_DOMAIN, ENFORCEMENT_DECISION_VERSION,
};
