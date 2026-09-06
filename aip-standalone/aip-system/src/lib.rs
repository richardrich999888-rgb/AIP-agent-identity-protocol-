//! Environment-neutral autonomous-system model.
//!
//! One accountability core serves AI agents, uncrewed aerial and ground
//! systems, maritime vessels, robots, industrial and critical-edge nodes,
//! spacecraft and enterprise workloads. This crate is the vocabulary that
//! makes that possible without a schema fork per vertical: it names the
//! identities involved and keeps them apart.
//!
//! # What this crate is
//!
//! A **description layer**. Two descriptors — [`AutonomousSystem`] and
//! [`SystemExecution`] — each with a domain-separated, injective canonical
//! encoding suitable for embedding in an artifact that is signed elsewhere.
//!
//! # What this crate is not
//!
//! - **Not a trust anchor.** No key, token, scope or signature appears in any
//!   type here. Constructing a value grants nothing.
//! - **Not in the verdict path.** `aip-reconcile`, `aip-warrant`,
//!   `aip-containment`, `aip-nexora` and `aip-airi` do not depend on this
//!   crate, and it depends on none of them. A description layer the verdict
//!   layers cannot see cannot change what they decide.
//! - **Not a vertical profile.** Profiles are commitments
//!   ([`ProfileRef`]) to documents defined elsewhere. UAS, robotics,
//!   industrial, space and enterprise specifics belong to later work and
//!   require no change here.
//!
//! # The separation
//!
//! ```text
//! SystemId          the autonomous system as a durable thing
//!   │  realised, per execution, as
//! AgentId           the intelligence (AIP-ID) — versioned, replaceable
//!   │  running as
//! ExecutionId       one execution instance
//!   │  bound to
//! ExecutionBinding  pid + start ticks + boot id + exe content hash
//!   │  on
//! HardwareId        the compute host — survives reboots, replaceable
//!   │  mounted in
//! PlatformId        the physical platform — survives compute swaps
//!   │  tasked by
//! MissionId         the mission context
//! ```
//!
//! Every arrow is many-to-many over time. That is the reason the levels are
//! separate types with no conversion between them: the same airframe flies
//! successive autonomy builds, and the same autonomy build flies successive
//! airframes. A model that fused any pair would be unable to say which of the
//! two changed.
//!
//! # Reuse
//!
//! Existing AIP identifiers remain authoritative. Agent identity is the
//! AIP-ID; execution identity, lineage, process instance, execution binding
//! and provenance are reused verbatim from `aip-airi` and `aip-types`. The
//! only identifiers this crate adds are the four that had no existing
//! representation: system, platform, hardware and mission.

pub mod error;
pub mod execution;
pub mod ids;
pub mod lifecycle;
pub mod profile;
pub mod system;

pub use error::SystemError;
pub use execution::{
    AuthorityContext, SystemExecution, SYSTEM_EXECUTION_DOMAIN, SYSTEM_EXECUTION_VERSION,
};
pub use ids::{HardwareId, MissionId, NamespacedId, PlatformId, SystemId};
pub use lifecycle::LifecycleState;
pub use profile::{ProfileKind, ProfileRef};
pub use system::{
    AutonomousSystem, SystemType, AUTONOMOUS_SYSTEM_DOMAIN, AUTONOMOUS_SYSTEM_VERSION,
};
