//! `aip-enterprise` — the enterprise autonomous systems accountability profile
//! (Skill 27).
//!
//! # One deployment class, not the definition of Vanian
//!
//! This crate occupies `ProfileKind::Environment` under a fifth ordinary id,
//! beside UAS, robotics, industrial and space. It has no reconciler of its own,
//! no verifier of its own, no trust score and no second evidence hierarchy.
//! `tests/no_second_architecture.rs` asserts that over its source, and
//! `tests/cross_vertical.rs` asserts it against the four shipped verticals.
//!
//! # The finding that makes this vertical different
//!
//! **It is the first whose effect tier is partially reachable.** UAS, robotics,
//! industrial and space all bottom out at a physical effect no mechanism
//! implements. Here a file write is `SourceMechanism::Fanotify` and a socket is
//! `ProcNetTable` — implemented mechanisms observing real effects.
//!
//! What stays out of reach is the **remote** effect: that a row changed in a
//! database on another host, that an API call had its consequence at the far
//! end, that a control-plane action took hold. Those are outside every
//! mechanism, exactly as a valve is. So the split is [`resource::EffectLocality`]
//! rather than "physical or not", and
//! [`state::EnterpriseEvidence::LocalEffectObserved`] is a reachable top tier
//! rather than an unreachable one wearing a borrowed name.
//!
//! This is the disconfirming instance ADR-009 was waiting for: three rules
//! generalise across five verticals, and *"the top tier is unreachable"* does
//! not. ADR-011 records it.
//!
//! # What a copied token buys
//!
//! Nothing. Tenant, workload and framework are strings, and anything holding
//! them can send them. [`binding::WorkloadBinding`] therefore commits to them
//! **together with `ExecutionBinding::identity_bytes`** — the agent AIP-ID, the
//! process instance triple and the executable's *contents*. There is no
//! constructor that takes the strings alone.
//!
//! A [`context::ContextChain`] roots in that binding's digest and each hop
//! links to the previous hop's, so a context lifted from one workload and
//! replayed by another names a process instance that is not the replayer's, and
//! is refused.
//!
//! # Four identities that must not collapse
//!
//! Tenant, autonomous actor, workload, process execution. Only the last is
//! measured; the rest are declared. [`binding::IdentityKind::may_substitute_for`]
//! is `false` for every pair.
//!
//! # A container is a process
//!
//! Skill 27 asks for container context propagation and this profile adds no
//! `PropagationBoundary` variant for one. A container crossing *is* a process
//! crossing at the boundary the kernel sees, so the existing `Process` boundary
//! represents it faithfully; what a container adds is an attribution, and no
//! mechanism measures a namespace set or a cgroup as an identity.
//! [`context::ContainerAttribution::is_measured`] is `false`, and no signed wire
//! format changed to imply otherwise.
//!
//! # No framework is a trust anchor
//!
//! `aip-airi::FrameworkIdentity` already refuses to be a trust input, and
//! [`adapter::EnterpriseAdapter`] keeps that one layer up: an adapter cannot
//! declare its own source, cannot declare a ceiling, and
//! `framework_grants_authority()` is `false` and not overridable.

#![forbid(unsafe_code)]

pub mod adapter;
pub mod binding;
pub mod context;
pub mod corroborate;
pub mod effect;
pub mod error;
pub mod profile;
pub mod resource;
pub mod source;
pub mod state;

pub use adapter::{ConversationFrameworkAdapter, EnterpriseAdapter, GraphFrameworkAdapter};
pub use binding::{
    framework_commitment, IdentityKind, WorkloadBinding, WORKLOAD_BINDING_PARAMETER_KEY,
};
pub use context::{ContainerAttribution, ContextChain, ContextHop};
pub use corroborate::{Agreement, SourceAgreement};
pub use effect::EnterpriseEffect;
pub use error::EnterpriseError;
pub use profile::{EnterpriseProfile, ENTERPRISE_PROFILE_ID};
pub use resource::{EffectLocality, EnterpriseResource};
pub use source::EnterpriseSource;
pub use state::{EnterpriseEvidence, WorkloadState};

/// Domain tag leading every canonical encoding this crate produces.
pub const ENTERPRISE_PROFILE_DOMAIN: &str = "SYNTRIASS/AUTONOMY/ENTERPRISE_PROFILE/v1";

/// Structure version. Unknown versions are refused, never guessed.
pub const ENTERPRISE_PROFILE_VERSION: u16 = 1;
