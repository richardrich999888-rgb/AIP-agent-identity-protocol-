//! # Placement supervisor (ADR-019)
//!
//! Runs each authorised decision's work in a cgroup v2 created for that
//! decision alone, so that the kernel — not a race between an exec and a
//! user-space measurement — records which decision every descendant process
//! belongs to. The observer reads the cgroup id the kernel writes into each
//! tracepoint sample (`PERF_SAMPLE_CGROUP`); this crate only creates the
//! placement.
//!
//! **What it holds.** No key. It signs nothing and attests nothing. Its
//! authority over a placement is established by the kernel: the observer
//! records which process instance created each decision cgroup, and the
//! reconciler accepts the placement only if that creator is a measured
//! instance of the supervisor binary the verifier names.
//!
//! **What it does not do.** It never decides whether work is permitted —
//! that is the decision point's — and never stops, freezes or kills work —
//! that is containment, gated on `Proven` evidence elsewhere.
//!
//! Modules:
//! - [`name`]: the cgroup name a decision id determines; pure.
//! - [`mount`]: finding the cgroup v2 hierarchy; parsing is pure.
//! - [`cgroup`]: creating and removing one decision cgroup.
//! - [`spawn`]: starting a program inside it with `clone3`.

pub mod cgroup;
pub mod mount;
pub mod name;
pub mod spawn;

pub use cgroup::{DecisionCgroup, PlacementError, PlacementRoot};
pub use mount::{cgroup2_mount_from_mountinfo, find_cgroup2_mount};
pub use name::{decision_cgroup_name, parse_decision_cgroup_name, NAME_LEN};
pub use spawn::{spawn_into, Child, SpawnError};
