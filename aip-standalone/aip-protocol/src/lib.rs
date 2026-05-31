//! AIP v4 — Agent Accountability Protocol.
//!
//! v4 builds on the v3 identity layer by adding signed sessions, decision
//! identity, action attestations, accountability graphs, and exportable
//! evidence packets with computed trust floors.

pub mod attestation;
pub mod decision;
pub mod errors;
pub mod evidence;
pub mod graph;
pub mod policy;
pub mod ports;
pub mod primitives;
pub mod signing;

pub use attestation::{ActionAttestation, AttestationStrength};
pub use decision::{derive_decision_id, derive_session_id, DecisionRecord, SessionContext};
pub use errors::{AipError, AipResult};
pub use evidence::EvidencePacket;
pub use graph::{
    AccountabilityEdge, AccountabilityGraph, AccountabilityNode, EdgeRelation, NodeKind,
};
pub use policy::TrustFloorPolicy;
