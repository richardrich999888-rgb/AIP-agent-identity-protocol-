//! aip-protocol — the AIP accountability layer.
//!
//! Mission: **"Prove what the agent did and who authorized it."**
//!
//! The primary artifact of the entire system is the [`EvidencePacket`]:
//! a self-contained, canonically encoded, cryptographically signed record
//! binding together
//!
//! 1. **Who acted** — the agent identity (AIP-ID, public key, provenance),
//! 2. **Under whose authority** — the root principal, the root scoped
//!    token, and the full delegation chain (with per-hop signatures and
//!    scope attenuation),
//! 3. **What was decided** — the decision record (inputs and rationale
//!    bound by hash),
//! 4. **What was done** — individually signed action attestations,
//! 5. **What it touched** — trace and receipt bindings to external
//!    systems, optionally countersigned by the counterparty,
//! 6. **How much to trust it** — an explicit, machine-derived
//!    [`TrustFloor`].
//!
//! Every other module exists to create, verify, or consume EvidencePackets:
//!
//! - [`evidence_packet`] — the packet format, canonical encoding, builder.
//! - [`verification`] — the verification engine: packet → [`VerificationReport`].
//! - [`verification_report`] — the structured verification result.
//! - [`accountability_graph`] — Human → Authority → Agent → Decision →
//!   Action → Receipt graph reconstruction from a packet.
//!
//! The wire format is specified in `AIP_SPEC.md` at the repository root.

pub mod accountability_graph;
mod canonical;
pub mod evidence_packet;
pub mod verification;
pub mod verification_report;

pub use accountability_graph::{AccountabilityGraph, GraphEdge, GraphNode, NodeKind, Relation};
pub use evidence_packet::{
    ActionAttestation, AgentIdentitySummary, DecisionRecord, EvidencePacket, EvidencePacketBuilder,
    ReceiptBinding, RootAuthority, TraceBinding, TrustFloor, PACKET_MAGIC, PACKET_VERSION,
};
pub use verification::{verify_packet, VerificationContext};
pub use verification_report::{RuleResult, VerificationReport};
