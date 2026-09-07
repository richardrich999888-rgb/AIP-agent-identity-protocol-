//! The wire contract of the Linux autonomous edge reference.
//!
//! # Why a separate crate
//!
//! The reference runs three processes with deliberately disjoint capability:
//!
//! ```text
//!   aip-edge-workload      the subject.  Holds an agent key.  Authors AIRI
//!                          self-reports.  Cannot construct an observation.
//!
//!   aip-edge-observer      the witness.  Holds the collector key.  Measures
//!                          the kernel.  Cannot author an agent claim.
//!
//!   aip-edge               the verifier.  Holds anchors and the registry.
//!                          Measures nothing and signs nothing.
//! ```
//!
//! Those boundaries are enforced by the *dependency graph*, not by review: the
//! workload's manifest does not name `aip-observe`, so no expression in it can
//! reach `CollectorSigner`; the observer's manifest does not name `aip-airi`,
//! so no expression in it can reach `sign_airi_event`. That enforcement only
//! holds if the three processes can agree on a protocol **without** a shared
//! dependency that re-links what the manifests exclude. This crate is that
//! agreement, and it therefore depends on `aip-types` and nothing else.
//!
//! # REFERENCE TRANSPORT — not a production transport
//!
//! Everything below describes a line protocol over pipes plus JSON Lines in a
//! state directory. It is chosen because it is synchronous, ordered, has no
//! clock in it and needs no daemon, which makes the reference deterministic.
//! It is **not** a protocol requirement of the architecture: nothing in
//! `aip-observe`, `aip-observation` or `aip-effect` knows these bytes exist.
//! A production deployment moves `AttestedBatch` values off the observed host
//! by whatever authenticated means it already operates; the security property
//! comes from the collector's signature over the batch, which survives any
//! transport, and not from anything here.

#![forbid(unsafe_code)]

use aip_types::canonical::{put_bytes, put_domain, put_u16, put_u8};
use serde::{Deserialize, Serialize};

/// Domain tag over the reference's canonical action parameters.
///
/// Distinct from every other domain in the workspace so a parameter preimage
/// from this reference cannot be replayed as any other structure's preimage.
pub const EDGE_PARAMETER_DOMAIN: &str = "SYNTRIASS/AUTONOMY/EDGE_REFERENCE_PARAMETERS/v1";

/// Version of the line protocol and of the JSON shapes below.
pub const EDGE_PROTOCOL_VERSION: u16 = 1;

// ─── File names in the reference state directory ───

/// Written by the observer once its key exists. Carries the **public** key
/// only; the private half never leaves the observer process.
pub const OBSERVER_ANNOUNCEMENT: &str = "observer.json";
/// Written by the workload once its identity exists. Public key only.
pub const WORKLOAD_ANNOUNCEMENT: &str = "workload.json";
/// One `AttestedBatch`, JSON, per line, in attestation order.
pub const BATCHES_JSONL: &str = "batches.jsonl";
/// One `SignedSensorHealth`, JSON, per line.
pub const HEALTH_JSONL: &str = "health.jsonl";
/// One `AiriEvent`, JSON, per line: the workload's own account of itself.
pub const CLAIMS_JSONL: &str = "claims.jsonl";

// ─── Line protocol ───
//
// Every command is one line on the child's stdin; every reply is one line on
// its stdout beginning with `ok ` or `err `. The driver blocks on the reply,
// so the reference contains no sleeps and no polling, and the ordering of
// kernel activity relative to batch boundaries is exact rather than likely.

/// Observer: announce identity and open the configured kernel sources.
pub const CMD_READY: &str = "ready";
/// Observer: attest an empty batch, opening a coverage epoch.
pub const CMD_EPOCH: &str = "epoch";
/// Observer: `observe <pid>` — measure that instance under a pidfd anchor,
/// read its socket rows, attest the result.
pub const CMD_OBSERVE: &str = "observe";
/// Observer: emit a signed health record.
pub const CMD_HEALTH: &str = "health";
/// Workload: announce identity and execution id.
pub const CMD_IDENTITY: &str = "identity";
/// Workload: `connect <addr:port>` — really open a TCP connection and hold it.
pub const CMD_CONNECT: &str = "connect";
/// Workload: `claim <addr:port>` — author an AIRI self-report claiming a
/// successful connection **without opening one**. The lie the reference must
/// not believe.
pub const CMD_CLAIM: &str = "claim";
/// Either child: shut down cleanly.
pub const CMD_QUIT: &str = "quit";

/// Reply prefix for success.
pub const REPLY_OK: &str = "ok";
/// Reply prefix for failure. The remainder of the line is a diagnostic.
pub const REPLY_ERR: &str = "err";

// ─── Announcements ───

/// What the observer publishes about itself.
///
/// The mechanisms are carried as **wire codes**, not as `SourceMechanism`
/// values, precisely so this crate does not have to link `aip-observe`. The
/// verifier maps the codes back through `SourceMechanism::ALL`, which fails
/// closed on a code this build does not know.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObserverAnnouncement {
    pub version: u16,
    pub observer_id: String,
    pub key_version: u32,
    /// Ed25519 public key, 32 bytes. The private half is never written.
    pub public_key: Vec<u8>,
    pub probe_id: String,
    /// `SourceMechanism::code()` for every mechanism this probe declared.
    ///
    /// **The single authoritative capability declaration.** The verifier's
    /// `ObservationProfile` is projected from exactly this list and from
    /// nothing else, so the deployment states its capability once (Skill 22
    /// Phase 7).
    pub declared_mechanism_codes: Vec<u8>,
}

/// What the workload publishes about itself. Every field is self-reported and
/// none of it is evidence; it is here so the verifier can *check* the claims
/// against what an observer measured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadAnnouncement {
    pub version: u16,
    /// The workload's AIP-ID, derived from the key it holds.
    pub agent_id: String,
    /// Ed25519 public key, 32 bytes.
    pub public_key: Vec<u8>,
    /// The AIRI execution instance. Chosen by the workload, which is correct:
    /// AIRI owns this identifier and Skill 17 reuses it verbatim.
    pub execution_id: [u8; 16],
    /// The pid the workload believes it has. **Self-reported**, carried only
    /// so the verifier can compare it with what it measures independently.
    pub self_reported_pid: u32,
}

/// Canonical parameter bytes for the reference's one action class: hold an
/// established TCP connection to `(ip, port)`.
///
/// Domain-tagged and prefix-free. Both the workload (building its AIRI
/// parameter commitment) and the verifier (building the `RequestedEffect`)
/// call this, so a commitment mismatch means the two disagreed about the
/// action — never that they encoded the same action differently.
pub fn connect_parameter_bytes(ip: [u8; 4], port: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    put_domain(&mut buf, EDGE_PARAMETER_DOMAIN);
    put_u16(&mut buf, EDGE_PROTOCOL_VERSION);
    // A protocol discriminant so a future UDP variant cannot collide with a
    // TCP one that happens to share an endpoint.
    put_u8(&mut buf, 0x06); // IPPROTO_TCP
    put_bytes(&mut buf, &ip);
    put_u16(&mut buf, port);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameter_bytes_are_injective_over_endpoint() {
        let a = connect_parameter_bytes([127, 0, 0, 1], 8080);
        let b = connect_parameter_bytes([127, 0, 0, 1], 8081);
        let c = connect_parameter_bytes([127, 0, 0, 2], 8080);
        assert_ne!(a, b, "a port change must change the bytes");
        assert_ne!(a, c, "an address change must change the bytes");
    }

    #[test]
    fn parameter_bytes_are_deterministic() {
        assert_eq!(
            connect_parameter_bytes([10, 0, 0, 7], 443),
            connect_parameter_bytes([10, 0, 0, 7], 443),
        );
    }

    #[test]
    fn parameter_bytes_carry_the_domain_tag() {
        let b = connect_parameter_bytes([127, 0, 0, 1], 1);
        let tag = EDGE_PARAMETER_DOMAIN.as_bytes();
        assert!(
            b.windows(tag.len()).any(|w| w == tag),
            "the domain tag must be inside the preimage"
        );
    }
}
