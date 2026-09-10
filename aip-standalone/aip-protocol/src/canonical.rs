//! Canonical encoding for EvidencePacket hashing and signing.
//!
//! The encoder itself lives in [`aip_types::canonical`] so that the
//! authority layer (`aip-core`) and the evidence layer (this crate) share a
//! single injective encoding. This module only narrows it to crate scope.

pub(crate) use aip_types::canonical::*;
