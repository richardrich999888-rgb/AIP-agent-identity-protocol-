//! Aegis-Quantum Common — Shared types for kernel↔userspace communication.
//!
//! This crate defines the binary-stable event structs that flow through BPF
//! Ring Buffers and the map key/value layouts used for the blocklist and
//! session tables.  It is `#![no_std]`-compatible (behind a feature flag)
//! so the eBPF kernel program can reference the same definitions.

#![cfg_attr(not(feature = "std"), no_std)]

// ── PacketEvent — Ring Buffer payload from kernel → userspace ─────────────

/// A compact, fixed-size event emitted by the XDP program for every
/// intercepted TCP SYN packet.  The user-space controller reads these
/// from the BPF Ring Buffer to initiate PQC key exchange.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PacketEvent {
    /// Source IPv4 address (network byte order).
    pub src_addr: u32,
    /// Destination IPv4 address (network byte order).
    pub dst_addr: u32,
    /// Source TCP port (host byte order — converted in kernel).
    pub src_port: u16,
    /// Destination TCP port (host byte order — converted in kernel).
    pub dst_port: u16,
    /// Total IP packet length in bytes.
    pub pkt_len: u32,
    /// Kernel timestamp (ktime_get_ns) in nanoseconds.
    pub timestamp_ns: u64,
    /// TCP flags byte (SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04).
    pub tcp_flags: u8,
    /// Padding for 8-byte alignment.
    pub _pad: [u8; 7],
}

// Safety: PacketEvent is a plain-old-data, repr(C) struct with no pointers.
#[cfg(feature = "std")]
unsafe impl Send for PacketEvent {}
#[cfg(feature = "std")]
unsafe impl Sync for PacketEvent {}

impl PacketEvent {
    /// Size of this struct in bytes (must be stable across kernel/user boundary).
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

// ── ConnectionKey — BPF HashMap key for session & blocklist maps ──────────

/// A 4-tuple that uniquely identifies a TCP connection.
/// Used as the key in both the PQC session map and the blocklist map.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

// ── BlocklistValue — BPF HashMap value for the blocklist ──────────────────

/// Value stored in the blocklist map.  When the circuit breaker trips,
/// user-space inserts a `BlocklistValue` keyed by `ConnectionKey`.
/// The XDP program checks this map on every packet and drops matches.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BlocklistValue {
    /// Kernel timestamp (ns) when the block was inserted.
    pub blocked_at_ns: u64,
    /// Duration (ns) for which the block is active.  0 = permanent.
    pub block_duration_ns: u64,
    /// Reason code:  1 = circuit breaker,  2 = manual block.
    pub reason: u32,
    /// Padding for alignment.
    pub _pad: u32,
}

// ── SessionValue — BPF HashMap value for PQC session state ────────────────

/// Value stored in the PQC session map.  After a successful Kyber key
/// exchange, user-space writes the shared secret hash into this map.
/// The XDP program can read this to verify that a connection has been
/// quantum-secured.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SessionValue {
    /// SHA-256 hash of the Kyber shared secret (first 32 bytes).
    pub shared_secret_hash: [u8; 32],
    /// Timestamp (ns) when the session was established.
    pub established_at_ns: u64,
    /// Whether the session is currently active.
    pub active: u8,
    /// Padding.
    pub _pad: [u8; 7],
}

// ── Map IDs — well-known names for BPF maps ──────────────────────────────

/// Well-known BPF map names shared between kernel and userspace.
pub mod map_names {
    /// Ring buffer for PacketEvent delivery (kernel → userspace).
    pub const EVENTS: &str = "AQ_EVENTS";
    /// HashMap<ConnectionKey, BlocklistValue> for circuit breaker drops.
    pub const BLOCKLIST: &str = "AQ_BLOCKLIST";
    /// HashMap<ConnectionKey, SessionValue> for PQC session tracking.
    pub const SESSIONS: &str = "AQ_SESSIONS";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_event_size_is_stable() {
        // This size must never change without updating both kernel and userspace.
        assert_eq!(PacketEvent::SIZE, 32);
    }

    #[test]
    fn connection_key_size_is_stable() {
        assert_eq!(core::mem::size_of::<ConnectionKey>(), 12);
    }

    #[test]
    fn blocklist_value_size_is_stable() {
        assert_eq!(core::mem::size_of::<BlocklistValue>(), 24);
    }

    #[test]
    fn session_value_size_is_stable() {
        assert_eq!(core::mem::size_of::<SessionValue>(), 48);
    }
}
