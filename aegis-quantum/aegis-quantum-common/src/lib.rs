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

#[cfg(feature = "aya-pod")]
unsafe impl aya::Pod for PacketEvent {}

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

#[cfg(feature = "aya-pod")]
unsafe impl aya::Pod for ConnectionKey {}

// ── BlocklistValue — BPF HashMap value for the blocklist ──────────────────

/// Value stored in the blocklist map.  When the circuit breaker trips,
/// user-space inserts a `BlocklistValue` keyed by `ConnectionKey`.
/// The XDP program checks this map on every packet and drops matches.
///
/// **Self-healing design:** The `expiry_ns` field is a pre-computed absolute
/// kernel timestamp. The XDP program performs a single comparison
/// (`current_time < expiry_ns`) to enforce time-based blocks. When the
/// block expires, the kernel automatically resumes passing traffic without
/// requiring manual human intervention or userspace coordination.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BlocklistValue {
    /// Kernel timestamp (ns) when the block was inserted.
    pub blocked_at_ns: u64,
    /// Absolute kernel timestamp (ns) when the block expires.
    /// The XDP program compares `bpf_ktime_get_ns() < expiry_ns` to
    /// determine if the block is still active.  0 = permanent block.
    pub expiry_ns: u64,
    /// Reason code:  1 = circuit breaker,  2 = manual block.
    pub reason: u32,
    /// Padding for alignment.
    pub _pad: u32,
}

#[cfg(feature = "aya-pod")]
unsafe impl aya::Pod for BlocklistValue {}

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

#[cfg(feature = "aya-pod")]
unsafe impl aya::Pod for SessionValue {}

// ── Map IDs — well-known names for BPF maps ──────────────────────────────

/// Well-known BPF map names shared between kernel and userspace.
pub mod map_names {
    /// Ring buffer for PacketEvent delivery (kernel → userspace).
    pub const EVENTS: &str = "AQ_EVENTS";
    /// HashMap<ConnectionKey, BlocklistValue> for circuit breaker drops.
    pub const BLOCKLIST: &str = "AQ_BLOCKLIST";
    /// HashMap<ConnectionKey, SessionValue> for PQC session tracking.
    pub const SESSIONS: &str = "AQ_SESSIONS";
    /// PerCpuArray<u64> telemetry counters.
    pub const COUNTERS: &str = "AQ_COUNTERS";
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper: compute the byte offset of a field without external crates ──

    fn field_offset<T, F>(field_ptr_fn: impl FnOnce(*const T) -> *const F) -> usize {
        let base = core::ptr::null::<T>();
        let field = field_ptr_fn(base);
        field as usize - base as usize
    }

    // ══════════════════════════════════════════════════════════════════════════
    // Original 4 size-stability tests (must never be removed)
    // ══════════════════════════════════════════════════════════════════════════

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

    // ══════════════════════════════════════════════════════════════════════════
    // ABI / Layout Tests — field offsets
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn packet_event_field_offsets() {
        assert_eq!(field_offset::<PacketEvent, u32>(|p| unsafe { core::ptr::addr_of!((*p).src_addr) }), 0);
        assert_eq!(field_offset::<PacketEvent, u32>(|p| unsafe { core::ptr::addr_of!((*p).dst_addr) }), 4);
        assert_eq!(field_offset::<PacketEvent, u16>(|p| unsafe { core::ptr::addr_of!((*p).src_port) }), 8);
        assert_eq!(field_offset::<PacketEvent, u16>(|p| unsafe { core::ptr::addr_of!((*p).dst_port) }), 10);
        assert_eq!(field_offset::<PacketEvent, u32>(|p| unsafe { core::ptr::addr_of!((*p).pkt_len) }), 12);
        assert_eq!(field_offset::<PacketEvent, u64>(|p| unsafe { core::ptr::addr_of!((*p).timestamp_ns) }), 16);
        assert_eq!(field_offset::<PacketEvent, u8>(|p| unsafe { core::ptr::addr_of!((*p).tcp_flags) }), 24);
        assert_eq!(field_offset::<PacketEvent, [u8; 7]>(|p| unsafe { core::ptr::addr_of!((*p)._pad) }), 25);
    }

    #[test]
    fn connection_key_field_offsets() {
        assert_eq!(field_offset::<ConnectionKey, u32>(|p| unsafe { core::ptr::addr_of!((*p).src_addr) }), 0);
        assert_eq!(field_offset::<ConnectionKey, u32>(|p| unsafe { core::ptr::addr_of!((*p).dst_addr) }), 4);
        assert_eq!(field_offset::<ConnectionKey, u16>(|p| unsafe { core::ptr::addr_of!((*p).src_port) }), 8);
        assert_eq!(field_offset::<ConnectionKey, u16>(|p| unsafe { core::ptr::addr_of!((*p).dst_port) }), 10);
    }

    #[test]
    fn blocklist_value_field_offsets() {
        assert_eq!(field_offset::<BlocklistValue, u64>(|p| unsafe { core::ptr::addr_of!((*p).blocked_at_ns) }), 0);
        assert_eq!(field_offset::<BlocklistValue, u64>(|p| unsafe { core::ptr::addr_of!((*p).expiry_ns) }), 8);
        assert_eq!(field_offset::<BlocklistValue, u32>(|p| unsafe { core::ptr::addr_of!((*p).reason) }), 16);
        assert_eq!(field_offset::<BlocklistValue, u32>(|p| unsafe { core::ptr::addr_of!((*p)._pad) }), 20);
    }

    #[test]
    fn session_value_field_offsets() {
        assert_eq!(field_offset::<SessionValue, [u8; 32]>(|p| unsafe { core::ptr::addr_of!((*p).shared_secret_hash) }), 0);
        assert_eq!(field_offset::<SessionValue, u64>(|p| unsafe { core::ptr::addr_of!((*p).established_at_ns) }), 32);
        assert_eq!(field_offset::<SessionValue, u8>(|p| unsafe { core::ptr::addr_of!((*p).active) }), 40);
        assert_eq!(field_offset::<SessionValue, [u8; 7]>(|p| unsafe { core::ptr::addr_of!((*p)._pad) }), 41);
    }

    // ══════════════════════════════════════════════════════════════════════════
    // ABI / Layout Tests — alignment
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn packet_event_alignment_is_8_bytes() {
        assert_eq!(core::mem::align_of::<PacketEvent>(), 8);
    }

    #[test]
    fn connection_key_alignment_is_4_bytes() {
        assert_eq!(core::mem::align_of::<ConnectionKey>(), 4);
    }

    #[test]
    fn blocklist_value_alignment_is_8_bytes() {
        assert_eq!(core::mem::align_of::<BlocklistValue>(), 8);
    }

    #[test]
    fn session_value_alignment_is_8_bytes() {
        assert_eq!(core::mem::align_of::<SessionValue>(), 8);
    }

    // ══════════════════════════════════════════════════════════════════════════
    // Serialization / Round-trip Tests
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn packet_event_zero_copy_roundtrip() {
        let original = PacketEvent {
            src_addr: 0xC0A80001,   // 192.168.0.1
            dst_addr: 0x0A000001,   // 10.0.0.1
            src_port: 12345,
            dst_port: 443,
            pkt_len: 1500,
            timestamp_ns: 1_000_000_000,
            tcp_flags: 0x02,        // SYN
            _pad: [0u8; 7],
        };

        let mut buf = [0u8; 32];
        unsafe {
            core::ptr::write_unaligned(buf.as_mut_ptr() as *mut PacketEvent, original);
        }
        let recovered: PacketEvent = unsafe {
            core::ptr::read_unaligned(buf.as_ptr() as *const PacketEvent)
        };

        assert_eq!(recovered.src_addr, original.src_addr);
        assert_eq!(recovered.dst_addr, original.dst_addr);
        assert_eq!(recovered.src_port, original.src_port);
        assert_eq!(recovered.dst_port, original.dst_port);
        assert_eq!(recovered.pkt_len, original.pkt_len);
        assert_eq!(recovered.timestamp_ns, original.timestamp_ns);
        assert_eq!(recovered.tcp_flags, original.tcp_flags);
        assert_eq!(recovered._pad, original._pad);
    }

    #[test]
    fn connection_key_hash_equality() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let a = ConnectionKey { src_addr: 1, dst_addr: 2, src_port: 80, dst_port: 443 };
        let b = ConnectionKey { src_addr: 1, dst_addr: 2, src_port: 80, dst_port: 443 };

        let hash_of = |k: &ConnectionKey| {
            let mut h = DefaultHasher::new();
            k.hash(&mut h);
            h.finish()
        };

        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn connection_key_hash_inequality() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let a = ConnectionKey { src_addr: 1, dst_addr: 2, src_port: 80, dst_port: 443 };
        let b = ConnectionKey { src_addr: 1, dst_addr: 2, src_port: 80, dst_port: 8080 };

        let hash_of = |k: &ConnectionKey| {
            let mut h = DefaultHasher::new();
            k.hash(&mut h);
            h.finish()
        };

        assert_ne!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn connection_key_clone_is_identical() {
        let original = ConnectionKey { src_addr: 0xDEAD, dst_addr: 0xBEEF, src_port: 22, dst_port: 2222 };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    // ══════════════════════════════════════════════════════════════════════════
    // Boundary / Edge Case Tests
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn blocklist_value_permanent_block() {
        let val = BlocklistValue {
            blocked_at_ns: 1_000_000,
            expiry_ns: 0,   // 0 = permanent block per doc comment
            reason: 2,
            _pad: 0,
        };
        assert_eq!(val.expiry_ns, 0, "expiry_ns=0 must represent a permanent block");
    }

    #[test]
    fn blocklist_value_max_expiry() {
        let val = BlocklistValue {
            blocked_at_ns: 1,
            expiry_ns: u64::MAX,
            reason: 1,
            _pad: 0,
        };
        assert_eq!(val.expiry_ns, u64::MAX);
    }

    #[test]
    fn session_value_inactive_session() {
        let val = SessionValue {
            shared_secret_hash: [0xAA; 32],
            established_at_ns: 42,
            active: 0,
            _pad: [0; 7],
        };
        assert_eq!(val.active, 0, "active=0 must mean inactive");
    }

    #[test]
    fn session_value_active_session() {
        let val = SessionValue {
            shared_secret_hash: [0xBB; 32],
            established_at_ns: 99,
            active: 1,
            _pad: [0; 7],
        };
        assert_eq!(val.active, 1, "active=1 must mean active");
    }

    #[test]
    fn packet_event_syn_flag() {
        let evt = PacketEvent {
            src_addr: 0, dst_addr: 0, src_port: 0, dst_port: 0,
            pkt_len: 64, timestamp_ns: 0, tcp_flags: 0x02, _pad: [0; 7],
        };
        assert_eq!(evt.tcp_flags & 0x02, 0x02, "SYN flag must be set");
    }

    #[test]
    fn packet_event_syn_ack_flag() {
        let evt = PacketEvent {
            src_addr: 0, dst_addr: 0, src_port: 0, dst_port: 0,
            pkt_len: 64, timestamp_ns: 0, tcp_flags: 0x12, _pad: [0; 7],
        };
        assert_eq!(evt.tcp_flags & 0x02, 0x02, "SYN flag must be set");
        assert_eq!(evt.tcp_flags & 0x10, 0x10, "ACK flag must be set");
        assert_eq!(evt.tcp_flags, 0x12, "SYN+ACK = 0x12");
    }

    #[test]
    fn packet_event_max_packet_length() {
        let evt = PacketEvent {
            src_addr: 0, dst_addr: 0, src_port: 0, dst_port: 0,
            pkt_len: u32::MAX, timestamp_ns: 0, tcp_flags: 0, _pad: [0; 7],
        };
        assert_eq!(evt.pkt_len, u32::MAX);
    }

    #[test]
    fn packet_event_zero_timestamp() {
        let evt = PacketEvent {
            src_addr: 0, dst_addr: 0, src_port: 0, dst_port: 0,
            pkt_len: 0, timestamp_ns: 0, tcp_flags: 0, _pad: [0; 7],
        };
        assert_eq!(evt.timestamp_ns, 0, "timestamp_ns=0 must be a valid value");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // Map Name Constants
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn map_name_events_is_correct() {
        assert_eq!(map_names::EVENTS, "AQ_EVENTS");
    }

    #[test]
    fn map_name_blocklist_is_correct() {
        assert_eq!(map_names::BLOCKLIST, "AQ_BLOCKLIST");
    }

    #[test]
    fn map_name_sessions_is_correct() {
        assert_eq!(map_names::SESSIONS, "AQ_SESSIONS");
    }

    #[test]
    fn map_name_counters_is_correct() {
        assert_eq!(map_names::COUNTERS, "AQ_COUNTERS");
    }
}
