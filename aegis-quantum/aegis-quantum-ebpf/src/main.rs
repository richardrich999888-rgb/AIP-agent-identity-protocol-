//! Aegis-Quantum XDP Kernel Program
//!
//! This eBPF/XDP program runs at the NIC driver level, intercepting every
//! inbound packet *before* the Linux networking stack processes it.
//!
//! Processing pipeline (strict priority order):
//!
//! 1. Parse Ethernet → IPv4 → TCP headers with zero-copy boundary offsets.
//! 2. Build `ConnectionKey` from 4-tuple.
//! 3. **FIRST** — Query `AQ_BLOCKLIST`: if source matches a blocked entity,
//!    increment `blocked_drops` counter and return `XDP_DROP` immediately.
//! 4. **SECOND** — Query `AQ_SESSIONS`: if key exists and `active == 1`,
//!    increment `session_hits` counter and return `XDP_PASS` (fast path,
//!    no ring buffer event).
//! 5. **THIRD** — If SYN packet AND no existing session, push `PacketEvent`
//!    to `AQ_EVENTS` ring buffer for PQC registration, increment
//!    `tcp_syn_events` counter, then return `XDP_PASS`.
//! 6. Default: `XDP_PASS` for all other traffic.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
    tcp::TcpHdr,
};

use aegis_quantum_common::{BlocklistValue, ConnectionKey, PacketEvent, SessionValue};

// ── Telemetry counter indices ────────────────────────────────────────────────

/// Index 0: total TCP packets inspected.
const COUNTER_TOTAL_PACKETS: u32 = 0;
/// Index 1: TCP SYN events pushed to ring buffer.
const COUNTER_TCP_SYN_EVENTS: u32 = 1;
/// Index 2: packets dropped by blocklist.
const COUNTER_BLOCKED_DROPS: u32 = 2;
/// Index 3: packets fast-pathed via active session.
const COUNTER_SESSION_HITS: u32 = 3;

// ── BPF Maps ─────────────────────────────────────────────────────────────────

/// Ring buffer for delivering PacketEvent structs to user-space.
/// Sized at 256 KiB (enough for ~8000 events before wrapping).
#[map]
static AQ_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Blocklist map: connections flagged by the circuit breaker are DROPped.
#[map]
static AQ_BLOCKLIST: HashMap<ConnectionKey, BlocklistValue> =
    HashMap::with_max_entries(4096, 0);

/// PQC session map: connections that have completed a Kyber key exchange.
#[map]
static AQ_SESSIONS: HashMap<ConnectionKey, SessionValue> =
    HashMap::with_max_entries(16384, 0);

/// Per-CPU packet counter array for telemetry.
/// 4 entries: total_packets, tcp_syn_events, blocked_drops, session_hits.
#[map]
static AQ_COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(4, 0);

// ── Counter helper ───────────────────────────────────────────────────────────

/// Atomically increment a per-CPU counter by 1.
#[inline(always)]
fn bump_counter(index: u32) {
    if let Some(cnt) = unsafe { AQ_COUNTERS.get_ptr_mut(index) } {
        unsafe { *cnt += 1 };
    }
}

// ── Packet parsing helpers ───────────────────────────────────────────────────

/// Safely cast a pointer at `offset` within the XDP packet buffer.
/// Returns `None` if the access would exceed `data_end` (BPF verifier safety).
#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }
    Some((start + offset) as *const T)
}

// ── XDP Entry Point ──────────────────────────────────────────────────────────

#[xdp]
pub fn aegis_xdp(ctx: XdpContext) -> u32 {
    match try_aegis_xdp(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS, // On error, pass the packet through
    }
}

fn try_aegis_xdp(ctx: &XdpContext) -> Result<u32, ()> {
    // ── Step 1: Parse Ethernet header ────────────────────────────────────
    let eth_hdr: *const EthHdr = ptr_at(ctx, 0).ok_or(())?;
    let eth = unsafe { *eth_hdr };

    // Only process IPv4 packets
    if eth.ether_type != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    // ── Step 2: Parse IPv4 header ────────────────────────────────────────
    let ip_offset = EthHdr::LEN;
    let ip_hdr: *const Ipv4Hdr = ptr_at(ctx, ip_offset).ok_or(())?;
    let ip = unsafe { *ip_hdr };

    // Only process TCP (protocol 6)
    if ip.proto as u8 != 6u8 {
        return Ok(xdp_action::XDP_PASS);
    }

    // ── Step 3: Parse TCP header ─────────────────────────────────────────
    let tcp_offset = ip_offset + Ipv4Hdr::LEN;
    let tcp_hdr: *const TcpHdr = ptr_at(ctx, tcp_offset).ok_or(())?;
    let tcp = unsafe { *tcp_hdr };

    let src_port = u16::from_be(tcp.source);
    let dst_port = u16::from_be(tcp.dest);

    // ── Step 4: Build ConnectionKey from 4-tuple ─────────────────────────
    let conn_key = ConnectionKey {
        src_addr: ip.src_addr,
        dst_addr: ip.dst_addr,
        src_port,
        dst_port,
    };

    // Bump total TCP packets counter
    bump_counter(COUNTER_TOTAL_PACKETS);

    // ── Step 5 (FIRST): Query AQ_BLOCKLIST — DROP blocked entities ───────
    // If the circuit breaker has flagged this connection, DROP immediately.
    if unsafe { AQ_BLOCKLIST.get(&conn_key) }.is_some() {
        bump_counter(COUNTER_BLOCKED_DROPS);
        info!(ctx, "AQ DROP: blocked connection {}:{}", src_port, dst_port);
        return Ok(xdp_action::XDP_DROP);
    }

    // ── Step 6 (SECOND): Query AQ_SESSIONS — fast-path active sessions ──
    // If the connection has an established, active PQC session, PASS
    // immediately without emitting a ring buffer event.
    if let Some(session) = unsafe { AQ_SESSIONS.get(&conn_key) } {
        if session.active == 1 {
            bump_counter(COUNTER_SESSION_HITS);
            return Ok(xdp_action::XDP_PASS);
        }
    }

    // ── Step 7 (THIRD): SYN detection → ring buffer event for PQC ────────
    // Extract TCP flags byte at offset 13 of the TCP header.
    let flags_offset = tcp_offset + 13;
    let flags_ptr: *const u8 = ptr_at(ctx, flags_offset).ok_or(())?;
    let tcp_flags = unsafe { *flags_ptr };

    // Only emit events for SYN packets (flag bit 1 set, ACK bit 4 clear)
    let is_syn = (tcp_flags & 0x02) != 0 && (tcp_flags & 0x10) == 0;

    if is_syn {
        // Build PacketEvent with real kernel timestamp
        let event = PacketEvent {
            src_addr: ip.src_addr,
            dst_addr: ip.dst_addr,
            src_port,
            dst_port,
            pkt_len: u16::from_be(ip.tot_len) as u32,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            tcp_flags,
            _pad: [0u8; 7],
        };

        // Write the event to the ring buffer.
        if let Some(mut buf) = AQ_EVENTS.reserve::<PacketEvent>(0) {
            unsafe {
                let ptr = buf.as_mut_ptr();
                core::ptr::write_unaligned(ptr, event);
                buf.submit(0);
            }
        }

        bump_counter(COUNTER_TCP_SYN_EVENTS);

        info!(
            ctx,
            "AQ SYN: {}:{} -> {}:{}",
            u32::from_be(ip.src_addr),
            src_port,
            u32::from_be(ip.dst_addr),
            dst_port
        );
    }

    // ── Step 8 (Default): XDP_PASS for all other traffic ─────────────────
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
