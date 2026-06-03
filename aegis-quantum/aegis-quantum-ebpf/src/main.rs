//! Aegis-Quantum XDP Kernel Program
//!
//! This eBPF/XDP program runs at the NIC driver level, intercepting every
//! inbound packet *before* the Linux networking stack processes it.
//!
//! Processing pipeline (strict priority order):
//!
//! 1. Parse Ethernet → IPv4 → TCP headers using `read_unaligned` + `addr_of!`
//!    for memory-safe field access on packed network structs.
//! 2. Build `ConnectionKey` from 4-tuple.
//! 3. **FIRST** — Query `AQ_BLOCKLIST` with expiry enforcement:
//!    - If `current_time < block.expiry_ns`, DROP immediately.
//!    - If block expired, fall through (self-healing infrastructure).
//!    - This runs BEFORE session check to prevent bypass of revoked access.
//! 4. **SECOND** — Query `AQ_SESSIONS`: if key exists and `active == 1`,
//!    fast-path PASS (no ring buffer event).
//! 5. **THIRD** — If SYN packet AND no existing session, push `PacketEvent`
//!    to `AQ_EVENTS` ring buffer for PQC registration.
//! 6. Default: `XDP_PASS` for all other traffic.

#![no_std]
#![no_main]

use core::ptr::addr_of;

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
/// Supports time-based expiry for self-healing infrastructure.
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
///
/// IMPORTANT: The returned pointer may be unaligned (network headers are
/// packed without padding). Callers MUST use `addr_of!(...).read_unaligned()`
/// to access fields, never direct struct dereference.
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
        // XDP_ABORTED provides better observability than XDP_PASS on error:
        // it increments the tracepoint counter so operators can detect
        // parsing failures via `bpftool prog tracelog`.
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_aegis_xdp(ctx: &XdpContext) -> Result<u32, ()> {
    // ── Step 1: Parse Ethernet header ────────────────────────────────────
    // SAFETY: Network headers are packed structs. We use `addr_of!` +
    // `read_unaligned` to avoid undefined behavior from unaligned access
    // on architectures that enforce alignment (ARM, MIPS, some x86 configs).
    let eth: *const EthHdr = ptr_at(ctx, 0).ok_or(())?;
    let ether_type = unsafe { addr_of!((*eth).ether_type).read_unaligned() };

    // Only process IPv4 packets
    if ether_type != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    // ── Step 2: Parse IPv4 header ────────────────────────────────────────
    let ip_offset = EthHdr::LEN;
    let ip: *const Ipv4Hdr = ptr_at(ctx, ip_offset).ok_or(())?;
    let src_addr = unsafe { addr_of!((*ip).src_addr).read_unaligned() };
    let dst_addr = unsafe { addr_of!((*ip).dst_addr).read_unaligned() };
    let proto = unsafe { addr_of!((*ip).proto).read_unaligned() };
    let tot_len = unsafe { addr_of!((*ip).tot_len).read_unaligned() };

    // Only process TCP (protocol 6)
    if proto as u8 != 6u8 {
        return Ok(xdp_action::XDP_PASS);
    }

    // ── Step 3: Parse TCP header ─────────────────────────────────────────
    let tcp_offset = ip_offset + Ipv4Hdr::LEN;
    let tcp: *const TcpHdr = ptr_at(ctx, tcp_offset).ok_or(())?;
    let src_port = u16::from_be(unsafe { addr_of!((*tcp).source).read_unaligned() });
    let dst_port = u16::from_be(unsafe { addr_of!((*tcp).dest).read_unaligned() });

    // ── Step 4: Build ConnectionKey from 4-tuple ─────────────────────────
    let conn_key = ConnectionKey {
        src_addr,
        dst_addr,
        src_port,
        dst_port,
    };

    // Bump total TCP packets counter
    bump_counter(COUNTER_TOTAL_PACKETS);

    // ── Step 5 (FIRST): Query AQ_BLOCKLIST with EXPIRY ENFORCEMENT ──────
    // STRATEGIC FIX 1: Blocklist is checked BEFORE the session map.
    // This prevents a previously-authorized session from bypassing a
    // circuit breaker revocation. Even if a PQC session exists, the
    // blocklist takes absolute priority.
    //
    // STRATEGIC FIX 2: Time-based expiry for self-healing infrastructure.
    // If expiry_ns == 0, the block is permanent. Otherwise, the block
    // automatically expires when `ktime_get_ns() >= expiry_ns`, allowing
    // the kernel to resume service without human intervention.
    if let Some(block) = unsafe { AQ_BLOCKLIST.get(&conn_key) } {
        let expiry = block.expiry_ns;

        if expiry == 0 {
            // Permanent block — always drop.
            bump_counter(COUNTER_BLOCKED_DROPS);
            info!(ctx, "AQ DROP [PERMANENT]: {}:{}", src_port, dst_port);
            return Ok(xdp_action::XDP_DROP);
        }

        let current_time = unsafe { bpf_ktime_get_ns() };
        if current_time < expiry {
            // Block is still active — drop the packet.
            bump_counter(COUNTER_BLOCKED_DROPS);
            info!(ctx, "AQ DROP [TTL]: {}:{}", src_port, dst_port);
            return Ok(xdp_action::XDP_DROP);
        }

        // Block has expired — fall through. The kernel self-heals.
        // NOTE: We do NOT remove the expired entry here because
        // bpf_map_delete_elem is not safe from the XDP fast path in all
        // kernel versions. Userspace garbage-collects expired entries
        // periodically via map iteration.
        info!(ctx, "AQ EXPIRED: blocklist entry for {}:{} lapsed", src_port, dst_port);
    }

    // ── Step 6 (SECOND): Query AQ_SESSIONS — fast-path active sessions ──
    // STRATEGIC FIX 3: Only fast-path if session.active == 1.
    // An inactive session (active == 0) forces re-handshake via the SYN path.
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
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            pkt_len: u16::from_be(tot_len) as u32,
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
            u32::from_be(src_addr),
            src_port,
            u32::from_be(dst_addr),
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
