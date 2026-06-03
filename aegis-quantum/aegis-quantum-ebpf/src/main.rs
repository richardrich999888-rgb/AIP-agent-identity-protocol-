//! Aegis-Quantum XDP Kernel Program
//!
//! This eBPF/XDP program runs at the NIC driver level, intercepting every
//! inbound packet *before* the Linux networking stack processes it.
//!
//! For every TCP SYN packet, it:
//! 1. Parses Ethernet → IPv4 → TCP headers with strict bounds checking.
//! 2. Checks the blocklist map — if the connection 4-tuple is present,
//!    the packet is immediately DROPped (circuit breaker enforcement).
//! 3. Emits a `PacketEvent` to the Ring Buffer for user-space PQC processing.
//! 4. Checks the session map — if a PQC session exists, the packet is PASSed
//!    with a marker; otherwise it is PASSed for initial handshake.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, RingBuf},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
    tcp::TcpHdr,
};

use aegis_quantum_common::{BlocklistValue, ConnectionKey, PacketEvent, SessionValue};

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

    // Build the connection key (4-tuple)
    let conn_key = ConnectionKey {
        src_addr: ip.src_addr,
        dst_addr: ip.dst_addr,
        src_port,
        dst_port,
    };

    // ── Step 4: Check blocklist (Circuit Breaker enforcement) ────────────
    // If the circuit breaker has flagged this connection, DROP immediately.
    if unsafe { AQ_BLOCKLIST.get(&conn_key) }.is_some() {
        info!(ctx, "AQ DROP: blocked connection {}:{}", src_port, dst_port);
        return Ok(xdp_action::XDP_DROP);
    }

    // ── Step 5: Extract TCP flags ────────────────────────────────────────
    // We access the flags byte at offset 13 of the TCP header.
    let flags_offset = tcp_offset + 13;
    let flags_ptr: *const u8 = ptr_at(ctx, flags_offset).ok_or(())?;
    let tcp_flags = unsafe { *flags_ptr };

    // Only emit events for SYN packets (flag bit 1 set, ACK bit 4 clear)
    let is_syn = (tcp_flags & 0x02) != 0 && (tcp_flags & 0x10) == 0;

    if is_syn {
        // ── Step 6: Emit PacketEvent via Ring Buffer ─────────────────────
        let event = PacketEvent {
            src_addr: ip.src_addr,
            dst_addr: ip.dst_addr,
            src_port,
            dst_port,
            pkt_len: u16::from_be(ip.tot_len) as u32,
            timestamp_ns: 0, // Filled by userspace from metadata
            tcp_flags,
            _pad: [0u8; 7],
        };

        // Write the event to the ring buffer.
        // We use `output()` which copies the struct into the ring buffer.
        if let Some(mut buf) = AQ_EVENTS.reserve::<PacketEvent>(0) {
            unsafe {
                let ptr = buf.as_mut_ptr();
                core::ptr::write_unaligned(ptr, event);
                buf.submit(0);
            }
        }

        info!(
            ctx,
            "AQ SYN: {}:{} -> {}:{}",
            u32::from_be(ip.src_addr),
            src_port,
            u32::from_be(ip.dst_addr),
            dst_port
        );
    }

    // ── Step 7: Check PQC session status ─────────────────────────────────
    if unsafe { AQ_SESSIONS.get(&conn_key) }.is_some() {
        // Connection has an established PQC session — pass with confidence.
        return Ok(xdp_action::XDP_PASS);
    }

    // Default: pass the packet through for standard processing.
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
