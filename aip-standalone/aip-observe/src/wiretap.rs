//! Wire-level observation: frames copied from a network device through an
//! `AF_PACKET` socket, decoded to TCP/IP **headers only**.
//!
//! **What this is.** For every frame a device receives (`packet_rcv`) or is
//! about to transmit (`dev_queue_xmit_nit`), the kernel hands a copy to each
//! `AF_PACKET` socket bound to that device (or to all devices), together
//! with the direction (`sll_pkttype`), the interface index, and — with
//! `SO_TIMESTAMPNS` — the kernel's own capture stamp on the realtime clock.
//! Frames the socket's receive queue could not hold are counted in
//! `PACKET_STATISTICS` (`tp_drops`). `SOCK_DGRAM` strips the link header, so
//! the buffer starts at the IP header. No eBPF program, no XDP, no
//! packet-filter bytecode: this is the kernel's ordinary packet tap.
//!
//! **What it keeps.** IP version and addresses, TCP ports, flags, sequence
//! and acknowledgement numbers, the payload *length* and the frame length.
//! Nothing after the TCP header is copied, hashed or retained, so a wire
//! segment can never carry application content (I23), and no "payload hash"
//! is ever claimed by this crate.
//!
//! **What it proves.** That a segment with these headers crossed this device
//! at this kernel time, in this direction. It says nothing about which
//! process owns the socket — the device layer has no task context — so a
//! wire segment is never bound to a process instance and never attributed.
//! It is the second kernel path (the socket-state tracepoint being the
//! first) by which a connection can be seen, and the only one here whose
//! code runs unchanged on a mirror-port or TAP host outside the observed
//! host's root. On the observed host itself it is root-forgeable like every
//! other source.
//!
//! **Privilege.** `CAP_NET_RAW`. Without it [`WireTap::open`] returns
//! `Unavailable` and nothing is simulated.

use crate::linux::SourceError;
use crate::observed::{KernelLifecycleKind, SocketEndpoint, SocketProtocol, WireDirection};

/// `sll_pkttype` values (`linux/if_packet.h`).
pub const PACKET_HOST: u8 = 0;
pub const PACKET_BROADCAST: u8 = 1;
pub const PACKET_MULTICAST: u8 = 2;
pub const PACKET_OTHERHOST: u8 = 3;
pub const PACKET_OUTGOING: u8 = 4;

const IPPROTO_TCP: u8 = 6;

fn be16(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
}

fn be32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn malformed(what: &str) -> SourceError {
    SourceError::Malformed(format!("wire frame: {what}"))
}

/// Decode one frame (link header already stripped) into a
/// [`KernelLifecycleKind::WireSegment`]. Pure: no syscalls, no guessing.
/// Anything that is not IPv4/IPv6 carrying TCP with no extension headers, or
/// whose lengths do not add up, is `Malformed` and is simply not a wire
/// segment — the caller skips it without counting it as loss.
pub fn parse_wire_frame(
    frame: &[u8],
    pkttype: u8,
    ifindex: u32,
    kernel_realtime_ns: u64,
) -> Result<KernelLifecycleKind, SourceError> {
    let first = *frame.first().ok_or_else(|| malformed("empty"))?;
    let (protocol, src_addr, dst_addr, tcp_off, ip_total): (
        SocketProtocol,
        [u8; 16],
        [u8; 16],
        usize,
        usize,
    ) = match first >> 4 {
        4 => {
            let ihl = ((first & 0x0f) as usize) * 4;
            if ihl < 20 || frame.len() < ihl {
                return Err(malformed("short IPv4 header"));
            }
            if frame[9] != IPPROTO_TCP {
                return Err(malformed("not TCP"));
            }
            let total = be16(frame, 2).ok_or_else(|| malformed("short IPv4 header"))? as usize;
            let mut s = [0u8; 16];
            let mut d = [0u8; 16];
            s[..4].copy_from_slice(&frame[12..16]);
            d[..4].copy_from_slice(&frame[16..20]);
            (SocketProtocol::Tcp, s, d, ihl, total)
        }
        6 => {
            if frame.len() < 40 {
                return Err(malformed("short IPv6 header"));
            }
            if frame[6] != IPPROTO_TCP {
                // Extension headers are not walked: a frame whose next
                // header is anything but TCP is not interpreted.
                return Err(malformed("not TCP or has extension headers"));
            }
            let payload = be16(frame, 4).ok_or_else(|| malformed("short IPv6 header"))? as usize;
            let mut s = [0u8; 16];
            let mut d = [0u8; 16];
            s.copy_from_slice(&frame[8..24]);
            d.copy_from_slice(&frame[24..40]);
            (SocketProtocol::Tcp6, s, d, 40, 40 + payload)
        }
        _ => return Err(malformed("not IP")),
    };
    if frame.len() < tcp_off + 20 {
        return Err(malformed("short TCP header"));
    }
    let doff = ((frame[tcp_off + 12] >> 4) as usize) * 4;
    if doff < 20 {
        return Err(malformed("TCP data offset below 20"));
    }
    if ip_total < tcp_off + doff {
        return Err(malformed("IP length shorter than its headers"));
    }
    if frame.len() < tcp_off + doff {
        return Err(malformed("truncated TCP options"));
    }
    let payload_len = (ip_total - tcp_off - doff) as u32;
    let is_v6 = protocol == SocketProtocol::Tcp6;
    let direction = match pkttype {
        PACKET_OUTGOING => WireDirection::Outgoing,
        PACKET_HOST => WireDirection::Incoming,
        _ => WireDirection::Other,
    };
    Ok(KernelLifecycleKind::WireSegment {
        ifindex,
        direction,
        protocol,
        src: SocketEndpoint {
            addr: src_addr,
            is_v6,
            port: be16(frame, tcp_off).ok_or_else(|| malformed("short TCP header"))?,
        },
        dst: SocketEndpoint {
            addr: dst_addr,
            is_v6,
            port: be16(frame, tcp_off + 2).ok_or_else(|| malformed("short TCP header"))?,
        },
        flags: frame[tcp_off + 13],
        seq: be32(frame, tcp_off + 4).ok_or_else(|| malformed("short TCP header"))?,
        ack: be32(frame, tcp_off + 8).ok_or_else(|| malformed("short TCP header"))?,
        payload_len,
        frame_len: frame.len() as u32,
        kernel_realtime_ns,
    })
}

#[cfg(target_os = "linux")]
mod sys {
    use super::*;
    use crate::linux::ProcEvent;
    use std::os::fd::RawFd;

    const SOL_PACKET: libc::c_int = 263;
    const PACKET_STATISTICS: libc::c_int = 6;
    /// Largest frame `lo` can carry (its MTU is 65536).
    const BUF_LEN: usize = 65_536 + 64;

    #[repr(C)]
    #[derive(Default)]
    struct TpacketStats {
        tp_packets: u32,
        tp_drops: u32,
    }

    /// The device tap: one `AF_PACKET` socket, bound to one interface or to
    /// all of them.
    pub struct WireTap {
        fd: RawFd,
        ifindex: u32,
        lost: u64,
        buf: Vec<u8>,
    }

    impl std::fmt::Debug for WireTap {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("WireTap")
                .field("ifindex", &self.ifindex)
                .field("lost", &self.lost)
                .finish()
        }
    }

    impl Drop for WireTap {
        fn drop(&mut self) {
            // SAFETY: the fd was opened by this struct.
            unsafe { libc::close(self.fd) };
        }
    }

    impl WireTap {
        /// Open the tap on `interface` (by name), or on every device when
        /// `None`. `Unavailable` without `CAP_NET_RAW` or when the interface
        /// does not exist; nothing is simulated in that case.
        pub fn open(interface: Option<&str>) -> Result<WireTap, SourceError> {
            let ifindex: u32 = match interface {
                None => 0,
                Some(name) => {
                    let c = std::ffi::CString::new(name)
                        .map_err(|_| SourceError::Unavailable("interface name has NUL".into()))?;
                    // SAFETY: `c` is a valid NUL-terminated string.
                    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
                    if idx == 0 {
                        return Err(SourceError::Unavailable(format!(
                            "no such interface: {name}"
                        )));
                    }
                    idx
                }
            };
            let proto = (libc::ETH_P_ALL as u16).to_be() as libc::c_int;
            // SAFETY: plain socket creation.
            let fd = unsafe {
                libc::socket(
                    libc::AF_PACKET,
                    libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                    proto,
                )
            };
            if fd < 0 {
                let err = std::io::Error::last_os_error();
                return Err(SourceError::Unavailable(format!(
                    "socket(AF_PACKET): {err} (CAP_NET_RAW required)"
                )));
            }
            let tap = WireTap {
                fd,
                ifindex,
                lost: 0,
                buf: vec![0u8; BUF_LEN],
            };
            // A larger receive queue: frames the queue cannot hold are counted
            // as loss, and the default queue overflows within a second of
            // host traffic between drains. Root may exceed rmem_max
            // (SO_RCVBUFFORCE); otherwise the ordinary option applies and the
            // kernel clamps. Either way loss stays counted, never hidden.
            let want: libc::c_int = 8 * 1024 * 1024;
            for opt in [libc::SO_RCVBUFFORCE, libc::SO_RCVBUF] {
                // SAFETY: `want` outlives the call; the option takes an int.
                let rc = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        opt,
                        &want as *const libc::c_int as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    )
                };
                if rc == 0 {
                    break;
                }
            }
            let one: libc::c_int = 1;
            // SAFETY: `one` outlives the call; the option takes an int.
            let rc = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_TIMESTAMPNS,
                    &one as *const libc::c_int as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                return Err(SourceError::Unavailable(format!("SO_TIMESTAMPNS: {err}")));
            }
            // SAFETY: sockaddr_ll is plain data; zeroed then filled.
            let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            addr.sll_family = libc::AF_PACKET as u16;
            addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
            addr.sll_ifindex = ifindex as libc::c_int;
            // SAFETY: `addr` is a valid sockaddr_ll of the stated length.
            let rc = unsafe {
                libc::bind(
                    fd,
                    &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                )
            };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                return Err(SourceError::Unavailable(format!("bind(AF_PACKET): {err}")));
            }
            // Reading the statistics resets them: start from a known zero.
            let _ = tap.read_drops();
            Ok(tap)
        }

        /// Interface index the tap is bound to; 0 means every device.
        pub fn ifindex(&self) -> u32 {
            self.ifindex
        }

        fn read_drops(&self) -> u64 {
            let mut st = TpacketStats::default();
            let mut len = std::mem::size_of::<TpacketStats>() as libc::socklen_t;
            // SAFETY: `st` is a valid, writable buffer of the stated length.
            let rc = unsafe {
                libc::getsockopt(
                    self.fd,
                    SOL_PACKET,
                    PACKET_STATISTICS,
                    &mut st as *mut TpacketStats as *mut libc::c_void,
                    &mut len,
                )
            };
            if rc != 0 {
                0
            } else {
                st.tp_drops as u64
            }
        }

        /// Frames the kernel dropped from this socket's queue since the last
        /// call (`PACKET_STATISTICS.tp_drops`, which the kernel resets on
        /// read), plus frames this reader received truncated.
        pub fn take_lost(&mut self) -> u64 {
            self.lost += self.read_drops();
            std::mem::take(&mut self.lost)
        }

        /// Next TCP segment, waiting up to `timeout_ms`. `Ok(None)` on
        /// timeout. Frames that are not TCP/IP are skipped silently — they
        /// are not loss, they are out of scope; frames the buffer could not
        /// hold are counted as lost.
        pub fn next_event(&mut self, timeout_ms: i32) -> Result<Option<ProcEvent>, SourceError> {
            let deadline = std::time::Instant::now()
                + std::time::Duration::from_millis(timeout_ms.max(0) as u64);
            loop {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                let mut pfd = libc::pollfd {
                    fd: self.fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: one valid pollfd.
                let rc = unsafe { libc::poll(&mut pfd, 1, remaining.as_millis() as libc::c_int) };
                if rc < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(SourceError::Unavailable(format!("poll: {err}")));
                }
                if rc == 0 {
                    return Ok(None);
                }
                match self.recv_one()? {
                    Some(ev) => return Ok(Some(ev)),
                    None => {
                        if std::time::Instant::now() >= deadline {
                            return Ok(None);
                        }
                    }
                }
            }
        }

        /// One `recvmsg`. `Ok(None)` when the frame was not a TCP segment.
        fn recv_one(&mut self) -> Result<Option<ProcEvent>, SourceError> {
            // SAFETY: zeroed plain-data structures, filled by the kernel.
            let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut control = [0u8; 128];
            let mut iov = libc::iovec {
                iov_base: self.buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: self.buf.len(),
            };
            // SAFETY: as above.
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_name = &mut addr as *mut libc::sockaddr_ll as *mut libc::c_void;
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = control.len() as _;
            // SAFETY: every pointer in `msg` refers to live, correctly sized
            // buffers owned by this frame.
            let n = unsafe { libc::recvmsg(self.fd, &mut msg, libc::MSG_DONTWAIT) };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::Interrupted
                {
                    return Ok(None);
                }
                return Err(SourceError::Unavailable(format!("recvmsg: {err}")));
            }
            if msg.msg_flags & libc::MSG_TRUNC != 0 {
                self.lost += 1;
                return Ok(None);
            }
            // Probe dequeue stamp on the monotonic clock: an upper bound on
            // when the kernel captured the frame.
            let mut ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // SAFETY: `ts` is a valid, writable timespec.
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
            let probe_ns = ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64;
            // Kernel capture stamp (realtime) from the control message.
            let mut kernel_realtime_ns = 0u64;
            // SAFETY: CMSG_* walk the control buffer the kernel just filled,
            // bounded by msg_controllen.
            unsafe {
                let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
                while !cmsg.is_null() {
                    if (*cmsg).cmsg_level == libc::SOL_SOCKET
                        && (*cmsg).cmsg_type == libc::SCM_TIMESTAMPNS
                    {
                        let data = libc::CMSG_DATA(cmsg) as *const libc::timespec;
                        let t = std::ptr::read_unaligned(data);
                        kernel_realtime_ns = t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64;
                    }
                    cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
                }
            }
            if kernel_realtime_ns == 0 {
                // A frame without a kernel stamp cannot be placed in time;
                // it is not evidence and is counted as lost.
                self.lost += 1;
                return Ok(None);
            }
            let frame = &self.buf[..n as usize];
            match parse_wire_frame(
                frame,
                addr.sll_pkttype,
                addr.sll_ifindex as u32,
                kernel_realtime_ns,
            ) {
                Ok(kind) => Ok(Some(ProcEvent {
                    kind,
                    cpu: 0,
                    timestamp_ns: probe_ns,
                })),
                Err(_) => Ok(None),
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use sys::WireTap;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direction_follows_pkttype_and_nothing_else() {
        let mut f = vec![0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0];
        f.extend_from_slice(&[127, 0, 0, 1, 127, 0, 0, 1]);
        f.extend_from_slice(&[
            0, 80, 0, 81, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0,
        ]);
        for (pkt, dir) in [
            (PACKET_HOST, WireDirection::Incoming),
            (PACKET_OUTGOING, WireDirection::Outgoing),
            (PACKET_BROADCAST, WireDirection::Other),
            (PACKET_MULTICAST, WireDirection::Other),
            (PACKET_OTHERHOST, WireDirection::Other),
            (200, WireDirection::Other),
        ] {
            match parse_wire_frame(&f, pkt, 1, 1).unwrap() {
                KernelLifecycleKind::WireSegment { direction, .. } => assert_eq!(direction, dir),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn ipv4_options_and_tcp_options_are_skipped_by_their_length_fields() {
        // IHL = 6 (24 bytes), data offset = 8 (32 bytes), 5 bytes payload.
        let total: u16 = 24 + 32 + 5;
        let mut f = vec![0x46, 0];
        f.extend_from_slice(&total.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0x40, 0, 64, 6, 0, 0]);
        f.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        f.extend_from_slice(&[0, 0, 0, 0]); // IP option
        f.extend_from_slice(&[0x12, 0x34, 0x01, 0xbb]); // ports
        f.extend_from_slice(&[0, 0, 0, 9, 0, 0, 0, 0]); // seq, ack
        f.push(8 << 4);
        f.push(0x18);
        f.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
        f.extend_from_slice(&[0; 12]); // TCP options
        f.extend_from_slice(b"hello");
        match parse_wire_frame(&f, PACKET_HOST, 1, 1).unwrap() {
            KernelLifecycleKind::WireSegment {
                src,
                dst,
                seq,
                payload_len,
                ..
            } => {
                assert_eq!(src.port, 0x1234);
                assert_eq!(dst.port, 443);
                assert_eq!(seq, 9);
                assert_eq!(payload_len, 5);
            }
            _ => unreachable!(),
        }
        // Options declared but not delivered: refused.
        assert!(parse_wire_frame(&f[..40], PACKET_HOST, 1, 1).is_err());
    }
}
