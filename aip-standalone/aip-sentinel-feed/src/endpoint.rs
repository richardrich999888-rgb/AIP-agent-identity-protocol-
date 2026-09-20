//! Rendering a kernel socket endpoint as the textual `host:port` an
//! allow-list is actually written in.
//!
//! # Why this is not cosmetic
//!
//! The reconciler this feed serves judges egress by comparing `destination`
//! against a declared allow-list of strings. A destination rendered in a form
//! the operator's policy does not use is a **false negative in the one check
//! that matters**: bytes leave to an unapproved host and the comparison finds
//! nothing to object to. So the output is the canonical textual form
//! (RFC 5952 for IPv6, dotted quad for IPv4), not a debug print.
//!
//! Three rules carry that:
//!
//! * lowercase hexadecimal with no leading zeros in a group (RFC 5952 §4.1,
//!   §4.3), so one address has one spelling;
//! * the **longest** run of two or more all-zero groups is replaced by `::`,
//!   leftmost run on a tie (§4.2) — a single zero group is never compressed,
//!   because `::` for one group is shorter to write and ambiguous to read;
//! * an IPv4-mapped address (`::ffff:a.b.c.d`) is rendered as the dotted quad
//!   (§5). A dual-stack listener reports a v4 peer on an `AF_INET6` socket,
//!   and an operator's allow-list says `10.0.0.7`, not `::ffff:10.0.0.7`.
//!
//! IPv6 takes brackets before the port (`[2001:db8::1]:443`), which is what
//! separates the address's colons from the port's.

use aip_observe::SocketEndpoint;

/// The canonical `host:port` text for an endpoint.
///
/// Total: every 16-byte address has a rendering, so there is no failure mode
/// here for a caller to have to handle, and none is invented.
pub fn render(endpoint: &SocketEndpoint) -> String {
    if endpoint.is_v6 {
        if let Some(quad) = ipv4_mapped(&endpoint.addr) {
            return format!("{quad}:{}", endpoint.port);
        }
        format!("[{}]:{}", ipv6(&endpoint.addr), endpoint.port)
    } else {
        format!("{}:{}", ipv4(&endpoint.addr[..4]), endpoint.port)
    }
}

/// Dotted quad from four octets.
fn ipv4(octets: &[u8]) -> String {
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

/// The embedded IPv4 address of an IPv4-mapped IPv6 address, if this is one:
/// eighty zero bits, sixteen one bits, then the address (RFC 4291 §2.5.5.2).
fn ipv4_mapped(addr: &[u8; 16]) -> Option<String> {
    let mapped = addr[..10].iter().all(|b| *b == 0) && addr[10] == 0xff && addr[11] == 0xff;
    mapped.then(|| ipv4(&addr[12..16]))
}

/// RFC 5952 textual form of a 128-bit address.
fn ipv6(addr: &[u8; 16]) -> String {
    // Eight 16-bit groups, big-endian, as the wire carries them.
    let groups: [u16; 8] =
        std::array::from_fn(|i| u16::from_be_bytes([addr[2 * i], addr[2 * i + 1]]));

    // Longest run of consecutive zero groups; leftmost wins a tie because
    // `best_len` is replaced only on a strictly longer run.
    let (mut best_start, mut best_len) = (0usize, 0usize);
    let (mut run_start, mut run_len) = (0usize, 0usize);
    for (i, g) in groups.iter().enumerate() {
        if *g == 0 {
            if run_len == 0 {
                run_start = i;
            }
            run_len += 1;
            if run_len > best_len {
                best_start = run_start;
                best_len = run_len;
            }
        } else {
            run_len = 0;
        }
    }
    // A run of one is not compressed: `::` must stand for at least two groups.
    if best_len < 2 {
        best_len = 0;
    }

    // Rendered as head `::` tail rather than by walking with a flag: the
    // separator count at the seam is where a hand-rolled loop gets a trailing
    // or leading group wrong, and a join has no seam to get wrong.
    let hex = |g: &u16| format!("{g:x}");
    if best_len == 0 {
        return groups.iter().map(hex).collect::<Vec<_>>().join(":");
    }
    let head = groups[..best_start]
        .iter()
        .map(hex)
        .collect::<Vec<_>>()
        .join(":");
    let tail = groups[best_start + best_len..]
        .iter()
        .map(hex)
        .collect::<Vec<_>>()
        .join(":");
    format!("{head}::{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v6(addr: [u8; 16], port: u16) -> SocketEndpoint {
        SocketEndpoint {
            addr,
            is_v6: true,
            port,
        }
    }

    fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketEndpoint {
        let mut addr = [0u8; 16];
        addr[..4].copy_from_slice(&[a, b, c, d]);
        SocketEndpoint {
            addr,
            is_v6: false,
            port,
        }
    }

    fn from_groups(groups: [u16; 8]) -> [u8; 16] {
        let mut addr = [0u8; 16];
        for (i, g) in groups.iter().enumerate() {
            addr[2 * i..2 * i + 2].copy_from_slice(&g.to_be_bytes());
        }
        addr
    }

    #[test]
    fn e01_ipv4_is_a_dotted_quad_with_its_port() {
        assert_eq!(render(&v4(10, 0, 0, 7, 443)), "10.0.0.7:443");
        assert_eq!(render(&v4(255, 255, 255, 255, 1)), "255.255.255.255:1");
    }

    #[test]
    fn e02_ipv4_ignores_the_twelve_trailing_bytes() {
        // Only the first four octets are the address; the rest of the fixed
        // buffer is padding and must not leak into the rendering.
        let mut e = v4(192, 0, 2, 1, 80);
        e.addr[4..].copy_from_slice(&[0xab; 12]);
        assert_eq!(render(&e), "192.0.2.1:80");
    }

    #[test]
    fn e03_ipv6_compresses_the_longest_zero_run_and_brackets_the_port() {
        let addr = from_groups([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1]);
        assert_eq!(render(&v6(addr, 443)), "[2001:db8::1]:443");
    }

    #[test]
    fn e04_a_single_zero_group_is_not_compressed() {
        // RFC 5952 §4.2.2: `::` for one group is not shorter and is harder to
        // read, so it stays written out.
        let addr = from_groups([0x2001, 0xdb8, 0, 1, 1, 1, 1, 1]);
        assert_eq!(render(&v6(addr, 8080)), "[2001:db8:0:1:1:1:1:1]:8080");
    }

    #[test]
    fn e05_the_longest_run_wins_not_the_first() {
        // One zero group, then three. The compression must land on the three.
        let addr = from_groups([1, 0, 1, 0, 0, 0, 1, 1]);
        assert_eq!(render(&v6(addr, 53)), "[1:0:1::1:1]:53");
    }

    #[test]
    fn e06_equal_runs_compress_the_leftmost() {
        // Two runs of two. RFC 5952 §4.2.3 picks the first.
        let addr = from_groups([1, 0, 0, 2, 3, 0, 0, 4]);
        assert_eq!(render(&v6(addr, 9)), "[1::2:3:0:0:4]:9");
    }

    #[test]
    fn e07_the_unspecified_and_loopback_addresses() {
        assert_eq!(render(&v6([0u8; 16], 0)), "[::]:0");
        let addr = from_groups([0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(render(&v6(addr, 22)), "[::1]:22");
    }

    #[test]
    fn e08_a_trailing_zero_run_compresses_to_a_double_colon_at_the_end() {
        let addr = from_groups([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]);
        assert_eq!(render(&v6(addr, 443)), "[2001:db8::]:443");
    }

    #[test]
    fn e09_an_ipv4_mapped_address_renders_as_the_dotted_quad() {
        // A dual-stack listener reports a v4 peer this way. An operator's
        // allow-list says `198.51.100.9`, so that is what must be compared.
        let mut addr = [0u8; 16];
        addr[10] = 0xff;
        addr[11] = 0xff;
        addr[12..].copy_from_slice(&[198, 51, 100, 9]);
        assert_eq!(render(&v6(addr, 443)), "198.51.100.9:443");
    }

    #[test]
    fn e10_a_near_miss_of_the_mapped_prefix_is_not_treated_as_ipv4() {
        // `::fffe:...` is not the mapped prefix; rendering it as a quad would
        // silently rewrite a different address into an allow-listed one.
        let mut addr = [0u8; 16];
        addr[10] = 0xff;
        addr[11] = 0xfe;
        addr[12..].copy_from_slice(&[198, 51, 100, 9]);
        assert_eq!(render(&v6(addr, 443)), "[::fffe:c633:6409]:443");
    }

    #[test]
    fn e11_groups_carry_no_leading_zeros_and_are_lowercase() {
        let addr = from_groups([0x0001, 0x00ab, 0x0ABC, 0xFFFF, 1, 2, 3, 4]);
        assert_eq!(render(&v6(addr, 1)), "[1:ab:abc:ffff:1:2:3:4]:1");
    }
}
