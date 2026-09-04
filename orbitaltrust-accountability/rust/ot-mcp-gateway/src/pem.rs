//! Minimal PEM handling shared by the TLS transport and the provisioning
//! tool.
//!
//! Hand-rolled rather than pulled from a PEM crate: it is forty lines, it
//! keeps the dependency surface of security-critical binaries smaller, and
//! the failure mode of getting it wrong is material that does not load
//! rather than material that loads incorrectly.

/// Extracts every DER block of one PEM label.
pub fn parse_pem(pem: &[u8], label: &str) -> Vec<Vec<u8>> {
    let text = String::from_utf8_lossy(pem);
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = text.as_ref();
    while let Some(start) = rest.find(&begin) {
        let body_start = start + begin.len();
        let Some(stop) = rest[body_start..].find(&end) else {
            break;
        };
        let body: String = rest[body_start..body_start + stop]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if let Some(der) = base64_decode(&body) {
            out.push(der);
        }
        rest = &rest[body_start + stop + end.len()..];
    }
    out
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for byte in input.bytes() {
        if byte == b'=' {
            break;
        }
        let value = TABLE.iter().position(|c| *c == byte)? as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decoding_matches_known_vectors() {
        assert_eq!(base64_decode("").unwrap(), b"");
        assert_eq!(base64_decode("TWE=").unwrap(), b"Ma");
        assert_eq!(base64_decode("TWFu").unwrap(), b"Man");
        assert_eq!(base64_decode("bGlnaHQgdw==").unwrap(), b"light w");
        assert_eq!(base64_decode("bGlnaHQgd29y").unwrap(), b"light wor");
        // A character outside the alphabet is refused rather than skipped:
        // silently dropping bytes from a certificate would be worse than
        // failing to load it.
        assert!(base64_decode("TWF!").is_none());
    }

    #[test]
    fn pem_parsing_extracts_every_block_of_the_requested_label() {
        let pem = b"\
-----BEGIN CERTIFICATE-----
TWFu
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
TWE=
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
TWFu
-----END CERTIFICATE-----
";
        assert_eq!(parse_pem(pem, "CERTIFICATE").len(), 2);
        assert_eq!(parse_pem(pem, "PRIVATE KEY"), vec![b"Ma".to_vec()]);
        assert!(parse_pem(pem, "EC PRIVATE KEY").is_empty());
        // An unterminated block yields nothing rather than a truncated key.
        assert!(parse_pem(b"-----BEGIN CERTIFICATE-----\nTWFu\n", "CERTIFICATE").is_empty());
    }
}
