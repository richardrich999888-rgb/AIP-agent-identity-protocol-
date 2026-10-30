//! Inference egress policy.
//!
//! The inference endpoint must be an IP **literal** in a loopback range.
//! Hostnames are refused outright, not resolved: resolution is itself
//! egress (DNS), and a hostname can be re-pointed after validation. There is
//! deliberately no configuration switch to allow a non-loopback endpoint;
//! serving a model on another host is a different deployment (with mutual
//! authentication) and is out of scope for this slice.

use std::net::{IpAddr, SocketAddr};

/// A validated loopback socket address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoopbackEndpoint(SocketAddr);

/// Why an endpoint was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressError {
    /// Not of the form `<ip-literal>:<port>`.
    NotAnIpLiteral(String),
    /// A parsed address outside 127.0.0.0/8 or ::1.
    NotLoopback(String),
    /// Port 0 is not a destination.
    ZeroPort,
}

impl std::fmt::Display for EgressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for EgressError {}

impl LoopbackEndpoint {
    /// Parse `127.0.0.1:8080` or `[::1]:8080`. Anything else is refused.
    pub fn parse(s: &str) -> Result<Self, EgressError> {
        let addr: SocketAddr = s
            .parse()
            .map_err(|_| EgressError::NotAnIpLiteral(s.chars().take(64).collect()))?;
        if addr.port() == 0 {
            return Err(EgressError::ZeroPort);
        }
        // IPv4-mapped IPv6 (::ffff:a.b.c.d) is judged by its IPv4 address so
        // ::ffff:8.8.8.8 cannot pass as "IPv6".
        let loopback = match addr.ip() {
            IpAddr::V4(v4) => v4.is_loopback(),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => v4.is_loopback(),
                None => v6.is_loopback(),
            },
        };
        if !loopback {
            return Err(EgressError::NotLoopback(addr.to_string()));
        }
        Ok(LoopbackEndpoint(addr))
    }

    /// The validated socket address.
    pub fn addr(&self) -> SocketAddr {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_literals_accepted() {
        assert!(LoopbackEndpoint::parse("127.0.0.1:8080").is_ok());
        assert!(LoopbackEndpoint::parse("127.9.9.9:1").is_ok());
        assert!(LoopbackEndpoint::parse("[::1]:8080").is_ok());
        assert!(LoopbackEndpoint::parse("[::ffff:127.0.0.1]:8080").is_ok());
    }

    #[test]
    fn hostnames_refused_without_resolution() {
        for h in ["localhost:8080", "api.openai.com:443", "huggingface.co:443"] {
            assert!(
                matches!(
                    LoopbackEndpoint::parse(h),
                    Err(EgressError::NotAnIpLiteral(_))
                ),
                "{h}"
            );
        }
    }

    #[test]
    fn non_loopback_refused() {
        for a in [
            "10.0.0.1:80",
            "0.0.0.0:80",
            "8.8.8.8:53",
            "[::]:80",
            "[::ffff:8.8.8.8]:53",
            "[fe80::1]:80",
        ] {
            assert!(
                matches!(LoopbackEndpoint::parse(a), Err(EgressError::NotLoopback(_))),
                "{a}"
            );
        }
    }

    #[test]
    fn port_zero_and_garbage_refused() {
        assert_eq!(
            LoopbackEndpoint::parse("127.0.0.1:0"),
            Err(EgressError::ZeroPort)
        );
        assert!(LoopbackEndpoint::parse("127.0.0.1").is_err());
        assert!(LoopbackEndpoint::parse("http://127.0.0.1:80").is_err());
    }
}
