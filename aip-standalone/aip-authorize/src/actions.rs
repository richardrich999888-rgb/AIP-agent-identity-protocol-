//! Observable action vocabulary.
//!
//! An `ExpectedExecution` authorizes an `action_kind` with a
//! `parameter_digest`. For the digest to ever be *matched* by the
//! reconciler, the parameters have to be something an independent observer
//! can measure — and today the observer measures exactly one thing that is
//! also an action: rows of the kernel socket tables joined to a process
//! instance. This module fixes the vocabulary for that one class so the
//! decision point and the reconciler agree, byte for byte, on what is being
//! authorized.
//!
//! This is authorization vocabulary only. It says how to *name* a network
//! connection so it can be authorized; it does not observe anything, and it
//! carries no notion of what the observer's provenance or strength will be.
//!
//! **Scope of the class.** `ghost.net.connect.v1` is an *established* TCP
//! connection from the authorized instance to `(protocol, remote_addr,
//! remote_port)`. Nothing about bytes, payload, TLS, DNS names or timing is
//! part of it, because no observer source in this repository sees those.

use aip_types::ScopeAction;

use crate::expected::ActionParameters;

/// The custom scope action naming an established TCP connection to a remote
/// endpoint. The string is part of the signed scope of every token and
/// expectation that mentions it.
pub const NET_CONNECT_ACTION: &str = "ghost.net.connect.v1";

/// Parameter keys. Values: `protocol` is the ASCII name, `remote_addr` the
/// raw 4- or 16-byte address, `remote_port` the port as two big-endian bytes.
/// Raw bytes rather than text, so there is exactly one encoding of each.
pub const PARAM_PROTOCOL: &str = "protocol";
pub const PARAM_REMOTE_ADDR: &str = "remote_addr";
pub const PARAM_REMOTE_PORT: &str = "remote_port";

/// Transport family of a connection. Only what the kernel socket tables
/// distinguish; deliberately not `SocketProtocol` from the observer crate,
/// so authorization does not depend on observation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetProtocol {
    Tcp,
    Tcp6,
}

impl NetProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            NetProtocol::Tcp => "tcp",
            NetProtocol::Tcp6 => "tcp6",
        }
    }

    /// Address length the family requires.
    pub fn addr_len(&self) -> usize {
        match self {
            NetProtocol::Tcp => 4,
            NetProtocol::Tcp6 => 16,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetConnectError {
    /// `remote_addr` length does not match the protocol family.
    AddressLength { protocol: NetProtocol, got: usize },
    /// Port 0 names no remote endpoint.
    ZeroPort,
}

impl std::fmt::Display for NetConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetConnectError::AddressLength { protocol, got } => write!(
                f,
                "{} address must be {} bytes, got {got}",
                protocol.as_str(),
                protocol.addr_len()
            ),
            NetConnectError::ZeroPort => write!(f, "remote port 0 names no endpoint"),
        }
    }
}

impl std::error::Error for NetConnectError {}

/// The scope action for [`NET_CONNECT_ACTION`].
pub fn net_connect_action() -> ScopeAction {
    ScopeAction::Custom(NET_CONNECT_ACTION.to_string())
}

/// Parameters naming one remote endpoint. The digest of the result is what
/// an `ExpectedExecution` carries and what a reconciler recomputes from an
/// observed socket; both sides must call this function.
pub fn net_connect_parameters(
    protocol: NetProtocol,
    remote_addr: &[u8],
    remote_port: u16,
) -> Result<ActionParameters, NetConnectError> {
    if remote_addr.len() != protocol.addr_len() {
        return Err(NetConnectError::AddressLength {
            protocol,
            got: remote_addr.len(),
        });
    }
    if remote_port == 0 {
        return Err(NetConnectError::ZeroPort);
    }
    Ok(ActionParameters::from_pairs([
        (PARAM_PROTOCOL, protocol.as_str().as_bytes().to_vec()),
        (PARAM_REMOTE_ADDR, remote_addr.to_vec()),
        (PARAM_REMOTE_PORT, remote_port.to_be_bytes().to_vec()),
    ])
    .expect("three distinct constant keys"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameters_are_a_fixed_injective_encoding() {
        let a = net_connect_parameters(NetProtocol::Tcp, &[10, 0, 0, 5], 443).unwrap();
        let b = net_connect_parameters(NetProtocol::Tcp, &[10, 0, 0, 5], 443).unwrap();
        assert_eq!(a.digest(), b.digest());
        // Byte-compatible with the raw construction the RED tests pinned.
        let raw = ActionParameters::from_pairs([
            ("protocol", b"tcp".to_vec()),
            ("remote_addr", vec![10, 0, 0, 5]),
            ("remote_port", 443u16.to_be_bytes().to_vec()),
        ])
        .unwrap();
        assert_eq!(a.digest(), raw.digest());
        for other in [
            net_connect_parameters(NetProtocol::Tcp, &[10, 0, 0, 6], 443),
            net_connect_parameters(NetProtocol::Tcp, &[10, 0, 0, 5], 444),
            net_connect_parameters(NetProtocol::Tcp6, &[0; 16], 443),
        ] {
            assert_ne!(other.unwrap().digest(), a.digest());
        }
    }

    #[test]
    fn malformed_endpoints_are_refused() {
        assert_eq!(
            net_connect_parameters(NetProtocol::Tcp, &[10, 0, 0, 5, 1], 443),
            Err(NetConnectError::AddressLength {
                protocol: NetProtocol::Tcp,
                got: 5
            })
        );
        assert_eq!(
            net_connect_parameters(NetProtocol::Tcp6, &[1; 4], 443),
            Err(NetConnectError::AddressLength {
                protocol: NetProtocol::Tcp6,
                got: 4
            })
        );
        assert_eq!(
            net_connect_parameters(NetProtocol::Tcp, &[10, 0, 0, 5], 0),
            Err(NetConnectError::ZeroPort)
        );
    }

    #[test]
    fn action_is_a_custom_scope_action_within_the_length_bound() {
        assert_eq!(
            net_connect_action(),
            ScopeAction::Custom("ghost.net.connect.v1".into())
        );
        assert!(NET_CONNECT_ACTION.len() <= 64);
    }
}
