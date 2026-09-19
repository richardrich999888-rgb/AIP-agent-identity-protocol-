//! Resource authority at the decision point (R2 of
//! `docs/pilot/RBI_REQUIREMENTS_COVERAGE.md`).
//!
//! A capability scope says which *actions* an agent may take. Inside a
//! regulated entity the question that matters as much is *which systems*
//! it may take them against: the loan ledger but never the payments switch.
//! This module adds that dimension without a new token format:
//!
//! - **The grant lives in the scope.** `res:<id>` entries in a token's
//!   `allowed` list grant named resources ([`aip_registry`]); `denied`
//!   withholds them. They are signed by the issuer and attenuate down the
//!   chain exactly as actions do, because they *are* scope entries. A hop
//!   cannot add a resource its parent did not hold.
//! - **The name comes from the institution's signed registry.** The decision
//!   point resolves the request's network destination against a
//!   [`ResourceRegistry`] it has verified under the institution's anchor.
//!   An address the institution never named is refused outright:
//!   `DestinationUnregistered` is a denial, never a pass-through.
//! - **The destination is the request's own parameters.** The same
//!   `protocol` / `remote_addr` / `remote_port` bytes whose digest the
//!   expectation signs and the reconciler recomputes. There is no second
//!   place a destination can be stated.
//!
//! What this does not do: it does not carry the resolved name into the
//! `ExpectedExecution` (its parameter digest must stay exactly what the
//! reconciler recomputes from the observation), and it does not make the
//! policy visible inside the expectation. The per-agent access ledger
//! (`aip-ledger`) is where names appear in signed evidence, resolved against
//! the registry revision it cites. A decision point with **no** resource
//! policy configured performs no resource check, and says so through
//! [`crate::DecisionPoint::resource_policy`]; the pilot deployment must
//! configure one.

use aip_registry::{ObservedProtocol, RegistryError, RegistryTrustAnchors, ResourceRegistry};

use crate::actions::{PARAM_PROTOCOL, PARAM_REMOTE_ADDR, PARAM_REMOTE_PORT};
use crate::expected::ActionParameters;

/// The institution's verified resource registry, as decision-point policy.
#[derive(Debug, Clone)]
pub struct ResourcePolicy {
    registry: ResourceRegistry,
}

impl ResourcePolicy {
    /// Adopt a registry as policy. Verified here, under the institution's
    /// anchors, before it can influence a single decision: a decision point
    /// never resolves against a registry nobody it trusts signed.
    pub fn new(
        registry: ResourceRegistry,
        anchors: &RegistryTrustAnchors,
    ) -> Result<Self, RegistryError> {
        registry.verify(anchors)?;
        Ok(Self { registry })
    }

    pub fn registry(&self) -> &ResourceRegistry {
        &self.registry
    }
}

/// A network destination named by an action's parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Destination {
    pub protocol: ObservedProtocol,
    pub is_v6: bool,
    pub addr: [u8; 16],
    pub port: u16,
}

/// Why parameters that name a destination could not be read as one. Each is
/// a refusal: a destination the decision point cannot parse is not resolved
/// permissively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestinationError {
    UnknownProtocol(Vec<u8>),
    MissingRemoteAddr,
    MissingRemotePort,
    AddressLength { expected: usize, got: usize },
    PortLength(usize),
    ZeroPort,
}

impl std::fmt::Display for DestinationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for DestinationError {}

/// Read the network destination out of action parameters, if they name one.
///
/// `Ok(None)` when the parameters carry no `protocol` key: the action is not
/// a network action and no resource check applies. `Ok(Some)` for the
/// `net.connect` / `net.send` vocabulary (`aip_authorize::actions`), read
/// from the raw bytes exactly as they are signed. `Err` when a `protocol`
/// key is present but the destination is malformed.
pub fn destination_of(params: &ActionParameters) -> Result<Option<Destination>, DestinationError> {
    let Some(proto) = params.get(PARAM_PROTOCOL) else {
        return Ok(None);
    };
    let (protocol, is_v6, want_len) = match proto {
        b"tcp" => (ObservedProtocol::Tcp, false, 4usize),
        b"tcp6" => (ObservedProtocol::Tcp, true, 16usize),
        b"udp" => (ObservedProtocol::Udp, false, 4usize),
        b"udp6" => (ObservedProtocol::Udp, true, 16usize),
        other => return Err(DestinationError::UnknownProtocol(other.to_vec())),
    };
    let raw_addr = params
        .get(PARAM_REMOTE_ADDR)
        .ok_or(DestinationError::MissingRemoteAddr)?;
    if raw_addr.len() != want_len {
        return Err(DestinationError::AddressLength {
            expected: want_len,
            got: raw_addr.len(),
        });
    }
    let raw_port = params
        .get(PARAM_REMOTE_PORT)
        .ok_or(DestinationError::MissingRemotePort)?;
    if raw_port.len() != 2 {
        return Err(DestinationError::PortLength(raw_port.len()));
    }
    let port = u16::from_be_bytes([raw_port[0], raw_port[1]]);
    if port == 0 {
        return Err(DestinationError::ZeroPort);
    }
    // The observer's layout (`aip_observe::SocketEndpoint`): IPv4 in the
    // first four bytes, zero-padded. The registry uses the same, so the
    // decision point and the ledger resolve identical bytes.
    let mut addr = [0u8; 16];
    addr[..raw_addr.len()].copy_from_slice(raw_addr);
    Ok(Some(Destination {
        protocol,
        is_v6,
        addr,
        port,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::{net_connect_parameters, process_exec_parameters, NetProtocol};

    #[test]
    fn a_connect_parameter_set_names_its_destination() {
        let p = net_connect_parameters(NetProtocol::Tcp, &[10, 0, 5, 20], 8443).unwrap();
        let d = destination_of(&p).unwrap().unwrap();
        assert_eq!(d.protocol, ObservedProtocol::Tcp);
        assert!(!d.is_v6);
        assert_eq!(&d.addr[..4], &[10, 0, 5, 20]);
        assert_eq!(&d.addr[4..], &[0u8; 12]);
        assert_eq!(d.port, 8443);
        let p6 = net_connect_parameters(NetProtocol::Tcp6, &[0xfd; 16], 22).unwrap();
        let d6 = destination_of(&p6).unwrap().unwrap();
        assert!(d6.is_v6);
        assert_eq!(d6.addr, [0xfd; 16]);
    }

    #[test]
    fn a_non_network_action_names_no_destination() {
        let p = process_exec_parameters([1u8; 32]);
        assert_eq!(destination_of(&p), Ok(None));
    }

    #[test]
    fn a_malformed_destination_is_an_error_not_a_pass() {
        let p = ActionParameters::from_pairs([
            (PARAM_PROTOCOL, b"tcp".to_vec()),
            (PARAM_REMOTE_ADDR, vec![10, 0, 5]),
            (PARAM_REMOTE_PORT, vec![0x20, 0xfb]),
        ])
        .unwrap();
        assert_eq!(
            destination_of(&p),
            Err(DestinationError::AddressLength {
                expected: 4,
                got: 3
            })
        );
        let q = ActionParameters::from_pairs([(PARAM_PROTOCOL, b"sctp".to_vec())]).unwrap();
        assert_eq!(
            destination_of(&q),
            Err(DestinationError::UnknownProtocol(b"sctp".to_vec()))
        );
    }
}
