//! Industrial protocols, and why speaking one establishes nothing about a plant.
//!
//! # No protocol is trusted here
//!
//! The spec rule is blunt: *industrial protocol messages are not automatically
//! proof of physical process change.* This module implements that as a
//! structural property rather than a warning.
//!
//! Each protocol declares facts about itself — its transport, whether it
//! defines message authentication at all, whether that authentication is
//! optional and negotiated, and what defence it has against replay. Those facts
//! are used for exactly one purpose: saying what an interaction **cannot**
//! establish. They are never used to raise a ceiling, and there is deliberately
//! no `is_trusted` method for a caller to reach for.
//!
//! [`ProtocolInteraction::evidence_ceiling`] is computed from the observation
//! mechanism that saw the interaction, and from nothing about the protocol. An
//! OPC UA exchange under a signing security policy and an unauthenticated
//! Modbus write observed the same way get the same ceiling, because the
//! difference between them is *who spoke*, and the question here is *what
//! happened in the plant*.
//!
//! # The adapters
//!
//! An adapter is a deployment's translation from whatever its stack already
//! records — a connection log line, a socket sample, a captured header — into a
//! [`ProtocolInteraction`]. Adapters carry no payload parser: parsing a payload
//! would mean this crate deciding what a write meant, and a payload read off
//! the subject's own network is the subject's account of the payload in any
//! case.
//!
//! Three representative adapters ship: Modbus/TCP, DNP3 and OPC UA. They differ
//! in the facts they declare and in nothing else. `tests/adversarial.rs`
//! asserts no adapter can produce a stronger interaction than another.

use aip_observation::{EvidenceCeiling, ObservationClass};
use serde::{Deserialize, Serialize};

use crate::sensing::ProcessSensingSource;

/// How a protocol's transport is carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProtocolTransport {
    /// Routable IP. Observable by the edge node's socket and wire mechanisms.
    TcpIp,
    /// Routable IP, connectionless.
    UdpIp,
    /// A serial line or fieldbus. No Linux socket, no frame on a network
    /// device: entirely outside every mechanism in this build.
    SerialFieldbus,
}

/// Whether a protocol defines cryptographic message authentication.
///
/// Three states rather than a boolean, because "the standard has an optional
/// security mode" and "every deployment enables it" are different facts and
/// only the first is a property of the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MessageAuthentication {
    /// The protocol defines none. Anything on the segment can write.
    None,
    /// The protocol defines it, as an optional mode negotiated per session or
    /// per association. Never assumed present.
    OptionalNegotiated,
}

/// What a protocol does about a message being replayed at it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ReplayDefence {
    /// Nothing. A captured frame replayed later is accepted.
    None,
    /// A sequence or transaction counter, which detects a duplicate in flight
    /// and does not survive an adversary who can also choose the counter.
    SequenceCounter,
    /// A cryptographic session with a per-message nonce or challenge. Defeats
    /// replay **when negotiated**, which is a deployment fact, not a protocol
    /// fact.
    CryptographicSession,
}

impl ReplayDefence {
    pub fn code(self) -> u8 {
        match self {
            Self::None => 0x01,
            Self::SequenceCounter => 0x02,
            Self::CryptographicSession => 0x03,
        }
    }

    /// Whether a replayed message can be distinguished from a fresh one.
    ///
    /// True for `CryptographicSession` alone. A sequence counter is
    /// deliberately not a weak yes: an adversary positioned to replay a frame
    /// is positioned to observe and increment its counter.
    pub fn distinguishes_replay(self) -> bool {
        matches!(self, Self::CryptographicSession)
    }
}

/// A protocol an industrial or critical-edge deployment speaks.
///
/// Closed on purpose. An open vocabulary could not carry the facts below, and
/// a deployment that could name its own protocol could name it as a trusted
/// one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IndustrialProtocol {
    /// Modbus over TCP.
    ModbusTcp,
    /// Modbus over a serial line.
    ModbusSerial,
    /// DNP3 over TCP.
    Dnp3,
    /// IEC 60870-5-104.
    Iec60870104,
    /// OPC Unified Architecture, binary transport.
    OpcUa,
    /// EtherNet/IP with CIP.
    EtherNetIp,
    /// PROFINET.
    Profinet,
    /// BACnet/IP.
    BacnetIp,
    /// MQTT, as used for edge telemetry and command.
    Mqtt,
}

impl IndustrialProtocol {
    pub const ALL: [IndustrialProtocol; 9] = [
        Self::ModbusTcp,
        Self::ModbusSerial,
        Self::Dnp3,
        Self::Iec60870104,
        Self::OpcUa,
        Self::EtherNetIp,
        Self::Profinet,
        Self::BacnetIp,
        Self::Mqtt,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::ModbusTcp => 0x01,
            Self::ModbusSerial => 0x02,
            Self::Dnp3 => 0x03,
            Self::Iec60870104 => 0x04,
            Self::OpcUa => 0x05,
            Self::EtherNetIp => 0x06,
            Self::Profinet => 0x07,
            Self::BacnetIp => 0x08,
            Self::Mqtt => 0x09,
        }
    }

    pub fn transport(self) -> ProtocolTransport {
        match self {
            Self::ModbusTcp
            | Self::Dnp3
            | Self::Iec60870104
            | Self::OpcUa
            | Self::EtherNetIp
            | Self::BacnetIp
            | Self::Mqtt => ProtocolTransport::TcpIp,
            Self::Profinet => ProtocolTransport::UdpIp,
            Self::ModbusSerial => ProtocolTransport::SerialFieldbus,
        }
    }

    /// Whether the protocol standard defines cryptographic message
    /// authentication.
    ///
    /// `OptionalNegotiated` for the two that define a security mode. Neither
    /// is `Always`, because neither standard makes it mandatory and a mode
    /// that can be negotiated down is a mode an attacker negotiates down.
    pub fn message_authentication(self) -> MessageAuthentication {
        match self {
            Self::OpcUa | Self::Dnp3 => MessageAuthentication::OptionalNegotiated,
            _ => MessageAuthentication::None,
        }
    }

    pub fn replay_defence(self) -> ReplayDefence {
        match self {
            // A negotiated secure channel with per-message signatures.
            Self::OpcUa => ReplayDefence::CryptographicSession,
            // DNP3's application-layer sequence, and the optional secure
            // authentication whose challenge is not assumed here.
            Self::Dnp3 | Self::Iec60870104 => ReplayDefence::SequenceCounter,
            // Modbus/TCP's transaction identifier correlates a response with a
            // request. It is not a replay defence and was never meant as one.
            _ => ReplayDefence::None,
        }
    }

    /// Who can author a message this protocol will accept.
    pub fn forgeable_by(self) -> &'static str {
        match self.message_authentication() {
            MessageAuthentication::None => {
                "anything with a path to the segment: a compromised engineering station, a \
                 misconfigured router, a laptop in a cabinet"
            }
            MessageAuthentication::OptionalNegotiated => {
                "anything with a path to the segment, unless the deployment negotiated the \
                 security mode and can show it did — which is a deployment fact this crate does \
                 not assume"
            }
        }
    }

    /// What a successful exchange establishes.
    ///
    /// Identical text for every protocol, deliberately. The differences
    /// between these protocols are real and are about authorship; none of them
    /// is about whether a plant changed.
    pub fn positive_response_establishes(self) -> &'static str {
        "that a message was accepted by whatever answered at that endpoint"
    }

    /// The gap between the exchange and the plant.
    pub fn effect_gap(self) -> &'static str {
        match self {
            Self::ModbusTcp | Self::ModbusSerial => {
                "a written holding register is a number in a controller's memory; whether the \
                 logic read it, and whether an output followed, are two further questions"
            }
            Self::Dnp3 => {
                "a select-before-operate that completed is a controller that accepted an operate; \
                 the point may be forced, the output card may be failed"
            }
            Self::Iec60870104 => {
                "an activation confirmation is a telecontrol acknowledgement, not a switched \
                 breaker"
            }
            Self::OpcUa => {
                "a good status code on a write is a server that accepted a value into its address \
                 space; the address space is a model of the plant, not the plant"
            }
            Self::EtherNetIp => "a CIP success is an adapter that accepted a service request",
            Self::Profinet => {
                "a cyclic frame delivered is a frame delivered; the process image is written by \
                 the same device that reports it"
            }
            Self::BacnetIp => {
                "a written present-value is a property in an object database; a damper is not a \
                 property"
            }
            Self::Mqtt => {
                "a publish acknowledged is a broker that stored a message, and a broker is not a \
                 plant"
            }
        }
    }

    /// Whether this protocol's traffic can be observed at all in this build.
    ///
    /// False for the serial fieldbus: there is no socket to sample and no
    /// frame on a network device. A deployment that speaks only serial is
    /// observable at the edge node's process boundary and nowhere else, and
    /// this says so rather than leaving a silent hole.
    pub fn traffic_observable(self) -> bool {
        !matches!(self.transport(), ProtocolTransport::SerialFieldbus)
    }

    /// The sources that could observe traffic for this protocol.
    pub fn observable_by(self) -> &'static [ProcessSensingSource] {
        if self.traffic_observable() {
            &[
                ProcessSensingSource::EdgeNetworkObservation,
                ProcessSensingSource::EdgeDataTransferObservation,
                ProcessSensingSource::ProtocolWireObservation,
            ]
        } else {
            &[]
        }
    }
}

/// One exchange with a controller, as a deployment can honestly record it.
///
/// Carries no payload. A payload read off the subject's own network is the
/// subject's account of the payload, and parsing one here would make this crate
/// the thing that decides what a write meant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolInteraction {
    pub protocol: IndustrialProtocol,
    /// Whether the far end answered positively. A fact about a message.
    pub positive_response: bool,
    /// Whether the deployment can show the security mode was negotiated for
    /// this exchange. Supplied by the adapter from configuration the
    /// deployment holds; never inferred from the protocol.
    pub authenticated: bool,
    /// Whether an anchored observer saw a socket to the endpoint at a sample.
    pub socket_observed: bool,
    /// Whether an anchored observer saw the kernel accept bytes for it.
    pub bytes_observed: bool,
    /// Whether an anchored observer saw a frame cross the device.
    pub wire_observed: bool,
}

impl ProtocolInteraction {
    /// An exchange nobody observed. The honest default.
    pub fn unobserved(protocol: IndustrialProtocol, positive_response: bool) -> Self {
        Self {
            protocol,
            positive_response,
            authenticated: false,
            socket_observed: false,
            bytes_observed: false,
            wire_observed: false,
        }
    }

    /// The sources that actually observed this exchange.
    pub fn observed_by(&self) -> Vec<ProcessSensingSource> {
        let mut v = Vec::new();
        if self.socket_observed {
            v.push(ProcessSensingSource::EdgeNetworkObservation);
        }
        if self.bytes_observed {
            v.push(ProcessSensingSource::EdgeDataTransferObservation);
        }
        if self.wire_observed {
            v.push(ProcessSensingSource::ProtocolWireObservation);
        }
        v
    }

    /// The strongest evidence this interaction could contribute.
    ///
    /// The maximum over the ceilings of the sources that actually observed it,
    /// and `Corroborative` when none did. **Nothing about the protocol enters
    /// this computation**, and neither does `authenticated`: a signed message
    /// is a message whose author is known, and authorship is not occurrence.
    pub fn evidence_ceiling(&self) -> EvidenceCeiling {
        self.observed_by()
            .into_iter()
            .map(|s| s.ceiling())
            .max()
            .unwrap_or(EvidenceCeiling::Corroborative)
    }

    /// Whether a replay of an earlier exchange could be told apart from this
    /// one.
    ///
    /// Requires both a protocol that defines a cryptographic session **and** a
    /// deployment that can show it was negotiated. Either alone is a claim.
    pub fn replay_distinguishable(&self) -> bool {
        self.protocol.replay_defence().distinguishes_replay() && self.authenticated
    }

    /// Whether this interaction establishes that the physical process changed.
    ///
    /// **False for every protocol, every response, and every observation
    /// state**, and computed from the source table rather than written as a
    /// literal: it would take a source that is outside the control system, has
    /// an implemented mechanism, and belongs to the physical-effect class. No
    /// source is all three. If a future build implements one, this returns
    /// `true` and this module's tests fail, which is the intended way to find
    /// out.
    pub fn establishes_process_change(&self) -> bool {
        ObservationClass::PhysicalEffect.is_implemented()
            && ProcessSensingSource::ALL.iter().any(|s| {
                s.observation_class() == Some(ObservationClass::PhysicalEffect)
                    && s.is_independent()
                    && s.can_produce_observation_record()
            })
    }

    /// What this interaction may honestly be said to establish.
    pub fn statement(&self) -> &'static str {
        if !self.socket_observed && !self.bytes_observed && !self.wire_observed {
            return "nothing an anchored observer saw; the exchange is the subject's account of \
                    its own conversation";
        }
        "that the edge node conducted a conversation with an endpoint; not what was said, and \
         not what the far end did about it"
    }
}

/// A deployment's translation from what its stack records into an interaction.
///
/// Deliberately narrow. An adapter names its protocol and builds an
/// interaction; it has no way to declare a ceiling, no way to assert an effect,
/// and no way to mark itself trusted.
pub trait ProtocolAdapter {
    /// The protocol this adapter speaks.
    fn protocol(&self) -> IndustrialProtocol;

    /// Build an interaction from what the deployment observed.
    ///
    /// The default is the whole implementation for every adapter that ships:
    /// there is nothing protocol-specific to do, which is the point.
    fn interaction(
        &self,
        positive_response: bool,
        authenticated: bool,
        observed: &[ProcessSensingSource],
    ) -> ProtocolInteraction {
        ProtocolInteraction {
            protocol: self.protocol(),
            positive_response,
            // An adapter may only *lower* the authentication claim: a protocol
            // with no security mode cannot report an authenticated exchange
            // however its caller asks.
            authenticated: authenticated
                && self.protocol().message_authentication()
                    == MessageAuthentication::OptionalNegotiated,
            socket_observed: observed.contains(&ProcessSensingSource::EdgeNetworkObservation),
            bytes_observed: observed.contains(&ProcessSensingSource::EdgeDataTransferObservation),
            wire_observed: observed.contains(&ProcessSensingSource::ProtocolWireObservation),
        }
    }
}

/// Modbus/TCP. The most deployed and the least defended.
#[derive(Debug, Clone, Copy, Default)]
pub struct ModbusTcpAdapter;
impl ProtocolAdapter for ModbusTcpAdapter {
    fn protocol(&self) -> IndustrialProtocol {
        IndustrialProtocol::ModbusTcp
    }
}

/// DNP3, as used in electric and water utilities.
#[derive(Debug, Clone, Copy, Default)]
pub struct Dnp3Adapter;
impl ProtocolAdapter for Dnp3Adapter {
    fn protocol(&self) -> IndustrialProtocol {
        IndustrialProtocol::Dnp3
    }
}

/// OPC UA, the one with a real security model — which changes who spoke and
/// not what happened.
#[derive(Debug, Clone, Copy, Default)]
pub struct OpcUaAdapter;
impl ProtocolAdapter for OpcUaAdapter {
    fn protocol(&self) -> IndustrialProtocol {
        IndustrialProtocol::OpcUa
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OBSERVED_FULLY: [ProcessSensingSource; 3] = [
        ProcessSensingSource::EdgeNetworkObservation,
        ProcessSensingSource::EdgeDataTransferObservation,
        ProcessSensingSource::ProtocolWireObservation,
    ];

    #[test]
    fn no_protocol_interaction_establishes_a_process_change() {
        for p in IndustrialProtocol::ALL {
            for positive in [true, false] {
                for authenticated in [true, false] {
                    let i = ProtocolInteraction {
                        protocol: p,
                        positive_response: positive,
                        authenticated,
                        socket_observed: true,
                        bytes_observed: true,
                        wire_observed: true,
                    };
                    assert!(
                        !i.establishes_process_change(),
                        "{p:?} positive={positive} auth={authenticated}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_ceiling_is_a_function_of_observation_and_not_of_protocol() {
        // The rule the module exists for: an authenticated OPC UA exchange and
        // a bare Modbus write observed the same way are worth the same.
        let opc = OpcUaAdapter.interaction(true, true, &OBSERVED_FULLY);
        let modbus = ModbusTcpAdapter.interaction(true, true, &OBSERVED_FULLY);
        assert_eq!(opc.evidence_ceiling(), modbus.evidence_ceiling());
        assert_eq!(opc.evidence_ceiling(), EvidenceCeiling::Attested);
    }

    #[test]
    fn an_adapter_cannot_claim_authentication_a_protocol_does_not_define() {
        let m = ModbusTcpAdapter.interaction(true, true, &[]);
        assert!(
            !m.authenticated,
            "Modbus defines no message authentication; asking for it must not grant it"
        );
        let o = OpcUaAdapter.interaction(true, true, &[]);
        assert!(o.authenticated);
    }

    #[test]
    fn an_unobserved_exchange_is_corroborative_at_best() {
        for p in IndustrialProtocol::ALL {
            let i = ProtocolInteraction::unobserved(p, true);
            assert_eq!(
                i.evidence_ceiling(),
                EvidenceCeiling::Corroborative,
                "{p:?}"
            );
            assert!(i.observed_by().is_empty());
            assert!(i.statement().contains("nothing an anchored observer saw"));
        }
    }

    #[test]
    fn only_a_negotiated_cryptographic_session_distinguishes_a_replay() {
        assert!(OpcUaAdapter
            .interaction(true, true, &OBSERVED_FULLY)
            .replay_distinguishable());
        // The same protocol without a negotiated session: not distinguishable.
        assert!(!OpcUaAdapter
            .interaction(true, false, &OBSERVED_FULLY)
            .replay_distinguishable());
        // A sequence counter is not a replay defence.
        assert!(!Dnp3Adapter
            .interaction(true, true, &OBSERVED_FULLY)
            .replay_distinguishable());
        assert!(!ModbusTcpAdapter
            .interaction(true, true, &OBSERVED_FULLY)
            .replay_distinguishable());
    }

    #[test]
    fn a_serial_protocol_is_observable_nowhere() {
        assert!(!IndustrialProtocol::ModbusSerial.traffic_observable());
        assert!(IndustrialProtocol::ModbusSerial.observable_by().is_empty());
        for p in IndustrialProtocol::ALL
            .iter()
            .filter(|p| p.traffic_observable())
        {
            assert_eq!(p.observable_by().len(), 3, "{p:?}");
        }
    }

    #[test]
    fn every_protocol_states_its_gap_and_its_codes_are_unique() {
        let mut codes: Vec<u8> = IndustrialProtocol::ALL.iter().map(|p| p.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), IndustrialProtocol::ALL.len());
        for p in IndustrialProtocol::ALL {
            assert!(!p.effect_gap().is_empty(), "{p:?}");
            assert!(!p.forgeable_by().is_empty(), "{p:?}");
            assert_eq!(
                p.positive_response_establishes(),
                "that a message was accepted by whatever answered at that endpoint",
                "{p:?}: no protocol gets a stronger sentence than any other"
            );
        }
    }

    #[test]
    fn authentication_does_not_move_the_ceiling() {
        for p in IndustrialProtocol::ALL {
            let plain = ProtocolInteraction {
                protocol: p,
                positive_response: true,
                authenticated: false,
                socket_observed: true,
                bytes_observed: false,
                wire_observed: false,
            };
            let signed = ProtocolInteraction {
                authenticated: true,
                ..plain
            };
            assert_eq!(plain.evidence_ceiling(), signed.evidence_ceiling(), "{p:?}");
            assert_eq!(
                plain.establishes_process_change(),
                signed.establishes_process_change(),
                "{p:?}"
            );
        }
    }

    #[test]
    fn a_wire_only_observation_does_not_reach_attested() {
        let i = ModbusTcpAdapter.interaction(
            true,
            false,
            &[ProcessSensingSource::ProtocolWireObservation],
        );
        assert_eq!(i.evidence_ceiling(), EvidenceCeiling::Corroborative);
    }
}
