//! Where an industrial deployment's reports come from, and what each is worth.
//!
//! # The question, unchanged across three verticals
//!
//! Not "is this instrument calibrated?" — calibration is a certificate and this
//! layer has no way to check one. The question is: **is the party producing
//! this report inside the thing being judged?**
//!
//! A pressure transmitter wired to a PLC is the control system reporting. A
//! process historian is the control system's own archive of what it reported.
//! An HMI alarm log is the control system's account of what it displayed. All
//! three are excellent engineering and none is independent evidence, because a
//! compromised supervisory host, a compromised controller, or an attacker on
//! the process network writes all of them.
//!
//! # The industrial case has more mechanised sources than the robotics one
//!
//! Six rather than two, and the difference is real rather than generous. A
//! critical-edge node is a Linux host that talks a routable protocol over a
//! network device, and five of the nine implemented Linux mechanisms therefore
//! observe something about it. What they observe is the *compute and network
//! half* of a command's journey — a process, a socket, a byte count, a frame
//! header, a written configuration file. None of them observes a plant.
//!
//! The extra reach makes the boundary sharper, not softer: this profile can
//! establish that a specific process on a specific host-boot opened a socket to
//! a controller's endpoint and handed the kernel bytes for it. It still cannot
//! establish that a valve moved, and the distance between those two sentences
//! is the whole subject.

use aip_observation::{EvidenceCeiling, ObservationClass};
use aip_observe::SourceMechanism;
use serde::{Deserialize, Serialize};

/// A source of reports about an industrial process or the edge node driving it.
///
/// Closed on purpose, like `ObservationClass` and `SourceMechanism`. An open
/// vocabulary could not carry a trust basis, and two deployments would spell
/// the same source differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProcessSensingSource {
    /// The supervisory or optimisation software's account of its own decisions.
    SupervisoryRuntimeReport,
    /// A controller's status: PLC, RTU or DCS, reported over the process
    /// protocol it speaks.
    ControllerStatusReport,
    /// A process transmitter wired into the control system: flow, pressure,
    /// level, temperature.
    ProcessTransmitter,
    /// Position or state feedback from an actuator: a valve limit switch, a
    /// motor contactor auxiliary, a breaker status contact.
    ActuatorPositionFeedback,
    /// The process historian's stored trend.
    HistorianArchive,
    /// The HMI's operator and alarm log.
    HmiOperatorLog,
    /// The safety instrumented system's own status report.
    SafetySystemStatus,
    /// A metering device: custody transfer, energy, emissions.
    MeteringDevice,
    /// An instrument on a loop physically separate from the control system.
    IndependentPlantSensor,
    /// A human walking the plant and writing down what they saw.
    FieldInspection,
    /// A regulator's or third party's own telemetry feed.
    RegulatoryTelemetry,
    /// An anchored observer measuring the edge node's **process identity**:
    /// which supervisory binary ran, as which instance, on which boot.
    EdgeProcessObservation,
    /// An anchored observer measuring the edge node's **process lifecycle**:
    /// that an instance forked, exec'd or exited, from a kernel-pushed event.
    EdgeLifecycleObservation,
    /// An anchored observer measuring the edge node's **sockets**: that a
    /// connection to a controller's endpoint existed at a sampled moment.
    EdgeNetworkObservation,
    /// An anchored observer measuring **bytes the kernel accepted** for such a
    /// socket. A count, never a payload.
    EdgeDataTransferObservation,
    /// An anchored observer tapping the **wire**: that a frame crossed a
    /// network device. Headers only, and bound to no process.
    ProtocolWireObservation,
    /// An anchored observer watching **configuration writes** on the edge node:
    /// a controller program, a point table, a protocol map, modified on disk.
    EdgeConfigWriteObservation,
}

impl ProcessSensingSource {
    pub const ALL: [ProcessSensingSource; 17] = [
        Self::SupervisoryRuntimeReport,
        Self::ControllerStatusReport,
        Self::ProcessTransmitter,
        Self::ActuatorPositionFeedback,
        Self::HistorianArchive,
        Self::HmiOperatorLog,
        Self::SafetySystemStatus,
        Self::MeteringDevice,
        Self::IndependentPlantSensor,
        Self::FieldInspection,
        Self::RegulatoryTelemetry,
        Self::EdgeProcessObservation,
        Self::EdgeLifecycleObservation,
        Self::EdgeNetworkObservation,
        Self::EdgeDataTransferObservation,
        Self::ProtocolWireObservation,
        Self::EdgeConfigWriteObservation,
    ];

    /// Stable wire code, assigned explicitly so reordering cannot change what
    /// previously encoded bytes mean.
    pub fn code(self) -> u8 {
        match self {
            Self::SupervisoryRuntimeReport => 0x01,
            Self::ControllerStatusReport => 0x02,
            Self::ProcessTransmitter => 0x03,
            Self::ActuatorPositionFeedback => 0x04,
            Self::HistorianArchive => 0x05,
            Self::HmiOperatorLog => 0x06,
            Self::SafetySystemStatus => 0x07,
            Self::MeteringDevice => 0x08,
            Self::IndependentPlantSensor => 0x09,
            Self::FieldInspection => 0x0A,
            Self::RegulatoryTelemetry => 0x0B,
            Self::EdgeProcessObservation => 0x0C,
            Self::EdgeLifecycleObservation => 0x0D,
            Self::EdgeNetworkObservation => 0x0E,
            Self::EdgeDataTransferObservation => 0x0F,
            Self::ProtocolWireObservation => 0x10,
            Self::EdgeConfigWriteObservation => 0x11,
        }
    }

    /// Whether the source sits **inside** the control system being judged.
    ///
    /// Eight of seventeen. The historian and the HMI log are inside for the
    /// reason people find least intuitive: they are archives *of what the
    /// control system said*, written by the control system, so a control system
    /// that reports a pressure it did not measure produces a historian trend of
    /// a pressure it did not measure. An archive inherits the trustworthiness
    /// of its writer and adds none of its own.
    ///
    /// The safety system is inside too. It is a separate logic solver, and it
    /// is separate in the sense that matters for *process safety* — a different
    /// box, a different program, a different certification. It is not separate
    /// in the sense that matters here: it is engineered, configured and
    /// reported through the same station, on the same networks, by the same
    /// integrator, and its status arrives over a bus the subject owns.
    pub fn is_inside_control_system(self) -> bool {
        matches!(
            self,
            Self::SupervisoryRuntimeReport
                | Self::ControllerStatusReport
                | Self::ProcessTransmitter
                | Self::ActuatorPositionFeedback
                | Self::HistorianArchive
                | Self::HmiOperatorLog
                | Self::SafetySystemStatus
                | Self::MeteringDevice
        )
    }

    /// Whether this source is outside the subject.
    ///
    /// Positional independence only. It does not mean the report is verified:
    /// an independent source still has to be anchored, and being named is not
    /// being trusted.
    pub fn is_independent(self) -> bool {
        !self.is_inside_control_system()
    }

    /// The Linux mechanism backing this source, when one exists.
    ///
    /// `Some` for six sources, all of them measurements of the **edge node**.
    /// Adding a variant to `SourceMechanism` for a transmitter or a metering
    /// device would put a device-specific value into signed bytes every
    /// verifier must understand — the schema fork ADR-003 exists to prevent,
    /// and the reason ADR-005 and ADR-006 refused the same move for avionics
    /// and for encoders.
    pub fn mechanism(self) -> Option<SourceMechanism> {
        match self {
            Self::EdgeProcessObservation => Some(SourceMechanism::PidFdAnchored),
            Self::EdgeLifecycleObservation => Some(SourceMechanism::ProcConnector),
            Self::EdgeNetworkObservation => Some(SourceMechanism::ProcNetTable),
            Self::EdgeDataTransferObservation => Some(SourceMechanism::SockSendTracepoint),
            Self::ProtocolWireObservation => Some(SourceMechanism::WireTapAfPacket),
            Self::EdgeConfigWriteObservation => Some(SourceMechanism::Fanotify),
            _ => None,
        }
    }

    /// Whether an observation record can be built from this source at all.
    pub fn can_produce_observation_record(self) -> bool {
        self.mechanism().is_some()
    }

    /// The observation class this source would belong to, when a mechanism
    /// exists to produce it. `None` wherever `mechanism()` is `None`: a class
    /// without a mechanism is a claim.
    pub fn observation_class(self) -> Option<ObservationClass> {
        self.mechanism().map(aip_observation::class_of)
    }

    /// Whether this source's mechanism survives an on-host adversary silently
    /// suppressing a perf tracepoint.
    ///
    /// The observation-integrity finding, carried into the profile: a source
    /// whose mechanism shares the per-tracepoint eBPF submission gate can be
    /// blinded host-wide with no dropped-record accounting, so its silence
    /// carries no information. `false` for every source with no mechanism,
    /// because a source that cannot observe cannot observe independently of a
    /// gate either.
    pub fn is_gate_independent(self) -> bool {
        self.mechanism()
            .is_some_and(|m| m.is_gate_independent_kernel_pushed())
    }

    pub fn observes(self) -> &'static str {
        match self {
            Self::SupervisoryRuntimeReport => {
                "the supervisory software's account of its own decisions and commands"
            }
            Self::ControllerStatusReport => "a controller's reported mode, health and point values",
            Self::ProcessTransmitter => "a transduced quantity at one tapping point",
            Self::ActuatorPositionFeedback => "a switch, contact or resolver at the actuator",
            Self::HistorianArchive => "what the control system previously reported, stored",
            Self::HmiOperatorLog => "what the HMI displayed and what was typed into it",
            Self::SafetySystemStatus => "the safety logic solver's account of its own state",
            Self::MeteringDevice => "an accumulated or instantaneous metered quantity",
            Self::IndependentPlantSensor => {
                "a quantity measured on an instrument loop separate from the control system"
            }
            Self::FieldInspection => "what a person saw and recorded",
            Self::RegulatoryTelemetry => "a quantity a third party collected and forwarded",
            Self::EdgeProcessObservation => {
                "a process instance on the edge node and its executable content"
            }
            Self::EdgeLifecycleObservation => {
                "a kernel-pushed fork, exec or exit event on the edge node"
            }
            Self::EdgeNetworkObservation => {
                "a socket owned by that instance, and the endpoint it reached at a sample"
            }
            Self::EdgeDataTransferObservation => {
                "a count of bytes the kernel accepted for one socket"
            }
            Self::ProtocolWireObservation => "a frame crossing a network device; headers only",
            Self::EdgeConfigWriteObservation => {
                "that a marked configuration path on the edge node was modified or closed for write"
            }
        }
    }

    pub fn establishes(self) -> &'static str {
        match self {
            Self::SupervisoryRuntimeReport | Self::ControllerStatusReport => {
                "that the subject said so, and — if signed — that it is the subject that said it"
            }
            Self::ProcessTransmitter
            | Self::ActuatorPositionFeedback
            | Self::HistorianArchive
            | Self::HmiOperatorLog
            | Self::SafetySystemStatus
            | Self::MeteringDevice => {
                "what a device or archive inside the control system reported; the subject's own \
                 account of itself and of the plant it is operating"
            }
            Self::IndependentPlantSensor | Self::FieldInspection | Self::RegulatoryTelemetry => {
                "that a party outside the control system reported something, if the deployment \
                 anchored it — which this build has no mechanism to do"
            }
            Self::EdgeProcessObservation => {
                "that one process instance, running measured executable content, existed on a \
                 measured host-boot"
            }
            Self::EdgeLifecycleObservation => {
                "that the kernel emitted a lifecycle event, in its own order and its own time"
            }
            Self::EdgeNetworkObservation => {
                "that the instance held a socket to a named endpoint at the moment of the sample"
            }
            Self::EdgeDataTransferObservation => {
                "that the kernel accepted a number of bytes for that socket"
            }
            Self::ProtocolWireObservation => "that a frame with those headers crossed the device",
            Self::EdgeConfigWriteObservation => {
                "that the marked path was written; not what was written into it"
            }
        }
    }

    pub fn does_not_establish(self) -> &'static str {
        match self {
            Self::SupervisoryRuntimeReport => "that anything it describes occurred",
            Self::ControllerStatusReport => {
                "that an output was energised, that an actuator moved, or that the process changed"
            }
            Self::ProcessTransmitter => {
                "the quantity in the process: a transmitter reads at one tapping, through one \
                 impulse line, and a blocked line reads a steady, plausible, wrong value"
            }
            Self::ActuatorPositionFeedback => {
                "that the process path opened: a limit switch says the stem travelled, not that \
                 the plug left the seat or that anything flowed"
            }
            Self::HistorianArchive => {
                "that the archived values were ever true; an archive of a forged report is a \
                 forged archive"
            }
            Self::HmiOperatorLog => "that the display matched the plant, or who was at the console",
            Self::SafetySystemStatus => {
                "that a safety function would act, or did act; a healthy self-report is what a \
                 bypassed function also produces"
            }
            Self::MeteringDevice => "that the metered stream is the stream anyone means",
            Self::IndependentPlantSensor => {
                "anything, absent an anchor: an unanchored independent reading is a claim from a \
                 party the verifier cannot name"
            }
            Self::FieldInspection => "what happened when nobody was looking",
            Self::RegulatoryTelemetry => {
                "more than its own collection chain, which this build does not model"
            }
            Self::EdgeProcessObservation => {
                "what the process did, any command it issued, or any effect on a plant"
            }
            Self::EdgeLifecycleObservation => "what ran between the events",
            Self::EdgeNetworkObservation => {
                "what the bytes were, that they arrived, or that a controller acted on them"
            }
            Self::EdgeDataTransferObservation => {
                "what the bytes were, that they left the host, or that they arrived"
            }
            Self::ProtocolWireObservation => {
                "which process sent the frame, its payload, or any effect at the far end"
            }
            Self::EdgeConfigWriteObservation => {
                "the file's contents, or that a controller ever loaded them"
            }
        }
    }

    pub fn trust_basis(self) -> &'static str {
        match self {
            s if s.is_inside_control_system() => {
                "the control system itself, and everything with access to its process networks \
                 and engineering stations: the party under scrutiny"
            }
            Self::IndependentPlantSensor | Self::FieldInspection | Self::RegulatoryTelemetry => {
                "an operator- or regulator-anchored external party; the verifier's trust model, \
                 not an improvement on it — and unanchored in this build"
            }
            Self::EdgeProcessObservation
            | Self::EdgeLifecycleObservation
            | Self::EdgeNetworkObservation
            | Self::EdgeDataTransferObservation
            | Self::ProtocolWireObservation
            | Self::EdgeConfigWriteObservation => {
                "the edge node's kernel for the measurement, and an off-host anchored collector \
                 for the attestation; host root forges the content"
            }
            // Unreachable: the first arm covers every inside variant. Written
            // as a match rather than a fallback string so a new source has to
            // be classified.
            _ => "unclassified",
        }
    }

    pub fn failure_mode(self) -> &'static str {
        match self {
            Self::SupervisoryRuntimeReport | Self::ControllerStatusReport => {
                "silence, or a fluent and correctly signed account of work that is not happening"
            }
            Self::ProcessTransmitter => {
                "a blocked impulse line, a frozen transmitter, or a value held at its last good \
                 reading — all of which look like a stable process"
            }
            Self::ActuatorPositionFeedback => {
                "a limit switch bypassed at the terminal strip, or a stem that moved with a \
                 sheared pin"
            }
            Self::HistorianArchive => "back-filled or interpolated points presented as measured",
            Self::HmiOperatorLog => "a log written by the process whose behaviour is in question",
            Self::SafetySystemStatus => {
                "a maintenance bypass left in, reported as healthy because the logic solver is \
                 healthy"
            }
            Self::MeteringDevice => "drift between proving runs, and a meter in the wrong stream",
            Self::IndependentPlantSensor => "an independent loop wired back through the same PLC",
            Self::FieldInspection => "a walk-down recorded from the last one",
            Self::RegulatoryTelemetry => "latency, and a chain of custody nobody modelled",
            Self::EdgeProcessObservation => {
                "the instance ends between reads and the measurement is discarded rather than \
                 weakened"
            }
            Self::EdgeLifecycleObservation => "a queue overrun, reported as a continuity break",
            Self::EdgeNetworkObservation => {
                "a socket opened and closed between samples is simply absent"
            }
            Self::EdgeDataTransferObservation => {
                "a foreign program on the tracepoint suppresses submission host-wide with no \
                 loss accounting, and the silence looks like an idle link"
            }
            Self::ProtocolWireObservation => {
                "a tap on the wrong segment, and traffic that never crosses the tapped device"
            }
            Self::EdgeConfigWriteObservation => {
                "a mark on the wrong path, and a controller programmed over the network without \
                 touching the disk at all"
            }
        }
    }

    /// The strongest evidence this source could ever contribute.
    ///
    /// Computed, not tabulated: a mechanised source is capped by its class's
    /// own ceiling, and an unmechanised one at `Corroborative` whether it is
    /// inside the control system or outside it. Independence without an
    /// implemented mechanism is nobody observing, which is the rule ADR-005
    /// stated and ADR-006 restated.
    ///
    /// Nothing reaches `Proven`: that ceiling is for facts a third party
    /// recomputes from bytes it holds, and no instrument reading is
    /// recomputable — only re-checkable for who signed it.
    pub fn ceiling(self) -> EvidenceCeiling {
        match self.observation_class() {
            Some(class) => class.ceiling(),
            None => EvidenceCeiling::Corroborative,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_six_sources_can_produce_an_observation_record() {
        let backed: Vec<ProcessSensingSource> = ProcessSensingSource::ALL
            .iter()
            .copied()
            .filter(|s| s.can_produce_observation_record())
            .collect();
        assert_eq!(
            backed,
            vec![
                ProcessSensingSource::EdgeProcessObservation,
                ProcessSensingSource::EdgeLifecycleObservation,
                ProcessSensingSource::EdgeNetworkObservation,
                ProcessSensingSource::EdgeDataTransferObservation,
                ProcessSensingSource::ProtocolWireObservation,
                ProcessSensingSource::EdgeConfigWriteObservation,
            ]
        );
    }

    #[test]
    fn no_plant_instrument_has_a_mechanism() {
        for s in [
            ProcessSensingSource::ProcessTransmitter,
            ProcessSensingSource::ActuatorPositionFeedback,
            ProcessSensingSource::SafetySystemStatus,
            ProcessSensingSource::MeteringDevice,
            ProcessSensingSource::HistorianArchive,
            ProcessSensingSource::IndependentPlantSensor,
            ProcessSensingSource::ControllerStatusReport,
        ] {
            assert!(s.mechanism().is_none(), "{s:?}");
            assert!(s.observation_class().is_none(), "{s:?}");
            assert!(!s.can_produce_observation_record(), "{s:?}");
        }
    }

    #[test]
    fn the_safety_system_is_inside_the_control_system() {
        // The one people argue about. A separate logic solver is separate for
        // process safety and not for accountability: same station, same
        // networks, same integrator.
        assert!(ProcessSensingSource::SafetySystemStatus.is_inside_control_system());
        assert!(ProcessSensingSource::HistorianArchive.is_inside_control_system());
        assert!(ProcessSensingSource::IndependentPlantSensor.is_independent());
    }

    #[test]
    fn no_source_reaches_proven() {
        for s in ProcessSensingSource::ALL {
            assert_ne!(s.ceiling(), EvidenceCeiling::Proven, "{s:?}");
        }
    }

    #[test]
    fn every_unmechanised_source_is_capped_at_corroborative() {
        for s in ProcessSensingSource::ALL
            .iter()
            .copied()
            .filter(|s| !s.can_produce_observation_record())
        {
            assert_eq!(s.ceiling(), EvidenceCeiling::Corroborative, "{s:?}");
        }
    }

    #[test]
    fn an_independent_source_with_no_mechanism_is_also_capped() {
        for s in [
            ProcessSensingSource::IndependentPlantSensor,
            ProcessSensingSource::FieldInspection,
            ProcessSensingSource::RegulatoryTelemetry,
        ] {
            assert!(s.is_independent(), "{s:?}");
            assert_eq!(
                s.ceiling(),
                EvidenceCeiling::Corroborative,
                "{s:?}: independence without an implemented mechanism is nobody observing"
            );
        }
    }

    #[test]
    fn the_wire_tap_is_capped_below_the_other_mechanised_sources() {
        // A frame is bound to no process, so it can corroborate and can never
        // carry a positive finding alone.
        assert_eq!(
            ProcessSensingSource::ProtocolWireObservation.ceiling(),
            EvidenceCeiling::Corroborative
        );
        for s in [
            ProcessSensingSource::EdgeProcessObservation,
            ProcessSensingSource::EdgeNetworkObservation,
            ProcessSensingSource::EdgeDataTransferObservation,
            ProcessSensingSource::EdgeConfigWriteObservation,
            ProcessSensingSource::EdgeLifecycleObservation,
        ] {
            assert_eq!(s.ceiling(), EvidenceCeiling::Attested, "{s:?}");
        }
    }

    #[test]
    fn no_source_claims_the_physical_effect_class() {
        for s in ProcessSensingSource::ALL {
            assert_ne!(
                s.observation_class(),
                Some(ObservationClass::PhysicalEffect),
                "{s:?}"
            );
        }
    }

    #[test]
    fn exactly_three_sources_are_gate_independent() {
        // The observation-integrity boundary, per source. The data-transfer
        // observation shares the perf tracepoint gate and is therefore not
        // gate-independent, however healthy the observer looks.
        let independent: Vec<ProcessSensingSource> = ProcessSensingSource::ALL
            .iter()
            .copied()
            .filter(|s| s.is_gate_independent())
            .collect();
        assert_eq!(
            independent,
            vec![
                ProcessSensingSource::EdgeLifecycleObservation,
                ProcessSensingSource::ProtocolWireObservation,
                ProcessSensingSource::EdgeConfigWriteObservation,
            ]
        );
        assert!(!ProcessSensingSource::EdgeDataTransferObservation.is_gate_independent());
        assert!(!ProcessSensingSource::EdgeProcessObservation.is_gate_independent());
    }

    #[test]
    fn wire_codes_are_unique_and_pinned() {
        let mut codes: Vec<u8> = ProcessSensingSource::ALL.iter().map(|s| s.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), ProcessSensingSource::ALL.len());
        assert_eq!(ProcessSensingSource::SupervisoryRuntimeReport.code(), 0x01);
        assert_eq!(
            ProcessSensingSource::EdgeConfigWriteObservation.code(),
            0x11
        );
    }

    #[test]
    fn every_source_answers_all_six_questions() {
        for s in ProcessSensingSource::ALL {
            for text in [
                s.observes(),
                s.establishes(),
                s.does_not_establish(),
                s.trust_basis(),
                s.failure_mode(),
            ] {
                assert!(!text.is_empty(), "{s:?} left a column blank");
            }
            assert_ne!(
                s.trust_basis(),
                "unclassified",
                "{s:?} fell through the trust-basis match"
            );
        }
    }
}
