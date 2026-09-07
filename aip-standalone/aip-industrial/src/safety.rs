//! Safety boundaries: what a deployment **declared** was in force.
//!
//! # This is a commitment, not an observation, and not an enforcement engine
//!
//! Nothing here stops a process. `aip-warrant` and `aip-containment` remain the
//! only enforcement path in the workspace, and this module produces no warrant,
//! no severity and no action.
//!
//! What it produces is a **document**: which safety functions a deployment says
//! are in force, which limits it says apply, which commands the boundary
//! permits, and whether a bypass was declared. That document's digest goes into
//! action parameters, and a decision point signs it exactly as it signs a
//! robotics task plan or a UAS mission plan. No new authorization engine, no new
//! signer, no new trust anchor.
//!
//! # Why the spec insists these are distinct from process effects
//!
//! Because conflating them is how safety cases are written. "The interlock was
//! in force" and "the interlock acted" are different sentences: the first is a
//! statement about configuration, which a deployment can commit to and a
//! verifier can check the commitment of; the second is a statement about a
//! plant, which nothing in this build can establish.
//!
//! [`SafetyBoundary`] carries the first. [`crate::process::PhysicalProcessEffect`]
//! carries the second. They have different structure discriminants, different
//! parameter keys, and there is deliberately no method turning one into the
//! other. [`SafetyBoundary::enforcement_establishable`] is `false`, computed,
//! so a reader who wants the second sentence is told where it is not.
//!
//! # A bypass is declared, never inferred
//!
//! A deployment that has bypassed an interlock says so in the document, and the
//! digest changes. A deployment that has bypassed one and does not say so
//! produces a document that does not match what is in force, and nothing here
//! can tell — which is the honest position, because the bypass is a jumper in a
//! cabinet and no Linux mechanism observes cabinets.

use aip_crypto::sha256;
use aip_types::canonical::{put_domain, put_str, put_u16, put_u32, put_u64, put_u8};
use serde::{Deserialize, Serialize};

use crate::command::IndustrialCommand;
use crate::controlloop::ControlRung;
use crate::error::IndustrialError;
use crate::process::ProcessVariable;
use crate::sensing::ProcessSensingSource;
use crate::state::ProcessEvidence;
use crate::{INDUSTRIAL_PROFILE_DOMAIN, INDUSTRIAL_PROFILE_VERSION};

/// The reserved action-parameter key carrying the safety-boundary commitment.
///
/// Distinct from [`crate::controlloop::CONTROL_LOOP_PARAMETER_KEY`], so a
/// decision point that signed a control loop has not thereby signed a safety
/// boundary, and vice versa.
pub const SAFETY_BOUNDARY_PARAMETER_KEY: &str = "aip.industrial.safety_boundary.v1";

/// A protective function a plant relies on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SafetyFunction {
    /// A safety instrumented function: sensor, logic solver, final element.
    SafetyInstrumentedFunction,
    /// A permissive or interlock chain in the basic control system.
    InterlockChain,
    /// An emergency shutdown system.
    EmergencyShutdownSystem,
    /// A mechanical pressure relief device.
    PressureRelief,
    /// An overspeed or overcurrent trip.
    OverspeedTrip,
    /// Gas, flame or fire detection.
    HazardDetection,
    /// A fire or gas suppression release.
    Suppression,
    /// A hard-wired manual trip station.
    ManualTripStation,
}

impl SafetyFunction {
    pub const ALL: [SafetyFunction; 8] = [
        Self::SafetyInstrumentedFunction,
        Self::InterlockChain,
        Self::EmergencyShutdownSystem,
        Self::PressureRelief,
        Self::OverspeedTrip,
        Self::HazardDetection,
        Self::Suppression,
        Self::ManualTripStation,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::SafetyInstrumentedFunction => 0x01,
            Self::InterlockChain => 0x02,
            Self::EmergencyShutdownSystem => 0x03,
            Self::PressureRelief => 0x04,
            Self::OverspeedTrip => 0x05,
            Self::HazardDetection => 0x06,
            Self::Suppression => 0x07,
            Self::ManualTripStation => 0x08,
        }
    }

    /// Whether any part of this function is reachable from a network the edge
    /// node speaks on.
    ///
    /// Two are not: a relief valve and a hard-wired trip station are mechanical
    /// and electrical, and no protocol addresses them. Recorded because
    /// "unreachable from the network" is the strongest safety property in this
    /// table and it belongs in the document rather than in a slide.
    pub fn network_addressable(self) -> bool {
        !matches!(self, Self::PressureRelief | Self::ManualTripStation)
    }

    /// Whether a deployment can bypass this function from the control system.
    pub fn bypassable_from_control_system(self) -> bool {
        matches!(
            self,
            Self::SafetyInstrumentedFunction
                | Self::InterlockChain
                | Self::EmergencyShutdownSystem
                | Self::OverspeedTrip
                | Self::HazardDetection
                | Self::Suppression
        )
    }

    /// What a healthy self-report from this function establishes.
    pub fn healthy_report_establishes(self) -> &'static str {
        match self {
            Self::SafetyInstrumentedFunction => {
                "that the logic solver believes its own diagnostics passed; not that the final \
                 element will move"
            }
            Self::InterlockChain => {
                "that the evaluated expression was true when it was read; not that the rung is \
                 unforced"
            }
            Self::EmergencyShutdownSystem => {
                "that the system is powered and scanning; not that a sequence would complete"
            }
            Self::PressureRelief => {
                "nothing: a relief valve has no report, and its condition is established by \
                 overhaul, not by telemetry"
            }
            Self::OverspeedTrip => "that the trip is armed; not that it is set to the right value",
            Self::HazardDetection => {
                "that a detector is powered; not that it is in the path of a release"
            }
            Self::Suppression => "that a release circuit reads continuity; not that agent remains",
            Self::ManualTripStation => {
                "nothing: a hard-wired station reports to a relay, not to a network"
            }
        }
    }
}

/// Which side of a limit a value must stay on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LimitBound {
    /// The value must stay at or below the limit.
    Upper,
    /// The value must stay at or above it.
    Lower,
}

impl LimitBound {
    pub fn code(self) -> u8 {
        match self {
            Self::Upper => 0x01,
            Self::Lower => 0x02,
        }
    }
}

/// One declared limit on one process variable.
///
/// The value is an integer in thousandths of the named unit. Fixed point rather
/// than floating point, because a limit is a security-relevant field that has to
/// encode injectively, and two `f64` bit patterns can compare equal while
/// encoding differently — and the reverse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessLimit {
    pub variable: ProcessVariable,
    pub bound: LimitBound,
    /// The limit, in thousandths of `unit`.
    pub milli_value: i64,
    unit: String,
}

impl ProcessLimit {
    pub fn new(
        variable: ProcessVariable,
        bound: LimitBound,
        milli_value: i64,
        unit: &str,
    ) -> Result<Self, IndustrialError> {
        if unit.is_empty() || unit.len() > 32 {
            return Err(IndustrialError::Malformed {
                reason: "a limit unit must be 1-32 bytes",
            });
        }
        Ok(Self {
            variable,
            bound,
            milli_value,
            unit: unit.to_owned(),
        })
    }

    pub fn unit(&self) -> &str {
        &self.unit
    }

    /// Whether a reported value sits inside the limit.
    ///
    /// A pure comparison over a number someone supplied. It says nothing about
    /// the plant: the input is a report from the control system, and this
    /// method does not know or care where it came from. Named `satisfied_by`
    /// rather than `is_safe` for exactly that reason.
    pub fn satisfied_by(&self, reported_milli: i64) -> bool {
        match self.bound {
            LimitBound::Upper => reported_milli <= self.milli_value,
            LimitBound::Lower => reported_milli >= self.milli_value,
        }
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        put_u8(buf, self.variable.code());
        put_u8(buf, self.bound.code());
        // Two's-complement bit cast into the existing u64 encoder. The map
        // i64 -> u64 is a bijection on bit patterns, so the encoding stays
        // injective, and no signed encoder has to be added to `aip-types` —
        // which would be a change to the shared canonical vocabulary for the
        // convenience of one profile.
        put_u64(buf, self.milli_value as u64);
        put_str(buf, &self.unit);
    }
}

/// What a deployment declares is in force around a command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyBoundary {
    pub version: u16,
    boundary_id: String,
    /// The boundary's revision. Two revisions are two documents.
    pub revision: u32,
    system_id: aip_system::SystemId,
    /// The protective functions declared in force. Sorted and deduplicated.
    functions: Vec<SafetyFunction>,
    /// The limits declared to apply. Order-normalised by the constructor.
    limits: Vec<ProcessLimit>,
    /// The commands this boundary permits. Sorted and deduplicated.
    permitted: Vec<IndustrialCommand>,
    /// Whether a bypass was declared in force at the time of the commitment.
    ///
    /// Part of the signed document, so a deployment cannot later claim the
    /// boundary was intact. Declared, never detected.
    pub bypass_declared: bool,
}

impl SafetyBoundary {
    pub fn new(
        boundary_id: &str,
        revision: u32,
        system_id: aip_system::SystemId,
        functions: &[SafetyFunction],
        limits: &[ProcessLimit],
        permitted: &[IndustrialCommand],
    ) -> Result<Self, IndustrialError> {
        if boundary_id.is_empty() || boundary_id.len() > 128 {
            return Err(IndustrialError::Malformed {
                reason: "boundary id must be 1-128 bytes",
            });
        }
        if functions.is_empty() {
            return Err(IndustrialError::Malformed {
                reason: "a safety boundary must declare at least one protective function",
            });
        }
        if permitted.is_empty() {
            return Err(IndustrialError::Malformed {
                reason: "a safety boundary must permit at least one command",
            });
        }
        let mut functions = functions.to_vec();
        functions.sort_unstable();
        functions.dedup();
        let mut permitted = permitted.to_vec();
        permitted.sort_unstable();
        permitted.dedup();
        let mut limits = limits.to_vec();
        // Order-normalised so two deployments declaring the same limits in
        // different orders produce the same digest, and a duplicated limit
        // does not become a different document.
        limits.sort_by(|a, b| {
            (
                a.variable.code(),
                a.bound.code(),
                a.milli_value,
                a.unit.as_str(),
            )
                .cmp(&(
                    b.variable.code(),
                    b.bound.code(),
                    b.milli_value,
                    b.unit.as_str(),
                ))
        });
        limits.dedup();
        Ok(Self {
            version: INDUSTRIAL_PROFILE_VERSION,
            boundary_id: boundary_id.to_owned(),
            revision,
            system_id,
            functions,
            limits,
            permitted,
            bypass_declared: false,
        })
    }

    /// Record that a bypass was declared in force. Changes the digest.
    pub fn with_declared_bypass(mut self) -> Self {
        self.bypass_declared = true;
        self
    }

    pub fn boundary_id(&self) -> &str {
        &self.boundary_id
    }
    pub fn system_id(&self) -> &aip_system::SystemId {
        &self.system_id
    }
    pub fn functions(&self) -> &[SafetyFunction] {
        &self.functions
    }
    pub fn limits(&self) -> &[ProcessLimit] {
        &self.limits
    }
    pub fn permitted_commands(&self) -> &[IndustrialCommand] {
        &self.permitted
    }

    /// Whether the boundary permits `command`.
    ///
    /// A set membership test: nothing is inferred, because permitting
    /// `WriteSetpoint` does not permit `BypassInterlock`, and permitting a
    /// bypass does not permit a trip.
    pub fn permits(&self, command: IndustrialCommand) -> bool {
        self.permitted.contains(&command)
    }

    /// Whether this deployment can establish that the boundary was **enforced**.
    ///
    /// `false`, computed from the class table. Enforcement is a fact about
    /// final elements, and this build observes no final element. The method
    /// exists so a reader looking for the sentence "the interlock held" is told
    /// where it is not, rather than reading the commitment as the answer.
    pub fn enforcement_establishable(&self) -> bool {
        aip_observation::ObservationClass::PhysicalEffect.is_implemented()
    }

    /// The evidence tier enforcement would require.
    pub fn enforcement_evidence_required(&self) -> ProcessEvidence {
        ProcessEvidence::PhysicallyObserved
    }

    /// The highest rung of the control chain a claim about this boundary
    /// reaches: the command left the edge node, and no further.
    pub fn highest_rung(&self) -> ControlRung {
        crate::controlloop::ControlLoopChain::current()
            .highest_observable()
            .unwrap_or(ControlRung::SupervisoryDecision)
    }

    pub fn check_version(&self) -> Result<(), IndustrialError> {
        if self.version != INDUSTRIAL_PROFILE_VERSION {
            return Err(IndustrialError::UnsupportedVersion {
                found: self.version,
                supported: INDUSTRIAL_PROFILE_VERSION,
            });
        }
        Ok(())
    }

    /// Domain-tagged, injective canonical bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, INDUSTRIAL_PROFILE_DOMAIN);
        // Structure discriminant inside the shared domain: 0x03 is a safety
        // boundary. A control loop is 0x01 and the profile document is 0x02,
        // so the three can never collide however their fields line up.
        put_u8(&mut buf, 0x03);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, &self.boundary_id);
        put_u32(&mut buf, self.revision);
        put_str(&mut buf, self.system_id.as_str());
        put_u8(&mut buf, u8::from(self.bypass_declared));
        put_u32(&mut buf, self.functions.len() as u32);
        for f in &self.functions {
            put_u8(&mut buf, f.code());
        }
        put_u32(&mut buf, self.limits.len() as u32);
        for l in &self.limits {
            l.encode(&mut buf);
        }
        put_u32(&mut buf, self.permitted.len() as u32);
        for c in &self.permitted {
            put_u8(&mut buf, c.code());
        }
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }

    /// The `(key, value)` pair to add to action parameters so a decision point
    /// commits to this boundary.
    pub fn authorization_parameter(&self) -> (String, Vec<u8>) {
        (
            SAFETY_BOUNDARY_PARAMETER_KEY.to_owned(),
            self.digest().to_vec(),
        )
    }

    /// Whether `parameter_value` commits to this exact boundary.
    pub fn is_committed_by(&self, parameter_value: Option<&[u8]>) -> bool {
        match parameter_value {
            Some(v) => v == self.digest(),
            None => false,
        }
    }
}

/// What is known about one protective function during one window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyEvidence {
    pub function: SafetyFunction,
    /// Whether an anchored observer saw the edge node issue the related
    /// command.
    pub command_observed: bool,
    /// Whether the function's action in the plant was established. Always
    /// false here.
    pub action_observed: bool,
}

impl SafetyEvidence {
    /// Derive from whether the deployment has an anchored edge observer.
    pub fn derive(function: SafetyFunction, edge_observer: bool) -> Self {
        Self {
            function,
            // Only a function something on the network can address produces a
            // command an edge observer could see at all.
            command_observed: edge_observer && function.network_addressable(),
            action_observed: aip_observation::ObservationClass::PhysicalEffect.is_implemented(),
        }
    }

    /// Whether the protective function may be reported as having acted.
    ///
    /// False whenever the action was not observed — which is always. A safety
    /// argument that needs this to be true needs a mechanism this build does
    /// not have.
    pub fn establishes_action(&self) -> bool {
        self.action_observed
    }

    /// What could have observed the command half.
    pub fn observable_by(&self) -> &'static [ProcessSensingSource] {
        if self.function.network_addressable() {
            &[
                ProcessSensingSource::EdgeNetworkObservation,
                ProcessSensingSource::EdgeDataTransferObservation,
            ]
        } else {
            &[]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sys() -> aip_system::SystemId {
        aip_system::SystemId::parse("ics:unit-4-supervisor").unwrap()
    }

    fn boundary() -> SafetyBoundary {
        SafetyBoundary::new(
            "unit-4-esd",
            1,
            sys(),
            &[
                SafetyFunction::SafetyInstrumentedFunction,
                SafetyFunction::InterlockChain,
            ],
            &[
                ProcessLimit::new(ProcessVariable::Pressure, LimitBound::Upper, 4_200, "bar")
                    .unwrap(),
            ],
            &[IndustrialCommand::WriteSetpoint],
        )
        .unwrap()
    }

    #[test]
    fn a_boundary_commitment_never_establishes_enforcement() {
        let b = boundary();
        assert!(!b.enforcement_establishable());
        assert_eq!(
            b.enforcement_evidence_required(),
            ProcessEvidence::PhysicallyObserved
        );
        assert!(!b.enforcement_evidence_required().is_reachable());
        assert_eq!(b.highest_rung(), ControlRung::CommandIssued);
    }

    #[test]
    fn the_boundary_commitment_and_the_control_loop_commitment_are_different_keys() {
        assert_ne!(
            SAFETY_BOUNDARY_PARAMETER_KEY,
            crate::controlloop::CONTROL_LOOP_PARAMETER_KEY,
            "a signature over one must not be readable as a signature over the other"
        );
    }

    #[test]
    fn permitting_a_setpoint_does_not_permit_a_bypass() {
        let b = boundary();
        assert!(b.permits(IndustrialCommand::WriteSetpoint));
        assert!(!b.permits(IndustrialCommand::BypassInterlock));
        assert!(!b.permits(IndustrialCommand::EmergencyShutdown));
    }

    #[test]
    fn a_declared_bypass_changes_the_document() {
        let plain = boundary();
        let bypassed = plain.clone().with_declared_bypass();
        assert_ne!(plain.digest(), bypassed.digest());
        assert!(!plain.bypass_declared);
        assert!(bypassed.bypass_declared);
        // And changes nothing about what can be established.
        assert_eq!(
            plain.enforcement_establishable(),
            bypassed.enforcement_establishable()
        );
    }

    #[test]
    fn the_commitment_is_order_independent_and_content_sensitive() {
        let a = SafetyBoundary::new(
            "b",
            1,
            sys(),
            &[
                SafetyFunction::InterlockChain,
                SafetyFunction::SafetyInstrumentedFunction,
            ],
            &[],
            &[
                IndustrialCommand::CloseValve,
                IndustrialCommand::WriteSetpoint,
            ],
        )
        .unwrap();
        let b = SafetyBoundary::new(
            "b",
            1,
            sys(),
            &[
                SafetyFunction::SafetyInstrumentedFunction,
                SafetyFunction::InterlockChain,
            ],
            &[],
            &[
                IndustrialCommand::WriteSetpoint,
                IndustrialCommand::CloseValve,
            ],
        )
        .unwrap();
        assert_eq!(a.digest(), b.digest());
        let narrower = SafetyBoundary::new(
            "b",
            1,
            sys(),
            &[SafetyFunction::InterlockChain],
            &[],
            &[IndustrialCommand::WriteSetpoint],
        )
        .unwrap();
        assert_ne!(a.digest(), narrower.digest());
    }

    #[test]
    fn a_limit_is_part_of_the_document_down_to_its_unit() {
        let mk = |milli: i64, unit: &str| {
            SafetyBoundary::new(
                "b",
                1,
                sys(),
                &[SafetyFunction::InterlockChain],
                &[
                    ProcessLimit::new(ProcessVariable::Pressure, LimitBound::Upper, milli, unit)
                        .unwrap(),
                ],
                &[IndustrialCommand::WriteSetpoint],
            )
            .unwrap()
            .digest()
        };
        assert_ne!(mk(4_200, "bar"), mk(4_201, "bar"));
        assert_ne!(mk(4_200, "bar"), mk(4_200, "psi"));
    }

    #[test]
    fn a_limit_comparison_is_a_comparison_and_not_a_safety_judgement() {
        let upper =
            ProcessLimit::new(ProcessVariable::Pressure, LimitBound::Upper, 4_200, "bar").unwrap();
        assert!(upper.satisfied_by(4_200));
        assert!(upper.satisfied_by(-1));
        assert!(!upper.satisfied_by(4_201));
        let lower = ProcessLimit::new(ProcessVariable::Level, LimitBound::Lower, 500, "m").unwrap();
        assert!(lower.satisfied_by(500));
        assert!(!lower.satisfied_by(499));
    }

    #[test]
    fn no_protective_function_has_an_establishable_action() {
        for f in SafetyFunction::ALL {
            let e = SafetyEvidence::derive(f, true);
            assert!(!e.establishes_action(), "{f:?}");
            assert!(!f.healthy_report_establishes().is_empty(), "{f:?}");
        }
    }

    #[test]
    fn a_mechanical_function_is_addressable_from_no_network_and_observed_by_nothing() {
        for f in [
            SafetyFunction::PressureRelief,
            SafetyFunction::ManualTripStation,
        ] {
            assert!(!f.network_addressable(), "{f:?}");
            assert!(!f.bypassable_from_control_system(), "{f:?}");
            let e = SafetyEvidence::derive(f, true);
            assert!(!e.command_observed, "{f:?}");
            assert!(e.observable_by().is_empty(), "{f:?}");
        }
    }

    #[test]
    fn without_an_edge_observer_even_the_command_is_unobserved() {
        for f in SafetyFunction::ALL {
            assert!(!SafetyEvidence::derive(f, false).command_observed, "{f:?}");
        }
    }

    #[test]
    fn malformed_boundaries_are_refused() {
        assert!(SafetyBoundary::new(
            "",
            1,
            sys(),
            &[SafetyFunction::InterlockChain],
            &[],
            &[IndustrialCommand::WriteSetpoint]
        )
        .is_err());
        assert!(
            SafetyBoundary::new("b", 1, sys(), &[], &[], &[IndustrialCommand::WriteSetpoint])
                .is_err()
        );
        assert!(
            SafetyBoundary::new("b", 1, sys(), &[SafetyFunction::InterlockChain], &[], &[])
                .is_err()
        );
        assert!(ProcessLimit::new(ProcessVariable::Flow, LimitBound::Upper, 1, "").is_err());
        assert!(
            ProcessLimit::new(ProcessVariable::Flow, LimitBound::Upper, 1, &"u".repeat(33))
                .is_err()
        );
    }

    #[test]
    fn a_commitment_matches_only_itself() {
        let b = boundary();
        assert!(b.is_committed_by(Some(&b.digest())));
        assert!(!b.is_committed_by(None));
        assert!(!b.is_committed_by(Some(&b.clone().with_declared_bypass().digest())));
        assert!(b.check_version().is_ok());
    }
}
