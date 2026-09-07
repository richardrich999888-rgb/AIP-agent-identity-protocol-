//! Operator and manual override, and where it appears in the lineage.
//!
//! # The question the spec asks
//!
//! *"Define operator/manual override semantics and how they appear in
//! authority/execution lineage."* The honest answer has three parts, and only
//! the first is comfortable.
//!
//! 1. An override that goes **through a host an observer watches** appears in
//!    the lineage the same way anything else does: a decision point issues an
//!    expectation naming the operator's identity as the authority, and an
//!    anchored observer measures the process that carried it out.
//! 2. An override that goes **through a host nobody watches** — an engineering
//!    workstation in a cabinet, a laptop on the segment — appears nowhere. It
//!    is `NotObservable`, not `NotObserved`, because no mechanism in this
//!    deployment could have seen it.
//! 3. An override that happens **in the field** — a hand wheel, a jumper, a
//!    keyswitch turned to LOCAL, a forced point on a controller's front panel —
//!    appears nowhere and never will. There is no Linux mechanism for a person
//!    with a spanner.
//!
//! # The rule this module exists to enforce
//!
//! [`OverrideClaim::excuses_divergence`] returns `false`. Always.
//!
//! When observed execution diverges from what was authorized, the most
//! available explanation is "an operator must have done something". It is also
//! exactly what an unauthorized write looks like from inside the accountability
//! system, and it is what an attacker will say. Letting an override claim close
//! a divergence would turn the single fact this architecture can establish — a
//! mismatch — into an unfalsifiable excuse.
//!
//! An override is admitted as authority only when it is **attributed**: a
//! decision behind it, an identity in it, and a kind of override that could
//! have been routed through a decision point at all. Anything else is recorded
//! as a claim and changes no verdict.

use aip_observation::Completeness;
use aip_system::AuthorityContext;
use serde::{Deserialize, Serialize};

use crate::error::IndustrialError;
use crate::sensing::ProcessSensingSource;
use crate::state::ProcessEvidence;

/// A way a human takes control of a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum OverrideKind {
    /// An operator writes from an HMI process running on a host an anchored
    /// observer watches.
    HmiWriteOnObservedHost,
    /// An engineer downloads from an engineering workstation. Usually not a
    /// host anyone watches.
    EngineeringWorkstationDownload,
    /// A maintenance bypass applied through the control system.
    MaintenanceBypass,
    /// A controller's mode keyswitch turned to LOCAL or PROGRAM.
    ControllerKeyswitchLocal,
    /// A point forced at the controller, so that logic no longer drives it.
    ForcedIoPoint,
    /// A valve turned by hand, a jumper fitted, a breaker racked out.
    FieldManualOperation,
    /// A hard-wired manual trip station operated.
    ManualTripStation,
}

impl OverrideKind {
    pub const ALL: [OverrideKind; 7] = [
        Self::HmiWriteOnObservedHost,
        Self::EngineeringWorkstationDownload,
        Self::MaintenanceBypass,
        Self::ControllerKeyswitchLocal,
        Self::ForcedIoPoint,
        Self::FieldManualOperation,
        Self::ManualTripStation,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::HmiWriteOnObservedHost => 0x01,
            Self::EngineeringWorkstationDownload => 0x02,
            Self::MaintenanceBypass => 0x03,
            Self::ControllerKeyswitchLocal => 0x04,
            Self::ForcedIoPoint => 0x05,
            Self::FieldManualOperation => 0x06,
            Self::ManualTripStation => 0x07,
        }
    }

    /// Whether this override could be routed through a decision point at all.
    ///
    /// Three of seven. The other four happen at a controller or in the plant,
    /// where there is no software to ask for authorization and no host to
    /// observe. Saying so is the point: a deployment that believes it has
    /// authority over all seven has misunderstood four of them.
    pub fn authority_expressible(self) -> bool {
        matches!(
            self,
            Self::HmiWriteOnObservedHost
                | Self::EngineeringWorkstationDownload
                | Self::MaintenanceBypass
        )
    }

    /// Whether an anchored observer on the edge node could see it happen.
    ///
    /// One of seven. An engineering workstation and a maintenance bypass can be
    /// *authorized* without being *observed*: the decision point gates them and
    /// nothing measures them, which is a real and common position and is worth
    /// being able to state.
    pub fn edge_observable(self) -> bool {
        matches!(self, Self::HmiWriteOnObservedHost)
    }

    /// How this override appears when no evidence of it exists.
    ///
    /// The distinction the whole module rests on: an override this deployment
    /// could have observed and did not is `NotObserved`; one it could never
    /// observe is `NotObservable`. Neither says the override did not happen.
    pub fn lineage_visibility(self) -> Completeness {
        if self.edge_observable() {
            Completeness::NotObserved
        } else {
            Completeness::NotObservable
        }
    }

    /// What could observe this override.
    pub fn observable_by(self) -> &'static [ProcessSensingSource] {
        if self.edge_observable() {
            &[
                ProcessSensingSource::EdgeProcessObservation,
                ProcessSensingSource::EdgeNetworkObservation,
            ]
        } else {
            &[]
        }
    }

    /// The evidence tier an override claim must reach to be admitted as
    /// authority.
    ///
    /// `DecisionSigned` for every kind. Not `ExecutionObserved`: the question
    /// is whether the override was *permitted*, and permission is a signature,
    /// not a measurement. And not `Declared`: a declaration is the subject
    /// saying an operator did it.
    pub fn authority_evidence_required(self) -> ProcessEvidence {
        ProcessEvidence::DecisionSigned
    }

    /// What may honestly be said about this kind of override.
    pub fn statement(self) -> &'static str {
        match self {
            Self::HmiWriteOnObservedHost => {
                "a process on an observed host issued a command; that a human was at the console \
                 is not established"
            }
            Self::EngineeringWorkstationDownload => {
                "a download may be authorized by a decision point and is observed by nothing here; \
                 the workstation is not a host this deployment watches"
            }
            Self::MaintenanceBypass => {
                "a bypass may be authorized and its removal is not observed; a bypass left in is \
                 indistinguishable here from one that was removed"
            }
            Self::ControllerKeyswitchLocal => {
                "a keyswitch position is reported by the controller it disables; the report is \
                 from the party the switch takes out of the loop"
            }
            Self::ForcedIoPoint => {
                "a forced point is a fact inside a controller; it is reported by the controller \
                 and observed by nothing outside it"
            }
            Self::FieldManualOperation => {
                "nothing: there is no mechanism for a person with a spanner, and there will not \
                 be one"
            }
            Self::ManualTripStation => {
                "nothing: a hard-wired station operates a relay and reports to no network"
            }
        }
    }
}

/// A claim that an override occurred.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverrideClaim {
    pub kind: OverrideKind,
    /// Who the claim says did it. A deployment-resolved identifier; naming
    /// someone here grants nothing and proves nothing.
    declared_by: String,
    /// The authorization the claim cites. Reused from `aip-system`: a citation,
    /// not a grant.
    pub authority: AuthorityContext,
}

impl OverrideClaim {
    pub fn new(
        kind: OverrideKind,
        declared_by: &str,
        authority: AuthorityContext,
    ) -> Result<Self, IndustrialError> {
        if declared_by.is_empty() || declared_by.len() > 128 {
            return Err(IndustrialError::Malformed {
                reason: "an override's declared operator must be 1-128 bytes",
            });
        }
        Ok(Self {
            kind,
            declared_by: declared_by.to_owned(),
            authority,
        })
    }

    pub fn declared_by(&self) -> &str {
        &self.declared_by
    }

    /// Whether the claim is attributed: a decision behind it, and a kind of
    /// override a decision point could have gated.
    pub fn is_attributed(&self) -> bool {
        self.kind.authority_expressible() && self.authority.decision_id.is_some()
    }

    /// Whether this claim may be admitted as authority for a command.
    ///
    /// Requires attribution **and** evidence at or above the required tier.
    /// Both, because a decision id that no signature backs is a number, and a
    /// signature over an override a decision point could never have gated is a
    /// signature over a fiction.
    pub fn accepted_as_authority(&self, available: ProcessEvidence) -> bool {
        self.is_attributed() && available >= self.kind.authority_evidence_required()
    }

    /// Refuse an unattributed override offered as authority.
    pub fn admit(&self, available: ProcessEvidence) -> Result<(), IndustrialError> {
        if self.accepted_as_authority(available) {
            return Ok(());
        }
        Err(IndustrialError::OverrideNotAttributed { kind: self.kind })
    }

    /// Whether this claim explains away a divergence between what was
    /// authorized and what was observed.
    ///
    /// **`false`. Always, for every kind, at every evidence tier, attributed or
    /// not.**
    ///
    /// An attributed override establishes that *an* override was permitted. It
    /// does not establish that *this* divergence is that override, and the two
    /// are joined only by the assumption that nothing else could have caused
    /// it — which is the assumption an attacker needs. A divergence stays a
    /// divergence; the override is recorded beside it, and a human decides.
    pub fn excuses_divergence(&self) -> bool {
        false
    }

    /// How the override appears in the lineage when nothing observed it.
    pub fn lineage_visibility(&self) -> Completeness {
        self.kind.lineage_visibility()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority(with_decision: bool) -> AuthorityContext {
        if with_decision {
            AuthorityContext {
                decision_id: Some([0x11; 16]),
                root_token_jti: Some([0x22; 16]),
            }
        } else {
            AuthorityContext::none()
        }
    }

    #[test]
    fn no_override_ever_excuses_a_divergence() {
        for kind in OverrideKind::ALL {
            for with_decision in [true, false] {
                let c = OverrideClaim::new(kind, "op-7", authority(with_decision)).unwrap();
                assert!(
                    !c.excuses_divergence(),
                    "{kind:?} with_decision={with_decision}"
                );
            }
        }
    }

    #[test]
    fn an_unattributed_override_is_refused_as_authority() {
        let c = OverrideClaim::new(
            OverrideKind::MaintenanceBypass,
            "op-7",
            AuthorityContext::none(),
        )
        .unwrap();
        assert!(!c.is_attributed());
        assert!(!c.accepted_as_authority(ProcessEvidence::PhysicallyObserved));
        assert!(matches!(
            c.admit(ProcessEvidence::ExecutionObserved),
            Err(IndustrialError::OverrideNotAttributed { .. })
        ));
    }

    #[test]
    fn a_field_override_is_never_authority_however_well_signed() {
        for kind in [
            OverrideKind::FieldManualOperation,
            OverrideKind::ManualTripStation,
            OverrideKind::ControllerKeyswitchLocal,
            OverrideKind::ForcedIoPoint,
        ] {
            let c = OverrideClaim::new(kind, "op-7", authority(true)).unwrap();
            assert!(!kind.authority_expressible(), "{kind:?}");
            assert!(!c.is_attributed(), "{kind:?}");
            assert!(
                !c.accepted_as_authority(ProcessEvidence::PhysicallyObserved),
                "{kind:?}: a decision point cannot have gated a hand wheel"
            );
        }
    }

    #[test]
    fn an_attributed_override_is_admitted_only_at_the_signed_tier() {
        let c = OverrideClaim::new(
            OverrideKind::HmiWriteOnObservedHost,
            "op-7",
            authority(true),
        )
        .unwrap();
        assert!(c.is_attributed());
        assert!(!c.accepted_as_authority(ProcessEvidence::Declared));
        assert!(c.accepted_as_authority(ProcessEvidence::DecisionSigned));
        assert!(c.accepted_as_authority(ProcessEvidence::ExecutionObserved));
        assert!(c.admit(ProcessEvidence::DecisionSigned).is_ok());
    }

    #[test]
    fn exactly_one_override_is_observable_and_the_rest_are_not_observable() {
        let observable: Vec<OverrideKind> = OverrideKind::ALL
            .iter()
            .copied()
            .filter(|k| k.edge_observable())
            .collect();
        assert_eq!(observable, vec![OverrideKind::HmiWriteOnObservedHost]);
        assert_eq!(
            OverrideKind::HmiWriteOnObservedHost.lineage_visibility(),
            Completeness::NotObserved
        );
        for k in OverrideKind::ALL.iter().filter(|k| !k.edge_observable()) {
            assert_eq!(
                k.lineage_visibility(),
                Completeness::NotObservable,
                "{k:?}: silence about an unobservable override is not evidence it did not happen"
            );
            assert!(k.observable_by().is_empty(), "{k:?}");
        }
    }

    #[test]
    fn authorized_and_observed_are_different_questions() {
        // The engineering workstation: a decision point can gate it, and no
        // mechanism here measures it. Both facts, at once.
        let k = OverrideKind::EngineeringWorkstationDownload;
        assert!(k.authority_expressible());
        assert!(!k.edge_observable());
        assert_eq!(k.lineage_visibility(), Completeness::NotObservable);
    }

    #[test]
    fn every_kind_states_what_may_be_said_and_codes_are_unique() {
        let mut codes: Vec<u8> = OverrideKind::ALL.iter().map(|k| k.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), OverrideKind::ALL.len());
        for k in OverrideKind::ALL {
            assert!(!k.statement().is_empty(), "{k:?}");
            assert_eq!(
                k.authority_evidence_required(),
                ProcessEvidence::DecisionSigned,
                "{k:?}"
            );
        }
    }

    #[test]
    fn a_declared_operator_is_bounded() {
        assert!(OverrideClaim::new(
            OverrideKind::MaintenanceBypass,
            "",
            AuthorityContext::none()
        )
        .is_err());
        assert!(OverrideClaim::new(
            OverrideKind::MaintenanceBypass,
            &"x".repeat(129),
            AuthorityContext::none()
        )
        .is_err());
    }
}
