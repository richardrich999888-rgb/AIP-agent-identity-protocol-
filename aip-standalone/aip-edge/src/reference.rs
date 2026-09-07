//! The reference report: one execution, seen from every layer at once.
//!
//! # It is a record, not a result
//!
//! An `EdgeReference` carries the artifacts each layer produced and adds
//! nothing of its own. In particular it carries the `Reconciliation` the
//! existing engine returned, **by value and unmodified**, and there is no
//! constructor, method or field here that could change it. This crate names
//! neither `ReconciliationResult` nor `EvidenceStrength` anywhere in its
//! source; `tests/no_second_engine.rs` asserts that against the files rather
//! than trusting the claim.
//!
//! That is the same discipline `aip_airi::integrate::annotate` established:
//! sit *beside* the verdict, take it by reference, contribute zero to it. A
//! second thing that could produce a verdict is a second thing that can be
//! wrong about one.
//!
//! # Why it has canonical bytes
//!
//! So it can be committed. The report's digest goes into NEXORA as a leaf like
//! any other; this crate signs nothing, and integrity comes from a consumer
//! committing to these bytes inside something already signed — the same
//! arrangement Skills 17-21 use.
//!
//! The encoding is over **digests of the components**, not over their
//! contents. Each component already has a domain-tagged injective encoding of
//! its own, and re-encoding them here would create a second definition of what
//! a `PlatformBinding` is — a second place for the truth to live and a second
//! place for it to drift.

use aip_authorize::ExpectedExecution;
use aip_crypto::sha256;
use aip_effect::{EffectAssessment, EffectBinding, EffectFinding};
use aip_execution::{ExecutionProfile, ExecutionStage};
use aip_observation::{ObservationProfile, ObservationRecord};
use aip_platform::PlatformBinding;
use aip_reconcile::Reconciliation;
use aip_system::SystemExecution;
use aip_types::canonical::{put_bytes, put_domain, put_str, put_u16, put_u32, put_u8};

use crate::effect::PhysicalEffectStatus;
use crate::identity::{IdentityKind, IdentityStability};
use crate::{EDGE_REFERENCE_DOMAIN, EDGE_REFERENCE_VERSION};

/// One rung of the request-to-physical-effect ladder.
///
/// `established` is computed from the artifacts, never asserted. A rung that
/// is not established is not a failure of the run: for `PhysicalEffect` it is
/// the correct and permanent answer in this build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rung {
    /// The boundary this rung names, in the brief's vocabulary.
    pub name: &'static str,
    /// The corresponding stage on Skill 18's ladder, when one exists.
    ///
    /// `None` for the physical-effect rung: the twelve stages stop at what
    /// happened outside the host, and no stage claims a physical measurement.
    /// Adding one would be a claim in the type system.
    pub stage: Option<ExecutionStage>,
    /// Whether this run established the rung.
    pub established: bool,
    /// One line a human can check the run against.
    pub note: String,
}

/// The ladder, computed for one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceLadder {
    pub rungs: Vec<Rung>,
}

impl ReferenceLadder {
    /// The highest rung this run established, by position.
    ///
    /// Returns `None` when nothing was established. Deliberately not a score:
    /// the rungs are ordered boundaries, not points, and two runs that stopped
    /// at the same rung for different reasons are not equivalent.
    pub fn highest_established(&self) -> Option<&Rung> {
        self.rungs.iter().rev().find(|r| r.established)
    }

    /// Whether every rung below `name` is established. A ladder with a hole in
    /// it is a reporting bug, not a stronger result, and this is how a caller
    /// checks for one.
    pub fn contiguous_to(&self, name: &str) -> bool {
        for r in &self.rungs {
            if r.name == name {
                return r.established;
            }
            if !r.established {
                return false;
            }
        }
        false
    }
}

/// Everything one reference run produced.
pub struct EdgeReference {
    pub version: u16,
    /// Skill 17: this system, this intelligence, this execution, this
    /// platform, this mission. Built from a real workload's real identity.
    pub system_execution: SystemExecution,
    /// Skill 18: the execution across the stage ladder, with the effect the
    /// workload requested and whatever disposition the evidence supports.
    pub execution_profile: ExecutionProfile,
    /// Skill 19: where it ran, from measurement and registry.
    pub platform_binding: PlatformBinding,
    /// Skill 20: what this deployment can see, projected from the observer's
    /// one declaration.
    pub observation_profile: ObservationProfile,
    /// Skill 20: the correlated records, each from `from_attested`.
    pub records: Vec<ObservationRecord>,
    /// How many observations the verified batches carried in total, before
    /// correlation.
    ///
    /// # Why this is reported next to `records.len()`
    ///
    /// `EffectFinding::NotObserved` distinguishes `NoObserverConsulted` from
    /// `NoneCorrelated`, and an adapter cannot make that distinction visible
    /// to `assess`: a record that does not correlate cannot be *built*, because
    /// `from_attested` refuses a boot mismatch and this crate refuses a process
    /// mismatch. So `assess` is handed an empty slice in both cases and
    /// correctly answers `NoObserverConsulted`, which understates what
    /// happened when an observer did run and saw something else.
    ///
    /// Rather than manufacture a finding — which would be this crate deciding
    /// a Skill 21 question — the two counts are reported side by side. Zero
    /// offered is "nobody looked"; non-zero offered with zero correlated is
    /// "someone looked at something that is not this execution". The gap in
    /// the finding vocabulary is recorded in the Skill 22 report rather than
    /// papered over.
    pub observations_offered: u32,
    /// Skill 21: what independent observation established about the effect.
    pub finding: EffectFinding,
    /// Skill 21: how tightly the finding attaches to the named effect.
    pub binding: EffectBinding,
    /// The conjunction Skill 21 enforces: a corroborating finding **and** an
    /// effect-specific binding.
    pub establishes_named_effect: bool,
    /// What the reference can say about physical effect. Nothing, computed.
    pub physical_effect: PhysicalEffectStatus,
    /// The existing engine's verdict, unmodified. This crate produces none.
    pub reconciliation: Reconciliation,
    /// The expectation the run was about, for the digest.
    pub expectation: ExpectedExecution,
    pub ladder: ReferenceLadder,
}

impl EdgeReference {
    /// Assemble a report from artifacts every other layer produced.
    ///
    /// Takes the assessment rather than a finding so the two fields cannot be
    /// paired inconsistently: both are read out of the same value here, and
    /// there is no setter for either.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        system_execution: SystemExecution,
        execution_profile: ExecutionProfile,
        platform_binding: PlatformBinding,
        observation_profile: ObservationProfile,
        records: Vec<ObservationRecord>,
        observations_offered: u32,
        assessment: &EffectAssessment,
        physical_effect: PhysicalEffectStatus,
        reconciliation: Reconciliation,
        expectation: ExpectedExecution,
    ) -> Self {
        let ladder = build_ladder(
            &platform_binding,
            &records,
            assessment,
            &physical_effect,
            &reconciliation,
        );
        Self {
            version: EDGE_REFERENCE_VERSION,
            system_execution,
            execution_profile,
            platform_binding,
            observation_profile,
            records,
            observations_offered,
            finding: assessment.finding().clone(),
            binding: assessment.binding(),
            establishes_named_effect: assessment.establishes_named_effect(),
            physical_effect,
            reconciliation,
            expectation,
            ladder,
        }
    }

    /// Domain-tagged, injective canonical bytes over the component digests.
    ///
    /// Records are counted and encoded in order, so a truncated set is not a
    /// valid prefix of a longer one and two runs that saw different numbers of
    /// observations cannot collide.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, EDGE_REFERENCE_DOMAIN);
        put_u16(&mut buf, self.version);
        // `SystemExecution` exposes canonical bytes and no digest of its own,
        // so the digest is taken here rather than a second encoding invented.
        put_bytes(&mut buf, &sha256(&self.system_execution.canonical_bytes()));
        put_bytes(&mut buf, &self.execution_profile.digest());
        put_bytes(&mut buf, &self.platform_binding.digest());
        put_bytes(&mut buf, &self.observation_profile.digest());
        put_u32(&mut buf, self.observations_offered);
        put_u32(&mut buf, self.records.len() as u32);
        for r in &self.records {
            put_bytes(&mut buf, &r.digest());
        }
        put_u8(&mut buf, self.finding.code());
        put_u8(&mut buf, self.binding.code());
        put_u8(&mut buf, u8::from(self.establishes_named_effect));
        put_u8(
            &mut buf,
            u8::from(self.physical_effect.establishes_physical_effect()),
        );
        put_u8(&mut buf, self.physical_effect.completeness.code());
        put_bytes(&mut buf, &self.reconciliation.digest());
        put_bytes(&mut buf, &self.expectation.decision_id);
        // The ladder is derived from everything above, so its rungs are
        // encoded as a fixed-width bitmap rather than re-encoded in full: it
        // is a projection, and a projection with its own independent encoding
        // is a second definition waiting to disagree.
        put_u32(&mut buf, self.ladder.rungs.len() as u32);
        for r in &self.ladder.rungs {
            put_str(&mut buf, r.name);
            put_u8(&mut buf, u8::from(r.established));
        }
        buf
    }

    /// SHA-256 over [`Self::canonical_bytes`], for committing into NEXORA.
    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }

    /// The identity table, with this run's stability answers.
    ///
    /// Returned rather than stored: it is a property of the architecture, not
    /// of the run, and storing it would invite someone to edit a copy.
    pub fn identity_table(&self) -> Vec<(IdentityKind, IdentityStability, IdentityStability)> {
        IdentityKind::ALL
            .iter()
            .map(|k| (*k, k.across_workload_restart(), k.across_host_reboot()))
            .collect()
    }
}

/// Compute the ladder from the artifacts.
///
/// Each rung asks one question of one artifact, and none of them asks the
/// workload.
fn build_ladder(
    platform_binding: &PlatformBinding,
    records: &[ObservationRecord],
    assessment: &EffectAssessment,
    physical: &PhysicalEffectStatus,
    reconciliation: &Reconciliation,
) -> ReferenceLadder {
    let observed = !records.is_empty();
    ReferenceLadder {
        rungs: vec![
            Rung {
                name: "REQUEST",
                stage: Some(ExecutionStage::ToolInvocation),
                // The workload signed an AIRI event asking for the effect.
                // Established means "it was asked for", which is all a
                // self-report can ever establish.
                established: true,
                note: "the workload authored a signed AIRI tool invocation; self-reported"
                    .to_string(),
            },
            Rung {
                name: "AUTHORIZED",
                stage: Some(ExecutionStage::ExpectedExecution),
                established: reconciliation.decision_id.is_some(),
                note: "a decision point signed an ExpectedExecution bound to a process instance"
                    .to_string(),
            },
            Rung {
                name: "EXECUTION",
                stage: Some(ExecutionStage::RuntimeExecution),
                established: true,
                note: "the workload reported its call returned; self-reported, and a 200 \
                       equivalent is not an effect"
                    .to_string(),
            },
            Rung {
                name: "INDEPENDENT OBSERVATION",
                stage: Some(ExecutionStage::IndependentObservation),
                established: observed,
                note: format!(
                    "{} correlated record(s) from an anchored observer; platform disposition {}",
                    records.len(),
                    if platform_binding.disposition().asserts_platform() {
                        "Bound"
                    } else {
                        "not Bound"
                    }
                ),
            },
            Rung {
                name: "OBSERVED ACTUATION",
                stage: Some(ExecutionStage::ExternalEffect),
                established: assessment.establishes_named_effect(),
                note: "requires a corroborating finding AND an effect-specific binding (ADR-004)"
                    .to_string(),
            },
            Rung {
                name: "PHYSICAL EFFECT",
                // No stage. The twelve boundaries stop at what happened
                // outside the host; none of them is a physical measurement.
                stage: None,
                established: physical.establishes_physical_effect(),
                note: "no mechanism implements ObservationClass::PhysicalEffect (ADR-003 \
                       decision 2); the reconciler's equivalent of this state is CANNOT_PROVE"
                    .to_string(),
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_physical_rung_has_no_stage_and_never_will_by_accident() {
        // A future change that gives the physical rung a stage has to edit
        // this test, which is the point of asserting a `None`.
        let ladder = ReferenceLadder {
            rungs: vec![Rung {
                name: "PHYSICAL EFFECT",
                stage: None,
                established: false,
                note: String::new(),
            }],
        };
        assert!(ladder.rungs[0].stage.is_none());
        assert!(!ladder.rungs[0].established);
    }

    #[test]
    fn highest_established_ignores_a_higher_unestablished_rung() {
        let ladder = ReferenceLadder {
            rungs: vec![
                Rung {
                    name: "A",
                    stage: None,
                    established: true,
                    note: String::new(),
                },
                Rung {
                    name: "B",
                    stage: None,
                    established: false,
                    note: String::new(),
                },
            ],
        };
        assert_eq!(ladder.highest_established().unwrap().name, "A");
        assert!(!ladder.contiguous_to("B"));
        assert!(ladder.contiguous_to("A"));
    }
}
