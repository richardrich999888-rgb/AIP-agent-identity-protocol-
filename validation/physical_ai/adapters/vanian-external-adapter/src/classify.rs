//! Layer 3 — CLASSIFICATION. The admission gate, and its refusals.
//!
//! # What this module will not do
//!
//! It will not construct an `ObservationRecord`. It cannot: building one
//! requires an attested batch from an anchored collector holding its own key,
//! and this crate holds no key and has no `SourceMechanism` for a camera. What
//! it produces is a *verdict about eligibility* — whether the production path
//! could be handed this observation at all, and if not, exactly which condition
//! failed.
//!
//! That distinction is the design. An adapter that could build a record would
//! be able to decide what was observed about the thing it describes, and a
//! validation tool that can do that has stopped being a validation tool.
//!
//! # The admission ladder
//!
//! ```text
//!   Refused                       nothing may be concluded; the reason is named
//!   AdmittedAsClaim               the subject said this; recorded, never corroborating
//!   AdmittedAsCorroboration       consistent with something else; raises no ceiling
//!   EligibleForObservationRecord  the production path could take this
//! ```
//!
//! The top rung is **unreachable in this build**, and it is computed rather
//! than written as `false`: it needs a class that is external, anchored, and
//! backed by an implemented `SourceMechanism` whose observation class matches
//! the event. Only the host-runtime path has a mechanism, and it observes
//! processes rather than plants. If an optical mechanism is ever implemented,
//! the top rung becomes reachable and this module's tests fail, which is the
//! intended way to find out.

use aip_observation::EvidenceCeiling;
use serde::{Deserialize, Serialize};

use crate::normalize::ExternalObservation;
use crate::observer::ObserverPosture;
use crate::provenance::ProvenanceClass;

/// Why an observation was not admitted. Every variant is a path declined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefusalReason {
    /// The raw bytes no longer hash to their capture digest.
    RawIntegrityFailed,
    /// Nobody looked.
    ObserverUnavailable,
    /// The observer was live and may have been blind. The observation-integrity
    /// finding, in the physical layer.
    ObserverIntegrityUnknown,
    /// The observer reported nothing; there is no observation to admit.
    ObserverSilent,
    /// The observation is older than the caller's freshness bound.
    Stale { age_ms: u64, bound_ms: u64 },
    /// The observation is dated after the moment it is being judged at.
    NotYetValid,
    /// This `(observer_id, sequence)` has already been admitted.
    Replay { observer_id: String, sequence: u64 },
    /// The observation names no subject.
    SubjectIdentityUnbound,
    /// A physical claim was offered from a class that cannot carry one.
    PhysicalClaimFromNonPhysicalSource { class: ProvenanceClass },
    /// A simulator's state was offered as a fact about the world.
    SimulatorGroundTruthOfferedAsPhysical,
}

impl RefusalReason {
    /// What a caller may conclude about the subject from this refusal.
    ///
    /// The same sentence for every variant, deliberately: **nothing**. A
    /// refusal is a statement about the evidence, never about the actor.
    pub fn conclusion_about_subject(&self) -> &'static str {
        "nothing: a refusal is a statement about the evidence, not about the subject"
    }
}

/// What may be done with an observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Admission {
    Refused {
        reason: RefusalReason,
    },
    /// The subject's own account. Recorded as a claim; never corroborates
    /// itself.
    AdmittedAsClaim {
        ceiling: EvidenceCeiling,
    },
    /// Consistent with something else, and raising nothing.
    AdmittedAsCorroboration {
        ceiling: EvidenceCeiling,
    },
    /// The production observation path could be handed this.
    EligibleForObservationRecord {
        ceiling: EvidenceCeiling,
        mechanism: aip_observe::SourceMechanism,
    },
}

impl Admission {
    /// Whether anything was admitted at all.
    pub fn is_admitted(&self) -> bool {
        !matches!(self, Self::Refused { .. })
    }

    /// Whether this admission could contribute to a claim that a physical
    /// event occurred.
    ///
    /// `false` for every variant reachable in this build.
    /// `EligibleForObservationRecord` is the only variant that could ever
    /// return `true`, and it additionally requires the mechanism's observation
    /// class to be the physical-effect one — which no implemented mechanism is.
    pub fn supports_physical_effect(&self) -> bool {
        match self {
            Self::EligibleForObservationRecord { mechanism, .. } => {
                aip_observation::class_of(*mechanism)
                    == aip_observation::ObservationClass::PhysicalEffect
                    && aip_observation::ObservationClass::PhysicalEffect.is_implemented()
            }
            _ => false,
        }
    }

    /// The ceiling this admission carries, if any.
    pub fn ceiling(&self) -> Option<EvidenceCeiling> {
        match self {
            Self::Refused { .. } => None,
            Self::AdmittedAsClaim { ceiling }
            | Self::AdmittedAsCorroboration { ceiling }
            | Self::EligibleForObservationRecord { ceiling, .. } => Some(*ceiling),
        }
    }
}

/// The caller's admission policy. Explicit so nothing is defaulted silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionPolicy {
    /// How old an observation may be, in milliseconds, at the moment of
    /// judgement.
    pub freshness_bound_ms: u64,
}

impl Default for AdmissionPolicy {
    /// Thirty seconds. A number the caller should override with its own; it is
    /// here so `Default` exists, not because it is right for any deployment.
    fn default() -> Self {
        Self {
            freshness_bound_ms: 30_000,
        }
    }
}

/// A ledger of `(observer_id, sequence)` pairs already admitted.
///
/// Not a replay *defence* in the cryptographic sense — it is a duplicate
/// detector over one verifier's own admission history, which is exactly what
/// the production engine's `replay_detected` does for attested batches. It is
/// here so "replay accepted" is a mutation that can be killed.
#[derive(Debug, Clone, Default)]
pub struct AdmissionLedger {
    seen: std::collections::BTreeSet<(String, u64)>,
}

impl AdmissionLedger {
    pub fn new() -> Self {
        Self::default()
    }

    fn contains(&self, o: &ExternalObservation) -> bool {
        self.seen
            .contains(&(o.nonce.observer_id.clone(), o.nonce.sequence))
    }

    fn record(&mut self, o: &ExternalObservation) {
        self.seen
            .insert((o.nonce.observer_id.clone(), o.nonce.sequence));
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// Classify one observation and decide whether it may be admitted.
///
/// # Order of checks
///
/// Integrity, then observer posture, then freshness, then replay, then binding,
/// then class. The order is not cosmetic: every check can only move the answer
/// towards `Refused`, and putting the cheapest and most fundamental first means
/// a failure is reported as the thing that actually went wrong rather than as a
/// downstream symptom.
///
/// `now_ms` and the policy come from the caller. This function reads no clock
/// and no configuration, so its answer is a pure function of its inputs and a
/// test can drive every branch.
pub fn admit(
    observation: &ExternalObservation,
    posture: ObserverPosture,
    now_ms: u64,
    policy: AdmissionPolicy,
    ledger: &mut AdmissionLedger,
) -> Admission {
    // 1. RAW integrity. An edited capture is not evidence of anything.
    if !observation.raw_integrity_holds() {
        return Admission::Refused {
            reason: RefusalReason::RawIntegrityFailed,
        };
    }

    // 2. Observer posture. Three absences, three refusals, never one.
    match posture {
        ObserverPosture::Unavailable => {
            return Admission::Refused {
                reason: RefusalReason::ObserverUnavailable,
            }
        }
        ObserverPosture::IntegrityUnknown => {
            return Admission::Refused {
                reason: RefusalReason::ObserverIntegrityUnknown,
            }
        }
        ObserverPosture::PresentAndSilent => {
            return Admission::Refused {
                reason: RefusalReason::ObserverSilent,
            }
        }
        ObserverPosture::Present => {}
    }

    // 3. Freshness, in both directions.
    if observation.timestamp_ms > now_ms {
        return Admission::Refused {
            reason: RefusalReason::NotYetValid,
        };
    }
    let age = now_ms - observation.timestamp_ms;
    if age > policy.freshness_bound_ms {
        return Admission::Refused {
            reason: RefusalReason::Stale {
                age_ms: age,
                bound_ms: policy.freshness_bound_ms,
            },
        };
    }

    // 4. Replay: the same observer's same sequence, twice.
    if ledger.contains(observation) {
        return Admission::Refused {
            reason: RefusalReason::Replay {
                observer_id: observation.nonce.observer_id.clone(),
                sequence: observation.nonce.sequence,
            },
        };
    }

    let class = observation.provenance_class;

    // 5. A physical claim needs a source that could carry one.
    if observation.event_type.is_physical_claim() {
        if class == ProvenanceClass::SimulatorGroundTruth {
            return Admission::Refused {
                reason: RefusalReason::SimulatorGroundTruthOfferedAsPhysical,
            };
        }
        if !observation.subject_identity.is_bound() {
            return Admission::Refused {
                reason: RefusalReason::SubjectIdentityUnbound,
            };
        }
    }

    ledger.record(observation);

    // 6. The class decides what the admission is worth. Nothing above this
    //    point could have raised it.
    if class.subject_controls_source() {
        return Admission::AdmittedAsClaim {
            ceiling: class.max_ceiling(),
        };
    }

    match class.mechanism() {
        // The only route to the top rung, and it additionally requires the
        // class to be anchored. Unreachable for any optical source in this
        // build, because no optical source has a mechanism.
        Some(mechanism) if class.is_anchored() => Admission::EligibleForObservationRecord {
            ceiling: class.max_ceiling(),
            mechanism,
        },
        // External to the subject, and either unanchored or unmechanised.
        // Corroboration, and no more: independence without an implemented
        // mechanism is nobody observing.
        _ => Admission::AdmittedAsCorroboration {
            ceiling: class.max_ceiling(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalize::{EventType, ObservationNonce, SubjectIdentity};
    use crate::raw::RawCapture;

    fn obs(class: ProvenanceClass, event: EventType, seq: u64) -> ExternalObservation {
        ExternalObservation {
            source: "external-camera".into(),
            mechanism: "apriltag36h11".into(),
            timestamp_ms: 10_000,
            subject_identity: SubjectIdentity::FiducialMarker { marker_id: 7 },
            event_type: event,
            payload: serde_json::json!({"x_mm": 1200}),
            provenance_class: class,
            nonce: ObservationNonce {
                observer_id: "cam-1".into(),
                sequence: seq,
            },
            raw: RawCapture::new("apriltag", Some("pupil"), 10_000, b"frame".to_vec()).unwrap(),
        }
    }

    fn admit_now(o: &ExternalObservation, p: ObserverPosture) -> Admission {
        admit(
            o,
            p,
            10_100,
            AdmissionPolicy::default(),
            &mut AdmissionLedger::new(),
        )
    }

    #[test]
    fn nothing_admitted_in_this_build_supports_a_physical_effect_claim() {
        for class in ProvenanceClass::ALL {
            for event in EventType::ALL {
                let a = admit_now(&obs(class, event, 1), ObserverPosture::Present);
                assert!(
                    !a.supports_physical_effect(),
                    "{class:?}/{event:?} supported a physical-effect claim"
                );
            }
        }
    }

    #[test]
    fn an_anchored_external_camera_reaches_corroboration_and_stops_there() {
        // The pivotal case. The camera is outside the robot, the collector
        // holds its own key — and there is still no mechanism, so the top rung
        // is not reached.
        let a = admit_now(
            &obs(
                ProvenanceClass::ExternalSensorAnchored,
                EventType::PoseMeasurement,
                1,
            ),
            ObserverPosture::Present,
        );
        assert_eq!(
            a,
            Admission::AdmittedAsCorroboration {
                ceiling: EvidenceCeiling::Corroborative
            }
        );
        assert!(!a.supports_physical_effect());
    }

    #[test]
    fn robot_telemetry_is_admitted_as_a_claim_and_never_as_corroboration() {
        for class in [
            ProvenanceClass::SubjectSelfReport,
            ProvenanceClass::SubjectControlledRecording,
            ProvenanceClass::ControllerAcknowledgement,
            ProvenanceClass::SubjectMiddlewareInstrumentation,
        ] {
            let a = admit_now(
                &obs(class, EventType::StateReport, 1),
                ObserverPosture::Present,
            );
            assert_eq!(
                a,
                Admission::AdmittedAsClaim {
                    ceiling: EvidenceCeiling::Corroborative
                },
                "{class:?}"
            );
        }
    }

    #[test]
    fn a_controller_acknowledgement_never_becomes_a_physical_observation() {
        let a = admit_now(
            &obs(
                ProvenanceClass::ControllerAcknowledgement,
                EventType::Displacement,
                1,
            ),
            ObserverPosture::Present,
        );
        assert!(matches!(a, Admission::AdmittedAsClaim { .. }));
        assert!(!a.supports_physical_effect());
    }

    #[test]
    fn simulator_ground_truth_is_refused_as_a_physical_claim() {
        let a = admit_now(
            &obs(
                ProvenanceClass::SimulatorGroundTruth,
                EventType::PoseMeasurement,
                1,
            ),
            ObserverPosture::Present,
        );
        assert_eq!(
            a,
            Admission::Refused {
                reason: RefusalReason::SimulatorGroundTruthOfferedAsPhysical
            }
        );
        // And is admissible for a non-physical event, as corroboration only.
        let b = admit_now(
            &obs(
                ProvenanceClass::SimulatorGroundTruth,
                EventType::CommandObserved,
                1,
            ),
            ObserverPosture::Present,
        );
        assert!(matches!(b, Admission::AdmittedAsCorroboration { .. }));
    }

    #[test]
    fn the_three_observer_absences_produce_three_distinct_refusals() {
        let o = obs(
            ProvenanceClass::ExternalSensorAnchored,
            EventType::PoseMeasurement,
            1,
        );
        assert_eq!(
            admit_now(&o, ObserverPosture::Unavailable),
            Admission::Refused {
                reason: RefusalReason::ObserverUnavailable
            }
        );
        assert_eq!(
            admit_now(&o, ObserverPosture::IntegrityUnknown),
            Admission::Refused {
                reason: RefusalReason::ObserverIntegrityUnknown
            }
        );
        assert_eq!(
            admit_now(&o, ObserverPosture::PresentAndSilent),
            Admission::Refused {
                reason: RefusalReason::ObserverSilent
            }
        );
    }

    #[test]
    fn a_refusal_concludes_nothing_about_the_subject() {
        for r in [
            RefusalReason::ObserverUnavailable,
            RefusalReason::ObserverIntegrityUnknown,
            RefusalReason::ObserverSilent,
            RefusalReason::RawIntegrityFailed,
        ] {
            assert!(r.conclusion_about_subject().starts_with("nothing"));
        }
    }

    #[test]
    fn a_replayed_observation_is_refused_the_second_time() {
        let mut ledger = AdmissionLedger::new();
        let o = obs(
            ProvenanceClass::ExternalSensorAnchored,
            EventType::PoseMeasurement,
            42,
        );
        let first = admit(
            &o,
            ObserverPosture::Present,
            10_100,
            AdmissionPolicy::default(),
            &mut ledger,
        );
        assert!(first.is_admitted());
        let second = admit(
            &o,
            ObserverPosture::Present,
            10_100,
            AdmissionPolicy::default(),
            &mut ledger,
        );
        assert_eq!(
            second,
            Admission::Refused {
                reason: RefusalReason::Replay {
                    observer_id: "cam-1".into(),
                    sequence: 42
                }
            }
        );
        assert_eq!(
            ledger.len(),
            1,
            "a refused replay must not enter the ledger"
        );
    }

    #[test]
    fn a_stale_observation_is_refused_and_a_fresh_one_is_not() {
        let o = obs(
            ProvenanceClass::ExternalSensorAnchored,
            EventType::PoseMeasurement,
            1,
        );
        let policy = AdmissionPolicy {
            freshness_bound_ms: 1_000,
        };
        assert!(admit(
            &o,
            ObserverPosture::Present,
            11_000,
            policy,
            &mut AdmissionLedger::new()
        )
        .is_admitted());
        assert_eq!(
            admit(
                &o,
                ObserverPosture::Present,
                11_001,
                policy,
                &mut AdmissionLedger::new()
            ),
            Admission::Refused {
                reason: RefusalReason::Stale {
                    age_ms: 1_001,
                    bound_ms: 1_000
                }
            }
        );
    }

    #[test]
    fn an_observation_from_the_future_is_refused() {
        let o = obs(
            ProvenanceClass::ExternalSensorAnchored,
            EventType::PoseMeasurement,
            1,
        );
        assert_eq!(
            admit(
                &o,
                ObserverPosture::Present,
                9_999,
                AdmissionPolicy::default(),
                &mut AdmissionLedger::new()
            ),
            Admission::Refused {
                reason: RefusalReason::NotYetValid
            }
        );
    }

    #[test]
    fn an_unbound_physical_claim_is_refused() {
        let mut o = obs(
            ProvenanceClass::ExternalSensorAnchored,
            EventType::PoseMeasurement,
            1,
        );
        o.subject_identity = SubjectIdentity::Unbound;
        assert_eq!(
            admit_now(&o, ObserverPosture::Present),
            Admission::Refused {
                reason: RefusalReason::SubjectIdentityUnbound
            }
        );
    }

    #[test]
    fn an_edited_capture_is_refused_before_anything_else_is_considered() {
        let o = obs(
            ProvenanceClass::ExternalSensorAnchored,
            EventType::PoseMeasurement,
            1,
        );
        let mut json = serde_json::to_value(&o).unwrap();
        json["raw"]["bytes"] = serde_json::to_value(b"tampered".to_vec()).unwrap();
        let edited: ExternalObservation = serde_json::from_value(json).unwrap();
        assert_eq!(
            admit_now(&edited, ObserverPosture::Present),
            Admission::Refused {
                reason: RefusalReason::RawIntegrityFailed
            }
        );
    }

    #[test]
    fn the_eligible_rung_is_unreachable_for_every_optical_class() {
        // The structural claim: no observation from any external sensor class
        // reaches the production observation path in this build, because no
        // optical mechanism exists.
        for class in [
            ProvenanceClass::ExternalSensorAnchored,
            ProvenanceClass::ExternalSensorUnanchored,
            ProvenanceClass::SimulatorGroundTruth,
        ] {
            for event in EventType::ALL {
                let a = admit_now(&obs(class, event, 1), ObserverPosture::Present);
                assert!(
                    !matches!(a, Admission::EligibleForObservationRecord { .. }),
                    "{class:?}/{event:?} reached the production observation path"
                );
            }
        }
    }
}
