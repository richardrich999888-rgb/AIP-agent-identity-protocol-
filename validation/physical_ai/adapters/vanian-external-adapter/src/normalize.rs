//! Layer 2 — NORMALIZED. The conceptual interface, filled in from RAW.
//!
//! This is the `ExternalObservation` the brief specifies, with one addition the
//! brief's own rules require: an `ObservationNonce` pair, because without a
//! `(observer_id, sequence)` there is no way to tell a replayed observation from
//! a fresh one, and "replay accepted" is one of the mutations that must be
//! killed.
//!
//! Nothing here classifies. `independent` is **not** a free-form boolean a
//! caller sets: it is derived from the [`ProvenanceClass`] in
//! [`ExternalObservation::is_independent`], so an integrator cannot assert
//! independence by assignment.

use serde::{Deserialize, Serialize};

use crate::provenance::ProvenanceClass;
use crate::raw::RawCapture;

/// What kind of thing the external tool reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EventType {
    /// A pose or position of a tracked body.
    PoseMeasurement,
    /// A displacement between two poses.
    Displacement,
    /// Entry into or exit from a named zone.
    ZoneTransition,
    /// A command was observed leaving something.
    CommandObserved,
    /// A controller reported accepting a command.
    AcknowledgementObserved,
    /// A machine or joint state was reported.
    StateReport,
    /// A process-level lifecycle fact.
    ProcessLifecycle,
}

impl EventType {
    pub const ALL: [EventType; 7] = [
        Self::PoseMeasurement,
        Self::Displacement,
        Self::ZoneTransition,
        Self::CommandObserved,
        Self::AcknowledgementObserved,
        Self::StateReport,
        Self::ProcessLifecycle,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::PoseMeasurement => 0x01,
            Self::Displacement => 0x02,
            Self::ZoneTransition => 0x03,
            Self::CommandObserved => 0x04,
            Self::AcknowledgementObserved => 0x05,
            Self::StateReport => 0x06,
            Self::ProcessLifecycle => 0x07,
        }
    }

    /// Whether this event type is a claim about the physical world.
    ///
    /// Four of seven. The distinction matters because a physical event type
    /// admitted from a non-physical class is exactly the promotion this adapter
    /// exists to refuse.
    pub fn is_physical_claim(self) -> bool {
        matches!(
            self,
            Self::PoseMeasurement | Self::Displacement | Self::ZoneTransition | Self::StateReport
        )
    }
}

/// How the observation identifies the thing it is about.
///
/// A pose measurement that cannot be tied to a subject is a pose measurement of
/// something. Binding is a precondition for admission, not a nicety.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubjectIdentity {
    /// No binding at all: the observation is about an unnamed body.
    Unbound,
    /// A fiducial marker id. Binds to a *marker*, which is attached to a
    /// subject by an assumption nothing here checks — and that assumption is
    /// recorded rather than hidden.
    FiducialMarker { marker_id: u32 },
    /// A subject named in the deployment's own namespace, bound by whatever
    /// the deployment says. A declaration, not a measurement.
    DeclaredSubject { subject: String },
}

impl SubjectIdentity {
    /// Whether the observation is bound to a subject at all.
    pub fn is_bound(&self) -> bool {
        !matches!(self, Self::Unbound)
    }

    /// Whether the binding was *measured* rather than declared.
    ///
    /// `false` for every variant. A marker id is measured; that the marker is
    /// on the subject is not. This is the physical analogue of the process
    /// identity problem, and it is the honest answer.
    pub fn is_measured_binding(&self) -> bool {
        false
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Unbound => "unbound".to_owned(),
            Self::FiducialMarker { marker_id } => {
                format!("fiducial marker {marker_id} (attachment to the subject is assumed)")
            }
            Self::DeclaredSubject { subject } => format!("declared subject {subject}"),
        }
    }
}

/// A replay guard: which observer said it, and where in its own sequence.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ObservationNonce {
    pub observer_id: String,
    pub sequence: u64,
}

/// Layer 2: one external observation, normalized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalObservation {
    /// The tool that produced it, as named in the license registry.
    pub source: String,
    /// The facility or algorithm behind it, in the tool's own words. A string
    /// on purpose: this is *not* `SourceMechanism`, and calling it one would
    /// be the schema fork.
    pub mechanism: String,
    /// Observer clock, milliseconds.
    pub timestamp_ms: u64,
    pub subject_identity: SubjectIdentity,
    pub event_type: EventType,
    /// The measured content, as JSON. Opaque to this crate.
    pub payload: serde_json::Value,
    pub provenance_class: ProvenanceClass,
    pub nonce: ObservationNonce,
    /// The RAW layer this was derived from. Kept, not replaced.
    pub raw: RawCapture,
}

impl ExternalObservation {
    /// Whether this observation is independent of the subject.
    ///
    /// **Derived from the provenance class, never assigned.** The brief's
    /// interface has an `independent` field; making it a settable boolean would
    /// let an integrator declare a `/odom` topic independent, which is the one
    /// thing this adapter exists to make impossible.
    pub fn is_independent(&self) -> bool {
        self.provenance_class.is_external_to_subject()
    }

    /// Whether the raw bytes still hash to what was captured.
    pub fn raw_integrity_holds(&self) -> bool {
        self.raw.integrity_holds()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(class: ProvenanceClass) -> ExternalObservation {
        ExternalObservation {
            source: "t".into(),
            mechanism: "m".into(),
            timestamp_ms: 1_000,
            subject_identity: SubjectIdentity::FiducialMarker { marker_id: 7 },
            event_type: EventType::PoseMeasurement,
            payload: serde_json::json!({"x_mm": 1200}),
            provenance_class: class,
            nonce: ObservationNonce {
                observer_id: "cam-1".into(),
                sequence: 1,
            },
            raw: RawCapture::new("t", None, 1_000, b"bytes".to_vec()).unwrap(),
        }
    }

    #[test]
    fn independence_is_derived_and_cannot_be_asserted() {
        // There is no `independent` field to set. The only way to change the
        // answer is to change the provenance class, which is the decision that
        // should be visible.
        assert!(!obs(ProvenanceClass::SubjectSelfReport).is_independent());
        assert!(!obs(ProvenanceClass::ControllerAcknowledgement).is_independent());
        assert!(obs(ProvenanceClass::ExternalSensorAnchored).is_independent());
        assert!(obs(ProvenanceClass::SimulatorGroundTruth).is_independent());
    }

    #[test]
    fn a_fiducial_binding_is_never_a_measured_binding() {
        let s = SubjectIdentity::FiducialMarker { marker_id: 7 };
        assert!(s.is_bound());
        assert!(!s.is_measured_binding());
        assert!(s.describe().contains("assumed"));
        assert!(!SubjectIdentity::Unbound.is_bound());
        assert!(!SubjectIdentity::DeclaredSubject {
            subject: "ugv-1".into()
        }
        .is_measured_binding());
    }

    #[test]
    fn physical_event_types_are_named_and_the_rest_are_not() {
        for e in [
            EventType::PoseMeasurement,
            EventType::Displacement,
            EventType::ZoneTransition,
            EventType::StateReport,
        ] {
            assert!(e.is_physical_claim(), "{e:?}");
        }
        for e in [
            EventType::CommandObserved,
            EventType::AcknowledgementObserved,
            EventType::ProcessLifecycle,
        ] {
            assert!(!e.is_physical_claim(), "{e:?}");
        }
        let mut codes: Vec<u8> = EventType::ALL.iter().map(|e| e.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), EventType::ALL.len());
    }

    #[test]
    fn the_raw_layer_survives_normalization() {
        let o = obs(ProvenanceClass::ExternalSensorAnchored);
        assert!(o.raw_integrity_holds());
        assert_eq!(o.raw.bytes(), b"bytes");
    }
}
