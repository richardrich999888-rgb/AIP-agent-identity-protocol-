//! Operational boundaries, and the four different things "position" means.
//!
//! # The distinction the whole module exists for
//!
//! ```text
//!   authorized operating region      what a decision point signed
//!         !=
//!   reported position                what the aircraft said
//!         !=
//!   independently observed position  what someone outside measured
//!         !=
//!   proven geofence violation        what may be asserted
//! ```
//!
//! A geofence assessment built on the second of those is a system that asks
//! the suspect where it was. It will report compliance for a compromised
//! aircraft and violation for a spoofed one, and it will do both with total
//! confidence.
//!
//! # What can be asserted, and what cannot
//!
//! [`GeofenceAssessment::assess`] can reach `Violation` **only** from a
//! position whose [`NavigationEvidence::establishes`] is true. In this build
//! that never happens for position, so the honest answer for every real UAS is
//! `CannotAssess`. That is not a failure of the assessment; it is the
//! assessment working. A deployment that anchors an independent tracker gets a
//! different answer with no change to this file.
//!
//! Compliance is held to the same standard, and for the same reason: "the
//! aircraft said it was inside" is not compliance, it is a claim, and treating
//! it as compliance is how a fence becomes decorative.
//!
//! # This is not a policy engine
//!
//! No enforcement, no severity, no verdict. An assessment is a structural fact
//! about the evidence bearing on a boundary question, and what to do about one
//! belongs to the existing warrant and containment path.

use serde::{Deserialize, Serialize};

use crate::navigation::{NavigationEvidence, NavigationQuantity};

/// The horizontal reference a coordinate is expressed in.
///
/// Carried explicitly because a latitude without a frame is a number, and two
/// frames disagreeing by tens of metres is the difference between inside and
/// outside a boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CoordinateFrame {
    /// WGS-84 geodetic latitude/longitude. What GNSS reports natively.
    Wgs84Geodetic,
    /// A local tangent plane fixed at a stated origin.
    LocalTangentPlane,
    /// A national or regional grid.
    RegionalGrid,
}

impl CoordinateFrame {
    pub fn code(self) -> u8 {
        match self {
            Self::Wgs84Geodetic => 0x01,
            Self::LocalTangentPlane => 0x02,
            Self::RegionalGrid => 0x03,
        }
    }
}

/// What an altitude is measured **from**.
///
/// "Altitude 100" names nothing until this is stated. The four references
/// below can differ by tens of metres at one point on the ground, and a
/// ceiling check that silently compares two of them is a check that passes
/// when it should fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AltitudeReference {
    /// Height above the WGS-84 ellipsoid. What GNSS reports natively.
    EllipsoidalWgs84,
    /// Height above mean sea level, via a geoid model.
    GeoidMsl,
    /// Height above the ground directly below. Changes as the ground does.
    AboveGroundLevel,
    /// Height above the point the aircraft launched from. What a barometer
    /// zeroed on the ground actually gives.
    AboveTakeoffPoint,
}

impl AltitudeReference {
    pub fn code(self) -> u8 {
        match self {
            Self::EllipsoidalWgs84 => 0x01,
            Self::GeoidMsl => 0x02,
            Self::AboveGroundLevel => 0x03,
            Self::AboveTakeoffPoint => 0x04,
        }
    }
}

/// An authorized operating region.
///
/// A rectangle in a stated frame with a stated altitude band. Deliberately the
/// simplest shape that can be checked without ambiguity: a polygon library
/// would be a dependency and a source of edge cases, and the shape is not
/// where the security lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeofenceRegion {
    pub frame: CoordinateFrame,
    pub altitude_reference: AltitudeReference,
    /// Micro-degrees, so the bounds are exact integers. Floating point in a
    /// boundary comparison is a source of disagreement between two verifiers
    /// checking the same fence.
    pub min_lat_udeg: i64,
    pub max_lat_udeg: i64,
    pub min_lon_udeg: i64,
    pub max_lon_udeg: i64,
    /// Centimetres above `altitude_reference`.
    pub min_alt_cm: i64,
    pub max_alt_cm: i64,
}

/// A position, as some party stated it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PositionClaim {
    pub frame: CoordinateFrame,
    pub altitude_reference: AltitudeReference,
    pub lat_udeg: i64,
    pub lon_udeg: i64,
    pub alt_cm: i64,
    /// When the position was *observed*, on the observing party's clock.
    pub observed_at_ms: u64,
}

/// Why a boundary question could not be answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CannotAssess {
    /// No position evidence bears on the question at all.
    NoPositionEvidence,
    /// Position exists but only as a self-report. The aircraft's own account
    /// of where it is cannot establish either compliance or violation.
    PositionOnlySelfReported,
    /// The position is older than the deployment's staleness bound. An
    /// aircraft moves; a position from a minute ago answers a question about a
    /// minute ago.
    StalePosition { age_ms: u64 },
    /// The claim and the region are in different horizontal frames.
    FrameMismatch {
        region: CoordinateFrame,
        claim: CoordinateFrame,
    },
    /// The claim and the region use different altitude references.
    AltitudeReferenceMismatch {
        region: AltitudeReference,
        claim: AltitudeReference,
    },
}

/// What may be said about an aircraft's position relative to a boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GeofenceAssessment {
    /// Independently observed position, in the right frame, in time, inside.
    Compliant,
    /// Independently observed position, in the right frame, in time, outside.
    ///
    /// The only variant that accuses anything, and the only one that requires
    /// [`NavigationEvidence::establishes`].
    Violation,
    /// The question could not be answered. Never read as compliance.
    CannotAssess(CannotAssess),
}

impl GeofenceAssessment {
    /// Assess a position claim against a region.
    ///
    /// # Order of refusal
    ///
    /// 1. no position evidence at all;
    /// 2. position that is only self-reported — the case every real UAS is in;
    /// 3. a frame or altitude-reference mismatch, refused rather than
    ///    converted: a silent conversion is a wrong answer with a confident
    ///    face;
    /// 4. staleness, on the observing party's clock;
    /// 5. only then, the comparison.
    ///
    /// Frame checks come **before** staleness so that a mismatched frame is
    /// reported as a mismatch even when the fix is also old. The more specific
    /// structural fault is the more useful thing to tell an operator.
    pub fn assess(
        region: &GeofenceRegion,
        claim: Option<&PositionClaim>,
        evidence: &NavigationEvidence,
        now_ms: u64,
        max_age_ms: u64,
    ) -> Self {
        debug_assert_eq!(evidence.quantity, NavigationQuantity::Position);

        let Some(claim) = claim else {
            return Self::CannotAssess(CannotAssess::NoPositionEvidence);
        };
        if !evidence.establishes() {
            return Self::CannotAssess(if evidence.self_reported {
                CannotAssess::PositionOnlySelfReported
            } else {
                CannotAssess::NoPositionEvidence
            });
        }
        if region.frame != claim.frame {
            return Self::CannotAssess(CannotAssess::FrameMismatch {
                region: region.frame,
                claim: claim.frame,
            });
        }
        if region.altitude_reference != claim.altitude_reference {
            return Self::CannotAssess(CannotAssess::AltitudeReferenceMismatch {
                region: region.altitude_reference,
                claim: claim.altitude_reference,
            });
        }
        let age = now_ms.saturating_sub(claim.observed_at_ms);
        if age > max_age_ms {
            return Self::CannotAssess(CannotAssess::StalePosition { age_ms: age });
        }

        let inside = claim.lat_udeg >= region.min_lat_udeg
            && claim.lat_udeg <= region.max_lat_udeg
            && claim.lon_udeg >= region.min_lon_udeg
            && claim.lon_udeg <= region.max_lon_udeg
            && claim.alt_cm >= region.min_alt_cm
            && claim.alt_cm <= region.max_alt_cm;
        if inside {
            Self::Compliant
        } else {
            Self::Violation
        }
    }

    /// Whether this assessment asserts the aircraft was outside the boundary.
    ///
    /// True for `Violation` alone. `CannotAssess` is false and is never a
    /// weak violation.
    pub fn asserts_violation(self) -> bool {
        matches!(self, Self::Violation)
    }

    /// Whether this assessment asserts the aircraft was inside.
    ///
    /// True for `Compliant` alone. In particular an unanswerable question is
    /// not compliance — which is the direction the pressure always runs.
    pub fn asserts_compliance(self) -> bool {
        matches!(self, Self::Compliant)
    }

    pub fn code(self) -> u8 {
        match self {
            Self::Compliant => 0x01,
            Self::Violation => 0x02,
            Self::CannotAssess(_) => 0x03,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::TelemetrySource;

    fn region() -> GeofenceRegion {
        GeofenceRegion {
            frame: CoordinateFrame::Wgs84Geodetic,
            altitude_reference: AltitudeReference::GeoidMsl,
            min_lat_udeg: 51_000_000,
            max_lat_udeg: 52_000_000,
            min_lon_udeg: -1_000_000,
            max_lon_udeg: 1_000_000,
            min_alt_cm: 0,
            max_alt_cm: 12_000,
        }
    }

    fn inside_claim() -> PositionClaim {
        PositionClaim {
            frame: CoordinateFrame::Wgs84Geodetic,
            altitude_reference: AltitudeReference::GeoidMsl,
            lat_udeg: 51_500_000,
            lon_udeg: 0,
            alt_cm: 6_000,
            observed_at_ms: 1_000,
        }
    }

    /// Evidence that position was independently observed. Constructed by
    /// declaring a mechanised independent source; there is no way to assert it
    /// directly, which is the point.
    fn independent_position() -> NavigationEvidence {
        let mut e = NavigationEvidence::from_sources(
            NavigationQuantity::Position,
            &[TelemetrySource::GroundStationTrack],
            false,
        );
        // No implemented mechanism observes position in this build, so the
        // computed value is false. The tests below that need a *counterfactual*
        // deployment set the field explicitly and say so; this is the only
        // place in the crate that does, and it is inside `cfg(test)`.
        e.independently_observed = true;
        e
    }

    fn self_reported_position() -> NavigationEvidence {
        NavigationEvidence::from_sources(
            NavigationQuantity::Position,
            &[
                TelemetrySource::GnssReceiverOnboard,
                TelemetrySource::FlightControllerTelemetry,
            ],
            true,
        )
    }

    #[test]
    fn a_self_reported_position_can_establish_neither_compliance_nor_violation() {
        let a = GeofenceAssessment::assess(
            &region(),
            Some(&inside_claim()),
            &self_reported_position(),
            1_500,
            60_000,
        );
        assert_eq!(
            a,
            GeofenceAssessment::CannotAssess(CannotAssess::PositionOnlySelfReported)
        );
        assert!(!a.asserts_compliance(), "a claim is not compliance");
        assert!(!a.asserts_violation());
    }

    #[test]
    fn a_self_reported_position_outside_the_fence_is_not_a_violation_either() {
        let mut outside = inside_claim();
        outside.lat_udeg = 60_000_000;
        let a = GeofenceAssessment::assess(
            &region(),
            Some(&outside),
            &self_reported_position(),
            1_500,
            60_000,
        );
        assert!(
            !a.asserts_violation(),
            "accusing an aircraft on the strength of its own report is the same error as \
             clearing one"
        );
    }

    #[test]
    fn an_independently_observed_position_inside_is_compliant() {
        let a = GeofenceAssessment::assess(
            &region(),
            Some(&inside_claim()),
            &independent_position(),
            1_500,
            60_000,
        );
        assert_eq!(a, GeofenceAssessment::Compliant);
    }

    #[test]
    fn an_independently_observed_position_outside_is_a_violation() {
        let mut outside = inside_claim();
        outside.alt_cm = 20_000;
        let a = GeofenceAssessment::assess(
            &region(),
            Some(&outside),
            &independent_position(),
            1_500,
            60_000,
        );
        assert_eq!(a, GeofenceAssessment::Violation);
    }

    #[test]
    fn a_stale_position_cannot_answer_the_question() {
        let a = GeofenceAssessment::assess(
            &region(),
            Some(&inside_claim()),
            &independent_position(),
            120_000,
            60_000,
        );
        match a {
            GeofenceAssessment::CannotAssess(CannotAssess::StalePosition { age_ms }) => {
                assert_eq!(age_ms, 119_000);
            }
            other => panic!("expected staleness, got {other:?}"),
        }
        assert!(!a.asserts_compliance());
        assert!(!a.asserts_violation());
    }

    #[test]
    fn a_frame_mismatch_is_refused_not_converted() {
        let mut claim = inside_claim();
        claim.frame = CoordinateFrame::LocalTangentPlane;
        let a = GeofenceAssessment::assess(
            &region(),
            Some(&claim),
            &independent_position(),
            1_500,
            60_000,
        );
        assert!(matches!(
            a,
            GeofenceAssessment::CannotAssess(CannotAssess::FrameMismatch { .. })
        ));
    }

    #[test]
    fn an_altitude_reference_mismatch_is_refused_not_converted() {
        let mut claim = inside_claim();
        claim.altitude_reference = AltitudeReference::AboveTakeoffPoint;
        let a = GeofenceAssessment::assess(
            &region(),
            Some(&claim),
            &independent_position(),
            1_500,
            60_000,
        );
        assert!(matches!(
            a,
            GeofenceAssessment::CannotAssess(CannotAssess::AltitudeReferenceMismatch { .. })
        ));
    }

    #[test]
    fn a_frame_mismatch_is_reported_even_when_the_fix_is_also_stale() {
        let mut claim = inside_claim();
        claim.frame = CoordinateFrame::RegionalGrid;
        let a = GeofenceAssessment::assess(
            &region(),
            Some(&claim),
            &independent_position(),
            999_999,
            60_000,
        );
        assert!(
            matches!(
                a,
                GeofenceAssessment::CannotAssess(CannotAssess::FrameMismatch { .. })
            ),
            "the more specific structural fault is the more useful one to report"
        );
    }

    #[test]
    fn no_position_at_all_is_not_compliance() {
        let a = GeofenceAssessment::assess(&region(), None, &independent_position(), 1_500, 60_000);
        assert_eq!(
            a,
            GeofenceAssessment::CannotAssess(CannotAssess::NoPositionEvidence)
        );
        assert!(!a.asserts_compliance());
    }

    #[test]
    fn the_boundary_itself_is_inclusive_on_both_edges() {
        let r = region();
        for (lat, alt) in [
            (r.min_lat_udeg, r.min_alt_cm),
            (r.max_lat_udeg, r.max_alt_cm),
        ] {
            let mut c = inside_claim();
            c.lat_udeg = lat;
            c.alt_cm = alt;
            assert_eq!(
                GeofenceAssessment::assess(&r, Some(&c), &independent_position(), 1_500, 60_000),
                GeofenceAssessment::Compliant,
                "a point exactly on the boundary is inside the authorized region"
            );
        }
    }

    #[test]
    fn one_unit_outside_the_boundary_is_a_violation() {
        let r = region();
        let mut c = inside_claim();
        c.lat_udeg = r.max_lat_udeg + 1;
        assert_eq!(
            GeofenceAssessment::assess(&r, Some(&c), &independent_position(), 1_500, 60_000),
            GeofenceAssessment::Violation
        );
    }

    #[test]
    fn a_real_uas_deployment_can_assess_nothing() {
        // The honest end state of this module for every aircraft flying today.
        let a = GeofenceAssessment::assess(
            &region(),
            Some(&inside_claim()),
            &self_reported_position(),
            1_500,
            60_000,
        );
        assert!(matches!(a, GeofenceAssessment::CannotAssess(_)));
    }
}
