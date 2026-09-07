//! Refusals. Every variant is a path the profile declined to take.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpaceError {
    /// A structure carried a version this build does not implement.
    UnsupportedVersion { found: u16, supported: u16 },
    /// A field that participates in a security decision was malformed.
    Malformed { reason: &'static str },
    /// A profile tried to declare a ceiling above what the class allows.
    CeilingRaised {
        class: aip_observation::ObservationClass,
    },
    /// A bundle carrying a non-contiguous segment run was offered.
    ///
    /// A bundle is a *container for a contiguous run*. One with a hole in it is
    /// two bundles pretending to be one, and accepting it would let a sender
    /// choose which gap a verifier notices.
    BundleNotContiguous { expected: u64, found: u64 },
    /// A bundle whose stated segment range does not match its contents.
    BundleRangeMismatch {
        declared_first: u64,
        declared_last: u64,
        actual_len: usize,
    },
    /// A bundle already admitted at this ground station.
    ///
    /// Replay across contacts: a previously seen bundle does not become fresh
    /// by being presented after reconnection.
    BundleAlreadySeen { digest: [u8; 32] },
    /// The continuity ledger refused the segment. Carried through, never
    /// repaired: the profile has no authority to overrule it.
    ContinuityRefused { fault: aip_observe::ContinuityFault },
    /// A gap was declared filled without supplying the sequences it names.
    ///
    /// The central refusal of this profile. A gap is closed by the missing
    /// evidence arriving, and by nothing else — not by reconnection, not by a
    /// later segment, and not by an operator saying so.
    GapNotFilled { missing: Vec<u64> },
    /// A time ordering was asserted that the trust model cannot establish.
    UnestablishableOrdering { reason: &'static str },
}

impl fmt::Display for SpaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { found, supported } => write!(
                f,
                "space profile version {found} is not implemented by this build \
                 (supported: {supported}); refusing rather than guessing what the fields mean"
            ),
            Self::Malformed { reason } => write!(f, "{reason}"),
            Self::CeilingRaised { class } => write!(
                f,
                "the space profile tried to raise the ceiling of {class:?}; a profile may lower \
                 a ceiling and may never raise one"
            ),
            Self::BundleNotContiguous { expected, found } => write!(
                f,
                "the bundle's segments jump from an expected {expected} to {found}; a bundle \
                 carries one contiguous run, and one with a hole in it lets a sender choose \
                 which gap a verifier notices"
            ),
            Self::BundleRangeMismatch {
                declared_first,
                declared_last,
                actual_len,
            } => write!(
                f,
                "the bundle declares segments {declared_first}..={declared_last} and carries \
                 {actual_len}; a truncated bundle is refused, never partially accepted"
            ),
            Self::BundleAlreadySeen { digest } => write!(
                f,
                "bundle {} was already admitted; a previously seen bundle does not become fresh \
                 by arriving after a reconnection",
                hex16(digest)
            ),
            Self::ContinuityRefused { fault } => write!(
                f,
                "the continuity ledger refused the segment: {fault:?}; this profile carries the \
                 refusal through and has no authority to repair it"
            ),
            Self::GapNotFilled { missing } => write!(
                f,
                "sequences {missing:?} are still missing; a gap is closed by the missing evidence \
                 arriving and by nothing else — not by reconnection, and not by later evidence"
            ),
            Self::UnestablishableOrdering { reason } => write!(f, "{reason}"),
        }
    }
}

/// First eight bytes of a digest, for messages. Never a security decision.
fn hex16(d: &[u8; 32]) -> String {
    d.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

impl std::error::Error for SpaceError {}

impl From<aip_observation::ObservationError> for SpaceError {
    fn from(e: aip_observation::ObservationError) -> Self {
        match e {
            aip_observation::ObservationError::CeilingRaised { class } => {
                Self::CeilingRaised { class }
            }
            aip_observation::ObservationError::UnsupportedVersion { found, supported } => {
                Self::UnsupportedVersion { found, supported }
            }
            aip_observation::ObservationError::Malformed { reason } => Self::Malformed { reason },
            aip_observation::ObservationError::ObserverNotTrusted { .. } => Self::Malformed {
                reason: "the observation batch did not verify against the verifier's anchors",
            },
        }
    }
}
