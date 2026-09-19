//! What holds a claim up.
//!
//! The six classes the specification names, in strength order. The ordering
//! is the point: a matrix cell may be *demoted* by a reviewer who disagrees
//! with a label, but nothing in this crate promotes one.

use serde::{Deserialize, Serialize};

/// The evidence behind one conformance cell.
///
/// Ordered weakest-last. `Unknown` is not the absence of a label — it is the
/// statement that the question was asked and not answered, which is different
/// from a cell that was never reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EvidenceClass {
    /// Real processes on this host, observed by a separate process.
    ExecutionProven,
    /// A test executed and asserted the property.
    TestProven,
    /// The property is enforced by the code's shape — a private field, a
    /// sealed constructor, a non-overridable method — and read by inspection.
    CodeProven,
    /// Stated in an architecture document or ADR, not executed.
    Documented,
    /// Follows from something proven, but was not itself checked.
    Inferred,
    /// Asked and not answered.
    Unknown,
}

impl EvidenceClass {
    /// Stable code, assigned explicitly so reordering the variants cannot
    /// change what a previously emitted artifact meant.
    pub fn code(self) -> u8 {
        match self {
            Self::ExecutionProven => 0x01,
            Self::TestProven => 0x02,
            Self::CodeProven => 0x03,
            Self::Documented => 0x04,
            Self::Inferred => 0x05,
            Self::Unknown => 0x06,
        }
    }

    pub const ALL: [EvidenceClass; 6] = [
        Self::ExecutionProven,
        Self::TestProven,
        Self::CodeProven,
        Self::Documented,
        Self::Inferred,
        Self::Unknown,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExecutionProven => "EXECUTION-PROVEN",
            Self::TestProven => "TEST-PROVEN",
            Self::CodeProven => "CODE-PROVEN",
            Self::Documented => "DOCUMENTED",
            Self::Inferred => "INFERRED",
            Self::Unknown => "UNKNOWN",
        }
    }

    /// Whether this class is strong enough to support a *supported-domain*
    /// claim.
    ///
    /// `Documented`, `Inferred` and `Unknown` are not. A domain whose
    /// invariants rest on prose is a domain whose invariants were not
    /// checked, and the acceptance gate says all supported domains pass the
    /// same core invariants — not that all supported domains have been
    /// written about.
    pub fn supports_a_conformance_claim(self) -> bool {
        matches!(
            self,
            Self::ExecutionProven | Self::TestProven | Self::CodeProven
        )
    }
}
