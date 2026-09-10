//! How a platform binding was established — and what each method is worth.
//!
//! The method is not decoration. It is the difference between "the agent said
//! so" and "an anchored observer measured it", and a model that records a
//! binding without recording how it was reached has thrown away the only
//! thing that makes the binding meaningful.

use aip_types::canonical::put_u8;
use serde::{Deserialize, Serialize};

/// The means by which an execution was associated with a platform.
///
/// Ordered by what it establishes, weakest first, and `Ord` follows that
/// ordering deliberately so a caller can ask "is this at least as strong as".
/// It is **not** an evidence-strength ladder and does not map onto one:
/// `EvidenceStrength` is per-record and the reconciler assigns it alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BindingMethod {
    /// The agent said which platform it was on.
    ///
    /// Establishes **nothing**. It is representable because a claim worth
    /// comparing is worth recording, and because a model that cannot express
    /// an untrusted claim invites callers to launder one into a trusted slot.
    SelfDeclared,
    /// The verifier's own registry maps the observed host-boot to a platform.
    ///
    /// Establishes: *an anchored observer measured this execution on a
    /// host-boot the verifier has registered as this platform.* Inherits the
    /// verifier's trust model — the same model that anchors issuer and
    /// observer keys — rather than improving on it.
    ///
    /// This is what Skill 19 implements, and its ceiling.
    DeploymentRegistry,
    /// A hardware root of trust attested the identity.
    ///
    /// **Reserved and unreachable.** No constructor produces it: see
    /// [`BindingMethod::is_implemented`]. It exists in the enum so that its
    /// absence is *visible in the model* — a reader can see there is a rung
    /// above the registry and that nothing occupies it — rather than being
    /// silently missing and later mistaken for unnecessary.
    ///
    /// Implementing it requires ADR-002 to move to ACCEPTED, because it is a
    /// new trust anchor.
    HardwareAttested,
}

impl BindingMethod {
    /// Stable wire code, assigned explicitly so reordering the variants
    /// cannot change what previously encoded bytes mean.
    pub fn code(self) -> u8 {
        match self {
            Self::SelfDeclared => 0x01,
            Self::DeploymentRegistry => 0x02,
            Self::HardwareAttested => 0x03,
        }
    }

    /// Whether this build can actually produce a binding by this method.
    ///
    /// `HardwareAttested` is `false` and must stay so until ADR-002 is
    /// accepted. A caller that finds this returning `true` for it is running
    /// against a build where a new trust anchor was introduced.
    pub fn is_implemented(self) -> bool {
        !matches!(self, Self::HardwareAttested)
    }

    /// Whether a binding by this method rests on something outside the
    /// subject.
    ///
    /// `SelfDeclared` is the only `false`, and that is the whole distinction:
    /// a claim by the thing being described is not evidence about it.
    pub fn is_independent(self) -> bool {
        !matches!(self, Self::SelfDeclared)
    }

    pub fn encode(self, buf: &mut Vec<u8>) {
        put_u8(buf, self.code());
    }
}
