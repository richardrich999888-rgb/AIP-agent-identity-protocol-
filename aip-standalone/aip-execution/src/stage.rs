//! The stage ladder: the ordered epistemic boundaries of one execution.
//!
//! Execution is not one event. It is a sequence of boundaries, each visible to
//! a different party and forgeable by an attacker at a different position.
//! Collapsing any two is how a system ends up believing its own agent.
//!
//! This module makes the ladder executable. Before it, the ladder existed only
//! as prose spread across crate documentation — which means nothing checked it.

use aip_types::canonical::put_u8;
use serde::{Deserialize, Serialize};

/// Where a statement made at a given stage comes from.
///
/// # This is not `EvidenceStrength`
///
/// The distinction matters enough to state twice. `EvidenceStrength`
/// (`Heuristic` … `Proven`) is *how certain*, is computed per record, and is
/// assigned by the reconciliation engine and by nothing else. `EvidenceOrigin`
/// is *which boundary the statement crossed*, is a static property of a stage,
/// and is computed for nothing.
///
/// Two axes, one owner each. This crate never computes strength and never asks
/// the reconciler for one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EvidenceOrigin {
    /// Configuration or tasking: what someone said would happen.
    Declared,
    /// Authored inside the process under scrutiny. Signing it establishes
    /// authorship and integrity; it never establishes occurrence, because a
    /// compromised agent signs exactly as a healthy one does.
    SelfReported,
    /// Measured by an anchored observer outside the subject.
    IndependentlyObserved,
    /// Recomputable by a third party from bytes it holds — signature and hash
    /// arithmetic. The only origin that survives a compromised host.
    Recomputable,
}

impl EvidenceOrigin {
    pub fn code(self) -> u8 {
        match self {
            Self::Declared => 0x01,
            Self::SelfReported => 0x02,
            Self::IndependentlyObserved => 0x03,
            Self::Recomputable => 0x04,
        }
    }

    /// Whether a statement of this origin may, on its own, establish that
    /// something *occurred* outside the subject.
    ///
    /// `false` for `Declared` and `SelfReported`, and that is the whole point:
    /// it is the machine-checkable form of "a self-report is not evidence".
    pub fn can_establish_occurrence(self) -> bool {
        matches!(self, Self::IndependentlyObserved | Self::Recomputable)
    }
}

/// The twelve boundaries, in order.
///
/// Ordered because the ordering is load-bearing: a stage may only be reached
/// from an earlier one, and no stage's statement carries to the next
/// automatically. The `Ord` derive follows declaration order deliberately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ExecutionStage {
    /// What an operator or tasking system asked for.
    ExecutionIntent,
    /// The signed authority chain behind the request.
    Authorization,
    /// What a decision point authorized, signed by it.
    ExpectedExecution,
    /// What the agent says it decided to do.
    AiClaim,
    /// What the agent says it asked a model.
    ModelInvocation,
    /// What the agent says it asked a tool.
    ToolInvocation,
    /// What the agent's runtime says came back.
    RuntimeExecution,
    /// What the OS shows about the process instance.
    ProcessExecution,
    /// What the platform or device shows.
    PlatformInteraction,
    /// What happened outside the host.
    ExternalEffect,
    /// What an anchored observer measured.
    IndependentObservation,
    /// The one engine's comparison of expected with observed.
    Reconciliation,
}

impl ExecutionStage {
    /// Stable wire code, assigned explicitly. Reordering the variants must not
    /// change what previously encoded bytes mean.
    pub fn code(self) -> u8 {
        match self {
            Self::ExecutionIntent => 0x01,
            Self::Authorization => 0x02,
            Self::ExpectedExecution => 0x03,
            Self::AiClaim => 0x04,
            Self::ModelInvocation => 0x05,
            Self::ToolInvocation => 0x06,
            Self::RuntimeExecution => 0x07,
            Self::ProcessExecution => 0x08,
            Self::PlatformInteraction => 0x09,
            Self::ExternalEffect => 0x0A,
            Self::IndependentObservation => 0x0B,
            Self::Reconciliation => 0x0C,
        }
    }

    /// What kind of statement this stage produces, by construction.
    ///
    /// Stages 4-7 are all `SelfReported` because they are all authored inside
    /// the process under scrutiny. That is not a comment about trust levels;
    /// it is a fact about who holds the pen.
    pub fn origin(self) -> EvidenceOrigin {
        use EvidenceOrigin::*;
        match self {
            Self::ExecutionIntent => Declared,
            // Signatures over a delegation chain are recomputable arithmetic.
            Self::Authorization | Self::ExpectedExecution => Recomputable,
            // Everything the agent authors about itself.
            Self::AiClaim
            | Self::ModelInvocation
            | Self::ToolInvocation
            | Self::RuntimeExecution => SelfReported,
            Self::ProcessExecution
            | Self::PlatformInteraction
            | Self::ExternalEffect
            | Self::IndependentObservation => IndependentlyObserved,
            // The engine's verdict is re-derivable from the record.
            Self::Reconciliation => Recomputable,
        }
    }

    /// Every stage, in order. Exposed so a caller sweeping the ladder cannot
    /// silently miss one that is added later.
    pub const ALL: [ExecutionStage; 12] = [
        Self::ExecutionIntent,
        Self::Authorization,
        Self::ExpectedExecution,
        Self::AiClaim,
        Self::ModelInvocation,
        Self::ToolInvocation,
        Self::RuntimeExecution,
        Self::ProcessExecution,
        Self::PlatformInteraction,
        Self::ExternalEffect,
        Self::IndependentObservation,
        Self::Reconciliation,
    ];

    /// Whether a statement at `self` may, on its own, establish a statement at
    /// `later`.
    ///
    /// The answer is almost always no, and the exceptions are narrow: a stage
    /// establishes only itself, unless the later stage's origin can be reached
    /// from this one's. A self-report never reaches an independently observed
    /// stage — which is the encoding of
    /// `tool success ≠ external effect` and `model claim ≠ runtime evidence`.
    pub fn may_establish(self, later: ExecutionStage) -> bool {
        if self == later {
            return true;
        }
        if later < self {
            return false;
        }
        // Crossing into a stage whose statements must come from outside the
        // subject requires having come from outside the subject.
        !later.origin().can_establish_occurrence() || self.origin().can_establish_occurrence()
    }

    pub fn encode(self, buf: &mut Vec<u8>) {
        put_u8(buf, self.code());
    }
}
