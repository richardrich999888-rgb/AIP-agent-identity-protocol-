//! What an observation must be about before it is evidence about an effect.

use aip_observation::ObservationRecord;
use aip_system::SystemId;
use aip_types::canonical::{put_bytes, put_domain, put_str, put_u8};
use serde::{Deserialize, Serialize};

use crate::EFFECT_ASSESSMENT_DOMAIN;

/// The subject an effect assessment is about.
///
/// Four of these five fields are exactly `aip_observation::ObservationCorrelation`'s,
/// deliberately: an observation and an effect must agree on *the same*
/// identifiers or the match means nothing. The fifth is the effect itself.
///
/// # Why identifiers rather than a description
///
/// A free-form target string ("the left thruster") is a join key for a human
/// and useless to a verifier: two deployments spell it differently and neither
/// spelling is bound to anything. The identifiers here are the ones the rest
/// of the system already binds — the system, the execution instance, the
/// host-boot the observer *measured*, and the decision that authorized it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectCorrelation {
    /// The autonomous system. Reused from `aip-system`; no new identifier.
    pub system_id: SystemId,
    /// The execution instance the effect was requested during.
    pub execution_id: [u8; 16],
    /// The host-boot the effect is claimed to have happened on.
    ///
    /// Checked against the boot the observer *measured*, never against one the
    /// agent reported. That is Skill 19's rule and it is not relaxed here.
    pub boot_id: [u8; 16],
    /// The decision that authorized the action, when one is claimed.
    ///
    /// `None` is a statement a verifier can act on. It is not "any decision".
    pub decision_id: Option<[u8; 16]>,
    /// The effect's own identity: the domain-separated commitment to the full
    /// parameter set, taken from the `RequestedEffect`.
    ///
    /// Carried so an assessment names which effect it is about. Note what it
    /// does **not** do: no observation mechanism in this workspace records a
    /// parameter commitment, so this cannot be matched against an observation.
    /// See [`crate::EffectBinding`] and ADR-004 — the limitation is
    /// represented rather than hidden.
    pub parameter_commitment: [u8; 32],
}

impl EffectCorrelation {
    /// Whether `record` is about this subject.
    ///
    /// All three of system, execution and measured boot must match. A record
    /// that fails any of them is **not weaker evidence about this effect** —
    /// it is evidence about something else, and is excluded rather than
    /// downgraded. Downgrading would let an attacker raise the count of
    /// "related" observations by supplying unrelated ones.
    ///
    /// `decision_id` is deliberately *not* part of the match. A record may
    /// legitimately carry `None` where the assessment names a decision: the
    /// observer records what the execution claimed, and an execution that
    /// claimed nothing still produces observations about itself. Requiring
    /// equality there would discard true evidence; see
    /// [`Self::decision_conflicts_with`] for the case that *is* a conflict.
    pub fn admits(&self, record: &ObservationRecord) -> bool {
        record.describes(&self.system_id, &self.execution_id)
            && record.measured_on(&self.boot_id)
            && !self.decision_conflicts_with(record)
    }

    /// Whether the record names a *different* decision than this assessment.
    ///
    /// Two stated decisions that disagree is a contradiction and the record is
    /// excluded. One stated and one absent is not: absence is not a
    /// competing claim.
    pub fn decision_conflicts_with(&self, record: &ObservationRecord) -> bool {
        match (self.decision_id, record.correlation.decision_id) {
            (Some(a), Some(b)) => a != b,
            _ => false,
        }
    }

    /// Domain-tagged, injective canonical bytes.
    ///
    /// Length-prefixed strings and a presence byte on the optional, so no two
    /// distinct correlations share an encoding.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, EFFECT_ASSESSMENT_DOMAIN);
        put_str(&mut buf, self.system_id.as_str());
        put_bytes(&mut buf, &self.execution_id);
        put_bytes(&mut buf, &self.boot_id);
        match &self.decision_id {
            Some(d) => {
                put_u8(&mut buf, 1);
                put_bytes(&mut buf, d);
            }
            None => put_u8(&mut buf, 0),
        }
        put_bytes(&mut buf, &self.parameter_commitment);
        buf
    }
}
