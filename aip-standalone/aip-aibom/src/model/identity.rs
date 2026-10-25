//! C1 — agent identity.

use serde::{Deserialize, Serialize};

/// Who the agent is, as the manifest's author states it.
///
/// `id` is any identifier. It is *verifiable* only when it is an AIP-ID and
/// the evidence bundle carries an identity document that derives to it; an
/// agent without one is still describable, and the assessment says that its
/// identity rests on the author's word.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentIdentity {
    pub id: String,
    pub name: String,
    pub owner: String,
    pub version: String,
    pub deployment: String,
}
