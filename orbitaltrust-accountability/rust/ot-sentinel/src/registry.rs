//! What the sentinel knows about the fleet it patrols.
//!
//! Built by replaying lifecycle anchors rather than by being told: "which
//! agents exist, on what weights, and are they still closed" are questions
//! the sealed chain already answers, and a second mutable source of truth
//! would be one more thing an attacker could edit instead of the chain.

use serde_json::Value;
use std::collections::BTreeMap;

/// How long an agent may go without reporting before its silence is a
/// finding. Deliberately long: a brief gap is ordinary, a sustained one
/// while effects keep appearing is not.
pub const DEFAULT_HEARTBEAT_DEADLINE_MILLIS: i64 = 300_000;

/// What the chain says about one agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownAgent {
    /// The DID.
    pub did: String,
    /// The weights the chain currently binds: genesis, superseded by the
    /// newest model migration.
    pub model_digest: Option<String>,
    /// Whether a terminal revocation closed the lifecycle.
    pub closed: bool,
    /// Timestamp of the newest anchor on its chain.
    pub last_anchor_utc: Option<String>,
    /// Timestamp of the newest heartbeat observed, filled in by the patrol.
    pub last_heartbeat_utc: Option<String>,
}

impl KnownAgent {
    /// True when the agent should be doing nothing at all.
    pub fn should_be_dormant(&self) -> bool {
        self.closed
    }
}

/// The fleet, as the lifecycle chain describes it.
#[derive(Debug, Clone, Default)]
pub struct AgentRegistry {
    agents: BTreeMap<String, KnownAgent>,
}

impl AgentRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuilds the fleet by replaying lifecycle anchors in chain order.
    ///
    /// Anchors after a terminal revocation are applied to the `closed` flag
    /// but never reopen it: a closed lifecycle stays closed, so an attacker
    /// appending a second genesis cannot resurrect a revoked identity in the
    /// sentinel's view of the world.
    pub fn from_anchors(anchors: &[Value]) -> Self {
        let mut registry = Self::new();
        for anchor in anchors {
            registry.apply_anchor(anchor);
        }
        registry
    }

    /// Applies one lifecycle anchor.
    pub fn apply_anchor(&mut self, anchor: &Value) {
        let Some(did) = anchor.get("agentDid").and_then(Value::as_str) else {
            return;
        };
        let anchor_type = anchor
            .get("anchorType")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let timestamp = anchor
            .get("timestampUtc")
            .and_then(Value::as_str)
            .map(str::to_string);

        let entry = self
            .agents
            .entry(did.to_string())
            .or_insert_with(|| KnownAgent {
                did: did.to_string(),
                model_digest: None,
                closed: false,
                last_anchor_utc: None,
                last_heartbeat_utc: None,
            });
        if timestamp.is_some() {
            entry.last_anchor_utc = timestamp;
        }

        match anchor_type {
            "AGENT_GENESIS" | "MODEL_VERSION_MIGRATION" => {
                // A closed lifecycle takes no rebinding: once terminal,
                // nothing appended can change what the agent may run.
                if !entry.closed {
                    if let Some(digest) = anchor
                        .pointer("/payload/modelDigest")
                        .and_then(Value::as_str)
                    {
                        entry.model_digest = Some(digest.to_string());
                    }
                }
            }
            "AUTHORITY_REVOCATION"
                if anchor
                    .pointer("/payload/terminal")
                    .and_then(Value::as_bool)
                    .unwrap_or(false) =>
            {
                entry.closed = true;
            }
            _ => {}
        }
    }

    /// Records that an agent reported itself alive.
    pub fn record_heartbeat(&mut self, did: &str, at_utc: &str) {
        if let Some(agent) = self.agents.get_mut(did) {
            let newer = agent
                .last_heartbeat_utc
                .as_deref()
                .is_none_or(|held| at_utc > held);
            if newer {
                agent.last_heartbeat_utc = Some(at_utc.to_string());
            }
        }
    }

    /// Looks up one agent.
    pub fn get(&self, did: &str) -> Option<&KnownAgent> {
        self.agents.get(did)
    }

    /// True when the chain has never heard of this DID.
    pub fn is_unknown(&self, did: &str) -> bool {
        !self.agents.contains_key(did)
    }

    /// Every known agent.
    pub fn iter(&self) -> impl Iterator<Item = &KnownAgent> {
        self.agents.values()
    }

    /// How many agents are known.
    pub fn len(&self) -> usize {
        self.agents.len()
    }

    /// True when no agent is known.
    pub fn is_empty(&self) -> bool {
        self.agents.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const AGENT: &str = "did:syntriass:agent:AGT-1";

    fn anchor(seq: u64, kind: &str, payload: Value, ts: &str) -> Value {
        json!({
            "anchorId": format!("{AGENT}#anchor-{seq}"),
            "sequenceNumber": seq,
            "anchorType": kind,
            "agentDid": AGENT,
            "timestampUtc": ts,
            "payload": payload,
        })
    }

    #[test]
    fn replaying_a_lifecycle_yields_the_agents_current_binding() {
        let anchors = [
            anchor(
                1,
                "AGENT_GENESIS",
                json!({ "modelDigest": "a".repeat(64) }),
                "2026-08-01T00:00:00.000Z",
            ),
            anchor(
                2,
                "MODEL_VERSION_MIGRATION",
                json!({ "modelDigest": "b".repeat(64) }),
                "2026-08-15T00:00:00.000Z",
            ),
        ];
        let registry = AgentRegistry::from_anchors(&anchors);
        let agent = registry.get(AGENT).unwrap();
        assert_eq!(agent.model_digest, Some("b".repeat(64)));
        assert!(!agent.closed);
        assert_eq!(
            agent.last_anchor_utc.as_deref(),
            Some("2026-08-15T00:00:00.000Z")
        );
        assert!(registry.is_unknown("did:syntriass:agent:GHOST"));
    }

    #[test]
    fn a_closed_lifecycle_cannot_be_reopened_by_appending_to_the_chain() {
        let anchors = [
            anchor(
                1,
                "AGENT_GENESIS",
                json!({ "modelDigest": "a".repeat(64) }),
                "2026-08-01T00:00:00.000Z",
            ),
            anchor(
                2,
                "AUTHORITY_REVOCATION",
                json!({ "terminal": true, "reason": "kill switch" }),
                "2026-08-02T00:00:00.000Z",
            ),
            // An attacker appends a fresh genesis and a migration.
            anchor(
                3,
                "AGENT_GENESIS",
                json!({ "modelDigest": "c".repeat(64) }),
                "2026-08-03T00:00:00.000Z",
            ),
            anchor(
                4,
                "MODEL_VERSION_MIGRATION",
                json!({ "modelDigest": "d".repeat(64) }),
                "2026-08-04T00:00:00.000Z",
            ),
        ];
        let registry = AgentRegistry::from_anchors(&anchors);
        let agent = registry.get(AGENT).unwrap();
        assert!(agent.closed, "a terminal revocation is terminal");
        assert!(agent.should_be_dormant());
        // And the weights it may run were not rebound after closure.
        assert_eq!(agent.model_digest, Some("a".repeat(64)));
    }

    #[test]
    fn a_non_terminal_revocation_does_not_close_the_lifecycle() {
        let anchors = [
            anchor(
                1,
                "AGENT_GENESIS",
                json!({ "modelDigest": "a".repeat(64) }),
                "2026-08-01T00:00:00.000Z",
            ),
            anchor(
                2,
                "AUTHORITY_REVOCATION",
                json!({ "terminal": false, "reason": "scope trimmed" }),
                "2026-08-02T00:00:00.000Z",
            ),
        ];
        let registry = AgentRegistry::from_anchors(&anchors);
        assert!(!registry.get(AGENT).unwrap().closed);
    }

    #[test]
    fn heartbeats_only_move_forward_and_only_for_known_agents() {
        let anchors = [anchor(
            1,
            "AGENT_GENESIS",
            json!({ "modelDigest": "a".repeat(64) }),
            "2026-08-01T00:00:00.000Z",
        )];
        let mut registry = AgentRegistry::from_anchors(&anchors);
        registry.record_heartbeat(AGENT, "2026-08-27T12:00:00.000Z");
        registry.record_heartbeat(AGENT, "2026-08-27T12:05:00.000Z");
        // A late-arriving older beat must not rewind the clock, or an
        // attacker could replay an old heartbeat to mask a silent agent.
        registry.record_heartbeat(AGENT, "2026-08-27T11:00:00.000Z");
        assert_eq!(
            registry.get(AGENT).unwrap().last_heartbeat_utc.as_deref(),
            Some("2026-08-27T12:05:00.000Z")
        );

        // A heartbeat from a DID the chain never saw creates nothing: an
        // unknown agent asserting liveness does not make it known.
        registry.record_heartbeat("did:syntriass:agent:GHOST", "2026-08-27T12:00:00.000Z");
        assert!(registry.is_unknown("did:syntriass:agent:GHOST"));
        assert_eq!(registry.len(), 1);
    }
}
