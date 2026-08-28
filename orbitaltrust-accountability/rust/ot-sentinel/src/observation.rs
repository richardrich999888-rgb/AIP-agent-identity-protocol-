//! What the world saw, independently of what the ledger claims.
//!
//! An [`Observation`] comes from a sensor *outside* the governed channel — a
//! tool server's own access log, an egress proxy, a host process monitor, a
//! cloud audit trail. That independence is the whole point. Evidence sealed
//! by the gateway describes what went through the gateway; an observation
//! describes what actually happened. A ghost agent is exactly the gap between
//! the two, and nothing that only reads the ledger can ever see it.
//!
//! # Sensor integrity bounds every conclusion
//!
//! A finding can be no stronger than the sensor that produced it. A sensor
//! the operator has not vouched for might be reporting effects that never
//! occurred, so [`Sensor::trusted`] gates whether its observations can
//! support [`crate::finding::Strength::Proof`] — and therefore whether they
//! can ever justify automatic enforcement. An untrusted sensor still raises
//! alerts for a human; it simply cannot, by itself, get an agent quarantined.

use ot_accountability_core::{canonical_json, sha256_hex};
use serde_json::Value;

/// Something that happened in the world.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// A tool ran. `params_digest` is SHA-256 of the canonical JSON of the
    /// arguments, which is what lets an observation be matched to the exact
    /// sealed packet rather than merely to "some call of this tool".
    ToolInvocation {
        /// Tool name as the upstream server saw it.
        tool: String,
        /// SHA-256 of canonical JSON of the arguments.
        params_digest: String,
    },
    /// Content was read into an agent's context.
    ResourceRead {
        /// Where it came from.
        uri: String,
        /// SHA-256 of the content.
        content_digest: String,
    },
    /// Bytes left the trust boundary.
    NetworkEgress {
        /// Host or address they went to.
        destination: String,
        /// How many.
        bytes: u64,
    },
    /// A process was launched.
    ProcessSpawn {
        /// The command line.
        command: String,
    },
    /// An agent reported itself alive on the weights it claims to run.
    Heartbeat {
        /// SHA-256 of the weights the runtime reports.
        model_digest: String,
    },
}

impl Effect {
    /// A short label for reports.
    pub fn label(&self) -> &'static str {
        match self {
            Self::ToolInvocation { .. } => "tool-invocation",
            Self::ResourceRead { .. } => "resource-read",
            Self::NetworkEgress { .. } => "network-egress",
            Self::ProcessSpawn { .. } => "process-spawn",
            Self::Heartbeat { .. } => "heartbeat",
        }
    }

    /// True when this effect changed something outside the agent — the class
    /// that must never occur without sealed evidence behind it.
    pub fn is_consequential(&self) -> bool {
        matches!(
            self,
            Self::ToolInvocation { .. } | Self::NetworkEgress { .. } | Self::ProcessSpawn { .. }
        )
    }

    /// A one-line description for a finding's summary.
    pub fn describe(&self) -> String {
        match self {
            Self::ToolInvocation { tool, .. } => format!("invocation of \"{tool}\""),
            Self::ResourceRead { uri, .. } => format!("read of {uri}"),
            Self::NetworkEgress { destination, bytes } => {
                format!("{bytes} bytes egressed to {destination}")
            }
            Self::ProcessSpawn { command } => format!("process spawn: {command}"),
            Self::Heartbeat { .. } => "heartbeat".to_string(),
        }
    }
}

/// Whose effect this was, as far as the sensor could tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    /// An agent DID was presented. Presented, not proven — that a caller
    /// claims a DID is exactly what a ghost impersonating a live agent would
    /// also do, so the claim is a lead, never a conclusion.
    Claimed(String),
    /// No identity was presented at all. The strongest ghost signal there is
    /// for a consequential effect: something acted, and nothing on the wire
    /// says who.
    Anonymous,
}

impl Subject {
    /// The DID, when one was claimed.
    pub fn did(&self) -> Option<&str> {
        match self {
            Self::Claimed(did) => Some(did),
            Self::Anonymous => None,
        }
    }
}

/// One thing a sensor saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// Sensor-local identifier, cited in findings so an operator can go back
    /// to the raw log line.
    pub id: String,
    /// Name of the sensor that reported it.
    pub sensor: String,
    /// ISO-8601 UTC.
    pub observed_at_utc: String,
    /// Who, as far as the sensor could tell.
    pub subject: Subject,
    /// What happened.
    pub effect: Effect,
}

impl Observation {
    /// A tool invocation observed from a server-side log.
    pub fn tool_invocation(
        id: impl Into<String>,
        sensor: impl Into<String>,
        observed_at_utc: impl Into<String>,
        subject: Subject,
        tool: impl Into<String>,
        params: &Value,
    ) -> Self {
        Self {
            id: id.into(),
            sensor: sensor.into(),
            observed_at_utc: observed_at_utc.into(),
            subject,
            effect: Effect::ToolInvocation {
                tool: tool.into(),
                // Digested with the same canonical bytes the packet uses, so
                // the two are comparable without either side re-encoding.
                params_digest: digest_params(params),
            },
        }
    }

    /// Bytes leaving the trust boundary, observed from an egress proxy or a
    /// socket-layer monitor.
    ///
    /// Unlike [`Observation::tool_invocation`] there is no parameter digest
    /// to key reconciliation on, which is exactly why egress is judged by
    /// [`EffectConformanceDetector`](crate::detector::EffectConformanceDetector)
    /// against a declared allowlist instead: there is no sealed packet for it
    /// to match against, so conformance is the only question that can be
    /// asked of it.
    pub fn network_egress(
        id: impl Into<String>,
        sensor: impl Into<String>,
        observed_at_utc: impl Into<String>,
        subject: Subject,
        destination: impl Into<String>,
        bytes: u64,
    ) -> Self {
        Self {
            id: id.into(),
            sensor: sensor.into(),
            observed_at_utc: observed_at_utc.into(),
            subject,
            effect: Effect::NetworkEgress {
                destination: destination.into(),
                bytes,
            },
        }
    }

    /// A process launch, observed from an exec monitor.
    pub fn process_spawn(
        id: impl Into<String>,
        sensor: impl Into<String>,
        observed_at_utc: impl Into<String>,
        subject: Subject,
        command: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            sensor: sensor.into(),
            observed_at_utc: observed_at_utc.into(),
            subject,
            effect: Effect::ProcessSpawn {
                command: command.into(),
            },
        }
    }

    /// A heartbeat observed from an agent runtime.
    pub fn heartbeat(
        id: impl Into<String>,
        sensor: impl Into<String>,
        observed_at_utc: impl Into<String>,
        agent_did: impl Into<String>,
        model_digest: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            sensor: sensor.into(),
            observed_at_utc: observed_at_utc.into(),
            subject: Subject::Claimed(agent_did.into()),
            effect: Effect::Heartbeat {
                model_digest: model_digest.into(),
            },
        }
    }
}

/// SHA-256 of the canonical JSON of a parameter object — the same bytes the
/// sealed packet hashes, which is what makes observation and evidence
/// comparable at all.
pub fn digest_params(params: &Value) -> String {
    sha256_hex(&canonical_json(params))
}

/// A registered source of observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sensor {
    /// Sensor name, matching [`Observation::sensor`].
    pub name: String,
    /// Whether the operator vouches for this sensor's integrity.
    ///
    /// Only a trusted sensor's observations can support
    /// [`crate::finding::Strength::Proof`], and therefore only a trusted
    /// sensor can put an agent in line for automatic quarantine. An
    /// unregistered sensor is untrusted by default.
    pub trusted: bool,
    /// Tool names this sensor claims to observe completely.
    ///
    /// Only within this set can silence be read as absence — that is what
    /// makes phantom-evidence detection sound. A sensor that declares nothing
    /// makes no completeness claim, and no phantom findings are drawn from it.
    pub covers_tools: Vec<String>,
}

impl Sensor {
    /// An untrusted sensor claiming no coverage: alerts only.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            trusted: false,
            covers_tools: Vec::new(),
        }
    }

    /// Marks the sensor's integrity as vouched for by the operator.
    pub fn trusted(mut self) -> Self {
        self.trusted = true;
        self
    }

    /// Declares that this sensor sees every invocation of these tools.
    pub fn covering(mut self, tools: &[&str]) -> Self {
        self.covers_tools = tools.iter().map(|t| t.to_string()).collect();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_params_digest_matches_the_bytes_a_sealed_packet_hashes() {
        // Key order differs between the two renderings; canonical JSON makes
        // them the same bytes, which is what the reconciliation relies on.
        let a = json!({ "target": "ALL", "command": "DEORBIT" });
        let b = json!({ "command": "DEORBIT", "target": "ALL" });
        assert_eq!(digest_params(&a), digest_params(&b));
        assert_ne!(
            digest_params(&a),
            digest_params(&json!({ "command": "SAFE" }))
        );
        assert_eq!(digest_params(&a).len(), 64);
    }

    #[test]
    fn consequential_effects_are_the_ones_that_reach_outside_the_agent() {
        assert!(Effect::ToolInvocation {
            tool: "t".into(),
            params_digest: "d".into()
        }
        .is_consequential());
        assert!(Effect::NetworkEgress {
            destination: "x".into(),
            bytes: 1
        }
        .is_consequential());
        assert!(Effect::ProcessSpawn {
            command: "sh".into()
        }
        .is_consequential());
        // Reading and reporting change nothing outside; they are context, not
        // action, and must not be treated as unattributed effects.
        assert!(!Effect::Heartbeat {
            model_digest: "d".into()
        }
        .is_consequential());
        assert!(!Effect::ResourceRead {
            uri: "u".into(),
            content_digest: "d".into()
        }
        .is_consequential());
    }

    #[test]
    fn a_sensor_is_untrusted_and_claims_no_coverage_until_told_otherwise() {
        let plain = Sensor::new("tool-server-log");
        assert!(!plain.trusted);
        assert!(plain.covers_tools.is_empty());

        let vouched = Sensor::new("tool-server-log")
            .trusted()
            .covering(&["send_command"]);
        assert!(vouched.trusted);
        assert_eq!(vouched.covers_tools, ["send_command"]);
    }
}
