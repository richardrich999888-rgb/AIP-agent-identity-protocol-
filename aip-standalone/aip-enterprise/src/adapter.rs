//! Thin framework adapters, and the reason a framework name buys nothing.
//!
//! # The existing pattern, reused
//!
//! `aip-airi::FrameworkIdentity` already carries a framework's name, its
//! version and the adapter's version, and its own documentation says it is
//! **not a trust input**: nothing in that crate branches on `name` to grant
//! anything. This module keeps that property one layer up.
//!
//! An adapter translates a framework's events into the profile's vocabulary. It
//! has no way to declare a ceiling, no way to assert an effect and no way to
//! mark itself trusted — there is no method for any of those, so introducing
//! one is a visible change rather than a flag.
//!
//! # Why the adapter version is committed
//!
//! A changed translation is a changed claim. Two runs of the same framework at
//! the same version, mapped by two different adapter versions, are two
//! different statements about what happened, and
//! [`crate::binding::framework_commitment`] covers all three strings so a
//! verifier can refuse a mapping it does not know.

use aip_airi::FrameworkIdentity;
use aip_observation::EvidenceCeiling;

use crate::resource::EnterpriseResource;
use crate::source::EnterpriseSource;

/// A deployment's translation from one framework's events into this profile.
pub trait EnterpriseAdapter {
    /// The framework this adapter speaks, with its own and the adapter's
    /// version.
    fn framework(&self) -> FrameworkIdentity;

    /// Which resource an event concerns. The adapter's one real decision.
    fn resource_of(&self, event_kind: &str) -> Option<EnterpriseResource>;

    /// The evidence source an adapter's own output is.
    ///
    /// Fixed at `FrameworkTrace` for every adapter, and not overridable. An
    /// adapter reads the framework's own instrumentation, which runs inside the
    /// workload; letting an adapter declare itself a different source is
    /// exactly how a self-report becomes independent evidence by assertion.
    fn source(&self) -> EnterpriseSource {
        EnterpriseSource::FrameworkTrace
    }

    /// The strongest evidence anything this adapter produces could carry.
    ///
    /// Delegates to the source's ceiling, which is `Corroborative`. Not
    /// overridable, for the same reason.
    fn ceiling(&self) -> EvidenceCeiling {
        self.source().ceiling()
    }

    /// Whether this adapter's framework grants any authority.
    ///
    /// `false`, and not overridable. A popular framework earns nothing here.
    fn framework_grants_authority(&self) -> bool {
        false
    }
}

/// A LangGraph-shaped adapter.
#[derive(Debug, Clone)]
pub struct GraphFrameworkAdapter {
    pub framework_version: String,
    pub adapter_version: String,
}

impl EnterpriseAdapter for GraphFrameworkAdapter {
    fn framework(&self) -> FrameworkIdentity {
        FrameworkIdentity {
            name: "langgraph".to_owned(),
            version: self.framework_version.clone(),
            adapter_version: self.adapter_version.clone(),
        }
    }

    fn resource_of(&self, event_kind: &str) -> Option<EnterpriseResource> {
        match event_kind {
            "node_start" | "graph_start" => Some(EnterpriseResource::Agent),
            "llm_call" => Some(EnterpriseResource::Model),
            "tool_call" => Some(EnterpriseResource::Tool),
            _ => None,
        }
    }
}

/// A multi-agent conversation framework adapter.
#[derive(Debug, Clone)]
pub struct ConversationFrameworkAdapter {
    pub framework_version: String,
    pub adapter_version: String,
}

impl EnterpriseAdapter for ConversationFrameworkAdapter {
    fn framework(&self) -> FrameworkIdentity {
        FrameworkIdentity {
            name: "autogen".to_owned(),
            version: self.framework_version.clone(),
            adapter_version: self.adapter_version.clone(),
        }
    }

    fn resource_of(&self, event_kind: &str) -> Option<EnterpriseResource> {
        match event_kind {
            "agent_message" => Some(EnterpriseResource::Agent),
            "model_client_call" => Some(EnterpriseResource::Model),
            "function_call" => Some(EnterpriseResource::Tool),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph() -> GraphFrameworkAdapter {
        GraphFrameworkAdapter {
            framework_version: "0.2.1".into(),
            adapter_version: "vanian-1".into(),
        }
    }

    fn conversation() -> ConversationFrameworkAdapter {
        ConversationFrameworkAdapter {
            framework_version: "0.4.0".into(),
            adapter_version: "vanian-1".into(),
        }
    }

    #[test]
    fn no_adapter_grants_authority_or_raises_a_ceiling() {
        assert!(!graph().framework_grants_authority());
        assert!(!conversation().framework_grants_authority());
        assert_eq!(graph().ceiling(), EvidenceCeiling::Corroborative);
        assert_eq!(conversation().ceiling(), EvidenceCeiling::Corroborative);
        assert_eq!(graph().ceiling(), conversation().ceiling());
    }

    #[test]
    fn every_adapter_is_a_framework_trace_and_cannot_say_otherwise() {
        // The one thing an adapter must not be able to declare about itself.
        assert_eq!(graph().source(), EnterpriseSource::FrameworkTrace);
        assert_eq!(conversation().source(), EnterpriseSource::FrameworkTrace);
        assert!(graph().source().workload_controls_source());
    }

    #[test]
    fn two_frameworks_map_their_own_events_and_agree_on_the_resources() {
        assert_eq!(
            graph().resource_of("tool_call"),
            Some(EnterpriseResource::Tool)
        );
        assert_eq!(
            conversation().resource_of("function_call"),
            Some(EnterpriseResource::Tool)
        );
        // And an event neither knows maps to nothing rather than to a guess.
        assert_eq!(graph().resource_of("function_call"), None);
        assert_eq!(conversation().resource_of("node_start"), None);
    }

    #[test]
    fn the_framework_identity_carries_both_versions() {
        let f = graph().framework();
        assert_eq!(f.name, "langgraph");
        assert_eq!(f.version, "0.2.1");
        assert_eq!(f.adapter_version, "vanian-1");
    }
}
