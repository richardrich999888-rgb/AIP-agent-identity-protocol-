//! The policy file the gateway is provisioned from.
//!
//! Everything that decides what an agent may do lives in one reviewable
//! document: the tool manifest, the delegation edges, the agent's identity and
//! weights, and the trust classification of resource origins. Nothing is
//! inferred from the upstream server, and nothing is defaulted permissively —
//! a tool absent from `tools` is uninvocable, and an origin absent from
//! `trustedResourcePrefixes` is untrusted.
//!
//! The file is deliberately declarative rather than executable. A policy that
//! can run code is a policy nobody can review, and the point of the document
//! is that a supervising officer can read it and know exactly what they have
//! delegated.

use ot_accountability_core::authority::{
    ClearanceLevel, DelegationEdge, EdgeStatus, MemoryAuthorityStore, ToolMandate, ToolManifest,
    TrustTier,
};
use ot_accountability_core::identity::{AuthMethod, CredentialRegistry};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

use crate::session::PrefixTrustPolicy;
use crate::trust::{CoSignatureAuthority, IssuerRegistry};

/// A parsed policy document.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GatewayPolicy {
    /// The agent this gateway instance fronts.
    pub agent: AgentIdentity,
    /// Tool name → mandate. A tool absent here cannot be invoked at all.
    pub tools: BTreeMap<String, ToolMandateSpec>,
    /// The delegation edges authority is resolved through.
    pub delegations: Vec<DelegationEdgeSpec>,
    /// Resource URI prefix → trust tier. Anything unmatched is untrusted.
    #[serde(default)]
    pub trusted_resource_prefixes: BTreeMap<String, String>,
    /// DID → signing key identities authorised to issue delegations as it.
    ///
    /// When present, every edge must carry a valid signature by one of these
    /// keys. When absent, the store itself is the trust boundary and the
    /// gateway says so at startup — correct for a local policy file on a host
    /// you control, wrong for a graph read from anywhere else.
    #[serde(default)]
    pub issuers: BTreeMap<String, Vec<String>>,
    /// Edge id → signing key identities authorised to co-sign its multi-sig
    /// tools. Absent means no approval verifies, so those tools stay
    /// uninvocable.
    #[serde(default)]
    pub co_signatories: BTreeMap<String, Vec<String>>,
}

/// Who the gateway is governing.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgentIdentity {
    /// The agent's DID.
    pub did: String,
    /// The officer or parent agent that births it.
    pub supervisor_did: String,
    /// SHA-256 of the weights it is expected to be running. A runtime
    /// reporting anything else is refused as a model-integrity failure.
    pub model_digest: String,
    /// The credentials authorised to speak for this agent.
    ///
    /// Empty means nothing can authenticate as it, and with the funnel's
    /// default the gateway will refuse every call — which is the correct
    /// behaviour for an agent nobody has enrolled a key for, not a bug.
    #[serde(default)]
    pub credentials: Vec<CredentialSpec>,
}

/// One enrolled credential, as written in the policy file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CredentialSpec {
    /// SHA-256 identity of the credential — for proof-of-possession, the
    /// signing key's `identity_hex`.
    pub digest: String,
    /// `PROOF_OF_POSSESSION`, `MUTUAL_TLS`, `SPIFFE`, or
    /// `PLATFORM_ATTESTATION`.
    pub method: String,
}

/// A tool's mandate, as written in the policy file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ToolMandateSpec {
    /// Permission verb the agent must hold.
    pub required_permission: String,
    /// Clearance the tool's material demands.
    pub minimum_clearance: String,
    /// Most-untrusted context tolerated when invoking. Defaults to
    /// `UNTRUSTED` — no restriction.
    #[serde(default)]
    pub max_context_taint: Option<String>,
    /// How far this tool's output may be trusted. Defaults to `INTERNAL`.
    #[serde(default)]
    pub result_trust: Option<String>,
}

/// One delegation edge, as written in the policy file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DelegationEdgeSpec {
    /// Stable edge identifier.
    pub edge_id: String,
    /// Officer DID at a root edge, agent DID for sub-delegation.
    pub parent_did: String,
    /// The agent receiving authority.
    pub child_did: String,
    /// Tools conferred.
    pub scope: Vec<String>,
    /// Tools additionally requiring a supervisor co-signature.
    #[serde(default)]
    pub multi_sig_tools: Vec<String>,
    /// Clearance conferred.
    pub clearance_level: String,
    /// ISO-8601 UTC start of the validity window.
    pub valid_from_utc: String,
    /// ISO-8601 UTC end of the validity window.
    pub expires_at_utc: String,
    /// `ACTIVE` or `REVOKED`. Defaults to `ACTIVE`.
    #[serde(default)]
    pub status: Option<String>,
    /// The parent's attestation envelope over this edge's canonical terms.
    /// Required when `issuers` is configured.
    #[serde(default)]
    pub signature: Option<serde_json::Value>,
}

/// Everything a policy file compiles down to.
#[derive(Debug)]
pub struct CompiledPolicy {
    /// The agent identity to register at startup.
    pub agent: AgentIdentity,
    /// The tool manifest.
    pub manifest: ToolManifest,
    /// The delegation graph.
    pub store: MemoryAuthorityStore,
    /// The resource trust policy.
    pub trust: PrefixTrustPolicy,
    /// Which credentials may speak for which agents.
    pub credentials: CredentialRegistry,
    /// Who may issue delegations, when the policy declared it.
    pub issuers: Option<IssuerRegistry>,
    /// Who may co-sign, when the policy declared it.
    pub co_signatories: Option<CoSignatureAuthority>,
}

impl GatewayPolicy {
    /// Reads and parses a policy file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, String> {
        let text = std::fs::read_to_string(path.as_ref())
            .map_err(|e| format!("cannot read policy {}: {e}", path.as_ref().display()))?;
        serde_json::from_str(&text)
            .map_err(|e| format!("cannot parse policy {}: {e}", path.as_ref().display()))
    }

    /// Compiles the document into the structures the gateway runs on.
    ///
    /// `now_utc` stamps the credential enrolments, which is when this policy
    /// was loaded — the moment these credentials became authoritative on this
    /// gateway.
    ///
    /// Every unrecognised vocabulary word is an error rather than a silent
    /// default: a typo in a clearance level must not quietly become
    /// `UNCLASSIFIED`.
    pub fn compile(self, now_utc: &str) -> Result<CompiledPolicy, String> {
        let mut manifest = ToolManifest::new();
        for (name, spec) in self.tools {
            let clearance = clearance(&spec.minimum_clearance).ok_or_else(|| {
                format!(
                    "tool \"{name}\": unknown clearance level \"{}\"",
                    spec.minimum_clearance
                )
            })?;
            let mut mandate = ToolMandate::new(spec.required_permission, clearance);
            if let Some(text) = &spec.max_context_taint {
                mandate = mandate
                    .with_max_context_taint(trust(text).ok_or_else(|| {
                        format!("tool \"{name}\": unknown trust tier \"{text}\"")
                    })?);
            }
            if let Some(text) = &spec.result_trust {
                mandate = mandate
                    .with_result_trust(trust(text).ok_or_else(|| {
                        format!("tool \"{name}\": unknown trust tier \"{text}\"")
                    })?);
            }
            manifest.insert(name, mandate);
        }

        let mut store = MemoryAuthorityStore::new();
        for spec in self.delegations {
            let clearance = clearance(&spec.clearance_level).ok_or_else(|| {
                format!(
                    "edge \"{}\": unknown clearance level \"{}\"",
                    spec.edge_id, spec.clearance_level
                )
            })?;
            let status = match spec.status.as_deref() {
                None | Some("ACTIVE") => EdgeStatus::Active,
                Some("REVOKED") => EdgeStatus::Revoked,
                Some(other) => {
                    return Err(format!(
                        "edge \"{}\": unknown status \"{other}\"",
                        spec.edge_id
                    ))
                }
            };
            // A scope naming a tool the manifest never mandated is almost
            // always a rename that silently dropped authority, so it is worth
            // saying out loud rather than resolving to a tool that is denied
            // at every call.
            for tool in &spec.scope {
                if !manifest.contains_key(tool) {
                    return Err(format!(
                        "edge \"{}\" delegates \"{tool}\", which has no mandate in `tools`",
                        spec.edge_id
                    ));
                }
            }
            store.add(DelegationEdge {
                edge_id: spec.edge_id,
                parent_did: spec.parent_did,
                child_did: spec.child_did,
                scope: spec.scope,
                multi_sig_tools: spec.multi_sig_tools,
                clearance_level: clearance,
                valid_from_utc: spec.valid_from_utc,
                expires_at_utc: spec.expires_at_utc,
                status,
                signature: spec.signature,
            });
        }

        let mut trust_policy = PrefixTrustPolicy::new();
        for (prefix, tier) in self.trusted_resource_prefixes {
            let tier = trust(&tier)
                .ok_or_else(|| format!("prefix \"{prefix}\": unknown trust tier \"{tier}\""))?;
            trust_policy = trust_policy.declare(prefix, tier);
        }

        let mut credentials = CredentialRegistry::new();
        for spec in &self.agent.credentials {
            let method = AuthMethod::parse(&spec.method).ok_or_else(|| {
                format!(
                    "credential {}…: unknown method \"{}\"",
                    &spec.digest[..spec.digest.len().min(12)],
                    spec.method
                )
            })?;
            if method == AuthMethod::Unauthenticated {
                return Err(format!(
                    "credential {}…: UNAUTHENTICATED is not something to enrol",
                    &spec.digest[..spec.digest.len().min(12)]
                ));
            }
            credentials.enrol(&self.agent.did, &spec.digest, method, now_utc);
        }

        // Absent rather than empty when undeclared: an empty registry refuses
        // everything, which would be the wrong reading of "this deployment
        // has not opted into signed edges".
        let issuers = if self.issuers.is_empty() {
            None
        } else {
            let mut registry = IssuerRegistry::new();
            for (did, keys) in &self.issuers {
                for key in keys {
                    registry = registry.authorise(did, key);
                }
            }
            Some(registry)
        };
        let co_signatories = if self.co_signatories.is_empty() {
            None
        } else {
            let mut authority = CoSignatureAuthority::new();
            for (edge_id, keys) in &self.co_signatories {
                for key in keys {
                    authority = authority.authorise(edge_id, key);
                }
            }
            Some(authority)
        };

        Ok(CompiledPolicy {
            agent: self.agent,
            manifest,
            store,
            trust: trust_policy,
            credentials,
            issuers,
            co_signatories,
        })
    }
}

fn clearance(text: &str) -> Option<ClearanceLevel> {
    ClearanceLevel::parse(text)
}

fn trust(text: &str) -> Option<TrustTier> {
    TrustTier::parse(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"{
      "agent": {
        "did": "did:syntriass:agent:AGT-1",
        "supervisorDid": "did:syntriass:officer:OFF-1",
        "modelDigest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      },
      "tools": {
        "read_feed": { "requiredPermission": "read", "minimumClearance": "UNCLASSIFIED",
                       "resultTrust": "UNTRUSTED" },
        "send_command": { "requiredPermission": "command", "minimumClearance": "SECRET",
                          "maxContextTaint": "INTERNAL" }
      },
      "delegations": [{
        "edgeId": "edge-1",
        "parentDid": "did:syntriass:officer:OFF-1",
        "childDid": "did:syntriass:agent:AGT-1",
        "scope": ["read_feed", "send_command"],
        "multiSigTools": ["send_command"],
        "clearanceLevel": "SECRET",
        "validFromUtc": "2026-01-01T00:00:00.000Z",
        "expiresAtUtc": "2027-01-01T00:00:00.000Z"
      }],
      "trustedResourcePrefixes": { "file:///opt/mission/": "TRUSTED" }
    }"#;

    const NOW: &str = "2026-08-27T00:00:00.000Z";

    fn compile(text: &str) -> Result<CompiledPolicy, String> {
        serde_json::from_str::<GatewayPolicy>(text)
            .map_err(|e| e.to_string())?
            .compile(NOW)
    }

    #[test]
    fn a_complete_policy_compiles_to_the_structures_the_gateway_runs_on() {
        let compiled = compile(GOOD).unwrap();
        assert_eq!(compiled.agent.did, "did:syntriass:agent:AGT-1");
        assert_eq!(compiled.manifest.len(), 2);
        assert_eq!(
            compiled.manifest["read_feed"].result_trust,
            TrustTier::Untrusted
        );
        assert_eq!(
            compiled.manifest["send_command"].max_context_taint,
            TrustTier::Internal
        );
        // Unstated taint fields take the documented defaults.
        assert_eq!(
            compiled.manifest["read_feed"].max_context_taint,
            TrustTier::Untrusted
        );
        assert_eq!(
            compiled.manifest["send_command"].result_trust,
            TrustTier::Internal
        );
        use ot_accountability_core::authority::AuthorityStore;
        assert_eq!(
            compiled
                .store
                .edges_for_child("did:syntriass:agent:AGT-1")
                .len(),
            1
        );
    }

    #[test]
    fn a_typo_is_an_error_rather_than_a_quiet_downgrade() {
        // A misspelled clearance must never resolve to UNCLASSIFIED.
        let err = compile(&GOOD.replace("\"SECRET\"", "\"SECERT\"")).unwrap_err();
        assert!(err.contains("SECERT"), "{err}");
        // Nor a misspelled trust tier to the permissive end.
        let err = compile(&GOOD.replace("\"UNTRUSTED\"", "\"UNTRUSTEDD\"")).unwrap_err();
        assert!(err.contains("UNTRUSTEDD"), "{err}");
        // An unknown field is a typo in a key, which `deny_unknown_fields`
        // catches rather than ignoring.
        let err = compile(&GOOD.replace("\"resultTrust\"", "\"resultTrusts\"")).unwrap_err();
        assert!(err.contains("resultTrusts"), "{err}");
    }

    #[test]
    fn delegating_a_tool_with_no_mandate_is_refused_at_load() {
        let err = compile(&GOOD.replace(
            r#""scope": ["read_feed", "send_command"]"#,
            r#""scope": ["read_feed", "send_cmmand"]"#,
        ))
        .unwrap_err();
        assert!(err.contains("send_cmmand"), "{err}");
        assert!(err.contains("no mandate"), "{err}");
    }

    #[test]
    fn an_edge_can_be_revoked_in_the_document_itself() {
        let revoked = GOOD.replace(
            r#""expiresAtUtc": "2027-01-01T00:00:00.000Z""#,
            r#""expiresAtUtc": "2027-01-01T00:00:00.000Z", "status": "REVOKED""#,
        );
        use ot_accountability_core::authority::{resolve_authority, TrustedStoreVerifier};
        let compiled = compile(&revoked).unwrap();
        assert!(resolve_authority(
            &compiled.store,
            &TrustedStoreVerifier,
            "did:syntriass:agent:AGT-1",
            "2026-06-01T00:00:00.000Z",
        )
        .is_none());
    }

    #[test]
    fn an_origin_the_document_does_not_mention_is_untrusted() {
        use crate::session::TrustPolicy;
        let compiled = compile(GOOD).unwrap();
        assert_eq!(
            compiled.trust.classify_resource("file:///opt/mission/x"),
            TrustTier::Trusted
        );
        assert_eq!(
            compiled.trust.classify_resource("https://elsewhere/x"),
            TrustTier::Untrusted
        );
    }
}
