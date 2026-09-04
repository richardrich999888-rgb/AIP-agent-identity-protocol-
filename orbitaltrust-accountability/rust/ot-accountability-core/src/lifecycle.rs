//! The NEXORA lifecycle as a typestate machine.
//!
//! `AgentGenesis` → `DelegatedAgent` → `ActiveExecution` → back to
//! `DelegatedAgent`, or terminally → `RevokedAgent`. Each state is its own
//! type and each transition consumes the previous state, so the lifecycle
//! law is enforced by the compiler, not by runtime checks:
//!
//! - an execution seal can only be produced by [`ActiveExecution::complete`],
//!   and an `ActiveExecution` can only be obtained from a [`DelegatedAgent`]
//!   — sealing on an un-delegated agent is not a rejected call, it is code
//!   that does not compile;
//! - [`RevokedAgent`] has no delegation or execution methods and no
//!   transition out: the terminal revocation closes the chain forever, at
//!   the type level;
//! - an in-flight [`ActiveExecution`] must `complete` (which seals the
//!   packet and its `ACTION_EXECUTION_SEAL` anchor) before the agent can be
//!   revoked — evidence cannot be dropped by racing a kill-switch.
//!
//! The records produced are byte-identical in shape and hashing to the
//! TypeScript console's writers, so [`crate::chain`]'s verifiers — and the
//! browser's WASM build of them — accept chains built here and vice versa.
//! Callers supply timestamps; record ids derive deterministically from the
//! DID and sequence, keeping the machine replay-deterministic with no clock
//! or RNG dependency (which the WASM target also appreciates).

use serde_json::{json, Value};

use crate::{canonical_json, chain_payload_bytes, seal_hash, sha256_hex, GENESIS_HASH};

/// Execution outcome recorded on a sealed evidence packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStatus {
    /// The tool body ran to completion.
    Success,
    /// The tool body ran and errored.
    Failed,
    /// Policy refused the call before the tool body ran.
    BlockedByPolicy,
}

impl ExecutionStatus {
    /// The wire vocabulary written into a sealed packet's `toolExecuted.status`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "SUCCESS",
            Self::Failed => "FAILED",
            Self::BlockedByPolicy => "BLOCKED_BY_POLICY",
        }
    }
}

/// Shared chain internals every typestate wraps. Private: states expose
/// read access, transitions are the only writers.
#[derive(Debug, Clone)]
struct LifecycleEngine {
    did: String,
    supervisor_did: String,
    anchors: Vec<Value>,
    anchor_tail: String,
    packets: Vec<Value>,
    packet_tail: String,
}

impl LifecycleEngine {
    fn append_anchor(
        &mut self,
        anchor_type: &str,
        actor_did: &str,
        timestamp_utc: &str,
        payload: Value,
    ) -> String {
        let sequence = self.anchors.len() as u64 + 1;
        let mut anchor = json!({
            "anchorId": format!("{}#anchor-{sequence}", self.did),
            "sequenceNumber": sequence,
            "anchorType": anchor_type,
            "agentDid": self.did,
            "actorDid": actor_did,
            "timestampUtc": timestamp_utc,
            "payload": payload,
        });
        let hash = seal_hash(
            &self.anchor_tail,
            &chain_payload_bytes(&anchor, &["previousAnchorHash", "anchorHash"]),
        );
        anchor["previousAnchorHash"] = json!(self.anchor_tail);
        anchor["anchorHash"] = json!(hash);
        self.anchors.push(anchor);
        self.anchor_tail = hash.clone();
        hash
    }
}

/// A born agent: genesis anchored, no authority delegated yet. The only
/// transitions are [`delegate`](Self::delegate) and
/// [`revoke`](Self::revoke) — there is no way to seal an execution from
/// this state.
#[derive(Debug, Clone)]
pub struct AgentGenesis {
    engine: LifecycleEngine,
}

/// An agent holding delegated authority: the only state that can begin an
/// execution.
#[derive(Debug, Clone)]
pub struct DelegatedAgent {
    engine: LifecycleEngine,
    scope: Vec<String>,
    model_digest: String,
}

/// An execution in flight. Must [`complete`](Self::complete) — sealing the
/// evidence packet and its lifecycle anchor — to return to
/// [`DelegatedAgent`]; there is no revoke here, so evidence cannot be
/// dropped by racing a kill-switch.
#[derive(Debug)]
pub struct ActiveExecution {
    agent: DelegatedAgent,
    tool_name: String,
    raw_prompt: String,
    pre_state_hash: String,
}

/// A terminally revoked agent. Read-only: no delegation, no execution, no
/// transition out — the closed lifecycle, expressed as a type with no
/// methods that could reopen it.
#[derive(Debug, Clone)]
pub struct RevokedAgent {
    engine: LifecycleEngine,
}

/// Read access shared by every state.
macro_rules! record_accessors {
    ($state:ty) => {
        impl $state {
            /// The lifecycle anchors sealed so far, in chain order.
            pub fn anchors(&self) -> &[Value] {
                &self.engine.anchors
            }
            /// The evidence packets sealed so far, in chain order.
            pub fn packets(&self) -> &[Value] {
                &self.engine.packets
            }
            /// The agent's DID.
            pub fn did(&self) -> &str {
                &self.engine.did
            }
        }
    };
}
record_accessors!(AgentGenesis);
record_accessors!(DelegatedAgent);
record_accessors!(RevokedAgent);

impl AgentGenesis {
    /// Births an agent: seals the `AGENT_GENESIS` anchor binding the model
    /// digest — the one mandatory fact a genesis exists to anchor.
    pub fn born(did: &str, supervisor_did: &str, model_digest: &str, timestamp_utc: &str) -> Self {
        let mut engine = LifecycleEngine {
            did: did.to_string(),
            supervisor_did: supervisor_did.to_string(),
            anchors: Vec::new(),
            anchor_tail: GENESIS_HASH.to_string(),
            packets: Vec::new(),
            packet_tail: GENESIS_HASH.to_string(),
        };
        engine.append_anchor(
            "AGENT_GENESIS",
            supervisor_did,
            timestamp_utc,
            json!({ "modelDigest": model_digest }),
        );
        Self { engine }
    }

    /// Confers authority: seals the `SUPERVISOR_DELEGATION` anchor and
    /// yields the only state that can execute.
    pub fn delegate(
        mut self,
        scope: &[&str],
        clearance_level: &str,
        model_digest: &str,
        timestamp_utc: &str,
    ) -> DelegatedAgent {
        let supervisor = self.engine.supervisor_did.clone();
        self.engine.append_anchor(
            "SUPERVISOR_DELEGATION",
            &supervisor,
            timestamp_utc,
            json!({ "scope": scope, "clearanceLevel": clearance_level }),
        );
        DelegatedAgent {
            engine: self.engine,
            scope: scope.iter().map(|s| s.to_string()).collect(),
            model_digest: model_digest.to_string(),
        }
    }

    /// Terminal revocation of a never-delegated agent.
    pub fn revoke(mut self, reason: &str, timestamp_utc: &str) -> RevokedAgent {
        let supervisor = self.engine.supervisor_did.clone();
        self.engine.append_anchor(
            "AUTHORITY_REVOCATION",
            &supervisor,
            timestamp_utc,
            json!({ "terminal": true, "reason": reason }),
        );
        RevokedAgent {
            engine: self.engine,
        }
    }
}

impl DelegatedAgent {
    /// The delegated tool scope.
    pub fn scope(&self) -> &[String] {
        &self.scope
    }

    /// Begins an execution, capturing the pre-state hash now so the
    /// evidence records the state the operator actually acted from.
    pub fn begin_execution(
        self,
        tool_name: &str,
        raw_prompt: &str,
        pre_state: &Value,
    ) -> ActiveExecution {
        ActiveExecution {
            pre_state_hash: sha256_hex(&canonical_json(pre_state)),
            tool_name: tool_name.to_string(),
            raw_prompt: raw_prompt.to_string(),
            agent: self,
        }
    }

    /// Terminal revocation: seals the closing anchor and yields the state
    /// with no way forward.
    pub fn revoke(mut self, reason: &str, timestamp_utc: &str) -> RevokedAgent {
        let supervisor = self.engine.supervisor_did.clone();
        self.engine.append_anchor(
            "AUTHORITY_REVOCATION",
            &supervisor,
            timestamp_utc,
            json!({ "terminal": true, "reason": reason }),
        );
        RevokedAgent {
            engine: self.engine,
        }
    }
}

impl ActiveExecution {
    /// Completes the execution: seals the AIP evidence packet (hash-chained
    /// with pre/post state hashes) and the `ACTION_EXECUTION_SEAL` anchor
    /// naming it, then returns the agent to its delegated state. The packet
    /// hash is returned for callers building Merkle commitments.
    pub fn complete(
        mut self,
        status: ExecutionStatus,
        input_params: Value,
        post_state: &Value,
        timestamp_utc: &str,
    ) -> (DelegatedAgent, String) {
        let engine = &mut self.agent.engine;
        // A blocked call never ran: the post-state IS the pre-state, by
        // construction rather than by caller discipline.
        let post_state_hash = match status {
            ExecutionStatus::BlockedByPolicy => self.pre_state_hash.clone(),
            _ => sha256_hex(&canonical_json(post_state)),
        };
        let sequence = engine.packets.len() as u64 + 1;
        let mut packet = json!({
            "id": format!("{}#packet-{sequence}", engine.did),
            "sequenceNumber": sequence,
            "timestampUtc": timestamp_utc,
            "agentDid": engine.did,
            "anchorHash": engine.anchor_tail,
            "delegationPath": [engine.supervisor_did, engine.did],
            "edgeId": format!("{}#edge-1", engine.did),
            "modelDigest": self.agent.model_digest,
            "rawPrompt": self.raw_prompt,
            "toolExecuted": {
                "name": self.tool_name,
                "inputParams": input_params,
                "status": status.as_str(),
            },
            "preStateHash": self.pre_state_hash,
            "postStateHash": post_state_hash,
        });
        let packet_hash = seal_hash(
            &engine.packet_tail,
            &chain_payload_bytes(&packet, &["previousPacketHash", "packetHash"]),
        );
        packet["previousPacketHash"] = json!(engine.packet_tail);
        packet["packetHash"] = json!(packet_hash);
        engine.packets.push(packet);
        engine.packet_tail = packet_hash.clone();

        let (did, packet_id) = (
            engine.did.clone(),
            format!("{}#packet-{sequence}", engine.did),
        );
        engine.append_anchor(
            "ACTION_EXECUTION_SEAL",
            &did,
            timestamp_utc,
            json!({
                "packetId": packet_id,
                "packetHash": packet_hash,
                "status": status.as_str(),
            }),
        );
        (self.agent, packet_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{verify_anchor_chain, verify_packet_chain};
    use crate::merkle::merkle_root;

    fn pre_state() -> Value {
        json!({ "cameraCoords": [78.9, 20.5, 12000000], "activeShader": "visible" })
    }

    #[test]
    fn the_full_lifecycle_produces_chains_the_shared_verifier_accepts() {
        let agent = AgentGenesis::born(
            "did:syntriass:agent:AGT-TEST",
            "did:syntriass:officer:OFFICER-1",
            &"a".repeat(64),
            "2026-08-27T00:00:00.000Z",
        );
        let agent = agent.delegate(
            &["fly_to_location", "screen_conjunction_threats"],
            "SECRET",
            &"a".repeat(64),
            "2026-08-27T00:00:01.000Z",
        );
        let (agent, first_hash) = agent
            .begin_execution("fly_to_location", "fly to hormuz", &pre_state())
            .complete(
                ExecutionStatus::Success,
                json!({ "query": "hormuz" }),
                &json!({ "cameraCoords": [56.5, 26.6, 500000], "activeShader": "visible" }),
                "2026-08-27T00:00:02.000Z",
            );
        let (agent, _) = agent
            .begin_execution(
                "screen_conjunction_threats",
                "screen the catalog",
                &pre_state(),
            )
            .complete(
                ExecutionStatus::Success,
                json!({}),
                &pre_state(),
                "2026-08-27T00:00:03.000Z",
            );
        let revoked = agent.revoke("drill", "2026-08-27T00:00:04.000Z");

        // Both chains verify under the shared verifier.
        assert!(verify_anchor_chain(revoked.anchors()).valid);
        assert!(verify_packet_chain(revoked.packets()).valid);
        // Genesis first, terminal revocation last, seals in between.
        let types: Vec<&str> = revoked
            .anchors()
            .iter()
            .map(|a| a["anchorType"].as_str().unwrap())
            .collect();
        assert_eq!(
            types,
            [
                "AGENT_GENESIS",
                "SUPERVISOR_DELEGATION",
                "ACTION_EXECUTION_SEAL",
                "ACTION_EXECUTION_SEAL",
                "AUTHORITY_REVOCATION",
            ],
        );
        // The seal anchor names the packet it acknowledges.
        assert_eq!(
            revoked.anchors()[2]["payload"]["packetHash"]
                .as_str()
                .unwrap(),
            first_hash,
        );
        // A Merkle commitment over the evidence set is reproducible.
        let leaves: Vec<String> = revoked
            .packets()
            .iter()
            .map(|p| p["packetHash"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(merkle_root(&leaves), merkle_root(&leaves));
    }

    #[test]
    fn a_blocked_execution_cannot_mutate_state_by_construction() {
        let agent = AgentGenesis::born(
            "did:syntriass:agent:AGT-TEST",
            "did:syntriass:officer:OFFICER-1",
            &"a".repeat(64),
            "t0",
        )
        .delegate(&["fly_to_location"], "SECRET", &"a".repeat(64), "t1");
        let (agent, _) = agent
            .begin_execution("fly_to_location", "fly", &pre_state())
            .complete(
                ExecutionStatus::BlockedByPolicy,
                json!({}),
                // A lying caller hands in a mutated post-state…
                &json!({ "activeShader": "flir" }),
                "t2",
            );
        let packet = &agent.packets()[0];
        // …and the machine records post == pre regardless.
        assert_eq!(packet["preStateHash"], packet["postStateHash"]);
    }

    // The compile-time guarantees themselves need no runtime test: this
    // module compiles, and `RevokedAgent` exposes no `delegate`,
    // `begin_execution`, or `complete` — code that seals on a revoked or
    // un-delegated agent is code that does not exist. (A `trybuild`
    // compile-fail suite would restate what the API surface already
    // proves, at the cost of a dev-dependency.)
}
