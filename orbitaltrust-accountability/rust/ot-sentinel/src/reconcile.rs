//! Set difference between what happened and what was sealed.
//!
//! This is the primitive the whole sentinel rests on. Everything else is
//! corroboration.
//!
//! ```text
//!   observed effects  ─┐
//!                      ├─▶  matched      (governed: an effect with its evidence)
//!   sealed packets    ─┘    unattributed (an effect nothing sealed  → ghost)
//!                           phantom      (evidence with no effect   → fabrication)
//! ```
//!
//! # Why matching is one-to-one
//!
//! Each sealed packet may satisfy exactly one observed effect. That single
//! constraint is what makes replay detectable: an attacker who captures a
//! legitimate governed call and re-issues it produces two effects with
//! identical parameters, and only one packet exists to account for them. The
//! second falls out as unattributed without anyone having modelled "replay"
//! as a threat.
//!
//! # Why the parameter digest is in the key
//!
//! Matching on tool name alone would let a ghost hide behind any concurrent
//! legitimate call of the same tool: fire `send_command DEORBIT` while an
//! approved `send_command SAFE_MODE` is in flight, and a name-only reconciler
//! would tick both off. Keying on the digest of the canonical parameters
//! means the evidence must describe *this* call — the same bytes the packet
//! hashed. A ghost would have to produce a sealed packet for its exact
//! payload, which is the thing it cannot do without going through the funnel.
//!
//! # What blocked packets are worth here
//!
//! A `BLOCKED_BY_POLICY` packet records a call that was refused, so it
//! describes an effect that must *not* have occurred. It is therefore never
//! available to explain an observed effect — and an observation matching a
//! blocked packet's parameters is the sharpest signal in the system: the
//! gateway said no, and it happened anyway.

use ot_accountability_core::{canonical_json, sha256_hex};
use serde_json::Value;

use crate::observation::{Effect, Observation, Subject};
use crate::time::abs_delta_millis;

/// How far apart an effect and its evidence may be before the pairing is
/// rejected. Generous by default: clock skew between a tool server and the
/// gateway is ordinary, and a false "unattributed" reading is expensive.
pub const DEFAULT_TOLERANCE_MILLIS: i64 = 30_000;

/// The outcome of reconciling a window of observations against a window of
/// sealed packets. Indices refer to the input slices.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reconciliation {
    /// `(observation index, packet index)` for effects with their evidence.
    pub matched: Vec<(usize, usize)>,
    /// Observations of consequential effects that no packet accounts for.
    pub unattributed: Vec<usize>,
    /// Observations that matched a packet recording a *refused* call — the
    /// gateway denied it and it happened regardless.
    pub executed_despite_denial: Vec<(usize, usize)>,
    /// Packets claiming an action that a sensor covering that tool never saw.
    pub phantom: Vec<usize>,
}

/// A packet reduced to what matching needs.
struct PacketFacts {
    index: usize,
    agent_did: String,
    tool: String,
    params_digest: String,
    timestamp: String,
    blocked: bool,
}

fn packet_facts(packets: &[Value]) -> Vec<PacketFacts> {
    packets
        .iter()
        .enumerate()
        .filter_map(|(index, packet)| {
            let tool = packet.pointer("/toolExecuted/name")?.as_str()?.to_string();
            let params = packet.pointer("/toolExecuted/inputParams")?;
            let status = packet
                .pointer("/toolExecuted/status")
                .and_then(Value::as_str)
                .unwrap_or_default();
            Some(PacketFacts {
                index,
                agent_did: packet
                    .get("agentDid")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                tool,
                params_digest: sha256_hex(&canonical_json(params)),
                timestamp: packet
                    .get("timestampUtc")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                blocked: status == "BLOCKED_BY_POLICY",
            })
        })
        .collect()
}

/// Reconciles observed effects against sealed evidence.
///
/// `covered_tools` names the tools some registered sensor claims to observe
/// completely; only those can yield [`Reconciliation::phantom`] findings,
/// because only there does the absence of an observation mean anything.
pub fn reconcile(
    observations: &[Observation],
    packets: &[Value],
    covered_tools: &[String],
    tolerance_millis: i64,
) -> Reconciliation {
    let facts = packet_facts(packets);
    let mut consumed = vec![false; facts.len()];
    let mut out = Reconciliation::default();

    for (obs_index, observation) in observations.iter().enumerate() {
        let Effect::ToolInvocation {
            tool,
            params_digest,
        } = &observation.effect
        else {
            // Only tool invocations are reconcilable against packets. Other
            // consequential effects — raw egress, a spawned process — have no
            // packet shape to match, and are judged by their own detector
            // rather than being silently declared attributed here.
            continue;
        };

        // Candidates: same tool, same exact parameters, same agent when one
        // was claimed, within tolerance, not already spent on another effect.
        let mut candidates: Vec<(usize, i64)> = facts
            .iter()
            .enumerate()
            .filter(|(slot, f)| {
                !consumed[*slot]
                    && &f.tool == tool
                    && &f.params_digest == params_digest
                    && observation
                        .subject
                        .did()
                        .is_none_or(|did| did == f.agent_did)
            })
            .filter_map(|(slot, f)| {
                let delta = abs_delta_millis(&observation.observed_at_utc, &f.timestamp)?;
                (delta <= tolerance_millis).then_some((slot, delta))
            })
            .collect();
        // Nearest in time wins, so concurrent identical calls pair up in the
        // order they actually happened rather than by position in the slice.
        candidates.sort_by_key(|(slot, delta)| (*delta, *slot));

        match candidates.first() {
            Some(&(slot, _)) => {
                consumed[slot] = true;
                let packet_index = facts[slot].index;
                if facts[slot].blocked {
                    out.executed_despite_denial.push((obs_index, packet_index));
                } else {
                    out.matched.push((obs_index, packet_index));
                }
            }
            None if observation.effect.is_consequential() => {
                out.unattributed.push(obs_index);
            }
            None => {}
        }
    }

    // Phantom evidence: a successful packet for a covered tool that no sensor
    // ever saw happen.
    for (slot, f) in facts.iter().enumerate() {
        if !consumed[slot] && !f.blocked && covered_tools.iter().any(|t| t == &f.tool) {
            out.phantom.push(f.index);
        }
    }

    out
}

/// Convenience: the observations that nothing in the ledger explains.
pub fn unattributed<'a>(
    reconciliation: &Reconciliation,
    observations: &'a [Observation],
) -> Vec<&'a Observation> {
    reconciliation
        .unattributed
        .iter()
        .filter_map(|i| observations.get(*i))
        .collect()
}

/// True when the observation presented no identity.
pub fn is_anonymous(observation: &Observation) -> bool {
    matches!(observation.subject, Subject::Anonymous)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observation::{Observation, Subject};
    use serde_json::json;

    const AGENT: &str = "did:syntriass:agent:AGT-1";
    const T: &str = "2026-08-27T12:00:00.000Z";

    fn packet(seq: u64, tool: &str, params: Value, status: &str, ts: &str) -> Value {
        json!({
            "id": format!("{AGENT}#packet-{seq}"),
            "sequenceNumber": seq,
            "timestampUtc": ts,
            "agentDid": AGENT,
            "toolExecuted": { "name": tool, "inputParams": params, "status": status },
            "packetHash": format!("{seq:064}"),
        })
    }

    fn obs(id: &str, tool: &str, params: Value, ts: &str, subject: Subject) -> Observation {
        Observation::tool_invocation(id, "tool-server-log", ts, subject, tool, &params)
    }

    #[test]
    fn a_governed_call_reconciles_against_its_own_evidence() {
        let packets = [packet(
            1,
            "send_command",
            json!({ "c": "SAFE" }),
            "SUCCESS",
            T,
        )];
        let observations = [obs(
            "o1",
            "send_command",
            json!({ "c": "SAFE" }),
            T,
            Subject::Claimed(AGENT.into()),
        )];
        let r = reconcile(&observations, &packets, &[], DEFAULT_TOLERANCE_MILLIS);
        assert_eq!(r.matched, [(0, 0)]);
        assert!(r.unattributed.is_empty());
        assert!(r.phantom.is_empty());
    }

    #[test]
    fn an_effect_with_no_evidence_anywhere_is_unattributed() {
        // The ledger has a legitimate call; the ghost made a different one.
        let packets = [packet(
            1,
            "send_command",
            json!({ "c": "SAFE" }),
            "SUCCESS",
            T,
        )];
        let observations = [
            obs(
                "o1",
                "send_command",
                json!({ "c": "SAFE" }),
                T,
                Subject::Claimed(AGENT.into()),
            ),
            obs(
                "o2",
                "send_command",
                json!({ "c": "DEORBIT" }),
                T,
                Subject::Claimed(AGENT.into()),
            ),
        ];
        let r = reconcile(&observations, &packets, &[], DEFAULT_TOLERANCE_MILLIS);
        assert_eq!(r.matched, [(0, 0)]);
        assert_eq!(r.unattributed, [1]);
    }

    #[test]
    fn matching_on_parameters_stops_a_ghost_hiding_behind_a_concurrent_call() {
        // A name-only reconciler would tick both effects off against the one
        // approved packet. The digest keeps them distinct.
        let packets = [packet(
            1,
            "send_command",
            json!({ "c": "SAFE" }),
            "SUCCESS",
            T,
        )];
        let observations = [obs(
            "o-ghost",
            "send_command",
            json!({ "c": "DEORBIT" }),
            T,
            Subject::Claimed(AGENT.into()),
        )];
        let r = reconcile(&observations, &packets, &[], DEFAULT_TOLERANCE_MILLIS);
        assert!(r.matched.is_empty());
        assert_eq!(r.unattributed, [0]);
    }

    #[test]
    fn one_packet_accounts_for_exactly_one_effect_so_replay_surfaces() {
        // Same call, sealed once, observed twice: the replay has nothing left
        // to account for it.
        let packets = [packet(
            1,
            "send_command",
            json!({ "c": "SAFE" }),
            "SUCCESS",
            T,
        )];
        let observations = [
            obs(
                "o1",
                "send_command",
                json!({ "c": "SAFE" }),
                T,
                Subject::Claimed(AGENT.into()),
            ),
            obs(
                "o2-replay",
                "send_command",
                json!({ "c": "SAFE" }),
                "2026-08-27T12:00:05.000Z",
                Subject::Claimed(AGENT.into()),
            ),
        ];
        let r = reconcile(&observations, &packets, &[], DEFAULT_TOLERANCE_MILLIS);
        assert_eq!(r.matched.len(), 1);
        assert_eq!(r.unattributed, [1]);
    }

    #[test]
    fn an_effect_matching_a_refused_call_is_flagged_rather_than_matched() {
        let packets = [packet(
            1,
            "send_command",
            json!({ "c": "DEORBIT" }),
            "BLOCKED_BY_POLICY",
            T,
        )];
        let observations = [obs(
            "o1",
            "send_command",
            json!({ "c": "DEORBIT" }),
            T,
            Subject::Claimed(AGENT.into()),
        )];
        let r = reconcile(&observations, &packets, &[], DEFAULT_TOLERANCE_MILLIS);
        // Refused and executed anyway: the sharpest signal there is.
        assert!(r.matched.is_empty());
        assert_eq!(r.executed_despite_denial, [(0, 0)]);
    }

    #[test]
    fn a_claimed_did_must_match_the_packets_own_agent() {
        let packets = [packet(
            1,
            "send_command",
            json!({ "c": "SAFE" }),
            "SUCCESS",
            T,
        )];
        // An impostor presenting a different DID cannot borrow this evidence.
        let observations = [obs(
            "o1",
            "send_command",
            json!({ "c": "SAFE" }),
            T,
            Subject::Claimed("did:syntriass:agent:OTHER".into()),
        )];
        let r = reconcile(&observations, &packets, &[], DEFAULT_TOLERANCE_MILLIS);
        assert_eq!(r.unattributed, [0]);
    }

    #[test]
    fn an_anonymous_effect_may_still_pair_with_evidence_that_explains_it() {
        // A sensor that cannot see identity is common; if the parameters and
        // timing match a sealed call, that call explains it. The point of the
        // reconciler is finding what is *un*explained, not punishing sensors
        // for being blind to DIDs.
        let packets = [packet(
            1,
            "send_command",
            json!({ "c": "SAFE" }),
            "SUCCESS",
            T,
        )];
        let observations = [obs(
            "o1",
            "send_command",
            json!({ "c": "SAFE" }),
            T,
            Subject::Anonymous,
        )];
        let r = reconcile(&observations, &packets, &[], DEFAULT_TOLERANCE_MILLIS);
        assert_eq!(r.matched, [(0, 0)]);
    }

    #[test]
    fn evidence_too_far_from_its_effect_does_not_explain_it() {
        let packets = [packet(
            1,
            "send_command",
            json!({ "c": "SAFE" }),
            "SUCCESS",
            T,
        )];
        let observations = [obs(
            "o1",
            "send_command",
            json!({ "c": "SAFE" }),
            "2026-08-27T13:00:00.000Z", // an hour later
            Subject::Claimed(AGENT.into()),
        )];
        let r = reconcile(&observations, &packets, &[], DEFAULT_TOLERANCE_MILLIS);
        assert_eq!(r.unattributed, [0]);
        // Widen the tolerance and the same pair reconciles.
        let r = reconcile(&observations, &packets, &[], 7_200_000);
        assert_eq!(r.matched, [(0, 0)]);
    }

    #[test]
    fn concurrent_identical_calls_pair_nearest_in_time() {
        let packets = [
            packet(
                1,
                "read_catalog",
                json!({ "n": 1 }),
                "SUCCESS",
                "2026-08-27T12:00:00.000Z",
            ),
            packet(
                2,
                "read_catalog",
                json!({ "n": 1 }),
                "SUCCESS",
                "2026-08-27T12:00:20.000Z",
            ),
        ];
        let observations = [
            obs(
                "late",
                "read_catalog",
                json!({ "n": 1 }),
                "2026-08-27T12:00:21.000Z",
                Subject::Claimed(AGENT.into()),
            ),
            obs(
                "early",
                "read_catalog",
                json!({ "n": 1 }),
                "2026-08-27T12:00:01.000Z",
                Subject::Claimed(AGENT.into()),
            ),
        ];
        let r = reconcile(&observations, &packets, &[], DEFAULT_TOLERANCE_MILLIS);
        // The later observation took the later packet even though it was
        // processed first, and both reconciled.
        assert_eq!(r.matched, [(0, 1), (1, 0)]);
        assert!(r.unattributed.is_empty());
    }

    #[test]
    fn phantom_evidence_is_only_claimed_where_a_sensor_declared_coverage() {
        let packets = [
            packet(1, "send_command", json!({ "c": "SAFE" }), "SUCCESS", T),
            packet(2, "read_catalog", json!({ "n": 1 }), "SUCCESS", T),
        ];
        // Nothing was observed at all.
        let r = reconcile(&[], &packets, &[], DEFAULT_TOLERANCE_MILLIS);
        assert!(
            r.phantom.is_empty(),
            "silence from a sensor claiming nothing must mean nothing"
        );

        // With a sensor vouching that it sees every send_command, the
        // unobserved one becomes a real question.
        let r = reconcile(
            &[],
            &packets,
            &["send_command".to_string()],
            DEFAULT_TOLERANCE_MILLIS,
        );
        assert_eq!(r.phantom, [0]);
    }

    #[test]
    fn a_refused_call_is_never_phantom_because_it_was_meant_not_to_happen() {
        let packets = [packet(
            1,
            "send_command",
            json!({ "c": "DEORBIT" }),
            "BLOCKED_BY_POLICY",
            T,
        )];
        let r = reconcile(
            &[],
            &packets,
            &["send_command".to_string()],
            DEFAULT_TOLERANCE_MILLIS,
        );
        assert!(r.phantom.is_empty());
    }
}
