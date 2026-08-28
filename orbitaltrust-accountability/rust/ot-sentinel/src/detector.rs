//! The detectors, and what each of them can honestly conclude.
//!
//! Each detector answers one question and states how firmly. Two of them —
//! [`ChainIntegrityDetector`] and [`ModelDriftDetector`] — reach
//! [`Strength::Proof`] from the sentinel's own arithmetic and need nothing
//! vouched for. [`ReconciliationDetector`] reaches it only through a sensor
//! the operator has vouched for, and caps itself otherwise. The rest are
//! leads for a human.
//!
//! Detectors are deliberately small and independent. A detector that needed
//! another's conclusions would make the strength of one finding depend on the
//! strength of another, which is how a chain of plausible inferences ends up
//! wearing the authority of a proof.

use ot_accountability_core::chain::verify_hash_chain;
use serde_json::Value;
use std::collections::BTreeMap;

use crate::attestation::{SensorCheckpoint, TamperedCheckpoint};
use crate::conformance::EffectPolicy;
use crate::finding::{Finding, FindingKind, Severity, Strength};
use crate::observation::{Effect, Observation, Sensor, Subject};
use crate::reconcile::{reconcile, Reconciliation};
use crate::registry::AgentRegistry;
use crate::state::ContinuityBreak;
use crate::time::parse_iso8601_millis;
use ot_accountability_core::identity::PrincipalBinding;

/// Everything a detector may look at for one patrol.
pub struct PatrolContext<'a> {
    /// Sealed evidence packets in the window, in ledger order.
    pub packets: &'a [Value],
    /// Sealed lifecycle anchors in the window, in ledger order.
    pub anchors: &'a [Value],
    /// What sensors observed in the window.
    pub observations: &'a [Observation],
    /// Registered sensors, by name.
    pub sensors: &'a BTreeMap<String, Sensor>,
    /// The fleet as the chain describes it.
    pub registry: &'a AgentRegistry,
    /// Patrol time, ISO-8601 UTC.
    pub now_utc: &'a str,
    /// Reconciliation tolerance.
    pub tolerance_millis: i64,
    /// How long an agent may be silent before it is a finding.
    pub heartbeat_deadline_millis: i64,
    /// Sealed stream checkpoints per sensor, oldest first — the sentinel's
    /// own attestation history, not raw sensor output.
    pub sensor_checkpoints: &'a BTreeMap<String, Vec<SensorCheckpoint>>,
    /// Checkpoints [`crate::sensors::JsonlAccessLog::deep_verify`] found no
    /// longer recomputing, precomputed by the caller before the patrol runs
    /// — a detector reads data, it does not open files, the same discipline
    /// every other detector in this module already follows.
    pub tampered_checkpoints: &'a [TamperedCheckpoint],
    /// How long a covering sensor may go without checkpointing before its
    /// coverage is treated as unattested rather than assumed current.
    pub sensor_heartbeat_deadline_millis: i64,
    /// The declared conformance posture for egress and process spawns, or
    /// `None` when the deployment has not declared one — in which case
    /// [`EffectConformanceDetector`] stays silent, the same opt-in stance the
    /// rest of the crate takes.
    pub effect_policy: Option<&'a EffectPolicy>,
    /// A disagreement between the sentinel's resumed chain head and the
    /// archive of anchors it emitted, latched at resume by
    /// [`Patrol::audit_continuity`](crate::patrol::Patrol::audit_continuity).
    /// `None` when continuity was verified, or when the deployment never
    /// audited it.
    pub continuity_break: Option<&'a ContinuityBreak>,
}

impl PatrolContext<'_> {
    /// The sensor that produced an observation, if it is registered.
    pub fn sensor_for(&self, observation: &Observation) -> Option<&Sensor> {
        self.sensors.get(&observation.sensor)
    }

    /// Whether the operator has vouched for the sensor behind an observation.
    /// Unregistered sensors are untrusted.
    pub fn is_trusted(&self, observation: &Observation) -> bool {
        self.sensor_for(observation).is_some_and(|s| s.trusted)
    }

    /// Every tool some registered sensor claims to observe completely.
    pub fn covered_tools(&self) -> Vec<String> {
        let mut tools: Vec<String> = self
            .sensors
            .values()
            .flat_map(|s| s.covers_tools.iter().cloned())
            .collect();
        tools.sort();
        tools.dedup();
        tools
    }

    /// Packets belonging to one agent, in ledger order.
    pub fn packets_for(&self, did: &str) -> Vec<&Value> {
        self.packets
            .iter()
            .filter(|p| p.get("agentDid").and_then(Value::as_str) == Some(did))
            .collect()
    }

    /// Every DID named anywhere in this window — by a packet or by an
    /// observation.
    pub fn dids_seen(&self) -> Vec<String> {
        let mut dids: Vec<String> = self
            .packets
            .iter()
            .filter_map(|p| p.get("agentDid").and_then(Value::as_str))
            .map(str::to_string)
            .chain(
                self.observations
                    .iter()
                    .filter_map(|o| o.subject.did())
                    .map(str::to_string),
            )
            .collect();
        dids.sort();
        dids.dedup();
        dids
    }
}

/// One question the sentinel asks of a patrol window.
pub trait Detector {
    /// Stable name, cited on every finding it produces.
    fn name(&self) -> &'static str;

    /// Examines the window.
    fn examine(&self, ctx: &PatrolContext) -> Vec<Finding>;
}

// ── Reconciliation ───────────────────────────────────────────────────────

/// Compares what happened against what was sealed.
///
/// The detector that actually catches escapes: everything else corroborates.
#[derive(Debug, Default)]
pub struct ReconciliationDetector;

impl Detector for ReconciliationDetector {
    fn name(&self) -> &'static str {
        "reconciliation"
    }

    fn examine(&self, ctx: &PatrolContext) -> Vec<Finding> {
        let covered = ctx.covered_tools();
        let report: Reconciliation = reconcile(
            ctx.observations,
            ctx.packets,
            &covered,
            ctx.tolerance_millis,
        );
        let mut findings = Vec::new();

        for &index in &report.unattributed {
            let Some(observation) = ctx.observations.get(index) else {
                continue;
            };
            let anonymous = matches!(observation.subject, Subject::Anonymous);
            let kind = if anonymous {
                FindingKind::AnonymousEffect
            } else {
                FindingKind::UnattributedEffect
            };
            let who = match &observation.subject {
                Subject::Claimed(did) => format!("claiming {did}"),
                Subject::Anonymous => "presenting no identity".to_string(),
            };
            let mut finding = Finding::new(
                kind,
                // Arithmetic: these parameters match no sealed packet. That
                // is only as good as the sensor that reported the effect.
                Strength::Proof,
                Severity::Critical,
                self.name(),
                ctx.now_utc,
                format!(
                    "{} occurred outside the governed channel — no sealed evidence accounts for it ({} via sensor \"{}\")",
                    observation.effect.describe(),
                    who,
                    observation.sensor,
                ),
            )
            .citing([format!("observation:{}", observation.id)]);
            if let Some(did) = observation.subject.did() {
                finding = finding.about(did);
            }
            if !ctx.is_trusted(observation) {
                finding = finding.capped_at(Strength::Corroborated);
            }
            findings.push(finding);
        }

        for &(obs_index, packet_index) in &report.executed_despite_denial {
            let (Some(observation), Some(packet)) = (
                ctx.observations.get(obs_index),
                ctx.packets.get(packet_index),
            ) else {
                continue;
            };
            let mut finding = Finding::new(
                FindingKind::UnattributedEffect,
                Strength::Proof,
                Severity::Critical,
                self.name(),
                ctx.now_utc,
                format!(
                    "{} was refused by policy and executed anyway — the gateway was bypassed, not fooled",
                    observation.effect.describe(),
                ),
            )
            .citing([
                format!("observation:{}", observation.id),
                format!("packet:{}", hash_of(packet)),
            ]);
            if let Some(did) = observation.subject.did() {
                finding = finding.about(did);
            }
            if !ctx.is_trusted(observation) {
                finding = finding.capped_at(Strength::Corroborated);
            }
            findings.push(finding);
        }

        for &index in &report.phantom {
            let Some(packet) = ctx.packets.get(index) else {
                continue;
            };
            let tool = packet
                .pointer("/toolExecuted/name")
                .and_then(Value::as_str)
                .unwrap_or("?");
            let mut finding = Finding::new(
                FindingKind::PhantomEvidence,
                // A sensor claiming complete coverage saw nothing. Real, but
                // coverage claims are operator judgement, not arithmetic.
                Strength::Corroborated,
                Severity::High,
                self.name(),
                ctx.now_utc,
                format!(
                    "the ledger records a successful \"{tool}\" that no sensor covering that tool observed",
                ),
            )
            .citing([format!("packet:{}", hash_of(packet))]);
            if let Some(did) = packet.get("agentDid").and_then(Value::as_str) {
                finding = finding.about(did);
            }
            findings.push(finding);
        }

        findings
    }
}

// ── Effect conformance ───────────────────────────────────────────────────

/// Judges the consequential effects [`ReconciliationDetector`] cannot: raw
/// network egress and process spawns, which have no `params_digest` to pair
/// against a sealed packet.
///
/// Where reconciliation asks "is there evidence for this?", conformance asks
/// "was this destination ever approved?" — set membership against a declared,
/// fail-closed [`EffectPolicy`]. That makes it arithmetic: a trusted sensor's
/// report of an egress to an unlisted host is [`Strength::Proof`], capped to
/// [`Strength::Corroborated`] when the sensor is unvouched, exactly as the
/// reconciliation findings are. Silent entirely when no policy is declared.
#[derive(Debug, Default)]
pub struct EffectConformanceDetector;

impl Detector for EffectConformanceDetector {
    fn name(&self) -> &'static str {
        "effect-conformance"
    }

    fn examine(&self, ctx: &PatrolContext) -> Vec<Finding> {
        let Some(policy) = ctx.effect_policy else {
            return Vec::new();
        };
        let mut findings = Vec::new();

        for observation in ctx.observations {
            let (kind, severity, summary) = match &observation.effect {
                Effect::NetworkEgress { destination, bytes }
                    if policy.governs_egress() && !policy.permits_destination(destination) =>
                {
                    (
                        FindingKind::UnauthorizedEgress,
                        Severity::Critical,
                        format!(
                            "{bytes} bytes egressed to {destination}, which the declared egress policy never approved — exfiltration or a network pivot",
                        ),
                    )
                }
                Effect::ProcessSpawn { command }
                    if policy.governs_spawn() && !policy.permits_command(command) =>
                {
                    (
                        FindingKind::UnauthorizedProcessSpawn,
                        Severity::High,
                        format!(
                            "process spawned outside the sanctioned set: {command}",
                        ),
                    )
                }
                _ => continue,
            };

            let mut finding = Finding::new(
                kind,
                // Set non-membership is arithmetic — but only as sound as the
                // sensor that reported the effect, so an unvouched sensor caps
                // it below the warrant threshold, alert not quarantine.
                Strength::Proof,
                severity,
                self.name(),
                ctx.now_utc,
                summary,
            )
            .citing([format!("observation:{}", observation.id)]);
            if let Some(did) = observation.subject.did() {
                finding = finding.about(did);
            }
            if !ctx.is_trusted(observation) {
                finding = finding.capped_at(Strength::Corroborated);
            }
            findings.push(finding);
        }

        findings
    }
}

// ── Chain integrity ──────────────────────────────────────────────────────

/// Checks each agent's packet chain for branches, reused sequences, and
/// links that no longer recompute.
///
/// Everything here is arithmetic on data the sentinel holds, so its findings
/// are [`Strength::Proof`] outright — no sensor is involved to be trusted or
/// not.
#[derive(Debug, Default)]
pub struct ChainIntegrityDetector;

impl Detector for ChainIntegrityDetector {
    fn name(&self) -> &'static str {
        "chain-integrity"
    }

    fn examine(&self, ctx: &PatrolContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for did in ctx.dids_seen() {
            let packets = ctx.packets_for(&did);
            if packets.is_empty() {
                continue;
            }

            // A fork: two records claiming the same predecessor, or the same
            // sequence number. One legitimate chain can do neither, so this
            // means one identity is being driven by two runtimes — or one
            // runtime and one impostor.
            let mut by_previous: BTreeMap<&str, Vec<&Value>> = BTreeMap::new();
            let mut by_sequence: BTreeMap<u64, Vec<&Value>> = BTreeMap::new();
            for packet in &packets {
                if let Some(prev) = packet.get("previousPacketHash").and_then(Value::as_str) {
                    by_previous.entry(prev).or_default().push(packet);
                }
                if let Some(seq) = packet.get("sequenceNumber").and_then(Value::as_u64) {
                    by_sequence.entry(seq).or_default().push(packet);
                }
            }
            for (prev, branch) in by_previous.iter().filter(|(_, v)| v.len() > 1) {
                findings.push(
                    Finding::new(
                        FindingKind::IdentityFork,
                        Strength::Proof,
                        Severity::Critical,
                        self.name(),
                        ctx.now_utc,
                        format!(
                            "{} records claim the same predecessor {}: one identity, two runtimes",
                            branch.len(),
                            &prev[..prev.len().min(12)],
                        ),
                    )
                    .about(&did)
                    .citing(branch.iter().map(|p| format!("packet:{}", hash_of(p)))),
                );
            }
            for (seq, clash) in by_sequence.iter().filter(|(_, v)| v.len() > 1) {
                // A sequence clash with distinct hashes is a second write of
                // the same slot; identical hashes are the same record twice,
                // which is duplication rather than a fork.
                let distinct: Vec<&&Value> = {
                    let mut seen: Vec<String> = Vec::new();
                    clash
                        .iter()
                        .filter(|p| {
                            let h = hash_of(p);
                            if seen.contains(&h) {
                                false
                            } else {
                                seen.push(h);
                                true
                            }
                        })
                        .collect()
                };
                if distinct.len() > 1 {
                    findings.push(
                        Finding::new(
                            FindingKind::IdentityFork,
                            Strength::Proof,
                            Severity::Critical,
                            self.name(),
                            ctx.now_utc,
                            format!(
                                "sequence {seq} was written {} times with different contents",
                                distinct.len()
                            ),
                        )
                        .about(&did)
                        .citing(distinct.iter().map(|p| format!("packet:{}", hash_of(p)))),
                    );
                }
            }

            // Links that no longer recompute: records were edited or removed.
            let owned: Vec<Value> = packets.iter().map(|p| (*p).clone()).collect();
            let verdict = verify_hash_chain(&owned, "previousPacketHash", "packetHash");
            if !verdict.valid {
                findings.push(
                    Finding::new(
                        FindingKind::LedgerBreak,
                        Strength::Proof,
                        Severity::Critical,
                        self.name(),
                        ctx.now_utc,
                        format!(
                            "packet chain fails to recompute at sequence {}: {}",
                            verdict.broken_sequence.unwrap_or(0),
                            verdict.reason.clone().unwrap_or_default(),
                        ),
                    )
                    .about(&did)
                    .citing([format!(
                        "chain:{did}#seq-{}",
                        verdict.broken_sequence.unwrap_or(0)
                    )]),
                );
            }

            // Timestamps that go backwards inside a monotonic chain.
            let mut previous: Option<(u64, i64)> = None;
            for packet in &packets {
                let (Some(seq), Some(stamp)) = (
                    packet.get("sequenceNumber").and_then(Value::as_u64),
                    packet
                        .get("timestampUtc")
                        .and_then(Value::as_str)
                        .and_then(parse_iso8601_millis),
                ) else {
                    continue;
                };
                if let Some((prev_seq, prev_stamp)) = previous {
                    if seq > prev_seq && stamp < prev_stamp {
                        findings.push(
                            Finding::new(
                                FindingKind::TemporalAnomaly,
                                Strength::Proof,
                                Severity::High,
                                self.name(),
                                ctx.now_utc,
                                format!(
                                    "sequence {seq} is timestamped before sequence {prev_seq} on the same chain",
                                ),
                            )
                            .about(&did)
                            .citing([format!("packet:{}", hash_of(packet))]),
                        );
                    }
                }
                previous = Some((seq, stamp));
            }
        }

        findings
    }
}

// ── Registration ─────────────────────────────────────────────────────────

/// Flags DIDs acting that the lifecycle chain never gave birth to, and agents
/// acting after their lifecycle was terminally closed.
#[derive(Debug, Default)]
pub struct RegistrationDetector;

impl Detector for RegistrationDetector {
    fn name(&self) -> &'static str {
        "registration"
    }

    fn examine(&self, ctx: &PatrolContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for did in ctx.dids_seen() {
            match ctx.registry.get(&did) {
                None => findings.push(
                    Finding::new(
                        FindingKind::UnregisteredAgent,
                        Strength::Proof,
                        Severity::Critical,
                        self.name(),
                        ctx.now_utc,
                        format!("{did} is acting but was never born on this ledger"),
                    )
                    .about(&did)
                    .citing([format!("registry:absent:{did}")]),
                ),
                Some(agent) if agent.should_be_dormant() => {
                    // Effects after a terminal revocation. The lifecycle
                    // check inside the gateway already refuses these, so
                    // seeing one out here means something is not using the
                    // gateway.
                    let active = ctx
                        .observations
                        .iter()
                        .filter(|o| {
                            o.subject.did() == Some(did.as_str()) && o.effect.is_consequential()
                        })
                        .count();
                    if active > 0 {
                        findings.push(
                            Finding::new(
                                FindingKind::UnattributedEffect,
                                Strength::Proof,
                                Severity::Critical,
                                self.name(),
                                ctx.now_utc,
                                format!(
                                    "{did} produced {active} consequential effect(s) after its lifecycle was terminally revoked",
                                ),
                            )
                            .about(&did)
                            .citing([format!("registry:closed:{did}")]),
                        );
                    }
                }
                Some(_) => {}
            }
        }
        findings
    }
}

// ── Model drift ──────────────────────────────────────────────────────────

/// Flags packets whose recorded weights differ from what the chain binds.
#[derive(Debug, Default)]
pub struct ModelDriftDetector;

impl Detector for ModelDriftDetector {
    fn name(&self) -> &'static str {
        "model-drift"
    }

    fn examine(&self, ctx: &PatrolContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut reported: Vec<(String, String)> = Vec::new();

        for packet in ctx.packets {
            let (Some(did), Some(running)) = (
                packet.get("agentDid").and_then(Value::as_str),
                packet.get("modelDigest").and_then(Value::as_str),
            ) else {
                continue;
            };
            let Some(expected) = ctx
                .registry
                .get(did)
                .and_then(|a| a.model_digest.as_deref())
            else {
                continue;
            };
            if expected == running {
                continue;
            }
            // One finding per (agent, drifted digest): a drifted agent making
            // a thousand calls is one problem, not a thousand.
            let key = (did.to_string(), running.to_string());
            if reported.contains(&key) {
                continue;
            }
            reported.push(key);
            findings.push(
                Finding::new(
                    FindingKind::ModelDrift,
                    Strength::Proof,
                    Severity::High,
                    self.name(),
                    ctx.now_utc,
                    format!(
                        "{did} is executing weights {}… while its chain binds {}…",
                        &running[..running.len().min(12)],
                        &expected[..expected.len().min(12)],
                    ),
                )
                .about(did)
                .citing([format!("packet:{}", hash_of(packet))]),
            );
        }

        // The same mismatch seen live, from a heartbeat.
        for observation in ctx.observations {
            let (Effect::Heartbeat { model_digest }, Some(did)) =
                (&observation.effect, observation.subject.did())
            else {
                continue;
            };
            let Some(expected) = ctx
                .registry
                .get(did)
                .and_then(|a| a.model_digest.as_deref())
            else {
                continue;
            };
            let key = (did.to_string(), model_digest.clone());
            if expected == model_digest || reported.contains(&key) {
                continue;
            }
            reported.push(key);
            let mut finding = Finding::new(
                FindingKind::ModelDrift,
                Strength::Proof,
                Severity::High,
                self.name(),
                ctx.now_utc,
                format!("{did} reported weights its chain does not bind"),
            )
            .about(did)
            .citing([format!("observation:{}", observation.id)]);
            if !ctx.is_trusted(observation) {
                finding = finding.capped_at(Strength::Corroborated);
            }
            findings.push(finding);
        }

        findings
    }
}

// ── Liveness ─────────────────────────────────────────────────────────────

/// Flags agents that stopped reporting.
///
/// Silence alone is only an indicator — an agent may simply have been shut
/// down. Silence *while consequential effects keep appearing under its DID*
/// is the ghost signature, and that combination is corroborated.
#[derive(Debug, Default)]
pub struct LivenessDetector;

impl Detector for LivenessDetector {
    fn name(&self) -> &'static str {
        "liveness"
    }

    fn examine(&self, ctx: &PatrolContext) -> Vec<Finding> {
        let Some(now) = parse_iso8601_millis(ctx.now_utc) else {
            return Vec::new();
        };
        let mut findings = Vec::new();

        for agent in ctx.registry.iter() {
            if agent.should_be_dormant() {
                // A revoked agent is *supposed* to be silent; that is the
                // registration detector's business, not this one's.
                continue;
            }
            let Some(last) = agent
                .last_heartbeat_utc
                .as_deref()
                .and_then(parse_iso8601_millis)
            else {
                continue;
            };
            let silent_for = now - last;
            if silent_for <= ctx.heartbeat_deadline_millis {
                continue;
            }

            let effects_since = ctx
                .observations
                .iter()
                .filter(|o| {
                    o.subject.did() == Some(agent.did.as_str())
                        && o.effect.is_consequential()
                        && o.observed_at_utc.as_str()
                            > agent.last_heartbeat_utc.as_deref().unwrap_or("")
                })
                .count();

            let (strength, severity, summary) = if effects_since > 0 {
                (
                    Strength::Corroborated,
                    Severity::Critical,
                    format!(
                        "{} has not reported for {}s yet produced {effects_since} consequential effect(s) since — acting while dark",
                        agent.did,
                        silent_for / 1000,
                    ),
                )
            } else {
                (
                    Strength::Indicator,
                    Severity::Medium,
                    format!("{} has not reported for {}s", agent.did, silent_for / 1000),
                )
            };
            findings.push(
                Finding::new(
                    FindingKind::LivenessLost,
                    strength,
                    severity,
                    self.name(),
                    ctx.now_utc,
                    summary,
                )
                .about(&agent.did)
                .citing([format!(
                    "heartbeat:last:{}",
                    agent.last_heartbeat_utc.as_deref().unwrap_or("never")
                )]),
            );
        }
        findings
    }
}

// ── Probing ──────────────────────────────────────────────────────────────

/// Flags patterns of refusal consistent with mapping the authority boundary.
///
/// Statistical by nature, so it never rises above [`Strength::Indicator`] on
/// volume alone. Denials across many *distinct* tools is a different shape
/// from repeatedly retrying one — the first is a scan, the second is usually
/// a confused agent — so breadth is what lifts it to corroborated.
#[derive(Debug, Clone)]
pub struct ProbingDetector {
    /// Denials by one agent in the window before it is worth reporting.
    pub denial_threshold: usize,
    /// Distinct tools denied before the pattern reads as a scan.
    pub distinct_tool_threshold: usize,
}

impl Default for ProbingDetector {
    fn default() -> Self {
        Self {
            denial_threshold: 5,
            distinct_tool_threshold: 3,
        }
    }
}

impl Detector for ProbingDetector {
    fn name(&self) -> &'static str {
        "probing"
    }

    fn examine(&self, ctx: &PatrolContext) -> Vec<Finding> {
        let mut denials: BTreeMap<&str, (usize, Vec<&str>)> = BTreeMap::new();
        for packet in ctx.packets {
            let blocked = packet
                .pointer("/toolExecuted/status")
                .and_then(Value::as_str)
                == Some("BLOCKED_BY_POLICY");
            if !blocked {
                continue;
            }
            let Some(did) = packet.get("agentDid").and_then(Value::as_str) else {
                continue;
            };
            let tool = packet
                .pointer("/toolExecuted/name")
                .and_then(Value::as_str)
                .unwrap_or("?");
            let entry = denials.entry(did).or_insert((0, Vec::new()));
            entry.0 += 1;
            if !entry.1.contains(&tool) {
                entry.1.push(tool);
            }
        }

        denials
            .into_iter()
            .filter(|(_, (count, _))| *count >= self.denial_threshold)
            .map(|(did, (count, tools))| {
                let scanning = tools.len() >= self.distinct_tool_threshold;
                Finding::new(
                    FindingKind::ScopeProbing,
                    if scanning {
                        Strength::Corroborated
                    } else {
                        Strength::Indicator
                    },
                    if scanning {
                        Severity::High
                    } else {
                        Severity::Low
                    },
                    self.name(),
                    ctx.now_utc,
                    format!(
                        "{did} was refused {count} time(s) across {} distinct tool(s){}",
                        tools.len(),
                        if scanning {
                            " — consistent with mapping the authority boundary"
                        } else {
                            ""
                        },
                    ),
                )
                .about(did)
                .citing(tools.iter().map(|t| format!("denied-tool:{t}")))
            })
            .collect()
    }
}

// ── Identity ─────────────────────────────────────────────────────────────

/// Flags actions sealed for a caller whose identity was never established.
///
/// Two shapes, and the distinction matters. A packet carrying an explicit
/// `UNAUTHENTICATED` binding was produced by a gateway deliberately running
/// with identity checks relaxed — a policy decision worth surfacing but not
/// an intrusion. A packet with **no** `principal` field at all was written by
/// something that has no identity tier: either a writer predating it, or one
/// that skipped it. In a fleet where identity binding is expected, that is a
/// rogue writer, and it is the more serious of the two.
///
/// Both are arithmetic on the record itself, so neither needs a sensor.
#[derive(Debug, Clone)]
pub struct PrincipalDetector {
    /// Whether every packet in this fleet is expected to carry a binding.
    /// When false, missing bindings are ignored and only explicitly
    /// unauthenticated ones are reported — the right setting mid-migration.
    pub binding_expected: bool,
}

impl Default for PrincipalDetector {
    fn default() -> Self {
        Self {
            binding_expected: true,
        }
    }
}

impl Detector for PrincipalDetector {
    fn name(&self) -> &'static str {
        "principal"
    }

    fn examine(&self, ctx: &PatrolContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        // One finding per agent per shape: a misconfigured gateway making a
        // thousand calls is one problem, not a thousand.
        let mut reported: Vec<(String, bool)> = Vec::new();

        for packet in ctx.packets {
            let did = packet
                .get("agentDid")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let binding = packet
                .get("principal")
                .and_then(PrincipalBinding::from_json);
            let (missing, proven) = match &binding {
                None => (true, false),
                Some(b) => (false, b.is_proven()),
            };
            if proven {
                continue;
            }
            if missing && !self.binding_expected {
                continue;
            }
            let key = (did.to_string(), missing);
            if reported.contains(&key) {
                continue;
            }
            reported.push(key);

            let (severity, summary) = if missing {
                (
                    Severity::High,
                    format!(
                        "{did} has sealed records with no identity binding at all — written by something outside the expected gateway",
                    ),
                )
            } else {
                (
                    Severity::Medium,
                    format!("{did} is acting on a session whose identity was never proven"),
                )
            };
            findings.push(
                Finding::new(
                    FindingKind::UnprovenPrincipal,
                    Strength::Proof,
                    severity,
                    self.name(),
                    ctx.now_utc,
                    summary,
                )
                .about(did)
                .citing([format!("packet:{}", hash_of(packet))]),
            );
        }
        findings
    }
}

// ── Sensor integrity ─────────────────────────────────────────────────────

/// Checks whether any sensor's own raw input stream still recomputes to
/// what the sentinel previously sealed about it.
///
/// Every conclusion the reconciliation and phantom-evidence detectors draw
/// is only as good as the bytes a sensor reported. This is the arithmetic
/// behind that assumption, applied the same way [`ChainIntegrityDetector`]
/// applies it to the evidence chain: a hash either recomputes or it does
/// not, so a finding here is [`Strength::Proof`] outright.
#[derive(Debug, Default)]
pub struct SensorIntegrityDetector;

impl Detector for SensorIntegrityDetector {
    fn name(&self) -> &'static str {
        "sensor-integrity"
    }

    fn examine(&self, ctx: &PatrolContext) -> Vec<Finding> {
        ctx.tampered_checkpoints
            .iter()
            .map(|t| {
                Finding::new(
                    FindingKind::SensorTampered,
                    Strength::Proof,
                    Severity::Critical,
                    self.name(),
                    ctx.now_utc,
                    format!(
                        "sensor \"{}\" stream no longer recomputes at offset {}: sealed {}…, now {}…",
                        t.sensor,
                        t.offset,
                        &t.sealed_hash[..t.sealed_hash.len().min(12)],
                        &t.recomputed_hash[..t.recomputed_hash.len().min(12)],
                    ),
                )
                .citing([format!("sensor-checkpoint:{}:{}", t.sensor, t.offset)])
            })
            .collect()
    }
}

// ── Sensor liveness ──────────────────────────────────────────────────────

/// Flags a sensor that declared coverage of some tools but has gone quiet
/// past its checkpoint deadline — or never checkpointed at all.
///
/// [`ReconciliationDetector`]'s phantom-evidence findings already say
/// coverage is "operator judgement, not arithmetic"; this narrows exactly
/// how much judgement is involved by making the *gap itself* a sealed
/// finding. A patrol with no findings during a coverage gap is not a clean
/// bill of health — it is a period nobody can say was watched.
#[derive(Debug, Default)]
pub struct SensorLivenessDetector;

impl Detector for SensorLivenessDetector {
    fn name(&self) -> &'static str {
        "sensor-liveness"
    }

    fn examine(&self, ctx: &PatrolContext) -> Vec<Finding> {
        // Attestation is opt-in. A deployment that has never sealed a
        // checkpoint for anything has not wired `attest_sensor` in yet, and
        // treating every covering sensor as unattested from patrol one
        // would make "not configured" itself the finding — the same reason
        // `ResponsePolicy` defaults to advisory rather than to violation.
        // The instant one sensor is attested, every covering sensor is held
        // to the standard; there is no per-sensor opt-out.
        if ctx.sensor_checkpoints.is_empty() {
            return Vec::new();
        }
        let Some(now) = parse_iso8601_millis(ctx.now_utc) else {
            return Vec::new();
        };
        let mut findings = Vec::new();

        for (name, sensor) in ctx.sensors {
            // A sensor that claims no coverage has nothing to back up; only
            // a completeness claim can go unattested.
            if sensor.covers_tools.is_empty() {
                continue;
            }
            let last_checkpoint = ctx
                .sensor_checkpoints
                .get(name)
                .and_then(|checkpoints| checkpoints.last());

            let summary = match last_checkpoint {
                None => Some(format!(
                    "sensor \"{name}\" declares coverage of {} but has never checkpointed — its coverage has never been attested",
                    sensor.covers_tools.join(", "),
                )),
                Some(checkpoint) => {
                    let Some(last_ms) = parse_iso8601_millis(&checkpoint.checkpointed_at_utc)
                    else {
                        continue;
                    };
                    let silent_for = now - last_ms;
                    (silent_for > ctx.sensor_heartbeat_deadline_millis).then(|| {
                        format!(
                            "sensor \"{name}\" has not checkpointed for {}s — coverage of {} is unattested since then",
                            silent_for / 1000,
                            sensor.covers_tools.join(", "),
                        )
                    })
                }
            };

            if let Some(summary) = summary {
                findings.push(
                    Finding::new(
                        FindingKind::CoverageGap,
                        // Silence proves nothing happened during the gap;
                        // it only proves the gap. Never above Indicator.
                        Strength::Indicator,
                        Severity::Medium,
                        self.name(),
                        ctx.now_utc,
                        summary,
                    )
                    .citing([format!("sensor:{name}")]),
                );
            }
        }
        findings
    }
}

// ── Sentinel continuity ──────────────────────────────────────────────────

/// Reports a sentinel whose own chain does not continue from where its
/// archive says it left off.
///
/// Every other detector here polices the fleet. This one polices the
/// sentinel, and it exists because the rest of them are only as trustworthy
/// as the record they run against: a sentinel restarted into amnesia holds
/// no sensor checkpoints, so
/// [`crate::sensors::JsonlAccessLog::deep_verify`] has no baseline to catch
/// a pre-restart edit against and [`SensorLivenessDetector`] falls silent.
/// Both then report nothing, which is indistinguishable from a clean
/// patrol. Saying so out loud is the point — the finding's whole content is
/// "do not read this report's silence as safety".
///
/// # Why this never names a subject
///
/// A continuity break is `Proof`-strength and `Critical`, which
/// [`crate::response::ResponsePolicy`] would ordinarily turn into a
/// quarantine of the named subject. The only DID this finding could name is
/// the sentinel's own, and an autonomous sentinel that revokes itself on a
/// forged state file is precisely the self-inflicted denial of service
/// [`crate::finding`] warns about: it would let anyone who can write that
/// file take the watchdog offline. Leaving `subject_did` unset keeps the
/// finding at full severity for the operator while
/// [`crate::patrol::quarantine_list`] and
/// [`crate::patrol::PatrolReport::contained_dids`] — both of which require a
/// subject — correctly revoke nobody.
#[derive(Debug, Default)]
pub struct ContinuityDetector;

impl Detector for ContinuityDetector {
    fn name(&self) -> &'static str {
        "sentinel-continuity"
    }

    fn examine(&self, ctx: &PatrolContext) -> Vec<Finding> {
        let Some(break_) = ctx.continuity_break else {
            return Vec::new();
        };
        vec![Finding::new(
            FindingKind::SentinelContinuityBreak,
            Strength::Proof,
            Severity::Critical,
            self.name(),
            ctx.now_utc,
            break_.summary(),
        )
        .citing(break_.evidence())]
    }
}

/// The packet hash, or a placeholder when the record has none.
fn hash_of(packet: &Value) -> String {
    packet
        .get("packetHash")
        .and_then(Value::as_str)
        .unwrap_or("<unhashed>")
        .to_string()
}

/// Every detector, with default settings.
pub fn default_detectors() -> Vec<Box<dyn Detector + Send + Sync>> {
    vec![
        Box::new(ReconciliationDetector),
        Box::new(EffectConformanceDetector),
        Box::new(ChainIntegrityDetector),
        Box::new(RegistrationDetector),
        Box::new(ModelDriftDetector),
        Box::new(LivenessDetector),
        Box::new(ProbingDetector::default()),
        Box::new(PrincipalDetector::default()),
        Box::new(SensorIntegrityDetector),
        Box::new(SensorLivenessDetector),
        Box::new(ContinuityDetector),
    ]
}
