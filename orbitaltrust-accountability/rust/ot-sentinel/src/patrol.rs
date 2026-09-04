//! The patrol: run every detector over a window, decide, and seal.
//!
//! A patrol is a pure function of what it was given — sealed records,
//! observations, the clock — so the same window always produces the same
//! report. That matters for an enforcement system: a decision an operator
//! disputes can be re-run from the archived inputs and must come out the
//! same way, or the sentinel's conclusions are not reviewable.

use ot_accountability_core::{chain_payload_bytes, seal_hash, GENESIS_HASH};
use serde_json::{json, Value};
use std::collections::BTreeMap;

use crate::attestation::{SensorCheckpoint, TamperedCheckpoint, SENSOR_STREAM_ATTESTATION};
use crate::conformance::EffectPolicy;
use crate::detector::{default_detectors, Detector, PatrolContext};
use crate::finding::{Finding, Severity, Strength};
use crate::observation::{Effect, Observation, Sensor};
use crate::reconcile::DEFAULT_TOLERANCE_MILLIS;
use crate::registry::{AgentRegistry, DEFAULT_HEARTBEAT_DEADLINE_MILLIS};
use crate::response::{EnforcementAction, Response, ResponsePolicy};
use crate::state::{verify_continuity, ContinuityBreak, PatrolState};

/// Default: a covering sensor is expected to checkpoint at least this often.
/// Shorter than [`DEFAULT_HEARTBEAT_DEADLINE_MILLIS`] on purpose — a sensor
/// is infrastructure the operator controls and should check in every patrol
/// cycle, where an agent may legitimately go longer between actions.
pub const DEFAULT_SENSOR_HEARTBEAT_DEADLINE_MILLIS: i64 = 120_000;

/// What one patrol concluded.
#[derive(Debug, Clone, Default)]
pub struct PatrolReport {
    /// Everything found, most serious first.
    pub findings: Vec<Finding>,
    /// What the policy decided to do about each.
    pub actions: Vec<EnforcementAction>,
    /// Sealed `SENTINEL_ENFORCEMENT` anchors, chained under the sentinel's
    /// own DID, in the order they were written.
    pub sealed_anchors: Vec<Value>,
    /// How many packets were examined.
    pub packets_examined: usize,
    /// How many observations were examined.
    pub observations_examined: usize,
}

impl PatrolReport {
    /// Findings at or above `floor`.
    pub fn at_least(&self, floor: Severity) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.severity >= floor)
            .collect()
    }

    /// Actions that took authority away from an agent.
    pub fn containments(&self) -> Vec<&EnforcementAction> {
        self.actions.iter().filter(|a| a.is_containment()).collect()
    }

    /// DIDs the patrol decided to contain.
    pub fn contained_dids(&self) -> Vec<String> {
        let mut dids: Vec<String> = self
            .containments()
            .iter()
            .filter_map(|a| a.subject_did.clone())
            .collect();
        dids.sort();
        dids.dedup();
        dids
    }

    /// True when nothing needs a human.
    pub fn all_clear(&self) -> bool {
        self.findings.is_empty()
    }

    /// A one-line summary for an operator log.
    pub fn headline(&self) -> String {
        if self.all_clear() {
            return format!(
                "clear — {} packets, {} observations reconciled",
                self.packets_examined, self.observations_examined
            );
        }
        let critical = self.at_least(Severity::Critical).len();
        let contained = self.containments().len();
        format!(
            "{} finding(s), {critical} critical, {contained} containment(s) — {} packets, {} observations",
            self.findings.len(),
            self.packets_examined,
            self.observations_examined,
        )
    }
}

/// The sentinel.
pub struct Patrol {
    sentinel_did: String,
    detectors: Vec<Box<dyn Detector + Send + Sync>>,
    policy: ResponsePolicy,
    sensors: BTreeMap<String, Sensor>,
    tolerance_millis: i64,
    heartbeat_deadline_millis: i64,
    sensor_heartbeat_deadline_millis: i64,
    /// Sealed checkpoint history per sensor, oldest first — what
    /// [`SensorLivenessDetector`](crate::detector::SensorLivenessDetector)
    /// reads to know how recently each sensor last attested.
    sensor_checkpoints: BTreeMap<String, Vec<SensorCheckpoint>>,
    /// The declared egress/spawn conformance posture, or `None` for a
    /// deployment that has not declared one.
    effect_policy: Option<EffectPolicy>,
    /// Head of the sentinel's own chain, so its conduct — enforcement
    /// actions and sensor attestations alike — is tamper-evident across
    /// patrols the same way an agent's is. One chain, one law: an
    /// attestation is exactly as sealed as a quarantine.
    anchor_tail: String,
    anchor_sequence: u64,
    /// A continuity disagreement found at resume, latched for the life of
    /// the process. Latched rather than recomputed per patrol because the
    /// break is a property of how this process started, not of the window
    /// being examined: it does not stop being true once the sentinel has
    /// sealed enough new anchors to pass its own head check again.
    continuity_break: Option<ContinuityBreak>,
}

impl Patrol {
    /// A patrol with the default detector suite and an advisory policy.
    pub fn new(sentinel_did: impl Into<String>) -> Self {
        Self {
            sentinel_did: sentinel_did.into(),
            detectors: default_detectors(),
            policy: ResponsePolicy::default(),
            sensors: BTreeMap::new(),
            tolerance_millis: DEFAULT_TOLERANCE_MILLIS,
            heartbeat_deadline_millis: DEFAULT_HEARTBEAT_DEADLINE_MILLIS,
            sensor_heartbeat_deadline_millis: DEFAULT_SENSOR_HEARTBEAT_DEADLINE_MILLIS,
            sensor_checkpoints: BTreeMap::new(),
            effect_policy: None,
            anchor_tail: GENESIS_HASH.to_string(),
            anchor_sequence: 0,
            continuity_break: None,
        }
    }

    /// Resumes a sentinel from a previously captured [`PatrolState`] instead
    /// of starting fresh at genesis.
    ///
    /// This restores two things a restart otherwise loses: the head of the
    /// sentinel's own chain, so its new anchors extend its old ones rather
    /// than starting a second chain under the same DID; and the sensor
    /// checkpoint history, which is the only baseline
    /// [`crate::sensors::JsonlAccessLog::deep_verify`] can catch a
    /// pre-restart edit against.
    ///
    /// Restoring is not the same as believing. A state file is
    /// self-consistent whatever it says, so resuming from one proves
    /// nothing on its own — call [`Patrol::audit_continuity`] against the
    /// archive of anchors this sentinel emitted to find out whether the
    /// state it just adopted is the state it actually left.
    ///
    /// Fails when the state belongs to a different sentinel: splicing one
    /// sentinel's chain onto another's DID would produce a chain that
    /// verifies internally while describing conduct neither of them had.
    pub fn resume(state: PatrolState, sentinel_did: impl Into<String>) -> Result<Self, String> {
        let sentinel_did = sentinel_did.into();
        if state.sentinel_did != sentinel_did {
            return Err(format!(
                "patrol state belongs to {} but was resumed as {sentinel_did}",
                state.sentinel_did
            ));
        }
        let mut patrol = Self::new(sentinel_did);
        patrol.anchor_tail = state.anchor_tail;
        patrol.anchor_sequence = state.anchor_sequence;
        patrol.sensor_checkpoints = state.sensor_checkpoints;
        Ok(patrol)
    }

    /// Captures everything this sentinel must carry across a restart.
    ///
    /// Take one after each patrol and persist it; hand it back to
    /// [`Patrol::resume`] on the way up.
    pub fn snapshot(&self) -> PatrolState {
        PatrolState {
            sentinel_did: self.sentinel_did.clone(),
            anchor_tail: self.anchor_tail.clone(),
            anchor_sequence: self.anchor_sequence,
            sensor_checkpoints: self.sensor_checkpoints.clone(),
        }
    }

    /// Checks the head this sentinel is running from against the archive of
    /// anchors it previously emitted, latching any disagreement so
    /// [`ContinuityDetector`](crate::detector::ContinuityDetector) reports
    /// it on every patrol from here on.
    ///
    /// Opt-in, like the rest of the crate: a deployment that never calls
    /// this gets exactly the behaviour it had before, and one that does gets
    /// a `Critical`, `Proof`-strength finding when its own record cannot
    /// account for itself. Returns the break for a caller that wants to
    /// refuse to start at all rather than run and report.
    ///
    /// Call at startup against a settled archive — see
    /// [`verify_continuity`] on why an archive mid-flush reads as truncated.
    pub fn audit_continuity(&mut self, archived_anchors: &[Value]) -> Option<&ContinuityBreak> {
        self.continuity_break = verify_continuity(
            &self.sentinel_did,
            self.anchor_sequence,
            &self.anchor_tail,
            archived_anchors,
        );
        self.continuity_break.as_ref()
    }

    /// Sets the response policy.
    pub fn with_policy(mut self, policy: ResponsePolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Declares the egress/spawn conformance posture. Without this, the
    /// conformance detector is silent; with it, egress or spawns outside the
    /// declared set are findings, fail-closed within each declared dimension.
    pub fn with_effect_policy(mut self, policy: EffectPolicy) -> Self {
        self.effect_policy = Some(policy);
        self
    }

    /// Registers a sensor. Unregistered sensors are untrusted and claim no
    /// coverage, so registering one can only ever narrow what the sentinel
    /// concludes from it — never broaden it silently.
    pub fn with_sensor(mut self, sensor: Sensor) -> Self {
        self.sensors.insert(sensor.name.clone(), sensor);
        self
    }

    /// Sets how far an effect may be from its evidence.
    pub fn with_tolerance_millis(mut self, millis: i64) -> Self {
        self.tolerance_millis = millis;
        self
    }

    /// Sets how long an agent may be silent.
    pub fn with_heartbeat_deadline_millis(mut self, millis: i64) -> Self {
        self.heartbeat_deadline_millis = millis;
        self
    }

    /// Sets how long a covering sensor may go without checkpointing before
    /// its coverage is treated as unattested.
    pub fn with_sensor_heartbeat_deadline_millis(mut self, millis: i64) -> Self {
        self.sensor_heartbeat_deadline_millis = millis;
        self
    }

    /// Seals a sensor's current stream position onto the sentinel's own
    /// chain as a `SENSOR_STREAM_ATTESTATION` anchor, and records it so
    /// [`SensorLivenessDetector`](crate::detector::SensorLivenessDetector)
    /// can see how recently the sensor last checked in. Call once per patrol
    /// per sensor, right after polling it — the checkpoint this seals is
    /// exactly what a later
    /// [`crate::sensors::JsonlAccessLog::deep_verify`] will be asked to
    /// reproduce.
    pub fn attest_sensor(&mut self, checkpoint: SensorCheckpoint, now_utc: &str) -> Value {
        let payload = checkpoint.to_payload();
        let anchor = self.seal_anchor(
            SENSOR_STREAM_ATTESTATION,
            "sensor-attestation",
            payload,
            now_utc,
        );
        self.sensor_checkpoints
            .entry(checkpoint.sensor.clone())
            .or_default()
            .push(checkpoint);
        anchor
    }

    /// Replaces the detector suite.
    pub fn with_detectors(mut self, detectors: Vec<Box<dyn Detector + Send + Sync>>) -> Self {
        self.detectors = detectors;
        self
    }

    /// The sentinel's DID.
    pub fn sentinel_did(&self) -> &str {
        &self.sentinel_did
    }

    /// The head of the sentinel's own enforcement chain.
    pub fn enforcement_tail(&self) -> &str {
        &self.anchor_tail
    }

    /// Runs one patrol over a window.
    pub fn patrol(
        &mut self,
        packets: &[Value],
        anchors: &[Value],
        observations: &[Observation],
        now_utc: &str,
    ) -> PatrolReport {
        self.patrol_with_integrity(packets, anchors, observations, &[], now_utc)
    }

    /// Runs one patrol, additionally taking the results of a
    /// [`crate::sensors::JsonlAccessLog::deep_verify`] pass so
    /// [`SensorIntegrityDetector`](crate::detector::SensorIntegrityDetector)
    /// can report on them.
    ///
    /// Kept as a separate entry point rather than a parameter on
    /// [`Patrol::patrol`] so a deployment that never runs a deep verify —
    /// every existing caller, until it opts in — pays nothing for the
    /// option and needs no code change.
    pub fn patrol_with_integrity(
        &mut self,
        packets: &[Value],
        anchors: &[Value],
        observations: &[Observation],
        tampered_checkpoints: &[TamperedCheckpoint],
        now_utc: &str,
    ) -> PatrolReport {
        let mut registry = AgentRegistry::from_anchors(anchors);
        for observation in observations {
            if let (Effect::Heartbeat { .. }, Some(did)) =
                (&observation.effect, observation.subject.did())
            {
                registry.record_heartbeat(did, &observation.observed_at_utc);
            }
        }

        let ctx = PatrolContext {
            packets,
            anchors,
            observations,
            sensors: &self.sensors,
            registry: &registry,
            now_utc,
            tolerance_millis: self.tolerance_millis,
            heartbeat_deadline_millis: self.heartbeat_deadline_millis,
            sensor_checkpoints: &self.sensor_checkpoints,
            tampered_checkpoints,
            sensor_heartbeat_deadline_millis: self.sensor_heartbeat_deadline_millis,
            effect_policy: self.effect_policy.as_ref(),
            continuity_break: self.continuity_break.as_ref(),
        };

        let mut findings: Vec<Finding> = self
            .detectors
            .iter()
            .flat_map(|detector| detector.examine(&ctx))
            .collect();

        // Most serious first, then most certain, then stably by kind and
        // subject so a report is reproducible rather than hash-order.
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(b.strength.cmp(&a.strength))
                .then(a.kind.cmp(&b.kind))
                .then(a.subject_did.cmp(&b.subject_did))
                .then(a.summary.cmp(&b.summary))
        });

        let mut report = PatrolReport {
            packets_examined: packets.len(),
            observations_examined: observations.len(),
            ..Default::default()
        };

        for finding in findings {
            let response = self.policy.decide(&finding);
            let action = EnforcementAction {
                sentinel_did: self.sentinel_did.clone(),
                subject_did: finding.subject_did.clone(),
                response,
                finding: finding.clone(),
                decided_at_utc: now_utc.to_string(),
            };
            // Observe-level actions are the finding itself; sealing an anchor
            // for every routine note would bury the record of real decisions
            // in noise.
            if response > Response::Observe {
                report.sealed_anchors.push(self.seal(&action, now_utc));
            }
            report.findings.push(finding);
            report.actions.push(action);
        }

        report
    }

    /// Seals one enforcement action onto the sentinel's own chain, under the
    /// same law the fleet's chains follow.
    fn seal(&mut self, action: &EnforcementAction, now_utc: &str) -> Value {
        self.seal_anchor(
            "SENTINEL_ENFORCEMENT",
            "enforcement",
            action.to_payload(),
            now_utc,
        )
    }

    /// Seals one anchor onto the sentinel's own chain. The one place either
    /// an enforcement action or a sensor attestation actually becomes a
    /// chained record — one head, one law, so the sentinel's own conduct is
    /// exactly as tamper-evident as what it polices.
    fn seal_anchor(
        &mut self,
        anchor_type: &str,
        id_suffix: &str,
        payload: Value,
        now_utc: &str,
    ) -> Value {
        let sequence = self.anchor_sequence + 1;
        let mut anchor = json!({
            "anchorId": format!("{}#{id_suffix}-{sequence}", self.sentinel_did),
            "sequenceNumber": sequence,
            "anchorType": anchor_type,
            "agentDid": self.sentinel_did,
            "actorDid": self.sentinel_did,
            "timestampUtc": now_utc,
            "payload": payload,
        });
        let hash = seal_hash(
            &self.anchor_tail,
            &chain_payload_bytes(&anchor, &["previousAnchorHash", "anchorHash"]),
        );
        anchor["previousAnchorHash"] = json!(self.anchor_tail);
        anchor["anchorHash"] = json!(hash);
        self.anchor_tail = hash;
        self.anchor_sequence = sequence;
        anchor
    }
}

/// Convenience: the DIDs a report says should lose authority, ready to feed
/// to the governing gateway's revocation path.
pub fn quarantine_list(report: &PatrolReport) -> Vec<(String, String)> {
    report
        .containments()
        .iter()
        .filter(|a| a.response >= Response::Quarantine)
        .filter_map(|a| {
            a.subject_did.clone().map(|did| {
                (
                    did,
                    format!("{}: {}", a.finding.kind.as_str(), a.finding.summary),
                )
            })
        })
        .collect()
}

/// True when every finding in a report is at least corroborated — a report an
/// operator can read without wading through statistical noise.
pub fn is_high_confidence(report: &PatrolReport) -> bool {
    report
        .findings
        .iter()
        .all(|f| f.strength >= Strength::Corroborated)
}

/// Every observation whose sensor is not registered. Worth surfacing: a
/// sentinel drawing conclusions from a source nobody configured is a
/// deployment mistake, not a fleet problem.
pub fn observations_from_unknown_sensors<'a>(
    patrol: &Patrol,
    observations: &'a [Observation],
) -> Vec<&'a Observation> {
    observations
        .iter()
        .filter(|o| !patrol.sensors.contains_key(&o.sensor))
        .collect()
}
