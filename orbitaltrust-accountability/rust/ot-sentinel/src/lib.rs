//! Out-of-band detection of ungoverned agent activity.
//!
//! # The problem this exists for
//!
//! Everything else in this stack is *inline* enforcement. The MCP gateway
//! adjudicates and seals every call that passes through it, and within that
//! channel the guarantees are strong: nothing executes unevidenced, authority
//! is resolved fresh on every call, untrusted context removes capabilities.
//!
//! But all of it is conditional on the agent going through the gateway.
//!
//! An agent that calls a tool server directly, keeps running after its
//! credentials were revoked, spawns a copy of itself, or gets its DID
//! borrowed by something else entirely — none of that touches the funnel, so
//! none of it appears in the ledger. Inline enforcement cannot see its own
//! bypass. That is the ghost problem, and it is not solved by making the
//! gateway stricter, because a stricter gateway is still one an agent can
//! decline to use.
//!
//! # How it is caught
//!
//! By reconciliation, not by watching the agent. Sensors outside the governed
//! channel report what actually happened — a tool server's own access log, an
//! egress proxy, a host process monitor. The sentinel compares that against
//! what the ledger sealed, and the difference is the finding:
//!
//! ```text
//!   observed effects  ─┐
//!                      ├─▶  matched      governed, accounted for
//!   sealed packets    ─┘    unattributed something acted outside the channel
//!                           phantom      the ledger claims what never happened
//! ```
//!
//! Matching is keyed on the digest of the canonical call parameters and is
//! one-to-one, so a ghost cannot hide behind a concurrent legitimate call of
//! the same tool, and a replayed call has no second packet to account for it.
//! Producing evidence for its own payload would mean going through the
//! funnel, which is the thing it is avoiding.
//!
//! Two consequential effects have no packet shape to reconcile against — raw
//! network egress and a spawned process, seen at the network or OS layer with
//! no `params_digest` to key on. Those are judged not by reconciliation but by
//! [`conformance::EffectPolicy`]: an operator declares the destinations egress
//! may reach and the commands a process may be, fail-closed, and
//! [`detector::EffectConformanceDetector`] flags anything outside the declared
//! set. This is the escape the July 2026 frontier-lab intrusions actually
//! used — a network pivot, not a tool call — which nothing here would have
//! seen until the effect it produced was given a detector of its own.
//!
//! Around that sit corroborating detectors that need no sensor at all,
//! because they are arithmetic on the ledger itself: a packet chain that
//! branched means one identity is being driven by two runtimes; a chain that
//! no longer recomputes means records were edited; a recorded model digest
//! that differs from what the lifecycle chain binds means the weights
//! changed underneath the credential.
//!
//! # Law and order, with a warrant standard
//!
//! Findings carry two independent axes: [`finding::Severity`] — how bad if
//! true — and [`finding::Strength`] — how certain. Automatic containment
//! requires [`finding::Strength::Proof`], and
//! [`response::ResponsePolicy::decide`] enforces that in code.
//!
//! The reason is practical. A watchdog that disables agents on statistical
//! suspicion is a denial-of-service weapon aimed at its own fleet: the
//! cheapest attack becomes generating odd-looking traffic until the watchdog
//! takes the real work offline. Requiring arithmetic means an attacker cannot
//! manufacture a sanction without manufacturing a hash collision. The default
//! policy is advisory — it alerts and never acts — because a wrongly
//! contained agent is usually more expensive than a briefly uncontained one,
//! and that judgement belongs to the operator.
//!
//! And the sentinel's own actions are sealed into the same hash-chained
//! ledger under its own DID, citing the evidence that justified them. An
//! enforcement record with no citations cannot be acted on. The watchdog is
//! audited by the same verifier as everything it watches.
//!
//! # What it does not claim
//!
//! A finding is never stronger than the sensor behind it. Sensors are
//! untrusted until an operator vouches for them
//! ([`observation::Sensor::trusted`]), and an untrusted sensor's conclusions
//! are capped below the warrant threshold — they raise alerts, they cannot
//! get an agent quarantined. Likewise, absence of an observation only means
//! something where a sensor has declared coverage
//! ([`observation::Sensor::covering`]); everywhere else, silence is silence.
//!
//! The sentinel cannot see effects no sensor reports. It narrows where a
//! ghost can hide to exactly the reach of the deployed sensors, and says so
//! rather than implying completeness it does not have.
//!
//! # The sensor is held to the same standard as the ledger
//!
//! An operator vouching for a sensor ([`observation::Sensor::trusted`]) was,
//! until now, the only guarantee behind it — a policy decision standing in
//! for a proof. [`attestation::SensorCheckpoint`] closes that: the same hash
//! construction that seals the evidence chain is applied to the sensor's own
//! raw input, sealed onto the sentinel's chain each patrol.
//! [`sensors::JsonlAccessLog::deep_verify`] then re-derives the chain from
//! disk and checks it against what was sealed, so [`detector::SensorIntegrityDetector`]
//! catches a retroactive edit to an already-attested log line with the same
//! arithmetic standard [`detector::ChainIntegrityDetector`] applies to the
//! ledger — even an edit that preserves the file's exact byte length.
//! [`detector::SensorLivenessDetector`] closes the other half: a sensor that
//! stops checkpointing no longer backs up its declared coverage, and the gap
//! is now a sealed [`finding::FindingKind::CoverageGap`] finding rather than
//! a silence indistinguishable from a clean patrol. Both are opt-in — a
//! deployment that never calls [`patrol::Patrol::attest_sensor`] is read as
//! not having adopted the mechanism, the same posture
//! [`response::ResponsePolicy`] takes by defaulting to advisory.
//!
//! # Surviving a restart
//!
//! Both mechanisms above were only as durable as the process holding them.
//! [`patrol::Patrol`] began every run at [`GENESIS_HASH`](ot_accountability_core::GENESIS_HASH),
//! so a restart orphaned its enforcement history and — worse — discarded the
//! sensor checkpoints that [`sensors::JsonlAccessLog::deep_verify`] needs as
//! a baseline. A restarted sentinel could no longer prove anything about
//! edits made before it went down, and reported a clean patrol because it
//! had nothing left to compare against. Anything able to cause a restart
//! could therefore reset the watchdog into amnesia.
//!
//! [`state::PatrolState`] carries the chain head and the checkpoint history
//! across a restart, and [`patrol::Patrol::resume`] restores them. Restoring
//! is not believing: a state file is self-consistent whatever it says, so
//! [`patrol::Patrol::audit_continuity`] checks the resumed head against the
//! archive of anchors the sentinel actually emitted — two independently held
//! records that must agree. [`detector::ContinuityDetector`] reports any
//! disagreement as a [`finding::FindingKind::SentinelContinuityBreak`] at
//! [`finding::Strength::Proof`], distinguishing amnesia, a rolled-back
//! state, a forked head, and a truncated archive. Uniquely among the
//! critical findings it names no subject, so a forged state file cannot be
//! used to make the sentinel revoke itself.
//!
//! # Example
//!
//! ```
//! use ot_sentinel::{
//!     observation::{Observation, Sensor, Subject},
//!     patrol::Patrol,
//!     response::ResponsePolicy,
//! };
//! use serde_json::json;
//!
//! let mut patrol = Patrol::new("did:syntriass:sentinel:SENT-1")
//!     .with_policy(ResponsePolicy::autonomous())
//!     .with_sensor(Sensor::new("tool-server-log").trusted());
//!
//! // The ledger holds nothing: this call never went through the gateway.
//! let observed = [Observation::tool_invocation(
//!     "log-42",
//!     "tool-server-log",
//!     "2026-08-27T12:00:00.000Z",
//!     Subject::Claimed("did:syntriass:agent:AGT-1".into()),
//!     "send_command",
//!     &json!({ "command": "DEORBIT" }),
//! )];
//!
//! let report = patrol.patrol(&[], &[], &observed, "2026-08-27T12:00:05.000Z");
//! assert!(!report.all_clear());
//! ```

#![warn(missing_docs)]

pub mod attestation;
pub mod conformance;
pub mod detector;
pub mod finding;
pub mod observation;
pub mod patrol;
pub mod reconcile;
pub mod registry;
pub mod response;
pub mod runtime;
pub mod sensors;
pub mod state;
pub mod time;

pub use attestation::{SensorCheckpoint, TamperedCheckpoint, SENSOR_STREAM_ATTESTATION};
pub use conformance::EffectPolicy;
pub use detector::{Detector, PatrolContext};
pub use finding::{Finding, FindingKind, Severity, Strength};
pub use observation::{Effect, Observation, Sensor, Subject};
pub use patrol::{Patrol, PatrolReport};
pub use reconcile::{reconcile, Reconciliation};
pub use registry::{AgentRegistry, KnownAgent};
pub use response::{EnforcementAction, Response, ResponsePolicy};
pub use runtime::{now_iso8601, CycleReport, RuntimeConfig, SentinelRuntime};
pub use sensors::{
    read_evidence_ledger, AccessLogLine, EffectLogLine, JsonlAccessLog, JsonlEffectLog,
    JsonlSensorLog, LineParser, TailReport,
};
pub use state::{verify_continuity, ContinuityBreak, PatrolState};
