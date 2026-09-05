//! What the observer saw — `ObservedExecution` and the unsigned
//! `ObservationBatch` a host-side probe hands to the collector.
//!
//! Nothing in this module can be signed. Signing lives in [`crate::attest`]
//! and belongs to the collector, which is off-host by construction.

use aip_crypto::sha256;
use aip_types::canonical::*;
use aip_types::{ExecutionBinding, ProcessInstance};
use serde::{Deserialize, Serialize};

/// Domain tag leading the canonical encoding of an [`ObservedExecution`].
pub const OBSERVED_EXECUTION_DOMAIN: &str = "SYNTRIASS/GHOST/OBSERVED_EXECUTION/v1";
/// Domain tag leading the canonical encoding of an [`ObservationBatch`].
pub const OBSERVATION_BATCH_DOMAIN: &str = "SYNTRIASS/GHOST/OBSERVATION_BATCH/v1";
/// Domain tag leading the canonical encoding of the observer-measured process
/// facts only (excludes every claimed field).
pub const OBSERVED_PROCESS_DOMAIN: &str = "SYNTRIASS/GHOST/OBSERVED_PROCESS/v1";
/// Protocol version of every structure in this crate.
pub const OBSERVE_PROTOCOL_VERSION: u16 = 1;

// ─── Agent attribution ───

/// Whether the observer could tie the process it measured to an AIP identity.
///
/// The observer reads the kernel's view of a process. It can measure the
/// process instance and the executable's contents. It **cannot** determine an
/// AIP-ID: that requires proof of key possession, which is an authority
/// question, not an observation. There is deliberately no `Verified` variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentAttribution {
    /// No AIP identity was associated with the observed process.
    NotEstablished,
    /// An AIP-ID was *claimed* to the observer by the named source. The
    /// observer attests that the claim was made, never that it is true.
    Claimed {
        agent_id: String,
        /// Where the claim came from, e.g. "agent-registration",
        /// "orchestrator". Free text; part of the signed bytes so it cannot
        /// be rewritten later, but it confers no trust.
        claim_source: String,
    },
}

impl AgentAttribution {
    pub fn claimed_agent_id(&self) -> Option<&str> {
        match self {
            AgentAttribution::NotEstablished => None,
            AgentAttribution::Claimed { agent_id, .. } => Some(agent_id),
        }
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            AgentAttribution::NotEstablished => put_u8(buf, 0x00),
            AgentAttribution::Claimed {
                agent_id,
                claim_source,
            } => {
                put_u8(buf, 0x01);
                put_str(buf, agent_id);
                put_str(buf, claim_source);
            }
        }
    }
}

// ─── Observed effect ───

/// The kind of effect the observer actually recorded.
///
/// Only process-lifecycle effects are implemented in this slice, because
/// only they have an implemented observation path (procfs). Network,
/// filesystem and syscall variants are **not** present: a variant with no
/// sensor behind it would be a claim, not an observation. Per I23, when a
/// network variant is added it must keep metadata and application payload
/// distinct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservedEffect {
    /// The observer measured a live process at this instant.
    ProcessPresent,
    /// The observer previously measured this instance and now finds it gone.
    /// Absence of the instance is a fact about the observer's own sampling;
    /// it says nothing about what the process did while it existed.
    ProcessNoLongerPresent,
}

impl ObservedEffect {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            ObservedEffect::ProcessPresent => put_u8(buf, 0x01),
            ObservedEffect::ProcessNoLongerPresent => put_u8(buf, 0x02),
        }
    }
}

// ─── Observed process identity ───

/// Exactly the process facts the observer measured itself.
///
/// This is the subset of [`ExecutionBinding`] the observer can establish
/// without trusting anyone: the process instance (pid, start ticks, boot id)
/// and the SHA-256 of the executable's contents. `exe_path` is context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedProcess {
    pub process: ProcessInstance,
    pub exe_content_sha256: [u8; 32],
    pub exe_path: String,
}

impl ObservedProcess {
    fn encode(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.process.pid);
        put_u64(buf, self.process.pid_start_time_ticks);
        buf.extend_from_slice(&self.process.boot_id);
        buf.extend_from_slice(&self.exe_content_sha256);
        put_str(buf, &self.exe_path);
    }

    /// Domain-tagged encoding of the measured facts only. `exe_path` is
    /// excluded so two spellings of one binary compare equal, matching the
    /// Stage 1 identity rule.
    pub fn identity_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, OBSERVED_PROCESS_DOMAIN);
        put_u16(&mut buf, OBSERVE_PROTOCOL_VERSION);
        put_u32(&mut buf, self.process.pid);
        put_u64(&mut buf, self.process.pid_start_time_ticks);
        buf.extend_from_slice(&self.process.boot_id);
        buf.extend_from_slice(&self.exe_content_sha256);
        buf
    }

    pub fn identity_digest(&self) -> [u8; 32] {
        sha256(&self.identity_bytes())
    }

    /// Do the observer's measurements match the process identity inside an
    /// expected/claimed [`ExecutionBinding`]?
    ///
    /// Compares process instance and executable contents only. The binding's
    /// `agent_id` is **not** compared here: the observer never measured it.
    /// Equal PIDs alone can never satisfy this — all three tuple fields and
    /// the executable digest must match.
    pub fn matches_process_of(&self, binding: &ExecutionBinding) -> bool {
        self.process == binding.process && self.exe_content_sha256 == binding.exe_content_sha256
    }
}

// ─── ObservedExecution ───

/// One observation: what the observer measured, when it measured it, and
/// which claims (if any) were attached to it.
///
/// There is no `permitted`, `authorized`, `allowed`, `safe` or `malicious`
/// field, and there never may be (I19). Authorization is the decision
/// point's authority; interpretation is the reconciler's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedExecution {
    pub version: u16,
    /// Identifier of the host-side probe that took the measurement. Not a
    /// trust anchor — the probe cannot sign anything.
    pub probe_id: String,
    /// The facts the observer measured.
    pub observed: ObservedProcess,
    /// Whether an AIP identity was claimed for this process, and by whom.
    pub attribution: AgentAttribution,
    pub effect: ObservedEffect,
    /// Correlation hint copied from a claim, when one was supplied. Present
    /// only so the reconciler can join; it carries no authorization meaning
    /// and the observer never reads an `ExpectedExecution`.
    pub claimed_decision_id: Option<[u8; 16]>,
    /// Host wall clock at measurement, Unix ms. **Contextual only** — the
    /// host clock is attacker-controllable under the threat model. Ordering
    /// comes from the collector's sequence, never from this field.
    pub host_wall_clock_ms: u64,
    /// Monotonic position within this probe run, used for intra-batch order.
    /// Resets on probe restart, which is why it is not a continuity source.
    pub probe_monotonic_ns: u64,
}

impl ObservedExecution {
    /// Canonical, domain-tagged, injective encoding of the whole observation.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, OBSERVED_EXECUTION_DOMAIN);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, &self.probe_id);
        self.observed.encode(&mut buf);
        self.attribution.encode(&mut buf);
        self.effect.encode(&mut buf);
        match &self.claimed_decision_id {
            Some(d) => {
                put_u8(&mut buf, 1);
                buf.extend_from_slice(d);
            }
            None => put_u8(&mut buf, 0),
        }
        put_u64(&mut buf, self.host_wall_clock_ms);
        put_u64(&mut buf, self.probe_monotonic_ns);
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }
}

// ─── ObservationBatch ───

/// A batch of observations as produced on the observed host.
///
/// **Unsigned by construction.** It carries no observer identity, no key
/// version, no sequence number and no chain head: those are collector state
/// that lives off-host, so a compromised host cannot fabricate a position in
/// the attested history. It is the collector that assigns them, in
/// [`crate::attest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationBatch {
    pub version: u16,
    pub probe_id: String,
    pub batch_id: [u8; 16],
    /// The interval the probe claims to have been sampling. A *claim*: the
    /// collector decides what coverage it will attest, and a claimed window
    /// never widens attested coverage.
    pub claimed_from_ms: u64,
    pub claimed_to_ms: u64,
    pub observations: Vec<ObservedExecution>,
}

impl ObservationBatch {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, OBSERVATION_BATCH_DOMAIN);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, &self.probe_id);
        buf.extend_from_slice(&self.batch_id);
        put_u64(&mut buf, self.claimed_from_ms);
        put_u64(&mut buf, self.claimed_to_ms);
        put_u32(&mut buf, self.observations.len() as u32);
        for o in &self.observations {
            put_bytes(&mut buf, &o.canonical_bytes());
        }
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc_at(pid: u32, start: u64, boot: u8, exe: u8) -> ObservedProcess {
        ObservedProcess {
            process: ProcessInstance {
                pid,
                pid_start_time_ticks: start,
                boot_id: [boot; 16],
            },
            exe_content_sha256: [exe; 32],
            exe_path: "/opt/agent".into(),
        }
    }

    #[test]
    fn process_identity_excludes_path_and_survives_pid_reuse() {
        let a = proc_at(42, 1000, 0xb0, 0xe0);
        let mut respelled = a.clone();
        respelled.exe_path = "/opt/./agent".into();
        assert_eq!(a.identity_digest(), respelled.identity_digest());

        let reused = proc_at(42, 2000, 0xb0, 0xe0);
        assert_eq!(a.process.pid, reused.process.pid);
        assert_ne!(a.identity_digest(), reused.identity_digest());

        let rebooted = proc_at(42, 1000, 0xb1, 0xe0);
        assert_ne!(a.identity_digest(), rebooted.identity_digest());

        let replaced_binary = proc_at(42, 1000, 0xb0, 0xe1);
        assert_ne!(a.identity_digest(), replaced_binary.identity_digest());
    }

    #[test]
    fn attribution_encoding_is_injective_and_has_no_verified_variant() {
        let mut none = Vec::new();
        AgentAttribution::NotEstablished.encode(&mut none);
        let mut ab_c = Vec::new();
        AgentAttribution::Claimed {
            agent_id: "ab".into(),
            claim_source: "c".into(),
        }
        .encode(&mut ab_c);
        let mut a_bc = Vec::new();
        AgentAttribution::Claimed {
            agent_id: "a".into(),
            claim_source: "bc".into(),
        }
        .encode(&mut a_bc);
        assert_ne!(none, ab_c);
        assert_ne!(ab_c, a_bc);

        // The only way to name an agent is as a claim.
        let json = serde_json::to_string(&AgentAttribution::Claimed {
            agent_id: "aip1x".into(),
            claim_source: "s".into(),
        })
        .unwrap();
        assert!(json.contains("Claimed"));
        assert!(!json.to_lowercase().contains("verified"));
    }

    #[test]
    fn batch_encoding_is_domain_tagged_and_count_prefixed() {
        let b = ObservationBatch {
            version: OBSERVE_PROTOCOL_VERSION,
            probe_id: "probe-1".into(),
            batch_id: [7u8; 16],
            claimed_from_ms: 1,
            claimed_to_ms: 2,
            observations: vec![],
        };
        let bytes = b.canonical_bytes();
        let tag = OBSERVATION_BATCH_DOMAIN.as_bytes();
        assert_eq!(&bytes[4..4 + tag.len()], tag);

        let mut b2 = b.clone();
        b2.observations.push(ObservedExecution {
            version: OBSERVE_PROTOCOL_VERSION,
            probe_id: "probe-1".into(),
            observed: proc_at(1, 1, 1, 1),
            attribution: AgentAttribution::NotEstablished,
            effect: ObservedEffect::ProcessPresent,
            claimed_decision_id: None,
            host_wall_clock_ms: 0,
            probe_monotonic_ns: 0,
        });
        assert_ne!(b.digest(), b2.digest());
    }
}
