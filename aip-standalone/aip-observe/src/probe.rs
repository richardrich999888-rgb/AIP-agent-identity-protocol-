//! The host-side probe: measures processes, holds no key.
//!
//! This type runs on the observed host, inside the attacker's reach under the
//! threat model. It therefore has **no signing key, no signing method, and no
//! access to the collector's chain state**. The strongest thing a compromised
//! host can do to this component is feed it lies or stop it; neither produces
//! an attestation, and stopping it produces a visible discontinuity at the
//! collector rather than silence that looks like coverage.
//!
//! What it measures is the kernel's view of a process — the same procfs facts
//! Stage 1 defined, but read by the observer about *another* process rather
//! than by the agent about itself. That is a real independence gain against a
//! non-root agent and no gain at all against root; §"Assumptions" of
//! `OBSERVER_IMPLEMENTATION_REPORT.md` states this plainly.

use aip_core::execution_binding::{parse_boot_id, parse_proc_stat_start_time, BindingError};
use aip_types::ProcessInstance;

use crate::observed::{
    AgentAttribution, ObservationBatch, ObservedEffect, ObservedExecution, ObservedProcess,
    OBSERVE_PROTOCOL_VERSION,
};

/// Why a measurement could not be taken. Never silently substituted with a
/// weaker identifier, and never turned into a statement about the workload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeError {
    UnsupportedPlatform(&'static str),
    /// The process was not there (exited, never existed, or invisible in this
    /// PID namespace). This is a fact about the measurement, not about
    /// whether anything executed.
    ProcessNotVisible {
        pid: u32,
    },
    Unavailable {
        field: &'static str,
        reason: String,
    },
}

impl From<BindingError> for ProbeError {
    fn from(e: BindingError) -> Self {
        match e {
            BindingError::UnsupportedPlatform(p) => ProbeError::UnsupportedPlatform(p),
            BindingError::Unavailable { field, reason } => {
                ProbeError::Unavailable { field, reason }
            }
        }
    }
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ProbeError {}

/// An identity claim handed to the probe by some host-side party. The probe
/// records it verbatim as a claim; it never checks it and never upgrades it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentClaim {
    pub agent_id: String,
    pub claim_source: String,
    pub decision_id: Option<[u8; 16]>,
}

/// Reads process facts from procfs and assembles unsigned batches.
///
/// Deliberately holds no key material: see the module docs.
#[derive(Debug, Clone)]
pub struct ProcfsProbe {
    probe_id: String,
    monotonic_counter: u64,
}

impl ProcfsProbe {
    pub fn new(probe_id: impl Into<String>) -> Self {
        Self {
            probe_id: probe_id.into(),
            monotonic_counter: 0,
        }
    }

    pub fn probe_id(&self) -> &str {
        &self.probe_id
    }

    /// Measure the process facts for `pid` from procfs.
    #[cfg(target_os = "linux")]
    pub fn measure(&self, pid: u32) -> Result<ObservedProcess, ProbeError> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .map_err(|_| ProbeError::ProcessNotVisible { pid })?;
        let pid_start_time_ticks = parse_proc_stat_start_time(&stat)?;
        let boot_text =
            std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|e| {
                ProbeError::Unavailable {
                    field: "boot_id",
                    reason: e.to_string(),
                }
            })?;
        let boot_id = parse_boot_id(&boot_text)?;
        let exe_link = std::path::PathBuf::from(format!("/proc/{pid}/exe"));
        let exe_path = std::fs::read_link(&exe_link)
            .map_err(|_| ProbeError::ProcessNotVisible { pid })?
            .to_string_lossy()
            .into_owned();
        let exe_content_sha256 = aip_core::execution_binding::hash_file_contents(&exe_link)?;
        Ok(ObservedProcess {
            process: ProcessInstance {
                pid,
                pid_start_time_ticks,
                boot_id,
            },
            exe_content_sha256,
            exe_path,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn measure(&self, _pid: u32) -> Result<ObservedProcess, ProbeError> {
        Err(ProbeError::UnsupportedPlatform(std::env::consts::OS))
    }

    /// Build one observation from an already-taken measurement.
    pub fn observation(
        &mut self,
        observed: ObservedProcess,
        effect: ObservedEffect,
        claim: Option<&AgentClaim>,
        host_wall_clock_ms: u64,
    ) -> ObservedExecution {
        self.monotonic_counter += 1;
        ObservedExecution {
            version: OBSERVE_PROTOCOL_VERSION,
            probe_id: self.probe_id.clone(),
            observed,
            attribution: match claim {
                None => AgentAttribution::NotEstablished,
                Some(c) => AgentAttribution::Claimed {
                    agent_id: c.agent_id.clone(),
                    claim_source: c.claim_source.clone(),
                },
            },
            effect,
            claimed_decision_id: claim.and_then(|c| c.decision_id),
            host_wall_clock_ms,
            probe_monotonic_ns: self.monotonic_counter,
        }
    }

    /// Assemble an unsigned batch. The probe cannot sign it, cannot assign it
    /// a chain position, and cannot decide what coverage will be attested.
    pub fn batch(
        &self,
        batch_id: [u8; 16],
        claimed_from_ms: u64,
        claimed_to_ms: u64,
        observations: Vec<ObservedExecution>,
    ) -> ObservationBatch {
        ObservationBatch {
            version: OBSERVE_PROTOCOL_VERSION,
            probe_id: self.probe_id.clone(),
            batch_id,
            claimed_from_ms,
            claimed_to_ms,
            observations,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn probe_measures_a_real_process_and_matches_stage_one_binding() {
        let probe = ProcfsProbe::new("probe-self");
        let pid = std::process::id();
        let measured = probe.measure(pid).unwrap();
        assert_eq!(measured.process.pid, pid);
        assert!(measured.process.pid_start_time_ticks > 0);
        assert_ne!(measured.process.boot_id, [0u8; 16]);
        assert_ne!(measured.exe_content_sha256, [0u8; 32]);

        // The observer's independent measurement agrees with what Stage 1's
        // self-collector reports for the same process — same kernel facts,
        // different reader.
        let self_reported =
            aip_core::execution_binding::collect_self_binding("aip1claimed").unwrap();
        assert!(measured.matches_process_of(&self_reported));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn probing_an_impossible_pid_is_an_explicit_measurement_failure() {
        let probe = ProcfsProbe::new("probe-self");
        assert_eq!(
            probe.measure(u32::MAX),
            Err(ProbeError::ProcessNotVisible { pid: u32::MAX })
        );
    }

    #[test]
    fn a_claim_is_recorded_as_a_claim() {
        let mut probe = ProcfsProbe::new("probe-1");
        let observed = ObservedProcess {
            process: ProcessInstance {
                pid: 1,
                pid_start_time_ticks: 1,
                boot_id: [1u8; 16],
            },
            exe_content_sha256: [2u8; 32],
            exe_path: "/x".into(),
        };
        let claim = AgentClaim {
            agent_id: "aip1agent".into(),
            claim_source: "orchestrator".into(),
            decision_id: Some([9u8; 16]),
        };
        let o = probe.observation(
            observed.clone(),
            ObservedEffect::ProcessPresent,
            Some(&claim),
            5,
        );
        assert!(matches!(o.attribution, AgentAttribution::Claimed { .. }));
        assert_eq!(o.attribution.claimed_agent_id(), Some("aip1agent"));

        let o2 = probe.observation(observed, ObservedEffect::ProcessPresent, None, 6);
        assert_eq!(o2.attribution, AgentAttribution::NotEstablished);
        assert_eq!(o2.claimed_decision_id, None);
        assert!(o2.probe_monotonic_ns > o.probe_monotonic_ns);
    }
}
