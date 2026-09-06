//! Target attribution: the binding the request names must be the process
//! instance that is alive now (Skill 9 §15; I3, I4).
//!
//! A pidfd is opened first and held for the life of the attribution, so
//! the pid number cannot be recycled underneath the check; then the start
//! ticks, boot id and executable contents are read through procfs and
//! compared with the binding. Any disagreement is a refusal named for what
//! disagreed. Nothing here guesses.

use aip_types::{ExecutionBinding, ProcessInstance};
use serde::{Deserialize, Serialize};

/// Why the named target could not be established as the live instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttributionFailure {
    /// No process with this pid is visible.
    ProcessNotVisible {
        pid: u32,
    },
    /// A process with this pid is alive, but it is not the instance the
    /// binding names — the number was reused.
    InstanceMismatch {
        pid: u32,
        expected_start_ticks: u64,
        found_start_ticks: u64,
    },
    /// The binding is from another boot.
    BootMismatch,
    /// The live instance runs different executable contents than bound.
    ExecutableMismatch,
    /// The containment process itself.
    SelfTarget,
    /// PID 1.
    InitTarget,
    Unavailable {
        reason: String,
    },
}

impl AttributionFailure {
    pub fn code(&self) -> u8 {
        match self {
            AttributionFailure::ProcessNotVisible { .. } => 0x01,
            AttributionFailure::InstanceMismatch { .. } => 0x02,
            AttributionFailure::BootMismatch => 0x03,
            AttributionFailure::ExecutableMismatch => 0x04,
            AttributionFailure::SelfTarget => 0x05,
            AttributionFailure::InitTarget => 0x06,
            AttributionFailure::Unavailable { .. } => 0x07,
        }
    }
}

impl std::fmt::Display for AttributionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A target established live. Holds the kernel handle so the instance
/// cannot be confused with a later holder of the same pid while this
/// value exists.
#[derive(Debug)]
pub struct Attributed {
    #[cfg(target_os = "linux")]
    pidfd: aip_observe::PidFd,
    agent_id: String,
    process: ProcessInstance,
    exe_content_sha256: [u8; 32],
}

impl Attributed {
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub fn process(&self) -> &ProcessInstance {
        &self.process
    }

    pub fn exe_content_sha256(&self) -> &[u8; 32] {
        &self.exe_content_sha256
    }

    /// Is the bound instance still alive right now?
    pub fn is_alive(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.pidfd.is_alive().unwrap_or(false)
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }
}

/// Establish `binding` as a live process instance.
#[cfg(target_os = "linux")]
pub fn attribute(binding: &ExecutionBinding) -> Result<Attributed, AttributionFailure> {
    use aip_core::execution_binding::{
        hash_file_contents, parse_boot_id, parse_proc_stat_start_time,
    };
    use aip_observe::{PidFd, ProbeError};

    let pid = binding.process.pid;
    if pid == std::process::id() {
        return Err(AttributionFailure::SelfTarget);
    }
    if pid == 1 {
        return Err(AttributionFailure::InitTarget);
    }
    let pidfd = PidFd::open(pid).map_err(|e| match e {
        ProbeError::ProcessNotVisible { pid } => AttributionFailure::ProcessNotVisible { pid },
        other => AttributionFailure::Unavailable {
            reason: other.to_string(),
        },
    })?;
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|_| AttributionFailure::ProcessNotVisible { pid })?;
    let found_start_ticks =
        parse_proc_stat_start_time(&stat).map_err(|e| AttributionFailure::Unavailable {
            reason: e.to_string(),
        })?;
    if found_start_ticks != binding.process.pid_start_time_ticks {
        return Err(AttributionFailure::InstanceMismatch {
            pid,
            expected_start_ticks: binding.process.pid_start_time_ticks,
            found_start_ticks,
        });
    }
    let boot_text = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|e| {
        AttributionFailure::Unavailable {
            reason: format!("boot_id: {e}"),
        }
    })?;
    let boot_id = parse_boot_id(&boot_text).map_err(|e| AttributionFailure::Unavailable {
        reason: e.to_string(),
    })?;
    if boot_id != binding.process.boot_id {
        return Err(AttributionFailure::BootMismatch);
    }
    let exe =
        hash_file_contents(std::path::Path::new(&format!("/proc/{pid}/exe"))).map_err(|e| {
            AttributionFailure::Unavailable {
                reason: e.to_string(),
            }
        })?;
    if exe != binding.exe_content_sha256 {
        return Err(AttributionFailure::ExecutableMismatch);
    }
    if !pidfd.is_alive().unwrap_or(false) {
        return Err(AttributionFailure::ProcessNotVisible { pid });
    }
    Ok(Attributed {
        pidfd,
        agent_id: binding.agent_id.clone(),
        process: binding.process,
        exe_content_sha256: exe,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn attribute(_binding: &ExecutionBinding) -> Result<Attributed, AttributionFailure> {
    Err(AttributionFailure::Unavailable {
        reason: "attribution requires Linux procfs and pidfd".into(),
    })
}
