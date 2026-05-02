//! Runtime Binding — Binds an agent identity to its execution environment.
//!
//! Computes a SHA-256 fingerprint of the runtime context (hostname, PID,
//! executable path, timestamp) and includes it in identity proofs.

use aip_crypto::sha256;
use serde::{Deserialize, Serialize};

/// A binding between an agent identity and its runtime environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeBinding {
    /// AIP-ID of the bound agent.
    pub agent_id: String,
    /// SHA-256 hash of the concatenated runtime context.
    pub runtime_hash: [u8; 32],
    /// Hostname of the machine (or "unknown").
    pub hostname: String,
    /// Process ID at time of binding.
    pub pid: u32,
    /// SHA-256 of the executable path.
    pub exe_hash: [u8; 32],
    /// Container instance ID if running in a container (or None).
    pub container_id: Option<String>,
    /// Timestamp when binding was created (Unix ms).
    pub bound_at: u64,
}

/// Collect the current runtime context and compute a binding.
///
/// This function gathers:
/// - Hostname (from system, fallback to "unknown")
/// - Process ID
/// - Executable path hash
/// - Optional container ID (from `HOSTNAME` env var if it looks like a container ID)
/// - Current timestamp
///
/// All fields are hashed together to produce `runtime_hash`.
pub fn bind_identity_to_runtime(agent_id: &str) -> RuntimeBinding {
    let hostname = get_hostname();
    let pid = std::process::id();
    let exe_path = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let exe_hash = sha256(exe_path.as_bytes());
    let container_id = detect_container_id();
    let bound_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Compute runtime_hash = SHA-256(agent_id || hostname || pid || exe_hash || bound_at)
    let mut context = Vec::new();
    context.extend_from_slice(agent_id.as_bytes());
    context.extend_from_slice(hostname.as_bytes());
    context.extend_from_slice(&pid.to_le_bytes());
    context.extend_from_slice(&exe_hash);
    context.extend_from_slice(&bound_at.to_le_bytes());
    if let Some(ref cid) = container_id {
        context.extend_from_slice(cid.as_bytes());
    }
    let runtime_hash = sha256(&context);

    RuntimeBinding {
        agent_id: agent_id.to_string(),
        runtime_hash,
        hostname,
        pid,
        exe_hash,
        container_id,
        bound_at,
    }
}

/// Verify that a runtime binding matches the current execution environment.
///
/// Checks hostname and executable path match. PID and timestamp are expected
/// to differ between sessions, so they are not checked.
pub fn verify_runtime_binding(binding: &RuntimeBinding) -> RuntimeBindingVerification {
    let current_hostname = get_hostname();
    let current_exe_hash = std::env::current_exe()
        .map(|p| sha256(p.to_string_lossy().as_bytes()))
        .unwrap_or([0u8; 32]);

    let hostname_match = binding.hostname == current_hostname;
    let exe_match = binding.exe_hash == current_exe_hash;
    let current_container = detect_container_id();
    let container_match = binding.container_id == current_container;

    RuntimeBindingVerification {
        hostname_match,
        exe_match,
        container_match,
        is_same_environment: hostname_match && exe_match,
    }
}

/// Result of verifying a runtime binding against the current environment.
#[derive(Debug, Clone)]
pub struct RuntimeBindingVerification {
    pub hostname_match: bool,
    pub exe_match: bool,
    pub container_match: bool,
    /// True if hostname and executable both match.
    pub is_same_environment: bool,
}

/// Get the system hostname, falling back to "unknown".
fn get_hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| {
            // Try reading from /etc/hostname on Unix
            std::fs::read_to_string("/etc/hostname")
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "unknown".to_string())
        })
}

/// Detect if running inside a container.
/// Checks for Docker/K8s-style container ID in cgroup or CONTAINER_ID env var.
fn detect_container_id() -> Option<String> {
    // Check env var first
    if let Ok(cid) = std::env::var("CONTAINER_ID") {
        return Some(cid);
    }

    // Check if /proc/1/cgroup contains docker/kubepods
    if let Ok(cgroup) = std::fs::read_to_string("/proc/1/cgroup") {
        for line in cgroup.lines() {
            if line.contains("docker") || line.contains("kubepods") {
                // Extract the container ID (last segment after /)
                if let Some(id) = line.rsplit('/').next() {
                    if id.len() >= 12 {
                        return Some(id[..12].to_string());
                    }
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bind_identity_to_runtime() {
        let binding = bind_identity_to_runtime("aip1testAgent");
        assert_eq!(binding.agent_id, "aip1testAgent");
        assert_ne!(binding.runtime_hash, [0u8; 32]);
        assert!(binding.pid > 0);
        assert!(binding.bound_at > 0);
    }

    #[test]
    fn test_different_agents_different_hashes() {
        let binding1 = bind_identity_to_runtime("agent1");
        let binding2 = bind_identity_to_runtime("agent2");
        assert_ne!(
            binding1.runtime_hash, binding2.runtime_hash,
            "Different agents must produce different runtime hashes"
        );
    }

    #[test]
    fn test_verify_runtime_binding_same_env() {
        let binding = bind_identity_to_runtime("testAgent");
        let verification = verify_runtime_binding(&binding);
        // Exe should match since we're in the same process
        assert!(verification.exe_match);
        assert!(verification.is_same_environment);
    }

    #[test]
    fn test_verify_runtime_binding_different_exe() {
        let mut binding = bind_identity_to_runtime("testAgent");
        binding.exe_hash = [0xFFu8; 32]; // Fake exe hash
        let verification = verify_runtime_binding(&binding);
        assert!(!verification.exe_match);
        assert!(!verification.is_same_environment);
    }

    #[test]
    fn test_runtime_binding_serialization() {
        let binding = bind_identity_to_runtime("testAgent");
        let json = serde_json::to_string(&binding).unwrap();
        let deserialized: RuntimeBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.agent_id, binding.agent_id);
        assert_eq!(deserialized.runtime_hash, binding.runtime_hash);
    }
}
