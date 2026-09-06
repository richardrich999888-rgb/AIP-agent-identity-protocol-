//! Execution Binding — collect and digest the identity of a process instance.
//!
//! Ghost Stage 1. Produces [`ExecutionBinding`] values from the Linux procfs:
//!
//! | Field | Source | Notes |
//! |---|---|---|
//! | `process.pid` | `/proc/<pid>` | recycled by the kernel; never identity alone |
//! | `process.pid_start_time_ticks` | field 22 of `/proc/<pid>/stat` | clock ticks (`CLK_TCK`, usually 100/s) since boot; fixed for the process lifetime |
//! | `process.boot_id` | `/proc/sys/kernel/random/boot_id` | random UUID generated at boot |
//! | `exe_content_sha256` | contents of `/proc/<pid>/exe` | the binary, not the path |
//! | `exe_path` | `readlink(/proc/<pid>/exe)` | context only |
//!
//! **Trust boundary.** Everything here is read by the calling process from
//! its own kernel view. A binding produced by `collect_self_binding` is a
//! *self-report*: it gives reconciliation a meaningful join key, but it is
//! not independent observation and must not be treated as proof that the
//! process exists or ran. A root-compromised host can present any procfs
//! content it likes. Independent attestation is the Observer's job (Stage 3).
//!
//! **Failure semantics.** If any required fact cannot be read or parsed, the
//! result is [`BindingError`]; no field is ever defaulted, zeroed, or
//! substituted with a weaker identifier (hostname, path, wall clock).
//!
//! **Platform.** Linux only. Other targets return
//! [`BindingError::UnsupportedPlatform`] rather than a degraded binding.

use aip_crypto::sha256;
use aip_types::{ExecutionBinding, ProcessInstance, EXECUTION_BINDING_VERSION};

/// Why a binding could not be established. Never silently recoverable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingError {
    /// The target platform does not expose the required process facts.
    UnsupportedPlatform(&'static str),
    /// A required source could not be read or parsed.
    Unavailable { field: &'static str, reason: String },
}

impl std::fmt::Display for BindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindingError::UnsupportedPlatform(p) => {
                write!(f, "execution binding unsupported on platform {p}")
            }
            BindingError::Unavailable { field, reason } => {
                write!(f, "execution binding field `{field}` unavailable: {reason}")
            }
        }
    }
}

impl std::error::Error for BindingError {}

// ─── Digests ───

/// SHA-256 over [`ExecutionBinding::canonical_bytes`] — the digest of the
/// whole binding as content.
pub fn binding_digest(b: &ExecutionBinding) -> [u8; 32] {
    sha256(&b.canonical_bytes())
}

/// SHA-256 over [`ExecutionBinding::identity_bytes`] — the execution identity
/// used as a reconciliation join key (agent + process instance + executable
/// contents; excludes path and collection time).
pub fn execution_identity_digest(b: &ExecutionBinding) -> [u8; 32] {
    sha256(&b.identity_bytes())
}

// ─── Parsers (pure; testable without procfs) ───

/// Extract field 22 (`starttime`, clock ticks since boot) from the contents
/// of `/proc/<pid>/stat`.
///
/// The `comm` field (2) is parenthesised and may itself contain spaces and
/// parentheses, so fields are counted from the *last* `)`.
pub fn parse_proc_stat_start_time(stat: &str) -> Result<u64, BindingError> {
    let close = stat.rfind(')').ok_or_else(|| BindingError::Unavailable {
        field: "pid_start_time_ticks",
        reason: "no `)` terminating comm in /proc/<pid>/stat".into(),
    })?;
    let rest = &stat[close + 1..];
    // After `)` the next field is #3 (state). Field 22 is therefore the 20th
    // whitespace-separated token of `rest` (index 19).
    let tok = rest
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| BindingError::Unavailable {
            field: "pid_start_time_ticks",
            reason: "fewer than 22 fields in /proc/<pid>/stat".into(),
        })?;
    let ticks = tok.parse::<u64>().map_err(|e| BindingError::Unavailable {
        field: "pid_start_time_ticks",
        reason: format!("field 22 `{tok}` is not a u64: {e}"),
    })?;
    if ticks == 0 {
        // Only PID 0/idle has starttime 0; a user process reporting 0 is
        // not a usable instance identifier.
        return Err(BindingError::Unavailable {
            field: "pid_start_time_ticks",
            reason: "start time is 0".into(),
        });
    }
    Ok(ticks)
}

/// Parse the textual UUID in `/proc/sys/kernel/random/boot_id` into 16 bytes.
pub fn parse_boot_id(text: &str) -> Result<[u8; 16], BindingError> {
    let hex: String = text.trim().chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(BindingError::Unavailable {
            field: "boot_id",
            reason: format!("`{}` is not a 128-bit UUID", text.trim()),
        });
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).map_err(|e| {
            BindingError::Unavailable {
                field: "boot_id",
                reason: e.to_string(),
            }
        })?;
    }
    if out == [0u8; 16] {
        return Err(BindingError::Unavailable {
            field: "boot_id",
            reason: "boot_id is all zeros".into(),
        });
    }
    Ok(out)
}

/// SHA-256 of a file's contents, streamed.
pub fn hash_file_contents(path: &std::path::Path) -> Result<[u8; 32], BindingError> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut f = std::fs::File::open(path).map_err(|e| BindingError::Unavailable {
        field: "exe_content_sha256",
        reason: format!("open {}: {e}", path.display()),
    })?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|e| BindingError::Unavailable {
            field: "exe_content_sha256",
            reason: format!("read {}: {e}", path.display()),
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

// ─── Collection (Linux procfs) ───

/// Collect the binding of the calling process, as a self-report.
pub fn collect_self_binding(agent_id: &str) -> Result<ExecutionBinding, BindingError> {
    collect_binding_for_pid(agent_id, std::process::id())
}

/// Collect the binding of an arbitrary PID visible in this PID namespace.
///
/// Used by the calling process about itself today; a future observer that
/// runs outside the agent's trust boundary may reuse the same parsers.
#[cfg(target_os = "linux")]
pub fn collect_binding_for_pid(agent_id: &str, pid: u32) -> Result<ExecutionBinding, BindingError> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|e| {
        BindingError::Unavailable {
            field: "pid_start_time_ticks",
            reason: format!("read /proc/{pid}/stat: {e}"),
        }
    })?;
    let pid_start_time_ticks = parse_proc_stat_start_time(&stat)?;

    let boot_text = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|e| {
        BindingError::Unavailable {
            field: "boot_id",
            reason: format!("read boot_id: {e}"),
        }
    })?;
    let boot_id = parse_boot_id(&boot_text)?;

    let exe_link = std::path::PathBuf::from(format!("/proc/{pid}/exe"));
    let exe_path = std::fs::read_link(&exe_link)
        .map_err(|e| BindingError::Unavailable {
            field: "exe_path",
            reason: format!("readlink /proc/{pid}/exe: {e}"),
        })?
        .to_string_lossy()
        .into_owned();
    // Hash through the /proc link so we hash the mapped binary even if the
    // path on disk was replaced or unlinked after exec.
    let exe_content_sha256 = hash_file_contents(&exe_link)?;

    let bound_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| BindingError::Unavailable {
            field: "bound_at_ms",
            reason: e.to_string(),
        })?
        .as_millis() as u64;

    Ok(ExecutionBinding {
        version: EXECUTION_BINDING_VERSION,
        agent_id: agent_id.to_string(),
        process: ProcessInstance {
            pid,
            pid_start_time_ticks,
            boot_id,
        },
        exe_content_sha256,
        exe_path,
        bound_at_ms,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn collect_binding_for_pid(
    _agent_id: &str,
    _pid: u32,
) -> Result<ExecutionBinding, BindingError> {
    Err(BindingError::UnsupportedPlatform(std::env::consts::OS))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_types::{EXECUTION_BINDING_DOMAIN, EXECUTION_IDENTITY_DOMAIN};

    fn binding(
        agent: &str,
        pid: u32,
        start: u64,
        boot: u8,
        exe: u8,
        path: &str,
    ) -> ExecutionBinding {
        ExecutionBinding {
            version: EXECUTION_BINDING_VERSION,
            agent_id: agent.into(),
            process: ProcessInstance {
                pid,
                pid_start_time_ticks: start,
                boot_id: [boot; 16],
            },
            exe_content_sha256: [exe; 32],
            exe_path: path.into(),
            bound_at_ms: 1_700_000_000_000,
        }
    }

    // ── Test A: PID reuse within one boot ──
    #[test]
    fn same_pid_different_start_time_is_a_different_instance() {
        let a = binding("aip1agent", 4242, 1000, 0xB0, 0xE0, "/opt/agent");
        let b = binding("aip1agent", 4242, 2000, 0xB0, 0xE0, "/opt/agent");
        assert_ne!(a.process, b.process);
        assert!(!a.same_execution(&b));
        assert_ne!(execution_identity_digest(&a), execution_identity_digest(&b));
    }

    // ── Test B: same PID and start ticks, different boot ──
    #[test]
    fn same_pid_same_start_different_boot_is_a_different_instance() {
        let a = binding("aip1agent", 4242, 1000, 0xB1, 0xE0, "/opt/agent");
        let b = binding("aip1agent", 4242, 1000, 0xB2, 0xE0, "/opt/agent");
        assert_ne!(a.process, b.process);
        assert!(!a.same_execution(&b));
    }

    // ── §14 permanent guard: PID equality is never identity ──
    #[test]
    fn pid_equality_never_implies_same_execution() {
        let a = binding("aip1agent", 7, 1, 0x01, 0xE0, "/x");
        let variants = [
            binding("aip1agent", 7, 2, 0x01, 0xE0, "/x"), // start differs
            binding("aip1agent", 7, 1, 0x02, 0xE0, "/x"), // boot differs
            binding("aip1agent", 7, 1, 0x01, 0xE1, "/x"), // executable differs
            binding("aip1other", 7, 1, 0x01, 0xE0, "/x"), // agent differs
        ];
        for v in &variants {
            assert_eq!(a.process.pid, v.process.pid, "precondition: PIDs equal");
            assert!(
                !a.same_execution(v),
                "identity collapsed to PID equality: {v:?}"
            );
        }
        // And the positive case still works.
        assert!(a.same_execution(&a.clone()));
    }

    // ── Test C: executable replacement at the same path ──
    #[test]
    fn same_path_different_contents_yields_different_executable_identity() {
        let dir = std::env::temp_dir().join(format!("aip-exec-bind-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("agent");
        std::fs::write(&path, b"binary A").unwrap();
        let h_a = hash_file_contents(&path).unwrap();
        std::fs::write(&path, b"binary B").unwrap();
        let h_b = hash_file_contents(&path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_ne!(h_a, h_b);
        assert_eq!(h_a, sha256(b"binary A"));
        assert_eq!(h_b, sha256(b"binary B"));
        // The old RuntimeBinding property — identical because it hashed the path:
        let path_str = path.to_string_lossy();
        assert_eq!(sha256(path_str.as_bytes()), sha256(path_str.as_bytes()));
    }

    // ── Test D: path is context, not identity ──
    #[test]
    fn exe_path_does_not_participate_in_identity_but_is_signed_content() {
        let a = binding("aip1agent", 1, 1, 0x01, 0xE0, "/opt/agent");
        let b = binding("aip1agent", 1, 1, 0x01, 0xE0, "/opt/../opt/agent");
        assert!(a.same_execution(&b));
        assert_eq!(a.identity_bytes(), b.identity_bytes());
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
        assert_ne!(binding_digest(&a), binding_digest(&b));
    }

    // ── Test E: injective encoding ──
    #[test]
    fn canonical_encoding_is_injective_over_variable_fields() {
        let a = binding("ab", 1, 1, 0x01, 0xE0, "c");
        let b = binding("a", 1, 1, 0x01, 0xE0, "bc");
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
        assert_ne!(a.identity_bytes(), b.identity_bytes());
        let c = binding("", 1, 1, 0x01, 0xE0, "abc");
        let d = binding("abc", 1, 1, 0x01, 0xE0, "");
        assert_ne!(c.canonical_bytes(), d.canonical_bytes());
        // Every field change changes the canonical bytes.
        let base = binding("aip1agent", 1, 1, 0x01, 0xE0, "/x");
        let mut m = base.clone();
        m.bound_at_ms += 1;
        assert_ne!(base.canonical_bytes(), m.canonical_bytes());
        let mut m = base.clone();
        m.version += 1;
        assert_ne!(base.canonical_bytes(), m.canonical_bytes());
    }

    #[test]
    fn domain_tags_lead_both_encodings_and_differ() {
        let b = binding("aip1agent", 1, 1, 0x01, 0xE0, "/x");
        let cb = b.canonical_bytes();
        let ib = b.identity_bytes();
        let t1 = EXECUTION_BINDING_DOMAIN.as_bytes();
        let t2 = EXECUTION_IDENTITY_DOMAIN.as_bytes();
        assert_eq!(&cb[4..4 + t1.len()], t1);
        assert_eq!(&ib[4..4 + t2.len()], t2);
        assert_ne!(t1, t2);
        assert_ne!(binding_digest(&b), execution_identity_digest(&b));
    }

    // ── Parsers ──
    #[test]
    fn parse_stat_handles_comm_with_spaces_and_parens() {
        // 22nd field = 433843. comm deliberately hostile.
        let stat = "11570 (my (evil) prog) R 11565 11570 11565 0 -1 4194304 114 0 0 0 0 0 0 0 20 0 1 0 433843 2920448 368 18446744073709551615 1 2 3";
        assert_eq!(parse_proc_stat_start_time(stat).unwrap(), 433843);
    }

    #[test]
    fn parse_stat_rejects_malformed_input_without_panicking() {
        for bad in [
            "",
            "1234",
            "1234 (x",
            "1234 (x) R 1 2 3",
            // tokens after `)`: R=f3, 1..18=f4..f21, so the 20th token is f22
            "1234 (x) R 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 notanumber 21",
            "1234 (x) R 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 0 21", // zero start
        ] {
            let r = std::panic::catch_unwind(|| parse_proc_stat_start_time(bad));
            assert!(r.is_ok(), "panicked on {bad:?}");
            assert!(r.unwrap().is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn parse_boot_id_roundtrip_and_rejections() {
        let id = parse_boot_id("0ca47378-335a-4cd5-81c2-8acec5ccc622\n").unwrap();
        assert_eq!(id[0], 0x0c);
        assert_eq!(id[15], 0x22);
        for bad in [
            "",
            "not-a-uuid",
            "0ca47378-335a-4cd5-81c2-8acec5ccc6",   // short
            "00000000-0000-0000-0000-000000000000", // zero
            "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz",
        ] {
            assert!(parse_boot_id(bad).is_err(), "accepted {bad:?}");
        }
    }

    // ── Live collection (Linux) ──
    #[cfg(target_os = "linux")]
    #[test]
    fn collect_self_binding_reads_real_process_instance() {
        let b = collect_self_binding("aip1selftest").unwrap();
        assert_eq!(b.version, EXECUTION_BINDING_VERSION);
        assert_eq!(b.agent_id, "aip1selftest");
        assert_eq!(b.process.pid, std::process::id());
        assert!(b.process.pid_start_time_ticks > 0);
        assert_ne!(b.process.boot_id, [0u8; 16]);
        assert_ne!(b.exe_content_sha256, [0u8; 32]);
        assert!(!b.exe_path.is_empty());
        // Path-hash is NOT what we store.
        assert_ne!(b.exe_content_sha256, sha256(b.exe_path.as_bytes()));
        // Collecting twice yields the same identity (same instance), even
        // though bound_at_ms may differ.
        let b2 = collect_self_binding("aip1selftest").unwrap();
        assert!(b.same_execution(&b2));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn collect_for_nonexistent_pid_fails_explicitly() {
        // PIDs are bounded by /proc/sys/kernel/pid_max (≤ 4194304); u32::MAX
        // cannot exist.
        let r = collect_binding_for_pid("aip1x", u32::MAX);
        assert!(matches!(
            r,
            Err(BindingError::Unavailable {
                field: "pid_start_time_ticks",
                ..
            })
        ));
    }
}
