//! Authorized tool runner: Linux namespace sandbox.
//!
//! The runner executes a tool only after **all** of these hold, in order:
//!
//! 1. The `ExpectedExecution` verifies under the runner's decision-point
//!    anchors (never anchors supplied by the requester).
//! 2. It is inside its validity window at launch time.
//! 3. It was issued for this exact process instance (agent id + pid +
//!    start time + boot id + executable contents) — a decision copied into
//!    another process is refused.
//! 4. Its action is `tool:<id>` for the manifest being run.
//! 5. The parameter digest the runner recomputes from the argv it is about
//!    to execute equals the signed digest — the runner cannot be talked into
//!    running anything other than what was authorized.
//! 6. The program file's contents hash to the manifest pin.
//! 7. The decision has not been consumed before (one-shot).
//!
//! The process then runs under `unshare --user --map-root-user --net --pid
//! --fork --kill-child --mount --mount-proc` with an empty environment,
//! stdin closed, a private working directory and a wall-clock deadline
//! enforced by SIGKILL. The new network namespace contains only a loopback
//! device, so the tool has no route off the host.
//!
//! # Known gaps (documented, not hidden)
//!
//! - Step 6 then exec is a TOCTOU window: the file could be swapped between
//!   hashing and execve. aip-enforce (seccomp user-notify on execve) closes
//!   this and is the planned integration.
//! - No filesystem isolation beyond the namespaces: the tool sees the host
//!   filesystem with the runner's uid. Read-only bind mounts / Landlock are
//!   the next hardening step.
//! - No CPU/memory cgroup limits yet; only the wall-clock deadline.

use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use aip_authorize::{
    verify_expected_execution, DecisionPointTrustAnchors, ExpectedExecution, TemporalStatus,
};
use aip_types::ExecutionBinding;

use crate::agent::evidence::{
    expected_execution_digest, ExitOutcome, Observation, RunRecord, SandboxDescriptor,
    RUN_RECORD_VERSION,
};
use crate::agent::replay::{ReplayError, ReplayGuard};
use crate::agent::tool::{decode_digest, file_sha256, ToolInvocation, ToolManifest};

/// Captured bytes per stream before truncation.
pub const MAX_CAPTURE_BYTES: usize = 1 << 20;
/// try_wait polling interval while enforcing the deadline.
const POLL: Duration = Duration::from_millis(10);

/// Static configuration of the runner.
pub struct SandboxRunner {
    pub runner_id: String,
    pub runner_private_key: Vec<u8>,
    pub decision_anchors: DecisionPointTrustAnchors,
    /// Absolute path to util-linux `unshare`.
    pub unshare_path: PathBuf,
    /// Directory the tool runs in (must exist).
    pub workdir: PathBuf,
}

/// Why the runner refused or failed. A refusal means nothing was executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunError {
    ExpectedExecutionInvalid(String),
    NotInWindow(String),
    BindingMismatch,
    WrongAction,
    ParameterMismatch,
    Manifest(String),
    ProgramDigestMismatch,
    Replay(ReplayError),
    SandboxUnavailable(String),
    Spawn(String),
    Signing(String),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for RunError {}

/// Result of an executed, signed run.
#[derive(Debug, Clone)]
pub struct RunOutput {
    pub record: RunRecord,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// All pre-execution checks (steps 1–6). Pure apart from hashing the program
/// file. Exposed separately so refusals can be tested without a sandbox.
pub fn preflight(
    runner: &SandboxRunner,
    manifest: &ToolManifest,
    inv: &ToolInvocation,
    ee: &ExpectedExecution,
    current_binding: &ExecutionBinding,
    now_ms: u64,
) -> Result<Vec<String>, RunError> {
    verify_expected_execution(ee, &runner.decision_anchors)
        .map_err(|e| RunError::ExpectedExecutionInvalid(format!("{e:?}")))?;
    match ee.temporal_status_at(now_ms) {
        TemporalStatus::Valid => {}
        other => return Err(RunError::NotInWindow(format!("{other:?}"))),
    }
    if !ee.covers(&ee.decision_id, &current_binding.agent_id, current_binding) {
        return Err(RunError::BindingMismatch);
    }
    if ee.action_kind != manifest.action_kind() {
        return Err(RunError::WrongAction);
    }
    let params = manifest
        .parameters(inv)
        .map_err(|e| RunError::Manifest(e.to_string()))?;
    if params.digest() != ee.parameter_digest {
        return Err(RunError::ParameterMismatch);
    }
    let pinned =
        decode_digest(&manifest.program_sha256).map_err(|e| RunError::Manifest(e.to_string()))?;
    let actual = file_sha256(&manifest.program).map_err(|e| RunError::Manifest(e.to_string()))?;
    if actual != pinned {
        return Err(RunError::ProgramDigestMismatch);
    }
    manifest
        .argv(inv)
        .map_err(|e| RunError::Manifest(e.to_string()))
}

fn capture(mut r: impl Read + Send + 'static) -> thread::JoinHandle<(Vec<u8>, bool)> {
    thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut r)
            .take(MAX_CAPTURE_BYTES as u64 + 1)
            .read_to_end(&mut buf);
        let truncated = buf.len() > MAX_CAPTURE_BYTES;
        buf.truncate(MAX_CAPTURE_BYTES);
        // Drain the rest so the child never blocks on a full pipe.
        let _ = std::io::copy(&mut r, &mut std::io::sink());
        (buf, truncated)
    })
}

impl SandboxRunner {
    /// Verify, consume, execute in the sandbox and return a signed record.
    pub fn run(
        &self,
        manifest: &ToolManifest,
        inv: &ToolInvocation,
        ee: &ExpectedExecution,
        current_binding: &ExecutionBinding,
        guard: &mut dyn ReplayGuard,
        clock: &dyn Fn() -> u64,
    ) -> Result<RunOutput, RunError> {
        let argv = preflight(self, manifest, inv, ee, current_binding, clock())?;
        if !Path::new(&self.unshare_path).is_file() {
            // Fail closed: never fall back to running unsandboxed.
            return Err(RunError::SandboxUnavailable(
                self.unshare_path.display().to_string(),
            ));
        }
        guard.consume(&ee.decision_id).map_err(RunError::Replay)?;

        let mut cmd = Command::new(&self.unshare_path);
        cmd.args([
            "--user",
            "--map-root-user",
            "--net",
            "--pid",
            "--fork",
            "--kill-child",
            "--mount",
            "--mount-proc",
            "--",
        ])
        .args(&argv)
        .env_clear()
        .current_dir(&self.workdir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

        let started_ms = clock();
        let started = Instant::now();
        let mut child = cmd.spawn().map_err(|e| RunError::Spawn(e.to_string()))?;
        let out_h = capture(child.stdout.take().expect("piped"));
        let err_h = capture(child.stderr.take().expect("piped"));
        let deadline = Duration::from_millis(manifest.timeout_ms);
        let status = loop {
            match child
                .try_wait()
                .map_err(|e| RunError::Spawn(e.to_string()))?
            {
                Some(s) => break s,
                None if started.elapsed() >= deadline => {
                    // SIGKILL to unshare; --kill-child propagates to the
                    // namespace init, which takes the whole PID namespace.
                    let _ = child.kill();
                    break child.wait().map_err(|e| RunError::Spawn(e.to_string()))?;
                }
                None => thread::sleep(POLL),
            }
        };
        let ended_ms = clock();
        let (stdout, stdout_truncated) = out_h.join().unwrap_or_default();
        let (stderr, _) = err_h.join().unwrap_or_default();
        let exit = match (status.code(), status.signal()) {
            (Some(c), _) => ExitOutcome::Code(c),
            (None, Some(s)) => ExitOutcome::Signal(s),
            (None, None) => ExitOutcome::Signal(-1),
        };

        let mut record = RunRecord {
            version: RUN_RECORD_VERSION,
            runner_id: self.runner_id.clone(),
            decision_id: ee.decision_id,
            expected_execution_sha256: expected_execution_digest(ee),
            tool_id: manifest.id.as_str().to_string(),
            parameter_digest: ee.parameter_digest,
            program_sha256: decode_digest(&manifest.program_sha256)
                .map_err(|e| RunError::Manifest(e.to_string()))?,
            started_ms,
            ended_ms,
            exit,
            stdout_sha256: aip_crypto::sha256(&stdout),
            stderr_sha256: aip_crypto::sha256(&stderr),
            stdout_truncated,
            sandbox: SandboxDescriptor {
                new_net_namespace: true,
                new_user_namespace: true,
                empty_environment: true,
                timeout_ms: manifest.timeout_ms,
            },
            observation: Observation::CannotProve {
                reason: "no independent kernel observer (Sniffer Dog) attached to this run; \
                         execution is attested by the runner only"
                    .into(),
            },
            signature: None,
        };
        record
            .sign(&self.runner_private_key)
            .map_err(RunError::Signing)?;
        Ok(RunOutput {
            record,
            stdout,
            stderr,
        })
    }
}
