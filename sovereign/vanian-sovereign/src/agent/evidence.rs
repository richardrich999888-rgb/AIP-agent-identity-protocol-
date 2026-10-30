//! Runner-signed run records and their offline verifier.
//!
//! # Epistemic status
//!
//! A [`RunRecord`] is the **runner's claim** about a sandboxed execution,
//! bound to the decision point's `ExpectedExecution`. It is signed with the
//! runner's key, which is distinct from the agent's and the decision
//! point's. It is not independent observation: the runner launched the
//! process and could lie. Therefore:
//!
//! - [`Observation`] has exactly one variant, `CannotProve`, in this slice.
//!   There is no type-level way to express "observed", so a tampered record
//!   cannot upgrade itself (serde rejects unknown variants).
//! - [`Verdict`] has no "verified execution" outcome. The strongest result is
//!   [`Verdict::AuthorizedAndRunnerAttested`].
//!
//! Attaching a Sniffer Dog observer (aip-observe) and reconciling through
//! aip-reconcile is what would add independent observation; it is the next
//! slice, not this one.

use aip_authorize::{
    verify_expected_execution, DecisionPointTrustAnchors, ExpectedExecution, TemporalStatus,
};
use aip_types::Signature;
use serde::{Deserialize, Serialize};

/// Record format version.
pub const RUN_RECORD_VERSION: u16 = 1;
/// Domain separator for the signing preimage.
const RUN_RECORD_DOMAIN: &[u8] = b"VANIAN-SOVEREIGN-RUN-RECORD-V1";

/// What is known about independent observation of the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Observation {
    /// No independent observer covered this run. `reason` says why.
    CannotProve { reason: String },
}

/// How the process ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExitOutcome {
    Code(i32),
    /// Terminated by a signal (including the timeout's SIGKILL).
    Signal(i32),
}

/// The isolation that was requested from the kernel for this run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxDescriptor {
    /// New network namespace (only a down loopback device inside).
    pub new_net_namespace: bool,
    pub new_user_namespace: bool,
    pub empty_environment: bool,
    pub timeout_ms: u64,
}

/// The runner's signed account of one execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunRecord {
    pub version: u16,
    pub runner_id: String,
    pub decision_id: [u8; 16],
    /// SHA-256 of the `ExpectedExecution` signing preimage.
    pub expected_execution_sha256: [u8; 32],
    pub tool_id: String,
    /// Parameter digest the runner recomputed from what it executed.
    pub parameter_digest: [u8; 32],
    pub program_sha256: [u8; 32],
    pub started_ms: u64,
    pub ended_ms: u64,
    pub exit: ExitOutcome,
    pub stdout_sha256: [u8; 32],
    pub stderr_sha256: [u8; 32],
    pub stdout_truncated: bool,
    pub sandbox: SandboxDescriptor,
    pub observation: Observation,
    pub signature: Option<Signature>,
}

fn put_u16(b: &mut Vec<u8>, v: u16) {
    b.extend_from_slice(&v.to_be_bytes());
}
fn put_u64(b: &mut Vec<u8>, v: u64) {
    b.extend_from_slice(&v.to_be_bytes());
}
fn put_str(b: &mut Vec<u8>, s: &str) {
    b.extend_from_slice(&(s.len() as u32).to_be_bytes());
    b.extend_from_slice(s.as_bytes());
}

impl RunRecord {
    /// Length-prefixed canonical bytes covered by the signature. Every field
    /// except `signature` is included.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut b = Vec::new();
        put_str(
            &mut b,
            std::str::from_utf8(RUN_RECORD_DOMAIN).unwrap_or_default(),
        );
        put_u16(&mut b, self.version);
        put_str(&mut b, &self.runner_id);
        b.extend_from_slice(&self.decision_id);
        b.extend_from_slice(&self.expected_execution_sha256);
        put_str(&mut b, &self.tool_id);
        b.extend_from_slice(&self.parameter_digest);
        b.extend_from_slice(&self.program_sha256);
        put_u64(&mut b, self.started_ms);
        put_u64(&mut b, self.ended_ms);
        match self.exit {
            ExitOutcome::Code(c) => {
                b.push(0);
                b.extend_from_slice(&c.to_be_bytes());
            }
            ExitOutcome::Signal(s) => {
                b.push(1);
                b.extend_from_slice(&s.to_be_bytes());
            }
        }
        b.extend_from_slice(&self.stdout_sha256);
        b.extend_from_slice(&self.stderr_sha256);
        b.push(self.stdout_truncated as u8);
        b.push(self.sandbox.new_net_namespace as u8);
        b.push(self.sandbox.new_user_namespace as u8);
        b.push(self.sandbox.empty_environment as u8);
        put_u64(&mut b, self.sandbox.timeout_ms);
        match &self.observation {
            Observation::CannotProve { reason } => {
                b.push(0);
                put_str(&mut b, reason);
            }
        }
        b
    }

    /// Sign in place with the runner's Ed25519 key.
    pub fn sign(&mut self, runner_private_key: &[u8]) -> Result<(), String> {
        self.signature = None;
        let sig = aip_crypto::sign_ed25519(
            runner_private_key,
            &self.runner_id,
            &self.signing_preimage(),
        )
        .map_err(|e| format!("{e:?}"))?;
        self.signature = Some(sig);
        Ok(())
    }
}

/// SHA-256 over an `ExpectedExecution`'s signing preimage.
pub fn expected_execution_digest(ee: &ExpectedExecution) -> [u8; 32] {
    aip_crypto::sha256(&ee.signing_preimage())
}

/// A self-contained evidence bundle. Trust anchors are deliberately absent:
/// the verifier supplies them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub expected_execution: ExpectedExecution,
    pub run_record: RunRecord,
}

/// Why verification refused the bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    ExpectedExecutionInvalid(String),
    UnsupportedRunRecordVersion(u16),
    UnknownRunner(String),
    MissingRunRecordSignature,
    RunRecordPayloadMismatch,
    RunRecordSignatureInvalid,
    DecisionIdMismatch,
    ExpectedExecutionDigestMismatch,
    ParameterDigestMismatch,
    StartedOutsideAuthorizationWindow,
    EndBeforeStart,
}

/// Outcome of offline verification. There is intentionally no variant that
/// asserts independently verified execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Rejected(RejectReason),
    /// The decision point authorized exactly these parameters, and the named
    /// runner signed a record of executing them inside the window. Execution
    /// is **claimed by the runner**, not independently observed.
    AuthorizedAndRunnerAttested {
        exit: ExitOutcome,
        observation: Observation,
    },
}

/// Runner trust anchor supplied by the verifier.
#[derive(Debug, Clone)]
pub struct RunnerAnchor {
    pub runner_id: String,
    pub public_key: Vec<u8>,
}

/// Verify a bundle against verifier-supplied anchors. Pure: no clock, no IO.
pub fn verify_bundle(
    b: &EvidenceBundle,
    dp: &DecisionPointTrustAnchors,
    runner: &RunnerAnchor,
) -> Verdict {
    use RejectReason::*;
    let ee = &b.expected_execution;
    let rr = &b.run_record;
    if let Err(e) = verify_expected_execution(ee, dp) {
        return Verdict::Rejected(ExpectedExecutionInvalid(format!("{e:?}")));
    }
    if rr.version != RUN_RECORD_VERSION {
        return Verdict::Rejected(UnsupportedRunRecordVersion(rr.version));
    }
    if rr.runner_id != runner.runner_id {
        return Verdict::Rejected(UnknownRunner(rr.runner_id.clone()));
    }
    let Some(sig) = &rr.signature else {
        return Verdict::Rejected(MissingRunRecordSignature);
    };
    if sig.signer_id != runner.runner_id {
        return Verdict::Rejected(UnknownRunner(sig.signer_id.clone()));
    }
    if aip_crypto::sha256(&rr.signing_preimage()) != sig.payload_hash {
        return Verdict::Rejected(RunRecordPayloadMismatch);
    }
    if !matches!(
        aip_crypto::verify_ed25519(&runner.public_key, sig),
        Ok(true)
    ) {
        return Verdict::Rejected(RunRecordSignatureInvalid);
    }
    if rr.decision_id != ee.decision_id {
        return Verdict::Rejected(DecisionIdMismatch);
    }
    if rr.expected_execution_sha256 != expected_execution_digest(ee) {
        return Verdict::Rejected(ExpectedExecutionDigestMismatch);
    }
    if rr.parameter_digest != ee.parameter_digest {
        return Verdict::Rejected(ParameterDigestMismatch);
    }
    if ee.temporal_status_at(rr.started_ms) != TemporalStatus::Valid {
        return Verdict::Rejected(StartedOutsideAuthorizationWindow);
    }
    if rr.ended_ms < rr.started_ms {
        return Verdict::Rejected(EndBeforeStart);
    }
    Verdict::AuthorizedAndRunnerAttested {
        exit: rr.exit.clone(),
        observation: rr.observation.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_observation_variant_cannot_be_deserialized() {
        let forged = r#"{"Verified":{"reason":"trust me"}}"#;
        assert!(serde_json::from_str::<Observation>(forged).is_err());
        let ok = r#"{"CannotProve":{"reason":"no observer"}}"#;
        assert!(serde_json::from_str::<Observation>(ok).is_ok());
    }
}
