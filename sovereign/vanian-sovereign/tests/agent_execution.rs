//! Authorized tool execution: happy path and attacks, against the real
//! Linux namespace sandbox. Every refusal test also asserts that nothing was
//! consumed or executed where that matters.
//!
//! Requires util-linux `unshare` with unprivileged user namespaces. If that
//! is unavailable the sandbox tests fail (they do not skip): the product
//! fails closed there, and so do its tests.

use std::path::PathBuf;
use std::time::Instant;

use aip_authorize::*;
use aip_core::capability::issue_scoped_token;
use aip_core::execution_binding::collect_self_binding;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_types::{CapabilityScope, ExecutionBinding, KeyPair, ProvenanceTriple, ScopeAction};
use vanian_sovereign::adapters::sandbox::{preflight, RunError, SandboxRunner};
use vanian_sovereign::agent::evidence::*;
use vanian_sovereign::agent::replay::{MemoryReplayGuard, ReplayError, ReplayGuard};
use vanian_sovereign::agent::tool::{action_for, file_sha256, ToolInvocation, ToolManifest};
use vanian_sovereign::app::now_ms;
use vanian_sovereign::domain::corpus::Ident;

fn prov(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(tag.as_bytes()),
        environment_commitment: sha256(b"env"),
        toolchain_commitment: sha256(b"tc"),
    }
}

fn manifest(id: &str, program: &str, fixed: &[&str], timeout_ms: u64) -> ToolManifest {
    let p = PathBuf::from(program);
    ToolManifest {
        id: Ident::new(id).unwrap(),
        program_sha256: hex::encode(file_sha256(&p).expect("test program exists")),
        program: p,
        fixed_args: fixed.iter().map(|s| s.to_string()).collect(),
        timeout_ms,
    }
}

struct Fx {
    dp: DecisionPoint,
    runner: SandboxRunner,
    runner_kp: KeyPair,
    dp_anchors: DecisionPointTrustAnchors,
    root: aip_types::ScopedToken,
    agent_id: String,
    binding: ExecutionBinding,
    _work: tempfile::TempDir,
}

fn fixture(granted: &[&str]) -> Fx {
    let inst = generate_ed25519_keypair();
    let inst_id = derive_aip_id(&inst.public_key, &prov("inst"));
    let (agent, _agent_kp) = aip_core::create_identity(prov("agent"), None).unwrap();
    let dp_kp = generate_ed25519_keypair();
    let dp_id = derive_aip_id(&dp_kp.public_key, &prov("dp"));
    let runner_kp = generate_ed25519_keypair();
    let runner_id = derive_aip_id(&runner_kp.public_key, &prov("runner"));
    let allowed: Vec<ScopeAction> = granted
        .iter()
        .map(|g| action_for(&Ident::new(g).unwrap()))
        .collect();
    let root = issue_scoped_token(
        &inst_id,
        &inst.private_key,
        &agent.id,
        CapabilityScope {
            allowed,
            denied: vec![],
        },
        Some(3_600_000),
    )
    .unwrap();
    let dp = DecisionPoint::new(&dp_id, &dp_kp.private_key, &dp_kp.public_key, 300_000)
        .unwrap()
        .trust_issuer(&inst_id, &inst.public_key);
    let dp_anchors = DecisionPointTrustAnchors::new().trust(&dp_id, &dp_kp.public_key);
    let work = tempfile::tempdir().unwrap();
    let runner = SandboxRunner {
        runner_id,
        runner_private_key: runner_kp.private_key.clone(),
        decision_anchors: dp_anchors.clone(),
        unshare_path: PathBuf::from("/usr/bin/unshare"),
        workdir: work.path().to_path_buf(),
    };
    let binding = collect_self_binding(&agent.id).unwrap();
    Fx {
        dp,
        runner,
        runner_kp,
        dp_anchors,
        root,
        agent_id: agent.id,
        binding,
        _work: work,
    }
}

fn authorize(f: &Fx, m: &ToolManifest, inv: &ToolInvocation) -> Decision {
    // The DP signs issued_at from its own clock; tokens issued "now" need a
    // later instant, so evaluate one ms ahead of the root's issue time.
    let now = now_ms().max(f.root.issued_at + 1);
    f.dp.authorize_at(
        &AuthorizationRequest {
            agent_id: f.agent_id.clone(),
            root_token: f.root.clone(),
            delegation_chain: vec![],
            action_kind: m.action_kind(),
            parameters: m.parameters(inv).unwrap(),
            execution_binding: f.binding.clone(),
            requested_ttl_ms: 60_000,
        },
        now,
    )
}

fn ee(f: &Fx, m: &ToolManifest, inv: &ToolInvocation) -> ExpectedExecution {
    match authorize(f, m, inv) {
        Decision::Authorized(e) => *e,
        Decision::Denied(d) => panic!("unexpected denial {d:?}"),
    }
}

fn inv(id: &str, args: &[&str]) -> ToolInvocation {
    ToolInvocation {
        tool_id: Ident::new(id).unwrap(),
        args: args.iter().map(|s| s.to_string()).collect(),
    }
}

fn runner_anchor(f: &Fx) -> RunnerAnchor {
    RunnerAnchor {
        runner_id: f.runner.runner_id.clone(),
        public_key: f.runner_kp.public_key.clone(),
    }
}

fn run_ok(f: &Fx, m: &ToolManifest, i: &ToolInvocation) -> (EvidenceBundle, Vec<u8>) {
    let e = ee(f, m, i);
    let out = f
        .runner
        .run(
            m,
            i,
            &e,
            &f.binding,
            &mut MemoryReplayGuard::default(),
            &now_ms,
        )
        .expect("run");
    (
        EvidenceBundle {
            expected_execution: e,
            run_record: out.record,
        },
        out.stdout,
    )
}

// ─── Happy path ───

#[test]
fn authorized_tool_runs_and_verifies_offline_without_claiming_observation() {
    let f = fixture(&["echo"]);
    let m = manifest("echo", "/bin/echo", &[], 5_000);
    let (b, stdout) = run_ok(&f, &m, &inv("echo", &["pump", "ok"]));
    assert_eq!(stdout, b"pump ok\n");
    // Offline: serialize, reload, verify with public anchors only.
    let json = serde_json::to_string(&b).unwrap();
    let b2: EvidenceBundle = serde_json::from_str(&json).unwrap();
    match verify_bundle(&b2, &f.dp_anchors, &runner_anchor(&f)) {
        Verdict::AuthorizedAndRunnerAttested { exit, observation } => {
            assert_eq!(exit, ExitOutcome::Code(0));
            assert!(matches!(observation, Observation::CannotProve { .. }));
        }
        v => panic!("{v:?}"),
    }
    assert_eq!(b2.run_record.stdout_sha256, sha256(b"pump ok\n"));
}

// ─── Authorization refusals (nothing executes) ───

#[test]
fn ungranted_tool_is_denied_by_the_decision_point() {
    let f = fixture(&["echo"]);
    let m = manifest("reboot-sim", "/bin/echo", &["REBOOT"], 5_000);
    match authorize(&f, &m, &inv("reboot-sim", &[])) {
        Decision::Denied(d) => assert_eq!(d.reason, DenialReason::ActionOutOfScope),
        Decision::Authorized(_) => panic!("ungranted tool authorized"),
    }
}

#[test]
fn argument_substitution_after_authorization_is_refused_and_not_consumed() {
    let f = fixture(&["echo"]);
    let m = manifest("echo", "/bin/echo", &[], 5_000);
    let e = ee(&f, &m, &inv("echo", &["safe"]));
    let mut g = MemoryReplayGuard::default();
    let r = f.runner.run(
        &m,
        &inv("echo", &["rm -rf /"]),
        &e,
        &f.binding,
        &mut g,
        &now_ms,
    );
    assert_eq!(r.unwrap_err(), RunError::ParameterMismatch);
    // Decision still unconsumed: the honest invocation can still run.
    assert!(f
        .runner
        .run(&m, &inv("echo", &["safe"]), &e, &f.binding, &mut g, &now_ms)
        .is_ok());
}

#[test]
fn replayed_decision_is_refused() {
    let f = fixture(&["echo"]);
    let m = manifest("echo", "/bin/echo", &[], 5_000);
    let i = inv("echo", &["x"]);
    let e = ee(&f, &m, &i);
    let mut g = MemoryReplayGuard::default();
    assert!(f
        .runner
        .run(&m, &i, &e, &f.binding, &mut g, &now_ms)
        .is_ok());
    assert_eq!(
        f.runner
            .run(&m, &i, &e, &f.binding, &mut g, &now_ms)
            .unwrap_err(),
        RunError::Replay(ReplayError::AlreadyConsumed)
    );
}

#[test]
fn decision_moved_to_another_process_is_refused() {
    let f = fixture(&["echo"]);
    let m = manifest("echo", "/bin/echo", &[], 5_000);
    let i = inv("echo", &["x"]);
    let e = ee(&f, &m, &i);
    let mut other = f.binding.clone();
    other.process.pid = other.process.pid.wrapping_add(1);
    assert_eq!(
        preflight(&f.runner, &m, &i, &e, &other, now_ms()).unwrap_err(),
        RunError::BindingMismatch
    );
}

#[test]
fn swapped_program_binary_is_refused() {
    let f = fixture(&["echo"]);
    let m = manifest("echo", "/bin/echo", &[], 5_000);
    let i = inv("echo", &["x"]);
    let e = ee(&f, &m, &i);
    // Same manifest pin, different file on disk at that path.
    let mut swapped = m.clone();
    swapped.program = PathBuf::from("/bin/true");
    // Re-authorize for the swapped path so only the content check can fail.
    let e2 = ee(&f, &swapped, &i);
    assert_eq!(
        preflight(&f.runner, &swapped, &i, &e2, &f.binding, now_ms()).unwrap_err(),
        RunError::ProgramDigestMismatch
    );
    drop(e);
}

#[test]
fn expectation_from_untrusted_decision_point_is_refused() {
    let f = fixture(&["echo"]);
    let rogue = fixture(&["echo"]);
    let m = manifest("echo", "/bin/echo", &[], 5_000);
    let i = inv("echo", &["x"]);
    let e = ee(&rogue, &m, &i);
    assert!(matches!(
        preflight(&f.runner, &m, &i, &e, &rogue.binding, now_ms()),
        Err(RunError::ExpectedExecutionInvalid(_))
    ));
}

#[test]
fn expired_expectation_is_refused() {
    let f = fixture(&["echo"]);
    let m = manifest("echo", "/bin/echo", &[], 5_000);
    let i = inv("echo", &["x"]);
    let e = ee(&f, &m, &i);
    assert!(matches!(
        preflight(&f.runner, &m, &i, &e, &f.binding, e.valid_until + 1),
        Err(RunError::NotInWindow(_))
    ));
}

#[test]
fn missing_sandbox_fails_closed_before_consuming() {
    let mut f = fixture(&["echo"]);
    f.runner.unshare_path = PathBuf::from("/nonexistent/unshare");
    let m = manifest("echo", "/bin/echo", &[], 5_000);
    let i = inv("echo", &["x"]);
    let e = ee(&f, &m, &i);
    let mut g = MemoryReplayGuard::default();
    assert!(matches!(
        f.runner.run(&m, &i, &e, &f.binding, &mut g, &now_ms),
        Err(RunError::SandboxUnavailable(_))
    ));
    assert!(
        g.consume(&e.decision_id).is_ok(),
        "decision must not be consumed when nothing ran"
    );
}

// ─── Sandbox properties ───

#[test]
fn sandbox_has_no_network_interface_but_loopback() {
    let f = fixture(&["netdev"]);
    let m = manifest("netdev", "/bin/cat", &["/proc/net/dev"], 5_000);
    let (_, out) = run_ok(&f, &m, &inv("netdev", &[]));
    let text = String::from_utf8_lossy(&out);
    let ifaces: Vec<&str> = text
        .lines()
        .skip(2)
        .filter_map(|l| l.split(':').next())
        .map(str::trim)
        .collect();
    assert_eq!(ifaces, vec!["lo"], "{text}");
}

#[test]
fn sandbox_environment_is_empty() {
    let f = fixture(&["env"]);
    let m = manifest("env", "/usr/bin/env", &[], 5_000);
    let (_, out) = run_ok(&f, &m, &inv("env", &[]));
    assert!(
        out.is_empty(),
        "leaked env: {}",
        String::from_utf8_lossy(&out)
    );
}

#[test]
fn deadline_kills_the_tool() {
    let f = fixture(&["sleep"]);
    let m = manifest("sleep", "/bin/sleep", &[], 300);
    let t = Instant::now();
    let (b, _) = run_ok(&f, &m, &inv("sleep", &["30"]));
    assert!(t.elapsed().as_secs() < 5, "deadline not enforced");
    assert_ne!(b.run_record.exit, ExitOutcome::Code(0));
}

// ─── Evidence tampering (offline verifier) ───

fn good_bundle() -> (Fx, EvidenceBundle) {
    let f = fixture(&["echo"]);
    let m = manifest("echo", "/bin/echo", &[], 5_000);
    let (b, _) = run_ok(&f, &m, &inv("echo", &["ok"]));
    (f, b)
}

fn rejected(f: &Fx, b: &EvidenceBundle) -> RejectReason {
    match verify_bundle(b, &f.dp_anchors, &runner_anchor(f)) {
        Verdict::Rejected(r) => r,
        v => panic!("tampered bundle accepted: {v:?}"),
    }
}

#[test]
fn tampered_exit_code_rejected() {
    let (f, mut b) = good_bundle();
    b.run_record.exit = ExitOutcome::Code(1);
    assert_eq!(rejected(&f, &b), RejectReason::RunRecordPayloadMismatch);
}

#[test]
fn resigned_with_forged_hash_rejected() {
    let (f, mut b) = good_bundle();
    b.run_record.stdout_sha256 = [0; 32];
    // Attacker recomputes payload hash to match the edited record.
    let pre = b.run_record.signing_preimage();
    b.run_record.signature.as_mut().unwrap().payload_hash = sha256(&pre);
    assert_eq!(rejected(&f, &b), RejectReason::RunRecordSignatureInvalid);
}

#[test]
fn record_signed_by_unknown_runner_rejected() {
    let (f, mut b) = good_bundle();
    let attacker = generate_ed25519_keypair();
    b.run_record.sign(&attacker.private_key).unwrap();
    assert_eq!(rejected(&f, &b), RejectReason::RunRecordSignatureInvalid);
}

#[test]
fn expectation_swapped_for_another_valid_one_rejected() {
    let (f, mut b) = good_bundle();
    let m = manifest("echo", "/bin/echo", &[], 5_000);
    b.expected_execution = ee(&f, &m, &inv("echo", &["ok"]));
    assert_eq!(rejected(&f, &b), RejectReason::DecisionIdMismatch);
}

#[test]
fn tampered_expectation_rejected() {
    let (f, mut b) = good_bundle();
    b.expected_execution.valid_until += 1;
    assert!(matches!(
        rejected(&f, &b),
        RejectReason::ExpectedExecutionInvalid(_)
    ));
}

#[test]
fn unsigned_record_rejected() {
    let (f, mut b) = good_bundle();
    b.run_record.signature = None;
    assert_eq!(rejected(&f, &b), RejectReason::MissingRunRecordSignature);
}

#[test]
fn forged_observation_upgrade_cannot_deserialize() {
    let (_, b) = good_bundle();
    let json = serde_json::to_string(&b)
        .unwrap()
        .replace("CannotProve", "VerifiedExecution");
    assert!(serde_json::from_str::<EvidenceBundle>(&json).is_err());
}
