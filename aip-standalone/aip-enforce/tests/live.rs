//! The enforcement tier against a real kernel: a real child, a real seccomp
//! filter, real `execve` calls decided by the supervisor.
//!
//! Requires Linux with `CONFIG_SECCOMP_FILTER` and the ability to
//! `pidfd_getfd` from a child (same uid, or `CAP_SYS_PTRACE`). These are
//! the same conditions the observation tier's live tests need, and they are
//! met on the validation host.

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::time::{SystemTime, UNIX_EPOCH};

use aip_crypto::{generate_ed25519_keypair, sha256};
use aip_enforce::linux::{exit_code, spawn_supervised, Supervisor};
use aip_enforce::*;

const AGENT: &str = "aip:agent-under-test";
const SH: &str = "/bin/sh";
const TRUE: &str = "/usr/bin/true";
const FALSE: &str = "/usr/bin/false";

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn content_hash(path: &str) -> [u8; 32] {
    sha256(&std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}")))
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

struct Rig {
    issuer: SoftwareIssuer,
    enforcer_key: aip_types::KeyPair,
    cache: EpochCache,
}

fn rig() -> Rig {
    let issuer_kp = generate_ed25519_keypair();
    let anchors = EpochAnchors::new().trust(
        "issuer:soft-1",
        &issuer_kp.public_key,
        RootOfTrust::SoftwareKey,
    );
    Rig {
        issuer: SoftwareIssuer::new("issuer:soft-1", issuer_kp, 1),
        enforcer_key: generate_ed25519_keypair(),
        cache: EpochCache::new(anchors, AGENT),
    }
}

fn epoch(programs: &[&str], from_ms: u64, until_ms: u64) -> EpochDraft {
    EpochDraft {
        epoch_id: [0x22; 16],
        agent_id: AGENT.into(),
        expectation_digest: sha256(b"ExpectedExecution preimage"),
        allowed_programs: programs.iter().map(|p| content_hash(p)).collect(),
        allowed_egress: vec![],
        issued_at: from_ms,
        valid_until: until_ms,
    }
}

/// Run `sh -c <script>` under the supervisor and return (exit code, records).
fn run(rig: Rig, script: &str) -> (Option<i32>, Vec<SignedEnforcementDecision>, EnforcerHealth) {
    let argv = [c("sh"), c("-c"), c(script)];
    let argv_refs: Vec<&std::ffi::CStr> = argv.iter().map(|a| a.as_c_str()).collect();
    let child = spawn_supervised(&c(SH), &argv_refs).expect("spawn under seccomp user-notify");
    let sup = Supervisor::new("enforcer:host-1", &rig.enforcer_key.private_key, rig.cache);
    let out = sup.serve_until_exit(child).expect("serve");
    (exit_code(out.wait_status), out.records, out.health)
}

#[test]
fn l01_an_allowed_program_execs_and_a_disallowed_one_is_refused_with_eperm() {
    // Allowed: the shell itself and /usr/bin/true.
    let mut r = rig();
    let now = now_ms();
    let e = r
        .issuer
        .issue(epoch(&[SH, TRUE], now - 1_000, now + 60_000))
        .unwrap();
    r.cache.admit(&e).unwrap();
    let (code, records, health) = run(r, "exec /usr/bin/true");
    assert_eq!(health, EnforcerHealth::Nominal);
    assert_eq!(code, Some(0), "true should have run");
    let decisions: Vec<_> = records
        .iter()
        .map(|s| (s.decision.program_hash, s.decision.decision))
        .collect();
    assert_eq!(
        decisions,
        vec![
            (Some(content_hash(SH)), Decision::Allow),
            (Some(content_hash(TRUE)), Decision::Allow),
        ]
    );

    // Not allowed: /usr/bin/false. The shell's exec fails with EPERM and
    // the shell exits 126 ("cannot execute").
    let mut r = rig();
    let e = r
        .issuer
        .issue(epoch(&[SH, TRUE], now - 1_000, now + 60_000))
        .unwrap();
    r.cache.admit(&e).unwrap();
    let (code, records, _) = run(r, "exec /usr/bin/false 2>/dev/null");
    assert_eq!(
        code,
        Some(126),
        "the shell must report the exec was refused"
    );
    let last = records.last().expect("a decision for the refused exec");
    assert_eq!(last.decision.program_hash, Some(content_hash(FALSE)));
    assert_eq!(
        last.decision.decision,
        Decision::Deny(DenyReason::ProgramNotAuthorised)
    );
    // Every record is signed by the enforcer and carries the instance.
    assert!(
        last.decision.process.is_some(),
        "the supervisor measured the instance"
    );
}

#[test]
fn l02_with_no_epoch_even_the_launch_is_refused() {
    let r = rig();
    let (code, records, _) = run(r, "exec /usr/bin/true");
    // The child's own execv of /bin/sh was denied; it _exit(127)s.
    assert_eq!(code, Some(127));
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].decision.decision,
        Decision::Deny(DenyReason::NoEpoch)
    );
    assert_eq!(records[0].decision.epoch_id, None);
}

#[test]
fn l03_an_expired_epoch_denies_a_program_it_names() {
    let mut r = rig();
    let now = now_ms();
    let e = r
        .issuer
        .issue(epoch(&[SH, TRUE], now - 10_000, now - 5_000))
        .unwrap();
    r.cache.admit(&e).unwrap();
    let (code, records, _) = run(r, "exec /usr/bin/true");
    assert_eq!(code, Some(127));
    assert_eq!(
        records[0].decision.decision,
        Decision::Deny(DenyReason::EpochExpired)
    );
}

#[test]
fn l04_a_supervisor_that_vanishes_is_fail_closed_by_the_kernel() {
    // Spawn, then close the listener without answering anything. The kernel
    // fails the child's pending execve with ENOSYS; the child _exit(127)s.
    // Nothing in this crate ran a decision — the fail-closed property here
    // is the kernel's, and it is the one everything else rests on.
    let argv = [c("sh"), c("-c"), c("exec /usr/bin/true")];
    let argv_refs: Vec<&std::ffi::CStr> = argv.iter().map(|a| a.as_c_str()).collect();
    let child = spawn_supervised(&c(SH), &argv_refs).expect("spawn");
    let status = child.close_listener_and_wait().expect("wait");
    assert_eq!(exit_code(status), Some(127));
}

#[test]
fn l05_the_signed_records_verify_under_the_enforcer_anchor() {
    let mut r = rig();
    let now = now_ms();
    let e = r
        .issuer
        .issue(epoch(&[SH, TRUE], now - 1_000, now + 60_000))
        .unwrap();
    r.cache.admit(&e).unwrap();
    let anchors = EnforcerAnchors::new().trust("enforcer:host-1", &r.enforcer_key.public_key);
    let (_, records, _) = run(r, "exec /usr/bin/true");
    assert!(!records.is_empty());
    for rec in &records {
        verify_decision(rec, &anchors).expect("each decision verifies");
        assert_eq!(rec.decision.epoch_id, Some([0x22; 16]));
        assert_eq!(rec.decision.agent_id, AGENT);
    }
}
