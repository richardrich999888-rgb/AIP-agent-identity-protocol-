//! The auditor's interface, exercised as an auditor uses it: the compiled
//! binary, real files on disk, exit codes and printed output.
//!
//! These tests exist because the library being correct is not the same as
//! the command being correct. The R7 acceptance criterion — a stale
//! revocation list must never read as a pass — is a property of what an
//! auditor sees, so it is checked here against the process's own output.

use std::io::Write;
use std::process::Command;

use aip_core::capability::{issue_scoped_token, scope_submitter};
use aip_core::create_identity;
use aip_crypto::{generate_ed25519_keypair, sha256};
use aip_protocol::{
    ActionAttestation, AgentIdentitySummary, DecisionRecord, EvidencePacketBuilder,
    RevocationReason, RevokedEntry, RootAuthority, SignedRevocationList, TrustFloor,
};
use aip_types::{Action, ProvenanceTriple, ScopeAction};

const BIN: &str = env!("CARGO_BIN_EXE_aip-verify");
const REV_ISSUER: &str = "aip1RevocationAuthority";
/// How long after issue the revocation list's issuer stands behind it.
const LIST_LIFETIME_MS: u64 = 86_400_000;

struct Scratch {
    dir: std::path::PathBuf,
}

impl Scratch {
    /// A unique directory under the system temp dir. Named from the test's
    /// own process id and a counter so two tests never collide.
    fn new(tag: &str) -> Self {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("aip-verify-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Self { dir }
    }

    fn write(&self, name: &str, contents: &str) -> String {
        let path = self.dir.join(name);
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(contents.as_bytes()).expect("write");
        path.to_string_lossy().into_owned()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn provenance(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("model-{tag}").as_bytes()),
        environment_commitment: sha256(format!("env-{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("tool-{tag}").as_bytes()),
    }
}

struct Packet {
    json: String,
    /// `--trust` argument naming the principal that issued the root token.
    trust_arg: String,
    root_jti: [u8; 16],
    /// The instant this packet is dated at, taken from the root token's own
    /// `issued_at` rather than from a clock read before the token existed.
    /// Reading the clock first races key generation and produces a decision
    /// that predates its own authority.
    at: u64,
}

/// A packet whose authority comes from a separate principal: the ordinary
/// shape, so the independence flag has something honest to pass.
fn delegated_packet() -> Packet {
    let (principal, principal_kp) = create_identity(provenance("principal"), None).unwrap();
    let (agent, agent_kp) = create_identity(provenance("agent"), None).unwrap();
    let root_token = issue_scoped_token(
        &principal.id,
        &principal_kp.private_key,
        &agent.id,
        scope_submitter(),
        Some(3_600_000),
    )
    .unwrap();
    let root_jti = root_token.jti;
    let now = root_token.issued_at + 1;
    let decision = DecisionRecord {
        decision_id: aip_core::capability::random_jti(),
        action_kind: ScopeAction::Standard(Action::Write),
        summary: "write the return".into(),
        input_hash: sha256(b"input"),
        rationale_hash: sha256(b"rationale"),
        decided_at: now,
    };
    let action = ActionAttestation::create(
        &agent.id,
        &agent_kp.private_key,
        &decision.decision_id,
        ScopeAction::Standard(Action::Write),
        "POST /returns",
        sha256(b"{}"),
        now + 1,
    )
    .unwrap();
    let packet = EvidencePacketBuilder::new(
        AgentIdentitySummary {
            aip_id: agent.id.clone(),
            public_key: agent.primary_key.clone(),
            provenance: agent.provenance.clone(),
        },
        RootAuthority {
            principal_id: principal.id.clone(),
            display_role: "filing principal".into(),
            root_token,
        },
    )
    .decision(decision)
    .action(action)
    .claimed_trust_floor(TrustFloor::AuthorityBound)
    .build_and_sign(&agent_kp.private_key)
    .unwrap();
    Packet {
        json: packet.to_json().unwrap(),
        trust_arg: format!("{}={}", principal.id, hex::encode(&principal_kp.public_key)),
        root_jti,
        at: now + 1,
    }
}

/// A packet whose agent issued its own authority.
fn self_issued_packet() -> Packet {
    let (agent, agent_kp) = create_identity(provenance("self"), None).unwrap();
    let root_token = issue_scoped_token(
        &agent.id,
        &agent_kp.private_key,
        &agent.id,
        scope_submitter(),
        Some(3_600_000),
    )
    .unwrap();
    let root_jti = root_token.jti;
    let now = root_token.issued_at + 1;
    let decision = DecisionRecord {
        decision_id: aip_core::capability::random_jti(),
        action_kind: ScopeAction::Standard(Action::Write),
        summary: "submit on my own say-so".into(),
        input_hash: sha256(b"input"),
        rationale_hash: sha256(b"rationale"),
        decided_at: now,
    };
    let action = ActionAttestation::create(
        &agent.id,
        &agent_kp.private_key,
        &decision.decision_id,
        ScopeAction::Standard(Action::Write),
        "POST /returns",
        sha256(b"{}"),
        now + 1,
    )
    .unwrap();
    let packet = EvidencePacketBuilder::new(
        AgentIdentitySummary {
            aip_id: agent.id.clone(),
            public_key: agent.primary_key.clone(),
            provenance: agent.provenance.clone(),
        },
        RootAuthority {
            principal_id: agent.id.clone(),
            display_role: "self".into(),
            root_token,
        },
    )
    .decision(decision)
    .action(action)
    .claimed_trust_floor(TrustFloor::AuthorityBound)
    .build_and_sign(&agent_kp.private_key)
    .unwrap();
    Packet {
        json: packet.to_json().unwrap(),
        trust_arg: format!("{}={}", agent.id, hex::encode(&agent_kp.public_key)),
        root_jti,
        at: now + 1,
    }
}

/// A signed revocation list plus the `--trust-revocation-issuer` argument.
fn revocation_list(now: u64, jtis: &[[u8; 16]]) -> (String, String) {
    let kp = generate_ed25519_keypair();
    let signed = SignedRevocationList::issue(
        REV_ISSUER,
        3,
        &kp.private_key,
        11,
        now - 1_000,
        now + LIST_LIFETIME_MS,
        jtis.iter()
            .map(|j| RevokedEntry {
                jti: *j,
                revoked_at_ms: now - 1_000,
                reason: RevocationReason::KeyCompromise,
            })
            .collect(),
    )
    .unwrap();
    (
        signed.to_json().unwrap(),
        format!("{REV_ISSUER}:3={}", hex::encode(&kp.public_key)),
    )
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str]) -> Run {
    let out = Command::new(BIN)
        .args(args)
        .output()
        .expect("run aip-verify");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

// ─── R7 ───

/// **The acceptance criterion.** An auditor who supplies a list that has
/// expired is told the rule was not evaluated, and why. The word "PASS" must
/// not appear on that line.
#[test]
fn an_expired_list_prints_not_evaluated_and_never_a_pass() {
    let s = Scratch::new("expired");
    let p = delegated_packet();
    let now = p.at;
    let (list_json, issuer_arg) = revocation_list(now, &[]);
    let packet_path = s.write("packet.json", &p.json);
    let list_path = s.write("revocations.json", &list_json);

    // Verify one day and one millisecond after the list stopped being one
    // the issuer stands behind.
    let r = run(&[
        &packet_path,
        "--trust",
        &p.trust_arg,
        "--revocations",
        &list_path,
        "--trust-revocation-issuer",
        &issuer_arg,
        "--at",
        &(now + LIST_LIFETIME_MS + 1).to_string(),
        "--report",
    ]);
    assert_eq!(
        r.code, 0,
        "an unevaluated rule does not fail the packet: {r:?}",
    );
    let line = r
        .stdout
        .lines()
        .find(|l| l.contains("REVOCATION"))
        .unwrap_or_else(|| panic!("no REVOCATION line in:\n{}", r.stdout));
    assert!(
        !line.contains("PASS"),
        "an expired list must never read as a pass: {line}"
    );
    assert!(
        line.contains("expired"),
        "the reason must be printed: {line}"
    );
    assert!(
        r.stdout.contains("REVOCATION was NOT evaluated"),
        "the report must call it out separately:\n{}",
        r.stdout
    );
}

/// A list inside its window is used, and the pass names the document.
#[test]
fn a_fresh_list_is_used_and_the_pass_names_the_document() {
    let s = Scratch::new("fresh");
    let p = delegated_packet();
    let now = p.at;
    let (list_json, issuer_arg) = revocation_list(now, &[[0x55; 16]]);
    let packet_path = s.write("packet.json", &p.json);
    let list_path = s.write("revocations.json", &list_json);

    let r = run(&[
        &packet_path,
        "--trust",
        &p.trust_arg,
        "--revocations",
        &list_path,
        "--trust-revocation-issuer",
        &issuer_arg,
        "--at",
        &(now + 1_000).to_string(),
        "--report",
    ]);
    assert_eq!(r.code, 0, "{r:?}");
    let line = r.stdout.lines().find(|l| l.contains("REVOCATION")).unwrap();
    assert!(line.contains("PASS"), "{line}");
    assert!(line.contains("sequence 11"), "{line}");
    assert!(line.contains(REV_ISSUER), "{line}");
}

/// The same list, naming this packet's own root token: the packet fails.
#[test]
fn a_list_naming_the_packets_root_token_fails_the_verification() {
    let s = Scratch::new("revoked");
    let p = delegated_packet();
    let now = p.at;
    let (list_json, issuer_arg) = revocation_list(now, &[p.root_jti]);
    let packet_path = s.write("packet.json", &p.json);
    let list_path = s.write("revocations.json", &list_json);

    let r = run(&[
        &packet_path,
        "--trust",
        &p.trust_arg,
        "--revocations",
        &list_path,
        "--trust-revocation-issuer",
        &issuer_arg,
        "--at",
        &(now + 1_000).to_string(),
    ]);
    assert_ne!(r.code, 0, "a revoked root must fail: {r:?}");
    assert!(r.stdout.contains("valid:       false"), "{}", r.stdout);
    assert!(r.stdout.contains("REVOCATION"), "{}", r.stdout);
}

/// A list the auditor has no anchor for is not quietly ignored: the rule is
/// unevaluated and says the issuer was not anchored.
#[test]
fn an_unanchored_list_leaves_the_rule_unevaluated_rather_than_being_dropped() {
    let s = Scratch::new("unanchored");
    let p = delegated_packet();
    let now = p.at;
    let (list_json, _) = revocation_list(now, &[]);
    let packet_path = s.write("packet.json", &p.json);
    let list_path = s.write("revocations.json", &list_json);

    let r = run(&[
        &packet_path,
        "--trust",
        &p.trust_arg,
        "--revocations",
        &list_path,
        "--at",
        &(now + 1_000).to_string(),
        "--report",
    ]);
    assert_eq!(r.code, 0, "{r:?}");
    assert!(
        r.stdout.contains("REVOCATION was NOT evaluated"),
        "{}",
        r.stdout
    );
    assert!(r.stdout.contains("no anchored key"), "{}", r.stdout);
}

/// A list with no instant to place it against is refused at the command
/// line, rather than being applied with an assumed "now".
#[test]
fn a_list_without_a_verification_instant_is_refused_up_front() {
    let s = Scratch::new("noinstant");
    let p = delegated_packet();
    let now = p.at;
    let (list_json, issuer_arg) = revocation_list(now, &[]);
    let packet_path = s.write("packet.json", &p.json);
    let list_path = s.write("revocations.json", &list_json);

    let r = run(&[
        &packet_path,
        "--trust",
        &p.trust_arg,
        "--revocations",
        &list_path,
        "--trust-revocation-issuer",
        &issuer_arg,
    ]);
    assert_ne!(r.code, 0);
    assert!(
        r.stderr.contains("--at or --now"),
        "stderr was: {}",
        r.stderr
    );
}

// ─── R6 ───

/// Without the flag a self-issued packet still verifies — the default is
/// unchanged — and with it the same bytes are refused.
#[test]
fn the_independence_flag_turns_a_self_issued_pass_into_a_refusal() {
    let s = Scratch::new("selfissued");
    let p = self_issued_packet();
    let packet_path = s.write("packet.json", &p.json);

    let permissive = run(&[&packet_path, "--trust", &p.trust_arg]);
    assert_eq!(permissive.code, 0, "{permissive:?}");
    assert!(permissive.stdout.contains("valid:       true"));

    let strict = run(&[
        &packet_path,
        "--trust",
        &p.trust_arg,
        "--require-independent-authority",
    ]);
    assert_ne!(strict.code, 0, "{strict:?}");
    assert!(
        strict.stdout.contains("valid:       false"),
        "{}",
        strict.stdout
    );
    assert!(
        strict
            .stdout
            .contains("no independent party authorized this"),
        "{}",
        strict.stdout
    );
    // Refusing self-issuance is not an accusation of tampering.
    assert!(
        strict.stdout.contains("tampered:    false"),
        "{}",
        strict.stdout
    );
}

/// A genuinely delegated packet passes under the same flag, so the test
/// above is not passing merely because the flag refuses everything.
#[test]
fn a_delegated_packet_passes_under_the_independence_flag() {
    let s = Scratch::new("delegated");
    let p = delegated_packet();
    let packet_path = s.write("packet.json", &p.json);
    let r = run(&[
        &packet_path,
        "--trust",
        &p.trust_arg,
        "--require-independent-authority",
    ]);
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.stdout.contains("valid:       true"), "{}", r.stdout);
}

impl std::fmt::Debug for Run {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "exit {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.code, self.stdout, self.stderr
        )
    }
}
