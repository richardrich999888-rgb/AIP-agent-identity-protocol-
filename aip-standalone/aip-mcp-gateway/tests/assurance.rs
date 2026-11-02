//! Cryptographic composition tests with explicitly constructed observer fixtures.
//! These test predicates, not a real Linux/model deployment.

use std::collections::BTreeMap;

use aip_airi::{GatewayDisposition, GatewaySigner, ToolBoundary, ToolBoundaryNotEvaluated};
use aip_authorize::tool_invoke_action;
use aip_core::capability::issue_scoped_token;
use aip_crypto::generate_ed25519_keypair;
use aip_mcp_gateway::{assurance::*, issue_receipt, ToolCall, MCP_TOOLS_CALL};
use aip_observe::{
    AgentAttribution, AttestedClock, CollectorSigner, ObservationBatch, ObservedEffect,
    ObservedExecution, ObservedProcess, ObserverAttestor, SourceMechanism,
    OBSERVE_PROTOCOL_VERSION,
};
use aip_reconcile::{IdentityComparison, ReasonCode, ReconcilerSigner, ReconciliationResult};
use aip_types::{CapabilityScope, ExecutionBinding, ProcessInstance};
use serde_json::json;

struct Fixture {
    bundle: RunBundle,
    trust: RunTrustConfig,
    authority: AuthorityConfig,
    decision_key: Vec<u8>,
    gateway: GatewaySigner,
    observer_key: Vec<u8>,
    reconciler_key: Vec<u8>,
}

fn checkpoint(bundle: &RunBundle) -> RunCheckpoint {
    RunCheckpoint {
        batches_sha256: hex::encode(aip_crypto::sha256(bundle.batches_jsonl.as_bytes())),
        health_sha256: hex::encode(aip_crypto::sha256(bundle.health_jsonl.as_bytes())),
    }
}

fn fixture() -> Fixture {
    let agent = generate_ed25519_keypair();
    let issuer = generate_ed25519_keypair();
    let authority = generate_ed25519_keypair();
    let gateway_key = generate_ed25519_keypair();
    let observer = generate_ed25519_keypair();
    let reconciler = generate_ed25519_keypair();
    let root = issue_scoped_token(
        "issuer.test",
        &issuer.private_key,
        "agent.test",
        CapabilityScope {
            allowed: vec![tool_invoke_action()],
            denied: vec![],
        },
        Some(60_000),
    )
    .unwrap();
    let config = AuthorityConfig {
        decision_point_id: "decision.test".into(),
        decision_key_file: "not-opened-in-unit-test".into(),
        decision_public_key_hex: hex::encode(&authority.public_key),
        agent_id: "agent.test".into(),
        agent_public_key_hex: hex::encode(&agent.public_key),
        issuer_keys: BTreeMap::from([("issuer.test".into(), hex::encode(&issuer.public_key))]),
        root_token: root,
        delegation_chain: vec![],
        allowed_calls: vec![AllowedCall {
            tool_id: "bank-loan_read".into(),
            arguments: json!({"loan_id":1,"amount":0}),
        }],
        max_ttl_ms: 30_000,
        requested_ttl_ms: 30_000,
    };
    let binding = ExecutionBinding {
        version: aip_types::EXECUTION_BINDING_VERSION,
        agent_id: "agent.test".into(),
        process: ProcessInstance {
            pid: 1234,
            pid_start_time_ticks: 4242,
            boot_id: [7; 16],
        },
        exe_content_sha256: [33; 32],
        exe_path: "/explicit/test/fixture".into(),
        bound_at_ms: 1,
        container: None,
    };
    let expectation = authorize_measured(
        &config,
        &authority.private_key,
        binding.clone(),
        "bank-loan_read",
        &json!({"amount":0,"loan_id":1}),
    )
    .unwrap();
    let now = expectation.issued_at;
    let gateway = GatewaySigner::new("gateway.test", 1, &gateway_key.private_key).unwrap();
    let receipt = issue_receipt(
        &gateway,
        &ToolCall {
            method: MCP_TOOLS_CALL.into(),
            tool_name: "bank-loan_read".into(),
            decision_id: expectation.decision_id,
            agent_id: "agent.test".into(),
            tool_call_id: Some("request.test".into()),
            arguments: json!({"loan_id":1,"amount":0}),
        },
        GatewayDisposition::Forwarded,
        Some(&json!({"synthetic":true})),
        now + 5,
    )
    .unwrap();
    let mut collector = CollectorSigner::new(
        "collector.test",
        1,
        &observer.private_key,
        &observer.public_key,
    )
    .unwrap();
    let mechanisms = [
        SourceMechanism::PidFdAnchored,
        SourceMechanism::ProcConnector,
    ];
    collector.register_probe("probe.test", &mechanisms);
    let mut batches = String::new();
    for i in 1..=3u8 {
        let start = now + (u64::from(i) - 1) * 10;
        let end = now + u64::from(i) * 10;
        let batch = ObservationBatch {
            version: OBSERVE_PROTOCOL_VERSION,
            probe_id: "probe.test".into(),
            batch_id: [i; 16],
            probe_run_id: [9; 16],
            probe_seq_first: u64::from(i),
            probe_seq_last: u64::from(i),
            dropped_events: Some(0),
            active_mechanisms: SourceMechanism::canonical_set(mechanisms.to_vec()),
            mechanism_integrity: vec![],
            claimed_from_ms: start,
            claimed_to_ms: end,
            observations: vec![ObservedExecution {
                version: OBSERVE_PROTOCOL_VERSION,
                probe_id: "probe.test".into(),
                observed: ObservedProcess {
                    process: binding.process,
                    exe_path: binding.exe_path.clone(),
                    exe_content_sha256: binding.exe_content_sha256,
                    container: None,
                },
                attribution: AgentAttribution::NotEstablished,
                effect: ObservedEffect::ProcessPresent,
                mechanism: SourceMechanism::PidFdAnchored,
                claimed_decision_id: None,
                host_wall_clock_ms: end,
                probe_monotonic_ns: u64::from(i) * 10_000_000,
            }],
            kernel_events: vec![],
            clock_anchor: None,
        };
        batches
            .push_str(&serde_json::to_string(&collector.attest_at(batch, end).unwrap()).unwrap());
        batches.push('\n');
    }
    let health = collector
        .health_with_clock(
            now + 30,
            Some(AttestedClock {
                synchronized: true,
                max_error_us: 1000,
                state: 0,
            }),
        )
        .unwrap();
    let bundle = RunBundle {
        run_id: "run.test".into(),
        agent_id: "agent.test".into(),
        expectation: Some(expectation),
        signed_receipt: Some(receipt),
        signed_reconciliation: None,
        batches_jsonl: batches,
        health_jsonl: serde_json::to_string(&health).unwrap() + "\n",
        verification_time_ms: now + 30,
    };
    let trust = RunTrustConfig {
        agent_id: "agent.test".into(),
        agent_public_key_hex: hex::encode(agent.public_key),
        decision_point_id: "decision.test".into(),
        decision_point_public_key_hex: hex::encode(authority.public_key),
        gateway_id: "gateway.test".into(),
        gateway_key_version: 1,
        gateway_public_key_hex: hex::encode(gateway_key.public_key),
        observer_id: "collector.test".into(),
        observer_key_version: 1,
        observer_public_key_hex: hex::encode(observer.public_key),
        reconciler_id: "reconciler.test".into(),
        reconciler_key_version: 1,
        reconciler_public_key_hex: hex::encode(reconciler.public_key),
        checkpoints: BTreeMap::from([("run.test".into(), checkpoint(&bundle))]),
        health_max_age_ms: 60_000,
        window_tolerance_ms: 0,
    };
    Fixture {
        bundle,
        trust,
        authority: config,
        decision_key: authority.private_key,
        gateway,
        observer_key: observer.private_key,
        reconciler_key: reconciler.private_key,
    }
}

#[test]
fn authorized_documents_agree_without_promoting_unobservable_tool_effect() {
    let f = fixture();
    let evaluated = evaluate_run(&f.bundle, &f.trust).unwrap();
    assert!(evaluated.authorization_verified && evaluated.gateway_receipt_verified);
    assert!(matches!(
        evaluated.tool_boundary,
        Some(ToolBoundary::Agrees { .. })
    ));
    let kernel = evaluated.reconciliation.unwrap();
    assert_eq!(kernel.result, ReconciliationResult::CannotProve);
    assert_eq!(kernel.reason, ReasonCode::ActionEvidenceUnavailable);
    assert!(matches!(kernel.identity, IdentityComparison::Match { .. }));
}

#[test]
fn authority_denies_other_resources_tools_extra_parameters_and_invalid_scope() {
    let mut f = fixture();
    let binding = f
        .bundle
        .expectation
        .as_ref()
        .unwrap()
        .execution_binding
        .clone();
    for (tool, args) in [
        ("bank-loan_read", json!({"loan_id":2,"amount":0})),
        ("bank-loan_write", json!({"loan_id":1,"amount":0})),
        ("bank-loan_read", json!({"loan_id":1,"amount":1})),
        (
            "bank-loan_read",
            json!({"loan_id":1,"amount":0,"extra":true}),
        ),
    ] {
        assert!(
            authorize_measured(&f.authority, &f.decision_key, binding.clone(), tool, &args)
                .is_err()
        );
    }
    let narrow_issuer = generate_ed25519_keypair();
    f.authority.root_token = issue_scoped_token(
        "narrow.issuer",
        &narrow_issuer.private_key,
        "agent.test",
        CapabilityScope {
            allowed: vec![aip_types::ScopeAction::Standard(aip_types::Action::Read)],
            denied: vec![],
        },
        Some(60_000),
    )
    .unwrap();
    f.authority.issuer_keys = BTreeMap::from([(
        "narrow.issuer".into(),
        hex::encode(narrow_issuer.public_key),
    )]);
    assert!(authorize_measured(
        &f.authority,
        &f.decision_key,
        binding,
        "bank-loan_read",
        &json!({"loan_id":1,"amount":0})
    )
    .is_err());
}

#[test]
fn signed_parameter_mismatch_is_computed_from_gateway_receipt_and_authorization() {
    let mut f = fixture();
    let original = f.bundle.signed_receipt.as_ref().unwrap();
    f.bundle.signed_receipt = Some(
        issue_receipt(
            &f.gateway,
            &ToolCall {
                method: MCP_TOOLS_CALL.into(),
                tool_name: "bank-loan_read".into(),
                decision_id: original.receipt.decision_id,
                agent_id: f.trust.agent_id.clone(),
                tool_call_id: Some("request.changed".into()),
                arguments: json!({"loan_id":2,"amount":0}),
            },
            GatewayDisposition::Refused,
            None,
            original.receipt.received_at_ms,
        )
        .unwrap(),
    );
    let evaluated = evaluate_run(&f.bundle, &f.trust).unwrap();
    assert!(matches!(
        evaluated.tool_boundary,
        Some(ToolBoundary::Diverges { .. })
    ));
    assert_eq!(
        evaluated.gateway_disposition,
        Some(GatewayDisposition::Refused)
    );
    assert_eq!(
        evaluated.reconciliation.unwrap().result,
        ReconciliationResult::CannotProve
    );
}

#[test]
fn missing_receipt_and_missing_authority_do_not_become_accusations() {
    let mut f = fixture();
    f.bundle.signed_receipt = None;
    let result = evaluate_run(&f.bundle, &f.trust).unwrap();
    assert!(matches!(
        result.tool_boundary,
        Some(ToolBoundary::NotEvaluated {
            reason: ToolBoundaryNotEvaluated::NoReceipt
        })
    ));
    assert!(!result.gateway_receipt_verified);
    f.bundle.expectation = None;
    let result = evaluate_run(&f.bundle, &f.trust).unwrap();
    assert!(result.reconciliation.is_none());
    assert!(result
        .limitations
        .iter()
        .any(|s| s.contains("completeness is unknown")));
}

#[test]
fn gateway_checks_actual_parameters_principal_signature_and_expiry() {
    let f = fixture();
    let expected = f.bundle.expectation.as_ref().unwrap();
    let check =
        |agent, tool, args, time| check_authorization(expected, &f.trust, agent, tool, &args, time);
    assert!(check(
        "agent.test",
        "bank-loan_read",
        json!({"loan_id":1,"amount":0}),
        expected.issued_at
    )
    .is_ok());
    assert!(check(
        "other.agent",
        "bank-loan_read",
        json!({"loan_id":1,"amount":0}),
        expected.issued_at
    )
    .is_err());
    assert!(check(
        "agent.test",
        "bank-loan_read",
        json!({"loan_id":2,"amount":0}),
        expected.issued_at
    )
    .is_err());
    assert!(check(
        "agent.test",
        "bank-loan_read",
        json!({"loan_id":1,"amount":0}),
        expected.valid_until + 1
    )
    .is_err());
    let mut tampered = expected.clone();
    tampered.parameter_digest[0] ^= 1;
    assert!(check_authorization(
        &tampered,
        &f.trust,
        "agent.test",
        "bank-loan_read",
        &json!({"loan_id":1,"amount":0}),
        expected.issued_at
    )
    .is_err());
}

#[test]
fn checkpoints_reject_prefix_suffix_and_interior_removal_even_when_remaining_signatures_are_valid()
{
    for keep in [vec![0, 1], vec![1, 2], vec![0, 2]] {
        let mut f = fixture();
        let lines: Vec<_> = f.bundle.batches_jsonl.lines().collect();
        f.bundle.batches_jsonl = keep
            .into_iter()
            .map(|i| format!("{}\n", lines[i]))
            .collect();
        assert!(evaluate_run(&f.bundle, &f.trust)
            .unwrap_err()
            .contains("checkpoint mismatch"));
    }
    let mut f = fixture();
    f.trust.checkpoints.clear();
    assert!(evaluate_run(&f.bundle, &f.trust).is_err());
}

#[test]
fn valid_checkpoint_cannot_launder_tampered_signatures_or_shared_signing_keys() {
    let mut f = fixture();
    let mut batch: serde_json::Value =
        serde_json::from_str(f.bundle.batches_jsonl.lines().next().unwrap()).unwrap();
    batch["attested_at_ms"] = json!(0);
    let tail = f
        .bundle
        .batches_jsonl
        .lines()
        .skip(1)
        .map(|s| format!("{s}\n"))
        .collect::<String>();
    f.bundle.batches_jsonl = format!("{batch}\n{tail}");
    f.trust
        .checkpoints
        .insert(f.bundle.run_id.clone(), checkpoint(&f.bundle));
    assert!(evaluate_run(&f.bundle, &f.trust)
        .unwrap_err()
        .contains("signature or continuity"));
    let mut f = fixture();
    f.trust.gateway_public_key_hex = f.trust.agent_public_key_hex.clone();
    assert!(evaluate_run(&f.bundle, &f.trust)
        .unwrap_err()
        .contains("keys must be distinct"));
}

#[test]
fn signed_reconciliation_must_match_recomputed_finding_under_separate_key() {
    let mut f = fixture();
    let rec = evaluate_run(&f.bundle, &f.trust)
        .unwrap()
        .reconciliation
        .unwrap();
    let signer = ReconcilerSigner::new(
        "reconciler.test",
        1,
        &f.reconciler_key,
        &public_key(&f.trust.reconciler_public_key_hex).unwrap(),
    )
    .unwrap();
    f.bundle.signed_reconciliation = Some(signer.sign(&rec).unwrap());
    assert!(
        evaluate_run(&f.bundle, &f.trust)
            .unwrap()
            .signed_reconciliation_verified
    );
    let roundtrip: RunBundle =
        serde_json::from_str(&serde_json::to_string(&f.bundle).unwrap()).unwrap();
    assert!(
        evaluate_run(&roundtrip, &f.trust)
            .unwrap()
            .signed_reconciliation_verified
    );
    let mut another_context = f.bundle.clone();
    another_context.signed_reconciliation = None;
    another_context.verification_time_ms += 1;
    let different = evaluate_run(&another_context, &f.trust)
        .unwrap()
        .reconciliation
        .unwrap();
    f.bundle.signed_reconciliation = Some(signer.sign(&different).unwrap());
    assert!(evaluate_run(&f.bundle, &f.trust)
        .unwrap_err()
        .contains("differs from independently recomputed"));
    f.bundle.signed_reconciliation = Some(signer.sign(&rec).unwrap());
    f.bundle
        .signed_reconciliation
        .as_mut()
        .unwrap()
        .reconciliation
        .reason = ReasonCode::NoObserverEvidence;
    assert!(evaluate_run(&f.bundle, &f.trust).is_err());
}

// Fixture-only re-signing lets these tests exercise predicate prerequisites.
// Production code never rewrites captured observations or inserts claims.
fn rewrite_fixture_observations(f: &mut Fixture, claimed: bool) {
    let expected = f.bundle.expectation.as_ref().unwrap();
    let mut head = [0; 32];
    let mut rewritten = String::new();
    for line in f.bundle.batches_jsonl.lines() {
        let mut signed: aip_observe::AttestedBatch = serde_json::from_str(line).unwrap();
        signed.prev_head = head;
        for observation in &mut signed.batch.observations {
            observation.observed.process.pid += 1;
            if claimed {
                observation.attribution = AgentAttribution::Claimed {
                    agent_id: f.trust.agent_id.clone(),
                    claim_source: "explicit-unit-test-only".into(),
                };
                observation.claimed_decision_id = Some(expected.decision_id);
            }
        }
        signed.attestation = aip_crypto::sign_ed25519(
            &f.observer_key,
            &f.trust.observer_id,
            &signed.signing_preimage(),
        )
        .unwrap();
        head = signed.head();
        rewritten.push_str(&serde_json::to_string(&signed).unwrap());
        rewritten.push('\n');
    }
    f.bundle.batches_jsonl = rewritten;
    let mut health: aip_observe::SignedSensorHealth =
        serde_json::from_str(f.bundle.health_jsonl.trim()).unwrap();
    health.health.head = head;
    health.attestation = aip_crypto::sign_ed25519(
        &f.observer_key,
        &f.trust.observer_id,
        &health.health.canonical_bytes(),
    )
    .unwrap();
    f.bundle.health_jsonl = serde_json::to_string(&health).unwrap() + "\n";
    f.trust
        .checkpoints
        .insert(f.bundle.run_id.clone(), checkpoint(&f.bundle));
}

#[test]
fn wrong_instance_requires_a_consistent_claim_and_verified_observer_before_identity_divergence() {
    let mut unrelated = fixture();
    rewrite_fixture_observations(&mut unrelated, false);
    let rec = evaluate_run(&unrelated.bundle, &unrelated.trust)
        .unwrap()
        .reconciliation
        .unwrap();
    assert_eq!(rec.result, ReconciliationResult::CannotProve);
    assert_eq!(rec.identity, IdentityComparison::NoReference);
    let mut claimed = fixture();
    rewrite_fixture_observations(&mut claimed, true);
    let rec = evaluate_run(&claimed.bundle, &claimed.trust)
        .unwrap()
        .reconciliation
        .unwrap();
    assert_eq!(rec.result, ReconciliationResult::IdentityDivergence);
    claimed.trust.observer_public_key_hex = hex::encode(generate_ed25519_keypair().public_key);
    assert!(evaluate_run(&claimed.bundle, &claimed.trust).is_err());
}

#[test]
fn newest_degraded_health_is_not_replaced_with_an_earlier_active_record() {
    let mut f = fixture();
    let mut degraded: aip_observe::SignedSensorHealth =
        serde_json::from_str(f.bundle.health_jsonl.trim()).unwrap();
    degraded.health.emitted_at_ms += 1;
    degraded.health.state = aip_observe::ObserverState::Degraded;
    degraded.health.attested_coverage = None;
    degraded.health.covered_by.clear();
    degraded.attestation = aip_crypto::sign_ed25519(
        &f.observer_key,
        &f.trust.observer_id,
        &degraded.health.canonical_bytes(),
    )
    .unwrap();
    f.bundle
        .health_jsonl
        .push_str(&(serde_json::to_string(&degraded).unwrap() + "\n"));
    f.bundle.verification_time_ms = degraded.health.emitted_at_ms;
    f.trust
        .checkpoints
        .insert(f.bundle.run_id.clone(), checkpoint(&f.bundle));
    let rec = evaluate_run(&f.bundle, &f.trust)
        .unwrap()
        .reconciliation
        .unwrap();
    assert_eq!(rec.result, ReconciliationResult::CannotProve);
    assert_ne!(rec.reason, ReasonCode::ActionEvidenceMatches);
}

#[test]
fn signed_health_clock_rollback_cannot_conceal_terminal_degradation() {
    for rollback in [false, true] {
        let mut f = fixture();
        let mut terminal: aip_observe::SignedSensorHealth =
            serde_json::from_str(f.bundle.health_jsonl.trim()).unwrap();
        if rollback {
            terminal.health.emitted_at_ms -= 1;
        }
        terminal.health.state = aip_observe::ObserverState::Degraded;
        terminal.health.attested_coverage = None;
        terminal.health.covered_by.clear();
        terminal.attestation = aip_crypto::sign_ed25519(
            &f.observer_key,
            &f.trust.observer_id,
            &terminal.health.canonical_bytes(),
        )
        .unwrap();
        f.bundle
            .health_jsonl
            .push_str(&(serde_json::to_string(&terminal).unwrap() + "\n"));
        f.trust
            .checkpoints
            .insert(f.bundle.run_id.clone(), checkpoint(&f.bundle));
        let evaluated = evaluate_run(&f.bundle, &f.trust);
        if rollback {
            assert!(evaluated
                .unwrap_err()
                .contains("chronology moved backwards"));
        } else {
            let rec = evaluated.unwrap().reconciliation.unwrap();
            assert_eq!(rec.result, ReconciliationResult::CannotProve);
            assert_ne!(rec.reason, ReasonCode::ActionEvidenceMatches);
        }
    }
}

#[test]
fn receipt_document_agreement_outside_window_or_without_dispatch_is_explicit() {
    let mut f = fixture();
    let expected = f.bundle.expectation.as_ref().unwrap();
    let receipt = &f.bundle.signed_receipt.as_ref().unwrap().receipt;
    f.bundle.signed_receipt = Some(
        issue_receipt(
            &f.gateway,
            &ToolCall {
                method: MCP_TOOLS_CALL.into(),
                tool_name: receipt.tool_id.clone(),
                decision_id: expected.decision_id,
                agent_id: f.trust.agent_id.clone(),
                tool_call_id: Some("late-request".into()),
                arguments: json!({"loan_id":1,"amount":0}),
            },
            GatewayDisposition::Failed,
            None,
            expected.valid_until + 1,
        )
        .unwrap(),
    );
    let result = evaluate_run(&f.bundle, &f.trust).unwrap();
    assert_eq!(result.receipt_within_authorization, Some(false));
    assert_eq!(result.gateway_disposition, Some(GatewayDisposition::Failed));
    assert!(result
        .limitations
        .iter()
        .any(|s| s.contains("outside the signed")));
    assert!(result
        .limitations
        .iter()
        .any(|s| s.contains("does not establish a successful")));
    assert_eq!(
        result.reconciliation.unwrap().result,
        ReconciliationResult::CannotProve
    );
}
