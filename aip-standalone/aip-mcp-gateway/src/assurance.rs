//! Same-run composition of existing authorization, receipt and observer verifiers.
//!
//! This module does not create a new execution verdict. The kernel reconciler
//! and signed-document tool comparison remain separate questions. Public keys
//! and retained checkpoints are supplied by the verifier's administrator.

use std::collections::BTreeMap;

use aip_airi::{
    compare_tool_boundary, verify_tool_receipt, GatewayDisposition, GatewayTrustAnchors,
    SignedToolReceipt, ToolBoundary,
};
use aip_authorize::{
    tool_invoke_action, tool_invoke_parameters, verify_expected_execution_for_agent,
    AuthorizationRequest, Decision, DecisionPoint, DecisionPointTrustAnchors, ExpectedExecution,
    TemporalStatus,
};
use aip_observe::{AttestedBatch, ObserverTrustAnchors, SignedSensorHealth};
use aip_observe_verify::verify::{parse_jsonl, verify_archives};
use aip_reconcile::{
    reconcile_expectation, ExpectedSideCoverage, ObserverEvidence, ReconcilerTrustAnchors,
    Reconciliation, ReconciliationContext, SignedReconciliation,
};
use aip_types::{DelegationToken, ExecutionBinding, ScopedToken};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const MAX_ARCHIVE_BYTES: usize = 8 * 1024 * 1024;
const MAX_RECORDS: usize = 2048;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunCheckpoint {
    pub batches_sha256: String,
    pub health_sha256: String,
}

/// Tenant-admin configuration, loaded separately from submitted evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunTrustConfig {
    pub agent_id: String,
    pub agent_public_key_hex: String,
    pub decision_point_id: String,
    pub decision_point_public_key_hex: String,
    pub gateway_id: String,
    pub gateway_key_version: u32,
    pub gateway_public_key_hex: String,
    pub observer_id: String,
    pub observer_key_version: u32,
    pub observer_public_key_hex: String,
    pub reconciler_id: String,
    pub reconciler_key_version: u32,
    pub reconciler_public_key_hex: String,
    #[serde(default)]
    pub checkpoints: BTreeMap<String, RunCheckpoint>,
    #[serde(default = "default_health_age")]
    pub health_max_age_ms: u64,
    #[serde(default)]
    pub window_tolerance_ms: u64,
}

fn default_health_age() -> u64 {
    60_000
}

pub fn public_key(value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|_| "public key is not hexadecimal")?;
    bytes
        .try_into()
        .map_err(|_| "public key is not 32 bytes".into())
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}

impl RunTrustConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !valid_id(&self.agent_id)
            || !valid_id(&self.decision_point_id)
            || !valid_id(&self.gateway_id)
            || !valid_id(&self.observer_id)
            || !valid_id(&self.reconciler_id)
            || self.gateway_key_version == 0
            || self.observer_key_version == 0
            || self.reconciler_key_version == 0
            || self.health_max_age_ms == 0
            || self.health_max_age_ms > 300_000
            || self.window_tolerance_ms > 5_000
        {
            return Err("invalid run trust configuration".into());
        }
        let keys = [
            public_key(&self.agent_public_key_hex)?,
            public_key(&self.decision_point_public_key_hex)?,
            public_key(&self.gateway_public_key_hex)?,
            public_key(&self.observer_public_key_hex)?,
            public_key(&self.reconciler_public_key_hex)?,
        ];
        for (index, key) in keys.iter().enumerate() {
            if keys[index + 1..].contains(key) {
                return Err(
                    "agent, authority, gateway, collector and reconciler keys must be distinct"
                        .into(),
                );
            }
        }
        Ok(())
    }

    fn decision_anchors(&self) -> Result<DecisionPointTrustAnchors, String> {
        Ok(DecisionPointTrustAnchors::new().trust(
            &self.decision_point_id,
            &public_key(&self.decision_point_public_key_hex)?,
        ))
    }
}

/// No private keys or trust-anchor inputs are accepted in this bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunBundle {
    pub run_id: String,
    pub agent_id: String,
    pub expectation: Option<ExpectedExecution>,
    pub signed_receipt: Option<SignedToolReceipt>,
    #[serde(default)]
    pub signed_reconciliation: Option<SignedReconciliation>,
    pub batches_jsonl: String,
    pub health_jsonl: String,
    /// Historical evaluation time, visibly retained rather than confused with
    /// the current service clock. Bounded by the latest signed health below.
    pub verification_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunEvaluation {
    pub run_id: String,
    pub agent_id: String,
    pub archive_integrity_verified: bool,
    pub checkpoint_verified: bool,
    pub authorization_verified: bool,
    pub gateway_receipt_verified: bool,
    pub signed_reconciliation_verified: bool,
    pub receipt_within_authorization: Option<bool>,
    pub gateway_disposition: Option<GatewayDisposition>,
    pub reconciliation: Option<Reconciliation>,
    pub tool_boundary: Option<ToolBoundary>,
    pub limitations: Vec<String>,
}

/// Invalid or untrusted records are rejected. Missing evidence is admitted as
/// an explicit inability to evaluate, never as an execution finding.
pub fn evaluate_run(bundle: &RunBundle, trust: &RunTrustConfig) -> Result<RunEvaluation, String> {
    trust.validate()?;
    if !valid_id(&bundle.run_id) || bundle.agent_id != trust.agent_id {
        return Err("run identifier or configured agent does not match".into());
    }
    if bundle
        .batches_jsonl
        .len()
        .saturating_add(bundle.health_jsonl.len())
        > MAX_ARCHIVE_BYTES
    {
        return Err("run archives exceed 8 MiB".into());
    }
    for text in [&bundle.batches_jsonl, &bundle.health_jsonl] {
        let count = text.lines().filter(|line| !line.trim().is_empty()).count();
        if count == 0 || count > MAX_RECORDS || !text.ends_with('\n') {
            return Err("archives require 1..2048 complete JSONL records".into());
        }
    }
    let checkpoint = trust
        .checkpoints
        .get(&bundle.run_id)
        .ok_or("no independently retained checkpoint is configured for this run")?;
    if hex::encode(aip_crypto::sha256(bundle.batches_jsonl.as_bytes())) != checkpoint.batches_sha256
        || hex::encode(aip_crypto::sha256(bundle.health_jsonl.as_bytes()))
            != checkpoint.health_sha256
    {
        return Err("independently retained archive checkpoint mismatch".into());
    }
    let agent_key = public_key(&trust.agent_public_key_hex)?;
    let observer_key = public_key(&trust.observer_public_key_hex)?;
    let report = verify_archives(
        &trust.observer_id,
        trust.observer_key_version,
        &observer_key,
        Some(parse_jsonl(&bundle.batches_jsonl)),
        Some(parse_jsonl(&bundle.health_jsonl)),
    );
    if !report.ok() {
        return Err("collector archive signature or continuity verification failed".into());
    }
    let batches: Vec<AttestedBatch> = bundle
        .batches_jsonl
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(|_| "invalid attested batch".to_string()))
        .collect::<Result<_, _>>()?;
    let health: Vec<SignedSensorHealth> = bundle
        .health_jsonl
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(|_| "invalid signed health".to_string()))
        .collect::<Result<_, _>>()?;
    // The latest signed state is authoritative, including degraded/recovering
    // states. Never select an earlier Active record to conceal interruption.
    if health
        .windows(2)
        .any(|pair| pair[1].health.emitted_at_ms < pair[0].health.emitted_at_ms)
    {
        return Err(
            "signed health chronology moved backwards; terminal coverage is ambiguous".into(),
        );
    }
    let newest = health.last().ok_or("no signed health record")?;
    if bundle.verification_time_ms < newest.health.emitted_at_ms {
        return Err("evaluation time precedes the retained signed health".into());
    }
    let mut result = RunEvaluation {
        run_id: bundle.run_id.clone(), agent_id: bundle.agent_id.clone(),
        archive_integrity_verified: true, checkpoint_verified: true,
        authorization_verified: false, gateway_receipt_verified: false,
        signed_reconciliation_verified: false,
        receipt_within_authorization: None, gateway_disposition: None,
        reconciliation: None, tool_boundary: None,
        limitations: vec![
            "Archive signatures establish integrity; collector administrative separation requires deployment evidence.".into(),
            "Kernel process identity does not establish logical sub-agent attribution or a business outcome.".into(),
            "Tool request comparison is separate from the kernel reconciliation and cannot upgrade its verdict.".into(),
        ],
    };
    let verified_receipt = if let Some(signed) = &bundle.signed_receipt {
        let anchors = GatewayTrustAnchors::new().trust(
            &trust.gateway_id,
            trust.gateway_key_version,
            &public_key(&trust.gateway_public_key_hex)?,
        );
        let receipt = verify_tool_receipt(signed, &anchors, Some(&agent_key))
            .map_err(|error| format!("gateway receipt verification failed: {error:?}"))?;
        if receipt.receipt().agent_id != trust.agent_id {
            return Err("receipt names another configured agent".into());
        }
        result.gateway_receipt_verified = true;
        result.gateway_disposition = Some(receipt.receipt().disposition);
        Some(receipt)
    } else {
        result.limitations.push("No trustworthy gateway receipt: gateway-received parameters and dispatch cannot be established.".into());
        None
    };
    if let Some(expectation) = &bundle.expectation {
        if expectation.agent_id != trust.agent_id {
            return Err("expectation names another configured agent".into());
        }
        let decision_anchors = trust.decision_anchors()?;
        verify_expected_execution_for_agent(expectation, &decision_anchors, &agent_key)
            .map_err(|error| format!("authorization verification failed: {error}"))?;
        result.authorization_verified = true;
        if let Some(receipt) = &verified_receipt {
            result.receipt_within_authorization = Some(matches!(
                expectation.temporal_status_at(receipt.receipt().received_at_ms),
                TemporalStatus::Valid
            ));
            if result.receipt_within_authorization != Some(true) {
                result.limitations.push("Gateway received the request outside the signed authorization window; document agreement is not timely authorization.".into());
            }
            if receipt.receipt().disposition != GatewayDisposition::Forwarded {
                result.limitations.push(
                    "Gateway disposition does not establish a successful tool dispatch.".into(),
                );
            }
        }
        result.tool_boundary = Some(compare_tool_boundary(
            expectation,
            &decision_anchors,
            verified_receipt.as_ref(),
            None,
        ));
        result.reconciliation = Some(reconcile_expectation(
            expectation,
            Some(&ObserverEvidence {
                batches,
                health: newest.clone(),
            }),
            &ReconciliationContext {
                decision_point_anchors: decision_anchors,
                observer_anchors: ObserverTrustAnchors::new().trust(
                    &trust.observer_id,
                    trust.observer_key_version,
                    &observer_key,
                ),
                verification_time_ms: bundle.verification_time_ms,
                health_max_age_ms: trust.health_max_age_ms,
                window_tolerance_ms: trust.window_tolerance_ms,
                expected_side: ExpectedSideCoverage::Unknown,
                agent_public_key: Some(agent_key.to_vec()),
            },
        ));
    } else {
        result.limitations.push("CANNOT_PROVE: authorization is absent and expected-side completeness is unknown; an observed effect is not automatically unauthorized.".into());
    }
    if let Some(signed) = &bundle.signed_reconciliation {
        let anchors = ReconcilerTrustAnchors::new().trust(
            &trust.reconciler_id,
            trust.reconciler_key_version,
            &public_key(&trust.reconciler_public_key_hex)?,
        );
        signed
            .verify(&anchors)
            .map_err(|error| format!("signed reconciliation: {error:?}"))?;
        let recomputed = result
            .reconciliation
            .as_ref()
            .ok_or("a signed kernel finding cannot be admitted without its authorization")?;
        if signed.reconciliation.canonical_bytes() != recomputed.canonical_bytes() {
            return Err(
                "signed reconciliation differs from independently recomputed kernel finding".into(),
            );
        }
        result.signed_reconciliation_verified = true;
    } else {
        result.limitations.push(
            "Kernel reconciliation has not been attested by the configured reconciler.".into(),
        );
    }
    Ok(result)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedCall {
    pub tool_id: String,
    pub arguments: Value,
}

/// Authority-owned policy, not agent input. Exact canonical allowlisting
/// covers tool, resource, argument values and absence of extra arguments.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityConfig {
    pub decision_point_id: String,
    pub decision_key_file: String,
    pub decision_public_key_hex: String,
    pub agent_id: String,
    pub agent_public_key_hex: String,
    pub issuer_keys: BTreeMap<String, String>,
    pub root_token: ScopedToken,
    pub delegation_chain: Vec<DelegationToken>,
    pub allowed_calls: Vec<AllowedCall>,
    pub max_ttl_ms: u64,
    pub requested_ttl_ms: u64,
}

/// Reuses core authority evaluation after an authority-owned exact-call
/// policy. The binding must have been independently measured by its caller.
pub fn authorize_measured(
    config: &AuthorityConfig,
    decision_key: &[u8],
    binding: ExecutionBinding,
    tool_id: &str,
    arguments: &Value,
) -> Result<ExpectedExecution, String> {
    if binding.agent_id != config.agent_id
        || !arguments.is_object()
        || config.allowed_calls.is_empty()
        || config.allowed_calls.len() > 128
        || config.max_ttl_ms == 0
        || config.max_ttl_ms > 300_000
        || config.requested_ttl_ms == 0
        || config.requested_ttl_ms > config.max_ttl_ms
    {
        return Err("authority policy, binding or TTL invalid".into());
    }
    if !config.allowed_calls.iter().any(|allowed| {
        allowed.tool_id == tool_id
            && allowed.arguments.is_object()
            && crate::canonical_json_bytes(&allowed.arguments)
                == crate::canonical_json_bytes(arguments)
    }) {
        return Err("requested tool/resource/parameters are outside authority policy".into());
    }
    let authority_key = public_key(&config.decision_public_key_hex)?;
    let agent_key = public_key(&config.agent_public_key_hex)?;
    if authority_key == agent_key
        || aip_crypto::public_key_from_private(decision_key).map_err(|_| "invalid authority key")?
            != authority_key
    {
        return Err("authority key is not independently configured".into());
    }
    let mut point = DecisionPoint::new(
        &config.decision_point_id,
        decision_key,
        &authority_key,
        config.max_ttl_ms,
    )
    .map_err(|e| format!("authority: {e:?}"))?;
    for (issuer, key) in &config.issuer_keys {
        let key = public_key(key)?;
        if key == agent_key || key == authority_key {
            return Err("issuer, agent and decision authority keys must be independent".into());
        }
        point = point.trust_issuer(issuer, &key);
    }
    let request = AuthorizationRequest {
        agent_id: config.agent_id.clone(),
        root_token: config.root_token.clone(),
        delegation_chain: config.delegation_chain.clone(),
        action_kind: tool_invoke_action(),
        parameters: tool_invoke_parameters(tool_id, crate::parameter_commitment(arguments))
            .map_err(|_| "invalid tool identity")?,
        execution_binding: binding,
        requested_ttl_ms: config.requested_ttl_ms,
    };
    match point.authorize(&request) {
        Decision::Authorized(expectation) => Ok(*expectation),
        Decision::Denied(denial) => Err(format!("authorization denied: {:?}", denial.reason)),
    }
}

/// Final gateway check over the actual received call, using configured public
/// authority anchors. No receipt is invented to perform authorization.
pub fn check_authorization(
    expectation: &ExpectedExecution,
    trust: &RunTrustConfig,
    agent_id: &str,
    tool_id: &str,
    arguments: &Value,
    received_at_ms: u64,
) -> Result<(), String> {
    trust.validate()?;
    if agent_id != trust.agent_id || expectation.agent_id != agent_id || !arguments.is_object() {
        return Err("authenticated agent or request structure does not match authorization".into());
    }
    verify_expected_execution_for_agent(
        expectation,
        &trust.decision_anchors()?,
        &public_key(&trust.agent_public_key_hex)?,
    )
    .map_err(|error| format!("authorization: {error}"))?;
    if expectation.action_kind != tool_invoke_action()
        || expectation.parameter_digest
            != tool_invoke_parameters(tool_id, crate::parameter_commitment(arguments))
                .map_err(|_| "invalid tool identity")?
                .digest()
    {
        return Err("gateway-received tool/parameters differ from signed authorization".into());
    }
    if expectation.temporal_status_at(received_at_ms) != TemporalStatus::Valid {
        return Err("gateway request is outside signed authorization window".into());
    }
    Ok(())
}
