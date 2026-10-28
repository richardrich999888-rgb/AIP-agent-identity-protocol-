//! Read-only offline composition of existing verifiers, with separately
//! supplied assessor anchors. No interoperability event can become an AIP
//! observation, authorization, or receipt by passing through this program.
use std::collections::HashSet;
use std::io::Read;

use aip_airi::{
    compare_tool_boundary, verify_tool_receipt, GatewayTrustAnchors, SignedToolReceipt,
};
use aip_authorize::{
    verify_expected_execution_for_agent, DecisionPointTrustAnchors, ExpectedExecution,
};
use aip_observe::{AttestedBatch, ObserverTrustAnchors, SignedSensorHealth};
use aip_reconcile::{
    reconcile_expectation, ExpectedSideCoverage, ObserverEvidence, ReconciliationContext,
};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Anchors {
    agent_key: Vec<u8>,
    decision_point_id: String,
    decision_point_key: Vec<u8>,
    gateway_id: String,
    gateway_version: u32,
    gateway_key: Vec<u8>,
    observer_id: String,
    observer_version: u32,
    observer_key: Vec<u8>,
    verification_time_ms: u64,
    health_max_age_ms: u64,
    window_tolerance_ms: u64,
}

impl Anchors {
    fn check(&self) -> Result<(), String> {
        let keys = [
            &self.agent_key,
            &self.decision_point_key,
            &self.gateway_key,
            &self.observer_key,
        ];
        if keys.iter().any(|k| k.len() != 32) {
            return Err("all four independently supplied public keys must be 32 bytes".into());
        }
        if keys.into_iter().collect::<HashSet<_>>().len() != 4 {
            return Err("agent, decision point, gateway and observer keys must differ".into());
        }
        if self.decision_point_id.is_empty()
            || self.gateway_id.is_empty()
            || self.observer_id.is_empty()
        {
            return Err("explicit signer identities are required".into());
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    batches: Vec<AttestedBatch>,
    health: SignedSensorHealth,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    expectation: ExpectedExecution,
    receipt: Option<SignedToolReceipt>,
    observation: Option<Observation>,
}

fn verify(bundle: Bundle, anchors: Anchors) -> Result<Value, String> {
    anchors.check()?;
    let decisions = DecisionPointTrustAnchors::new()
        .trust(&anchors.decision_point_id, &anchors.decision_point_key);
    verify_expected_execution_for_agent(&bundle.expectation, &decisions, &anchors.agent_key)
        .map_err(|e| format!("expected execution rejected: {e:?}"))?;
    let gateways = GatewayTrustAnchors::new().trust(
        &anchors.gateway_id,
        anchors.gateway_version,
        &anchors.gateway_key,
    );
    let receipt = bundle
        .receipt
        .as_ref()
        .map(|r| verify_tool_receipt(r, &gateways, Some(&anchors.agent_key)))
        .transpose()
        .map_err(|e| format!("gateway receipt rejected: {e:?}"))?;
    let boundary = compare_tool_boundary(&bundle.expectation, &decisions, receipt.as_ref(), None);
    let observation = bundle.observation.map(|o| ObserverEvidence {
        batches: o.batches,
        health: o.health,
    });
    let context = ReconciliationContext {
        decision_point_anchors: decisions,
        observer_anchors: ObserverTrustAnchors::new().trust(
            &anchors.observer_id,
            anchors.observer_version,
            &anchors.observer_key,
        ),
        verification_time_ms: anchors.verification_time_ms,
        health_max_age_ms: anchors.health_max_age_ms,
        window_tolerance_ms: anchors.window_tolerance_ms,
        expected_side: ExpectedSideCoverage::Unknown,
        agent_public_key: Some(anchors.agent_key),
    };
    let reconciliation = reconcile_expectation(&bundle.expectation, observation.as_ref(), &context);
    Ok(json!({
        "schema": "vanian.interop.offline-reference.v1",
        "expected_execution_signature": "VERIFIED",
        "tool_boundary": boundary,
        "runtime_reconciliation": reconciliation,
        "authority_chain": "NOT_ASSESSED_BY_THIS_COMPOSITION",
        "external_identity_mapping": "NOT_ASSESSED_BY_THIS_COMPOSITION",
        "key_administrative_independence": "REQUIRES_DEPLOYMENT_EVIDENCE",
        "note": "Distinct keys do not prove separate administration. Policy references and application traces are not accepted as native evidence. Tool receipts do not prove downstream business outcomes."
    }))
}

fn read(path: &str) -> Result<Vec<u8>, String> {
    let file = std::fs::File::open(path).map_err(|_| "cannot open input")?;
    let mut bytes = Vec::new();
    file.take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read input")?;
    if bytes.len() > 64 * 1024 * 1024 {
        return Err("input exceeds 64 MiB".into());
    }
    Ok(bytes)
}

fn run() -> Result<Value, String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: interop_verify ASSESSOR_ANCHORS.json UNTRUSTED_BUNDLE.json".into());
    }
    let anchors =
        serde_json::from_slice(&read(&args[1])?).map_err(|_| "invalid assessor context")?;
    let bundle =
        serde_json::from_slice(&read(&args[2])?).map_err(|_| "invalid native evidence bundle")?;
    verify(bundle, anchors)
}

fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("interop verification refused: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn anchors() -> Anchors {
        Anchors {
            agent_key: vec![1; 32],
            decision_point_id: "dp".into(),
            decision_point_key: vec![2; 32],
            gateway_id: "gateway".into(),
            gateway_version: 1,
            gateway_key: vec![3; 32],
            observer_id: "observer".into(),
            observer_version: 1,
            observer_key: vec![4; 32],
            verification_time_ms: 100,
            health_max_age_ms: 100,
            window_tolerance_ms: 0,
        }
    }
    #[test]
    fn duplicate_roles_are_refused_including_observer_gateway() {
        let mut a = anchors();
        a.observer_key = a.gateway_key.clone();
        assert!(a.check().is_err());
        let mut a = anchors();
        a.decision_point_key = a.agent_key.clone();
        assert!(a.check().is_err());
    }
    #[test]
    fn malformed_keys_are_refused() {
        let mut a = anchors();
        a.agent_key.pop();
        assert!(a.check().is_err());
    }
    #[test]
    fn external_allow_cannot_deserialize_as_core_authorization() {
        assert!(serde_json::from_str::<Bundle>(
            r#"{"expectation":{"allow":true},"receipt":null,"observation":null}"#
        )
        .is_err());
    }
}
