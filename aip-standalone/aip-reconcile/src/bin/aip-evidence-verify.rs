//! Offline verifier for an exported authorization + observer evidence bundle.
//! Trust anchors are read separately from the bundle and must match its
//! informational copies. This binary never opens a network connection.

use std::{env, fs, path::PathBuf, process::ExitCode};

use aip_authorize::{
    verify_expected_execution_for_agent, DecisionPointTrustAnchors, ExpectedExecution,
};
use aip_observe::{
    verify_attested_batch_independent_of_agent, verify_signed_health, AttestedBatch,
    ObserverTrustAnchors, SignedSensorHealth,
};
use aip_observe_verify::verify::{parse_jsonl, verify_archives};
use aip_reconcile::{
    reconcile_expectation, ExpectedSideCoverage, ObserverEvidence, ReconciliationContext,
};
use serde::Deserialize;
use serde_json::{json, Value};

const USAGE: &str = "Usage: aip-evidence-verify --bundle FILE --anchors FILE\n\n\
Bundle format: version 1 exported AIP + Sniffer Dog evidence JSON.\n\
The anchors file is independently supplied JSON:\n\
  {\"decision_point\":{\"id\":\"...\",\"public_key\":\"64 hex chars\"},\n\
   \"observer\":{\"id\":\"...\",\"key_version\":1,\"public_key\":\"64 hex chars\"}}\n\n\
The bundle's embedded public anchors are informational and must match this file.\n";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    bundle_version: u16,
    evidence_origin: String,
    expected_execution: ExpectedExecution,
    observer_batches: Vec<AttestedBatch>,
    signed_sensor_health: SignedSensorHealth,
    trust_anchors: BundleAnchors,
    verification_context: VerificationSettings,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleAnchors {
    decision_point: PublicAnchor,
    observer: ObserverAnchor,
    agent_public_key: KeyInput,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalAnchors {
    decision_point: PublicAnchor,
    observer: ObserverAnchor,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicAnchor {
    id: String,
    public_key: KeyInput,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObserverAnchor {
    id: String,
    key_version: u32,
    public_key: KeyInput,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum KeyInput {
    Hex(String),
    Bytes(Vec<u8>),
}

impl KeyInput {
    fn decode(&self, label: &str) -> Result<Vec<u8>, String> {
        let bytes = match self {
            Self::Bytes(bytes) => bytes.clone(),
            Self::Hex(value) => decode_hex(value).map_err(|e| format!("{label}: {e}"))?,
        };
        if bytes.len() != 32 {
            return Err(format!("{label} must be a 32-byte Ed25519 public key"));
        }
        Ok(bytes)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationSettings {
    verification_time_ms: u64,
    health_max_age_ms: u64,
    window_tolerance_ms: u64,
    expected_side_coverage: String,
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err("hex key must have an even number of digits".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |b: u8| match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                b'A'..=b'F' => Ok(b - b'A' + 10),
                _ => Err("public key contains non-hex characters".to_string()),
            };
            Ok(digit(pair[0])? * 16 + digit(pair[1])?)
        })
        .collect()
}

fn rejected(error: impl Into<String>) -> Value {
    json!({
        "status": "REJECTED",
        "error": error.into(),
        "reconciliation": null,
        "limitations": limitations()
    })
}

fn limitations() -> Vec<&'static str> {
    vec![
        "Observer signatures authenticate the supplied bytes; they do not prove the observations are true.",
        "Fixture provenance is retained as a producer label and is not upgraded to live kernel evidence.",
        "Kernel observations do not reveal encrypted TLS payloads, MCP tool names, or tool arguments.",
        "No external business effect is established without separate independent evidence.",
        "The embedded agent public key is bundle-supplied; DecisionPoint and observer trust come only from the separate anchors file.",
    ]
}

fn verify(bundle: Bundle, external: ExternalAnchors) -> (Value, bool) {
    if bundle.bundle_version != 1 {
        return (rejected("unsupported evidence bundle version"), false);
    }
    if bundle.evidence_origin.is_empty() {
        return (rejected("evidence_origin is required"), false);
    }
    if bundle.verification_context.expected_side_coverage != "unknown" {
        return (
            rejected("this verifier supports only expected_side_coverage=unknown"),
            false,
        );
    }

    let bundle_dp_key = match bundle
        .trust_anchors
        .decision_point
        .public_key
        .decode("bundle DecisionPoint key")
    {
        Ok(key) => key,
        Err(e) => return (rejected(e), false),
    };
    let external_dp_key = match external
        .decision_point
        .public_key
        .decode("external DecisionPoint key")
    {
        Ok(key) => key,
        Err(e) => return (rejected(e), false),
    };
    let bundle_observer_key = match bundle
        .trust_anchors
        .observer
        .public_key
        .decode("bundle observer key")
    {
        Ok(key) => key,
        Err(e) => return (rejected(e), false),
    };
    let external_observer_key = match external.observer.public_key.decode("external observer key") {
        Ok(key) => key,
        Err(e) => return (rejected(e), false),
    };
    let agent_key = match bundle
        .trust_anchors
        .agent_public_key
        .decode("bundle agent public key")
    {
        Ok(key) => key,
        Err(e) => return (rejected(e), false),
    };

    let health = &bundle.signed_sensor_health.health;
    let dp_anchor_matches = external.decision_point.id == bundle.trust_anchors.decision_point.id
        && external.decision_point.id == bundle.expected_execution.decision_point_id
        && external_dp_key == bundle_dp_key;
    let observer_anchor_matches = external.observer.id == bundle.trust_anchors.observer.id
        && external.observer.id == health.observer_id
        && external.observer.key_version == bundle.trust_anchors.observer.key_version
        && external.observer.key_version == health.key_version
        && external_observer_key == bundle_observer_key;
    if !dp_anchor_matches || !observer_anchor_matches {
        return (
            rejected("independent trust anchors do not match bundle metadata"),
            false,
        );
    }

    let dp_anchors =
        DecisionPointTrustAnchors::new().trust(&external.decision_point.id, &external_dp_key);
    let observer_anchors = ObserverTrustAnchors::new().trust(
        &external.observer.id,
        external.observer.key_version,
        &external_observer_key,
    );

    let expected_result =
        verify_expected_execution_for_agent(&bundle.expected_execution, &dp_anchors, &agent_key);
    let batch_results: Vec<bool> = bundle
        .observer_batches
        .iter()
        .map(|batch| {
            verify_attested_batch_independent_of_agent(batch, &observer_anchors, &agent_key).is_ok()
        })
        .collect();
    let health_result = verify_signed_health(&bundle.signed_sensor_health, &observer_anchors);

    // The existing observer archive verifier checks signatures, sequence,
    // previous-head links, and health/head consistency using the same public
    // verification API already shipped in aip-observe-verify.
    let batch_jsonl = bundle
        .observer_batches
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>();
    let health_jsonl = serde_json::to_string(&bundle.signed_sensor_health);
    let (archive_ok, archive_report) = match (batch_jsonl, health_jsonl) {
        (Ok(lines), Ok(health_line)) => {
            let archive = verify_archives(
                &external.observer.id,
                external.observer.key_version,
                &external_observer_key,
                Some(parse_jsonl(&lines.join("\n"))),
                Some(parse_jsonl(&health_line)),
            );
            (
                bundle.observer_batches.is_empty() || archive.ok(),
                serde_json::to_value(archive).unwrap_or(Value::Null),
            )
        }
        (Err(e), _) | (_, Err(e)) => {
            return (
                rejected(format!("cannot serialize verifier input: {e}")),
                false,
            )
        }
    };

    let signatures_ok = expected_result.is_ok()
        && batch_results.iter().all(|ok| *ok)
        && health_result.is_ok()
        && archive_ok;
    let incomplete = bundle.observer_batches.is_empty();

    let evidence = ObserverEvidence {
        batches: bundle.observer_batches.clone(),
        health: bundle.signed_sensor_health.clone(),
    };
    let context = ReconciliationContext {
        decision_point_anchors: dp_anchors,
        observer_anchors,
        verification_time_ms: bundle.verification_context.verification_time_ms,
        health_max_age_ms: bundle.verification_context.health_max_age_ms,
        window_tolerance_ms: bundle.verification_context.window_tolerance_ms,
        expected_side: ExpectedSideCoverage::Unknown,
        agent_public_key: Some(agent_key),
    };
    // The engine independently re-verifies its inputs. This call is the sole
    // source of the reconciliation result; the CLI never upgrades it.
    let reconciliation =
        reconcile_expectation(&bundle.expected_execution, Some(&evidence), &context);
    let status = if !signatures_ok {
        "REJECTED"
    } else if incomplete {
        "INCOMPLETE"
    } else {
        "INPUTS_VERIFIED"
    };
    let report = json!({
        "status": status,
        "evidence_origin": bundle.evidence_origin,
        "evidence_origin_is_self_asserted": true,
        "expected_execution": {
            "agent_id": bundle.expected_execution.agent_id,
            "decision_id": bundle.expected_execution.decision_id.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "decision_point_id": bundle.expected_execution.decision_point_id,
            "action_kind": format!("{:?}", bundle.expected_execution.action_kind),
            "execution_binding": bundle.expected_execution.execution_binding
        },
        "observer_health": {
            "observer_id": health.observer_id,
            "key_version": health.key_version,
            "state": format!("{:?}", health.state),
            "sequence": health.sequence,
            "emitted_at_ms": health.emitted_at_ms,
            "attested_coverage": health.attested_coverage
        },
        "signature_verification": {
            "expected_execution": {"verified": expected_result.is_ok(), "error": expected_result.err().map(|e| e.to_string())},
            "observer_batches": batch_results,
            "signed_sensor_health": {"verified": health_result.is_ok(), "error": health_result.err().map(|e| e.to_string())},
            "observer_archive": archive_report
        },
        "reconciliation": serde_json::to_value(&reconciliation).unwrap_or(Value::Null),
        "reconciliation_result": format!("{:?}", reconciliation.result),
        "evidence_strength": format!("{:?}", reconciliation.strength),
        "reason_code": format!("{:?}", reconciliation.reason),
        "limitations": limitations()
    });
    let accepted = signatures_ok && !incomplete;
    (report, accepted)
}

fn parse_args(args: &[String]) -> Result<Option<(PathBuf, PathBuf)>, String> {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        return Ok(None);
    }
    let mut bundle = None;
    let mut anchors = None;
    let mut i = 0;
    while i < args.len() {
        let slot = match args[i].as_str() {
            "--bundle" => &mut bundle,
            "--anchors" => &mut anchors,
            other => return Err(format!("unknown argument {other}")),
        };
        i += 1;
        let value = args
            .get(i)
            .ok_or_else(|| format!("{} requires a file", args[i - 1]))?;
        *slot = Some(PathBuf::from(value));
        i += 1;
    }
    Ok(Some((
        bundle.ok_or("--bundle is required")?,
        anchors.ok_or("--anchors is required")?,
    )))
}

fn read_json(path: &PathBuf, what: &str) -> Result<Value, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("cannot read {what}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("malformed {what}: {e}"))
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let paths = match parse_args(&args) {
        Ok(Some(paths)) => paths,
        Ok(None) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            println!("{}", rejected(e));
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let (bundle_path, anchors_path) = paths;
    let bundle_value = match read_json(&bundle_path, "bundle") {
        Ok(v) => v,
        Err(e) => {
            println!("{}", rejected(e));
            return ExitCode::FAILURE;
        }
    };
    let anchor_value = match read_json(&anchors_path, "external trust anchors") {
        Ok(v) => v,
        Err(e) => {
            println!("{}", rejected(e));
            return ExitCode::FAILURE;
        }
    };
    let bundle = match serde_json::from_value::<Bundle>(bundle_value) {
        Ok(v) => v,
        Err(e) => {
            println!("{}", rejected(format!("malformed evidence bundle: {e}")));
            return ExitCode::FAILURE;
        }
    };
    let anchors = match serde_json::from_value::<ExternalAnchors>(anchor_value) {
        Ok(v) => v,
        Err(e) => {
            println!(
                "{}",
                rejected(format!("malformed or missing external trust anchor: {e}"))
            );
            return ExitCode::FAILURE;
        }
    };
    let (report, accepted) = verify(bundle, anchors);
    println!(
        "{}",
        serde_json::to_string_pretty(&report).unwrap_or_else(|_| {
            "{\"status\":\"REJECTED\",\"error\":\"report serialization failed\"}".into()
        })
    );
    if accepted {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
