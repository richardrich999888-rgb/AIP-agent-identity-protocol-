//! The invariants that make the product worth anything (A2, A12, report
//! safety). If one of these fails, the report could overclaim.

mod common;

use aip_aibom::adapters::mcp_config::parse;
use aip_aibom::evidence::{AssessorContext, EvidenceBundle};
use aip_aibom::model::*;
use aip_aibom::report::{assessment_json, assessment_text, csv_field, fields_csv, findings_csv};
use aip_aibom::{Assessment, Component};
use common::*;

struct Rich {
    m: Manifest,
    bundle: EvidenceBundle,
    trusted: AssessorContext,
}

/// A manifest populated in every component, backed by real evidence.
fn rich() -> Rich {
    let cfo = principal("cfo");
    let (doc, _) = active_identity("treasury-agent");
    let token = grant(
        &cfo,
        &doc.id,
        scope(&["read_balance", "create_payment"], &[]),
        Some(HOUR_MS),
    );
    let mut m = manifest(&doc.id);
    m.models = vec![Model {
        provider: "p".into(),
        model: "m".into(),
        version: None,
        hosting: Hosting::Hosted,
        weight_sha256: None,
    }];
    m.frameworks = vec![Framework {
        name: "langgraph".into(),
        version: "0.2".into(),
    }];
    m.tools = vec![Tool {
        id: "ledger".into(),
        kind: ToolKind::Mcp,
        actions: vec![],
        endpoint: None,
    }];
    m.permissions.allowed = vec![custom("read_balance"), custom("create_payment")];
    m.permissions.limits = vec![Limit {
        action: custom("create_payment"),
        per: LimitPeriod::PerAction,
        max: usd(1000),
    }];
    m.data_access = vec![DataAccess {
        resource: "ledger-db".into(),
        kind: ResourceKind::Database,
        access: Access::Read,
    }];
    m.relationships.delegated_from = vec![cfo.id.clone()];
    m.security_controls = vec![SecurityControl {
        kind: ControlKind::Sandbox,
        description: "gVisor".into(),
    }];
    m.crypto = CryptoPosture {
        identity_key_algorithm: Some(aip_types::AlgorithmId::Ed25519),
        signing: vec!["ed25519".into()],
        post_quantum: true,
    };
    m.supply_chain = vec![SupplyComponent {
        component: "openssl".into(),
        version: "3".into(),
        sha256: None,
        origin: None,
    }];
    m.governance = Governance {
        risk_class: Some("high".into()),
        policies: vec![],
        audit_owner: None,
    };
    let mut trusted = AssessorContext::trusting_nothing(token.issued_at + 1);
    trusted
        .issuer_keys
        .insert(cfo.id.clone(), cfo.kp.public_key.clone());
    Rich {
        m,
        bundle: EvidenceBundle {
            identity: Some(doc),
            authority: vec![chain(token)],
            ..Default::default()
        },
        trusted,
    }
}

fn independent(a: &Assessment) -> usize {
    a.fields
        .iter()
        .filter(|f| f.standing.is_independent())
        .count()
}

#[test]
fn the_rich_fixture_does_reach_independent_standing() {
    let r = rich();
    let a = run(&r.m, &r.bundle, &r.trusted, &[]);
    assert!(
        independent(&a) >= 4,
        "the control for the two tests below must itself be live"
    );
}

/// **A2.** Without trust from the assessor, nothing an assessed party offers
/// raises any field above its own word.
#[test]
fn no_independent_standing_without_the_assessors_trust() {
    let r = rich();
    let a = run(
        &r.m,
        &r.bundle,
        &AssessorContext::trusting_nothing(r.trusted.present_time_ms),
        &[],
    );
    let ids: Vec<_> = a
        .fields
        .iter()
        .filter(|f| f.standing.is_independent())
        .map(|f| &f.path)
        .collect();
    assert_eq!(
        ids,
        vec!["$.agent.id", "$.crypto.identity_key_algorithm"],
        "only the self-certifying identity may verify without anchors"
    );
}

/// **A2.** Without evidence, full trust raises nothing either.
#[test]
fn no_independent_standing_without_evidence() {
    let r = rich();
    let a = run(&r.m, &EvidenceBundle::default(), &r.trusted, &[]);
    assert_eq!(independent(&a), 0);
}

/// The report covers all thirteen components when the manifest populates them.
#[test]
fn every_component_is_reported() {
    let r = rich();
    let a = run(&r.m, &r.bundle, &r.trusted, &[]);
    for c in Component::ALL {
        assert!(
            a.fields.iter().any(|f| f.component == c),
            "{} missing",
            c.code()
        );
    }
}

/// **A12.** Same inputs, same bytes.
#[test]
fn assessment_and_rendering_are_deterministic() {
    let r = rich();
    let d = parse(
        br#"{"mcpServers": {"ledger": {"command": "npx"}}}"#,
        "mcp.json",
    )
    .unwrap();
    let a = run(&r.m, &r.bundle, &r.trusted, std::slice::from_ref(&d));
    let b = run(&r.m, &r.bundle, &r.trusted, std::slice::from_ref(&d));
    assert_eq!(assessment_json(&a), assessment_json(&b));
    assert_eq!(assessment_text(&a), assessment_text(&b));
    assert_eq!(fields_csv(&a), fields_csv(&b));
    assert_eq!(findings_csv(&a), findings_csv(&b));
}

#[test]
fn the_summary_counts_add_up() {
    let r = rich();
    let a = run(&r.m, &r.bundle, &r.trusted, &[]);
    let s = &a.summary;
    assert_eq!(
        s.verified
            + s.observed
            + s.discovered
            + s.self_reported
            + s.unknowable
            + s.lapsed
            + s.contradicted
            + s.evidence_rejected,
        s.fields
    );
    assert_eq!(s.critical + s.high + s.medium + s.info, a.findings.len());
}

/// Reports are opened in spreadsheets.
#[test]
fn csv_cells_cannot_become_formulas() {
    assert_eq!(csv_field("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
    assert_eq!(csv_field("+1"), "'+1");
    assert_eq!(csv_field("-1"), "'-1");
    assert_eq!(csv_field("@SUM(A1)"), "'@SUM(A1)");
    assert_eq!(csv_field("plain"), "plain");
    assert_eq!(csv_field("a,b"), "\"a,b\"");
}

#[test]
fn the_text_report_ends_with_its_own_limit() {
    let r = rich();
    let a = run(&r.m, &r.bundle, &r.trusted, &[]);
    assert!(assessment_text(&a).contains("It does not establish what the agent did."));
}
