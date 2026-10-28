//! C2 models, C4 tools, C9 controls, C10 post-quantum, C13 validity — and the
//! seal.

mod common;

use aip_aibom::adapters::mcp_config::parse;
use aip_aibom::assess::SealStanding;
use aip_aibom::evidence::{AssessorContext, EvidenceBundle};
use aip_aibom::finding::FindingKind;
use aip_aibom::model::*;
use aip_aibom::seal::Publisher;
use aip_aibom::standing::{NonEstablishment, Standing};
use aip_aibom::{assess, Inputs};
use common::*;

fn ctx() -> AssessorContext {
    AssessorContext::trusting_nothing(1_000)
}

#[test]
fn model_identity_is_unknowable_and_says_which_limit_applies() {
    let mut m = manifest("agent");
    m.models = vec![
        Model {
            provider: "example-provider".into(),
            model: "example-model".into(),
            version: Some("2026-10".into()),
            hosting: Hosting::Hosted,
            weight_sha256: None,
        },
        Model {
            provider: "local".into(),
            model: "llama".into(),
            version: None,
            hosting: Hosting::Local,
            weight_sha256: Some("a".repeat(64)),
        },
    ];
    let a = run(&m, &EvidenceBundle::default(), &ctx(), &[]);
    assert_eq!(
        standing(&a, "$.models[0]"),
        Standing::Unknowable {
            non_establishment: NonEstablishment::N3
        }
    );
    assert_eq!(
        standing(&a, "$.models[1]"),
        Standing::Unknowable {
            non_establishment: NonEstablishment::N4
        }
    );
    assert_eq!(
        standing(&a, "$.models[1].weight_sha256"),
        Standing::SelfReported
    );
}

/// The $5,000 lesson, per tool: that a call's external effect landed is not
/// something any mechanism here can establish.
#[test]
fn every_tools_external_effect_is_unknowable() {
    let mut m = manifest("agent");
    m.tools = vec![Tool {
        id: "payments-api".into(),
        kind: ToolKind::Api,
        actions: vec!["create_payment".into()],
        endpoint: None,
    }];
    let a = run(&m, &EvidenceBundle::default(), &ctx(), &[]);
    assert_eq!(
        standing(&a, "$.tools[0].effects"),
        Standing::Unknowable {
            non_establishment: NonEstablishment::N2
        }
    );
}

fn discovered() -> aip_aibom::ports::Discovery {
    parse(
        br#"{"mcpServers": {
            "ledger": {"command": "npx", "env": {"LEDGER_TOKEN": "sk-inline-123"}},
            "shadow-crm": {"url": "https://crm.example/mcp"}
        }}"#,
        "claude_desktop_config.json",
    )
    .unwrap()
}

#[test]
fn a_discovered_tool_is_discovered_and_a_shadow_tool_is_flagged() {
    let mut m = manifest("agent");
    m.tools = vec![
        Tool {
            id: "ledger".into(),
            kind: ToolKind::Mcp,
            actions: vec![],
            endpoint: None,
        },
        Tool {
            id: "retired-tool".into(),
            kind: ToolKind::Mcp,
            actions: vec![],
            endpoint: None,
        },
    ];
    let d = discovered();
    let a = run(
        &m,
        &EvidenceBundle::default(),
        &ctx(),
        std::slice::from_ref(&d),
    );
    assert_eq!(
        standing(&a, "$.tools[0]"),
        Standing::Discovered {
            source: d.source.clone()
        }
    );
    assert_eq!(standing(&a, "$.tools[1]"), Standing::SelfReported);
    assert!(has_finding(&a, |k| *k == FindingKind::DeclaredToolNotFound));
    assert!(has_finding(&a, |k| *k
        == FindingKind::UndeclaredTool {
            server: "shadow-crm".into()
        }));
    assert!(has_finding(
        &a,
        |k| matches!(k, FindingKind::SecretInConfig { server, .. } if server == "ledger")
    ));
    assert!(a.has_critical());
    let rendered = aip_aibom::report::assessment_json(&a) + &aip_aibom::report::assessment_text(&a);
    assert!(!rendered.contains("sk-inline-123"));
}

/// Discovery the assessor did not run cannot be claimed: without one, an MCP
/// tool is the author's word and no "not found" is reported.
#[test]
fn without_a_discovery_run_no_tool_is_discovered_and_none_is_missing() {
    let mut m = manifest("agent");
    m.tools = vec![Tool {
        id: "ledger".into(),
        kind: ToolKind::Mcp,
        actions: vec![],
        endpoint: None,
    }];
    let a = run(&m, &EvidenceBundle::default(), &ctx(), &[]);
    assert_eq!(standing(&a, "$.tools[0]"), Standing::SelfReported);
    assert!(!has_finding(&a, |k| *k == FindingKind::DeclaredToolNotFound));
}

#[test]
fn every_security_control_is_reported_as_unevidenced() {
    let mut m = manifest("agent");
    m.security_controls = vec![
        SecurityControl {
            kind: ControlKind::Sandbox,
            description: "gVisor".into(),
        },
        SecurityControl {
            kind: ControlKind::ApprovalGate,
            description: "payments over $500".into(),
        },
    ];
    let a = run(&m, &EvidenceBundle::default(), &ctx(), &[]);
    assert_eq!(
        a.findings
            .iter()
            .filter(|f| f.kind == FindingKind::ControlNotEvidenced)
            .count(),
        2
    );
}

#[test]
fn a_post_quantum_claim_is_unknowable() {
    let mut m = manifest("agent");
    m.crypto.post_quantum = true;
    let a = run(&m, &EvidenceBundle::default(), &ctx(), &[]);
    assert_eq!(
        standing(&a, "$.crypto.post_quantum"),
        Standing::Unknowable {
            non_establishment: NonEstablishment::N10
        }
    );
}

#[test]
fn the_manifests_own_window_is_enforced() {
    let mut m = manifest("agent");
    m.validity = Validity {
        issued_at_ms: 100,
        valid_until_ms: Some(200),
    };
    let lapsed = run(
        &m,
        &EvidenceBundle::default(),
        &AssessorContext::trusting_nothing(201),
        &[],
    );
    assert!(matches!(
        standing(&lapsed, "$.validity"),
        Standing::Lapsed { .. }
    ));
    assert!(has_finding(&lapsed, |k| *k == FindingKind::ManifestLapsed));
    let early = run(
        &m,
        &EvidenceBundle::default(),
        &AssessorContext::trusting_nothing(99),
        &[],
    );
    assert!(matches!(
        standing(&early, "$.validity"),
        Standing::Lapsed { .. }
    ));

    m.validity.valid_until_ms = None;
    let forever = run(
        &m,
        &EvidenceBundle::default(),
        &AssessorContext::trusting_nothing(150),
        &[],
    );
    assert!(has_finding(&forever, |k| *k == FindingKind::ManifestNeverExpires));
}

fn sealed(m: &Manifest, publisher: &Publisher, anchored: bool) -> aip_aibom::Assessment {
    let seal = publisher.seal(m, 50).unwrap();
    let mut c = ctx();
    if anchored {
        c.publishers
            .insert("platform-team".into(), publisher.public_key().to_vec());
    }
    assess(&Inputs {
        manifest: m,
        seal: Some(&seal),
        bundle: &EvidenceBundle::default(),
        context: &c,
        discoveries: &[],
    })
}

fn publisher() -> Publisher {
    let kp = aip_crypto::generate_ed25519_keypair();
    Publisher::new("platform-team", &kp.private_key, &kp.public_key).unwrap()
}

#[test]
fn a_seal_from_an_anchored_publisher_is_recorded() {
    let m = manifest("agent");
    let a = sealed(&m, &publisher(), true);
    assert_eq!(
        a.seal,
        SealStanding::Published {
            publisher_id: "platform-team".into(),
            sealed_at_ms: 50
        }
    );
    assert!(!has_finding(&a, |k| *k == FindingKind::NotSealed));
}

#[test]
fn a_seal_from_an_unanchored_publisher_is_rejected() {
    let a = sealed(&manifest("agent"), &publisher(), false);
    assert!(matches!(a.seal, SealStanding::Rejected { .. }));
    assert!(a.has_critical());
}

/// **A10.** A seal says who published the inventory. It raises nothing.
#[test]
fn a_seal_never_changes_any_fields_standing() {
    let mut m = manifest("agent");
    m.permissions.allowed = vec![custom("create_payment")];
    m.security_controls = vec![SecurityControl {
        kind: ControlKind::Sandbox,
        description: "gVisor".into(),
    }];
    let with = sealed(&m, &publisher(), true);
    let without = run(&m, &EvidenceBundle::default(), &ctx(), &[]);
    assert_eq!(with.fields, without.fields);
}

/// Only an MCP tool can be discovered from an MCP client config. An API tool
/// that happens to share a server's name is not the server.
///
/// Written for mutation AB-28, which survived the first matrix run.
#[test]
fn an_api_tool_sharing_a_server_name_is_not_discovered() {
    let mut m = manifest("agent");
    m.tools = vec![Tool {
        id: "ledger".into(),
        kind: ToolKind::Api,
        actions: vec![],
        endpoint: None,
    }];
    let d = discovered();
    let a = run(
        &m,
        &EvidenceBundle::default(),
        &ctx(),
        std::slice::from_ref(&d),
    );
    assert_eq!(standing(&a, "$.tools[0]"), Standing::SelfReported);
    assert!(has_finding(&a, |k| *k
        == FindingKind::UndeclaredTool {
            server: "ledger".into()
        }));
}
