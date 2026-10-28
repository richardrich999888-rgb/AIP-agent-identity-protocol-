//! Canonical encoding (A9): domain-separated, injective, order-independent
//! over sets, and sensitive to every field.

mod common;

use aip_aibom::canonical::{manifest_bytes, manifest_digest, manifest_digest_hex, MANIFEST_DOMAIN};
use aip_aibom::model::*;
use common::*;

fn rich() -> Manifest {
    let mut m = manifest("agent-payment-001");
    m.models = vec![
        Model {
            provider: "p".into(),
            model: "a".into(),
            version: None,
            hosting: Hosting::Hosted,
            weight_sha256: None,
        },
        Model {
            provider: "p".into(),
            model: "b".into(),
            version: Some("1".into()),
            hosting: Hosting::Local,
            weight_sha256: Some("0".repeat(64)),
        },
    ];
    m.tools = vec![
        Tool {
            id: "payments-api".into(),
            kind: ToolKind::Api,
            actions: vec!["read_balance".into(), "create_payment".into()],
            endpoint: None,
        },
        Tool {
            id: "ledger".into(),
            kind: ToolKind::Mcp,
            actions: vec![],
            endpoint: Some("https://ledger".into()),
        },
    ];
    m.permissions.allowed = vec![custom("read_balance"), custom("create_payment")];
    m.permissions.limits = vec![Limit {
        action: custom("create_payment"),
        per: LimitPeriod::PerAction,
        max: usd(1000),
    }];
    m.permissions.approval_gates = vec![ApprovalGate {
        action: custom("create_payment"),
        above: usd(500),
        approver: "cfo".into(),
    }];
    m.security_controls = vec![SecurityControl {
        kind: ControlKind::Sandbox,
        description: "gVisor".into(),
    }];
    m
}

#[test]
fn the_encoding_is_domain_separated() {
    let b = manifest_bytes(&rich());
    let tag = MANIFEST_DOMAIN.as_bytes();
    assert!(b.windows(tag.len()).any(|w| w == tag));
    assert_eq!(manifest_digest_hex(&rich()).len(), 64);
}

/// Reordering a set is not a change to the manifest.
#[test]
fn sets_are_order_independent() {
    let a = rich();
    let mut b = rich();
    b.models.reverse();
    b.tools.reverse();
    b.tools[0].actions.reverse();
    b.tools[1].actions.reverse();
    b.permissions.allowed.reverse();
    assert_eq!(manifest_digest(&a), manifest_digest(&b));
}

/// `["ab", "c"]` and `["a", "bc"]` are different manifests.
#[test]
fn the_encoding_is_injective_across_boundaries() {
    let mut a = rich();
    a.tools[0].actions = vec!["ab".into(), "c".into()];
    let mut b = rich();
    b.tools[0].actions = vec!["a".into(), "bc".into()];
    assert_ne!(manifest_digest(&a), manifest_digest(&b));

    let mut a = rich();
    a.agent.name = "ab".into();
    a.agent.owner = "c".into();
    let mut b = rich();
    b.agent.name = "a".into();
    b.agent.owner = "bc".into();
    assert_ne!(manifest_digest(&a), manifest_digest(&b));

    let mut a = rich();
    a.models[0].version = None;
    let mut b = rich();
    b.models[0].version = Some(String::new());
    assert_ne!(manifest_digest(&a), manifest_digest(&b));
}

/// Every field is inside the digest. A field left out is one a seal does not
/// protect, so each mutation here must change it.
#[test]
fn every_field_is_covered_by_the_digest() {
    type Edit = fn(&mut Manifest);
    let edits: Vec<(&str, Edit)> = vec![
        ("schema_version", |m| m.schema_version = 9),
        ("validity.issued_at", |m| m.validity.issued_at_ms = 2),
        ("validity.until", |m| m.validity.valid_until_ms = None),
        ("agent.id", |m| m.agent.id = "other".into()),
        ("agent.name", |m| m.agent.name = "x".into()),
        ("agent.owner", |m| m.agent.owner = "x".into()),
        ("agent.version", |m| m.agent.version = "x".into()),
        ("agent.deployment", |m| m.agent.deployment = "x".into()),
        ("model.provider", |m| m.models[0].provider = "q".into()),
        ("model.hosting", |m| m.models[0].hosting = Hosting::Local),
        ("model.weights", |m| {
            m.models[1].weight_sha256 = Some("1".repeat(64))
        }),
        ("framework", |m| {
            m.frameworks.push(Framework {
                name: "langgraph".into(),
                version: "1".into(),
            })
        }),
        ("tool.kind", |m| m.tools[0].kind = ToolKind::Function),
        ("tool.endpoint", |m| m.tools[0].endpoint = Some("e".into())),
        ("tool.actions", |m| m.tools[0].actions.push("refund".into())),
        ("allowed", |m| {
            m.permissions.allowed.push(custom("refund_payment"))
        }),
        ("limit.amount", |m| {
            m.permissions.limits[0].max.minor_units += 1
        }),
        ("limit.currency", |m| {
            m.permissions.limits[0].max.currency = "EUR".into()
        }),
        ("limit.exponent", |m| {
            m.permissions.limits[0].max.exponent = 3
        }),
        ("limit.period", |m| {
            m.permissions.limits[0].per = LimitPeriod::PerDay
        }),
        ("gate.amount", |m| {
            m.permissions.approval_gates[0].above.minor_units += 1
        }),
        ("gate.approver", |m| {
            m.permissions.approval_gates[0].approver = "ceo".into()
        }),
        ("data", |m| {
            m.data_access.push(DataAccess {
                resource: "db".into(),
                kind: ResourceKind::Database,
                access: Access::Read,
            })
        }),
        ("env.runtime", |m| m.environment.runtime = RuntimeKind::Vm),
        ("env.network", |m| {
            m.environment.network = NetworkPosture::Open
        }),
        ("env.binary", |m| {
            m.environment.binary = Some(Binary {
                exe_sha256: "2".repeat(64),
                exe_path: None,
            })
        }),
        ("rel.parent", |m| {
            m.relationships.parent_agent = Some("p".into())
        }),
        ("rel.from", |m| {
            m.relationships.delegated_from.push("cfo".into())
        }),
        ("rel.to", |m| {
            m.relationships.delegates_to.push("sub".into())
        }),
        ("control", |m| {
            m.security_controls[0].kind = ControlKind::RateLimit
        }),
        ("crypto.alg", |m| {
            m.crypto.identity_key_algorithm = Some(aip_types::AlgorithmId::Ed25519)
        }),
        ("crypto.signing", |m| {
            m.crypto.signing.push("ed25519".into())
        }),
        ("crypto.pq", |m| m.crypto.post_quantum = true),
        ("supply", |m| {
            m.supply_chain.push(SupplyComponent {
                component: "c".into(),
                version: "1".into(),
                sha256: None,
                origin: None,
            })
        }),
        ("gov.risk", |m| {
            m.governance.risk_class = Some("high".into())
        }),
        ("gov.policies", |m| m.governance.policies.push("p".into())),
        ("gov.owner", |m| m.governance.audit_owner = Some("o".into())),
    ];
    let base = manifest_digest(&rich());
    for (name, edit) in edits {
        let mut m = rich();
        edit(&mut m);
        assert_ne!(
            manifest_digest(&m),
            base,
            "{name} is not covered by the digest"
        );
    }
}

#[test]
fn the_digest_is_stable_across_calls() {
    assert_eq!(manifest_bytes(&rich()), manifest_bytes(&rich()));
}
