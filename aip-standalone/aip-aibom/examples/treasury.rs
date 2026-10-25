//! The treasury agent from the AIBOM brief — the honest version.
//!
//! An agent authorised to read balances and create payments, declared with a
//! $1,000 limit and a $500 approval gate. Every artifact is real: the
//! identity, the CFO's grant, the publisher's seal. The MCP configuration
//! carries an inline credential and a tool the manifest forgot.
//!
//! ```text
//! cargo run -p aip-aibom --example treasury [OUTPUT_DIR]
//! ```
//!
//! Writes `manifest.json`, `seal.json`, `evidence.json`, `context.json` and
//! `mcp.json` to `OUTPUT_DIR` (default `target/aibom-treasury`), prints the
//! assessment, and prints the `aibom assess` command that reproduces it from
//! those files.

use aip_aibom::evidence::{AssessorContext, AuthorityChain, ContextFile, EvidenceBundle};
use aip_aibom::model::*;
use aip_aibom::ports::DiscoverySource;
use aip_aibom::seal::Publisher;
use aip_aibom::{assess, report, Inputs};
use aip_core::capability::issue_scoped_token;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256, sign_ed25519};
use aip_types::{CapabilityScope, ProvenanceTriple, ScopeAction};
use std::collections::BTreeMap;
use std::path::PathBuf;

const ONE_HOUR_MS: u64 = 3_600_000;
const NINETY_DAYS_MS: u64 = 90 * 24 * ONE_HOUR_MS;

fn provenance(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("model-{tag}").as_bytes()),
        environment_commitment: sha256(format!("env-{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("toolchain-{tag}").as_bytes()),
    }
}

fn act(name: &str) -> ScopeAction {
    ScopeAction::Custom(name.into())
}

fn usd(dollars: u64) -> Amount {
    Amount {
        minor_units: dollars * 100,
        currency: "USD".into(),
        exponent: 2,
    }
}

fn write<T: serde::Serialize>(dir: &std::path::Path, name: &str, v: &T) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, serde_json::to_vec_pretty(v).expect("plain data")).expect("write");
    p
}

fn main() {
    let out = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/aibom-treasury"));
    std::fs::create_dir_all(&out).expect("create output directory");

    // ── The agent's identity, activated and re-signed. ──
    let (mut identity, agent_kp) =
        aip_core::create_identity(provenance("treasury-agent"), None).expect("identity");
    aip_core::activate_identity(&mut identity).expect("activate");
    let payload = aip_core::identity_signing_payload(&identity);
    identity.self_signature =
        Some(sign_ed25519(&agent_kp.private_key, &identity.id, &payload).expect("sign"));

    // ── The CFO grants read and pay, and explicitly denies refunds. ──
    let cfo = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo.public_key, &provenance("cfo"));
    let grant = issue_scoped_token(
        &cfo_id,
        &cfo.private_key,
        &identity.id,
        CapabilityScope {
            allowed: vec![act("read_balance"), act("create_payment")],
            denied: vec![act("refund_payment")],
        },
        Some(ONE_HOUR_MS),
    )
    .expect("grant");
    let now = grant.issued_at + 1;

    // ── What the owner declares. ──
    let manifest = Manifest {
        schema_version: AIBOM_SCHEMA_VERSION,
        validity: Validity {
            issued_at_ms: now,
            valid_until_ms: Some(now + NINETY_DAYS_MS),
        },
        agent: AgentIdentity {
            id: identity.id.clone(),
            name: "Treasury Automation Agent".into(),
            owner: "finance-team".into(),
            version: "1.2.0".into(),
            deployment: "production".into(),
        },
        models: vec![Model {
            provider: "example-provider".into(),
            model: "example-model".into(),
            version: Some("2026-10".into()),
            hosting: Hosting::Hosted,
            weight_sha256: None,
        }],
        frameworks: vec![Framework {
            name: "langgraph".into(),
            version: "0.2.0".into(),
        }],
        tools: vec![
            Tool {
                id: "payments-api".into(),
                kind: ToolKind::Api,
                actions: vec!["read_balance".into(), "create_payment".into()],
                endpoint: Some("https://payments.internal".into()),
            },
            Tool {
                id: "ledger".into(),
                kind: ToolKind::Mcp,
                actions: vec!["post_entry".into()],
                endpoint: None,
            },
        ],
        permissions: Permissions {
            allowed: vec![
                act("read_balance"),
                act("create_payment"),
                act("refund_payment"),
            ],
            limits: vec![Limit {
                action: act("create_payment"),
                per: LimitPeriod::PerAction,
                max: usd(1_000),
            }],
            approval_gates: vec![ApprovalGate {
                action: act("create_payment"),
                above: usd(500),
                approver: "cfo".into(),
            }],
        },
        data_access: vec![DataAccess {
            resource: "ledger-db".into(),
            kind: ResourceKind::Database,
            access: Access::ReadWrite,
        }],
        environment: Environment {
            runtime: RuntimeKind::Container,
            network: NetworkPosture::Restricted,
            binary: None,
        },
        relationships: Relationships {
            parent_agent: None,
            delegated_from: vec![cfo_id.clone()],
            delegates_to: vec![],
        },
        security_controls: vec![SecurityControl {
            kind: ControlKind::Sandbox,
            description: "gVisor container sandbox".into(),
        }],
        crypto: CryptoPosture {
            identity_key_algorithm: Some(aip_types::AlgorithmId::Ed25519),
            signing: vec!["ed25519".into()],
            post_quantum: false,
        },
        supply_chain: vec![],
        governance: Governance {
            risk_class: Some("high".into()),
            policies: vec!["treasury-payments-v3".into()],
            audit_owner: Some("internal-audit".into()),
        },
    };
    manifest.validate().expect("the example manifest is valid");

    // ── The platform team seals it: authorship, not truth. ──
    let publisher_kp = generate_ed25519_keypair();
    let publisher = Publisher::new(
        "platform-team",
        &publisher_kp.private_key,
        &publisher_kp.public_key,
    )
    .expect("publisher");
    let seal = publisher.seal(&manifest, now).expect("seal");

    // ── What the deployment can show, and what the assessor trusts. ──
    let bundle = EvidenceBundle {
        identity: Some(identity),
        authority: vec![AuthorityChain {
            root: grant,
            delegations: vec![],
        }],
        ..Default::default()
    };
    let mut issuers = BTreeMap::new();
    issuers.insert(cfo_id, hex::encode(&cfo.public_key));
    let mut publishers = BTreeMap::new();
    publishers.insert(
        "platform-team".to_string(),
        hex::encode(&publisher_kp.public_key),
    );
    let context_file = ContextFile {
        issuers,
        publishers,
        ..Default::default()
    };

    // ── The agent's real MCP configuration. ──
    let mcp = serde_json::json!({
        "mcpServers": {
            "ledger": {
                "command": "npx",
                "args": ["-y", "@acme/ledger-mcp"],
                "env": { "LEDGER_API_KEY": "sk-example-not-a-real-key" }
            },
            "crm-export": { "url": "https://crm.example.com/mcp" }
        }
    });

    let paths = [
        write(&out, "manifest.json", &manifest),
        write(&out, "seal.json", &seal),
        write(&out, "evidence.json", &bundle),
        write(&out, "context.json", &context_file),
        write(&out, "mcp.json", &mcp),
    ];

    let ctx: AssessorContext = context_file.into_context(now).expect("context");
    let discovery = aip_aibom::adapters::mcp_config::McpConfigFile::new(&paths[4])
        .discover()
        .expect("discovery");
    let a = assess(&Inputs {
        manifest: &manifest,
        seal: Some(&seal),
        bundle: &bundle,
        context: &ctx,
        discoveries: std::slice::from_ref(&discovery),
    });
    print!("{}", report::assessment_text(&a));
    println!(
        "\nReproduce:\n  aibom assess --manifest {} --seal {} --evidence {} --context {} --mcp-config {} --now-ms {now}",
        paths[0].display(),
        paths[1].display(),
        paths[2].display(),
        paths[3].display(),
        paths[4].display(),
    );
}
