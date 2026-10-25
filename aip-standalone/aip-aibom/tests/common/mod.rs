//! Shared fixtures. Every artifact is real: keys are generated, identities
//! come from `create_identity`, tokens from `issue_scoped_token`,
//! expectations from a `DecisionPoint`, batches from a `CollectorSigner`.

#![allow(dead_code)]

pub mod evidence;
pub mod spend;
pub mod staging;

use aip_aibom::evidence::{AssessorContext, AuthorityChain, EvidenceBundle};
use aip_aibom::model::*;
use aip_aibom::ports::Discovery;
use aip_aibom::{assess, Assessment, Inputs, Standing};
use aip_core::capability::issue_scoped_token;
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256, sign_ed25519};
use aip_types::{
    AgentIdentityDocument, CapabilityScope, KeyPair, ProvenanceTriple, ScopeAction, ScopedToken,
};

pub const HOUR_MS: u64 = 3_600_000;

pub fn provenance(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("model-{tag}").as_bytes()),
        environment_commitment: sha256(format!("env-{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("toolchain-{tag}").as_bytes()),
    }
}

pub fn custom(s: &str) -> ScopeAction {
    ScopeAction::Custom(s.into())
}

/// An identity document in the `Active` state, re-signed after activation —
/// `activate_identity` changes the signed status and does not re-sign.
pub fn active_identity(tag: &str) -> (AgentIdentityDocument, KeyPair) {
    let (mut doc, kp) = aip_core::create_identity(provenance(tag), None).unwrap();
    aip_core::activate_identity(&mut doc).unwrap();
    resign(&mut doc, &kp);
    (doc, kp)
}

pub fn resign(doc: &mut AgentIdentityDocument, kp: &KeyPair) {
    let payload = aip_core::identity_signing_payload(doc);
    doc.self_signature = Some(sign_ed25519(&kp.private_key, &doc.id, &payload).unwrap());
}

/// An issuing principal: an AIP-ID and its key.
pub struct Principal {
    pub id: String,
    pub kp: KeyPair,
}

pub fn principal(tag: &str) -> Principal {
    let kp = generate_ed25519_keypair();
    Principal {
        id: derive_aip_id(&kp.public_key, &provenance(tag)),
        kp,
    }
}

pub fn scope(allowed: &[&str], denied: &[&str]) -> CapabilityScope {
    CapabilityScope {
        allowed: allowed.iter().map(|a| custom(a)).collect(),
        denied: denied.iter().map(|a| custom(a)).collect(),
    }
}

pub fn grant(issuer: &Principal, to: &str, s: CapabilityScope, ttl: Option<u64>) -> ScopedToken {
    issue_scoped_token(&issuer.id, &issuer.kp.private_key, to, s, ttl).unwrap()
}

/// A root grant to `middle`, then a hop from `middle` to `leaf`.
pub fn two_hop(
    root: &Principal,
    middle: &Principal,
    leaf: &str,
    s: CapabilityScope,
) -> AuthorityChain {
    let r = grant(root, &middle.id, s.clone(), Some(HOUR_MS));
    let hop = create_delegation(&r, &middle.kp.private_key, leaf, s).unwrap();
    AuthorityChain {
        root: r,
        delegations: vec![hop],
    }
}

pub fn chain(token: ScopedToken) -> AuthorityChain {
    AuthorityChain {
        root: token,
        delegations: vec![],
    }
}

/// The smallest valid manifest, for `agent_id`.
pub fn manifest(agent_id: &str) -> Manifest {
    Manifest {
        schema_version: AIBOM_SCHEMA_VERSION,
        validity: Validity {
            issued_at_ms: 1,
            valid_until_ms: Some(u64::MAX - 1),
        },
        agent: AgentIdentity {
            id: agent_id.into(),
            name: "Treasury Automation Agent".into(),
            owner: "finance-team".into(),
            version: "1.2.0".into(),
            deployment: "production".into(),
        },
        models: vec![],
        frameworks: vec![],
        tools: vec![],
        permissions: Permissions::default(),
        data_access: vec![],
        environment: Environment {
            runtime: RuntimeKind::Container,
            network: NetworkPosture::Restricted,
            binary: None,
        },
        relationships: Relationships::default(),
        security_controls: vec![],
        crypto: CryptoPosture::default(),
        supply_chain: vec![],
        governance: Governance::default(),
    }
}

pub fn usd(dollars: u64) -> Amount {
    Amount {
        minor_units: dollars * 100,
        currency: "USD".into(),
        exponent: 2,
    }
}

pub fn run(
    m: &Manifest,
    bundle: &EvidenceBundle,
    ctx: &AssessorContext,
    discoveries: &[Discovery],
) -> Assessment {
    m.validate().expect("fixture manifests are valid");
    assess(&Inputs {
        manifest: m,
        seal: None,
        bundle,
        context: ctx,
        discoveries,
    })
}

pub fn standing(a: &Assessment, path: &str) -> Standing {
    a.standing_of(path)
        .unwrap_or_else(|| {
            panic!(
                "no field {path}; fields: {:?}",
                a.fields.iter().map(|f| &f.path).collect::<Vec<_>>()
            )
        })
        .clone()
}

pub fn has_finding(
    a: &Assessment,
    pred: impl Fn(&aip_aibom::finding::FindingKind) -> bool,
) -> bool {
    a.findings.iter().any(|f| pred(&f.kind))
}
