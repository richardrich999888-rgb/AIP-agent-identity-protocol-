//! Resource authority at the decision point — attacked and used.
//!
//! The institution names its systems in a signed registry; a principal
//! grants an agent named resources inside the same signed, attenuating scope
//! that grants actions. The decision point resolves every network
//! destination against the registry and refuses anything unnamed or
//! ungranted. Each test below is either an agent reaching for a system it
//! was not given, or the honest path.

use aip_authorize::{
    net_connect_action, net_connect_parameters, process_exec_action, process_exec_parameters,
    AuthorizationRequest, Decision, DecisionPoint, DenialReason, NetProtocol, ResourcePolicy,
};
use aip_core::capability::issue_scoped_token;
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_registry::{
    resource_scope_action, AddressRange, Criticality, PortRange, Protocol, RegistryError,
    RegistryTrustAnchors, ResourceEntry, ResourceRegistry,
};
use aip_types::{
    CapabilityScope, ExecutionBinding, ProcessInstance, ProvenanceTriple, ScopeAction,
    EXECUTION_BINDING_VERSION,
};

const CORE: [u8; 4] = [10, 0, 5, 20];
const CORE_PORT: u16 = 8443;
const SWITCH: [u8; 4] = [10, 0, 9, 3];
const SWITCH_PORT: u16 = 9001;
const UNNAMED: [u8; 4] = [10, 0, 77, 7];

fn provenance(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("model:{tag}").as_bytes()),
        environment_commitment: sha256(format!("env:{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("tool:{tag}").as_bytes()),
    }
}

fn binding(agent_id: &str) -> ExecutionBinding {
    ExecutionBinding {
        version: EXECUTION_BINDING_VERSION,
        agent_id: agent_id.to_string(),
        process: ProcessInstance {
            pid: 4242,
            pid_start_time_ticks: 910_000,
            boot_id: [0x3c; 16],
        },
        exe_content_sha256: sha256(b"resource-test agent binary"),
        exe_path: "/opt/agent/bin/agent".into(),
        bound_at_ms: 1_700_000_000_000,
        container: None,
    }
}

fn entry(id: &str, addr: [u8; 4], port: u16, crit: Criticality) -> ResourceEntry {
    ResourceEntry {
        id: id.into(),
        display_name: id.replace('-', " "),
        criticality: crit,
        protocol: Protocol::Tcp,
        addresses: vec![AddressRange::v4_host(addr)],
        ports: vec![PortRange::single(port)],
    }
}

/// The institution's registry: two named systems, signed under its key.
fn registry() -> (ResourceRegistry, RegistryTrustAnchors) {
    let kp = generate_ed25519_keypair();
    let reg = ResourceRegistry::sign(
        "bank/dc1",
        "bank.example",
        &kp.private_key,
        3,
        1_690_000_000_000,
        vec![
            entry(
                "core-banking-api",
                CORE,
                CORE_PORT,
                Criticality::TransactionCritical,
            ),
            entry(
                "payments-switch",
                SWITCH,
                SWITCH_PORT,
                Criticality::TransactionCritical,
            ),
        ],
    )
    .unwrap();
    let anchors = RegistryTrustAnchors::new().trust("bank.example", &kp.public_key);
    (reg, anchors)
}

struct World {
    dp: DecisionPoint,
    agent_id: String,
    root: aip_types::ScopedToken,
    chain: Vec<aip_types::DelegationToken>,
    now: u64,
}

/// CFO → orchestrator → agent, with the given root and hop scopes; the
/// decision point trusts both issuers and (optionally) adopts the registry.
fn world(root_scope: CapabilityScope, hop_scope: CapabilityScope, with_policy: bool) -> World {
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo_kp.public_key, &provenance("cfo"));
    let (orch_aid, orch_kp) = create_identity(provenance("orchestrator"), None).unwrap();
    let (agent_aid, _agent_kp) = create_identity(provenance("loan-agent"), None).unwrap();
    let root = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &orch_aid.id,
        root_scope,
        Some(3_600_000),
    )
    .unwrap();
    let hop = create_delegation(&root, &orch_kp.private_key, &agent_aid.id, hop_scope).unwrap();
    let now = root.issued_at.max(hop.issued_at) + 1;
    let dp_kp = generate_ed25519_keypair();
    let dp_id = derive_aip_id(&dp_kp.public_key, &provenance("decision-point"));
    let mut dp = DecisionPoint::new(&dp_id, &dp_kp.private_key, &dp_kp.public_key, 3_600_000)
        .unwrap()
        .trust_issuer(&cfo_id, &cfo_kp.public_key)
        .trust_issuer(&orch_aid.id, &orch_kp.public_key);
    if with_policy {
        let (reg, anchors) = registry();
        dp = dp.with_resource_policy(ResourcePolicy::new(reg, &anchors).unwrap());
    }
    World {
        dp,
        agent_id: agent_aid.id,
        root,
        chain: vec![hop],
        now,
    }
}

fn scope(actions: &[ScopeAction], denied: &[ScopeAction]) -> CapabilityScope {
    CapabilityScope {
        allowed: actions.to_vec(),
        denied: denied.to_vec(),
    }
}

fn connect(w: &World, remote: [u8; 4], port: u16) -> Decision {
    let req = AuthorizationRequest {
        agent_id: w.agent_id.clone(),
        root_token: w.root.clone(),
        delegation_chain: w.chain.clone(),
        action_kind: net_connect_action(),
        parameters: net_connect_parameters(NetProtocol::Tcp, &remote, port).unwrap(),
        execution_binding: binding(&w.agent_id),
        requested_ttl_ms: 60_000,
    };
    w.dp.authorize_at(&req, w.now)
}

fn reason(d: &Decision) -> Option<DenialReason> {
    d.denial().map(|x| x.reason)
}

// ─── The honest path ───

#[test]
fn a_granted_resource_is_authorized_and_the_expectation_binds_the_endpoint() {
    let s = scope(
        &[
            net_connect_action(),
            resource_scope_action("core-banking-api"),
        ],
        &[],
    );
    let w = world(s.clone(), s, true);
    assert!(w.dp.resource_policy().is_some());
    let d = connect(&w, CORE, CORE_PORT);
    let ee = d.expected().unwrap_or_else(|| panic!("{:?}", d.denial()));
    assert_eq!(ee.agent_id, w.agent_id);
    // The parameter digest is exactly the connect vocabulary's: the resolved
    // name is not smuggled into the expectation.
    assert_eq!(
        ee.parameter_digest,
        net_connect_parameters(NetProtocol::Tcp, &CORE, CORE_PORT)
            .unwrap()
            .digest()
    );
}

#[test]
fn a_non_network_action_is_not_resource_checked() {
    let s = scope(&[process_exec_action()], &[]);
    let w = world(s.clone(), s, true);
    let req = AuthorizationRequest {
        agent_id: w.agent_id.clone(),
        root_token: w.root.clone(),
        delegation_chain: w.chain.clone(),
        action_kind: process_exec_action(),
        parameters: process_exec_parameters([7u8; 32]),
        execution_binding: binding(&w.agent_id),
        requested_ttl_ms: 60_000,
    };
    assert!(w.dp.authorize_at(&req, w.now).expected().is_some());
}

// ─── Reaching for systems the agent was not given ───

#[test]
fn a_named_resource_the_chain_never_granted_is_refused() {
    let s = scope(
        &[
            net_connect_action(),
            resource_scope_action("core-banking-api"),
        ],
        &[],
    );
    let w = world(s.clone(), s, true);
    let d = connect(&w, SWITCH, SWITCH_PORT);
    assert_eq!(reason(&d), Some(DenialReason::ResourceNotGranted));
    assert!(d.denial().unwrap().detail.contains("payments-switch"));
}

#[test]
fn an_address_the_institution_never_named_is_refused_outright() {
    let s = scope(
        &[
            net_connect_action(),
            resource_scope_action("core-banking-api"),
            resource_scope_action("payments-switch"),
        ],
        &[],
    );
    let w = world(s.clone(), s, true);
    let d = connect(&w, UNNAMED, 443);
    assert_eq!(reason(&d), Some(DenialReason::DestinationUnregistered));
    assert!(d.denial().unwrap().detail.contains("bank/dc1"));
}

#[test]
fn the_right_host_on_an_unnamed_port_is_still_unregistered() {
    let s = scope(
        &[
            net_connect_action(),
            resource_scope_action("core-banking-api"),
        ],
        &[],
    );
    let w = world(s.clone(), s, true);
    let d = connect(&w, CORE, 22);
    assert_eq!(reason(&d), Some(DenialReason::DestinationUnregistered));
}

#[test]
fn a_hop_cannot_add_a_resource_its_parent_did_not_hold() {
    let root = scope(
        &[
            net_connect_action(),
            resource_scope_action("core-banking-api"),
        ],
        &[],
    );
    let hop = scope(
        &[
            net_connect_action(),
            resource_scope_action("core-banking-api"),
            resource_scope_action("payments-switch"),
        ],
        &[],
    );
    // Delegation refuses to *create* the widened hop: attenuation is
    // enforced at issuance, before any decision point sees it.
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo_kp.public_key, &provenance("cfo"));
    let (orch_aid, orch_kp) = create_identity(provenance("orchestrator"), None).unwrap();
    let (agent_aid, _) = create_identity(provenance("agent"), None).unwrap();
    let root_tok = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &orch_aid.id,
        root,
        Some(3_600_000),
    )
    .unwrap();
    assert!(
        create_delegation(&root_tok, &orch_kp.private_key, &agent_aid.id, hop).is_err(),
        "a resource grant is a scope entry; a child may not hold one its parent lacks"
    );
}

#[test]
fn a_deny_anywhere_in_the_chain_withholds_the_resource() {
    let root = scope(
        &[
            net_connect_action(),
            resource_scope_action("core-banking-api"),
            resource_scope_action("payments-switch"),
        ],
        &[],
    );
    // The orchestrator passes both grants down but explicitly denies the
    // payments switch to this agent.
    let hop = scope(
        &[
            net_connect_action(),
            resource_scope_action("core-banking-api"),
            resource_scope_action("payments-switch"),
        ],
        &[resource_scope_action("payments-switch")],
    );
    let w = world(root, hop, true);
    assert!(connect(&w, CORE, CORE_PORT).expected().is_some());
    assert_eq!(
        reason(&connect(&w, SWITCH, SWITCH_PORT)),
        Some(DenialReason::ResourceNotGranted)
    );
}

#[test]
fn an_action_grant_alone_grants_no_resource_once_a_policy_is_configured() {
    // A scope that permits connecting but names no resource: under a policy,
    // every registered destination is ungranted. Fail closed.
    let s = scope(&[net_connect_action()], &[]);
    let w = world(s.clone(), s, true);
    assert_eq!(
        reason(&connect(&w, CORE, CORE_PORT)),
        Some(DenialReason::ResourceNotGranted)
    );
}

// ─── The policy boundary itself ───

#[test]
fn without_a_policy_no_resource_check_is_performed_and_the_decision_point_says_so() {
    let s = scope(&[net_connect_action()], &[]);
    let w = world(s.clone(), s, false);
    assert!(w.dp.resource_policy().is_none());
    assert!(connect(&w, UNNAMED, 443).expected().is_some());
    assert!(format!("{:?}", w.dp).contains("resource_policy: None"));
}

#[test]
fn a_registry_nobody_the_decision_point_trusts_signed_cannot_become_policy() {
    let (reg, _) = registry();
    let impostor = generate_ed25519_keypair();
    let wrong = RegistryTrustAnchors::new().trust("bank.example", &impostor.public_key);
    assert_eq!(
        ResourcePolicy::new(reg.clone(), &wrong).err(),
        Some(RegistryError::SignatureInvalid)
    );
    let nobody = RegistryTrustAnchors::new();
    assert!(matches!(
        ResourcePolicy::new(reg, &nobody),
        Err(RegistryError::UntrustedIssuer(_))
    ));
}

#[test]
fn a_registry_edited_after_signing_cannot_become_policy() {
    let (mut reg, anchors) = registry();
    let i = reg
        .entries
        .iter()
        .position(|e| e.id == "payments-switch")
        .unwrap();
    // Re-point the payments switch at the core banking host: an attacker who
    // could do this would make a grant for one system reach another.
    reg.entries[i].addresses = vec![AddressRange::v4_host([10, 0, 5, 99])];
    assert_eq!(
        ResourcePolicy::new(reg, &anchors).err(),
        Some(RegistryError::PayloadHashMismatch)
    );
}
