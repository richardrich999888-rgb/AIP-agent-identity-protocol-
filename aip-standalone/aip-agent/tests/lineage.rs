//! Phase C — parent / child lineage on the profile, RED.
//!
//! Three kinds of lineage, never merged:
//!
//! - **identity**: a parent identity signed `(child_id, child_key)` at the
//!   child's creation (the AID lineage proof), rebuilt across generations
//!   from proofs against each ancestor's own validated document;
//! - **authority**: the issuer → grantee path of every verified token chain
//!   that reaches this agent;
//! - **process**: kernel fork/exec edges between bound instances, with the
//!   *agent* at each end a separate fact established only through a
//!   decision-point-signed expectation whose binding matches structurally.
//!
//! A reconciled lineage verdict does not exist yet (Phase C2, after the
//! delegation graph); the type says so and has no violation variant.

use std::collections::BTreeSet;

use aip_agent::*;
use aip_authorize::{
    ActionParameters, AuthorizationRequest, DecisionPoint, DecisionPointTrustAnchors,
    ExpectedExecution,
};
use aip_core::capability::{issue_scoped_token, scope_orchestrator, scope_submitter};
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_observe::{ObservedProcess, SourceMechanism};
use aip_reconcile::{EventPosition, LineageEdge};
use aip_types::{
    Action, AgentIdentityDocument, ExecutionBinding, ProcessInstance, ProvenanceTriple,
    ScopeAction, EXECUTION_BINDING_VERSION,
};

// ─── fixtures ───

fn provenance(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("model-{tag}").as_bytes()),
        environment_commitment: sha256(format!("env-{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("toolchain-{tag}").as_bytes()),
    }
}

fn binding_for(agent_id: &str, pid: u32, image: &[u8]) -> ExecutionBinding {
    ExecutionBinding {
        version: EXECUTION_BINDING_VERSION,
        agent_id: agent_id.to_string(),
        process: ProcessInstance {
            pid,
            pid_start_time_ticks: 700_000 + u64::from(pid),
            boot_id: [0x0c; 16],
        },
        exe_content_sha256: sha256(image),
        exe_path: "/opt/agent/bin/image".into(),
        bound_at_ms: 1_700_000_000_000,
    }
}

fn process_of(b: &ExecutionBinding) -> ObservedProcess {
    ObservedProcess {
        process: b.process,
        exe_content_sha256: b.exe_content_sha256,
        exe_path: b.exe_path.clone(),
    }
}

fn edge(parent: &ExecutionBinding, child: &ExecutionBinding) -> LineageEdge {
    LineageEdge {
        parent: process_of(parent),
        child: process_of(child),
        fork: EventPosition {
            batch_sequence: 2,
            index: 0,
            kernel_timestamp_ns: 5_000_000_000,
        },
        exec: EventPosition {
            batch_sequence: 2,
            index: 1,
            kernel_timestamp_ns: 5_003_000_000,
        },
        image_sha256: child.exe_content_sha256,
        filename: child.exe_path.clone(),
        mechanism: SourceMechanism::SchedTracepoint,
        batch_sequence: 2,
    }
}

const TTL: u64 = 60_000;
const MAX_TTL: u64 = 3_600_000;

/// Two agents: `orch` (delegates to `agent`) and `agent`. The decision point
/// trusts the CFO root and `orch` as issuers.
struct Fx {
    agent_aid: AgentIdentityDocument,
    orch_aid: AgentIdentityDocument,
    cfo_id: String,
    chain: AuthorityChain,
    issuer_keys: IssuerKeys,
    dp: DecisionPoint,
    dp_anchors: DecisionPointTrustAnchors,
    now: u64,
}

fn fixture() -> Fx {
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo_kp.public_key, &provenance("cfo"));
    let (orch_aid, orch_kp) = create_identity(provenance("orchestrator"), None).unwrap();
    let (agent_aid, _agent_kp) = create_identity(provenance("worker"), None).unwrap();

    let root = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &orch_aid.id,
        scope_orchestrator(),
        Some(3_600_000),
    )
    .unwrap();
    let hop = create_delegation(
        &root,
        &orch_kp.private_key,
        &agent_aid.id,
        scope_submitter(),
    )
    .unwrap();
    let now = root.issued_at.max(hop.issued_at) + 1;

    let dp_kp = generate_ed25519_keypair();
    let dp_id = derive_aip_id(&dp_kp.public_key, &provenance("decision-point"));
    let dp = DecisionPoint::new(&dp_id, &dp_kp.private_key, &dp_kp.public_key, MAX_TTL)
        .unwrap()
        .trust_issuer(&cfo_id, &cfo_kp.public_key)
        .trust_issuer(&orch_aid.id, &orch_kp.public_key);
    let dp_anchors = DecisionPointTrustAnchors::new().trust(&dp_id, &dp_kp.public_key);
    let issuer_keys = IssuerKeys::new()
        .trust(&cfo_id, &cfo_kp.public_key)
        .trust(&orch_aid.id, &orch_kp.public_key);

    Fx {
        agent_aid,
        orch_aid,
        cfo_id,
        chain: AuthorityChain {
            root,
            chain: vec![hop],
        },
        issuer_keys,
        dp,
        dp_anchors,
        now,
    }
}

impl Fx {
    /// A decision-point-signed expectation for `agent_id` with `binding`.
    /// The worker uses the delegated chain; the orchestrator uses the root
    /// token directly.
    fn expectation(&self, agent_id: &str, binding: ExecutionBinding) -> ExpectedExecution {
        let (root, chain, action) = if agent_id == self.agent_aid.id {
            (
                self.chain.root.clone(),
                self.chain.chain.clone(),
                ScopeAction::Standard(Action::Write),
            )
        } else {
            (
                self.chain.root.clone(),
                vec![],
                ScopeAction::Standard(Action::Delegate),
            )
        };
        let req = AuthorizationRequest {
            agent_id: agent_id.to_string(),
            root_token: root,
            delegation_chain: chain,
            action_kind: action,
            parameters: ActionParameters::empty(),
            execution_binding: binding,
            requested_ttl_ms: TTL,
        };
        self.dp
            .authorize_at(&req, self.now)
            .expected()
            .expect("fixture authorizes")
            .clone()
    }

    fn inputs<'a>(
        &'a self,
        identity: &'a AgentIdentityDocument,
        expectations: &'a [ExpectedExecution],
        peer_expectations: &'a [ExpectedExecution],
        process_edges: &'a [LineageEdge],
        ancestor_documents: &'a [AgentIdentityDocument],
    ) -> ProfileInputs<'a> {
        ProfileInputs {
            identity: IdentityInput::Document {
                document: identity,
                parent: None,
            },
            self_declared: &[],
            authority: std::slice::from_ref(&self.chain),
            issuer_keys: &self.issuer_keys,
            expectations,
            decision_point_anchors: &self.dp_anchors,
            claimed_bindings: &[],
            reconciliations: &[],
            peer_expectations,
            process_edges,
            ancestor_documents,
            as_of_ms: self.now + 10,
        }
    }
}

fn keys_recursive(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(m) => {
            for (k, v) in m {
                out.push(k.clone());
                keys_recursive(v, out);
            }
        }
        serde_json::Value::Array(a) => a.iter().for_each(|v| keys_recursive(v, out)),
        _ => {}
    }
}

// ─── identity lineage ───

/// l01 — a root identity has no identity parent and no ancestors.
#[test]
fn l01_root_identity_has_no_identity_parent() {
    let fx = fixture();
    let p = build_profile(&fx.inputs(&fx.agent_aid, &[], &[], &[], &[])).unwrap();
    assert_eq!(p.lineage.identity.parent, IdentityParent::None);
    assert!(p.lineage.identity.ancestors.is_empty());
    assert_eq!(p.lineage.identity.generations, 0);
}

/// l02 — a lineage proof names a parent; that is a *claim* until the
/// parent's own validated document is in hand, at which point the proof is
/// verified against the parent's key and the link is *endorsed*. Ancestry
/// continues generation by generation from proofs, never from the
/// document's `lineage_depth` field (which is 1 for every parented identity).
#[test]
fn l02_identity_ancestry_is_rebuilt_from_proofs_not_depth() {
    let fx = fixture();
    let (root, root_kp) = create_identity(provenance("root"), None).unwrap();
    let (mid, mid_kp) =
        create_identity(provenance("mid"), Some((&root.id, &root_kp.private_key))).unwrap();
    let (leaf, _) =
        create_identity(provenance("leaf"), Some((&mid.id, &mid_kp.private_key))).unwrap();
    assert_eq!(leaf.lineage_depth, 1, "the field does not chain (c02)");

    // No ancestor documents: the parent is named by the proof, unverified.
    let p = build_profile(&fx.inputs(&leaf, &[], &[], &[], &[])).unwrap();
    assert_eq!(
        p.lineage.identity.parent,
        IdentityParent::Claimed {
            parent_id: mid.id.clone()
        }
    );
    assert!(p.lineage.identity.ancestors.is_empty());
    assert_eq!(p.lineage.identity.generations, 0);

    // Both ancestors supplied: two endorsed links, generations from proofs.
    let docs = [mid.clone(), root.clone()];
    let p = build_profile(&fx.inputs(&leaf, &[], &[], &[], &docs)).unwrap();
    assert_eq!(
        p.lineage.identity.parent,
        IdentityParent::Endorsed {
            parent_id: mid.id.clone()
        }
    );
    assert_eq!(p.lineage.identity.ancestors.len(), 2);
    assert_eq!(p.lineage.identity.ancestors[0].id, mid.id);
    assert_eq!(p.lineage.identity.ancestors[0].link, AncestorLink::Endorsed);
    assert_eq!(p.lineage.identity.ancestors[1].id, root.id);
    assert_eq!(p.lineage.identity.ancestors[1].link, AncestorLink::Endorsed);
    assert_eq!(p.lineage.identity.generations, 2);

    // Only the grandparent supplied: the chain stops at the first missing
    // document — the parent stays claimed and the grandparent is not reached.
    let docs = [root.clone()];
    let p = build_profile(&fx.inputs(&leaf, &[], &[], &[], &docs)).unwrap();
    assert_eq!(
        p.lineage.identity.parent,
        IdentityParent::Claimed {
            parent_id: mid.id.clone()
        }
    );
    assert!(p.lineage.identity.ancestors.is_empty());
}

/// l03 — an ancestor document that does not validate contributes nothing
/// and is recorded as excluded; a document for an unrelated identity is
/// simply not an ancestor. A proof that fails against the named parent's
/// real key is a refused link, never a downgraded one.
#[test]
fn l03_invalid_or_unrelated_ancestor_documents_never_endorse() {
    let fx = fixture();
    let (root, root_kp) = create_identity(provenance("root"), None).unwrap();
    let (leaf, _) =
        create_identity(provenance("leaf"), Some((&root.id, &root_kp.private_key))).unwrap();

    // Mutated parent document (lifecycle flipped after signing).
    let mut bad_root = root.clone();
    aip_core::activate_identity(&mut bad_root).unwrap();
    let docs = [bad_root, fx.orch_aid.clone()];
    let p = build_profile(&fx.inputs(&leaf, &[], &[], &[], &docs)).unwrap();
    assert_eq!(
        p.lineage.identity.parent,
        IdentityParent::Claimed {
            parent_id: root.id.clone()
        }
    );
    assert!(p.lineage.identity.ancestors.is_empty());
    assert_eq!(p.lineage.identity.excluded_documents.len(), 1);
    assert_eq!(p.lineage.identity.excluded_documents[0].id, root.id);

    // A proof forged under another key but naming the real parent id: the
    // parent's genuine document is present, the proof does not verify
    // against it, and the link is refused with the reason.
    let (imposter, imposter_kp) = create_identity(provenance("imposter"), None).unwrap();
    let (forged, _) = create_identity(
        provenance("forged"),
        Some((&root.id, &imposter_kp.private_key)),
    )
    .unwrap();
    let _ = imposter;
    let docs = [root.clone()];
    let p = build_profile(&fx.inputs(&forged, &[], &[], &[], &docs)).unwrap();
    assert_eq!(
        p.lineage.identity.parent,
        IdentityParent::Refused {
            parent_id: root.id.clone()
        }
    );
    assert!(p.lineage.identity.ancestors.is_empty());
}

// ─── authority lineage ───

/// l04 — every verified chain yields one authority path, root issuer first,
/// each hop as issuer → grantee with its token id; standing is carried.
/// An excluded chain yields no path.
#[test]
fn l04_authority_paths_come_from_verified_chains_only() {
    let fx = fixture();
    let p = build_profile(&fx.inputs(&fx.agent_aid, &[], &[], &[], &[])).unwrap();
    assert_eq!(p.lineage.authority.len(), 1);
    let path = &p.lineage.authority[0];
    assert_eq!(path.root_issuer, fx.cfo_id);
    assert_eq!(path.root_jti, fx.chain.root.jti);
    assert_eq!(path.hops.len(), 1);
    assert_eq!(path.hops[0].issuer_id, fx.orch_aid.id);
    assert_eq!(path.hops[0].grantee_id, fx.agent_aid.id);
    assert_eq!(path.hops[0].jti, fx.chain.chain[0].jti);
    assert_eq!(path.standing, Standing::Valid);
    assert_eq!(
        path.delegators(),
        vec![fx.cfo_id.clone(), fx.orch_aid.id.clone()]
    );

    let mut forged = fx.chain.clone();
    forged.root.expires_at = None;
    let mut inputs = fx.inputs(&fx.agent_aid, &[], &[], &[], &[]);
    let chains = [forged];
    inputs.authority = &chains;
    let p = build_profile(&inputs).unwrap();
    assert!(p.lineage.authority.is_empty());
}

// ─── process lineage ───

/// l05 — an edge whose parent instance is one of this agent's instances is
/// an observed spawn by this agent. The child *process* is a kernel fact;
/// the child *agent* is unattributed until a decision-point-signed
/// expectation for some agent names a binding that matches it structurally.
#[test]
fn l05_observed_spawn_attributes_the_child_only_through_a_signed_expectation() {
    let fx = fixture();
    let orch_b = binding_for(&fx.orch_aid.id, 5000, b"orchestrator image");
    let worker_b = binding_for(&fx.agent_aid.id, 5001, b"worker image");
    let orch_ee = fx.expectation(&fx.orch_aid.id, orch_b.clone());
    let worker_ee = fx.expectation(&fx.agent_aid.id, worker_b.clone());
    let e = [edge(&orch_b, &worker_b)];

    // Orchestrator's profile, no peer expectation: spawned an unattributed child.
    let p = build_profile(&fx.inputs(&fx.orch_aid, std::slice::from_ref(&orch_ee), &[], &e, &[]))
        .unwrap();
    assert_eq!(p.lineage.process.spawned.len(), 1);
    let s = &p.lineage.process.spawned[0];
    assert_eq!(s.child, process_of(&worker_b));
    assert_eq!(s.child_agent, ChildAttribution::Unattributed);
    assert_eq!(
        s.parent_basis,
        InstanceAssertion::AuthorizedTarget {
            decision_id: orch_ee.decision_id,
            decision_point_id: orch_ee.decision_point_id.clone(),
        }
    );
    assert!(p.lineage.process.spawned_by.is_empty());

    // With the worker's expectation as a peer: the child is attributed.
    let p = build_profile(&fx.inputs(
        &fx.orch_aid,
        std::slice::from_ref(&orch_ee),
        std::slice::from_ref(&worker_ee),
        &e,
        &[],
    ))
    .unwrap();
    assert_eq!(
        p.lineage.process.spawned[0].child_agent,
        ChildAttribution::AuthorizedTarget {
            agent_id: fx.agent_aid.id.clone(),
            decision_id: worker_ee.decision_id,
        }
    );

    // A peer expectation the anchors do not trust attributes nothing and is
    // recorded as excluded.
    let mut inputs = fx.inputs(
        &fx.orch_aid,
        std::slice::from_ref(&orch_ee),
        std::slice::from_ref(&worker_ee),
        &e,
        &[],
    );
    let empty = DecisionPointTrustAnchors::new();
    inputs.decision_point_anchors = &empty;
    let p = build_profile(&inputs).unwrap();
    // The orchestrator's own expectation is now unverified too, so there is
    // no bound instance to be the parent — no spawn is attributed to it.
    assert!(p.lineage.process.spawned.is_empty());
    assert_eq!(p.lineage.process.unrelated_edges, 1);
    assert_eq!(p.lineage.process.excluded_peer_expectations.len(), 1);
}

/// l06 — the same edge, seen from the child: this agent was spawned by an
/// instance, and the parent agent is attributed through the peer expectation
/// or not at all.
#[test]
fn l06_spawned_by_is_the_same_edge_from_the_child_side() {
    let fx = fixture();
    let orch_b = binding_for(&fx.orch_aid.id, 5000, b"orchestrator image");
    let worker_b = binding_for(&fx.agent_aid.id, 5001, b"worker image");
    let orch_ee = fx.expectation(&fx.orch_aid.id, orch_b.clone());
    let worker_ee = fx.expectation(&fx.agent_aid.id, worker_b.clone());
    let e = [edge(&orch_b, &worker_b)];

    let p = build_profile(&fx.inputs(
        &fx.agent_aid,
        std::slice::from_ref(&worker_ee),
        &[],
        &e,
        &[],
    ))
    .unwrap();
    assert_eq!(p.lineage.process.spawned_by.len(), 1);
    assert_eq!(p.lineage.process.spawned_by[0].parent, process_of(&orch_b));
    assert_eq!(
        p.lineage.process.spawned_by[0].parent_agent,
        ChildAttribution::Unattributed
    );
    assert!(p.lineage.process.spawned.is_empty());

    let p = build_profile(&fx.inputs(
        &fx.agent_aid,
        std::slice::from_ref(&worker_ee),
        std::slice::from_ref(&orch_ee),
        &e,
        &[],
    ))
    .unwrap();
    assert_eq!(
        p.lineage.process.spawned_by[0].parent_agent,
        ChildAttribution::AuthorizedTarget {
            agent_id: fx.orch_aid.id.clone(),
            decision_id: orch_ee.decision_id,
        }
    );
}

/// l07 — process relations match on the full instance (pid, start ticks,
/// boot id, image content). Same pid with another start tick is another
/// process; same everything but another image is another execution.
#[test]
fn l07_relations_never_match_on_pid_alone() {
    let fx = fixture();
    let orch_b = binding_for(&fx.orch_aid.id, 5000, b"orchestrator image");
    let worker_b = binding_for(&fx.agent_aid.id, 5001, b"worker image");
    let orch_ee = fx.expectation(&fx.orch_aid.id, orch_b.clone());

    let mut recycled = orch_b.clone();
    recycled.process.pid_start_time_ticks += 1;
    let e1 = [edge(&recycled, &worker_b)];
    let p = build_profile(&fx.inputs(&fx.orch_aid, std::slice::from_ref(&orch_ee), &[], &e1, &[]))
        .unwrap();
    assert!(p.lineage.process.spawned.is_empty());
    assert_eq!(p.lineage.process.unrelated_edges, 1);

    let mut other_image = orch_b.clone();
    other_image.exe_content_sha256 = sha256(b"other image");
    let e2 = [edge(&other_image, &worker_b)];
    let p = build_profile(&fx.inputs(&fx.orch_aid, std::slice::from_ref(&orch_ee), &[], &e2, &[]))
        .unwrap();
    assert!(p.lineage.process.spawned.is_empty());
}

/// l08 — the swarm shape, Case 1 of the specification: A spawned B and no
/// authority reaches B from A. The profile shows the observed spawn and the
/// absence of an authority path side by side and says nothing more: there
/// is no reconciled lineage verdict yet, and the type cannot express a
/// violation. A spawn edge is never an authority edge.
#[test]
fn l08_a_spawn_is_never_authority_and_no_verdict_is_manufactured() {
    let fx = fixture();
    // `rogue` is spawned by the orchestrator but holds no delegation.
    let (rogue_aid, _) = create_identity(provenance("rogue"), None).unwrap();
    let orch_b = binding_for(&fx.orch_aid.id, 5000, b"orchestrator image");
    let rogue_b = binding_for(&rogue_aid.id, 5002, b"rogue image");
    let orch_ee = fx.expectation(&fx.orch_aid.id, orch_b.clone());
    let e = [edge(&orch_b, &rogue_b)];

    // The rogue's profile: no authority at all, but spawned by a known instance.
    let mut inputs = fx.inputs(&rogue_aid, &[], std::slice::from_ref(&orch_ee), &e, &[]);
    inputs.authority = &[];
    let claimed = [rogue_b.clone()];
    inputs.claimed_bindings = &claimed; // the rogue's own claim about its process
    let p = build_profile(&inputs).unwrap();

    assert!(p.lineage.authority.is_empty());
    assert!(p.authority.authorized.is_empty());
    assert_eq!(p.lineage.process.spawned_by.len(), 1);
    assert_eq!(
        p.lineage.process.spawned_by[0].parent_agent,
        ChildAttribution::AuthorizedTarget {
            agent_id: fx.orch_aid.id.clone(),
            decision_id: orch_ee.decision_id,
        }
    );
    // The rogue's own instance is only its claim, and the relation says so.
    assert_eq!(
        p.lineage.process.spawned_by[0].child_basis,
        InstanceAssertion::Claimed
    );
    // No verdict. The match is exhaustive: adding a variant is a compile error.
    match p.lineage.reconciled {
        ReconciledLineage::NotReachable => {}
    }
}

/// l09 — the lineage partition has exactly four sections, and no key under
/// it names a score, trust, confidence, reputation, rating, rank or grade.
/// A claimed parent is never rendered under an endorsed key.
#[test]
fn l09_lineage_partition_shape_is_fixed() {
    let fx = fixture();
    let (root, root_kp) = create_identity(provenance("root"), None).unwrap();
    let (leaf, _) =
        create_identity(provenance("leaf"), Some((&root.id, &root_kp.private_key))).unwrap();
    let p = build_profile(&fx.inputs(&leaf, &[], &[], &[], &[])).unwrap();
    let v = serde_json::to_value(&p).unwrap();
    let lineage = v.get("lineage").unwrap();
    let top: BTreeSet<String> = lineage.as_object().unwrap().keys().cloned().collect();
    let expected: BTreeSet<String> = ["identity", "authority", "process", "reconciled"]
        .into_iter()
        .map(String::from)
        .collect();
    assert_eq!(top, expected);

    let mut keys = Vec::new();
    keys_recursive(lineage, &mut keys);
    for k in &keys {
        let lk = k.to_ascii_lowercase();
        for f in [
            "score",
            "trust",
            "confiden",
            "reputation",
            "rating",
            "rank",
            "grade",
        ] {
            assert!(!lk.contains(f), "forbidden key `{k}` in lineage");
        }
    }
    let identity = lineage.get("identity").unwrap();
    assert!(identity.get("parent").unwrap().get("Claimed").is_some());
    assert!(identity.get("parent").unwrap().get("Endorsed").is_none());
}
