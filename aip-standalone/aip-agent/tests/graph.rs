//! Phase D — the delegation graph (SD-06), RED.
//!
//! A graph over *verified* token chains: nodes are tokens, edges are
//! `parent_jti` links, indexed by grantee. Every node's signature was
//! verified by `aip_core` before it entered; a chain that fails is excluded
//! whole. The graph answers who delegated what to whom and never invents an
//! edge: a hop whose parent is not in hand is reported as incompleteness,
//! not verified against nothing. Revocation is a verifier-supplied set of
//! token ids (the same shape the packet verifier's rule R9 consumes); the
//! graph does not decide what is revoked.

use aip_agent::*;
use aip_core::capability::{issue_scoped_token, scope_orchestrator, scope_submitter};
use aip_core::create_identity;
use aip_core::delegation::{create_delegation, create_sub_delegation, MAX_DELEGATION_DEPTH};
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_types::{
    Action, AgentIdentityDocument, AipError, KeyPair, ProvenanceTriple, ScopeAction, ScopedToken,
};

fn provenance(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("model-{tag}").as_bytes()),
        environment_commitment: sha256(format!("env-{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("toolchain-{tag}").as_bytes()),
    }
}

struct Fx {
    cfo_id: String,
    cfo_kp: KeyPair,
    orch: AgentIdentityDocument,
    orch_kp: KeyPair,
    a: AgentIdentityDocument,
    a_kp: KeyPair,
    b: AgentIdentityDocument,
    root: ScopedToken,
    keys: IssuerKeys,
    now: u64,
}

fn fixture() -> Fx {
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo_kp.public_key, &provenance("cfo"));
    let (orch, orch_kp) = create_identity(provenance("orch"), None).unwrap();
    let (a, a_kp) = create_identity(provenance("a"), None).unwrap();
    let (b, _) = create_identity(provenance("b"), None).unwrap();
    let root = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &orch.id,
        scope_orchestrator(),
        Some(3_600_000),
    )
    .unwrap();
    let keys = IssuerKeys::new()
        .trust(&cfo_id, &cfo_kp.public_key)
        .trust(&orch.id, &orch_kp.public_key)
        .trust(&a.id, &a_kp.public_key);
    let now = root.issued_at + 1;
    Fx {
        cfo_id,
        cfo_kp,
        orch,
        orch_kp,
        a,
        a_kp,
        b,
        root,
        keys,
        now,
    }
}

impl Fx {
    fn chain_to(&self, grantee: &str) -> AuthorityChain {
        let hop = create_delegation(
            &self.root,
            &self.orch_kp.private_key,
            grantee,
            scope_submitter(),
        )
        .unwrap();
        AuthorityChain {
            root: self.root.clone(),
            chain: vec![hop],
        }
    }
}

fn write() -> ScopeAction {
    ScopeAction::Standard(Action::Write)
}

/// d01 — one verified chain: two nodes, one path to the grantee with the
/// root issuer first, every delegator named, the effective scope, `Valid`
/// standing, and a complete graph.
#[test]
fn d01_one_chain_is_one_path() {
    let fx = fixture();
    let chain = fx.chain_to(&fx.a.id);
    let g = DelegationGraph::build(&[chain.clone()], &[], &fx.keys, &[], fx.now);
    assert_eq!(g.nodes().len(), 2);
    assert!(g.is_complete());
    assert!(g.excluded().is_empty());
    let paths = g.paths_to(&fx.a.id);
    assert_eq!(paths.len(), 1);
    let p = &paths[0];
    assert_eq!(p.jtis, vec![chain.root.jti, chain.chain[0].jti]);
    assert_eq!(p.root_issuer, fx.cfo_id);
    assert_eq!(p.delegators, vec![fx.cfo_id.clone(), fx.orch.id.clone()]);
    assert_eq!(p.grantee, fx.a.id);
    assert_eq!(p.effective_scope, scope_submitter());
    assert_eq!(p.standing, PathStanding::Valid);
    assert!(g.paths_to(&fx.b.id).is_empty());
}

/// d02 — two chains sharing a root: the root node appears once; the agents
/// under the root issuer are the orchestrator and both grantees; the
/// orchestrator's outgoing delegations are exactly the two hops.
#[test]
fn d02_shared_root_is_one_node_and_agents_under_are_transitive() {
    let fx = fixture();
    let ca = fx.chain_to(&fx.a.id);
    let cb = fx.chain_to(&fx.b.id);
    let g = DelegationGraph::build(&[ca.clone(), cb.clone()], &[], &fx.keys, &[], fx.now);
    assert_eq!(g.nodes().len(), 3);
    let mut under = g.agents_under(&fx.cfo_id);
    under.sort();
    let mut expected = vec![fx.orch.id.clone(), fx.a.id.clone(), fx.b.id.clone()];
    expected.sort();
    assert_eq!(under, expected);
    let mut out: Vec<[u8; 16]> = g.delegated_by(&fx.orch.id).iter().map(|n| n.jti).collect();
    out.sort();
    let mut exp = vec![ca.chain[0].jti, cb.chain[0].jti];
    exp.sort();
    assert_eq!(out, exp);
    assert!(g.delegated_by(&fx.a.id).is_empty());
    assert!(g.agents_under(&fx.a.id).is_empty());
}

/// d03 — a hop whose parent token is not in hand cannot be verified against
/// its parent's scope, so it is not a node and not a path; it is reported
/// as incompleteness naming the missing parent. The graph says it is
/// incomplete.
#[test]
fn d03_a_dangling_hop_is_incompleteness_not_authority() {
    let fx = fixture();
    let hop = create_delegation(
        &fx.root,
        &fx.orch_kp.private_key,
        &fx.a.id,
        scope_submitter(),
    )
    .unwrap();
    let g = DelegationGraph::build(&[], std::slice::from_ref(&hop), &fx.keys, &[], fx.now);
    assert!(g.nodes().is_empty());
    assert!(!g.is_complete());
    assert_eq!(g.incomplete().len(), 1);
    assert_eq!(g.incomplete()[0].jti, hop.jti);
    assert_eq!(g.incomplete()[0].missing_parent_jti, fx.root.jti);
    assert_eq!(g.incomplete()[0].grantee_id, fx.a.id);
    assert!(g.paths_to(&fx.a.id).is_empty());

    // Supplying the root as well resolves it: the hop is now verified in
    // its chain and the graph is complete.
    let g = DelegationGraph::build(
        &[AuthorityChain {
            root: fx.root.clone(),
            chain: vec![hop.clone()],
        }],
        std::slice::from_ref(&hop),
        &fx.keys,
        &[],
        fx.now,
    );
    assert!(g.is_complete());
    assert_eq!(g.paths_to(&fx.a.id).len(), 1);
}

/// d04 — revocation is a verifier-supplied set of token ids. A path through
/// a revoked token stands `Revoked` naming that token, is not among the
/// valid paths, and confers no authority for any action. Revoking the root
/// revokes every path under it.
#[test]
fn d04_revoked_tokens_stand_revoked_and_confer_nothing() {
    let fx = fixture();
    let ca = fx.chain_to(&fx.a.id);
    let cb = fx.chain_to(&fx.b.id);
    let chains = [ca.clone(), cb.clone()];

    let g = DelegationGraph::build(&chains, &[], &fx.keys, &[ca.chain[0].jti], fx.now);
    assert_eq!(
        g.paths_to(&fx.a.id)[0].standing,
        PathStanding::Revoked {
            jti: ca.chain[0].jti
        }
    );
    assert!(g.valid_paths_to(&fx.a.id).is_empty());
    assert!(g.authority_reaching(&fx.a.id, &write()).is_empty());
    assert_eq!(g.valid_paths_to(&fx.b.id).len(), 1);

    let g = DelegationGraph::build(&chains, &[], &fx.keys, &[fx.root.jti], fx.now);
    for agent in [&fx.a.id, &fx.b.id] {
        assert_eq!(
            g.paths_to(agent)[0].standing,
            PathStanding::Revoked { jti: fx.root.jti }
        );
        assert!(g.valid_paths_to(agent).is_empty());
    }
}

/// d05 — a chain with a rewritten hop is excluded whole with the reason;
/// none of its tokens becomes a node, so the untouched root of that chain
/// contributes nothing either unless another verified chain carries it.
#[test]
fn d05_a_chain_that_fails_verification_contributes_no_node() {
    let fx = fixture();
    let mut forged = fx.chain_to(&fx.a.id);
    forged.chain[0].grantee_id = fx.b.id.clone();
    let g = DelegationGraph::build(&[forged.clone()], &[], &fx.keys, &[], fx.now);
    assert!(g.nodes().is_empty());
    assert_eq!(g.excluded().len(), 1);
    assert_eq!(g.excluded()[0].root_jti, forged.root.jti);
    assert!(matches!(
        g.excluded()[0].reason,
        ExclusionReason::ChainInvalid(AipError::SignatureInvalid)
    ));
    assert!(g.paths_to(&fx.a.id).is_empty());
    assert!(g.paths_to(&fx.b.id).is_empty());
}

/// d06 — the same token presented through two chains and again as a loose
/// hop is one node, never a conflict; the graph stays complete. (Two
/// *different* genuinely signed tokens sharing an id cannot be produced from
/// outside `aip_core`, which chooses ids itself; the conflict branch is
/// therefore defensive and is not claimed as a tested property.)
#[test]
fn d06_identical_tokens_dedupe_to_one_node() {
    let fx = fixture();
    let ca = fx.chain_to(&fx.a.id);
    let cb = fx.chain_to(&fx.b.id);
    let hop = ca.chain[0].clone();
    let g = DelegationGraph::build(
        &[ca.clone(), cb],
        std::slice::from_ref(&hop),
        &fx.keys,
        &[],
        fx.now,
    );
    assert_eq!(g.nodes().iter().filter(|n| n.jti == fx.root.jti).count(), 1);
    assert_eq!(g.nodes().iter().filter(|n| n.jti == hop.jti).count(), 1);
    assert!(g.conflicts().is_empty());
    assert!(g.is_complete());
}

/// d07 — depth is bounded by `aip_core`: a chain may be extended hop by hop
/// up to the library's limit and every prefix is a path; the library refuses
/// the hop past the limit, and the graph never sees it.
#[test]
fn d07_depth_is_bounded_by_the_library_and_every_prefix_is_a_path() {
    let fx = fixture();
    let mut chain: Vec<aip_types::DelegationToken> = Vec::new();
    let mut keys = fx.keys.clone();
    let mut holder_kp = fx.orch_kp.clone();
    let mut last_grantee = fx.orch.id.clone();
    let mut agents: Vec<(AgentIdentityDocument, KeyPair)> = Vec::new();
    loop {
        let (next, next_kp) =
            create_identity(provenance(&format!("hop-{}", chain.len())), None).unwrap();
        let attempt = match chain.last() {
            None => create_delegation(
                &fx.root,
                &holder_kp.private_key,
                &next.id,
                scope_submitter(),
            ),
            Some(prev) => {
                create_sub_delegation(prev, &holder_kp.private_key, &next.id, scope_submitter())
            }
        };
        match attempt {
            Ok(hop) => {
                keys = keys.trust(&last_grantee, &holder_kp.public_key);
                chain.push(hop);
                last_grantee = next.id.clone();
                holder_kp = next_kp.clone();
                agents.push((next, next_kp));
            }
            Err(AipError::LineageInvalid) => break,
            Err(e) => panic!("unexpected {e:?}"),
        }
        assert!(
            chain.len() < usize::from(MAX_DELEGATION_DEPTH),
            "no unbounded chains"
        );
    }
    assert!(chain.len() >= 2, "the library allows several hops");
    let full = AuthorityChain {
        root: fx.root.clone(),
        chain: chain.clone(),
    };
    let g = DelegationGraph::build(&[full], &[], &keys, &[], fx.now);
    assert!(g.excluded().is_empty(), "{:?}", g.excluded());
    assert_eq!(g.nodes().len(), chain.len() + 1);
    // Every intermediate grantee has exactly one path, of increasing length.
    for (i, (agent, _)) in agents.iter().enumerate() {
        let paths = g.paths_to(&agent.id);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].jtis.len(), i + 2);
    }
    let leaf = &agents.last().unwrap().0;
    assert_eq!(g.paths_to(&leaf.id)[0].delegators.len(), chain.len() + 1);
}

/// d08 — `authority_reaching(agent, action)` is the set of valid paths whose
/// effective scope permits the action. Out-of-scope actions and expired paths
/// reach nothing; an expired path is still a path (`Expired`), not excluded.
#[test]
fn d08_authority_reaching_is_scope_and_standing() {
    let fx = fixture();
    let ca = fx.chain_to(&fx.a.id);
    let g = DelegationGraph::build(std::slice::from_ref(&ca), &[], &fx.keys, &[], fx.now);
    assert_eq!(g.authority_reaching(&fx.a.id, &write()).len(), 1);
    assert!(g
        .authority_reaching(&fx.a.id, &ScopeAction::Standard(Action::Admin))
        .is_empty());

    let expiry = fx.root.expires_at.unwrap();
    let g = DelegationGraph::build(std::slice::from_ref(&ca), &[], &fx.keys, &[], expiry + 1);
    assert_eq!(g.paths_to(&fx.a.id).len(), 1);
    assert_eq!(
        g.paths_to(&fx.a.id)[0].standing,
        PathStanding::Expired { at_ms: expiry }
    );
    assert!(g.authority_reaching(&fx.a.id, &write()).is_empty());
    assert!(g.excluded().is_empty());
}

/// d09 — a self-issued root (issuer == grantee) is excluded before any key
/// lookup, and an untrusted issuer is excluded by name.
#[test]
fn d09_self_issued_and_untrusted_roots_are_excluded() {
    let fx = fixture();
    let self_root = issue_scoped_token(
        &fx.a.id,
        &fx.a_kp.private_key,
        &fx.a.id,
        scope_submitter(),
        Some(3_600_000),
    )
    .unwrap();
    let g = DelegationGraph::build(
        &[AuthorityChain {
            root: self_root,
            chain: vec![],
        }],
        &[],
        &fx.keys,
        &[],
        fx.now,
    );
    assert_eq!(g.excluded()[0].reason, ExclusionReason::SelfIssuedRoot);
    assert!(g.nodes().is_empty());

    let no_cfo = IssuerKeys::new().trust(&fx.orch.id, &fx.orch_kp.public_key);
    let g = DelegationGraph::build(&[fx.chain_to(&fx.a.id)], &[], &no_cfo, &[], fx.now);
    assert_eq!(
        g.excluded()[0].reason,
        ExclusionReason::UntrustedIssuer(fx.cfo_id.clone())
    );
    assert!(g.nodes().is_empty());
}

/// d10 — the profile carries the graph's answers for its agent: paths to
/// it, delegations it issued, agents under it, incompleteness and
/// conflicts. A chain that reaches another agent is not an exclusion for the
/// graph even though it is `LeafNotAgent` for the agent's own authority.
#[test]
fn d10_profile_carries_delegation_summary() {
    let fx = fixture();
    let ca = fx.chain_to(&fx.a.id);
    let cb = fx.chain_to(&fx.b.id);
    let chains = [ca.clone(), cb.clone()];

    // The orchestrator's profile: it holds the root, delegated to A and B.
    let dp_kp = generate_ed25519_keypair();
    let dp_id = derive_aip_id(&dp_kp.public_key, &provenance("dp"));
    let anchors = aip_authorize::DecisionPointTrustAnchors::new().trust(&dp_id, &dp_kp.public_key);
    let inputs = ProfileInputs {
        identity: IdentityInput::Document {
            document: &fx.orch,
            parent: None,
        },
        self_declared: &[],
        authority: &chains,
        loose_hops: &[],
        revoked_jtis: &[],
        issuer_keys: &fx.keys,
        expectations: &[],
        decision_point_anchors: &anchors,
        claimed_bindings: &[],
        reconciliations: &[],
        peer_expectations: &[],
        process_edges: &[],
        ancestor_documents: &[],
        as_of_ms: fx.now,
    };
    let p = build_profile(&inputs).unwrap();
    let d = &p.lineage.delegation;
    assert_eq!(
        d.paths_to_agent.len(),
        2,
        "both chains' roots reach the orchestrator"
    );
    assert_eq!(d.delegated_by_agent.len(), 2);
    let mut grantees: Vec<String> = d
        .delegated_by_agent
        .iter()
        .map(|o| o.grantee_id.clone())
        .collect();
    grantees.sort();
    let mut exp = vec![fx.a.id.clone(), fx.b.id.clone()];
    exp.sort();
    assert_eq!(grantees, exp);
    let mut under = d.agents_under_agent.clone();
    under.sort();
    assert_eq!(under, exp);
    assert!(d.incomplete.is_empty());
    assert!(d.conflicts.is_empty());
    // For the orchestrator's *own* authority both chains end elsewhere.
    assert_eq!(p.authority.excluded.len(), 2);
    assert!(p
        .authority
        .excluded
        .iter()
        .all(|e| matches!(e.reason, ExclusionReason::LeafNotAgent { .. })));

    // A's profile: one path in, nothing out, nobody under.
    let mut inputs_a = inputs;
    inputs_a.identity = IdentityInput::Document {
        document: &fx.a,
        parent: None,
    };
    let p = build_profile(&inputs_a).unwrap();
    assert_eq!(p.lineage.delegation.paths_to_agent.len(), 1);
    assert!(p.lineage.delegation.delegated_by_agent.is_empty());
    assert!(p.lineage.delegation.agents_under_agent.is_empty());
}

/// d11 — the graph is a projection: serializing it exposes token ids,
/// issuers, grantees, scopes, times and standings — no score, trust,
/// confidence, reputation, rating, rank or grade anywhere.
#[test]
fn d11_graph_has_no_scalar_summary() {
    let fx = fixture();
    let g = DelegationGraph::build(&[fx.chain_to(&fx.a.id)], &[], &fx.keys, &[], fx.now);
    let v = serde_json::to_value(&g).unwrap();
    let mut keys = Vec::new();
    fn walk(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, v) in m {
                    out.push(k.clone());
                    walk(v, out);
                }
            }
            serde_json::Value::Array(a) => a.iter().for_each(|v| walk(v, out)),
            _ => {}
        }
    }
    walk(&v, &mut keys);
    assert!(!keys.is_empty());
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
            assert!(!lk.contains(f), "forbidden key `{k}`");
        }
    }
}
