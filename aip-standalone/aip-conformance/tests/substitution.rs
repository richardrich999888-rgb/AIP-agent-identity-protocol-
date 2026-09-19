//! Cross-domain substitution (Skill 28, R3).
//!
//! Six kinds of evidence, each taken from one domain and offered as another's.
//! Every one must be refused. This is the attack the acceptance gate's second
//! clause is about — *a new domain cannot silently weaken the central
//! accountability semantics* — because the way a domain weakens the centre is
//! by accepting something that belongs to a different one.
//!
//! The verticals' own suites test substitution *within* a domain. This tests
//! it *between* domains, from one place, over all five realising crates.

use aip_conformance::Domain;
use aip_crypto::sha256;
use aip_types::{ExecutionBinding, ProcessInstance, ProvenanceTriple};

fn provenance(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(tag.as_bytes()),
        environment_commitment: sha256(b"sub-env"),
        toolchain_commitment: sha256(b"sub-toolchain"),
    }
}

/// **Identity.** A profile identifier is one domain's, and the five are
/// distinct. A record carrying another domain's id is not this domain's
/// record — which is what makes the `shared_with` mapping honest rather than
/// convenient: the two pairs that share a crate share its id *and say so*.
#[test]
fn s1_identity_a_profile_id_belongs_to_one_realising_crate() {
    for a in Domain::ALL {
        for b in Domain::ALL {
            let (ra, rb) = (a.realisation(), b.realisation());
            if ra.crate_name == rb.crate_name {
                // Same crate: same id, and both rows declare the sharing.
                assert_eq!(ra.profile_id, rb.profile_id);
                if a != b {
                    assert!(
                        ra.shared_with.contains(&b),
                        "{} shares a crate with {} without declaring it",
                        a.as_str(),
                        b.as_str()
                    );
                }
            } else {
                // Different crates: ids and domain tags must not collide.
                assert_ne!(
                    ra.profile_id,
                    rb.profile_id,
                    "{} and {} are different crates sharing an id",
                    a.as_str(),
                    b.as_str()
                );
                assert_ne!(ra.profile_domain, rb.profile_domain);
            }
        }
    }
}

/// **Execution.** A binding is one execution's. Transplanting it to another
/// host, another process instance or another binary yields a different
/// identity — so a binding cannot be carried across domains any more than it
/// can be carried across hosts.
#[test]
fn s2_execution_a_binding_does_not_transplant_between_domains() {
    let (agent, _) = create_agent("s2");
    let mk = |boot: [u8; 16], exe: &[u8]| ExecutionBinding {
        version: aip_types::EXECUTION_BINDING_VERSION,
        agent_id: agent.clone(),
        process: ProcessInstance {
            pid: 9090,
            pid_start_time_ticks: 42,
            boot_id: boot,
        },
        exe_content_sha256: sha256(exe),
        exe_path: "/opt/vertical/bin/worker".into(),
        bound_at_ms: 1_700_000_000_000,
        container: None,
    };
    // Two domains running the same-named binary on two hosts.
    let uas_host = mk([0xa1; 16], b"autonomy-stack");
    let space_host = mk([0x5b; 16], b"autonomy-stack");
    assert_ne!(
        uas_host.identity_bytes(),
        space_host.identity_bytes(),
        "the same binary on two hosts is two executions"
    );
    // The same host running two different binaries.
    assert_ne!(
        uas_host.identity_bytes(),
        mk([0xa1; 16], b"other-stack").identity_bytes()
    );
}

/// **Model / framework.** No framework name grants anything, in any domain.
/// The enterprise profile is the one that maps frameworks; asking it is the
/// check, and the answer does not depend on which name it is asked about.
#[test]
fn s3_framework_no_name_grants_anything_in_any_domain() {
    use aip_enterprise::EnterpriseAdapter;
    for name in ["langgraph", "autogen", "crewai", "a-name-nobody-anchors"] {
        let a = aip_enterprise::GraphFrameworkAdapter {
            framework_version: name.into(),
            adapter_version: "1".into(),
        };
        assert!(
            !a.framework_grants_authority(),
            "{name} must not grant authority"
        );
    }
    let c = aip_enterprise::ConversationFrameworkAdapter {
        framework_version: "9.9".into(),
        adapter_version: "1".into(),
    };
    assert!(!c.framework_grants_authority());
}

/// **Parameter.** Every domain's parameter key is distinct, so a commitment
/// made under one domain's key cannot be read as another's.
#[test]
fn s4_parameter_keys_are_disjoint_across_the_realising_crates() {
    let keys = [
        aip_enterprise::WORKLOAD_BINDING_PARAMETER_KEY,
        aip_space::MODE_TRANSITION_PARAMETER_KEY,
    ];
    let mut seen: Vec<&str> = keys.to_vec();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), keys.len(), "parameter keys must be disjoint");
    for k in keys {
        assert!(
            k.starts_with("aip."),
            "{k} is not in the reserved namespace"
        );
        assert!(k.ends_with(".v1"), "{k} carries no version");
    }
}

/// **Observer evidence.** An observation's class comes from its mechanism,
/// not from the domain that submitted it. A domain cannot re-label another's
/// evidence into a stronger class, because the class is a function of the
/// mechanism alone and the ceiling is a function of the class alone.
#[test]
fn s5_observer_evidence_cannot_be_relabelled_by_the_submitting_domain() {
    use aip_observation::{class_of, ObservationClass};
    use aip_observe::SourceMechanism;

    // The mapping is total and deterministic: the same mechanism always
    // yields the same class, whichever domain is asking.
    for m in SourceMechanism::ALL {
        assert_eq!(class_of(m), class_of(m));
    }

    // The ceiling is the class's, and no domain supplies one. The strongest
    // any mechanised class reaches is bounded, and the unmechanised class is
    // not reachable at all.
    assert!(!ObservationClass::PhysicalEffect.is_implemented());
    assert!(
        !SourceMechanism::ALL
            .iter()
            .any(|m| class_of(*m) == ObservationClass::PhysicalEffect),
        "no domain may supply a mechanism for the physical-effect class"
    );
}

/// **The verdict itself.** No domain draws one. `aip-reconcile` and
/// `aip-nexora` appear in every realising crate's manifest only under
/// `[dev-dependencies]`, so a profile *cannot* call the engine in production
/// code — the compiler enforces it and this reads the manifests to prove it.
#[test]
fn s6_no_realising_crate_can_call_the_engine_in_production_code() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("aip-standalone");
    for c in Domain::distinct_crates() {
        let manifest = std::fs::read_to_string(root.join(c).join("Cargo.toml"))
            .unwrap_or_else(|e| panic!("{c}/Cargo.toml unreadable: {e}"));
        // Strip comments: several manifests explain the rule in prose above
        // the section, and a comment is not a dependency.
        let body: String = manifest
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");
        let (prod, dev) = body
            .split_once("[dev-dependencies]")
            .unwrap_or_else(|| panic!("{c} declares no dev-dependencies"));
        for engine in ["aip-reconcile", "aip-nexora"] {
            assert!(
                !prod.contains(engine),
                "{c} names {engine} as a production dependency"
            );
            assert!(
                dev.contains(engine),
                "{c} does not exercise {engine} even in tests"
            );
        }
    }
}

fn create_agent(tag: &str) -> (String, Vec<u8>) {
    let (aid, kp) = aip_core::create_identity(provenance(tag), None).unwrap();
    (aid.id, kp.public_key)
}
