//! Skill 17 — the accountability core must be unchanged by this crate.
//!
//! A new model layer is a good place to accidentally change what an existing
//! identity means. These tests are the guard: they establish that `aip-system`
//! is additive, that it reuses existing identifiers rather than redefining
//! them, and — structurally — that no crate which decides anything can see it.
//!
//! # Why the dependency direction is tested and not merely documented
//!
//! D17-6 says `aip-reconcile`, `aip-warrant`, `aip-containment`, `aip-nexora`
//! and `aip-airi` do not depend on this crate. That is the *reason* Skill 17
//! cannot cause a semantic regression in the verdict path: a layer those
//! crates cannot see cannot change what they decide. A comment saying so
//! survives exactly until someone adds a convenient import, so the manifests
//! are read and asserted instead.

use std::fs;
use std::path::Path;

/// The crates that decide something. If any of these ever depends on
/// `aip-system`, the isolation argument for Skill 17 stops holding and this
/// test is where that must be noticed.
const VERDICT_PATH: [&str; 6] = [
    "aip-reconcile",
    "aip-warrant",
    "aip-containment",
    "aip-nexora",
    "aip-airi",
    "aip-observe",
];

fn manifest(crate_name: &str) -> String {
    // Tests run with CWD at the crate root; the siblings are one level up.
    let path = Path::new("..").join(crate_name).join("Cargo.toml");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn no_crate_in_the_verdict_path_depends_on_this_one() {
    for c in VERDICT_PATH {
        let m = manifest(c);
        assert!(
            !m.contains("aip-system"),
            "SECURITY (D17-6): {c} now depends on aip-system. The isolation \
             argument for Skill 17 — that a description layer the verdict \
             layers cannot see cannot change what they decide — no longer \
             holds. If this dependency is genuinely required, it needs its own \
             justification and its own gate; it must not appear silently."
        );
    }
}

#[test]
fn this_crate_depends_only_on_types_and_crypto() {
    // The mirror. A dependency *out* of this crate into the verdict path
    // would let a future edit here reach into semantics it must not touch.
    let m = fs::read_to_string("Cargo.toml").expect("own manifest");
    for forbidden in VERDICT_PATH {
        assert!(
            !m.contains(forbidden),
            "aip-system must not depend on {forbidden}"
        );
    }
    assert!(m.contains("aip-types"), "aip-types is the reuse source");
    assert!(m.contains("aip-crypto"), "aip-crypto validates AIP-IDs");
}

#[test]
fn existing_aip_identity_semantics_are_unchanged() {
    // S17-13. This crate validates AIP-IDs with the existing function and
    // derives none of its own. If AIP identity semantics had been forked, an
    // id derived the existing way would stop validating.
    use aip_crypto::{derive_aip_id, sha256, validate_aip_id};
    use aip_types::ProvenanceTriple;

    let prov = ProvenanceTriple {
        model_commitment: sha256(b"model"),
        environment_commitment: sha256(b"env"),
        toolchain_commitment: sha256(b"tool"),
    };
    let id = derive_aip_id(&sha256(b"pubkey"), &prov);

    assert!(id.starts_with("aip1"), "AIP-ID prefix unchanged");
    validate_aip_id(&id).expect("an AIP-ID derived the existing way must validate");

    // And this crate accepts exactly what the existing validator accepts —
    // no wider, which would let a malformed identity in, and no narrower,
    // which would reject identities the rest of the system considers valid.
    aip_system::SystemExecution::new(
        aip_system::SystemId::parse("sys:s").unwrap(),
        &id,
        [0xA1; 16],
        1_700_000_000_000,
    )
    .expect("this crate must accept every id the core considers valid");
}

#[test]
fn the_airi_execution_identifier_is_reused_verbatim() {
    // S17-14. Execution identity is `[u8; 16]`, the same width and the same
    // meaning as `aip_airi::ExecutionId`. This crate introduces no execution
    // identifier of its own — a second one would be two answers to "which run
    // was this", which is the collapse the model exists to prevent.
    let exec: [u8; 16] = [0xE1; 16];
    let e = aip_system::SystemExecution::new(
        aip_system::SystemId::parse("sys:s").unwrap(),
        &aip_crypto::derive_aip_id(
            &aip_crypto::sha256(b"pubkey"),
            &aip_types::ProvenanceTriple {
                model_commitment: aip_crypto::sha256(b"m"),
                environment_commitment: aip_crypto::sha256(b"e"),
                toolchain_commitment: aip_crypto::sha256(b"t"),
            },
        ),
        exec,
        1_700_000_000_000,
    )
    .unwrap();

    assert_eq!(e.execution_id, exec);
    assert_eq!(
        std::mem::size_of_val(&e.execution_id),
        16,
        "execution id width must match aip-airi's"
    );
}

#[test]
fn the_execution_binding_is_reused_verbatim_including_its_caveat() {
    // The binding embedded here is `aip_types::ExecutionBinding` — the same
    // type, with the same self-report caveat. This crate does not wrap it,
    // extend it, or reinterpret it; embedding it must not upgrade a
    // self-reported binding into evidence that the execution occurred.
    use aip_types::{ExecutionBinding, ProcessInstance, EXECUTION_BINDING_VERSION};

    let binding = ExecutionBinding {
        version: EXECUTION_BINDING_VERSION,
        agent_id: "aip1whatever".into(),
        process: ProcessInstance {
            pid: 1,
            pid_start_time_ticks: 2,
            boot_id: [3; 16],
        },
        exe_content_sha256: [4; 32],
        exe_path: "/bin/x".into(),
        bound_at_ms: 5,
        container: None,
    };
    // The binding's own canonical encoding is what gets embedded, unmodified.
    let embedded = binding.canonical_bytes();
    assert!(!embedded.is_empty());
    assert_eq!(
        binding.canonical_bytes(),
        embedded,
        "this crate must not alter the binding's encoding"
    );
}

#[test]
fn the_domain_tags_do_not_collide_with_existing_ones() {
    // Domain separation across the whole system, not just within this crate.
    // Two structures sharing a domain tag could be confused by a verifier
    // reading raw bytes.
    let ours = [
        aip_system::AUTONOMOUS_SYSTEM_DOMAIN,
        aip_system::SYSTEM_EXECUTION_DOMAIN,
    ];
    assert_ne!(ours[0], ours[1]);
    for d in ours {
        assert!(d.starts_with("SYNTRIASS/AUTONOMY/"), "namespaced: {d}");
        for existing in [
            "SYNTRIASS/GHOST/RECONCILIATION/v1",
            "SYNTRIASS/GHOST/WARRANT/v1",
            "SYNTRIASS/AIRI/EVENT/v1",
            "SYNTRIASS/AIRI/PARAM_COMMITMENT/v1",
        ] {
            assert_ne!(d, existing, "domain tag collides with {existing}");
        }
    }
}

#[test]
fn the_two_domain_tags_separate_the_two_structures() {
    // Even if the field layouts were to coincide, the leading domain tag
    // means a system descriptor can never be read as an execution record.
    use aip_system::*;
    let s = AutonomousSystem::new(
        SystemId::parse("sys:s").unwrap(),
        SystemType::Enterprise,
        LifecycleState::Created,
        1,
    );
    let e = SystemExecution::new(
        SystemId::parse("sys:s").unwrap(),
        &aip_crypto::derive_aip_id(
            &aip_crypto::sha256(b"p"),
            &aip_types::ProvenanceTriple {
                model_commitment: aip_crypto::sha256(b"m"),
                environment_commitment: aip_crypto::sha256(b"e"),
                toolchain_commitment: aip_crypto::sha256(b"t"),
            },
        ),
        [0; 16],
        1,
    )
    .unwrap();

    let sb = s.canonical_bytes();
    let eb = e.canonical_bytes();
    assert_ne!(sb, eb);
    assert!(
        !sb.starts_with(&eb[..8]) && !eb.starts_with(&sb[..8]),
        "the domain tags must differ from the first bytes"
    );
}
