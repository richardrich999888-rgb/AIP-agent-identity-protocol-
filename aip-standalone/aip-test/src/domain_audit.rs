//! PR3 item 34: one test that can see every crate, asserting that every
//! signed-payload domain tag in the evidence chain is distinct and that a
//! domain tag is always the first, length-prefixed element of its preimage.
//!
//! Per-crate tests already assert this within each crate's dependency reach;
//! this is the only place all nineteen tags are in scope at once.

use aip_types::canonical::put_domain;

const ALL_DOMAINS: [&str; 19] = [
    aip_core::AID_SELF_SIGNATURE_DOMAIN,
    aip_core::LINEAGE_PROOF_DOMAIN,
    aip_core::CAPABILITY_GRANT_DOMAIN,
    aip_core::REPUTATION_VOTE_DOMAIN,
    aip_core::capability::SCOPED_TOKEN_DOMAIN,
    aip_core::delegation::DELEGATION_TOKEN_DOMAIN,
    aip_types::EXECUTION_BINDING_DOMAIN,
    aip_types::EXECUTION_IDENTITY_DOMAIN,
    aip_authorize::EXPECTED_EXECUTION_DOMAIN,
    aip_authorize::ACTION_PARAMETERS_DOMAIN,
    aip_observe::OBSERVED_EXECUTION_DOMAIN,
    aip_observe::OBSERVATION_BATCH_DOMAIN,
    aip_observe::OBSERVED_PROCESS_DOMAIN,
    aip_observe::KERNEL_EVENT_DOMAIN,
    aip_observe::OBSERVER_HEAD_DOMAIN,
    aip_observe::OBSERVER_HEALTH_DOMAIN,
    aip_reconcile::RECONCILIATION_DOMAIN,
    aip_reconcile::DECISION_POINT_COVERAGE_DOMAIN,
    aip_warrant::WARRANT_DOMAIN,
];

#[test]
fn every_signed_domain_tag_is_distinct_non_empty_and_versioned() {
    for (i, a) in ALL_DOMAINS.iter().enumerate() {
        assert!(!a.is_empty());
        assert!(a.ends_with("/v1"), "{a} must carry a version suffix");
        assert!(
            a.starts_with("AIP/") || a.starts_with("GHOST/") || a.starts_with("SYNTRIASS/GHOST/"),
            "{a} outside the known namespaces"
        );
        for b in &ALL_DOMAINS[i + 1..] {
            assert_ne!(a, b, "duplicate domain tag");
            // No tag may be a prefix of another: a length-prefixed encoding
            // already prevents confusion, but a shared prefix would still be
            // a readability trap for anyone comparing tags by eye.
            assert!(
                !a.starts_with(b) && !b.starts_with(a),
                "{a} / {b} share a prefix"
            );
        }
    }
}

#[test]
fn a_domain_tag_encodes_as_a_length_prefixed_first_element() {
    for d in ALL_DOMAINS {
        let mut buf = Vec::new();
        put_domain(&mut buf, d);
        assert_eq!(&buf[..4], &(d.len() as u32).to_le_bytes());
        assert_eq!(&buf[4..], d.as_bytes());
    }
    // Two different tags of equal length still differ in bytes.
    let mut x = Vec::new();
    put_domain(&mut x, "AIP/ScopedToken/v1");
    let mut y = Vec::new();
    put_domain(&mut y, "AIP/ScopedTokeN/v1");
    assert_ne!(x, y);
}

/// The evidence-chain preimages really do start with their tags (spot check
/// across the three Ghost crates, using real constructors).
#[test]
fn real_preimages_begin_with_their_tag() {
    use aip_types::{ExecutionBinding, ProcessInstance, EXECUTION_BINDING_VERSION};
    let b = ExecutionBinding {
        version: EXECUTION_BINDING_VERSION,
        agent_id: "aip1x".into(),
        process: ProcessInstance {
            pid: 1,
            pid_start_time_ticks: 1,
            boot_id: [1; 16],
        },
        exe_content_sha256: [2; 32],
        exe_path: "/x".into(),
        bound_at_ms: 0,
    };
    let starts_with = |bytes: &[u8], tag: &str| {
        bytes.len() > 4 + tag.len() && &bytes[4..4 + tag.len()] == tag.as_bytes()
    };
    assert!(starts_with(
        &b.canonical_bytes(),
        aip_types::EXECUTION_BINDING_DOMAIN
    ));
    assert!(starts_with(
        &b.identity_bytes(),
        aip_types::EXECUTION_IDENTITY_DOMAIN
    ));
    let params = aip_authorize::ActionParameters::empty();
    assert!(starts_with(
        &params.canonical_bytes(),
        aip_authorize::ACTION_PARAMETERS_DOMAIN
    ));
    let obs = aip_observe::ObservedProcess {
        process: b.process,
        exe_content_sha256: b.exe_content_sha256,
        exe_path: b.exe_path.clone(),
    };
    assert!(starts_with(
        &obs.identity_bytes(),
        aip_observe::OBSERVED_PROCESS_DOMAIN
    ));
    // And the two identity encodings are deliberately NOT comparable by bytes
    // (PR3 E-1): one names the agent, one does not.
    assert_ne!(b.identity_bytes(), obs.identity_bytes());
    assert!(
        obs.matches_process_of(&b),
        "structural comparison is the contract"
    );
}
