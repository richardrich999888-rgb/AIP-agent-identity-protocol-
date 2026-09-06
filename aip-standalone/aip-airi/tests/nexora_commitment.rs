//! Gate 5 — committing AI-stack provenance into a NEXORA proof.
//!
//! A NEXORA proof package must be able to carry the AIRI evidence a
//! reconciliation rested on, so an offline verifier holding only the package
//! can re-derive what it is asked to believe. The mechanism is the existing
//! Merkle commitment: an AIRI event is committed under its own leaf kind
//! (`LeafKind::AiriEvent`, code `0x09`), appended to the frozen set rather
//! than renumbering it.
//!
//! What is committed is the event's **signing preimage** — the exact bytes
//! the agent signed. Committing a re-serialisation instead would make the
//! verifier check a round-trip rather than the artefact, and any encoder
//! asymmetry would open a gap between what was signed and what was proved.

use aip_airi::*;
use aip_nexora::{leaf_hash, LeafKind};

mod support;
use support::*;

#[test]
fn an_airi_event_commits_under_its_own_leaf_kind() {
    let a = agent("agent-1");
    let ev = signed_tool_request(&a, EXEC_A, Some(DECISION_A), "tool.http.post", b"{}");
    let leaf = leaf_hash(LeafKind::AiriEvent, &ev.signing_preimage());
    assert_ne!(leaf, [0u8; 32]);
}

#[test]
fn an_airi_leaf_cannot_be_replayed_as_another_kind() {
    // The whole point of the kind code: the same bytes committed as a
    // reconciliation, a warrant or an expectation must produce different
    // leaves, so a committed AIRI event cannot be presented as any of them.
    let a = agent("agent-1");
    let ev = signed_tool_request(&a, EXEC_A, Some(DECISION_A), "tool.http.post", b"{}");
    let bytes = ev.signing_preimage();

    let airi = leaf_hash(LeafKind::AiriEvent, &bytes);
    for other in LeafKind::ALL {
        if other == LeafKind::AiriEvent {
            continue;
        }
        assert_ne!(
            airi,
            leaf_hash(other, &bytes),
            "SECURITY: an AIRI leaf collides with {other:?}"
        );
    }
}

#[test]
fn distinct_events_commit_to_distinct_leaves() {
    let a = agent("agent-1");
    let e1 = signed_tool_request(&a, EXEC_A, Some(DECISION_A), "tool.http.post", b"{\"amount\":5}");
    let e2 = signed_tool_request(&a, EXEC_A, Some(DECISION_A), "tool.http.post", b"{\"amount\":500000}");
    assert_ne!(
        leaf_hash(LeafKind::AiriEvent, &e1.signing_preimage()),
        leaf_hash(LeafKind::AiriEvent, &e2.signing_preimage()),
        "SECURITY: two different parameter sets share a commitment"
    );
}

#[test]
fn a_whole_chain_commits_leaf_by_leaf_and_order_matters() {
    // Committing a chain as an ordered list of leaves preserves the property
    // the chain already has: a reordering is a different commitment.
    let a = agent("agent-1");
    let chain = signed_chain(&a, EXEC_A, 4);
    let leaves: Vec<[u8; 32]> = chain
        .iter()
        .map(|e| leaf_hash(LeafKind::AiriEvent, &e.signing_preimage()))
        .collect();
    assert_eq!(leaves.len(), 4);

    let mut swapped = leaves.clone();
    swapped.swap(1, 2);
    assert_ne!(leaves, swapped);

    // Every leaf is distinct — the events differ in sequence and prev hash.
    let mut sorted = leaves.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 4, "two events in one chain share a leaf");
}

#[test]
fn the_committed_bytes_are_the_bytes_that_were_signed() {
    // A verifier holding the package must be able to check the signature
    // against the committed bytes directly, with no re-encoding step in
    // between. This asserts the two are the same object.
    let a = agent("agent-1");
    let ev = signed_tool_request(&a, EXEC_A, Some(DECISION_A), "tool.http.post", b"{}");
    let committed = ev.signing_preimage();

    assert!(verify_airi_event(&ev, &a.public_key).is_ok());
    assert_eq!(
        ev.signature.payload_hash,
        aip_crypto::sha256(&committed),
        "the committed bytes are not the bytes the signature covers"
    );
}
