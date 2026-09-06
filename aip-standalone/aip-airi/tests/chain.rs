//! Gate 2 — chain integrity: replay, duplication, drop, reorder, splice.
//!
//! An agent that wants to hide one action has cheaper options than forging a
//! signature: emit the events out of order, send one twice, drop the
//! inconvenient one, or splice in a genuine event from another run. Every
//! test here uses signatures that are individually valid; the attack is on
//! the *sequence*, and the sequence is what a narrative is made of.

use aip_airi::*;

mod support;
use support::*;

#[test]
fn an_untouched_chain_is_intact() {
    let a = agent("agent-1");
    let chain = signed_chain(&a, EXEC_A, 5);
    match verify_event_chain(&chain, &a.public_key) {
        ChainReport::Intact(c) => {
            assert_eq!(c.len, 5);
            assert_eq!(c.execution_id, EXEC_A);
            assert_eq!(c.agent_id, "agent-1");
            assert_eq!(c.head, chain[4].event_hash());
        }
        ChainReport::Defective(d) => panic!("an untouched chain was rejected: {d:?}"),
    }
}

#[test]
fn a_replayed_event_is_detected() {
    // The agent re-sends event 2 to pad the record. Its signature is genuine.
    let a = agent("agent-1");
    let chain = signed_chain(&a, EXEC_A, 4);
    let replayed = vec![
        chain[0].clone(),
        chain[1].clone(),
        chain[2].clone(),
        chain[2].clone(),
        chain[3].clone(),
    ];
    assert_eq!(
        verify_event_chain(&replayed, &a.public_key),
        ChainReport::Defective(ChainDefect::SequenceDuplicate { sequence: 2 }),
        "SECURITY: a replayed event was accepted into the chain"
    );
}

#[test]
fn a_dropped_event_is_detected() {
    // The agent omits the event describing the tool call it does not want
    // examined. Every remaining signature is valid.
    let a = agent("agent-1");
    let chain = signed_chain(&a, EXEC_A, 5);
    let dropped = vec![
        chain[0].clone(),
        chain[1].clone(),
        // chain[2] withheld
        chain[3].clone(),
        chain[4].clone(),
    ];
    assert_eq!(
        verify_event_chain(&dropped, &a.public_key),
        ChainReport::Defective(ChainDefect::SequenceGap { after: 1, found: 3 }),
        "SECURITY: a withheld event left no trace"
    );
}

#[test]
fn dropping_the_last_event_is_not_detectable_and_that_is_documented() {
    // The honest limit of a chain: truncation at the head leaves an intact
    // prefix. Nothing in the chain itself can distinguish "the run ended
    // here" from "the rest was withheld". Only an observer, or a signed
    // completion the verifier insists on, closes this.
    let a = agent("agent-1");
    let chain = signed_chain(&a, EXEC_A, 5);
    let truncated = &chain[..3];
    assert!(
        matches!(
            verify_event_chain(truncated, &a.public_key),
            ChainReport::Intact(_)
        ),
        "a prefix of a valid chain is a valid chain — this is a known limitation, \
         recorded so nobody mistakes chain integrity for completeness"
    );
}

#[test]
fn reordering_is_detected() {
    let a = agent("agent-1");
    let chain = signed_chain(&a, EXEC_A, 4);
    let reordered = vec![
        chain[0].clone(),
        chain[2].clone(),
        chain[1].clone(),
        chain[3].clone(),
    ];
    assert!(
        matches!(
            verify_event_chain(&reordered, &a.public_key),
            ChainReport::Defective(ChainDefect::SequenceGap { .. })
                | ChainReport::Defective(ChainDefect::SequenceOutOfOrder { .. })
        ),
        "SECURITY: a reordered chain verified"
    );
}

#[test]
fn the_verifier_does_not_sort_its_way_out_of_a_reordering() {
    // Guard against a "helpful" future edit that sorts by sequence before
    // checking. Sorting turns the attack above into a pass.
    let a = agent("agent-1");
    let chain = signed_chain(&a, EXEC_A, 3);
    let swapped = vec![chain[0].clone(), chain[2].clone(), chain[1].clone()];
    assert!(
        !matches!(
            verify_event_chain(&swapped, &a.public_key),
            ChainReport::Intact(_)
        ),
        "SECURITY: the chain verifier sorted the input and hid a reordering"
    );
}

#[test]
fn splicing_an_event_from_another_execution_is_detected() {
    let a = agent("agent-1");
    let mut chain = signed_chain(&a, EXEC_A, 3);
    let other = signed_chain(&a, EXEC_B, 3);
    // Same agent, valid signature, right sequence number — wrong run.
    chain[1] = other[1].clone();
    assert!(
        matches!(
            verify_event_chain(&chain, &a.public_key),
            ChainReport::Defective(ChainDefect::ExecutionMismatch { .. })
                | ChainReport::Defective(ChainDefect::PrevHashMismatch { .. })
        ),
        "SECURITY: an event from another execution was spliced in undetected"
    );
}

#[test]
fn splicing_an_event_from_another_agent_is_detected() {
    let a = agent("agent-1");
    let b = agent("agent-2");
    let mut chain = signed_chain(&a, EXEC_A, 3);
    let theirs = signed_chain(&b, EXEC_A, 3);
    chain[1] = theirs[1].clone();
    assert!(
        !matches!(
            verify_event_chain(&chain, &a.public_key),
            ChainReport::Intact(_)
        ),
        "SECURITY: another agent's event was spliced into this agent's chain"
    );
}

#[test]
fn renumbering_after_a_deletion_is_caught_by_the_hash_link() {
    // The interesting attack: delete event 2 and renumber 3→2, 4→3 so the
    // sequence is contiguous again. Sequence numbers alone would pass. The
    // prev_event_hash link is what catches it.
    let a = agent("agent-1");
    let chain = signed_chain(&a, EXEC_A, 4);
    let mut forged = vec![chain[0].clone(), chain[1].clone()];
    let mut renumbered = chain[3].clone();
    renumbered.sequence = 2;
    // Re-sign so this is purely a test of the chain rule, not of the signature.
    forged.push(resign(&a, renumbered));
    assert_eq!(
        verify_event_chain(&forged, &a.public_key),
        ChainReport::Defective(ChainDefect::PrevHashMismatch { sequence: 2 }),
        "SECURITY: a deletion hidden by renumbering was not caught"
    );
}

#[test]
fn a_chain_must_start_at_zero_with_a_zero_genesis() {
    let a = agent("agent-1");
    let chain = signed_chain(&a, EXEC_A, 4);
    assert_eq!(
        verify_event_chain(&chain[1..], &a.public_key),
        ChainReport::Defective(ChainDefect::DoesNotStartAtZero { first: 1 }),
        "SECURITY: a chain beginning mid-run was accepted as complete"
    );

    let mut fake_genesis = chain[0].clone();
    fake_genesis.prev_event_hash = [0x5; 32];
    let fake_genesis = resign(&a, fake_genesis);
    assert_eq!(
        verify_event_chain(&[fake_genesis], &a.public_key),
        ChainReport::Defective(ChainDefect::GenesisNotZero)
    );
}

#[test]
fn an_empty_run_is_a_defect_not_an_intact_chain() {
    let a = agent("agent-1");
    assert_eq!(
        verify_event_chain(&[], &a.public_key),
        ChainReport::Defective(ChainDefect::Empty),
        "an empty chain must not read as 'nothing went wrong'"
    );
}

#[test]
fn an_event_with_a_broken_signature_fails_the_chain() {
    let a = agent("agent-1");
    let mut chain = signed_chain(&a, EXEC_A, 3);
    chain[1].emitted_at_ms += 1; // signature no longer covers the event
    assert_eq!(
        verify_event_chain(&chain, &a.public_key),
        ChainReport::Defective(ChainDefect::EventUnverified { sequence: 1 })
    );
}

#[test]
fn a_verified_chain_cannot_be_constructed_by_a_caller() {
    // `VerifiedChain` has a private field, so the only way to obtain one is
    // to pass `verify_event_chain`. This test documents the property; the
    // compiler enforces it. Uncommenting the struct literal below is a
    // compile error (E0451: field `_seal` is private), which is the point.
    let a = agent("agent-1");
    let chain = signed_chain(&a, EXEC_A, 2);
    let verified = verify_event_chain(&chain, &a.public_key);
    assert!(matches!(verified, ChainReport::Intact(_)));

    // let forged = VerifiedChain { _seal: (), execution_id: EXEC_A, ... };
}
