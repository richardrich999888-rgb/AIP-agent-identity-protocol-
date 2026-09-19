# ADR-012 — Disconnected Evidence and the Continuity Boundary

**Status** ACCEPTED (scope: the space/disconnected profile's semantics only)
**Date** 2026-09-07
**Branch** `claude/skill-25-implementation-xbz0t3`
**Baseline** `742517c`
**Related** ADR-011, ADR-003 (observation class boundary — depended on,
unchanged), ADR-001 (autonomous containment / continuity — depended on,
unchanged), ADR-005, ADR-006, ADR-008

---

## Context

Skill 26 extends accountability into environments where the verifier cannot see
the subject for hours or weeks. Three things about that are genuinely new and
one is a trap.

**New:** evidence is collected with nobody watching, moved later, and verified
later still. **New:** the clocks multiply — the vehicle's, the ground station's,
the decision point's. **New:** contacts deliver bundles in whatever order the
orbit allows.

**The trap:** every one of those makes it easier to read *absence* as
*non-occurrence*, and a disconnected mission is mostly absence.

## Decision 1 — the continuity authority is `aip-observe`, unchanged

`ObserverLedger` already decides replay, fork, rollback and gap; already latches
`ContinuityStatus::GapObserved` so a later contiguous batch does not restore
`Verified`; and already quarantines permanently on a proven fork. Every
requirement in Skill 26's continuity section was already implemented.

`aip-space` therefore adds an **arrival and reassembly layer above it**, and
nothing else. `SegmentLedger` stages bundles, offers segments in sequence order,
and propagates every fault the ledger returns without repair. There is no second
ledger, no second fault vocabulary and no path that turns a fault into a success
— `tests/no_second_architecture.rs` asserts the crate cannot even name the
types it would need to build one.

**Why a fresh `ObserverLedger` after a gap is not a second ledger.** A chain
cannot link across evidence nobody supplied: the segment after a gap declares a
`prev_head` the ground station never received, so offering it produces a
`HeadMismatch` — true, and less useful than recording the gap. A new run under
the same authority, with the gap latched across the boundary, says what actually
happened: two verified runs that cannot be linked to each other.

## Decision 2 — four clocks, and only one bounds an event

| clock | signed by | bounds the event? |
|---|---|---|
| event time | nobody | **no — not established** |
| observation time | the onboard collector | yes, from above only |
| receipt time | the ground station | no — about the verifier |
| verification time | the ground station | no — about the verifier |

`ObservationRecord::attested_at_ms` already carries the second and already
documents that an event inside cannot have happened after it. Receipt and
verification are facts about the ground station, which the vehicle cannot sign
and does not know, so `DelayedEvidence` **wraps** the record rather than
extending it. No signed field changed.

`DelayedEvidence::latency_ms` is reported because operators need it and feeds no
decision. Evidence arriving in a second says exactly as much about event time as
evidence arriving in a month, and `event_time_established()` is `false` for both.

`CommandTiming` carries six distinct moments for a delayed ground command and
computes no order between the onboard and ground clocks. A vehicle whose clock
is wrong — or made to report a wrong one — produces an execution timestamp
preceding its authorization, and a system that "corrects" that has erased the
finding.

## Decision 3 — a bundle is a container, and containers are not evidence

`StoreAndForwardBundle` carries **one contiguous run**. A bundle with a hole in
it is two bundles pretending to be one, and accepting it would let the sender —
the party under scrutiny — choose which gaps a verifier notices.

It adds **no NEXORA leaf kind**. Its contents are already committable as
`AttestedBatch`, `SignedHealth`, `Expectation` and `Reconciliation` leaves, and
`LeafKind::ALL.len() == 9` is asserted in this crate's own integration test.
Offline reconstruction flows through the existing verifier: the mission test
serialises a real commitment-log proof, parses it on the ground and verifies it
with `aip_nexora::verify_proof` against anchors provisioned separately.

`BundleLedger` keys on the bundle digest, so a bundle re-presented at a later
contact is refused — the discipline `aip-nexora::ProofLedger` already applies to
proofs, one layer down, and outside verification for the same reason:
verification stays a pure function, duplicate detection is inherently stateful.

## Decision 4 — a late arrival does not rewind the chain

A bundle covering sequences the chain has already passed is retained and
recorded as `SegmentOutcome::LateArrival`. It does **not** close a gap it would
have filled.

This is the sharpest judgement call in the profile and it is deliberate.
Admitting it would mean reordering attested history after the fact — the ground
station would have to say that a chain it had already extended now runs through
different bytes. The evidence is kept, the gap stays open, and
`completeness_claimable()` is false while any late arrival is outstanding.

## Decision 5 — the link state grants nothing

`LinkState::changes_evidential_standing()` is `false` for every state, and
`SpaceExecutionProfile::link_state_changes_capability()` is `false` for every
state. A spacecraft out of contact is operating normally, not degraded; a
reconnection is a transition, not a repair; and whatever was unobserved during
an outage stays unobserved.

`DegradedCarrier` is a state of its own because "we could talk and could not
send evidence" is a real operational fact, and the asymmetry — commands may flow
where evidence cannot — is worth recording rather than folding into
`Disconnected`.

## Alternatives rejected

**Add `receipt_at_ms` to `ObservationRecord`.** A signed-field change to carry a
number the signer cannot know. `DelayedEvidence` wraps instead.

**Add a `SourceMechanism` for a star tracker or a radiometric range.** The
schema fork ADR-003 exists to prevent, refused for the fifth time.

**Add a `LeafKind::StoreAndForwardBundle`.** A container is not evidence, and
nine frozen leaf kinds are asserted by four tests across the workspace.

**Let a late-arriving bundle close the gap it covers.** Rejected under Decision
4. Operationally attractive and epistemically wrong.

**Infer that nothing happened during an unfilled gap.**
`SegmentLedger::non_occurrence_admissible()` takes no arguments and returns
`false`, so there is no state to parameterise into optimism, and
`GroundConclusion::asserts_non_occurrence()` is `false` for all four variants.

**Treat a healthy reconnection as restoring continuity.** The single most
available mistake in this domain, refused under Decision 5 and pinned by
mutation S9.

## What this decision does not settle

**Whether a gap can ever be closed.** Today it cannot, by design. A protocol in
which the ground station rewinds to a checkpoint and replays from it is
conceivable and would need its own ADR, because it changes what an attested
chain means.

**Clock discipline.** Nothing here models a synchronised time source. If a
deployment has one — a GNSS-disciplined onboard clock with its own attestation
— the cross-clock ordering `CommandTiming` refuses could become establishable,
and that would be a new mechanism, not a new profile method.

**Real spacecraft.** Nothing in this profile has been validated against
orbital hardware, a real radio, or real link timing. The acceptance gate is a
**simulated** disconnected mission, and the crate's own test module says so.
