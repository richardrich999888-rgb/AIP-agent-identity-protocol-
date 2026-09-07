# ADR-007 — Vertical Profile Composition and Deferred Extraction

**Status** ACCEPTED
**Date** 2026-09-07
**Branch** `claude/codebase-production-readiness-wm6idp`
**Baseline** `2c79363`
**Related** ADR-005 (UAS), ADR-006 (robotics)

---

## Context

There are now two vertical profiles — `aip-uas` (Skill 23) and `aip-robotics`
(Skill 24) — and the plan names four more: industrial, space, enterprise, and a
conformance profile above them. Both existing verticals independently implement
three generic rules:

1. **Agreement never raises a ceiling.** `ceiling_after_agreement` returns the
   base, for any count, and contains no arithmetic.
2. **A state claim never outruns its evidence tier.** `assertable(claimed,
   available)` may only echo or weaken, never strengthen or substitute.
3. **Independence without a mechanism establishes nothing.** A source outside
   the subject with no implemented `SourceMechanism` is nobody observing.

They are small — a few lines each — and they are the rules everything else in a
profile rests on. Duplicated without a guard, they will diverge, and the
divergence will be discovered by whichever vertical is audited last.

## The decision

**Duplicate now; extract at the third vertical; guard the interval with a
cross-vertical consistency test.**

`aip-robotics/tests/cross_vertical.rs` drives both profiles through the same
questions and asserts identical answers: ceiling invariance under agreement at
every base and every count, conflict never resolved, the echo-or-weaken rule
over the full product of states and tiers, the physical tier unreachable in
both, independence-without-mechanism establishing nothing in both, and a
signature moving no occurrence answer in either. It also asserts the two action
namespaces are disjoint and that the two profiles occupy the same
`ProfileKind::Environment` slot under different ids.

When the third vertical arrives, the extraction should happen and this test
should be deleted — its properties belong to the extracted crate's own suite.

## Why not extract now

**Because it would mean editing Skill 23.** The Skill 24 brief forbids
redesigning Skills 17–23, and refactoring `aip-uas` to consume a new shared
crate is a redesign of Skill 23 however small the diff. The constraint is
correct: a completed, validated skill should not be reopened to serve the
convenience of the next one.

**Because two instances is too few.** The rule of three exists for a reason.
UAS and robotics look similar because they are both embodied and both
sensor-rich; an enterprise profile has no sensors, no platform and no physical
effect, and factoring a "profile kit" out of two embodied verticals would
produce an abstraction shaped like embodiment that the third vertical then has
to work around. The third instance is where the genuinely common shape becomes
visible.

**Because the guard is cheap and the extraction is not.** A consistency test is
nine assertions in one file. An extraction touches two shipped crates, their
manifests, their public APIs and two validated test suites.

## Alternatives rejected

**Extract a shared `aip-profile-kit` immediately.** The right answer eventually
and the wrong answer now, for the three reasons above.

**Make `aip-robotics` depend on `aip-uas`.** Grotesque: it would make every
robot deployment link an aviation profile, and it would make Skill 23 a
dependency of Skill 24 rather than a sibling. Verticals must compose beside one
another, not on top.

**Accept the duplication with no guard, and rely on review.** This is what
produces two profiles that disagree about whether corroboration establishes
anything, discovered in an audit two skills later. Review is not a mechanism.

**Move the three rules into the generic core.** Superficially attractive and
wrong: the core has no notion of a "source" or a "state claim", both of which
are profile-layer concepts. Pushing them down would put vertical vocabulary
into the accountability core, which is the schema fork every ADR from 003
onward exists to prevent.

## What this decision does not settle

**Where the extracted crate should sit.** Beside the profiles, depending on
`aip-observation` and nothing else, is the obvious shape — but which of the
three rules generalise and which turn out to be embodiment-specific is exactly
what the third vertical will reveal.

**Whether the conformance skill changes the answer.** A conformance profile
that has to compare verticals against one another may want the shared crate to
exist first. That is a reason to revisit this at that point, not now.
