# ADR-011 — Five Verticals, and What the Non-Embodied One Showed

**Status** ACCEPTED
**Date** 2026-09-07
**Branch** `claude/skill-25-implementation-xbz0t3`
**Baseline** `742517c`
**Related** ADR-007 (deferred the profile-kit extraction at two verticals),
ADR-009 (deferred it again at three and moved the trigger to *the first
non-embodied vertical*), ADR-012 (space), ADR-013 (enterprise)

---

## Context

ADR-007 recorded a deliberate duplication: `aip-uas` and `aip-robotics` each
implemented three generic rules, and extracting them into a shared crate was
deferred with a two-way consistency guard in the meantime.

ADR-009 revisited it at the third vertical, found that industrial was a third
*embodied* vertical rather than a differently-shaped one, deferred again on that
evidence, widened the guard to three, and set an explicit trigger:

> the first non-embodied vertical or the first cross-vertical consumer,
> whichever arrives first.

**Skill 27 is the first non-embodied vertical.** This ADR is what the trigger
produced.

## The finding

Four properties looked universal across the embodied verticals. Three of them
are. The fourth is not.

| property | UAS | robotics | industrial | space | **enterprise** |
|---|---|---|---|---|---|
| agreement never raises a ceiling | ✓ | ✓ | ✓ | ✓ | **✓** |
| a state claim may only echo or weaken over an ordered ladder | ✓ | ✓ | ✓ | ✓ | **✓** |
| independence without an implemented mechanism establishes nothing | ✓ | ✓ | ✓ | ✓ | **✓** |
| **the top evidence tier is unreachable** | ✓ | ✓ | ✓ | ✓ | **✗** |

**Enterprise's top tier is reachable.** A file write is
`SourceMechanism::Fanotify` producing an `ObservationClass::FilesystemEffect`
record; a socket is `ProcNetTable`. Those are implemented mechanisms observing
real effects, so `EnterpriseEvidence::LocalEffectObserved` is a tier a
deployment actually reaches.

What enterprise cannot reach is the **remote** effect — a row in a database on
another host, a consequence at the far end of an API call, a control-plane
action taking hold. That is outside every mechanism, exactly as a valve is. So
the constraint is a property of the *resource*
(`EnterpriseResource::EffectLocality`), not of the ladder.

Four embodied verticals in a row made an embodiment-specific property look like
a rule. It was not one. That is precisely the disconfirming instance ADR-009
said was missing, and it arrived exactly where ADR-009 predicted it would.

## Decision 1 — the guard becomes two guards, not one wider one

`aip-enterprise/tests/cross_vertical.rs` has two sections:

- **Universal.** The three rules, asserted over all five verticals.
- **Embodiment-specific.** The top tier is asserted unreachable for the four
  embodied verticals **and explicitly reachable for enterprise**, so an edit
  that quietly flipped either direction fails here.

Writing the second section as a positive assertion rather than an omission is
the point. A guard that simply left enterprise out would let a future change
make its tier unreachable — a semantic weakening dressed as consistency — with
nothing to catch it.

`aip-robotics/tests/cross_vertical.rs` and
`aip-industrial/tests/cross_vertical.rs` are left exactly as they shipped. A
completed, validated skill is not reopened to serve the next one's tidiness,
which is the principle ADR-007 invoked for Skill 23 and ADR-009 for Skill 24.
They are now redundant coverage; they go when the extraction does.

## Decision 2 — the extraction is owed, and this session does not perform it

The evidence is in and it supports extracting the three universal rules. This
session does not do it, for one reason:

**It is not what was gated.** The extraction edits five shipped crates. Riding
it along with two skill implementations, each of which has its own acceptance
gate, would put five validated suites at risk inside a change gated on something
else, and would violate *"implement the smallest compatible change"* in both
skills' governing discipline.

It belongs to **Skill 28**, which is the cross-vertical conformance skill and
therefore both the first cross-vertical *consumer* and the natural owner of a
shared crate. The extraction is recorded here as owed rather than deferred: the
question ADR-007 asked has an answer, and the answer is yes for three rules and
no for the fourth.

## Decision 3 — what the extracted crate must and must not contain

Recorded now, while the evidence is fresh:

**Must contain** the three universal rules, over a vocabulary that does not
assume a sensor. The industrial profile already had to apply the independence
rule to a *protocol exchange* and the enterprise profile to a *cloud audit
log*; a `Source`-shaped API extracted from two embodied verticals would have
had both as non-fitting callers.

**Must not contain** the evidence ladder's top tier, the notion of a physical
effect, or anything else that assumes embodiment. Those differ across the five
and the difference is real.

## Alternatives rejected

**Extract now, in this session.** Rejected under Decision 2. The engineering is
understood; the gating is wrong.

**Widen the existing three-way guard in place.** It lives in `aip-industrial`,
so widening it would make Skill 25's crate depend on Skills 26 and 27 — the
newest verticals becoming dependencies of an older one, and every future
vertical reopening a shipped test suite. The guard belongs with the newest
vertical, which is the one whose arrival could break it.

**Name enterprise's top tier `PhysicallyObserved` so the five ladders match.**
The tempting one, and the worst. It would have made the five look identical and
made one of them lie, and it would have hidden the finding this ADR exists to
record.

**Delete the two older cross-vertical files now.** Redundant is not wrong.
Deleting them edits validated suites for no gain.

## What this decision does not settle

**Where the extracted crate sits.** Beside the profiles, depending on
`aip-observation` and nothing else, remains the obvious shape.

**Whether a sixth vertical would move the line again.** Skills 28–30 are
conformance, threat modelling and a defence deployment rather than new
verticals, so on the current plan the five are the set. If a sixth arrives, the
table in §"The finding" is the thing to extend before extracting anything.
