# ADR-014 — The Conformance Program, and the Profile Kit It Did Not Extract

**Status** ACCEPTED
**Date** 2026-09-08
**Branch** `claude/skill-25-implementation-xbz0t3`
**Baseline** `b5c401a`
**Related** ADR-007 (deferred the profile-kit extraction at two verticals),
ADR-009 (deferred it again at three, and moved the trigger), ADR-011 (fired
the trigger and assigned the extraction to Skill 28)

---

## Context

ADR-011 §Decision 2 said this, and it was right to:

> It belongs to **Skill 28**, which is the cross-vertical conformance skill and
> therefore both the first cross-vertical *consumer* and the natural owner of a
> shared crate. The extraction is recorded here as owed rather than deferred.

Skill 28 has now been implemented. **It did not perform the extraction**, and
this ADR is the reason, written now rather than left for a reader to infer
from an absence.

## Decision 1 — the conformance program is built, and it is not the kit

`aip-conformance` states the universal invariant set **once** and applies it to
**every** domain from one place. That is the property ADR-007 wanted when it
first noticed the duplication: one statement of a rule, not five.

But it achieves it at the *conformance* layer, not the *production* layer. The
five profile crates still each contain their own local statement of the three
universal rules. Nothing in them changed.

So the duplication ADR-007 recorded is now **covered by a normative check**
without being **removed**. Those are different things and this ADR does not
conflate them.

## Decision 2 — the production extraction is still not done

Three reasons, in order of weight.

**It is not what Skill 28 asks for.** Its required work is an invariant set, a
matrix, substitution tests, version tests and an artifact generator. Its
acceptance gate is that all supported domains pass the same core invariants and
that a new domain cannot silently weaken them. None of that requires editing a
profile crate, and all of it is now delivered.

**The same rule that deferred it still applies.** Skill 28's governing
discipline carries *"implement the smallest compatible change"* — the identical
clause ADR-011 invoked when it declined to ride the extraction along with two
skill implementations. Riding it along with a conformance program would put
five validated suites at risk inside a change gated on something else, which is
the failure ADR-011 was avoiding. The gating did not improve by being
reassigned.

**The value moved.** ADR-007's argument for extracting was that five copies of
a rule are five places for them to diverge. The conformance program now fails
if they diverge — `tests/substitution.rs` and the five-way guard in
`aip-enterprise` both check the rules hold everywhere. Divergence is now
*detected*, which was the whole risk. Extraction would additionally make
divergence *impossible*, which is better, but it is no longer urgent.

## Decision 3 — the debt is recorded as unassigned, not as discharged

This is the part that matters, and the reason this ADR exists rather than a
sentence in a report.

After Skill 28, the profile-kit extraction has **no assigned skill**. Skills 29
and 30 are a threat model and a defence deployment; neither is a natural owner,
and inventing an owner for a piece of work nobody has scheduled is how debt
becomes invisible.

So the position is stated plainly:

- The extraction remains **owed**.
- Its trigger fired at Skill 27 and has not been answered.
- It is now **unassigned**, and assigning it is a decision for the
  repository's owner rather than for the next skill that happens to touch a
  profile crate.
- ADR-011 §Decision 3 already records what the extracted crate must and must
  not contain, so whoever takes it does not start from nothing.

## What would change the calculus

Any of these, and the extraction should be scheduled rather than recorded:

- **A sixth vertical.** Six copies is where the guard's own cost — every new
  vertical reopens a shipped test suite to widen it — exceeds the extraction's.
- **A divergence the guard catches.** The first time the five-way guard fails
  because two profiles disagree, the argument in Decision 2 is over: detection
  worked, and removal is then the cheaper fix than repeated detection.
- **A consumer outside the profiles.** ADR-011's trigger named "the first
  cross-vertical consumer". The conformance program is one, and it consumes the
  profiles' *public API* rather than a shared rule crate. A consumer that needed
  the rules themselves would be a different matter.

## Alternatives rejected

**Extract now, alongside the conformance program.** Rejected under Decision 2.
The engineering is understood and recorded; the gating is wrong for the third
time, and doing it badly under the wrong gate is worse than doing it later
under the right one.

**Declare the debt discharged because the conformance program covers it.**
Rejected, and it was the tempting one. Covered is not removed. A report that
said Skill 28 discharged ADR-011 would be the kind of quiet overclaim this
repository's discipline exists to prevent — and the next reader would have no
way to tell that five copies of a rule still exist.

**Assign it to Skill 29 or 30 to keep it owned.** Rejected. Neither is a
natural owner, and an assignment made for tidiness is one that gets deferred
again on arrival — which is exactly the pattern ADR-007, ADR-009 and ADR-011
already describe three times over. Better to say it is unassigned and let that
be visible.
