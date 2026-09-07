# ADR-009 — Profile-Kit Extraction, Deferred Again, on Evidence

**Status** ACCEPTED
**Date** 2026-09-07
**Branch** `claude/skill-25-implementation-xbz0t3`
**Baseline** `12767ea`
**Related** ADR-007 (vertical profile composition — this ADR answers its open
question and supersedes its trigger condition), ADR-005, ADR-006, ADR-008

---

## Context

ADR-007 recorded a deliberate duplication. `aip-uas` and `aip-robotics` each
implement three generic rules:

1. **Agreement never raises a ceiling.**
2. **A state claim never outruns its evidence tier**, and may only echo or
   weaken.
3. **Independence without a mechanism establishes nothing.**

It deferred extracting them into a shared crate, guarded the interval with
`aip-robotics/tests/cross_vertical.rs`, and named the trigger explicitly:

> When the third vertical arrives, the extraction should happen and this test
> should be deleted — its properties belong to the extracted crate's own suite.

Skill 25 is the third vertical. This ADR is what the trigger condition
produced.

## The decision

**Defer the extraction again, on new evidence rather than on the old argument;
replace the two-vertical guard with a three-vertical one; and move the trigger
from "the third vertical" to "the first non-embodied vertical."**

`aip-industrial/tests/cross_vertical.rs` drives all three profiles through the
same questions and asserts identical answers: ceiling invariance under
agreement at every base and every count, conflict never resolved, echo-or-weaken
over the full product of states and tiers in all three, the physical tier
unreachable in all three, the evidence ladders ordered identically rung for
rung, independence-without-mechanism establishing nothing in all three, and a
signature moving no occurrence answer in any of them. It adds three structural
properties the two-way test could not check: three ids in one profile slot,
three disjoint action namespaces, and four distinct commitment parameter keys.

`aip-robotics/tests/cross_vertical.rs` is left exactly as Skill 24 shipped it.
A completed, validated skill is not reopened to serve the next one's tidiness —
which is the same principle ADR-007 invoked when it declined to edit Skill 23.
The industrial file is a strict superset, so the robotics file is now redundant
coverage rather than the guard, and deleting it can happen when the extraction
does.

## Why the extraction is still wrong now

**ADR-007's own reasoning applies to this third vertical.** It said:

> an enterprise profile has no sensors, no platform and no physical effect, and
> factoring a "profile kit" out of two embodied verticals would produce an
> abstraction shaped like embodiment that the third vertical then has to work
> around. The third instance is where the genuinely common shape becomes
> visible.

The premise was that the third instance would be *differently shaped*. It is
not. Industrial and critical-edge autonomy is a third **embodied** vertical: it
has instruments, a platform, actuators and a physical effect, and its chain is
the robotics chain with different nouns — eight rungs, two observable, the rest
about devices and a world. Skill 26 (disconnected space autonomy) is embodied
too. Skill 27 (enterprise autonomy) is the first that is not.

So the rule of three has been satisfied three times **within one shape**, and
an abstraction extracted now would be an embodiment-shaped abstraction with
three confirming instances and no disconfirming one. That is precisely the
abstraction ADR-007 predicted the enterprise profile would have to work around;
having three instances of it rather than two makes it more entrenched, not
better founded.

**What the third vertical actually revealed, which is the evidence ADR-007
asked for.** Its open question was "which of the three rules generalise and
which turn out to be embodiment-specific". The answer, from three instances:

| rule | generalises? | evidence |
|---|---|---|
| agreement never raises a ceiling | **yes, unconditionally** | stated identically in three crates; depends on nothing domain-specific; the industrial version's argument (a controller-computed vote is the subject reporting again) is a new argument for the same rule |
| echo-or-weaken over an evidence ladder | **yes, and the ladder generalises too** | all three ladders have four rungs with the same four names, the same order, and the same top rung unreachable — which the two-vertical test could not have established, because two points define any line |
| independence without a mechanism establishes nothing | **partly** | the *rule* generalises; the thing it ranges over does not. UAS and robotics ask it of a sensor. Industrial asks it of a sensor **and** of a protocol exchange, where the confounder is message authentication rather than sensor placement, and the answer had to be re-derived rather than reused |

The third row is the finding. A shared crate extracted from UAS and robotics
would have offered a `Source`-shaped API, and the industrial profile's
protocol-interaction case would have been the first caller to not fit it —
which is the "work around" failure mode, arriving one vertical earlier than
ADR-007 expected.

**A third confirming instance is not the same as a disconfirming one.** The
value of extraction is that a change to a rule reaches every vertical. The risk
is that the extracted shape constrains a vertical that does not share it. Three
embodied verticals raise the first and leave the second entirely untested.

## Alternatives rejected

**Extract `aip-profile-kit` now, as ADR-007's trigger says.** The trigger was
written before its own premise could be checked. Following it mechanically
would honour the letter of ADR-007 against the reasoning in the same document,
and would require editing two shipped, validated crates to serve an abstraction
whose shape the fourth vertical is likely to change.

**Delete `aip-robotics/tests/cross_vertical.rs` now, as ADR-007 says.** It is
redundant, not wrong. Deleting it is a change to Skill 24's validated suite for
no gain; it costs one file of duplicated assertions to leave it, and it goes
when the extraction goes.

**Keep the guard in `aip-robotics` and add the industrial profile to it.** This
would make Skill 24's crate depend on Skill 25's, so the newest vertical would
be a dependency of an older one, and every future vertical would reopen Skill
24's test suite. The guard belongs with the newest vertical, which is the one
whose arrival could break it.

**Extract only rules 1 and 2, which do generalise.** Tempting, and worse than
either alternative: it produces a shared crate that covers the two rules nobody
has ever got wrong and leaves the third — the one that already needed
re-derivation — duplicated and unguarded.

**Accept the duplication with no guard and rely on review.** ADR-007's answer
still holds: review is not a mechanism.

## Migration impact

None. No crate's public API changes, no dependency is added to a shipped
vertical, and the new test file is the only thing that did not exist before.

## What this decision does not settle

**Where the extracted crate should sit, when it happens.** Beside the profiles,
depending on `aip-observation` and nothing else, remains the obvious shape.

**Whether the extracted API should range over a "source" or over something
more general.** The industrial protocol case says it should be more general,
and one instance is not enough to say what.

**Whether the conformance skill changes the answer.** Skill 28 has to compare
verticals against one another and may want the shared crate to exist first.
That is a reason to revisit this at Skill 27 or 28 — the first non-embodied
vertical, or the first cross-vertical consumer, whichever arrives first — and
that, not "the third vertical", is now the trigger.
