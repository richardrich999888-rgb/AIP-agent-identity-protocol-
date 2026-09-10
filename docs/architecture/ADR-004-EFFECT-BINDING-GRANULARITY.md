# ADR-004 — Effect Binding Granularity

**Status** ACCEPTED (scope: Skill 21's abstraction only)
**Date** 2026-09-07
**Branch** `claude/codebase-production-readiness-wm6idp`
**Baseline** `c922bc7`
**Related** ADR-003 (observation class boundary), ADR-002 (hardware attestation — **PROPOSED**, unchanged by this decision)

---

## Context

Skill 21 joins two models that were built separately and never connected:

- `aip-execution` (Skill 18) — what the *agent* says it asked for and what its
  call returned. Self-reported, all of it.
- `aip-observation` (Skill 20) — what an anchored *observer* recorded, with a
  class and a computed evidence ceiling.

The join needs one thing neither side provides: a way to say that a particular
observation is evidence about a particular **effect**.

## The problem

`ObservationCorrelation` binds an observation to `(system_id, execution_id,
boot_id, decision_id)`. That is execution granularity. It does **not** carry a
parameter commitment, and it cannot, because no mechanism in this workspace
produces one:

| mechanism | what it knows | what it does not know |
|---|---|---|
| `ProcfsPoll`, `PidFdAnchored` | a process instance and its executable | which requested effect it corresponds to |
| `Fanotify` | a path was closed for write | which of several writes the agent intended |
| `SockSendTracepoint` | bytes accepted for a socket | which request they belong to |
| `WireTapAfPacket` | a frame crossed a device | not even the process |

An execution that requests "open valve A" and "open valve B" and produces one
observed device write has **one observation and two candidate effects**. Nothing
in the observation says which.

## The decision

**Represent the ambiguity in the type system rather than resolving it.**

`EffectBinding` has two states:

| state | condition | meaning |
|---|---|---|
| `Exact` | the execution requested exactly one effect | the observation can only be about this effect |
| `ExecutionOnly { candidate_effects }` | it requested more than one | the observation is about the execution; which effect is unknown |

`EffectAssessment::establishes_named_effect()` requires **both** a corroborating
finding **and** an `Exact` binding. A corroboration under `ExecutionOnly` is
still reported — it is real evidence that something the execution asked for was
observed — but it is not evidence about the effect it names, and the conjunction
is enforced in one place rather than left to each caller to remember.

## Alternatives rejected

**Attribute to the effect being assessed.** The obvious shortcut and the reason
this ADR exists. It manufactures effect-level attribution out of
execution-level evidence, and it is worst exactly where it matters most: an
execution that fires several actuators is the case where knowing *which one*
moved is the whole question.

**Add a parameter commitment to `ObservationCorrelation`.** The commitment would
have to come from somewhere. The agent is the only party that holds it, so the
field would be agent-authored — a self-reported value inside an
independently-signed record, which is precisely the confusion the observer model
exists to prevent. Rejected on those grounds, not on effort.

**Require single-effect executions.** Pushes the problem to the caller and
would be silently violated by any real autonomous system, which batches.

**Infer from timing.** Ordering observations against requested effects by
timestamp assumes the agent's clock and the collector's clock are comparable at
sub-effect resolution. They are not, and an agent that controls its own
reported times would control the attribution.

## What this decision does not settle

**It does not make effect-level attribution possible.** It makes its absence
visible. A deployment that needs it must supply a mechanism whose observations
carry something the effect can be matched on — a device handle, a command
sequence number, a controller transaction id — and that mechanism does not
exist here. Until it does, multi-effect executions bind at execution
granularity and say so.

**It does not touch `EvidenceStrength` or the reconciler.** `EffectBinding` is
an input alongside the finding; what a verdict makes of an `ExecutionOnly`
corroboration is `aip-reconcile`'s decision, and this ADR does not pre-empt it.

**It does not change ADR-002 or ADR-003.** No hardware mechanism is introduced,
and `ObservationClass::PhysicalEffect` remains representable with no mechanism
behind it — so a physical-effect claim remains unreachable, which is ADR-003's
decision 2 and not weakened here.
