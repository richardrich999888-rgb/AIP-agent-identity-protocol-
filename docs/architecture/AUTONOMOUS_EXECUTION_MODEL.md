# Autonomous Execution Model

**Status** SPECIFICATION — written before implementation.
**Scope** Skill 18. Environment-neutral. No vertical profile is defined here.

---

## 0. What this document adds, and what it must not duplicate

Most of the objects Skill 18 names **already exist**. The inspection was done
first, and the result determines the scope of the work:

| # | Skill 18 object | Existing type | Crate | Action |
|---|---|---|---|---|
| 1 | Execution Intent | — | — | **new** (thin) |
| 2 | Expected Execution | `ExpectedExecution` (DP-signed) | `aip-authorize` | **reuse verbatim** |
| 3 | AI / application claim | `AiriEvent` (agent-signed, chained) | `aip-airi` | **reuse verbatim** |
| 4 | Model invocation | `ModelProvenance` | `aip-airi` | **reuse verbatim** |
| 5 | Tool invocation | `ToolInvocation` | `aip-airi` | **reuse verbatim** |
| 6 | Runtime execution | `ToolReport`, `SubprocessReport` | `aip-airi` | **reuse verbatim** |
| 7 | Process / container | `ProcessInstance`, `ExecutionBinding` | `aip-types` | **reuse verbatim** |
| 8 | Device / platform | `PlatformId`, `HardwareId` | `aip-system` | **reuse verbatim** |
| 9 | **External effect** | — | — | **new — the real gap** |
| 10 | Independent observation | `ObservedExecution`, `AttestedBatch` | `aip-observe` | **reuse verbatim** |
| 11 | Reconciliation | `reconcile_expectation` | `aip-reconcile` | **reuse verbatim** |
| 12 | Proof | `NexoraProof` | `aip-nexora` | **reuse verbatim** |

Nine of twelve exist. Building them again would be the duplication the skill
forbids. So Skill 18 delivers exactly four things:

1. **The stage ladder made explicit and executable** — the ordered epistemic
   boundaries and what each can establish. Today this exists only as prose
   spread across crate documentation, which means nothing checks it.
2. **The external-effect boundary** — genuinely absent. `ObservedEffect` in
   `aip-observe` covers process presence and kernel sockets; there is no model
   of an effect *outside* the host at all.
3. **The runtime-declaration ladder** — declared / selected / observed /
   independently evidenced, as four separate facts none of which implies
   another.
4. **The binding of Skill 17's descriptors into an authoritative artifact**,
   without a new trust anchor. See §3.

---

## 1. The stage ladder

Execution is not one event. It is a sequence of boundaries, each of which a
different party can see, and each of which an attacker at a different position
can forge.

```
 #  stage                       who states it        origin of a statement here
 ─────────────────────────────────────────────────────────────────────────────
 1  ExecutionIntent             operator / tasking   Declared
 2  Authorization               authority chain      Recomputable (signatures)
 3  ExpectedExecution           decision point       Recomputable (DP signature)
 4  AiClaim                     the agent            SelfReported
 5  ModelInvocation             the agent            SelfReported
 6  ToolInvocation              the agent            SelfReported
 7  RuntimeExecution            the agent's runtime  SelfReported
 8  ProcessExecution            OS + observer        IndependentlyObserved
 9  PlatformInteraction         platform / observer  IndependentlyObserved
10  ExternalEffect              a counterparty       IndependentlyObserved
11  IndependentObservation      anchored observer    IndependentlyObserved
12  Reconciliation              the one engine       Recomputable (verdict)
```

`EvidenceOrigin` above is **a static property of the stage**, not a computed
judgement about a record. It says what kind of statement a stage can produce
*by construction*. It is deliberately **not** `EvidenceStrength`: strength is
how certain, is per-record, and is assigned by the reconciler alone. Two axes,
one owner each; the model never computes strength and never asks to.

### The non-collapse rule

Each of these is a distinct claim, and none implies the next:

```
intent  ≠  authorization  ≠  expected execution  ≠  AI claim
        ≠  runtime execution  ≠  independent observation
        ≠  external effect  ≠  proof
```

Stages 4-7 are all authored inside the process under scrutiny. An agent that
is compromised authors all four exactly as a healthy one does. Their value is
that they are *signed and chained* — so they establish authorship and
integrity, and pin what was claimed so a contradiction becomes visible. They
never establish occurrence.

---

## 2. The external-effect boundary

The gap this skill exists to close, and the one place a successful system most
easily lies to itself.

```
RequestedEffect      the agent asked for X            SelfReported
      │                                               "I intended to"
      ▼
RuntimeAction        the software layer did Y and      SelfReported
      │              got a response                    "I called it"
      ▼
EffectEvidence       an independent party observed Z  IndependentlyObserved
      │                                               "someone else saw it"
      ▼
EffectDisposition    what may honestly be said
```

**A 200 response is not an effect.** It establishes that bytes resembling a
success returned to this process. A proxy, a stub, a replayed cassette, a
compromised client library, or a service that acknowledged and then failed all
produce the identical value. `ToolReport` in `aip-airi` already carries this
warning in its own documentation; what has been missing is a type that makes
it impossible to ignore.

### Enforcement, not documentation

`EffectDisposition::Confirmed` is **unconstructible from a `RuntimeAction`
alone**. Its constructor requires an `EffectEvidence`, and `EffectEvidence`
cannot be built from agent-authored material. This is the same pattern
`aip-reconcile` uses for `ActionComparison`'s positive variants: the invariant
lives in the type system, where forgetting it is a compile error rather than a
review miss.

The dispositions:

| Disposition | Meaning | Requires |
|---|---|---|
| `Confirmed` | independent evidence corroborates the requested effect | `EffectEvidence` |
| `Contradicted` | independent evidence disagrees with it | `EffectEvidence` |
| `Unconfirmed` | independent observation ran and did not establish it | evidence path present, nothing found |
| `NotEvaluated` | no independent observation was available | the default |

`Unconfirmed` and `NotEvaluated` are separated for the same reason
`CANNOT_PROVE` exists: "we looked and did not find it" and "we did not look"
are different states, and summing them is how a blind spot becomes a clean
bill of health.

**None of these is a verdict.** They are structural facts about what evidence
exists for one effect, and they are inputs to the reconciler. This model
produces no accusation and no result class.

---

## 3. Signed carrier — the decision

Skill 17 left `AutonomousSystem` and `SystemExecution` unsigned, deliberately.
Skill 18 must say what makes them authoritative, and must not add a signing
key to `aip-system` to make the problem go away — that would be a new trust
anchor.

### What each field's authority already is

The inspection splits cleanly:

| Field | Already carried authoritatively by |
|---|---|
| `agent_id` | `ExpectedExecution` (DP-signed), `AiriEvent` (agent-signed) |
| `execution_id`, `parent_execution_id` | `AiriEvent` (agent-signed, chained) |
| `execution_binding` | `ExpectedExecution` (DP-signed) |
| `decision_id` | `ExpectedExecution` (DP-signed) |
| `system_id`, `platform_id`, `hardware_id`, `mission_id` | **nothing** |

Only the four Skill 17 identifiers are unanchored. So the question narrows to:
*can an existing signer legitimately attest them?*

### The answer: yes, through `ActionParameters`

`ExpectedExecution.parameter_digest` is the decision point's signature over
`ActionParameters` — an **open, key-sorted, domain-separated map** of named
byte strings. Nothing about it is fixed to a particular vocabulary.

A reserved key carrying the `SystemExecution` canonical digest therefore
becomes part of what the decision point signs:

```
ActionParameters {
    …the action's own parameters…,
    "aip.system_execution.v1" → SystemExecution::canonical_bytes() digest
}
        │  digested
        ▼
ExpectedExecution.parameter_digest        ← DP-signed
```

**No new trust anchor. No wire-format change. No new signer.** The decision
point is also the *correct* authority for this: it decides what an agent may
do, and "on which platform, for which mission" is a legitimate part of that
decision rather than a fact bolted on afterwards.

### What this establishes, and what it does not

This is the part that must not be overstated.

- **It establishes** that the decision point *authorized* execution for that
  system, platform, hardware and mission context, and that the context cannot
  be swapped afterwards without breaking the DP signature.
- **It does not establish** that the execution *ran* on that platform or that
  hardware. Authorized ≠ attested ≠ observed. A DP signature over "platform P"
  is a statement about permission, not about physics.

Proving the execution ran where it claims needs hardware attestation
(Skill 19) or independent observation (Skill 20). Both are out of scope here,
and this document does not pretend the binding substitutes for either.

---

## 4. The runtime ladder

Four separate facts about "what ran this". None implies another, and the model
stores them in four fields precisely so that no code can silently promote one
to another.

| Fact | Source | What it means |
|---|---|---|
| `declared` | configuration | what the deployment said would run |
| `selected` | the agent | what the agent says it chose |
| `observed` | the OS / an observer | what a measurement found |
| `evidenced` | an anchored observer | what an attested observation established |

The failure this prevents: a model claiming `runtime: "cuda:0 NVIDIA H100"`
becoming, three layers later, "the execution ran on a GPU". `ModelProvenance`
already labels `accelerator` as self-reported; this makes the ladder the
record's shape rather than a comment.

`model requested ≠ model served ≠ weights loaded ≠ accelerator executed`
remains NOT ESTABLISHED at every rung except `evidenced`, and this skill does
not change that.

---

## 5. Normative reference flow

Each arrow is labelled with what crossing it *is*. No arrow is trusted merely
because the previous one held.

```
Identity                  AIP-ID, derived                        [VERIFICATION]
   │
   ▼  delegation chain, signatures verified                      [VERIFICATION]
Authority
   │
   ▼  decision point adjudicates                                 [DECISION]
ExpectedExecution ────────────────────────────────────── DP-signed
   │
   ▼  the agent says what it did                                 [CLAIM]
AI Claim  (AIRI: model, tool, subprocess)  ───────────── agent-signed, chained
   │
   ▼  the agent's runtime reports                                [CLAIM]
Runtime Execution Claim
   │
   ▼  an anchored observer measures                              [OBSERVATION]
Independent Observation  ─────────────────────────────── observer-signed
   │
   ▼  a counterparty or observer attests the effect              [OBSERVATION]
External Effect Evidence
   │
   ▼  the one engine compares expected with observed             [VERIFICATION]
Reconciliation  ──────────────────────────────────────── engine-produced only
   │
   ▼  policy maps a verdict to a permitted response              [DECISION]
Warrant
   │
   ▼  gates, then possibly an actuator                           [ENFORCEMENT]
Containment
   │
   ▼  export, offline re-derivation                              [PROOF]
NEXORA
```

Two arrows are worth stating explicitly because they are the ones people
assume:

- **AI Claim → Runtime Execution Claim is CLAIM, not OBSERVATION.** Both sides
  are authored inside the process under scrutiny.
- **Runtime Execution Claim → Independent Observation is a boundary, not a
  step.** Nothing carries across it automatically. A claim with no observation
  on the other side stays a claim.

---

## 6. Reconciliation boundary

There remains exactly one reconciliation engine. This model:

- produces **no verdict**, no result class, and no severity;
- computes **no `EvidenceStrength`**;
- feeds the existing reconciler as **input** only.

`aip-execution` does not depend on `aip-reconcile`, `aip-warrant`,
`aip-containment` or `aip-nexora`, and none of them depends on it. As with
Skill 17, that direction is asserted by test rather than documented, because a
comment survives exactly until someone adds a convenient import.

---

## 7. B-3 interaction

Skill 18 does **not** solve B-3 and does not touch its boundary. ADR-001
remains authoritative.

What this model contributes is structure, not evidence. `ADR-001` §Q13
identifies the legitimate future path to a `Proven` workload violation as
*agent-side cryptographic equivocation* — two validly signed, mutually
exclusive statements under one identity and one decision. The stage ladder
makes the places such a contradiction could arise explicit and nameable
(stages 4-7 are all agent-signed and chained), which is what a future evidence
path would need in order to be specified.

Nothing here:

- lowers an evidence threshold,
- bypasses availability semantics,
- manufactures `Proven`,
- treats absence of observation as proof,
- connects containment to AIRI claims.

`EffectDisposition::Confirmed` requiring independent evidence is the same
discipline applied one layer out: a self-report cannot become a confirmation
by passing through a type.

---

## 8. Canonicalization requirements

Every security-relevant object in this model carries:

- an explicit domain tag, distinct per structure;
- a version, refused rather than guessed when unknown;
- prefix-free encoding — length-prefixed variable fields, presence bytes on
  optionals;
- deterministic ordering for set-valued fields.

The test contract is two-sided:

- the same semantic object → the same canonical bytes;
- any difference in security identity or context → different bytes.

Cross-execution, cross-agent, cross-model, cross-framework, cross-platform and
cross-mission separation are all consequences of the second property, and each
is tested individually rather than assumed from the first.

No field that affects authorization or evidence semantics sits outside the
committed preimage, and no bare hash stands in for a complete commitment.

---

## 9. Out of scope

UAS, UGV, robotics, industrial, critical-infrastructure, space and enterprise
profiles (Skills 23-27). Hardware attestation (Skill 19). The full observation
profile (Skill 20). Actuation (Skill 21). The Linux edge reference (Skill 22).
Solving B-3.
