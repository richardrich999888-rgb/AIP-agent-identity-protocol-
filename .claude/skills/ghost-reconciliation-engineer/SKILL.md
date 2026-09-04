---
name: ghost-reconciliation-engineer
description: Build the engine that compares AIP's authorized execution against Sentinel's observed execution and classifies the difference. Use whenever the user mentions reconciliation, expected vs observed, divergence, VERIFIED_EXECUTION, UNATTRIBUTED_EFFECT, PHANTOM_CLAIM, IDENTITY_DIVERGENCE, CANNOT_PROVE, ghost detection, warrants, containment thresholds, or false positives in agent monitoring — and also when they describe the intent, such as deciding whether an execution had authority behind it, or whether to alert versus contain. Consult this before writing comparison or alerting logic, because a reconciliation engine that cannot say "I could not observe this" manufactures accusations and gets switched off in its first production week.
---

# Ghost Reconciliation

Two independently produced records meet here. AIP says what was authorized; the observer
says what was seen. This engine says what the difference means, and nothing else in the
system is allowed to draw that conclusion.

The product thesis rests entirely on this component being conservative:

> A Ghost AI agent is an execution that exists in reality but has no corresponding
> cryptographic authority.

That claim is only worth making if the engine is trusted, and it is only trusted if it is
right about the boring cases. One confident false accusation costs more credibility than
ten correct detections earn.

## Read before building

| Task | Read |
|---|---|
| The case matrix, what each classification requires, evidence thresholds | `divergence-cases.md` |
| Warrant construction, the two axes, containment policy, false-positive control | `warrant-policy.md` |

## Inputs, and what they are worth

| Input | Source | Worth |
|---|---|---|
| Authorization record | AIP | Only as good as the packet. Until `expires_at` is signed and the verifier reads a clock, a valid `AUTHORITY_BOUND` packet may carry an authority the agent minted for itself. |
| Observation | Observer | Three-valued. Carries custody strength and continuity state. |
| Physical identity binding | `execution-binding-engineer` | Carries its own strength label: asserted / attested / observed. |
| Continuity state | Observer | Determines whether absence is evidence. |

The engine reads the strength labels and propagates them. A reconciliation result is never
stronger than its weakest input, and the code enforces that rather than leaving it to the
reader. This is the same derivation discipline `TrustFloor` already uses in
`verification.rs:277-285` — reuse the pattern rather than inventing a second one.

## The classifications

Full matrix and entry conditions in `divergence-cases.md`. Summary:

| Result | Authorization | Observation | Meaning |
|---|---|---|---|
| `VERIFIED_EXECUTION` | present | `OBSERVED`, matching | The system worked. |
| `UNATTRIBUTED_EFFECT` | absent | `OBSERVED` | The strongest Ghost signal. Something happened with no authority behind it. |
| `CANNOT_PROVE` | present | `OBSERVATION_UNAVAILABLE` | Not a finding. Not an alert by default. |
| `PHANTOM_CLAIM` | present | `NOT_OBSERVED` **with continuity proven** | The governance record claims an execution the healthy observer did not see. |
| `IDENTITY_DIVERGENCE` | present | `OBSERVED`, different binding | Executed by a process the authority was not issued to. |
| `LINEAGE_VIOLATION` | present | `OBSERVED`, unexpected ancestry | Authorized tool reached through an unapproved chain. |
| `SENSOR_INTEGRITY_FAILURE` | — | observer self-report | About the observer, not the agent. Never a containment trigger against the agent. |

`CANNOT_PROVE` and `PHANTOM_CLAIM` are the same raw shape — authorization present,
observation absent — separated only by whether continuity establishes the observer was
healthy across the interval. Collapsing them is the single most damaging error available in
this engine, and it is the default outcome if observation is modelled as a boolean.

## Continuity is what converts absence into evidence

`PHANTOM_CLAIM` requires an affirmative continuity proof over the interval: the observer
was running, its sequence had no gaps, its clock did not jump, it did not restart, and its
configuration did not change. Any of those unproven means `CANNOT_PROVE`.

Ring-buffer overflow deserves specific handling. Under load, a kernel observer drops
events, and load correlates with activity, so the periods most likely to contain something
interesting are the periods most likely to have gaps. An engine that reads drops as absence
will produce its highest-severity findings exactly when it is least able to see. Treat a
drop counter increment as continuity-breaking for the affected interval.

## Never conclude from correlation alone

Matching an authorization to an observation needs a shared identifier, not a heuristic. That
is what `execution_id`, minted before the action, is for.

Time-window matching — "an authorization at T and an observation at T+ε, so they are the
same event" — fails under concurrency, and agents are concurrent. Two authorized transfers
in the same second become indistinguishable, and the engine will pair them wrongly and
report divergence with confidence. If `execution_id` correlation is unavailable for a pair,
the result is `CANNOT_PROVE`, not a best-effort match.

## Every result is falsifiable

For each classification the engine emits, it must be possible to state what evidence would
overturn it. Record that alongside the result:

```
result          UNATTRIBUTED_EFFECT
evidence        observation O-4471, custody=RemoteSigner, binding=observed
would_overturn  an authorization record bearing execution_id 0x… ; none found in
                tenant scope over interval [t0,t1]
searched        <what was searched, and the completeness bound of that search>
```

The `searched` line is what keeps the engine honest. "No authorization found" means
something different when the search covered one tenant's log versus every store, and the
difference decides whether the finding is real.

## Rules

- Absence of observation is never a finding without continuity. Default to `CANNOT_PROVE`.
- Never automatically contain on `CANNOT_PROVE`. Degraded observation is an operational
  problem, and killing agents because a sensor restarted trains operators to disable the
  system.
- Reconciliation is pure. Inputs in, classification out, no I/O and no side effects —
  matching the core discipline the audit credited in `aip-core`'s scope algebra. Containment
  is a separate subsystem reading warrants; see `warrant-policy.md`.
- Determinism is required. Same inputs, same classification, every time. No randomness, no
  wall-clock reads inside the comparison — the evaluation time is an input.
- Do not claim parameter-level divergence from out-of-band observation. Payloads inside TLS
  are not readable without becoming the proxy the architecture rejects. Parameter binding
  comes from the pre-execution `action_digest` commitment; see `execution-binding-engineer`.
- Never let a result exceed the strength of its inputs. An `UNATTRIBUTED_EFFECT` built on an
  asserted binding is a suspicion, and the output says so.
