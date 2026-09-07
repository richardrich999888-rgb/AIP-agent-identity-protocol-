---
name: ghost-adversarial-tester
description: Attack the AIP + observer + reconciliation stack and record what it actually detects, as opposed to what it is documented to detect. Use whenever the user mentions adversarial testing, red teaming the sensor, evasion, bypass, forged observations, PID reuse attacks, sensor shutdown, ring-buffer loss, clock manipulation, replay, ledger manipulation, or asks whether a detection actually works — and also when they are about to claim a security property in a spec, patent, deck, or customer conversation. Consult this before any such claim is made externally, because the audit already found four documented integrity properties that the code contradicts, and an unverified detection claim is a liability rather than a feature.
---

# Ghost Adversarial Testing

Every security property in this stack is a claim until an attack fails against it. The
existing audit established what happens without this discipline: four documented integrity
claims that the code contradicts, and one module comment describing a protection that
permits exactly the bypass it names.

The rule this skill enforces is narrow and absolute:

> A detection is real when an attack against it has been executed and recorded as failing.
> Until then it is a design intention, and it is described as one.

## Read before testing

| Task | Read |
|---|---|
| The attack catalogue, what each targets, what each proves | `attack-catalog.md` |

## What is testable now

The synthetic observer from `execution-binding-engineer` makes most of this catalogue
runnable before any kernel code exists. That is the point of building it first. Forged
attestations, replayed observations, clock manipulation, ledger manipulation, identity
substitution and continuity gaps are all driven far more easily through a synthetic observer
than through eBPF, and they exercise the layers where the interesting logic lives.

Kernel-specific evasion — ring-buffer exhaustion, probe detachment, namespace escape,
verifier-level tricks — waits for the kernel sensor and is marked `DEFERRED` in the results
table rather than omitted. An omitted attack reads as a passed attack six months later.

## Result vocabulary

Use exactly these. They map onto the existing audit's discipline of separating what code
proves from what documentation asserts.

| Result | Meaning |
|---|---|
| `DETECTED` | The attack was performed and the system emitted the correct classification. |
| `MISSED` | Performed, and the system emitted nothing or the wrong classification. |
| `DEGRADED` | Performed, and the system correctly emitted `CANNOT_PROVE` — it did not falsely accuse, and it did not detect. |
| `NOT_RUN` | Not attempted. Never inferred from a related test passing. |
| `DEFERRED` | Blocked on a component that does not exist yet. Name the component. |

`DEGRADED` deserves its own label because it is the correct outcome for a large class of
attacks. An adversary who blinds the sensor should produce `CANNOT_PROVE`, not a false
`PHANTOM_CLAIM` and not silence. Scoring `DEGRADED` as a failure pushes the design toward
accusing on absence, which is the failure mode the reconciliation engine exists to prevent.

## Method

1. **State the claim.** One sentence, in the form the product would use externally.
2. **Derive the attack.** What an adversary does to make the claim false.
3. **Execute it.** Against a real deployment of the stack, with the observer configured as
   it would ship.
4. **Record raw output.** Commands, actual output, and the classification emitted. Not a
   summary.
5. **Classify** with the vocabulary above.
6. **Revise the claim** to what the evidence supports.

Step 6 is the deliverable. Adversarial testing that produces a list of bugs without
correcting the claims those bugs falsify has done half the job, and it is the half that does
not protect you when the claim is repeated in a deck or a filing.

## Attacker models

Test against each separately; results differ sharply and conflating them overstates
coverage.

| Model | Capability | Notes |
|---|---|---|
| A1 — Confused agent | Executes unintended actions, no evasion intent | The baseline. Most real incidents. |
| A2 — Adversarial agent, unprivileged | Actively evades, no root, cannot leave its namespace | The realistic threat for a sandboxed agent runtime. |
| A3 — Adversarial agent, root on host | Can read local keys, stop processes, manipulate the clock | Defeats every host-local attestation custody option. |
| A4 — Compromised observer | Attacker controls the sensor | Tests whether observer compromise is detectable and whether it can be weaponised against agents. |

A3 is the model that decides the attestation key architecture. If the deployment story
assumes A2 and the agent can plausibly reach root — spawning subprocesses, installing
packages, executing model-authored code — the assumption is stated explicitly in the results
document or it is wrong.

A4 matters more than it looks. An attacker who can forge observations can manufacture
`UNATTRIBUTED_EFFECT` findings against innocent workloads, turning the containment path into
a denial-of-service tool. Confirm that `SENSOR_INTEGRITY_FAILURE` never triggers containment
against an agent.

## Output

One document, `docs/security/ADVERSARIAL_RESULTS.md`, with one row per attack: id, attacker
model, claim targeted, commands run, raw output, result label, and the revised claim.

Keep it current. It is the document that gets cited when someone asks whether a detection
works, and a stale version is worse than none — `AUDIT_CORRECTIONS.md` already went stale in
three statements, and that was one file maintained by people who cared about it.

## Rules

- Never mark an attack `DETECTED` from reasoning. Run it.
- Never infer coverage. If PID reuse was tested on the process sensor and not the network
  sensor, that is one `DETECTED` and one `NOT_RUN`.
- A green test suite means nothing here. The audit found Postgres tests printing `skip` and
  reporting `ok` (`store/pg.rs:261`), and `handlers.rs` with zero tests at all.
- Test the failure path, not the happy path. Every control in the audit that failed open
  passed its happy-path test.
- When an attack succeeds, fix the claim before fixing the code. The claim is what is
  currently doing damage, and it can be corrected the same day.
- Attacks run against systems you own. This catalogue is for testing your own deployment.
