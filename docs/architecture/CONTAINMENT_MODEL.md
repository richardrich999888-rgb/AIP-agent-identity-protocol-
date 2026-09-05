# CONTAINMENT_MODEL

## 1. Current state

`CONTAINMENT = MISSING` from production, and this is **correct for now**.

Verified: no process termination, no cgroup control, no network blocking, no
firewall manipulation, no actuation of any kind in `aip-standalone/` or
`aip-service/`. The only `kill`-adjacent code anywhere in the repository is on
the unmerged PR #3 branch and is an unrelated child-process teardown.

AIP is an evidence system. It has no enforcement surface, and adding one before
the evidence pipeline exists would be the single most dangerous change
available.

## 2. The prohibited shape

```
anomaly  →  kill process
```

This is forbidden by the skill's §18 and by **I13**. A watchdog that
quarantines on statistical suspicion is a denial-of-service weapon aimed at its
own fleet — one false positive at scale takes down production, and the blast
radius is proportional to how much the operator trusted it.

## 3. Required decision path

```
Observation
    ↓  (attested by an observer the agent does not control)
Evidence
    ↓  (reconciled against ExpectedExecution on decision_id + ExecutionBinding)
Reconciliation Result
    ↓
Evidence Strength          Heuristic | Correlated | Attested | Proven
    ↓
Warrant                    policy predicate over (severity, strength)
    ↓
Containment Decision       explicit, logged, itself sealed as evidence
```

Every arrow is a gate. No arrow may be skipped, and the path may not be
short-circuited by a "high confidence" score, because confidence is Axis 1 and
the gate is on Axis 2 (**I12**).

## 4. Warrant standard

| Evidence strength | Definition | Maximum permitted response |
|---|---|---|
| `Heuristic` | statistical/behavioural inference | **Alert only** |
| `Correlated` | multiple unattested sources agree | **Alert only** |
| `Attested` | signed observer, continuity verified over the window | Alert; Constrain only with explicit operator opt-in |
| `Proven` | arithmetic on held data any third party can recompute — e.g. signature mismatch, hash-chain break, unsealed execution against attested coverage | Containment permitted, subject to policy |

**Non-negotiable:** containment requires `Proven`. Suspicion alone generates an
alert. This mirrors the principle already implemented (correctly) on the
unmerged PR #3 branch at `ot-sentinel/src/response.rs:112-129`, which is worth
reading as prior art even though **I17** bars citing it as capability.

## 5. Default posture

| Setting | Default | Rationale |
|---|---|---|
| Mode | **advisory** | a new deployment must not be able to disable its own fleet |
| Autonomous containment | **off** | requires explicit operator enablement |
| Uncited findings | capped at Alert | a finding with no evidence reference cannot warrant action |
| Degraded sensor | **never** escalates | **I9**; a sensor outage is not a ghost |
| `OBSERVATION_UNAVAILABLE` | **never** warrants containment | **I8** |
| Protected identities | exempt from autonomous action | prevents self-quarantine and control-plane lockout |

## 6. Fail-safe direction

Containment failures must fail **open** (do not contain) and be reported, not
fail closed. Inverting this makes the containment path itself an availability
attack: an adversary who can induce containment errors could otherwise take
down workloads.

Conversely, *detection* failures must fail **closed** in the epistemic sense —
an unverifiable observation yields `CANNOT_PROVE`, never `VERIFIED_EXECUTION`.

## 7. Containment must be accountable to itself

Any containment action is a privileged act and must produce evidence of the
same quality it demanded before acting:

- the action, its target, the warrant, and the reconciliation result that
  justified it are sealed into the evidence chain;
- the sealed record must be independently verifiable by the same
  `verify_packet` path used for agent evidence;
- **I20** applies to the containment feature itself: THREAT → ASSUMPTION →
  MECHANISM → IMPLEMENTATION → TEST → LIMITATION.

## 8. Sequencing

Containment is **step 13** of the skill's §23 order. Preconditions, all
currently unmet:

1. `ExpectedExecution` producer exists (decision point) — **library CLOSED (Skill 5)**; separate-process deployment design only
2. `ExecutionBinding` survives PID reuse — **CLOSED (Skill 4)**
3. Observer with an independent trust root — **CLOSED (Skills 6/6.5)**, collector off-host; deployment separation an operator obligation
4. Reconciliation with `CANNOT_PROVE` as default — **CLOSED (Skill 7)**
5. Warrant engine with orthogonal axes — **CLOSED (Skill 8, `aip-warrant`)**
6. Adversarial tests proving suspicion cannot reach containment — **CLOSED at the warrant boundary** (`aip-warrant/tests/warrant.rs` w12 sweeps every result × strength × severity × availability × policy)

The six preconditions now hold at the library level. Containment itself
(Skill 9) is still **not implemented**: no code in this repository signals,
freezes, isolates or filters anything, and today no production evidence path
yields a `Proven` workload violation, so `Contain` is unreachable from real
inputs even where the engine would permit it. PR #3's actuation (authority
revocation inside the detector loop) was reviewed and not harvested
(`OT_SENTINEL_HARVEST_AUDIT.md` §G, Phase 3).
