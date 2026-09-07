# Divergence Cases

Each case gives entry conditions, the minimum evidence required, and the most likely benign
cause. The benign-cause column is not commentary — it is the check that must be ruled out
before the classification is emitted.

## A — `VERIFIED_EXECUTION`

**Entry.** Authorization present and valid. Observation `OBSERVED`. `execution_id` matches.
Physical binding matches the identity the authority was issued to. Action digest matches
the authorized commitment.

**Evidence.** All five. A missing element downgrades rather than passes.

**Note.** This is the common case and it must be cheap. If verification cost scales badly
here, the system will be sampled in production, and sampling reintroduces
`OBSERVATION_UNAVAILABLE` across the board.

## B — `UNATTRIBUTED_EFFECT`

**Entry.** Observation `OBSERVED`. No authorization record correlates to it.

**Evidence.** The observation, its custody strength, its binding strength, and a stated
search bound — what was searched for a corresponding authorization and how complete that
search was.

**Benign causes to rule out first.**
- The authorization exists in another tenant's scope and the search was tenant-limited.
- The process is not an agent at all — a system daemon, a package manager, an operator's
  shell. Enrollment scope must be explicit, or every host process becomes a Ghost.
- The authorization was written but not yet durable. Ordering matters; see the audit's
  fail-open revocation writes for what happens when persistence is assumed.

**Strength.** The strongest available signal, and the core of the product thesis. It is
also the one that will be wrong most expensively, so the search bound is mandatory, not
optional.

## C — `CANNOT_PROVE`

**Entry.** Authorization present. Observation `OBSERVATION_UNAVAILABLE`, or continuity
unproven over the interval.

**Evidence.** The continuity state and the specific reason: drop counter increment, sensor
restart, clock jump, sequence gap, configuration change, sensor not deployed on that host.

**Action.** Record it. Do not alert by default, do not contain, do not escalate on volume
alone. A spike in `CANNOT_PROVE` is an observability incident and routes to whoever owns
the sensor fleet, not to whoever responds to agent misbehaviour.

**Why this case carries the design.** It is the pressure valve that keeps every other case
honest. Without it, every operational gap is forced into `PHANTOM_CLAIM`.

## D — `PHANTOM_CLAIM`

**Entry.** Authorization present. Observation `NOT_OBSERVED`. **Continuity affirmatively
proven** across the full interval — observer running, no sequence gaps, no drops, no clock
anomaly, no restart, no configuration change.

**Evidence.** The continuity proof itself, as a first-class artifact. A `PHANTOM_CLAIM`
without an attached continuity proof is a `CANNOT_PROVE` that was rounded up.

**Benign causes to rule out.**
- The authorization was issued and the action legitimately never ran — a decision recorded
  but not executed is not a phantom claim unless something asserts it executed.
- The execution happened on a host the observer does not cover. Coverage scope is part of
  the continuity proof.

**Meaning.** The governance record claims something the healthy observer did not see. This
implicates the control plane, not only the agent, and should route differently from case B.

## E — `IDENTITY_DIVERGENCE`

**Entry.** Authorization present. Observation `OBSERVED`. Physical binding differs from the
identity the authority was issued to.

**Evidence.** Both bindings, both strength labels, and which tuple fields differ.

**Benign causes to rule out.**
- PID reuse in the observation path. If `process_start_time` is absent from either binding,
  this case cannot be emitted at all — the comparison is not sound without it.
- Legitimate re-exec or runtime restart, which produces a new `runtime_instance` for the
  same logical agent. Model that as a binding transition, not a divergence.

**Note.** Potentially the strongest detection in the system, and entirely dependent on
binding quality. Weak bindings make this case unusable rather than merely noisy.

## F — `LINEAGE_VIOLATION`

**Entry.** Authorization present. Observation `OBSERVED`. Ancestry chain does not match the
approved shape — e.g. `agent -> python -> bash -> curl` where the authority covered a
direct tool invocation.

**Evidence.** The full chain with start times at each hop, and the expected shape.

**Benign causes to rule out.**
- Legitimate wrapper processes: shells in container entrypoints, `uv`/`npx`-style
  launchers, supervisor processes. The approved shape needs to be configured per deployment
  and will require tuning. Ship it in observe-only mode first.
- Reconstructed genealogy across a PID reuse. A chain of bare PIDs produces plausible wrong
  ancestry; require start times at every hop or do not emit the case.

## G — `SENSOR_INTEGRITY_FAILURE`

**Entry.** Observer self-reports or the reconciler detects: sequence gap, counter rollback,
unexpected restart, state corruption, configuration change, disablement.

**Evidence.** The observer's own hash chain and checkpoint state.

**Critical rule.** This is a finding about the observer, never about the agent. It must not
by itself trigger containment against any agent. An attacker who can degrade the sensor
would otherwise gain a way to trigger containment of arbitrary workloads — a denial of
service built directly into the security control.

Route it to the sensor fleet owner. Its effect on agent-facing cases is indirect: it moves
`PHANTOM_CLAIM` back to `CANNOT_PROVE` for the affected interval, which is exactly what it
should do.

## Emission discipline

- One classification per correlated pair. Do not emit a cascade of findings from one
  divergence; pick the most specific applicable case.
- Precedence when several apply: `SENSOR_INTEGRITY_FAILURE` first (it invalidates the
  others' premises), then `IDENTITY_DIVERGENCE`, then `LINEAGE_VIOLATION`, then
  `UNATTRIBUTED_EFFECT`, then `PHANTOM_CLAIM`, then `CANNOT_PROVE`, then
  `VERIFIED_EXECUTION`.
- Every emission carries the `would_overturn` and `searched` fields from the parent skill.
