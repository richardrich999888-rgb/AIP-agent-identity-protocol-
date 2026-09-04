# Warrant Policy

A warrant is the artifact that authorizes a response. Detection produces classifications;
warrants decide what may be done about them. Keeping the two separate is what stops the
product becoming an automated kill switch driven by heuristics.

## Two axes, never collapsed

**Axis 1 — severity.** How bad it would be if the finding is true.
`LOW` / `MEDIUM` / `HIGH` / `CRITICAL`

**Axis 2 — evidentiary strength.** How much the evidence actually supports the finding.
`HEURISTIC` / `CORRELATED` / `ATTESTED` / `CRYPTOGRAPHICALLY_PROVEN`

Most runtime security products multiply these into one score, which destroys the
information that matters: a critical-severity finding on heuristic evidence and a
medium-severity finding on cryptographic proof can produce the same number while warranting
completely different responses.

Keep them as an ordered pair through the whole pipeline. The pair is the warrant's type.

## Mapping strength honestly

Axis 2 is derived, not assigned. Compute it from the inputs rather than letting a rule
author declare it:

| Strength | Requires |
|---|---|
| `HEURISTIC` | Pattern match, timing correlation, or any binding labelled *asserted*. |
| `CORRELATED` | Shared `execution_id` between authorization and observation, bindings at least *attested*. |
| `ATTESTED` | Observer attestation verifies, custody `HostLocalSeparateUid` or better, continuity proven. |
| `CRYPTOGRAPHICALLY_PROVEN` | Observer attestation verifies against a key the agent provably cannot reach — custody `Hardware` or `RemoteSigner` — over a committed `(execution_id, packet_hash, binding, observation time)`. |

Note what this forecloses. Until the wire break lands `expires_at` inside the signed payload
and `now_ms` on the verification context, an authorization record cannot support
`CRYPTOGRAPHICALLY_PROVEN` on the authority side, because the authority may be one the agent
minted for itself. Cap accordingly and say so in the warrant, rather than issuing a proof
claim the foundation does not support.

## Response policy

```
HIGH     + HEURISTIC                 -> alert
HIGH     + CORRELATED                -> investigate
CRITICAL + ATTESTED                  -> restrict
CRITICAL + CRYPTOGRAPHICALLY_PROVEN  -> contain
```

Everything below `HIGH` records without paging. Containment requires both axes at maximum,
and that threshold is the design, not a conservative starting point to be relaxed once the
team gains confidence. Confidence is not the missing ingredient; evidence strength is, and
it is measured rather than felt.

## Containment is a separate subsystem

Detection, warrant evaluation, and containment are three components with three boundaries.
Containment reads warrants and nothing else — it does not read classifications, observations,
or authorization records directly. A containment path that can be reached without a warrant
is a bug regardless of how good the reasoning behind it is.

Requirements for any containment action:

- **Reversible, with a recorded reversal path.** Network isolation and cgroup freeze are
  reversible; process kill is not. Prefer the reversible mechanism and state why when
  choosing otherwise.
- **Scoped to the bound process**, using the full tuple. Containing by PID alone can hit a
  reused PID — containment aimed at the wrong process is an outage caused by the security
  control.
- **Recorded as evidence.** The containment event is itself an accountability record and
  belongs in the evidence chain.
- **Rate-limited and blast-radius-capped.** A bug that produces warrants at scale must not
  be able to contain a fleet. Cap containments per interval and per tenant, and fail the cap
  closed — refuse to contain further and escalate to a human.

## False-positive control

The failure mode that kills this class of product is not missed detections. It is a
detection rate high enough that operators stop reading the output, at which point the true
positives are lost too.

- **Ship every new case in observe-only mode.** Emit, do not act, until the rate is
  characterised on real traffic. `LINEAGE_VIOLATION` in particular will need per-deployment
  tuning for legitimate wrapper processes.
- **Measure precision per case, not in aggregate.** One noisy case discredits the whole
  engine; aggregate metrics hide which one.
- **`CANNOT_PROVE` volume is an observability metric, not a detection metric.** Track it
  separately and route it to the sensor fleet owner. If it trends up, detection quality is
  degrading regardless of what the detection counts say.
- **Every warrant carries its `would_overturn` line.** An operator who can immediately see
  what would disprove a finding can dismiss a false positive in seconds instead of minutes,
  and that difference determines whether the system stays switched on.

## What a warrant contains

```
warrant_id
classification            from reconciliation
severity                  axis 1
strength                  axis 2, derived
inputs                    ids of the authorization, observation, binding, continuity proof
would_overturn            what evidence would invalidate this
searched                  search scope and completeness bound
recommended_response      per the policy table
containment_scope         the full physical identity tuple, if applicable
issued_at                 evaluation time, an explicit input rather than a clock read
```

The warrant is signed and durable. It is the record that a response was authorized, and in
an accountability system the response needs to be as accountable as the thing it responds
to.
