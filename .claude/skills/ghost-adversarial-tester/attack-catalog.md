# Attack Catalogue

Each entry: what it targets, how to run it, what result means what. `[synthetic]` runs
against the synthetic observer today. `[kernel]` waits for the real sensor and is recorded
`DEFERRED` until then.

## Identity and binding

**AT-01 — PID reuse `[synthetic]`**
Bind an agent to a process, let it exit, spawn an unrelated process that acquires the same
PID, have it act. `DETECTED` requires the second process to be recognised as a different
identity. If `process_start_time` is absent from the binding this will be `MISSED`, and the
failure is a false attribution — the unrelated process's actions attributed to the agent.
That is the worst outcome in the catalogue.

**AT-02 — Re-exec mid-binding `[synthetic]`**
Process execs into a different binary while bound. `DETECTED` requires a `BROKEN` binding
transition, not continued attribution under the old identity.

**AT-03 — Binary replacement after measurement `[kernel]`**
Replace the on-disk binary after the content hash was taken. Tests the
time-of-measure-to-time-of-use gap. `DEGRADED` is acceptable if the measurement records when
it was taken; `DETECTED` requires load-time measurement.

**AT-04 — Interpreter substitution `[synthetic]`**
Same `python3` binary, different script. `MISSED` is expected unless the entrypoint script
is separately measured — which is the point of running it. Record it and fix the claim about
what `executable_measurement` covers.

**AT-05 — Agent-to-agent impersonation `[synthetic]`**
Agent A presents agent B's identity. Tests whether the binding is checked against the
authority holder rather than merely present. Should surface `IDENTITY_DIVERGENCE`.

## Lineage

**AT-06 — Subprocess chain `[synthetic]`**
`agent -> python -> bash -> curl`. Does attribution survive one hop, two, three? Record the
depth at which it is lost.

**AT-07 — Orphaned child `[kernel]`**
Child survives parent exit and reparents to init. Tests whether ancestry is captured at
spawn rather than reconstructed later. Reconstruction after reparenting produces wrong
genealogy.

**AT-08 — Fork bomb under attribution `[kernel]`**
High-rate process creation. Tests both attribution correctness and the visited-set / depth
cap on lineage traversal. An unbounded walk here is the same defect the audit found at
`delegation.rs:312`.

## Authority

**AT-09 — Forged expiry `[synthetic]`**
Rewrite `expires_at` without re-signing. Confirmed by execution in the original audit as
passing. Re-run after the wire break; this is the regression test for AIP-C-01 and it should
move `MISSED` to `DETECTED`.

**AT-10 — Expired authority `[synthetic]`**
Present a token whose expiry has passed. Regression test for AIP-C-02. Before the verifier
clock lands, expect `MISSED`.

**AT-11 — Authorization replay `[synthetic]`**
Submit the same packet twice. Expect `MISSED` until `NonceTracker` is wired into
`VerificationContext` — `verify_packet` is stateless today and returns `true` both times.

**AT-12 — Chain forgery via unbound issuer `[synthetic]`**
Mint a hop off a root token not held, using the public `aip-core` API. `AUTHORITY_CHAIN` in
`aip-protocol` blocks this at packet level; `verify_delegation_chain` does not (H-01). Test
both paths and record them separately — a consumer using the core API directly is
unprotected.

**AT-13 — Scope escalation via service `[synthetic]`**
Request a delegation with wider scope than held. `MISSED` expected until the service either
calls `is_subset_of` or the endpoint is deleted (AIP-C-03).

## Attestation and observation

**AT-14 — Forged observation `[synthetic]`**
Agent fabricates an `ObserverAttestation`. `DETECTED` requires signature verification
against a key the agent cannot reach. Run under attacker model A3 specifically: if the agent
has root and the key is host-local, this succeeds and the entire observation layer is void
for that deployment.

**AT-15 — Attestation replay `[synthetic]`**
Lift a valid attestation and present it for a different execution. `DETECTED` requires
`execution_id` and a sequence number inside the signed content.

**AT-16 — Observer key theft `[synthetic]`**
Attempt to read the signing key as the agent. This is the single test that validates the
custody claim. Run it for each supported custody mode and record which modes survive.

**AT-17 — Clock manipulation `[synthetic]`**
Move the host clock forward and backward during execution. Tests whether attestation
timestamps come from the observer's clock and whether jumps break continuity. A clock jump
must degrade continuity, not silently shift the interval.

## Continuity and sensor integrity

**AT-18 — Sensor shutdown `[synthetic]`**
Stop the observer mid-execution. `DEGRADED` is the correct result: `CANNOT_PROVE`, not a
`PHANTOM_CLAIM`. A `PHANTOM_CLAIM` here is a false accusation and is scored `MISSED`.

**AT-19 — Ring-buffer exhaustion `[kernel]`**
Generate events faster than they can be drained. The critical test for the false-positive
story, because load correlates with activity. Drops must break continuity for the affected
interval.

**AT-20 — Sensor restart with checkpoint gap `[synthetic]`**
Restart across an interval containing an action. Tests whether the gap is detected on
resume, or whether the observer silently resumes as trusted. Silent resume is `MISSED`.

**AT-21 — Sequence rollback `[synthetic]`**
Rewind the observer's sequence counter. Tests the sensor hash chain. Unkeyed chains detect
corruption but not tampering — the audit's H-05 applies identically here, so confirm the
construction is keyed before claiming tamper evidence.

**AT-22 — Weaponised sensor failure `[synthetic]`**
Attacker model A4. Degrade the sensor and check whether `SENSOR_INTEGRITY_FAILURE` can
trigger containment against an innocent agent. Any path from sensor failure to agent
containment is a denial-of-service built into the security control and must be
`DETECTED`-as-blocked.

## Evidence and ledger

**AT-23 — Evidence deletion `[synthetic]`**
Delete rows from the store. `MISSED` expected until per-tenant sequence numbers and a signed
chain tip exist. The audit calls this the first thing an adversarial insider would do.

**AT-24 — Log field rewrite `[synthetic]`**
Rewrite `scope` in a delegation log row. Passes startup validation cleanly today because the
integrity hash omits `scope` and `expires_at` (H-03). Regression test for that fix.

**AT-25 — Revocation un-revoke `[synthetic]`**
Corrupt a revocation log line. The line is skipped on load, leaving the token valid (H-06).
Both write and load directions fail open; test both.

**AT-26 — Bundle origin forgery `[synthetic]`**
Re-sign an audit bundle with an arbitrary key. `verify_bundle_signature` reads the key from
the object under verification (H-02), so `BUNDLE_SIGNATURE PASS` establishes nothing about
origin. Confirm and fix the claim.

## Bypass

**AT-27 — Direct sink, no gateway `[synthetic]`**
Reach infrastructure without any AIP involvement. Cross-reference with
`aip-mcp-execution-audit` B-01; the result here is the coverage denominator.

**AT-28 — Ambient cloud credentials `[synthetic]`**
Use a default-credential chain to reach infrastructure with no tool call and no AIP artifact.
Usually the highest-severity bypass on a real host, and frequently untested because it does
not look like an agent action.

**AT-29 — Namespace escape `[kernel]`**
Attacker model A2 attempting to become A3. Determines whether the A2 assumption in the
deployment story holds.

## Scoring

Report per attacker model, never aggregated across models. A catalogue that is 90%
`DETECTED` under A1 and 30% under A3 is not 60% detected — it is two different products, and
the deployment story has to say which one is being sold.
