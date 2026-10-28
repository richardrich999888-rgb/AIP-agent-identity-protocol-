# RBI demonstration readiness — evidence-backed

Source: `claude/strategic-validation-loop` @ `4ca5a4d`. Assurance levels kept
separate; nothing here is promoted from a lower level.

## What is live-proven this invocation

- **Real-agent execution observed, attested, and offline-verified (M1).**
  A genuine LangGraph agent spawning a real child process (file write + TCP
  connect) was observed from the kernel by a key-less probe, attested by a
  separate-process collector holding the only key, and the archive **VERIFIED**
  offline from the published `observer.pub` alone. Negative controls reject
  tampering (wrong observer, mutated signed timestamp/observer-id/pid). Evidence:
  `validation/strategic/run_m1/` (sealed, `SHA256SUMS`).

## The five-act RBI demo

`validation/rbi_demo/` exists on this branch but was **NOT_RUN** this
invocation (budget). It is the next RBI action. The five acts (honest path,
observer interference, unregistered-destination refusal, modified-argument
detection, offline verification) are not re-asserted from any historical bundle.

## Honest boundaries for an RBI presentation

- **Clock/timestamp assurance is REDUCED on this host.** It has no NTP sync;
  the collector correctly refuses to start under its default
  (`AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=1`). M1 ran with that switch off, and
  the resulting evidence **signs a 16 s clock error bound**. A real RBI host
  must run chrony (`deploy/pilot/chrony-cert-in.conf`); that is a
  presentation-host readiness item, distinct from hosted-rehearsal readiness.
- **Process-separated, not host-separated.** The collector ran on the same host
  as the probe (separate process, sole key holder). Independent *administrative*
  custody on a separate host is not demonstrated here.
- **Observation, not attribution-to-identity.** M1 proves the execution is in
  the signed evidence and that lineage is derivable; it does **not** prove the
  `VERIFIED_EXECUTION` reconciler verdict (join against a signed
  `ExpectedExecution`). That is Phase 3 / M2, NOT_RUN here.

**RBI readiness verdict: PARTIAL** — the observe→attest→offline-verify core is
live-proven on a real agent; the full five-act demo and a synced-clock,
host-separated presentation rehearsal remain to run.
