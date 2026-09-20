# Phase 1 — observe a real agent (runbook, NOT executed here)

**Status: not executed in the build environment.** Running a real agent
framework needs a network install (`pip`) and a live two-daemon run
(`aip-probe` + `aip-collector`), neither available where this repo is built.
This is the runbook a team executes; nothing here fakes a result.

## Subject

**LangGraph**, pinned. Preferred over CrewAI because its explicit directed
graph is an independent ground-truth call chain to score attribution against
(Phase 3), rather than a delegation model the agent narrates about itself.

```
langgraph==<pin at setup>        # record the exact version in THIRD_PARTY_LICENSES.md
langchain-core==<pin at setup>
```

The subject agent must: spawn a **child sub-agent** (a real OS process),
have the child **write a file** to a marked path, and **open one outbound TCP
connection**. Those three are the consequential effects the observer must
attribute in Phase 3.

## Wiring

- `aip-probe` on the agent host with `AIP_PROBE_SENSORS=sched,connector`
  (both — the connector is the gate-independent anchor).
- `aip-collector` in a separate process over the existing Noise_NK transport
  (`aip-transport`). **Do not reimplement the transport.**
- A signed `ExpectedExecution` issued by the decision point (the
  orchestrator, **not** the agent) naming the parent's authority.

## Exit gate

The honest path yields `VERIFIED_EXECUTION` for the parent's authorised
action, verified offline by `aip-observe-verify` with no network. Reuse the
two-daemon harness in `validation/pilot_e2e/run.sh` — it already stands up the
pair; the new part is putting a real LangGraph agent on the observed side
instead of the synthetic workload.
