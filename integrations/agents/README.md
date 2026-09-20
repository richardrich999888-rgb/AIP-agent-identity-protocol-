# Phase 1 — observe a real agent (EXECUTED)

**Status: executed on a development host (kernel 6.18.44, root, tracefs).** A
real LangGraph 1.2.11 agent was observed by the two-daemon pair and its signed
evidence verified offline. Run it with `run.sh`; sealed output is in
`results/sealed/`.

## Result (results/sealed/)

- The agent (`agent_subject.py`) ran 8 times; each run's parent graph node
  spawned a child sub-agent process (`child_action.py`) that wrote a marked
  file and opened one outbound TCP connection.
- The probe (no key) observed it from the kernel and shipped to the collector
  (holds the only key) over Noise_NK. **167 process exec/fork events** landed
  in the collector-signed attested archive.
- `aip-observe-verify`, a separate process given the archive and the published
  `observer.pub` and nothing else, reported **VERIFIED**.
- What this does NOT claim: the `VERIFIED_EXECUTION` reconciler verdict (join
  against a signed `ExpectedExecution`), which is Phase 3. Phase 1 is
  "observed, signed off-host, verified offline" — met.

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
