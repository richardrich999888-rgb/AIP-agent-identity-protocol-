# VANIAN strategic validation report

**Invocation date:** 2026-10-28
**Source revision:** `claude/strategic-validation-loop` @ `4ca5a4d`
(based on the most complete remote branch
`integration/snifferdog-complete-enterprise-validation`, 2026-10-29, 54 crates).

This is an evidence report, not a plan. Assurance levels are kept separate and
nothing is promoted from a lower level. The one genuine experiment that ran is
backed by sealed artifacts; everything not run says so.

## Engineering changes

None to production Rust this invocation. The work was: branch discovery and
selection, host/kernel grounding, and a **live** end-to-end execution of the
existing Phase 1 real-agent harness with negative controls. New files are under
`validation/strategic/` only. The committed harness was not modified; the one
operator switch needed for an unsynchronized-clock host was applied via a
scratchpad copy whose sole difference is that one line (diff recorded in the
journal).

## Real agents executed

- **LangGraph 1.2.11** (`integrations/agents/agent_subject.py`) — a genuine
  `plan → act → report` graph whose `act` node spawns `child_action.py` as a
  **real separate process** that writes a marked file and opens one outbound
  TCP connection. No LLM, by deliberate design (the observer watches kernel
  execution, not model I/O; the explicit graph is the independent ground truth).
  Ran 8 times.

## Independent evidence

Observed from the kernel by `aip-probe` (holds no key; sched/sockstate/
socksend/connector sensors) → attested by `aip-collector` in a separate process
holding the only key (Noise_NK transport) → **112 exec/fork events and 347
kernel events** sealed into a collector-signed archive (2 attested batches) →
**VERIFIED offline** by `aip-observe-verify` from the published `observer.pub`
alone, in a separate process, with no network → **1 start-verified parent→child
lineage edge** derived by `aip-lineage` after re-verifying under the anchor.

The collector stayed honest about the degraded clock: it **signed** a 16 s
worst-case error bound and `ContinuityUnverified` with `coverage asserted = 0`.
The reduced timestamp assurance is inside the evidence, not hidden.
Sealed: `validation/strategic/run_m1/` + `SHA256SUMS`.

## Security results (negative controls)

| Attack | Result |
|---|---|
| Verify under wrong observer id | **NOT VERIFIED** (rejected) |
| Mutate signed `attested_at_ms` | **NOT VERIFIED** (rejected) |
| Mutate signed `observer_id` | **NOT VERIFIED** (rejected) |
| Mutate kernel-event `child_pid` | **NOT VERIFIED** (rejected) |
| Raw byte-flip at a JSON-cosmetic offset | VERIFIED — **correct**: the signature covers canonical bytes recomputed from the typed structure, not the JSON text; confirmed by the semantic mutations above being caught |

## Benchmark results

Counts measured and sealed (`BENCHMARK_RESULTS.csv`): 8 agent runs; 112
exec/fork and 347 kernel events signed; 2 batches; 1 lineage edge; offline
verify PASS; signed clock error bound 16 s; coverage asserted 0.
Recall / precision / attribution-accuracy / latency-overhead are **NOT_MEASURED**
— they require an independent ftrace ground-truth harness over a counted window
and a monitored-vs-unmonitored A/B, which is the next measurement step. No
coverage, recall or performance number is invented.

## RBI readiness

**PARTIAL.** The observe→attest→offline-verify core is live-proven on a real
agent with tamper rejection. The five-act RBI demo (`validation/rbi_demo/`) was
NOT_RUN this invocation. A presentation host must additionally run chrony and,
for custody claims, a host-separated collector. (`RBI_READINESS.md`.)

## Enterprise design-partner readiness

**PARTIAL.** VERIFIED: independent, offline-verifiable execution evidence with
tamper rejection. PARTIAL (component-level only): reconciler verdict, MCP
signed receipt, SDKs, console. BLOCKED (environment): off-host custody, NTP
sync, model-backed task, kprobe sensors. (`PILOT_READINESS.md`.)

## Production readiness

Not claimed. Explicit limitations: no synchronized clock on this host (default
collector posture unmet); `CONFIG_KPROBES` unset; same-run
authorization→receipt→`VERIFIED_EXECUTION` not exercised end-to-end; single
host (no independent custody); no model-backed workload.

## Artifacts

- `validation/strategic/run_m1/` — sealed evidence + `SHA256SUMS`
  (archive `2889153b…`, health `caea075f…`, observer.pub
  `c844bbef…`, offline_verify `7a19816c…`, lineage `9d39b5a0…`).
- `validation/strategic/{BASELINE,STATUS.json,EXECUTION_JOURNAL,TEST_MATRIX.csv,EVIDENCE_MANIFEST.json,BENCHMARK_RESULTS.csv,RBI_READINESS,PILOT_READINESS,BLOCKERS}`.

**Reproduce:**
```
git checkout claude/strategic-validation-loop        # @ 4ca5a4d
python3 -m venv integrations/agents/.venv && \
  integrations/agents/.venv/bin/pip install -r integrations/agents/requirements.lock
sudo integrations/agents/run.sh <outdir>             # needs an NTP-synced clock
# On a host without NTP: set AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=0 and accept the
# signed clock-error bound (as this run did).
```

## Code delivery

Committed to `claude/strategic-validation-loop`; pushed. No change to `main`,
no change to the source integration branch, no production Rust modified.

## Next three actions

1. **M2 — same-run chain:** drive one task instance through authorization →
   `aip-mcp-gateway` signed receipt → kernel observation → reconciler
   `VERIFIED_EXECUTION` against a signed `ExpectedExecution`, all one run.
2. **Measurement harness:** independent ftrace ground truth over a counted
   window → recall/precision/attribution with explicit denominators, plus a
   monitored-vs-unmonitored overhead A/B.
3. **RBI five-act rerun** on this branch, then begin M3 (≥3 frameworks),
   recording per-framework what genuinely executes vs. needs model credentials.
