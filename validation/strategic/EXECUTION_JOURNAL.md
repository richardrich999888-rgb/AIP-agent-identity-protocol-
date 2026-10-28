# Execution journal

## Cycle 0 — DISCOVER / baseline (2026-10-28)

- Session opened on a stale checkout at `872dbf3` (8-crate early main, no
  Sniffer Dog, no `validation/`). Did **not** take it at face value.
- Fetched all remotes; surveyed candidate branches with `git ls-tree` (no
  checkout). Selected `origin/integration/snifferdog-complete-enterprise-validation`
  (`4ca5a4d`, 2026-10-29, 54 crates) as the most complete base and branched
  `claude/strategic-validation-loop` from it. Source branches untouched.
- Measured host: kernel `6.18.44-fc-v180`, `CONFIG_KPROBES` **unset** (kprobe
  observation impossible), uprobes + ftrace-syscalls + tracefs available —
  the sched/sockstate/socksend/connector sensors the Phase 1 harness uses do
  not need kprobes, so Phase 1 observation is feasible.
- Read `integrations/agents/{run.sh,agent_subject.py}` in full. Confirmed it is
  a genuine LangGraph agent (no LLM by design) spawning a real child process;
  observed kernel→collector→offline-verify→lineage. Honest about stopping short
  of the reconciler VERIFIED_EXECUTION verdict.
- Noted a pre-existing `results/sealed/` bundle; will treat as historical and
  re-run live (anti-fabrication rule).
- Created `validation/strategic/` output manifest.

### Cycle 1 — selected
Run `integrations/agents/run.sh` live. Prep in progress: pinned langgraph venv
and the four binaries (`aip-probe`, `aip-collector`, `aip-observe-verify`,
`aip-lineage`) building in the background.

## Cycle 1 — IMPLEMENT/EXECUTE/MEASURE/FALSIFY/SHIP (M1)

- Prereqs built live: 4 binaries (`aip-probe/collector/observe-verify/lineage`,
  `cargo build --locked`, exit 0) and the pinned venv (langgraph 1.2.11).
- **EXECUTE:** first run FAILED correctly — the collector refused to start on an
  unsynchronized clock (a genuine fail-closed control, not a bug). No time
  daemon / NTP egress exists here, and faking `STA_UNSYNC` would be simulating
  success. Used the product's own documented switch
  (`AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=0`) via a scratchpad copy of the harness
  that differs from the committed one by exactly that one line (diff recorded).
- Live run PASSED: real LangGraph agent → kernel observation → collector-signed
  archive (112 exec/fork, 347 kernel events, 2 batches) → **VERIFIED** offline
  under `observer.pub` alone → 1 start-verified lineage edge. The collector
  honestly signed a 16 s clock error bound and `ContinuityUnverified`,
  `coverage=0` — the degraded timestamp assurance is inside the evidence.
- **FALSIFY:** wrong observer id, mutated signed `attested_at_ms`, mutated
  signed `observer_id`, mutated kernel-event `child_pid` → all **NOT VERIFIED**
  (rejected). A raw byte-flip at a JSON-cosmetic offset still verified — correct,
  because the signature covers canonical bytes recomputed from the typed
  structure, not the JSON text; confirmed by the semantic mutations being caught.
- **SHIP:** sealed `run_m1/` with `SHA256SUMS`; wrote EVIDENCE_MANIFEST,
  BENCHMARK_RESULTS, TEST_MATRIX, RBI/PILOT/BLOCKERS readiness.

### Next (not run this invocation, recorded truthfully)
- M2: same-run authorization + MCP signed receipt + reconciler
  `VERIFIED_EXECUTION` against a signed `ExpectedExecution`.
- Measurement harness: independent ftrace ground truth over a counted window →
  recall/precision/attribution with explicit denominators; monitored-vs-unmonitored overhead.
- RBI five-act rerun; multi-framework (M3).
