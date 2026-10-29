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

## Cycle 2 — 2026-10-29 — RBI honest path, two defects, benchmark

- **DISCOVER/EXECUTE (pre-fix):** unmodified RBI rehearsal FAIL (clock refusal,
  correct). With clock enforcement off, the pilot passed its own checks but the
  RBI `check_control` failed twice in two distinct ways:
  - **D1** control `Degraded`: batch 1 carried `dropped_events=1` in 3/3 runs
    (connector `ENOBUFS`), and Degraded is sticky for the epoch.
  - **D2** control `IntegrityUnknown` with no attack: `divergence_replay.py`
    found every control-phase divergence had its sched counterpart in an
    adjacent batch; connector exec timestamps trail sched 591/591 (27–168 µs).
    Root cause: connector drained last, so a sched exec could fall into the
    next batch while its connector exec sat in this one.
- **REPAIR (5b146be):** connector drained first; after `ENOBUFS` keep reading
  (bounded); collector lets the previous *attested* batch of the same probe run
  corroborate (same pid/tgid, same 50 ms window); connector buffer enlarged to
  8 MiB via `SO_RCVBUFFORCE` (`AIP_PROBE_CONNECTOR_RCVBUF_BYTES`, `0` = old);
  `AIP_SENSOR_LOSS` diagnostics. Regression tests incl. a mutation check (the
  boundary test fails with the carry removed). Workspace: 3248 pass, 15 fail —
  all `aip-hsm` softhsm, SoftHSM2 absent.
- **MEASURE/FALSIFY (E2):** 6 live pilot runs, two arms. 6/6 PASS
  (control Active+coverage, live attack → IntegrityUnknown, offline verify,
  deletion refused, no recovery backfill). **Kernel-default arm also had 0
  loss**, so the buffer enlargement is not shown to be the cause; it stays as
  defence in depth, claimed as nothing more.
- **MEASURE (E3):** first two benchmark runs had whole trials with no signed
  batch. Not hidden: gdb showed the debug-build probe CPU-bound, not hung; the
  fixed 3 s window closed before shipping. Harness amended (drain rule, release
  build, logs kept), both earlier runs kept. Run 3: 2000/2000 recall on both
  sensors, precision 1.0, 0 fabricated, pid attribution 1.0, 10/10 verified,
  exec→signed p50 795 ms, overhead median ×1.09 (upper bound).
- **VERIFY:** unmodified RBI rehearsal re-run post-fix: still FAIL on the
  clock precondition only; acts 3, 4, 4b PASS. The system acts cannot run on
  this host without the documented clock switch.
- **Minor finding, open:** the collector's divergence override replaces a
  probe's specific `ForeignTracepointGate` with generic `Unverifiable` —
  diagnostic precision lost, signed state unchanged.

## Cycle 3 — 2026-10-29 — M2 same-run chain, M3 three frameworks, two probe defects

- **M2 discovery:** `validation/enterprise/same_run_validation.py` refuses to
  run outside GitHub-hosted runners (`RUNNER_ENVIRONMENT`), needs an NTP clock,
  a pinned ContextForge checkout and a 1.5 GB local model. Not spoofed. CI run
  40748072732 failed with sched `Unverifiable` in two batches, "root cause
  not yet established"; symptom matches D2 but its archive (Actions artifact)
  is behind this session's egress policy — UNCONFIRMED.
- **M2 local harness** (`m2/run_m2.py`): live agent; decision point measures
  its instance and signs `ExpectedExecution`; gateway signer forwards the
  matching call and refuses a mismatched one; observer Active; offline
  evaluation verifies archive, checkpoint, authorization, receipt (inside the
  window) and the signed reconciliation. Harness defects found on the way and
  kept: tracefs unmounted (run 0, not retained), chain not frozen at the
  attested head (run 1 → `ObservationSetIncomplete`, a correct refusal).
  Verdict: `CannotProve` — identity `UnboundReferencesOnly` for a ~40 ms agent,
  `Match` 3/3 for an agent alive 3 s; `ActionEvidenceUnavailable` because
  `tool_invoke` has no kernel-observable class. VERIFIED_EXECUTION in the
  daemon pipeline is unreachable: `aip-probe` never calls `register_claim`.
  `ghost-demo` (single process, self-labelled NOT_PRODUCTION) reaches it live.
- **M1 correction:** cycle 1's "1 start-verified lineage edge" was
  bash → `/usr/bin/sleep` from the harness itself. All 16 agent pids are in
  the signed evidence, but 0/8 agent edges. `run.sh` counted any edge — fixed
  to count only the agent's own pairs; it now FAILs honestly (0/8).
- **M3** (`m3/run_m3.sh`): LangGraph, LlamaIndex Workflows, pydantic-ai
  (FunctionModel; no LLM). Presence 15/15 in every arm. Edges low.
  Hypothesis 1 (ingest once per 1 s batch → child gone before measured):
  20 ms drain implemented; first 20 ms arm 0/15 — **falsified as sole cause**.
  Instrumented build (not committed): misses are `pidfd_open` ESRCH (gone)
  and, for pydantic-ai, the fork is by a **worker thread**: `pidfd_open`
  refuses a non-leader tid → never bound. Fix: resolve tid → owning process
  with a thread-start ≤ event check (recycled-tid guard). After both fixes:
  5/15 edges, pydantic-ai 2/2 of bound children; the rest is the ~16 ms
  child lifetime vs the 20 ms drain — recorded unbound, never guessed.
- **Regression:** workspace 3249 pass / 15 env-fail (SoftHSM2); pilot 2/2 PASS.
