# Enterprise design-partner readiness — evidence-backed

Source: code under test `5590075`.

## VERIFIED (reproducible, live, this host)
- Independent kernel observation of a real agent, sealed into collector-signed
  evidence that verifies offline, with tamper rejection (M1).
- Honest control path reaches `Active`; live tracepoint interference becomes a
  signed `IntegrityUnknown` (E2, 6/6, clock enforcement off).
- Against an independent ftrace ground truth (E3, 10 × 200 execs, release
  build): sched and connector recall 2000/2000, precision 1.0, 0 fabricated
  records, pid attribution 2000/2000, 0 counted loss, 10/10 trials verified
  offline; exec→signed p50 795 ms / p95 909 ms at a 1 s batch interval;
  overhead median ×1.09 on a short synthetic workload (upper bound, n=10).

- Same-run chain (M2, local, no model): decision point measures the live
  agent and signs the authorization; gateway forwards the authorized call and
  refuses a mismatched one with signed receipts; offline evaluation verifies
  all five artifacts and the signed reconciliation; 5/5 tampering controls
  refused in each of 6 runs.
- Three frameworks (LangGraph, LlamaIndex Workflows, pydantic-ai; no LLM):
  every run's processes present in offline-verified evidence (M3).

## PARTIAL
- Reconciler verdict for tool calls is `CANNOT_PROVE` by design; identity
  `Match` only when the agent outlives a probe drain (3/3 at 3 s, 0/2 at ~40 ms).
- Agent lineage edges 5/15 (short-lived children); thread-pool frameworks
  bindable only since 5590075.
- SDKs, console, installation: not exercised.
- E3 measured signed observations; it did **not** reach attested coverage
  (every trial `ContinuityUnverified` in its short window).

## BLOCKED (environment)
- Host-separated collector custody; NTP-synchronized clock; model-backed agent
  task (no credentials); kprobe sensors (`CONFIG_KPROBES` unset); SoftHSM2.

**Pilot readiness: PARTIAL.**
