# Enterprise design-partner readiness — evidence-backed

Source: code under test `5b146be`.

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

## PARTIAL
- Reconciler `VERIFIED_EXECUTION`, MCP signed receipt in the same run (M2),
  SDKs, console, installation: component-level only.
- E3 measured signed observations; it did **not** reach attested coverage
  (every trial `ContinuityUnverified` in its short window).

## BLOCKED (environment)
- Host-separated collector custody; NTP-synchronized clock; model-backed agent
  task (no credentials); kprobe sensors (`CONFIG_KPROBES` unset); SoftHSM2.

**Pilot readiness: PARTIAL.**
