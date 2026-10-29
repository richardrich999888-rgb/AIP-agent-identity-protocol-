# RBI demonstration readiness — evidence-backed

Source: `claude/strategic-validation-loop`; code under test `5590075`.
Assurance levels kept separate; nothing promoted from a lower level.

## Live-proven on this host

- **Real agent observed → attested → offline-verified (M1, cycle 1).**
  LangGraph agent with a real child process; key-less probe; separate-process
  collector holding the only key; VERIFIED from `observer.pub` alone; tamper
  rejected. `run_m1/`.
- **Acts 1, 2, 5 core, repeated (E2, cycle 2) — with clock enforcement off.**
  6/6 runs: honest control `Active` with attested coverage (RBI
  `check_control.py` PASS); live foreign BPF program on the sched tracepoint →
  the collector (other process, other key) signs `IntegrityUnknown` and
  withdraws coverage; recovery never backfills coverage over the unknown
  interval; every record verifies offline; deleting one record is refused.
  `e2_pilot_repeats/`.
- **Acts 3, 4, 4b** (library-level scoping and tool-boundary assertions; live
  gateway receipt signing): PASS in the unmodified rehearsal.

## Not passing here, and why

- **The unmodified five-act rehearsal FAILS on this host** — by design. The
  collector refuses to start on an unsynchronized clock (`STA_UNSYNC`, 16 s
  max error; no time daemon, no NTP egress). `run_rbi_postfix_unmodified/`.
  Before cycle 2 the system acts would also have failed on a synced host
  (defects D1, D2); that is now repaired and evidenced with enforcement off,
  **not yet on a synced host**.

## Honest boundaries for an RBI presentation
- Timestamp assurance is reduced in every run here (16 s bound, signed into
  the evidence). A presentation host must run chrony
  (`deploy/pilot/chrony-cert-in.conf`) and pass the unmodified rehearsal.
- Process-separated, not host-separated, collector custody.
- The same-run chain (authorization → gateway receipt → observation →
  signed reconciliation) runs and verifies end to end locally (M2, 6/6), but
  its verdict is `CANNOT_PROVE`: a tool call has no kernel-observable action
  class, and the deployed probe cannot carry a decision claim. Do not present
  `VERIFIED_EXECUTION` from the deployed pipeline; it exists only in the
  single-process `ghost-demo`.
- Lineage of short-lived child processes is not reliable: a child that exits
  within ~20 ms is recorded unbound (5/15 agent edges in M3).
- Detection of a *perf-path* gate. A hook on both the tracepoint and the
  connector, or any kernel-level adversary, is out of boundary.

**RBI readiness: PARTIAL.** Next gate: the unmodified `validation/rbi_demo/run.sh`
passing on an NTP-synchronized host.
