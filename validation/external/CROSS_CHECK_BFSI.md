# Cross-check methodology for the BFSI pilot

How to compare the Sniffer Dog's account against independent open-source
observers during the pilot, and — the part that matters — what a comparison
does and does not license you to conclude.

This is the operational companion to `docs/pilot/BFSI_PILOT_PLAN.md` §5. It
inherits its rules from `README.md`, `linux/INDEPENDENCE.md`,
`airi/OBSERVER_INDEPENDENCE.md`, `scenarios/TEST_PLAN.md`, and
`scenarios/INDEPENDENCE_MATRIX.md` — read those before drawing conclusions.

## The one rule

> The actor must not control the evidence used to judge the actor.

Every instrument here is **outside** the trust boundary. It is compared against
Vanian and is **never** fed into a Reconciliation, NEXORA proof, EvidenceCeiling,
or warrant. An instrument Vanian consumed would become part of Vanian, and the
comparison would stop being a comparison. This is not a style preference; it is
the property the whole pilot exists to demonstrate.

## The witnesses and their independence

| Witness | Site | Independent of the Sniffer Dog? |
|---|---|---|
| **Sniffer Dog** (subject) | perf on `sched`/`sock` tracepoints | — (it is the system under test) |
| **audit** | `audit_syscall_exit` (syscall boundary) | **Yes** — different facility; survives a perf-tracepoint gate (`auditd/STATUS.md`) |
| **Tetragon** | eBPF on **kprobes** | **Yes, if `CONFIG_KPROBES`** — else unavailable (`tetragon/BUILD.md`) |
| **ftrace reader** | the **same** tracepoints | **No** — interface-independent only; cross-checks Vanian's *reading*, not a second witness (`linux/INDEPENDENCE.md`) |

Mechanism-independence is the point: two consumers of the *same* tracepoint are
blinded by one gate (the observation-integrity finding), so they do not
corroborate each other. audit and Tetragon each observe through a facility the
Sniffer Dog does not use.

## Procedure (per comparison window)

1. **Define the window explicitly.** Record `t_open`/`t_close` on a stated clock.
   Generate a fixed, distinctive workload (the pilot agent's real actions) inside
   it. Same discipline as `observation_integrity/reproduce_interference.sh`.
2. **Capture each witness's account** of the window, verbatim, to its own file.
   Never edit a captured account to reconcile it — a disagreement is data.
3. **Align on the act, not the clock.** The witnesses stamp on different clocks;
   align on the event identity (exec of binary X, connect to endpoint Y), the
   way the sealed integrity run counts `wc` execs rather than filtering by a
   cross-clock window.
4. **Classify each event** into the four-way cell:

   | | Sniffer Dog saw it | Sniffer Dog did **not** |
   |---|---|---|
   | **independent witness saw it** | **AGREE** — corroborated (still ≤ `Attested`) | **SNIFFER-DOG GAP** — a Vanian defect *iff* Vanian did not report loss/`IntegrityUnknown` for the window |
   | **independent witness did not** | **WITNESS GAP** — the other instrument's blind spot, or a Vanian false event | **NEITHER** — outside both; no claim |

5. **Record raw output and the classification**, one row per event, in the pilot's
   adversarial ledger (`docs/security/ADVERSARIAL_RESULTS.md`), never a summary.

## What a comparison licenses — and what it does not

- **AGREE does not prove the event.** Two host-local witnesses under the same
  root can both be wrong the same way; corroboration never raises evidence above
  its `EvidenceCeiling`, and never to `Proven` (`scenarios/TEST_PLAN.md`).
- **A SNIFFER-DOG GAP with no reported loss or `IntegrityUnknown` is a real
  finding** — the Sniffer Dog missed an act two independent facilities recorded,
  and did not admit it. This is exactly what the pilot's honesty claim (plan P2)
  must survive; if it appears, it is a defect to fix, not to explain away.
- **A SNIFFER-DOG GAP the Sniffer Dog *did* report** as loss or
  `IntegrityUnknown` is the system working: it declined to vouch, which is the
  correct outcome, not a miss.
- **None of this changes a verdict.** The comparison lives in `validation/`; its
  output is a report about Vanian's accuracy, never an input to Vanian.

## Provenance and licensing

Each instrument added for the pilot gets its own `validation/external/<tool>/`
directory with repository, version, licence, build/install recipe as executed,
and this independence assessment — the existing convention
(`external/TOOL_INVENTORY.md`). Nothing is installed because it was on a list,
and nothing is substituted for something that turned out to be unavailable.
