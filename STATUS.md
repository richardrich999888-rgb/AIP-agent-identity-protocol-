# STATUS — Hostile-validation program, pre-RBI

Same self-critical register we use with the RBI. Written for a reader who will
check it against the repository.

## The one-line answer

**Phase 0 — the decisive phase, the one the plan says "can falsify the core
product claim outright" — is built, wired, tested and committed. Phases 1–5
are scaffolded as runbooks and were not executed, because they need
infrastructure this build environment does not have (network installs, a live
two-daemon run, and a dedicated VM), and because the safety rules forbid
running a rootkit here at all.** TRL 4/5 is unchanged; B8 (institution
hardware) and B2 (external assessor) are untouched, exactly as the plan says
this program cannot move them.

## Now demonstrated (built, tested, committed)

- **Phase 0 — cross-sensor blinding detection.** The plan's decisive gap. The
  kernel increments the perf loss counter only when the ring is genuinely
  full, so a submission-path hook drops events with no loss record — invisible
  to the sensor's own books. `aip-observe::divergence` catches the one signal
  that survives such a hook: a gate-independent netlink connector `Exec` the
  perf `sched` tracepoint failed to corroborate while declared live. It is
  wired into the collector sink and drives `IntegrityUnknown`. 10 unit tests +
  an end-to-end exit-gate test in which a batch shaped exactly as a hook
  produces it — connector saw the exec, perf did not, probe reported perf
  `Verified` — still lands on `IntegrityUnknown` with coverage withdrawn.
- **`docs/security/BLINDING_RESILIENCE.md`** — all five honest signals scored:
  what each catches, what each misses, why cross-sensor divergence is
  load-bearing. The audit found the other four already existed; divergence was
  the genuine gap.
- **Phase 5 output-parsing harness** — `adversarial/rootkit-runbooks/parse_health.py`
  ingests an observer health capture and asserts the attack forced an honest
  non-answer. Built and fixture-tested (`run.sh` passes; proven non-vacuous —
  it fails on malformed input). It runs **no** rootkit.

## Demonstrated with a limit

- The Phase 0 detector defeats a **single-path** delivery hook, which is what
  every public PoC (TripleCross, ebpfkit, the 0xMatheuZ perf rootkit) actually
  deploys. An attacker who hooks **both** the perf path and the netlink
  connector, or the connector alone, defeats it. That is the standing
  kernel-compromise limit and is **not** narrowed.
- The Phase 5 harness is validated against **fixtures**, not a real VM capture.
  The fixtures are synthetic and labelled so in the tool's own output. It is a
  rehearsal that is correct before it meets real data; it is not evidence of a
  live rootkit result.

## Not demonstrated (runbooks only; needs infrastructure or a human)

| Phase | Deliverable | Why not done here | Where the runbook is |
|-------|-------------|-------------------|----------------------|
| 1 | Observe a real LangGraph agent | needs `pip` install + live two-daemon run | `integrations/agents/README.md` |
| 2 | ContextForge ToolReceipt plugin (B10) | needs ContextForge (network); gated on prior-art review | `integrations/mcp-gateway/README.md`, `PRIOR_ART_NOTES.md` |
| 3 | Delegation-chain attribution | depends on Phases 1 + 2 | (covered by 1 & 2 runbooks) |
| 4 | Atomic Red Team ATT&CK layer | needs corpus clone (network) | `adversarial/atomic/README.md` |
| 5 | Rootkit runs | forbidden on host; needs snapshotted VM | `adversarial/rootkit-runbooks/README.md` |

## Standing limits, unchanged by any of this

- **Not past TRL 4/5.** TRL 5/6 needs the two-daemon stack on a regulated
  entity's own hardware — B8, not in this lab.
- **B2 not closed.** A CERT-In empanelled assessment is external. These
  artefacts give an assessor a baseline to audit; they do not self-certify.
- **No survival against a full kernel attacker.** The claim stays narrow: when
  the kernel is hostile we aim to return `CANNOT_PROVE`, not a false clean
  finding. Phase 0 tests whether we do for the common case; it does not make us
  immune.
- **Completeness only partly addressed.** Phase 4 (external corpus) removes the
  "we only test ourselves" objection but proves no corpus is complete.
- **Observer overhead on a real institutional workload: not measured**, and
  not measurable on synthetic lab load. (The signing/verification path *is*
  measured — `docs/OBSERVER_PERFORMANCE.md`.)
- **Kernel-dependent CI: still open.** Phase 0 unit tests are synthetic and run
  anywhere; the rootkit and live-sensor tests need capable hosts.
- **Two evidence-chain formats.** `ot-sentinel` (the out-of-band reconciler the
  plan's F11 gap wants) uses a chain not byte-compatible with `aip-core`'s;
  `docs/adr/ADR-EVIDENCE-CHAIN-FORMAT.md` is OPEN and a guard test forbids
  cross-dependency until it is closed.

## How to check the built parts

```bash
cargo test -p aip-observe --lib divergence          # 10 unit tests
cargo test -p aip-collector --lib                   # incl. the Phase 0 exit gate
adversarial/rootkit-runbooks/run.sh                 # Phase 5 harness vs fixtures
```
