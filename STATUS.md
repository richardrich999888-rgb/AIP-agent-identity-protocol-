# STATUS — Hostile-validation program, pre-RBI

Same self-critical register we use with the RBI. Written for a reader who will
check it against the repository.

## The one-line answer

**Phases 0–4 are built, tested and committed. Phase 1 was executed end-to-end
against a real LangGraph agent; Phase 3 derives the delegation chain from that
same real evidence; Phase 4 grades the observer against an external
(Atomic Red Team / ATT&CK) corpus. Phase 5 is document-only by rule: its
output-parsing harness, per-tool runbook and VM-setup script are built and the
harness is fixture-tested, but no rootkit is run in this environment.** The one
thing that still needs infrastructure absent here is a live rootkit VM capture
(Phase 5), which the safety rules forbid running on this host. **AIP's
observations have also now been corroborated by two runtime observers we did
not build**, one of them reaching the kernel by a different mechanism; neither
found an execution missing from AIP's signed evidence. TRL 5 is unchanged; B8
(institution hardware) and B2 (external assessor) are untouched, exactly as the
plan says this program cannot move them. **Of the two conditions the technical
brief names for TRL 6, the second — independent corroboration by an observer we
did not build — is now met and evidenced; the first, a non-synthetic agent
under representative load, stands alone and is what a pilot supplies.**

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
- **Phase 1 — a real LangGraph agent observed end-to-end.** A genuine LangGraph 1.2.11 graph whose parent node spawns a child sub-agent process (real fork/exec) that writes a file and opens a TCP connection, observed by the two-daemon pair on a live kernel. **167 exec/fork events** reached the collector-signed archive; `aip-observe-verify` accepted it offline from the published `observer.pub` alone. Sealed in `integrations/agents/results/sealed/`; reproduce with `integrations/agents/run.sh`. The `VERIFIED_EXECUTION` reconciler verdict (join against a signed `ExpectedExecution`) is Phase 3 and is not claimed.
- **Phase 2 — MCP tool boundary (B10).** `aip-mcp-gateway` countersigns every
  `tools/call` with a gateway-signed `ToolReceipt` over its own recomputation
  of the argument commitment (never the agent's key). A mis-parameterised call
  is caught by `compare_tool_boundary` against the decision point's sealed
  digest **with no agent claim in evidence**; the 2026-07-28 header/body
  disagreement is refused before signing. 11 tests. The ContextForge adapter
  (`integrations/mcp-gateway/`) shells to this binary rather than reimplementing
  the crypto.
- **Phase 3 — delegation-chain attribution.** `aip-lineage` verifies an
  attested archive under the anchor and only then derives start-verified
  parent→child edges (fail closed). Run against Phase 1's real sealed archive it
  yields **21 edges including a genuine multi-level chain**; sealed at
  `integrations/agents/results/sealed/delegation_chain.txt`. The exit-gate test
  (`delegation_attribution.rs`) proves a dropped fork fabricates **no** edge
  (the CANNOT_PROVE guarantee) and that attribution follows the kernel-bound
  forking instance, not a decoy.
- **Phase 4 — external ATT&CK corpus coverage.** A deterministic generator
  (`adversarial/atomic/gen_layer.py`, 10 tests) turns an auditable coverage map
  into a MITRE Navigator layer coloured by coverage class: of 20 techniques,
  8 attributed / 6 effect-observed / **6 not-covered** (AIP's honest blind
  spots). No atomic is executed here; only Phase-1 primitives carry live
  evidence. Ledger rows in `docs/security/ADVERSARIAL_RESULTS.md`.
- **Independent corroboration — observers we did not build.** The one objection
  more of our own tests could not answer: every sensor that had ever agreed with
  AIP was one we built. Two independently built observers — **bpftrace 0.20.2**
  (independent eBPF implementation, same tracepoint) and **auditd 3.1.2** (the
  audit subsystem, a *different* kernel mechanism) — watched the same kernel over
  the same window as AIP's probe. **Neither recorded an execution absent from
  AIP's signed evidence** (bpftrace 113 agreed / 0 gaps; auditd 112 agreed / 0
  gaps, with 938 failed execve *attempts* excluded and reported as a scope
  difference). `aip-corroborate` (32 tests) verifies the archive under its anchor
  before comparing anything, and labels each report with which class of
  independence it represents — a gate on the shared tracepoint would blind both
  bpftrace and AIP, which auditd is carried to cover. Sealed in
  `validation/external/corroborate/results/sealed/`. The exercise found **two
  defects in the comparison harness, not in AIP** — 275 failed execve attempts
  counted as blind spots, and one 3 ms teardown boundary artefact that the
  *other* observer also missed — both now guarded by tests and written up.
  Falco/Tetragon were first choice and are unreachable from this environment;
  stated, not substituted.
- **Phase 5 output-parsing harness** — `adversarial/rootkit-runbooks/parse_health.py`
  ingests an observer health capture and asserts the attack forced an honest
  non-answer. Built and fixture-tested (`run.sh` passes; proven non-vacuous —
  it fails on malformed input). It runs **no** rootkit. The VM-setup script
  (`vm_setup.sh`) provisions the disposable VM and fails closed off it.

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

## Not demonstrated (needs a human and a disposable VM)

| Phase | Deliverable | Why not done here | Where the runbook is |
|-------|-------------|-------------------|----------------------|
| 5 | A live rootkit VM capture | forbidden on host (rule 1); needs a snapshotted, isolated VM run by a human | `adversarial/rootkit-runbooks/README.md`, `vm_setup.sh` |

The Phase 5 *harness*, per-tool runbook and VM-setup script are built and the
harness is fixture-tested; only the act of running a rootkit and capturing the
observer's health in a real VM remains, and that is deliberately left to a
human in the isolated environment.

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
cargo test -p aip-observe --lib divergence          # Phase 0: 10 unit tests
cargo test -p aip-collector --lib                   # Phase 0 exit gate
cargo test -p aip-mcp-gateway                        # Phase 2: 11 tests
cargo test -p aip-reconcile --test delegation_attribution  # Phase 3 exit gate
./target/debug/aip-lineage --observer-id collector.phase1 --key-version 1 \
  --pubkey-file integrations/agents/results/sealed/observer.pub \
  --batches integrations/agents/results/sealed/attested.archive.jsonl  # Phase 3 on real evidence
bash adversarial/atomic/run.sh                       # Phase 4 layer: tests + drift check
cargo test -p aip-corroborate                        # independent corroboration: 32 tests
validation/external/corroborate/run.sh               # live: AIP vs bpftrace + auditd
adversarial/rootkit-runbooks/run.sh                 # Phase 5 harness vs fixtures
```
