# STATUS — Hostile-validation program, pre-RBI

Same self-critical register we use with the RBI. Written for a reader who will
check it against the repository.

## Interoperability continuation — 2026-10-28

Draft PR #9 builds on the already-combined draft PR #8. Actual ADK/A2A and
Microsoft-governed ContextForge runs retain verified gateway receipts, while
the complete institutional same-run acceptance gate remains open. The offline
verifier now optionally authenticates the exact native authority chain and
action scope at issuance; this does not establish revocation, resource policy,
key custody or observed execution. Local host prerequisites and GitHub runner
execution remain blocked. See [the current validation report](docs/interoperability/VALIDATION_REPORT.md)
for exact tests, failures, evidence and remaining guarantees. The historical
observations below are separate runs and are not proof of this new milestone.

## The one-line answer

**Phases 0–4 are built, tested and committed. Phase 1 was executed end-to-end
against a real LangGraph agent; Phase 3 derives the delegation chain from that
same real evidence; Phase 4 grades the observer against an external
(Atomic Red Team / ATT&CK) corpus. Phase 5 is document-only by rule: its
output-parsing harness, per-tool runbook and VM-setup script are built and the
harness is fixture-tested, but no rootkit is run in this environment.** The one
thing that still needs infrastructure absent here is a live rootkit VM capture
(Phase 5), which the safety rules forbid running on this host. **AIP has now been corroborated
by systems we did not build, on both axes**: two independent runtime observers
found no execution missing from its signed evidence, and its identity binding
cross-checks against SPIFFE/SPIRE — agreeing on a live workload and catching one
re-pointed at unapproved code. TRL 5 is unchanged; B8
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
- **Identity corroboration — cross-checked against SPIFFE/SPIRE.** The second
  corroboration axis. Where bpftrace/auditd corroborate what AIP *observed*,
  this corroborates what AIP *binds*. SPIRE v1.15.3 built from source, run
  standalone with the `unix` attestor offering a `unix:sha256` selector — the
  same digest AIP measures from the kernel, which is the join. Live: the two
  **AGREE** on a workload; with the identity re-pointed at different code they
  still agree against SPIRE's *current* registration (so the tool is not
  always-red) and **DIVERGE** against the *approved* one — an unauthorised
  change to a workload identity registration, caught. Soundness control: the
  same program with one byte changed was **refused** by SPIRE, proving the
  digest selector was load-bearing and not decoration. `aip-spiffe`, 25 tests.
  Sealed in `validation/external/spiffe/results/`.
  **Two more defects found, both ours:** the pid-reuse guard cried wolf on a
  healthy workload because SPIRE *pre-mints* SVIDs (so `notBefore` is minting,
  not attestation — re-anchored to the fetch, two tests lock it); and a run
  failed where the probe recorded an exec it could not bind, which the
  comparison correctly answered **NotComparable** rather than inventing an
  agreement. **A claim withdrawn:** the September 2026 SPIRE weakness was
  checked against its primary source and dropped — root-required
  post-exploitation research, Kubernetes attestor, no CVE, no advisory; and
  SPIRE's unix attestor reads `/proc/<pid>/exe`, the same source AIP measures
  from, so any immunity claim would have been false.
- **Out-of-band reconciliation wired to the kernel (F11).** The one gap
  inline enforcement cannot close by being stricter: an agent that declines to
  use the funnel leaves no packet, so nothing in the ledger is missing.
  `ot-sentinel` reconciles observed effects against sealed packets for exactly
  this, and its effect sensor tails a JSONL log — which, in its own source's
  words, "had nothing feeding it", and which in its intended deployment is
  written by the components being watched. `aip-sentinel-feed` (34 tests)
  replaces that root: it verifies an attested archive under the observer's
  anchor, then renders the spawns and connections AIP observed **from the
  kernel** as that effect log. Run against Phase 1's real archive it emits
  **22 records — 21 spawns (agreeing with Phase 3's 21 delegation edges) and
  1 established connection with a measured 81,920 bytes** — sealed at
  `integrations/agents/results/sealed/effect_feed.jsonl`.
  `aip-feed-conformance` (4 tests) settles the join with the consumer itself:
  the real feed parses through `ot-sentinel`'s own tailer with **zero
  malformed lines**, an unapproved destination becomes a finding citing the
  feed's record id, and an approved one produces none, so the detector is not
  always red. The coupling is a **file, not a link** — no packet crosses
  evidence formats, nothing is re-sealed, and
  `docs/adr/ADR-EVIDENCE-CHAIN-FORMAT.md` is now **closed** (option A,
  bounded coexistence) with its boundary still enforced by a test that was
  re-verified against a deliberate violation. **Not corroboration:**
  `ot-sentinel` is ours, so this completes an architecture rather than
  validating one, and the RBI documents say so.
- **A coverage number that was not visible before.** Building the feed's
  scope report exposed a defect in the report itself: it was built only from
  derived values, and `aip-reconcile` discards unbound events before
  derivation, so eight `connect()` attempts in the real archive were counted
  nowhere while the report implied full coverage. Fixed with a direct scan and
  locked by `sf14`/`sf15`, which assert the accounting balances exactly. What
  it then showed: **84 of 105 `execve`s in the Phase-1 run could not be bound
  to a measured instance** — `bash` spawning short-lived children that exited
  before a pidfd-anchored measurement could complete. That is the documented
  `bound: null` case, and this is the first artefact that shows its magnitude
  on a busy host.
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

- **Not past TRL 5.** TRL 6 needs the two-daemon stack watching a real agent
  under representative load on a regulated entity's own hardware — B8, not in
  this lab. The other TRL 6 condition (independent corroboration) is now met.
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
- **Two evidence-chain formats — decided, not merged.**
  `ot-accountability-core` chains `SHA-256(previous ‖ canonical JSON)` as hex
  where `aip-core` chains raw 32-byte digests; a packet sealed by one will not
  verify under the other. `docs/adr/ADR-EVIDENCE-CHAIN-FORMAT.md` is now
  **closed** under option A: `aip-core` is the evidence format everywhere
  outside the import, the second stays internal to the sentinel's
  reconciliation path, and the guard test is permanent. The duplication is
  still there; what is gone is the risk of resolving it by accident.

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
cargo test -p aip-sentinel-feed                      # F11 feed: 34 tests incl. the real archive
cargo test -p aip-feed-conformance                   # the join: ot-sentinel parses and acts on it
cargo test -p aip-test --test evidence_chain_boundary # the closed ADR's boundary, still enforced
cargo test -p aip-corroborate                        # observation corroboration: 32 tests
cargo test -p aip-spiffe                             # identity corroboration: 25 tests
validation/external/spiffe/joint_run.sh              # live: AIP + SPIRE, agreement and divergence
validation/external/corroborate/run.sh               # live: AIP vs bpftrace + auditd
adversarial/rootkit-runbooks/run.sh                 # Phase 5 harness vs fixtures
```
