# P0-050 execution roadmap

**Concurrent source preserved:** `5bc0c5f` added a general teaching-session
scoreboard while S2 evidence was being finalized. Its source and teaching CI
are present, but this S2 iteration does not independently accept its new trust
bindings. The evidence checkpoint is appended on top; source results for
`6764c7e` remain separately attributed. No shared commit was overwritten.

**S2 continuation:** the sandbox readiness/teaching-CI discrepancy is repaired
in `6764c7e`; see the [evidence checkpoint](../assurance/evidence/p0-050-sandbox/README.md).
Next S2 item is per-launch acknowledgement: a successful readiness probe must not
be mistaken for proof of a later tool launch. Add probe-success/launch-failure
controls; never sign a tool-exit claim without adequate evidence. Estimated
C=4, V=5, D=4, U=5, E=2, I=0 gives **19.333**. Correctness overrides UI work.
Then classify the four retained-render Trivy findings without deleting originals,
before S3 and lifecycle/pack composition. This updates the historical order below.

Iteration 1, 12 November 2026. One bounded change per iteration. No automatic
merge, force-push, licence change, purchase, outreach or new repository publication.
The [gap matrix](P0-050-STRATEGIC-GAP-MATRIX.md) is the source of scope and evidence.

## Scoring method

Score = `(4 × C + 4 × V + 3 × D + 2 × U) / (E + I + 1)`.
These are explicit planning estimates, not measured demand, revenue or staffing.

| Factor | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|
| Customer impact C | Minor convenience | Narrow usability | Useful component | Important evaluator workflow | Blocks a credible core demonstration/pilot |
| Verification value V | Description only | Limited check | Repeatable component check | Strong multi-case evidence | Independent failure detection / critical trust boundary |
| Dependency unblocking D | Isolated | One downstream task | Several tasks | Major workstream | Core chain across workstreams |
| Commercial urgency U | Defer safely | Later evaluation | Helpful current proof | Important evaluation prerequisite | Core buyer/investor acceptance prerequisite |
| Engineering effort E | Up to half an engineering day | About 1–2 days | About 3–5 days | About 6–10 days | More than 10 days |
| Infrastructure I | Existing-resource staging/access effort | Unconfirmed second host or special facilities | Multiple special hosts/facilities | Substantial infrastructure | Major unavailable testbed |

Infrastructure **0** means no additional resource dependency beyond the available
development environment. I is friction/cost ordinal, **not rupees or permission
to spend**. Re-estimate after experiments. Dates are not delivery commitments.

| Raw rank | Item | C | V | D | U | E | I | Score |
|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 1 | S1 Applicability (bounded item delivered) | 5 | 5 | 5 | 5 | 2 | 0 | 21.667 |
| 2 | S3 General scoreboard integration | 4 | 4 | 5 | 4 | 2 | 0 | 18.333 |
| 3 | S14 Commercial sequences | 5 | 3 | 2 | 5 | 2 | 0 | 16.000 |
| 4= | S2 Security / branch integration | 4 | 5 | 4 | 5 | 3 | 0 | 14.500 |
| 4= | S7 Local model / swap | 5 | 4 | 4 | 5 | 2 | 1 | 14.500 |
| 6 | S6 Signed answers / interfaces | 4 | 5 | 4 | 4 | 3 | 0 | 14.000 |
| 7 | S4 Signed expert approval | 5 | 5 | 5 | 5 | 4 | 0 | 13.000 |
| 8 | S5 Knowledge pack | 5 | 5 | 4 | 5 | 4 | 0 | 12.400 |
| 9 | S8 Teaching interface | 5 | 3 | 3 | 5 | 4 | 0 | 10.200 |
| 10 | S9 Sensor qualification | 5 | 5 | 4 | 5 | 4 | 2 | 8.857 |
| 11 | S10 Quantum X-ray | 4 | 4 | 2 | 3 | 3 | 1 | 8.800 |
| 12 | S15 Independent acceptance | 5 | 5 | 3 | 5 | 4 | 2 | 8.429 |
| 13 | S12 Complete kit | 5 | 5 | 5 | 5 | 5 | 2 | 8.125 |
| 14 | S13 Benchmark | 4 | 5 | 3 | 4 | 4 | 2 | 7.571 |
| 15 | S11 PQ proof of concept | 4 | 5 | 2 | 3 | 4 | 2 | 6.857 |

## Executable order and overriding gates

The applicability replay follow-up closes a small S1 verification dependency:
external trust pins, signatures and recomputed outcomes instead of unsigned PASS
summaries. C=4, V=5, D=3, U=4, E=1, I=0 yield **26.5** using the same scale;
these are planning estimates, not benchmark data. Selected while the original
applicability checkpoint was being completed, it is now delivered in bounded
scope. It does not postpone S2 or change the open-item order below. See
`../assurance/evidence/p0-050-replay/README.md`.

1. **S1 completed in bounded scope:** taught context before applicability,
   unchanged 12/12 holdout, 26/26 attacks, 6/6 frozen nonactivation subset. No
   candidate activation or historical artifact rewriting.
2. **Next: S2, sandbox/CI discrepancy.** Security overrides the raw score. Start
   from the current head, review PR #16 against current sandbox and tests, then
   make only the minimal justified integration. Acceptance: authorized output
   actually runs; loopback-only namespace asserted; a genuinely changed exit code
   is rejected; unavailable namespaces fail closed; affected CI tests pass without
   skip/ignore/assertion removal. Classify the separate Trivy failure from its
   actual artifact next; never erase original evidence to satisfy the scanner.
3. **S3**, general answered-session scoreboard and precise cited question linkage.
   Passing a scenario-specific recorder is insufficient to close C1. Preserve the
   now-passing applicability attack gate throughout this work.
4. **S4**, authenticated signed approval composition, expiry/revocation policy,
   source/suite/version/scope bindings, supersession and rollback. Reuse existing
   Ed25519 primitives. No activation on a diagnostic's unsigned verdict.
5. **S5**, signed portable pack; independently held trust keys, policy floor,
   validation/approval/model checks and inactive-by-default import. Then **S6**
   per-answer receipts, replay checks and authenticated REST/MCP/SDK interfaces.
6. **S7** is an independent resource task when verified weights/runtime become
   available. Do not substitute cloud calls. **S8** follows the lifecycle and pack
   gates; its UI must expose NOT READY for unmet dependencies.
7. **S9** qualified native sensor trials on approved Linux hardware can proceed
   as an independent bounded iteration. Preserve the initial network namespace
   where required and prove isolation outside that namespace with captures and
   counters. Retain original signed archives, including failures and restarts.
8. **S10/S11**: recover authorized originals if they become available; otherwise
   review a new implementation against verified requirements. No claimed recovery
   of unavailable commits. PQ remains a proof of concept.
9. **S12**, two complete offline profiles with pre-install hash checks, provenance,
   pinned local dependencies, model licences and no download fallback. Profile A
   targets the founder laptop and labels retained Linux evidence recorded;
   Profile B requires a qualified Linux sensor host. Neither profile is delivered
   by the existing partial kit.
10. **S13**, one-command pinned benchmark on each labelled host. **S14** executes
    the real sequences after their dependencies pass. **S15** requires an external
    evaluator, independent trust anchors, a genuinely separate clean machine and
    consecutive full-mode runs. CI/new directories earn no offline-install credit.

When blocked, record the exact missing resource and select the next safe independent
item; do not skip a dependency inside a workstream. Each iteration fetches, states
acceptance, implements one item, tests/attacks, retains evidence, commits/pushes,
inspects CI, updates the matrix and stops.

## Buyer explanation and pilot boundary

SYNTRIASS AIRON Native runs local intelligence and reuses bounded capabilities
drafted from cited documents and reviewed by an expert. Its customer value is
controlled use of local knowledge with explicit refusal when the evidence or
authorization is insufficient. This is expert-guided capability learning; no
autonomous model training is claimed.

VANIAN Sniffer Dog compares authorized agent behavior with separately observed
execution. Its useful output distinguishes VERIFIED, DIVERGENT and CANNOT_PROVE;
missing coverage must never be presented as proof of absence. Quantum X-ray
discovers cryptographic use and produces a CBOM. SYNTRIASS Overlay's proposed
post-quantum demonstration tests communication protection around an unchanged
application, with an explicit **PROOF OF CONCEPT** boundary.

An initial pilot must agree supported hardware/kernel/runtime versions, tenant and
clearance policy, expert authority and revocation, trust-anchor provisioning,
retention/custody, threat assumptions and refusal behavior. Acceptance must
include all applicable attacks in P0-050, a disconnected installation from the
exact kit, live required scenes, verification without the original agent runtime,
and recovery after expected failures. Use only synthetic documents until those
boundaries are agreed. Product demos do not establish certification or endorsement.

The [founder guide](../demos/DEMO_GUIDE.md) distinguishes runnable component
commands from the planned three-minute/five-minute commercial sequences. Measure
the complete live script before quoting a duration; one short component run cannot
be extrapolated into the investor show.
