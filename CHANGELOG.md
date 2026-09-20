# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is [SemVer](https://semver.org/).

## [Unreleased]

### Fixed (a false-accusation path in the central verdict)
- **`PHANTOM_CLAIM` could be drawn over an execution the observer saw and
  could not identify.** The verdict says *the authorised execution never
  happened*, and `recompute_coverage` gated it on a gap-free window, one probe
  run, a clean loss counter and kernel-pushed lifecycle coverage. Every one of
  those checks asks whether the observer was **watching**; none asked whether
  what it watched could be **identified**. An event with `bound: None` is not a
  dropped event — the loss counter stays clean — so coverage passed and the
  reconciler concluded "never happened" across a window containing an execution
  it had witnessed and could not name. The authorised program may have been
  exactly that event.
- On the sealed Phase-1 run **84 of 105 `execve` events were unbound**, so this
  is the ordinary shape of a busy host, not a corner case.
- Fixed in `recompute_coverage`: any process event with `bound: None` in a
  covering batch returns `ReasonCode::CoverageUnboundProcessEvent` (`0x57`) and
  the verdict falls back to `CANNOT_PROVE`. **No protocol change** — the kernel
  events were already inside the signed bytes; the verdict path had simply
  never consulted them. A strict tightening: it can turn `PHANTOM_CLAIM` into
  `CANNOT_PROVE`, never the reverse.
- **Proven non-vacuous.** With the check removed the reconciler returns
  `PhantomClaim` where the test demands `CannotProve`. Two companion tests
  (`t03i`, `t03j`) prove the verdict is still reachable when the window is
  genuinely clean and when the event is bound, so the fix is a correction
  rather than a denial of service on the system's central verdict.
- Ledger rows `GH-01`–`GH-03` in `docs/security/ADVERSARIAL_RESULTS.md`.

### Added (hybrid Ed25519 + ML-DSA-65 signatures — brief Revision 10)
- **`aip_crypto::hybrid`** — the migration path for the evidence horizon §9a
  named one revision ago. Signs under **both** Ed25519 and ML-DSA-65
  (FIPS 204, RustCrypto `ml-dsa`, pinned `=0.1.1`) and **requires both halves
  to verify**. Either-suffices would defeat the construction outright: a break
  in Ed25519 alone would then forge a hybrid signature and the second
  algorithm would be decoration. 15 tests.
- **Neither era can be mistaken for the other**, and it costs nothing because
  the `AlgorithmId` was already inside the signed bytes. The Ed25519 half of a
  hybrid signature does not verify as a standalone signature (`h05`), and a
  standalone signature relabelled `Hybrid` and padded with ML-DSA-shaped bytes
  is caught **by the mature algorithm, not only by the new one** (`h06`).
- **Nothing already sealed changes.** `sign_ed25519` and `verify_ed25519` are
  untouched; the hybrid path is additive (`h09`). A migration that invalidated
  the history it was meant to protect would be worse than none.
- **`SignaturePolicy`** belongs to the verifier, not the artefact. A strict
  verifier refuses an Ed25519 artefact as **insufficient, not invalid**
  (`h10`) — logging a correctly signed document under a superseded algorithm
  as a bad signature would make an estate mid-migration read as though it were
  under attack.
- **Demonstrated end to end** on a real signed document: `RouteMap::verify_under_policy`,
  with a route map sealed hybrid, serialised, reloaded and verified offline
  under a strict policy; the Ed25519 map still accepted under a transitional
  one; a route edited after hybrid signing still caught. 5 tests
  (`hybrid_migration::hm01`–`hm05`).
- `THIRD_PARTY_LICENSES.md` records the shipped cryptography, including that
  `ml-dsa` is **pre-1.0 and not independently audited** — which is exactly why
  the construction verifies the mature half too, and why the pin is `=` rather
  than caret.

### Changed
- `aip-nexora/tests/audit.rs` a07's **comment** corrected, its assertions
  untouched. It said "exactly one is implemented"; `Hybrid` now is, by a
  different function taking a second key. The test is still exactly right:
  `verify_ed25519` must refuse a `Hybrid` label rather than check it, because
  a caller holding only the Ed25519 key must never verify half a hybrid
  signature and believe it verified the whole. The layering is the guarantee.

### Still not done, and said so in the brief
- **The four evidence-signing authorities are not migrated.** Collector,
  decision point, reconciler and gateway all still sign Ed25519, so **no
  evidence artefact carries a hybrid signature**. The primitive and the
  transition policy exist and one document type is exercised end to end;
  rolling that through the evidence families, the NEXORA log and the three
  offline verifiers is mechanical but unbuilt. That work touches the most
  safety-critical code in the repository and was deliberately not attempted in
  the same pass as the primitive.
- Standalone ML-DSA-65 remains a refused identifier. PKCS#11 custody was
  exercised for Ed25519 only. The size cost — a 3,309-byte signature against
  Ed25519's 64 — is unmeasured, and an institution should size it before
  committing.

### Added (the evidence horizon — brief Revision 9, matrix D8)
- **A branch survey found the gap by accident.** `codex/val-ladder-sync` carries
  an `ML-DSA-65` assembler-signature hook and a Kyber-768 network layer, and
  checking whether any of it belonged in the RBI submission surfaced a
  different question that did: post-quantum appeared **once** in the technical
  brief, inside a list of things "not deployed", and **zero times** in the
  requirements matrix and the cover note.
- That is a gap because this submission asks a regulator to treat signed
  artefacts as evidence re-verifiable later, and D7 puts a **180-day CERT-In
  retention floor plus a legal hold that outlives it** into the database. An
  artefact held for a proceeding may need to verify years after signing.
  Everything is Ed25519, so **the non-repudiation of retained evidence has a
  horizon**, and unlike confidentiality it cannot be repaired afterwards.
- Brief **§9a "Cryptographic agility and the evidence horizon"** states it,
  along with the part that is already right and is the hard part: the algorithm
  identifier is *inside* the signed bytes so it cannot be rewritten, and an
  unimplemented algorithm is **refused with an error — never checked as
  Ed25519, never reported merely invalid**. A label may not become a
  capability (`aip-nexora/tests/audit.rs` a07, plus a companion proving the
  refusal reaches package level). Migration is therefore a change of
  implementation, not of evidence format.
- It also states, in the same section, what has **not** been done: no
  post-quantum signature is implemented; **Kyber-768 is a KEM — session
  confidentiality — and gives no signature path**, and conflating the two would
  be exactly the kind of claim this brief exists not to make; no hybrid signing
  has been exercised through the four authorities, the NEXORA log and the three
  offline verifiers; and PKCS#11 custody was exercised for Ed25519 only.

### Not added, and why
- **Nothing else from `codex/val-ladder-sync` or `codex/aip-v4-accountability`
  enters the submission.** Those branches carry the superseded AIRON design:
  `/v1/identity/issue` JWT endpoints, `/.well-known/jwks.json`, and
  `aip-service/src/delegation.rs` — the weak legacy delegation routes this
  branch **deliberately removed** for the RBI submission. Their
  `benchmark-results/*.json` are dated March 2026 and exercise those removed
  routes, so they are not current performance evidence and must not be
  presented as any.
- The `python/airon-aip-sdk` LangChain, PyTorch, NumPy and pandas integrations
  are **not** the framework adapters blocker B9 names. They attach identity
  metadata and tags to a runnable against the legacy JWT service; they do not
  sign AIRI events or feed the evidence pipeline. B9's status is unchanged and
  correct, but the existence of adapter-shaped code on a branch is recorded
  here so nobody reads it as a contradiction.

### Added (F11: out-of-band reconciliation fed from the kernel)
- **`aip-sentinel-feed`** — renders verified AIP evidence as the effect log
  `ot-sentinel`'s out-of-band reconciler tails. Closes the one failure class
  no amount of additional strictness reaches: an agent that does not use the
  governed path leaves no record to be missing from, and inline enforcement
  cannot see its own bypass. The reconciler's effect sensor previously read a
  JSONL log which, in the deployment it was designed for, is written by the
  components being watched — its own source records that the detector behind
  it "had nothing feeding it". The feed replaces that root with kernel-derived,
  pidfd-bound, collector-signed evidence. Verifies the archive under the
  observer's anchor **first** and writes nothing if that fails. 34 tests.
- **`aip-feed-conformance`** — test-only crate, 4 tests, and the only place
  the two evidence worlds link. Against the real Phase-1 archive: **0 malformed
  lines** through `ot-sentinel`'s own tailer, an unapproved destination
  becoming `UNAUTHORIZED_EGRESS` citing the feed's record id and carrying the
  measured 81,920 bytes, and a soundness control proving the detector is not
  always red. The 21 spawn records agree with the 21 delegation edges Phase 3
  derives from the same archive.
- **Sealed:** `integrations/agents/results/sealed/effect_feed.jsonl`.
- Technical brief **Revision 8**, section 10c — filed as an architecture item,
  explicitly **not** as a third corroboration axis, because `ot-sentinel` is
  ours. Ledger rows `OB-01`–`OB-11`, `OB-H1`, `OB-H2` in
  `docs/security/ADVERSARIAL_RESULTS.md`.

### Changed
- **`docs/adr/ADR-EVIDENCE-CHAIN-FORMAT.md` is CLOSED** — option A, bounded
  coexistence. `aip-core` is the evidence format everywhere outside the
  import; `ot-accountability-core` stays internal to the sentinel's
  reconciliation path. Option B (porting the sentinel, 6,181 lines and 82
  tests, forking from upstream) was rejected as a large regression risk
  against no external gain. The feed made option A worth having by working on
  the *observation* side, which carries no chain, so no packet crosses formats
  and nothing is re-sealed — the objection that sank the translation-layer
  option does not arise. The dependency guard is now permanent, its message
  points to the two legitimate ways forward, and it was re-verified against a
  deliberate violation.

### Fixed
- **The feed's coverage report undercounted its own blind spots.** It was
  built only from derived values, and unbound events are discarded *before*
  derivation — correctly, since an unbound event is not evidence of a process
  instance. **Eight `connect()` attempts in the real Phase-1 archive were
  counted nowhere** while the report implied full coverage. A direct scan now
  counts them; `sf14` locks the regression and `sf15` asserts the accounting
  balances exactly against real evidence. (`OB-H1`)
- **RFC 5952 rendering dropped the trailing colon** on an address ending in a
  zero run, so `2001:db8::` rendered as `2001:db8:`. A destination rendered in
  a form an allow-list does not use is a false negative in the one check that
  matters. Rewritten as a head/tail join; 11 tests including IPv4-mapped,
  longest-run and leftmost-tie cases. (`OB-H2`)

### Disclosed
- **84 of 105 `execve` events in the Phase-1 run could not be bound to a
  measured process instance** — a shell spawning short-lived children that
  exited before a pidfd-anchored measurement could complete. The mechanism was
  already recorded (`XI-H2`); the **magnitude on a workload of that shape** was
  not, and became visible only after fixing `OB-H1`. The system reports the
  remainder as unmeasured rather than guessing, which is `CANNOT_PROVE`
  operating as specified — but the coverage ratio must be measured per
  deployment, never assumed, and a pilot must report it for the institution's
  own workload. Raising it is probe-side engineering (earlier pidfd
  acquisition) and is on the roadmap, not presented anywhere as solved.

### Added (Phase 0 of the hostile-validation program: cross-sensor blinding detection)
- **The gap the pre-RBI validation plan identified as decisive is now closed
  in code.** The kernel increments the perf loss counter (`PERF_RECORD_LOST`)
  only in the `fail:` path of `__perf_output_begin()`, when the ring is
  genuinely full. A rootkit that hooks the submission path (`perf_event_output`,
  `perf_trace_run_bpf_submit`, `bpf_ringbuf_submit`) and returns early produces
  no sample **and** no loss record — an invisible drop that a sensor's own
  books cannot see. Every public eBPF-blinding PoC works this way.
- **`aip-observe::divergence`** — a pure detector for the one signal that
  survives such a hook: a gate-independent netlink connector `Exec` that the
  perf `sched` tracepoint, declared live in the same batch, did not corroborate
  within a 50 ms window. It is expressed as `MechanismIntegrity::Unverifiable`
  (not `ForeignTracepointGate` — the probe found no program; the collector
  simply cannot establish the silent sensor was capable), which already drives
  `IntegrityUnknown`. 10 unit tests: agreement, the decisive miss, the
  fail-closed preconditions (silence is divergence only when the sensor was
  live and the connector anchor was present), the window boundary, the
  `(pid,tgid)` join key, aggregation, and exec-only comparability.
- **Wired into the collector sink** before attest: the collector, as attesting
  authority, records its cross-sensor finding into the batch's integrity
  reports, overriding a probe's too-rosy self-report for that cycle; a later
  clean batch restores `Verified` and recovery proceeds. **Exit-gate test:** a
  batch shaped exactly as a delivery-path hook produces it — connector
  delivered the exec, perf did not, probe reported perf `Verified` — still
  lands on `IntegrityUnknown` with coverage withdrawn. Negative control (both
  deliver) raises nothing.
- **`docs/security/BLINDING_RESILIENCE.md`** scores all five honest signals
  (perf `PERF_RECORD_LOST`, netlink `ENOBUFS`, cross-sensor divergence,
  heartbeat/sequence-gap, the signed coverage rule): what each catches, what
  each misses, and why signal 3 is load-bearing. The audit found the other
  four already existed; divergence was the one genuine gap.
- **Limit kept intact:** this defeats a *single-path* delivery hook, the common
  case. An attacker who hooks both paths, or the connector alone, defeats it;
  that is the standing kernel-compromise limit and is not narrowed. TRL 4/5
  unchanged; nothing here ran on institution hardware or observed a real agent.


### Added (the OrbitalTrust accountability layer, audited and partly wired)
- **`orbitaltrust-accountability/` merged and two of its four Rust crates
  wired into the workspace.** The import had been sitting on a branch,
  additive and unbuilt, since 2026-08-28.
- **`ot-sentinel` is why this was worth doing.** Everything else in this
  repository is *inline*: it proves what went through the funnel and has no
  answer for an agent that declines to use the funnel at all — one that calls
  a tool server directly, keeps running after revocation, or spawns a copy of
  itself. Inline enforcement cannot see its own bypass. The sentinel
  reconciles what independent sensors observed against what the ledger
  sealed, one-to-one on the digest of the canonical call parameters, so a
  ghost cannot hide behind a concurrent legitimate call of the same tool and
  a replayed call has no second packet to account for it. **82 tests pass.**
- **`ot-accountability-core` wired; 56 tests pass** — exactly the count the
  import claimed.
- **Two of the four crates cannot build here, and the import did not say so.**
  `ot-mcp-gateway` (11 non-optional references across 6 files) and
  `ot-verifier` (2) depend on `ot-pqc`, which the source workspace lists as a
  sibling and which **was not brought across**. The import's own message said
  only that the crates "will not build here until added to a workspace
  carrying that block or pinned directly", which is true and is not the whole
  obstacle. `ot-mcp-gateway` is the funnel on the MCP wire — directly the
  capability blocker **B10** describes as outstanding — so this is the
  expensive half of the gap.
- `ot-sentinel/tests/ghost_hunt.rs` (31 tests) is **preserved verbatim and
  excluded from compilation** via `autotests = false`, because it needs both
  absent crates. A stated exclusion, not a deleted test.
- **The import's SHA-256 manifest still holds, and it is checked rather than
  claimed.** `verify_manifest.py` compares all 114 files and exits non-zero if
  any but the two rewritten `Cargo.toml` files has moved: **112 byte-identical**.
  A clippy lint on `runtime.rs` is exempted in the manifest rather than fixed
  in the source, because silently rewriting imported code to satisfy a style
  lint destroys the one property that manifest exists to give.
- Dependencies are pinned directly in the two crates rather than inherited
  from the source workspace's `[workspace.dependencies]`, so resolution for
  the forty crates already here is unchanged. New third-party dependency:
  `tempfile`, dev-only, reaching no shipped binary.
- **`docs/adr/ADR-EVIDENCE-CHAIN-FORMAT.md`, status OPEN** *(superseded — closed 2026-09-20 under option A; see the F11 entry below)* — the decision
  written down rather than made by accident. Four options with the reasoning,
  including the one rejected on sight (porting `aip-core` onto the imported
  chain would invalidate every shipped verifier, the NEXORA log, the
  attested-batch chain and every sealed demonstration in
  `ADVERSARIAL_RESULTS.md`) and the one rejected for now (a translation layer
  makes the re-sealer a party the verifier must trust, which is the opposite
  of the point).
- **The rule is a test, not prose** *(now permanent, per the closed ADR)*.
  `aip-test/tests/evidence_chain_boundary.rs` scans every `Cargo.toml`
  outside the import and fails if any declares `ot-accountability-core`,
  `[dev-dependencies]` included. A second test pins that the crate still
  exists, so the guard cannot start forbidding something absent and pass
  forever. Both were checked against a deliberate violation: adding the
  dependency fails the guard, removing it passes.
- **`WHAT_THE_TESTS_PROVE.md` gains the failure class it was missing.** Its
  ten classes came from the risk map, which was written about agents that
  *use* the accountability channel. **F11 — the agent declines to use it at
  all** — was absent, and its absence is the worked example of §1.1's point
  that tests written by the party being tested miss the class nobody thought
  to name. `ot-sentinel` addresses it at rung R2; its 31 end-to-end ghost-hunt
  tests cannot run here, so the reconciliation primitive is unit-tested and
  the ghost hunt is not.
- **Still open, and now more urgent rather than less.** The two hash-chain
  constructions are not byte-compatible — `aip-core` chains raw 32-byte
  digests, `ot-accountability-core` chains `SHA-256(previous ‖ canonical
  JSON)` as hex. A packet sealed by one will not verify under the other.
  Wiring made the incompatible construction *compiled* rather than dormant.
  This is deliberately **not** reflected in the RBI submission documents:
  two incompatible evidence chains is not something to put in front of a
  regulator mid-resolution.

### Fixed (the TRL number in the RBI documents was wrong, and the repository contradicted itself)
- **Three documents gave three different readiness levels.** The submission
  documents used **TRL 4**, taken from
  `docs/idex_open_challenge/02_TECHNOLOGY_AND_TRL.md` (2026-06-14) — the
  oldest of the three, and one that `TECH_AUDIT_AND_ROADMAP.md` (2026-08-23,
  also TRL 4) already flags as stale for unrelated reasons. The current
  assessment is `ENGINEERING_MATURITY_AND_STRATEGIC_READINESS.md`
  (2026-09-07), a post-validation addendum that assesses maturity **by
  component**: the AIRI/Sniffer Dog software accountability core at **~TRL 5,
  approaching TRL 6**, physical-autonomy profiles at TRL 4, and physical
  autonomous-system accountability at TRL 2–3.
- **Neither 4 nor 6 is right.** The brief and covering note now state **TRL 5
  for the software accountability core**, differentiated by component, and say
  in terms that TRL 6 is not claimed. The gate is quoted from our own
  assessment rather than paraphrased: *a non-synthetic agent under
  representative load*. Every agent this system has observed was written by us
  to be observed, and that single missing condition is exactly what the
  proposed pilot supplies — the same gap as blocker B8, expressed in readiness
  terms rather than deployment terms.
- Understating a readiness level to a regulator is a smaller error than
  overstating one, and it is still an error: a number that does not match the
  vendor's own repository is the same defect pointing the other way, and the
  repository is offered to the Department on request.
- The two superseded documents now carry a note saying so and pointing at the
  addendum, so a reader who asks for the repository does not find three
  numbers. The addendum gains a dated record of what has been demonstrated
  since it was written — the live two-daemon attack, the Phase 1 exit gate,
  the attested clock, the measured signing path — **and why the band does not
  move**: none of it supplies a non-synthetic agent, and all of it ran on the
  same development host.

### Changed (the RBI submission documents, redrafted for accuracy)
- **The brief's "no performance figure has been measured" was false twice
  over** — the evidence vault has had figures since `STORAGE_PERFORMANCE.md`,
  and the observer path now has its own. Replaced with the measurement, its
  host line, and the decomposition that matters.
- **`docs/OBSERVER_PERFORMANCE.md`** and `validation/perf/observer_path.txt`.
  On four cores at 2.80 GHz, single-threaded, 139-byte batch: attest 395 µs
  (~2,500/s), verify offline 46 µs (~21,700/s), so a retained archive of one
  million batches verifies in ~46 s on one core. **Of the 395 µs, 43 is
  signing and chaining and 351 — 89% — is writing the chain position to
  disk.** Attestation is bound by storage, not by cryptography: the lever for
  more throughput is the storage path, and replacing Ed25519 would move 11%
  of the cost. The benchmark measures the signer with and without the persist
  precisely so that question is answered with a number.
- **Two documents in the same email disagreed.** The brief said no
  readiness-level figure was quoted; the covering note stated TRL 4. The brief
  now states TRL 4 explicitly and says what TRL 5 would require. The covering
  note said the brief was nine pages — it is ten — so the count is now read
  from the rendered enclosure and cannot drift again; a missing brief is a
  hard error rather than a stale number.
- **"Our software not in the trust path" was not accurate**, because the
  verifier we ship is our software. Replaced with the property that is true:
  the format is published and canonically encoded, the verifier opens no
  network connection and reads nothing from us at run time, and the
  institution may write its own against the same specification. The trust
  rests on the format and the institution's keys, not on our binary being
  honest.
- The brief now names `aip-observe-verify`, `attested.archive.jsonl` and
  `observer.pub` where it previously described them in prose, so a technical
  reviewer can ask for them by name.

### Fixed (a guard that clippy was right to reject)
- `container_identity.rs` asserted `OBSERVE_PROTOCOL_VERSION >= 11` at
  runtime — a comparison between two constants, which is not a test. It is now
  a `const` assertion, which is strictly stronger: a version that cannot carry
  the protocol-11 field fails the **build**, for everyone, rather than only
  when that test is run.
- The throughput benchmark was briefly added to the RED suite manifest and
  correctly failed: it is `#[ignore]`d, so its selector matches zero tests, and
  the runner's "a filter matching nothing is not a pass" rule caught it.
  Reverted rather than weakened — the suite's contract is one row per
  adversarial ledger entry, and a measurement is not an attack.

### Added (an honest answer to "do the tests prove we solve the problem?")
- **`docs/pilot/WHAT_THE_TESTS_PROVE.md`.** The answer is **no**, and the
  document says so in its first paragraph. The tests prove an *evidentiary*
  property — given evidence this system produced, tampering is detectable and
  the system will not assert coverage it cannot justify — which is not an
  outcome property and is not the same as preventing an agent from doing harm.
- **A four-rung ladder** replaces the binary "tested / not tested" that a
  matrix disposition implies: by construction, adversarially tested against
  synthetic inputs, demonstrated live on a development host, and demonstrated
  in the target environment. **Nothing in this repository is on the fourth
  rung**, and the document says that is the honest headline.
- **The ten failure classes of `RBI_AGENT_RISK_MAP.md` scored individually**,
  each with what the tests establish and what is missing before the class is
  actually solved. The weakest row is `PHANTOM_CLAIM` — the class regulated
  entities are buying against — which is reachable by construction and on
  synthetic inputs and has never been produced end to end on live hardware.
- **Three structural limits stated up front**, none of which more testing
  inside this repository removes: every attack in the ledger is one we thought
  of; most of the suite constructs its inputs in one process; and nothing here
  has run on a regulated entity's hardware or observed a real agent.
- **The four claims that are supported**, written as sentences that can be
  defended under questioning — and the sentence that must not be said.
- **"All twenty roadmap items are done" is answered separately**, because it
  is true and is not the same answer. R1–R20 are built, four with qualifiers
  that must travel with them (R5 binding side; R11 and R16 as mechanisms whose
  placement is the institution's; R13 as controls whose operation is). But
  completing a list derived from our own reading of the RBI instruments is a
  closed loop: it shows we built what we said was needed, not that what we
  said was needed is sufficient. Exactly one matrix row in sections A–F is
  still `BUILD` — **C6**, `PHANTOM_CLAIM` on real hardware — and no roadmap
  item closes it; pilot Phases 2–3 do. Section G is out of scope by design
  and names an owner per row. The roadmap is complete; the matrix is not; the
  ecosystem is not.
- Linked from `RBI_REQUIREMENTS_COVERAGE.md`, `RBI_AGENT_RISK_MAP.md` and
  `BFSI_PILOT_PLAN.md`, each with a note that a disposition is not a proof. The
  technical brief's section 10 carries the same three limits in the body rather
  than in a footnote.

### Added (observe protocol 12: the collector's clock discipline is signed evidence)
- **The clock reading was a control nobody could check.** The collector
  stamps `attested_at_ms` on every batch and `emitted_at_ms` on every health
  record; those stamps are the evidence's placement in time. The clock behind
  them *was* checked — `ntp_adjtime` at start and on every health cycle, a
  fail-closed startup gate, CERT-In Direction 20(3)/2022 — and the answer went
  to the daemon's log. A log is not evidence a verifier holds, and the brief
  said so: *"the clock-discipline reading is operational, not attested."*
  The failure mode is why this is a protocol change rather than a note: an
  undisciplined collector does not produce one wrong timestamp, it produces an
  archive that is wrong **together** and perfectly self-consistent, which
  nothing inside the sealed bytes reveals.
- **`SensorHealth.clock: Option<AttestedClock>`** — synchronised flag, the
  kernel's error bound in microseconds, and the raw `ntp_adjtime` return code
  — inside the canonical bytes the key signs (`OBSERVE_PROTOCOL_VERSION`
  **11 → 12**; version-11 records are refused). `None` means **not read**,
  never "fine", and is encoded distinctly, so a collector that never looked at
  its clock cannot pass as one that looked and found it disciplined.
- **The daemon reads; the signer signs.** `clock_discipline()` is called in
  `aip-collector`, at the process boundary, and the reading is handed to
  `CollectorRuntime::health_with_clock`. `aip-observe` performs no syscall on
  that path, so what the key signs is what that process observed rather than
  something the library fetched for itself. A failed read yields `None` and
  health keeps being emitted: a collector that stopped signing health because
  it could not read its clock would withdraw coverage for a reason unrelated
  to coverage.
- **`AttestedClock::within(budget_ms)`** is the same predicate the startup
  gate applies, so a verifier reaches the daemon's answer instead of
  re-deriving the rule. Both conditions must hold: a stale bound on a clock
  nothing is steering fails however small it is.
- **Ledger rows CL-01..CL-09**: editing, dropping and inserting the reading
  after signing each fail verification; absence is distinguishable from a good
  reading and an unsynchronised reading from a synchronised one with the same
  bound; a negative `maxerror` (which `c_long` permits) round-trips exactly;
  and this host's real reading round-trips into signed evidence.
- `aip-observe-verify` reports three counts — steered, adrift, not stated —
  and the worst bound any record asserted, and judges none of it. What bound
  is acceptable is the institution's policy; what the verifier will not do is
  let silence read as a good reading.
- **Bounds, unchanged.** Root on the collector host can call `adjtimex` itself
  and clear `STA_UNSYNC` on a clock it has just moved. Signing raises the bar
  from "trust the operator's log" to "the key signed this claim" and no
  further (N1).

### Fixed (a live test conflated "the image was wrong" with "we saw the image")
- **`ghost-demo/tests/live_exec.rs` was intermittently red under load.**
  `x_a_wrong_image_is_a_transition_mismatch_on_content` asserts the reason is
  `ActionEvidenceDoesNotMatch`. On a loaded host the `fork`/`exec` pair can be
  incomplete when the window closes, and the engine then answers
  `ActionTransitionIncomplete` with the action `Unobservable`. **That is the
  architecture working** — absence of evidence is not converted into a
  finding — but a test asking *"is a wrong image reported as a content
  mismatch?"* is asking something that only has an answer once the image was
  seen.
- Observation of the execution is now an explicit **precondition**: the run is
  repeated (at most three times) while the action comes back `Unobservable`,
  and the test fails loudly if it is never observed rather than passing on a
  run that proved nothing. The retry never fires because the observer saw
  something and the verdict disagreed, so a real regression still fails on the
  first attempt.
- Scoped to the three tests whose assertion is about the action comparison.
  `x_b` and `x_c` deliberately keep the plain run: for
  `ExecBeforeAuthorization`, `Unobservable` is the **correct** action outcome —
  the exec fell outside the window and the verdict rests on
  `temporal: BeforeWindow` — so applying the precondition there would reject
  the result the test exists to pin. The precondition is also deliberately not
  `availability.is_covered()`: in this demonstrator a run that reaches
  `VerifiedExecution` on a matched exec transition still reports
  `WindowNotCovered`, so coverage would have rejected passing runs.

### Fixed (the reference tests passed for the wrong reason)
- **Five profile test crates depended on build order.** `aip-robotics`,
  `aip-industrial`, `aip-space`, `aip-uas` and `aip-enterprise` all drive
  `aip_edge::orchestrate::run`, which spawns `aip-edge-observer` and
  `aip-edge-workload`. `cargo test --workspace` does not build those: a
  package's binaries are compiled for tests only when that package has
  integration tests of its own, and neither has any. Only `aip-edge`'s own
  harness built them, so the five profiles passed when `aip-edge` happened to
  run first in the same invocation and failed on a clean checkout. The
  protocol-12 bump exposed the worse half of the same defect: a binary left
  over from before a protocol change is *found*, spawned, and emits records
  the current engine refuses, so the failure surfaces as an evidence error
  with nothing to do with evidence.
- `aip_edge::transport::ensure_sibling_binaries()` is now one implementation
  in the library that every consumer calls, and it **always** runs
  `cargo build` rather than only building what is missing — a no-op when the
  binaries are current, and the correct action when they are stale.

### Added (the Phase 1 exit gate: the evidence survives, and an outside party can verify it)
- **The collector kept nothing it signed.** `RuntimeSink` attested a batch,
  took its sequence number for the acknowledgement and dropped it. The chain
  position was persisted, which proves a batch existed; the batch itself was
  not. The pilot's own Phase 1 exit gate — *"a real agent process is observed;
  its batch is signed by a collector on a different host; **the verifier
  accepts it offline**"* — was therefore unreachable, whatever this
  repository's tests said about the library functions behind it. Every
  `AttestedBatch` is now appended to `attested.archive.jsonl` (one JSON
  object per line, in attestation order; path overridable with
  `AIP_COLLECTOR_ATTESTED_ARCHIVE_PATH`). A write failure is returned to the
  probe rather than logged and swallowed: a probe must learn that its batch
  was not durably kept instead of being told everything is fine.
- **The collector publishes its evidence *public* key.** `observer.pub` is
  written beside the state at every start and echoed to stderr. Before this,
  the only way to obtain the anchor an auditor needs was to unwrap the
  private key with the passphrase — precisely what custody exists to prevent.
  The Noise static public key is published the same way (`noise.pub`), so an
  operator pins a named file instead of scraping a log for "the 64 hex
  characters"; with two public keys now printed at start, that scrape pins
  whichever the daemon happened to print first.
- **`aip-observe-verify`** — the verifier an auditor actually runs.
  `aip-verify` covers `EvidencePacket`s; nothing covered the **observer**
  chain, so the gate's third clause had no tool behind it. Given two archive
  files and one public key it checks every signature, then the chain that
  links them: sequences contiguous, and each record's `prev_head` equal to the
  **recomputed** head of the one before it (`AttestedBatch::head()` derives
  the head from the record's own bytes, so there is no supplied hash to
  trust). It cross-checks signed health heads against the attested batch at
  the same chain position — both signatures are valid in isolation, and only
  that comparison exposes a collector that signed two different answers about
  one moment. It opens no socket, reads no environment, and has no
  command-line parser dependency: the binary whose claim is a minimal trust
  surface should not ask an auditor to account for a transitive dependency
  tree. Exit 0 verified, 1 findings, 2 unusable arguments.
- **Ledger rows EA-01..EA-10** in `ADVERSARIAL_RESULTS.md`, executed against a
  **real** attested chain rather than hand-written fixtures: wrong key, edited
  observation, a record deleted from the middle, reordering, duplication, a
  corrupt line, an empty archive, a disagreeing health head, and two controls
  (clean chain; a mid-chain window, accepted *and reported as a window*).
  Deletion and reordering leave every surviving signature genuine, so only the
  chain check catches them — which is why the chain check exists.
- **Phase D of `validation/pilot_e2e/run.sh`.** The live demonstration now
  ends by running the verifier as a separate process against the archives the
  live collector just wrote, with only the published `observer.pub`, and then
  running the same verifier against the same archive with one record deleted,
  which must be refused. A verifier that accepts everything is worth nothing,
  so the negative control is part of the demonstration.
- RED suite: **46 rows**; 43 reproduced or runnable on a privileged host, one
  deferred (`OI-08`), zero failing.


### Security (pre-evaluation fixes for a supervised BFSI pilot)
- **The second authority engine in `aip-service` is gone.**
  `POST /v1/identity/delegate` and `POST /v1/identity/verify-chain` — unsigned
  delegation tokens whose keyless hash omitted `scope` and `expires_at`, no
  attenuation at issuance, an unauthenticated chain verifier that answered
  ADMIN for a bare root JWT — are removed together with
  `aip-service/src/{delegation,capability}.rs` and `AIP_DELEGATION_LOG_PATH`.
  Delegated authority is expressed only by signed `aip-core` chains inside
  evidence packets. The discovery document (`AipConfiguration`, `aip-types`)
  no longer advertises a delegation endpoint (`delegation_verify_uri`
  removed — a wire change to an unsigned discovery document).
- **Revocation is a tenant-scoped, authenticated fact.** `RevocationEntry`
  carries `tenant_id` (from the administrator's API key, never the body);
  the in-memory set is keyed `(tenant, jti)`; identity JWTs carry the
  minting tenant as a `tid` claim and are checked against their own tenant's
  revocations; `GET /v1/identity/revocation-status/{jti}` requires a key and
  answers for the caller's tenant only (it was a public oracle over every
  tenant's log); `cascade` is refused rather than silently ignored; JTIs are
  canonicalised to 32 hex characters so a UUID JWT id and a 16-byte evidence
  JTI share one spelling. Pre-tenancy log lines load under the legacy tenant
  with their original hash.
- **`POST /v1/evidence/verify` consults the server-side revocation set.**
  The caller's `revoked_jtis` are unioned with the tenant's revocations
  recorded through `POST /v1/identity/revoke`; a revoked chain JTI fails
  `REVOCATION` whether or not the caller lists it. Tests:
  `aip-service/tests/revocation_scope.rs` (HTTP level, two tenants).
- **The two-host observer can now sign `IntegrityUnknown`.** `ObservationBatch`
  gains `mechanism_integrity: Vec<MechanismIntegrityReport>` — the probe's
  per-sensor foreign-eBPF finding — inside the attested bytes
  (`OBSERVE_PROTOCOL_VERSION` **9 → 10**; version-9 batches are refused).
  `aip-probe` reports every open tracer every cycle; `CollectorSigner`
  absorbs reports fail-closed (a `Verified` report counts only for a
  mechanism the batch declares active); `aip-collector`'s sink treats a
  declared gate-able sensor with no report as `Unverifiable`. `ghost-demo`
  now declares findings into the probe so the demo and the pilot share one
  path. Tests: `aip-collector/src/sink.rs`; ledger §OI rows OI-09..OI-12.
- **The pilot probe drives the netlink process-event connector**
  (`AIP_PROBE_SENSORS=...,connector`; `CAP_NET_ADMIN` and `AF_NETLINK` added to
  the systemd unit). It is the pilot's only gate-independent kernel-pushed
  source and the only coverage the reconciler accepts for a process-lifecycle
  non-occurrence claim; without it `PHANTOM_CLAIM` was unreachable in the
  pilot topology. `ENOBUFS` is recorded as counted loss.

### Demonstrated (the Phase 4 attack, executed against the two real daemons)
- **`validation/pilot_e2e/run.sh`.** The technical brief said, of the
  foreign-eBPF tracepoint gate, that the two-host path was "covered by
  automated tests against synthetic batches" and that "the live attack
  against the two daemons ... is a pilot Phase 4 item". This runs that
  attack. Not a synthetic batch and not an in-process shortcut:
  `aip-collector` and `aip-probe` are separate processes, the probe holds no
  key and has four kernel sensors open, the link is the authenticated and
  confidential transport, and the evidence read afterwards is the collector's
  own signed health archive.
- **The result, sealed in `validation/pilot_e2e/results/sealed/`.** Control:
  `Active`, attested coverage present, sequence 12. Under a foreign eBPF
  program returning 0 on `sched:sched_process_exec`: **`IntegrityUnknown`,
  coverage withdrawn**, sequence 39. Detached: `Active` again, sequence 66.
- **Why the sequence numbers are the point.** They advance throughout, so the
  observer was never down and the chain never broke. This is neither loss nor
  a continuity failure: it is a live, continuous observer stating — in a
  record signed by a *different process holding the only key* — that it
  cannot establish its own capability over that window. Absence of an exec in
  that window therefore carries no information, which is what stops it
  becoming a `PHANTOM_CLAIM` against an innocent workload.
- **One attach is enough.** The instrument reported `cpus=1` with `EEXIST` on
  the other three. That is the mechanism, not a partial failure: the BPF array
  is keyed on the tracepoint, so the first attach installs the gate and later
  attaches are refused, and that one attach blinds every perf consumer of the
  tracepoint host-wide.
- **Sealed as ledger rows OI-13 to OI-15** and wired into the RED suite as
  `requires=pilot_e2e` rows, driven by that script rather than by `cargo test`.
- **What this does not close, stated.** The attack is detected, not prevented
  — a CAP_BPF adversary can blind the sensor. It ran on a development virtual
  machine, so blocker B8 (the run on a regulated entity's own hosts) is
  unchanged. And it is not `PHANTOM_CLAIM`: matrix row C6 additionally needs
  the decision point issuing signed expectations into the same pipeline, which
  is pilot Phases 2-3. C6 is narrowed, not closed.
- Technical brief regenerated as **Revision 4** with the superseded claim
  replaced. Throwaway key material from the run is gitignored; the signed
  health archive, the daemon logs and the attack log are committed as the raw
  output the ledger cites.

### Added (RBI requirements coverage — E4: clock discipline, and what it does not prove)
- **`aip_observe::clock`.** `BootClockAnchor` samples the realtime and boot
  clocks together so a kernel-timestamped event can be *placed* on the wall
  clock; it says nothing about whether that wall clock is right. An
  undisciplined host hands out a perfectly self-consistent anchor while
  being hours out. This module asks the kernel the other question through
  `ntp_adjtime`: is a daemon steering this clock, and what does the kernel
  believe its error bound to be. It reads and never sets — `modes: 0` is the
  pure query, and a module that could adjust the clock it reports on would
  be a poor witness.
- **The collector refuses to start on a bad clock.** It stamps and signs
  every attested batch, so an undisciplined clock there does not produce one
  wrong timestamp — it produces an archive that is wrong *together* and
  internally consistent, which nothing in the sealed bytes afterwards
  reveals. Default budget 1000 ms: far wider than a working NTP client needs
  and far tighter than the drift of a host nothing is steering. The reading
  is repeated on every health cycle, because a clock that was disciplined at
  start and has since lost its daemon is exactly what a start-only check
  misses.
- **Unsynchronised and unreadable are different, and are not conflated.** An
  unreadable reading is reported as unreadable and the policy decides;
  `within()` fails an unsynchronised clock *however small* its error bound
  looks, because a stale bound from a daemon that died is not evidence of
  accuracy. `AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=0` is an explicit act, and a
  malformed value is refused rather than read as "off".
- **`deploy/pilot/chrony-cert-in.conf`** points at NIC and NPL time servers
  per CERT-In Direction 20(3)/2022, requires two sources before steering,
  and steps the clock only in the first updates after boot so a running
  collector never has its clock jumped underneath it.
- **Bounds, stated rather than implied.** The reading is an operational
  control and is **not** inside the attested bytes, so an offline verifier
  cannot confirm it — making it signed evidence would be another
  observe-protocol change and is named as future work, not implied. And
  root can call `adjtimex` to clear `STA_UNSYNC` on a clock it has just
  moved: like every other syscall source here, this is honest about a
  cooperative host and defeated by one whose kernel is owned (N1).
- Tests: 7 in `aip-observe`, including a live `ntp_adjtime` read; the gate
  was exercised end to end against the real binary — it refuses on this
  unsynchronised host, proceeds under the explicit override, and rejects a
  malformed policy value.

### Added (RBI requirements coverage — B3: the observer reads container placement itself)
- **`ObservedProcess.container`, observe protocol 10 → 11.**
  `ExecutionBinding` has carried `ContainerIdentity` since v2, but only the
  party that *authorized* an execution filled it in, so a claim that two
  workloads sat in different containers rested on one side's word. The
  observer now reads the same kernel facts itself, from `/proc/<pid>/ns/*`,
  on both the polled and the pidfd-anchored measurement paths.
- **`None` means *not observed*, never "not in a container".** An observer
  without permission, on a kernel that withholds the files, or measuring a
  process that already exited, records `None` — and the namespaces are
  all-or-nothing, so a partial read records nothing rather than a placement
  that would compare unequal against a complete one for the same container.
- **The delicate part is refusing to turn a read failure into an
  accusation.** `ObservedProcess::compare_container` gives three answers:
  agreeing placements are `Same`; differing placements are
  `DifferentContainer`, a **positive finding**; and exactly one side having
  read it is `ContainerNotComparable`, which is *not* a difference. A
  degraded observer has told us about its own blindness, not about the
  process. This mirrors `ExecutionBinding::compare_execution`, so both
  halves of a reconciliation answer the same question the same way.
- **Attested, but deliberately not in the identity digest.** The placement
  is inside `ObservedProcess::encode`, so what the observer saw — including
  that it saw nothing — is signed and non-repudiable. It is **not** in
  `identity_bytes`, because an observer that could read the namespaces and
  one that could not would otherwise produce different identity digests for
  the very same process, manufacturing a divergence out of a read failure.
  The cgroup id stays context, not identity: a cgroup-v1-only host exposes
  none, and a cgroup move is not a change of workload.
- **One encoder, not two.** `aip_types::put_container` becomes public and is
  now the single canonical encoding for this shape on both the authorized
  and the observed side. Two encoders that drifted apart would silently make
  the same container compare unequal across a reconciliation.
- **The privacy inventory caught it, which is the control working.** Adding
  a field that leaves the host failed
  `dpdp_inventory::every_field_that_leaves_the_host_is_in_the_inventory`
  until the four namespace/cgroup fields were written down with their risk
  and purpose. The DPDP fixture now carries a *populated* placement rather
  than `None`, so the inventory is checked against the shape that actually
  leaves the host, and `docs/compliance/` is regenerated.
- **Tests:** 10 in `aip-observe/tests/container_identity.rs`, including a
  live reading of this host's own namespaces, that the identity digest does
  not move when only the placement differs, that the placement does change
  the canonical bytes, and that a v10 observation without the field
  deserializes as "not observed" rather than failing.
- **Sealed in the adversarial ledger** as section `CI` (8 rows), because the
  attack this opens is against the *comparison*, not the kernel: a degraded
  or hostile observer trying to manufacture `DifferentContainer` out of its
  own blindness. The RED suite (R19) reproduces all of them, taking it from
  25 rows to 33.

### Added (RBI requirements coverage — R8: file and wire evidence in the pilot probe)
- **`aip-probe` drives `fanotify` and `AF_PACKET`.** Both taps already
  existed in `aip-observe` and were exercised by `ghost-demo`; the pilot
  probe refused them as "Phase 1.x". They are now real sensors, which the
  matrix row B7 asked for.
- **What each one proves, and what it does not.** `fanotify`
  (`CAP_SYS_ADMIN`) marks the mount holding `AIP_PROBE_FANOTIFY_PATH` for
  `FAN_CLOSE_WRITE` — one event per completed write-and-close, carrying a
  pidfd **the kernel** created from the event's own process reference, so
  the acting instance is bound by the kernel and not by a pid number that
  may since have been recycled. The probe reads nothing through the
  descriptor. `afpacket` (`CAP_NET_RAW`) records TCP/IP **headers only**:
  addresses, ports, flags, sequence numbers and the payload *length*. No
  payload byte is copied, hashed or kept (I23), and a wire segment is never
  bound to an instance, because the device layer knows no task — it proves
  bytes crossed a device, not who sent them.
- **The mount path is required.** `FAN_MARK_MOUNT` makes the choice of path
  the choice of how much of the host is watched. Defaulting it would either
  mark `/` (a firehose whose queue overflows, and an overflow is counted
  loss that degrades the epoch) or mark nothing while appearing to work, so
  the probe refuses to start without it and names the reason.
- **Gate independence is the real gain.** The three tracepoint sensors all
  share one eBPF submission gate, so they are not independent observers of
  one another. `fanotify` and `AF_PACKET` each reach the probe by a facility
  that gate does not touch, joining the netlink connector. Neither owes an
  integrity report and neither is asked for one — declaring a finding for a
  mechanism outside the gate would be inventing a check that was never run,
  and the collector's sink asks only where `shares_perf_tracepoint_gate` is
  true. The connector remains the only source licensing a
  *process-lifecycle* non-occurrence claim, which is what `PHANTOM_CLAIM`
  rests on; that has not changed.
- **Live tests, against the real kernel** (`aip-probe/tests/live_sensors.rs`,
  6): a real write is captured and bound through its pidfd; real loopback
  TCP is captured; a distinctive secret written to the watched file and a
  distinctive payload sent over the socket are each asserted **absent from
  the whole serialized batch**, which is how I23 is checked rather than
  trusted. Fail-closed startup is proven without any capability: a fanotify
  sensor with no path, and a sensor that cannot open, are startup errors.
  Where a host lacks the capability the test prints `SKIPPED` with the
  reason and asserts nothing — this workspace's convention for a kernel
  facility a host does not provide. On the development host none skipped.
- **Capability trimming is per sensor.** The systemd unit lists which
  capability each sensor needs and deliberately does **not** grant
  `CAP_SYS_ADMIN`: enabling `fanotify` means granting a near-root capability
  on the observed host, which is a decision for the entity, not a default.
  `aip-probe` also gains a `[lib]` target so the tests drive the same
  `SensorSet` the daemon does, rather than a copy.
- **Still open, and named:** the other half of matrix row B3 —
  `ObservedProcess` carrying container identity so the observer can assert
  it independently — is a signed observe-protocol version bump and is not
  part of this change.

### Added (RBI requirements coverage — E5: durability, exercised not assumed)
- **`deploy/sql/restore_drill.sh` — the restore, run end to end.** Immutability
  is not durability: `hardening.sql` makes a packet impossible to delete or
  alter, and does nothing about the disk under it failing. A table nobody can
  delete from is still lost with its disk. Every DBA runs `pg_dump`; the claim
  worth making is that a restore has been **exercised**, and this is it.
- **It proves the half a naive drill skips.** Against a real PostgreSQL it
  stands up a hardened vault, dumps it, restores into a *separate empty
  cluster*, checks the evidence is byte-identical (including the verbatim
  signed `evidence_json` that must re-verify offline), and then checks that
  **every control survived the restore**: the append-only trigger still
  refuses an `UPDATE` (owner included), the legal hold still refuses a
  `DELETE`, the retention floor still refuses a sub-180-day policy, the
  `aip_app` role still holds `SELECT`/`INSERT` only, and row-level security
  still isolates tenants. A restore that brings the data back but leaves it
  mutable has lost the control that made it evidence, and step 5 is where
  that is caught. Verified passing on Linux 6.18.44.
- **Root-safe and self-contained.** PostgreSQL refuses to run as root, so
  when invoked as root the drill runs every server and client command as an
  unprivileged user; it builds throwaway clusters under a temp dir, uses
  Unix-socket auth only, changes no system state outside that dir, and exits
  non-zero on any failed assertion.
- **`docs/BACKUP_AND_RECOVERY.md`** states what the drill cannot decide for
  the entity: RPO and RTO, off-site and off-host custody under a different
  failure and administrative domain, backup encryption and key custody,
  backup immutability (object-lock/WORM), and the restore-drill cadence —
  and notes what a `pg_dump` does not carry (the cluster roles), which the
  restore runbook recreates from provisioning, not from the backup.

### Added (RBI requirements coverage — R19: the adversarial ledger, reproducible by one command)
- **`validation/red_suite/`.** A ledger of attacks is worth the attacks
  behind it, and an attack is worth re-running. This makes "reproducible by
  script" a checked fact: `manifest.tsv` maps each of the 25
  `ADVERSARIAL_RESULTS.md` rows to the exact test that asserts its recorded
  outcome, and `run.sh` runs them and reports, per row, `REPRODUCED`,
  `BLOCKED` (with the capability it lacks named), `NOTE` (a boundary, not a
  detection) or `FAILED`. The exit code is the contract: non-zero if any
  row the ledger claims no longer reproduces.
- **The trap it avoids.** A `cargo test` filter that matches nothing runs
  zero tests and exits 0 — a vacuous pass. A harness trusting cargo's exit
  code would let a stale selector read as a reproduced detection. `run.sh`
  is stricter: a row passes only if the output shows at least one test
  passed and zero failed, so a selector matching no test is a `FAILED` row.
  That property is itself tested — renaming a selector turns the suite red.
- **Honest about the host.** The six live foreign-eBPF rows need `CAP_BPF`,
  `CAP_PERFMON` and `tracefs`; without them they are `BLOCKED` with the
  reason, already sealed in the ledger from a host that had them. The
  off-host half of the same integrity property (`OI-09`..`OI-12` — the
  collector refusing to sign `Active` over a gate finding or over silence)
  runs everywhere and is reproduced. `OI-08` is `deferred` on a component
  that does not exist yet, and the ledger names it. A `BLOCKED` row is never
  counted as a pass and never as a failure.
- **CI runs it,** so a regression in any claimed detection turns the build
  red rather than being discovered in an audit.

### Added (RBI requirements coverage — R9b: ingress limits, split by what each layer can see)
- **In-process, in `aip_service::ingress`, because the proxy cannot see it.**
  A request body is streamed; a handler that deserializes a giant JSON body
  has already spent the memory before any proxy rule on the *parsed* content
  could apply. So the body cap (`413` above `AIP_MAX_BODY_BYTES`, default
  1 MiB), the per-request timeout (`408` above `AIP_REQUEST_TIMEOUT_SECS`,
  default 30 s) and a global in-flight cap (`AIP_MAX_IN_FLIGHT`, default 256)
  live at the one place that owns the deserialization and the work. A
  malformed limit **fails the start** rather than silently becoming
  unlimited — a control turned off by a typo is worse than none, because it
  reads as present.
- **At the proxy, in `deploy/docker/reverse-proxy.conf`, because it is
  per-connection and per-client.** TLS termination, per-client rate and
  connection limits, and slow-loris header/body timeouts all need the
  client's address and raw connection — which a reverse proxy has and an
  application behind it does not, since every request arrives from the
  proxy's address. The file is a commented reference, nginx syntax with the
  intent of each rule spelled out so it translates to HAProxy or Envoy, and
  compose points at it.
- **Tests.** `tests/ingress_limits.rs` over the real hardened router: a body
  over the cap is `413` before the handler; a body under it reaches the
  handler (which then rejects the shape with `422`, proving admission); an
  unauthenticated giant body is refused with `401` *without being read*,
  which is a stronger guarantee than the cap firing; the hardened router
  still serves. Plus four unit tests on the limit parsing, including that a
  malformed value is refused. `tower` becomes a real dependency (it was
  dev-only) with `limit`; `tower-http` is added with `timeout`. No new TLS
  stack — TLS is the proxy's.

### Added (RBI requirements coverage — R9a: a link a capture cannot read)
- **`aip_transport::confidential` — the authenticated channel inside a Noise
  session.** The Phase 1 channel authenticated which host may submit and
  made every frame unforgeable; it sent the bytes in the clear. A batch
  carries no payload content, but its metadata — probe identity, pids,
  executable paths, socket endpoints, timestamps — is a map of what ran
  where, and under DPDP that map is not for a network observer. The
  authenticated protocol now runs unchanged inside
  `Noise_NK_25519_ChaChaPoly_SHA256`: challenge, probe id, transport key
  and every frame are encrypted.
- **Why NK, and why a third key.** The probe pins the collector's static
  public key, so an active attacker without the collector's static private
  key cannot complete the handshake; forward secrecy comes from the
  ephemeral step. The probe is anonymous at this layer on purpose: its
  identity is the Ed25519 challenge inside the tunnel, where it is also
  confidential. The collector's Noise key is separate from its Ed25519
  evidence key and from any probe's transport-auth key — a signing key is
  not a Diffie–Hellman key, and the Ed25519→X25519 map is exactly the kind
  of cleverness custody should not rest on. A loaded key file is **proven
  to be a pair** by a local handshake before use, so swapped halves are
  refused at load rather than found as every probe failing to connect.
- **The acceptance test is a capture.** A tap on the probe's socket records
  the whole session; the recording contains neither the probe id, nor its
  public key in any encoding, nor a wire field name, nor the batch. A
  plaintext control runs the same search and finds all of them — and
  caught a first draft of the test that searched for strings the wire never
  carries byte-for-byte, which is what a control is for. Also: a wrong
  pinned key fails before any authentication; a tampered message fails its
  tag and **poisons the stream** so nothing after it is delivered; a 4 MiB
  payload crosses ~65 messages intact; a clean close is EOF; two sessions
  never share ciphertext. 12 unit + 7 integration tests.
- **Both daemons use it unconditionally.** `aip-probe` requires
  `AIP_PROBE_COLLECTOR_NOISE_PUBKEY` and refuses to start without it;
  `aip-collector` requires `AIP_COLLECTOR_NOISE_KEY_PATH`, generates the key
  `0600` on first start and prints the public half at every start. There
  is no plaintext mode in either daemon; the plaintext adapters remain in
  the library for tests and are named as such.
- **Dependencies.** `snow` pinned exactly, default features off — its `std`
  feature drags in `ring` through a legacy forward — on the curve25519,
  ChaCha20-Poly1305 and SHA-256 crates the workspace already carries. No
  TLS stack, no certificate authority to run.
- Ingress limits and the reference proxy configuration for the *service*
  (matrix E6) follow as R9b.

### Added (RBI requirements coverage — R16: the key that never leaves the module)
- **A PKCS#11 `Custodian` (`aip-standalone/aip-hsm`).** With the wrapped-file
  custodian the signing key is decrypted into process memory for the life
  of the process, and whoever can read that memory has it. Here the key is
  generated *inside* the module with `CKA_SENSITIVE=true` and
  `CKA_EXTRACTABLE=false`, and the module's own firmware refuses to return
  it. This process sends 32 bytes and receives a signature. There is no
  import path: a key that was ever outside the module cannot be shown
  never to have been copied, and that is the property the backend exists
  for.
- **What is refused at open, once, so a bad deployment fails at start-up
  and not at the first signature an audit needs.** A key whose policy would
  let it leave the module — **read back from the module**, not assumed
  from how the key was said to be created; two keys under one label,
  rather than guessing; a public object that does not verify a probe
  signature by the private object, so a mislabelled pair is caught at
  commissioning; a PIN on the command line, or in a file another user can
  read; a module that will not report the policy at all.
- **The envelope is the software signer's, byte for byte.** Built with the
  one `signature_signed_bytes` the signer and verifier already share;
  `aip_crypto::verify_ed25519` accepts it and `ReconcilerSigner` signs a
  verdict through the module with no change to any verifier. The nonce is
  drawn from the module's RNG (`C_GenerateRandom`), not the host's.
- **Two PKCS#11 facts handled and stated rather than met in production.**
  Login state is per token per application: a second custodian on the same
  token gets `CKR_USER_ALREADY_LOGGED_IN`, which is treated as success, and
  the consequence — its PIN is not re-checked — is documented, because it
  is the standard's model and not something the application can tighten.
  SoftHSM2's file-backed object store fails intermittently with
  `CKR_GENERAL_ERROR` when a key is generated while anything else is in
  flight on the token; generation is serialised within a process, and the
  cross-process case is stated as a commissioning rule (provision with the
  signer stopped) rather than papered over. The test suite is structured
  the same way — every key provisioned serially at setup, then opened and
  signed with in parallel — because that is the deployment, not a harness
  convenience.
- **Tested against a real token.** `tests/softhsm.rs` runs against
  SoftHSM2 through the same interface a hardware module presents,
  including a second PIN-holding session asking for the private key and
  not getting it. The tests **fail rather than skip** when the module is
  absent, with the install command, because a custody test that passes on
  a machine without the module has never run; `ci.yml` installs it.
  `Backend::Pkcs11` is added to `aip-crypto` now that an implementation
  exists, as the custody module always said it would be. 27 tests.
- **`aip-hsm` CLI:** `provision`, `public-key`, `self-test`. The PIN comes
  from an owner-only file or the environment, never an argument.
- **Not covered by code, stated in `deploy/pilot/HSM_CUSTODY.md`:** which
  module and its certification, who holds the PIN, dual control and key
  ceremony, and key backup — a non-extractable key cannot be backed up by
  copying it, and that choice has regulatory consequences (E5, open).

### Added (RBI requirements coverage — R15: metrics, SIEM, runbook)
- **Verified verdicts as CEF over RFC 5424 syslog (`aip-standalone/aip-siem`).**
  A verdict nobody reads changes nothing, and an institution's analysts
  work in a SIEM. `CefEvent::from_verdict` verifies under anchors the
  caller supplies and there is no constructor that skips it: the SIEM is
  exactly where a forgery would acquire the institution's own provenance,
  arriving as something the bank's reconciler said.
- **The severity this crate had to invent, and how it is bounded.** A
  `Reconciliation` carries no severity, confidence or score by design, and
  a test in `aip-reconcile` enforces that; CEF's header makes one
  mandatory. It is therefore a documented routing hint owned by the
  exporter: a total table over `ReconciliationResult` alone, never over
  `strength`, with no wildcard arm so a new result class is a compile
  error rather than a silent "informational". `CANNOT_PROVE` maps to the
  middle of the range, not the bottom — an unproven claim is not a clean
  one — and its `msg` says so in words.
- **Refusal rather than ambiguous logging.** Escaping (`escape.rs`) is
  correct and separately tested for both halves of a CEF line, which
  differ. It is not sufficient on its own: a signed-but-hostile
  `reconciler_id` can still spell a literal `CEF:0|…` inside a
  conformantly-escaped record, which a stream consumer that re-scans for
  `CEF:` reads as a second event. An exporter cannot verify what its
  receiver does, so a value containing a pipe, a backslash or a control
  character is refused, and the refusal names the verdict digest so the
  document is not lost. Device identity is validated the same way, once,
  at construction.
- **No new dependencies.** CEF and RFC 5424 are text formats; the one
  thing that usually drags in a crate — Unix milliseconds to RFC 3339 — is
  `time.rs`, with the derivation of Hinnant's `civil_from_days` written
  out and tested against known instants, leap days, the 1900/2000 century
  rule and eleven years of consecutive days.
- **`GET /metrics` on `aip-service`,** Prometheus text exposition format.
  **Authenticated** — request volume is operationally sensitive and an
  unauthenticated counter of filed evidence tells an observer when an
  institution is busy. **Unlabelled** — a series labelled by tenant is a
  cross-tenant disclosure channel on a shared scrape, and agent or
  document identifiers are unbounded cardinality as well as being
  evidence. Ten counters, including `aip_verdicts_rejected_total` and
  `aip_siem_exports_refused_total`: both count events that are by
  definition invisible in the store, because nothing was stored.
  **Decision:** the exposition format rather than the OpenTelemetry SDK —
  every stack the requirement names scrapes it, the OTel Collector
  included, and the SDK would add a large tree to a ten-counter surface.
- **`deploy/pilot/RUNBOOK.md`,** written for someone on call at 03:00:
  which `cs1` values page, the CERT-In six-hour assembly, the anchor audit
  before a submission, and the instruction to alert on
  `aip_evidence_stored_total` *falling to zero* — a pipeline that stopped
  looks exactly like a quiet day. It opens with the rule that
  `CANNOT_PROVE`, `NotEvaluated` and an empty gap list are not clean
  results.
- Tests: 35 in `aip-siem` (20 integration over real signed verdicts, 15
  unit over escaping, framing and the date arithmetic) and 4 over the
  service's real router.

### Added (RBI requirements coverage — R11: anchoring against the operator)
- **An external witness for NEXORA log heads (`aip-standalone/aip-anchor`).**
  A Merkle commitment log establishes that a record is under a root and
  that one root extends another. It does not establish that the root shown
  today is the root that existed yesterday: whoever holds the NEXORA
  signing key can build a shorter log, sign a head over it, and hand out
  proofs that all check out. `aip_nexora::MemoryAnchor` already said as
  much — "the shape of an anchor, not its independence".
- **The mechanism is one negative property.** A witness on a second system
  holds its own key, verifies each head under NEXORA anchors it was
  provisioned with, requires a proven consistency step for every extension,
  and countersigns into a `WitnessReceipt` chained to its own previous
  receipt. An operator who rewrites the log can still sign the new head;
  they cannot produce a receipt for it. Receipts already distributed are
  therefore evidence the operator cannot revise.
- **`aip_anchor::audit` is three-valued.** `Consistent`, `Diverged`
  (truncation, same-size in-place rewrite, a divergent longer history, a
  log that cannot prove extension, or the wrong log) or `NotEvaluated`.
  A log with no receipts is `NotEvaluated::NoReceipts` and never a pass:
  an unanchored log and an anchored one must not read alike, which is the
  entire point. A log that declines to produce a consistency proof is
  treated as divergent, so refusing to prove is not an escape.
- **What the witness refuses to sign.** A head it cannot verify; a rollback;
  a fork (two roots at one size); an extension with no consistency proof; a
  head dated more than `DEFAULT_FUTURE_TOLERANCE_MS` (5 s) past its own
  clock, because a witness cannot corroborate a time it has not reached.
  It refuses at construction to hold the log's own key, or a public key
  its private key does not derive. A refusal leaves the witness's state
  untouched.
- **Restart safety.** Resumable state is replayed from the receipt file
  rather than stored beside it, so a restart cannot be used to slip a
  rollback past a witness that has forgotten. Appends are `fsync`ed before
  the receipt is reported. A corrupt line is reported with its line number,
  never skipped — skipping would silently discard a countersignature.
- **`aip-crypto` gains `public_key_from_private`.** So a component holding a
  signing key is never told its own public key as a second argument: two
  arguments can disagree, and the failure is silent in the worst way —
  signing with one key while publishing another. Four unit tests.
- Tests: `aip-anchor/tests/witness.rs` (19) and `tests/store.rs` (5). Every
  rewrite test actually rewrites — rebuilding a log and signing it with the
  real NEXORA key, so the attack is the one an operator can mount.
- **Not covered by code, and stated as such:** that the witness is
  independent. A witness on the same host, under the same administrator,
  with its key in a file that administrator can read, is a second signature
  by one party, and no flag can detect it.
  `deploy/pilot/ANCHOR_WITNESS.md` states the four deployment conditions,
  of which copying receipts outside the entity is the one that separates an
  internal control from evidence a third party can rely on.

### Added (RBI requirements coverage — R14: the incident bundle)
- **A bundle that states its own coverage gaps (`aip-standalone/aip-incident`).**
  CERT-In directs that a reportable incident be reported within six hours.
  Six hours is not enough time to assemble evidence by hand, and hand
  assembly is where a window quietly acquires a hole nobody can later
  distinguish from an absence of activity. `aip-incident export --agent
  --from --to` assembles one signed bundle from documents that are already
  signed — attested batches, reconciliation verdicts, access ledgers, sensor
  health records, expectations — and derives `CoverageSummary::gaps` by
  subtracting the intervals the enclosed batches actually claim from the
  window that was asked for. Intervals are closed at both ends, the
  convention `CoverageWindow::contains` already documents. The summary is
  computed, never supplied by the caller.
- **Two independent defences on the coverage claim.** The summary sits
  inside the manifest signature, so it cannot be edited without breaking
  it; and `verify` recomputes the summary from the enclosed batches and
  compares. The second is what survives an exporter key held by whoever
  wants the bundle to look complete.
- **The exporter's signature is scoped in the artefact itself.** It attests
  that this set of documents was assembled by this exporter at this time and
  nothing else; every enclosed document keeps its own signature and must be
  verified under its own anchors. `verify` prints that sentence so a reader
  cannot mistake bundle assembly for document verification.
- **The `aip-incident` command reads only files.** No collector call, no
  service call: an incident is the wrong moment to discover a network path
  is down, and a bundle assembled from files is one an operator can
  reproduce. The bundle identifier is derived — SHA-256 over the agent, the
  window, the export instant and every document digest, truncated to 128
  bits — rather than random, so re-running an export demonstrably yields the
  same artefact.
- Tests: `aip-incident/tests/bundle.rs` (13) over the library and
  `tests/cli.rs` (9) against the compiled binary. A hole between two batches
  is stated with its bounds; a window with no batches reads as wholly
  uncovered; a bundle re-signed with its gaps erased fails recomputation; a
  document removed, altered or undeclared is detected; an untrusted or
  unanchored exporter exits non-zero; a malformed invocation writes no
  bundle at all.
- **Not covered:** the reporting path itself — who files, to whom, on which
  form, and the six-hour clock — is the regulated entity's process. This
  crate produces the evidence that process attaches.

### Added (RBI requirements coverage — R17, R18, R20: what a reviewer reads)
- **A regulatory control map that cannot claim what it cannot show (R18).**
  `aip_conformance::regulatory`: 25 rows over seven instruments (IT
  Governance, IT Outsourcing, FREE-AI, draft MRM, Digital Lending, CERT-In,
  DPDP), emitted to `docs/compliance/CONTROL_MAP.{csv,json}`. Three rules are
  enforced by test: a row claiming a control must name a file that exists in
  the repository; a gap must be a sentence saying what would close it, never
  an omission, because a map whose gaps are missing reads as complete; and no
  row may claim compliance, which is a judgement for the entity and its
  auditor, not for this crate. Three gaps are stated (backup/DR, ingress
  security, the six-hour incident bundle) and three controls are assigned to
  the regulated entity rather than claimed.
- **A DPDP field inventory that cannot fall behind the code (R20).**
  `aip_conformance::dpdp`: every one of the 35 fields that leaves the
  observed host, with what it holds, a personal-data risk class and why it is
  collected. The field set is **derived from a fully-populated
  `ObservationBatch`** rather than from the inventory's own list, so adding a
  field fails the build until someone writes down what it is — the only
  mechanism that survives the six months between a DPO's signature and the
  next change. A separate test asserts that no field is classed as carrying
  personal data directly, which is the claim the pilot rests on; if that ever
  changes it becomes a decision rather than a passing test. DPO sign-off
  template in `deploy/pilot/DPO_SIGNOFF_TEMPLATE.md`, completed by the entity
  because a supplier cannot make a lawful-basis determination on its behalf.
- **The AI-inventory attachment (R17).** `aip_ledger::InventoryEntry`
  derives, from a **verified** access ledger, what an inventory entry is
  usually weakest on: which named institutional systems the agent reached in
  a window, on evidence rather than recollection. Ordered most-critical
  first; cites the ledger by digest and the registry revision, since two
  entries from different revisions are not comparable. `unproven` and
  `no_verdict` rows are reported separately from `verified`, so a window
  nobody observed cannot read as a clean one. An unsigned or altered ledger
  yields no entry at all.
- New binary `emit-compliance` writes all four artefacts deterministically,
  so a diff in a committed file is a change in the system rather than a
  change in the run.

### Added (RBI requirements coverage — R10: verdicts and ledgers the RE serves)
- **An inspector now has an endpoint to ask.** `POST /v1/verdicts`,
  `GET /v1/verdicts/{id}`, `POST /v1/ledgers` and
  `GET /v1/agents/{id}/ledger`, all tenant-scoped from the caller's API key.
- **Verify before storing.** A document is checked under anchors the caller
  supplies, and refused if it does not verify. Storing an unverified one
  would make the service a laundry: a forged verdict would acquire the
  bank's endpoint as its provenance. A submission with no anchors is
  likewise refused, because it cannot be checked at all.
- **The service adds no signature and re-serialises nothing.** Bytes are
  stored and returned verbatim, so an auditor pipes a response into the
  producing crate's own verifier with their own keys and gets the same
  answer — which is the only reason to believe the service. A response
  re-serialised from parsed structures would verify only if this crate's
  serialiser happened to agree with the producer's.
- **Ids are document digests**, so re-filing the same verdict is one row
  rather than a duplicate, and a cross-tenant id collision is refused.
- A cross-tenant read returns 404, byte-identical to not-found: a
  distinguishable 403 would confirm that an id exists under another tenant.
- Stored in PostgreSQL in `signed_artifacts`, created with the evidence
  schema and therefore covered by the same `hardening.sql` grants and row
  policy — an artifact tier with weaker storage controls than the evidence
  it rests on is the place that answer goes to be edited. It shares the
  evidence connection pool rather than opening a second one.
- **Not done, stated:** a `Reconciliation` names no agent, so verdicts are
  not indexed per agent; attribution is the reconciler's finding carried in
  evidence references. The per-agent route is the access ledger's, which does
  name one.

### Added (RBI requirements coverage — R12, R13: supply chain and storage)
- **Release artefacts are signed (R12).** `release.yml` signs each archive
  with keyless Sigstore and then **verifies the signature it just produced**,
  under the same identity constraints a downloader uses. An unverified
  signing step is a step that can silently stop signing; this one fails the
  release instead. No long-lived signing key exists, so there is none to leak
  or rotate. `VERIFYING.md` ships with the release and says plainly that
  omitting the identity flags accepts any Sigstore signature ever issued, to
  anyone, which is not a check.
- **The evidence store's immutability is now the database's property, not the
  service's (R13).** `deploy/sql/hardening.sql`, applied once by the owning
  role: the service connects as a role holding SELECT and INSERT only.
  A fully compromised service still cannot delete or alter a stored packet,
  because the connection it holds was never granted the privilege.
- **Legal hold binds the operator too.** A `BEFORE DELETE` trigger refuses to
  remove a held packet even for the role that runs the retention job — a hold
  the operator can step around is not a hold. Holds are per packet or
  tenant-wide, and a tenant-wide hold covers packets stored after it was
  placed. Releasing it restores retention.
- **Retention floor is a constraint.** 180 days (CERT-In) as a CHECK, so a
  misconfigured policy is refused at write time rather than discovered at an
  inspection.
- **Row-level security closes the single-forgotten-WHERE disclosure.** The
  policy reads `aip.tenant_id`, which the store now sets inside each
  transaction (`is_local`, so a pooled connection cannot carry one request's
  tenant into the next). A connection that declared no tenant sees nothing:
  failing closed is the whole value of the control. `count()` consequently
  reports zero under RLS, because a cross-tenant total is exactly what tenant
  isolation forbids.
- The store tolerates a database it may not provision: DDL refused for lack
  of privilege is followed by confirming the tables exist, so a restricted
  role starts cleanly while a genuinely unprovisioned database still fails
  loudly at startup rather than on the first request.
- **These are proven, not asserted.** `aip-service/tests/storage_controls.rs`
  runs against a real PostgreSQL and checks what the database refuses: the
  service role's DELETE, UPDATE, TRUNCATE, DROP and `DISABLE ROW LEVEL
  SECURITY`; an unfiltered SELECT crossing tenants; an undeclared
  connection; a held packet against the owner; a 90-day retention policy.
  They are `#[ignore]` rather than self-skipping, so an unconfigured run
  reports them as *ignored* instead of *ok* — the failure mode the audit
  recorded in the existing Postgres suite.
- **Not done, stated:** backup, disaster recovery and a tested restore drill.
  Immutability is not durability; a table nobody can delete from is still lost
  with its disk.

### Changed — wire (RBI requirements coverage — R5: container identity)
- **`EXECUTION_BINDING_VERSION` is 2.** `ExecutionBinding` gains
  `container: Option<ContainerIdentity>`. The version is inside both the full
  and the identity encodings, so a v1 binding and a v2 binding never produce
  equal bytes even when every other field agrees: **existing stored bindings
  do not match newly collected ones, and a deployment upgrades both sides
  together.** No packet format changed; `PACKET_VERSION` is untouched.
- **What v1 could not see.** Two containers on one host, running the same
  image, whose processes the kernel gave the same PID in different PID
  namespaces and which started in the same clock tick, agree on every v1
  field. A payments agent and a reporting agent would reconcile against each
  other's evidence. `ContainerIdentity` carries the pid, mount and network
  namespace inodes — the only stable identifiers a namespace has — and those
  three are the identity.
- **The cgroup v2 id is recorded context, not identity.** It is in the full
  canonical encoding and deliberately absent from `identity_bytes`: a
  cgroup-v1-only host exposes none, and making it load-bearing would withdraw
  container identity from those hosts entirely; and a process migrated
  between cgroups is still the same execution.
- **Absence is not difference.** `ExecutionBinding::compare_execution`
  returns a reason rather than a boolean, and distinguishes
  `DifferentContainer` (the kernel separates these workloads — a positive
  finding v1 could not make) from `ContainerNotComparable` (exactly one side
  recorded an identity). A consumer that collapsed those two would let an
  un-instrumented collector manufacture divergences out of its own
  blindness. The collector records all three namespaces or none, never a
  partial identity, and never zeros — zeros are a real container.
- `aip-core` reads `/proc/<pid>/ns/{pid,mnt,net}` link text and the cgroup id
  under the cgroup2 mount. A read failure costs container identity, never the
  whole binding: a binding without it is weaker, not wrong.
- **Not done, stated:** `aip_observe::ObservedProcess` does not carry the
  field, so the observer cannot yet assert container identity independently
  and the reconciler cannot compare it. That is an observe-protocol version
  bump and is folded into R8, where the probe is being changed anyway.

### Added (RBI requirements coverage — R6, R7: what the offline verifier can establish)
- **A verifier can now require that something other than the agent decided
  (R6).** `VerificationContext::independent_authority_required`
  (`aip-verify --require-independent-authority`) fails `AUTHORITY_CHAIN`
  when the acting agent is its own authority root. Both spellings are
  caught: the declared principal being the agent, and the root token's
  issuer being the agent, so relabelling one does not evade the other. The
  default is unchanged, because some deployments are legitimately their own
  principal — but a self-issued pass is no longer silent: the rule's detail
  says the root is the agent itself and that independence was not
  established. Self-issuance is not recorded as tamper evidence; nothing was
  altered.
- **Revocation is a signed, time-bounded document (R7).**
  `aip_protocol::RevocationList` (AIP_SPEC §4.4): domain
  `AIP/RevocationList/v1`, length-prefixed canonical encoding, every field
  inside the signature, entries sorted and unique so one set of revocations
  has one encoding, a per-issuer `sequence` so a replayed older list is
  visible as older, and an `issued_at`/`valid_until` window the verifier
  places against its own instant. `verify_revocation_list` is the only way
  to obtain a `VerifiedRevocationList`, so the engine cannot be handed a
  list nobody checked or one that has expired.
- **The vacuous revocation pass is gone.** `REVOCATION` previously reported
  "no token in the authority chain is revoked" whenever the verifier's set
  was empty — a claim about the world made by a verifier that had not looked
  at the world. It now separates three states: a hit in any source FAILS
  (whatever the source's freshness: a revocation does not lapse); a usable
  source with no hit PASSES **citing that source**, including the admission
  that a bare identifier list carries no issuer, issue time or expiry; and
  no usable source is NOT EVALUATED, naming what was missing. An expired or
  unanchored list lands in the third state, which is the R7 acceptance
  criterion. `valid` is unaffected, since it already ignored unevaluated
  rules.
- `aip-verify` gains `--revocations`, `--trust-revocation-issuer
  <id>:<version>=<hex>` and `--require-independent-authority`. A list
  supplied without `--at`/`--now` is refused at the command line rather than
  applied against an assumed present. A list that fails to verify is carried
  into the report as the reason the rule could not be evaluated, not dropped
  with a warning the operator may scroll past.
- First tests for the `aip-verify` binary itself (7): the compiled command,
  real files, exit codes and printed output — because the library being
  correct is not the same as the command being correct.

### Added (RBI requirements coverage — R4: the tool boundary)
- **A mandate can carry transaction parameters without carrying them.**
  `aip-authorize` gains the `ghost.tool.invoke.v1` action class
  (`tool_invoke_action`, `tool_invoke_parameters(tool_id, params_commitment)`,
  `MAX_TOOL_ID_LEN`, `ToolInvokeError`). The decision point seals a tool
  identifier and the agent SDK's domain-separated commitment to the canonical
  tool arguments (`aip_airi::parameter_commitment`) into the expectation's
  parameter digest; the arguments themselves (an amount, a beneficiary) enter
  no signed document. No existing action class or digest changes.
- **A third signer at the tool boundary.** `aip-airi::ToolReceipt`, signed by
  the institution's tool gateway (`GatewaySigner`, `GatewayTrustAnchors`,
  `verify_tool_receipt`): the gateway's own recomputation of the commitment
  over the request it actually received, the decision it cited, the agent it
  named, and what the gateway did with it (`GatewayDisposition`). Domain
  `GHOST/AIRI/ToolReceipt/v1`, length-prefixed canonical encoding, every
  field inside the signature. A gateway anchored under the agent's own key is
  refused (`GatewayKeyIsAgentKey`), as a decision point (I1) and an observer
  (I10) are.
- **Authorized versus received versus claimed.** `aip-airi::compare_tool_boundary`
  recomputes the sealed digest from the verified receipt through the same
  `tool_invoke_parameters` the decision point used and names the outcome:
  `ReceiptDoesNotMatchAuthorization` (what reached the system is not what was
  authorized, whatever the agent said), `ClaimDoesNotMatchAuthorization` (the
  request was in order; the agent misreported it), `Agrees` with the claim's
  standing, or `NotEvaluated` with a reason — an absent receipt is a coverage
  statement, never a finding. Built on AIRI's existing `ToolInvocation`; there
  is no second tool-call layer. Like `AiriAnnotation` and `aip-approval`, the
  outcome sits beside a reconciliation and is not a verdict: engine
  integration remains gated (ADR-016 §gate).
- **The kernel side says nothing about this class, on purpose.** The
  reconciler derives no action evidence for `ghost.tool.invoke.v1` and
  returns `ACTION_EVIDENCE_UNAVAILABLE` even with a kernel-pushed socket
  transition on the authorized instance claimed under the decision
  (`aip-airi/tests/tool_boundary.rs`, 12 tests, real engine). A socket is not
  a tool call and is not matched to one.
- Not done, stated: committing receipts to NEXORA (a twelfth leaf kind is a
  wire change and is batched with the next one); policy over plaintext
  amounts at the decision point (the decision point receives a commitment; a
  policy engine that needs the arguments is a separate, DPDP-scoped design).

### Merged (branch consolidation before further roadmap work)
- `claude/vanian-audit-maturity-addendum-n5ysvd`: `aip-enforce` (seccomp
  user-notify execve gate under a signed `CapabilityEpoch`), `aip-interlock`
  (dead-man heartbeat, actuator watchdog), `aip-approval` (shown-versus-
  authorized over two signed artefacts). Its ADR-008/009 are renumbered
  ADR-015/016 to avoid colliding with the skill-25 series.
- `claude/skill-25-implementation-xbz0t3`: `aip-conformance` (invariant ×
  domain matrix, threat × layer execution log, substitution and versioning
  suites), `aip-industrial`, `aip-space`, `aip-enterprise`, ADR-008..014,
  mutation-assurance results and the regression tests they produced in
  `aip-nexora` and `aip-reconcile`.
- Both branches pinned the proof tree at nine leaf kinds and observe protocol
  9; the tree is at eleven kinds and protocol 10. Six pins moved to 11 with
  corrected rationale; conformance blocker B-10 now accepts the equivalent
  `cargo test --workspace` this CI runs. Full workspace green after both
  merges.

### Added (RBI requirements coverage — R2, R3)
- **Resource-scoped authority at the decision point (R2).** A resource grant
  is a `res:<id>` entry in the existing signed capability scope
  (`aip_registry::resource_scope_action`), so it is covered by the issuer's
  signature and attenuates down the delegation chain with **no change to any
  token's wire format**; explicit deny overrides. `DecisionPoint::
  with_resource_policy(ResourcePolicy)` adopts the institution's registry
  after verifying it; adjudication reads the network destination from the
  same parameter bytes the expectation signs, resolves it, and denies
  `DestinationMalformed`, `DestinationUnregistered` (an unnamed system is not
  a permitted one) or `ResourceNotGranted`. The resolved name is kept out of
  the expectation's parameter digest, which must stay exactly what the
  reconciler recomputes. Without a policy no resource check runs, and the
  decision point says so. Resource ids are capped at 60 bytes so a grant
  fits a `Custom` action. Tests: `aip-authorize/tests/resources.rs`.
- **Per-agent access ledger (R3).** `aip-ledger::AccessLedger`: for one
  agent over one window, every endpoint reached (socket effects and
  kernel-pushed connect initiations attributed to the agent), resolved
  against a verified registry revision it cites, with the reconciler's
  signed verdicts cited to rows through the observation, kernel event or
  claimed decision they reference. Results and strengths verbatim; a row's
  `Standing` is a fixed summary never above its citations; verdicts that
  match no row are counted, not dropped. Signed by a fifth authority
  (`LedgerSigner`), canonical order enforced at verification, offline
  verification under `LedgerTrustAnchors`. `aip-nexora` gains
  `LeafKind::AccessLedger` (0x0b), `commit_access_ledger` and
  `verify_committed_ledger`. Tests over a real probe and collector
  (`aip-ledger/tests/ledger.rs`) and over the real-engine
  `VERIFIED_EXECUTION` fixture committed to a log
  (`aip-nexora/tests/access_ledger.rs`). Three profile pins move from ten to
  eleven leaf kinds.
- IPv4 layout: the registry and the decision point's destination parser use
  the observer's layout (first four bytes of the 16-byte field), so all
  three resolve identical bytes.

### Added (RBI requirements coverage — R1)
- **`aip-registry`**: the institution's signed, versioned registry of named
  network resources (address ranges, ports, protocol, criticality). Entries
  are sorted and pairwise non-overlapping at signing, so resolving an
  observed endpoint is a total, deterministic function: exactly one
  resource, or `Unregistered` — an answer, never an inference. Verified
  offline against the institution's anchor; every downstream artefact cites
  `(registry_id, revision)` so a later edit cannot re-label past evidence.
  Depends on `aip-types` and `aip-crypto` only. 21 tests: signing, every
  post-signing edit detected, impostor key, overlap and malformation
  refusals, resolution including v4/v6 non-confusion.
- `docs/pilot/RBI_REQUIREMENTS_COVERAGE.md`: every requirement the RBI
  ecosystem places on an agent deployment, each with one disposition —
  EXISTS (code and test named), BUILD (roadmap item R1–R20 with acceptance
  test), INTEGRATE (who supplies it), or OUT OF SCOPE (named owner).

### Added (research)
- `docs/pilot/RBI_AGENT_RISK_MAP.md`: where AI agents will create failures in
  the RBI-regulated ecosystem (ten classes, from mandate violations and
  phantom work to blinded monitoring and agent-payment liability), the
  regulatory clock from CERT-In 2022 through the June 2026 MRM draft and
  fraud-liability amendment to NPCI's agent protocol, and for each class what
  this repository proves, what it does not, and which instrument it serves.
  Secondary sources flagged for primary verification before use with RBI.

### Fixed (documentation and delivery that did not match the code)
- `deploy/docker/Dockerfile` built against `aip-standalone/Cargo.toml`, which
  no longer exists; it now builds from the single root workspace and ships
  `nexora-verify` alongside `aip-service`, `aip-migrate` and `aip-verify`.
  `docker-compose.yml` fails fast when `AIP_KEY_PASSPHRASE` is unset instead
  of letting the service `exit(1)` in a restart loop.
- `release.yml` ships `nexora-verify` (the only offline verifier for Ghost
  verdicts and NEXORA proofs); release artifacts are described as
  checksummed, not signed.
- `AIP_SPEC.md` §5 documents rules R15–R18 and the three-state outcome
  (`valid` covers evaluated rules only); design-partner documents say 18
  rules, not 14. `PRODUCTION_READINESS.md`: container image, compose and
  release rows corrected from ✅ to 🟡 with the reason; the signed
  audit-export bundle row corrected from ⬜ to ✅ (it shipped).
- `aip-edge/tests/nexora.rs` pinned the NEXORA leaf list at nine; SD-10
  added the tenth (`SignedReconciliation`). The pin now says so.

### Added (expected-side completeness — `UNATTRIBUTED_EFFECT` reachable)
- **Decision-point coverage statements, produced from a ledger.** The
  decision point (`aip-authorize`) now records every `ExpectedExecution` it
  signs in an in-process `DecisionLedger` and issues
  `DecisionPointCoverageStatement`s from it
  (`DecisionPoint::coverage_statement(agent_id, window, issued_at_ms)`). The
  decision list is **computed, never supplied**; the producer refuses a
  window before its declared epoch (`with_coverage_ledger`) or not yet closed
  at issue time; and once a statement is issued, a decision for that agent
  at or before the attested `to_ms` is denied
  (`DenialReason::AttestedWindowClosed`, new variant) so the statement cannot
  be falsified afterwards. Check, signature and append share one guard.
- **`UNATTRIBUTED_EFFECT` fires live.** `ghost-demo` scenario B now attaches
  the decision point's statement over the observed window and reconciles to
  `UnattributedEffect` / `Attested` / `NoExpectationAttested` from a real
  process, the real observer and the real reconciler; new scenario **B-U**
  (`ExecutedNotExpectedUnattested`) pins that the same observation without a
  statement stays `CannotProve` / `ExpectedSideCompletenessUnknown`.
- **Type moves, no wire change.** `CoverageWindow` now lives in `aip-types`
  (re-exported unchanged from `aip-observe`; gains `is_well_formed` and
  `intersects`); `DecisionPointCoverageStatement`, `CoverageStatementError`
  and the coverage domain/version constants moved from `aip-reconcile` to
  `aip-authorize` and are re-exported from `aip-reconcile` at their old
  paths. Domain string, version, preimage and verification rule are
  unchanged.
- Tests: producer attacks `aip-authorize/tests/coverage.rs` (P-01..P-14);
  live attacks `ghost-demo/tests/live_coverage.rs` (CS-01..CS-06); ledger
  unit tests. Ledger `docs/security/ADVERSARIAL_RESULTS.md` §CS;
  `docs/architecture/DECISION_POINT.md` §16a states the restart contract.
  Chosen over SD-11 (a `NexoraProof` version bump that buys packaging, not a
  new security property).

### Added (committed verdicts — SD-10)
- **Signed verdicts committed to NEXORA, verifiable offline.** New
  `LeafKind::SignedReconciliation` (code `0x0a`, appended; earlier codes
  frozen) commits `SignedReconciliation::canonical_bytes()` — the verdict
  *plus* the reconciler's signature, under its own domain
  (`SYNTRIASS/GHOST/SIGNED_RECONCILIATION/v1`, distinct from the signing
  preimage's) so stored bytes can never pose as something the reconciler
  signed. `aip_nexora::commit_signed_verdict` appends one;
  `aip_nexora::verify_committed_verdict` lets a party holding only the proof,
  the signed verdict and its own anchors establish, in order: the reconciler's
  attestation (reconciler anchors), the inclusion under an anchored head
  (NEXORA anchors), that the leaf is a signed-verdict leaf (a bare verdict
  relabelled is refused), and that the committed bytes are *this* verdict's,
  recomputed from the struct — never trusted from the proof. Result and
  strength are carried verbatim, never raised. Both new domains registered in
  the Gate-13 domain audit (now 28, prefix-free). Tests over real-engine
  verdicts: bare-leaf relabel, proof-for-another-verdict, untrusted reconciler,
  post-commit tamper, unanchored head, and preimage/commit domain separation.
  Closes SD-10; SD-11 (signed verdict inside `NexoraProof`, a version bump)
  and SD-12 (`nexora-verify` surface) remain.

### Added (reconciliation attestation — SD-09)
- **Signed reconciliation verdicts.** `aip-reconcile` gains a fourth authority
  that signs its verdict: `ReconcilerSigner` (custody-based, so the key may be
  wrapped or off-host) produces a `SignedReconciliation`, verified offline with
  `SignedReconciliation::verify` against `ReconcilerTrustAnchors` the verifier
  supplies. The signature covers a domain-separated
  (`SYNTRIASS/GHOST/RECONCILIATION_ATTESTATION/v1`), length-prefixed preimage
  binding the envelope version, reconciler id, key version, and the verdict's
  own canonical bytes — so a verdict's bytes cannot be replayed as an
  attestation and identity/version fields cannot be swapped. Signing attributes
  the verdict; it never strengthens it (a `CannotProve` stays `CannotProve`).
  No existing signed struct, canonical encoder, or wire version changed —
  additive new signed object. Adversarial tests (mutation, swapped id, untrusted
  key/version, foreign-key forger, bare-verdict-signature domain confusion,
  unsupported version) plus a real-engine end-to-end test
  (`ghost-demo/tests/signed_verdict.rs`). Closes SD-09; unblocks SD-10 (NEXORA
  commit of the signed verdict).

### Added (two-host pilot — Phase 1)
- **`aip-transport`** — an authenticated probe↔collector channel over blocking
  TCP (std only; no async runtime). Length-prefixed frames bounded before
  allocation; an Ed25519 challenge/response handshake and a per-frame signature
  over a domain-separated preimage (session nonce + strictly increasing
  sequence + `sha256(batch)`). Evidence-agnostic: it carries opaque batch bytes
  and holds no evidence key. Refuses replay, reorder, tamper, oversize, and an
  unlisted probe key. Unit + loopback tests.
- **`aip-collector`** — the off-host collector daemon. Attests authenticated
  batches under a wrapped signing key, binds each batch to its authenticated
  probe id, persists chain state, keeps a fresh signed health record, and fails
  closed on a continuity refusal. An operator-controlled JSON allow-list gates
  which transport key may submit as which probe id.
- **`aip-probe`** — the host-side probe daemon. Drives `aip-observe`'s perf
  sensors (sched, sockstate, socksend), ships unsigned batches to the collector,
  and holds a transport-auth key only — never an evidence key.
- **Custody-composable collector runtime.** `CollectorRuntime::start_with_custodian`
  and `CollectorSigner::resume_with_custodian` (plus `CollectorKey::into_custodian`)
  let the persistence/continuity runtime resume under a wrapped-file custodian
  without the raw key ever entering the process as bytes. `resume` now delegates
  to the custody path, so there is one continuity implementation. No signed
  field, canonical encoder, verification rule, or protocol version changed.
- **End-to-end proof** (`aip-collector/tests/e2e.rs`): a probe ships a real
  `ObservationBatch` over TCP to a collector holding a wrapped key; the
  resulting `AttestedBatch` verifies offline against the collector's public key;
  an unlisted transport key is refused with nothing attested.
- Design record `docs/pilot/PHASE1_DAEMONS.md`; `deploy/pilot/` updated to the
  built, env-driven daemons.

### Security
- **Observer integrity boundary (observation-integrity finding).** A foreign
  eBPF program on a tracepoint Sniffer Dog samples suppresses that tracepoint's
  perf submission host-wide with no dropped-record accounting, so a live,
  continuity-verified observer can be silently blind — and, before this change,
  still sign `Active` coverage and let a blinded window drive a `PhantomClaim`.
  Fixed, fail-safe and strictly monotone (it can only turn a coverage claim
  into `CannotProve`, never the reverse):
  - New `ObserverState::IntegrityUnknown`, carried inside the signed
    `SensorHealth`, set when the collector detects a foreign tracepoint gate.
  - `PerfTracepoints::foreign_bpf_program_count` (via `PERF_EVENT_IOC_QUERY_BPF`)
    and `ProcessTracer::mechanism_integrity` — the synchronous, fail-closed
    detector.
  - `covered_by_kernel_pushed_source` now requires a gate-independent
    kernel-pushed mechanism (netlink connector / `fanotify` / `AF_PACKET`); a
    lone perf-tracepoint mechanism no longer licenses a non-occurrence claim.
  - Reconciler maps `IntegrityUnknown` to `cannot_prove(ObserverIntegrityUnknown)`.
  - **Wire change:** `OBSERVE_PROTOCOL_VERSION` 8 → 9 (additive state code
    `0x06`; all in-tree records rebuild against v9). `CANNOT_PROVE`,
    `EvidenceCeiling` and the single reconciler authority are unchanged.
  Specs: `docs/OBSERVATION_INTEGRITY_REQUIREMENTS.md`,
  `docs/OBSERVATION_MECHANISM_INDEPENDENCE.md`,
  `docs/OBSERVATION_INTEGRITY_DECISION_RECORD.md`; reproduction in
  `validation/observation_integrity/`.
- **Observer integrity boundary — extended to every perf sensor and wired
  live.** The first cut detected the foreign tracepoint gate only on the
  `sched` process tracepoints. An adversarial pass found
  `sock:inet_sock_set_state` and `sock:sock_send_length` still went silently
  blind. Now closed, fail-safe and monotone, with no wire change
  (`MechanismIntegrity` is not serialized; state code `0x06` already ships):
  - `SockStateTracer::mechanism_integrity` and
    `SockSendTracer::mechanism_integrity` added, all three perf sensors routed
    through one fail-closed `MechanismIntegrity::from_foreign_program_query`.
  - New `MechanismIntegrity::Unverifiable` for a refused kernel query, distinct
    from a *found* gate and failing closed identically.
  - `CollectorSigner::note_mechanism_integrity` is keyed per `SourceMechanism`
    (worst-of), so a clean reading cannot mask a gated one; state self-heals
    when the gated mechanism clears.
  - The detector is wired into `ghost-demo`'s live drain, not only the
    validation recorder.
  - New adversarial ledger `docs/security/ADVERSARIAL_RESULTS.md`; live
    before/after evidence sealed under
    `validation/observation_integrity/results/20260917T_*` via
    `validation/observation_integrity/pipeline_under_gate.sh`.

### Added
- **Signed audit-export bundle.** `GET /v1/evidence/{id}/export` returns a
  portable `application/zip` (evidence, verification report JSON + Markdown,
  authority graph JSON + DOT, manifest, Ed25519 bundle signature) for offline
  verification by auditors/regulators. New `aip-protocol::bundle`
  (`build_zip`/`verify_zip`), raw Ed25519 helpers in `aip-crypto`, and
  `aip-verify bundle.zip` (PASS/WARNING/FAIL). Spec: `docs/AUDIT_EXPORT_SPEC.md`.
  Tenant-scoped export (cross-tenant → 404); every tamper scenario flips a
  named bundle check (tested in `aip-protocol/tests/bundle.rs` and an
  in-process HTTP test).

### Added (storage)
- **PostgreSQL Evidence Vault backend.** New `EvidenceStore` trait with two
  implementations: `JsonlEvidenceStore` (the original append-only file) and
  `PostgresEvidenceStore` (feature `postgres`) — durable, transactional,
  tenant-isolated. Handlers depend only on the trait; backend chosen at
  runtime via `AIP_STORE_BACKEND` (`jsonl` default | `postgres`) + `DATABASE_URL`.
- Schema: `evidence_packets` (+ tenant/hash/created_at indexes) and
  materialised, tenant-isolated `authority_nodes` / `authority_edges`
  (`deploy/sql/schema.sql`; applied idempotently on startup under an advisory
  lock).
- `aip-migrate` tool: idempotent JSONL → PostgreSQL import preserving each
  record's tenant (requires `--features postgres`).
- `aip-service` converted to lib + bins (`airon-aip`, `aip-migrate`).
- Live-DB integration tests (store/get/all/count, cross-tenant isolation,
  tenant-conflict, authority materialisation) gated by `AIP_TEST_DATABASE_URL`;
  10k-packet benchmark (`pg_benchmark_10k`, `--ignored`).
- `docs/BACKUP_AND_RECOVERY.md`, `docs/STORAGE_PERFORMANCE.md`; docker compose
  now wires PostgreSQL as the primary backend with a healthcheck.

### Changed
- Authority graph is now built from a supplied packet list
  (`AuthorityGraph::from_packets`), making it storage-backend agnostic.

### Added (prior)
- `aip-verify`: standalone offline EvidencePacket verifier CLI for auditors
  (`cargo install --path aip-standalone/aip-verify`). Verifies integrity with
  no configuration; accepts trusted issuer/counterparty keys and a revocation
  list for full authority verification.
- GitHub Actions: `ci.yml` (fmt, clippy `-D warnings`, test, audit, deny,
  best-effort coverage), `security.yml` (cargo-audit, gitleaks, trivy),
  `release.yml` (multi-target binaries → GitHub Release).
- 