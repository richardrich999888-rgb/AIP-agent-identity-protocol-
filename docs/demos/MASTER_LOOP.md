# SYNTRIASS "wow moments" — master loop

One item per iteration. An item is ticked only with a commit SHA, test counts
and result-file paths. BLOCKED items say exactly what a human must do.

AIP working branch: `feature/wow-demos` from `feature/syntriass-runtime-v02`
@ `2883da7`. OVERLAY working branch: `feature/wow-demos`, based on
`claude/cbom-dashboard-ai-analysis-uujp2g` @ `eccb668` (owner-approved),
**only after W4.1 confirms it builds and its suite runs**, with real pass/fail
counts recorded first. W4/W5 work is prepared locally and not pushed until
write access to OVERLAY is granted.

Facts behind these items: `docs/demos/INVENTORY.md`.

## W0 — Inventory and foundations
- [x] W0.1 Inventory both repositories → `docs/demos/INVENTORY.md`
- [x] W0.2 `demos/` common harness: offline check, hardware report, result-file writer (JSON: timestamps, commit SHAs, hardware), recorded-vs-live label helper — `demos/common/`; 12/12 unit tests (local run; no CI covers `demos/`)
- [ ] W0.3 Model manifest (name, file, SHA-256, size, source URL, licence) + a staging script the owner runs once on a connected machine. Pin Qwen2.5-1.5B-Instruct, one 7B-class model, IBM Granite (Apache-2.0) and Mistral-7B-Instruct (Apache-2.0); licences verified from each model card; **stop if any restricts commercial use**. Weights never in git; demos load only from the bundle path; never a model API

## W1 — Pull the plug
- [ ] W1.1 Cloud-API comparison app (no embedded key; fails cleanly offline)
- [ ] W1.2 Live meter (strategy, model calls, ms, CPU-s, bytes out, ₹/answer at a configurable rate)
- [ ] W1.3 Side-by-side local page (no CDN)
- [ ] W1.4 `demos/pull-the-plug/run.sh` + acceptance test (offline: cited answer, 0 bytes out, cloud side fails)

## W2 — Catch the lying agent
- [ ] W2.1 Agent with a hidden undeclared action its own log omits (from `validation/rbi_demo/run.sh`)
- [ ] W2.2 Show own log vs signed observation vs independent cross-check; offline verify; one-byte tamper fails
- [ ] W2.3 `demos/lying-agent/run.sh` (5 min), explainer, acceptance test (always detected; reproducible verdict)

## W3 — The AI asks the teacher + knowledge pack
- [—] W3 **Tracked in the teaching-demo loop** (separate session, own branch, checklist `docs/demo/TEACH_DEMO_LOOP.md`). Not built here; that session's files are not edited from this loop.

## W4 — Quantum X-ray (OVERLAY)
- [ ] W4.1 Build the CBOM engine; record the real executed test count
- [ ] W4.2 Synthetic sample image with planted mixed cryptography
- [ ] W4.3 Scan → CycloneDX 1.6 CBOM → one-page report; control mapping only with cited evidence
- [ ] W4.4 `demos/quantum-xray/run.sh` + acceptance test (every planted weakness found, nothing invented)

## W6 — Reproducible benchmark package
- [ ] W6.1 Package the capability benchmark for one-command offline rerun
- [ ] W6.2 `demos/benchmark/REPRODUCE.md` with expected ranges and the "must not say" list
- [ ] W6.3 Fresh-machine rerun; record differences honestly

## W5 — Post-quantum in one switch (OVERLAY; "proof of concept")
- [ ] W5.1 Two containers, unmodified TCP client/server
- [ ] W5.2 Packet captures before/after; app binary hash unchanged
- [ ] W5.3 Fail-closed check (identity removed → refused, not downgraded)
- [ ] W5.4 Measured overhead; `demos/pq-switch/run.sh`

## W7 — One-USB demo kit
- [ ] W7.1 Offline bundle with checksums; clean-machine no-network install test
- [ ] W7.2 `demos/launch.sh` modes (customer-<sector>, security, pq, investor-3min); a `teach` mode prints **"not ready"** until the teaching-demo loop reports ready, and calls that loop's own script after
- [ ] W7.3 10 consecutive passes per mode → `docs/demos/REHEARSAL_LOG.md`

## W8 — Buyer evidence pack
- [ ] W8.1 One-page security note per product
- [ ] W8.2 SBOM / AIBOM / CBOM; licence list
- [ ] W8.3 Hardware sizing from measured runs on ≥2 machines
- [ ] W8.4 Buyer questionnaire, each answer available / partial / planned

## W9 — Recording kit
- [ ] W9.1 Terminal recordings + screenshot sequences + narration scripts (no synthetic voice/video)

## Iteration log
| # | Item | Result | Evidence |
|---|---|---|---|
| — | Owner decisions 2026-11-05 | Corrections accepted as source of truth; W3 handed to the teaching-demo loop; release loop stays paused; no branch deletions | `INVENTORY.md` §Source of truth |
| 2 | W0.2 harness | DONE; 12/12 tests incl. live offline refusal on this host and namespaced offline run; memory label fixed to round down (15 not 16) | `demos/common/` |
| 1 | W0.1 inventory | DONE; 4 corrections to the brief (snifferdog head moved to `ab16159`; "~2,540 tests" is whole-repo, CBOM-path ~646/875; scene 3 is recorded by default; AIP-only events omitted); W3 companion file missing | `docs/demos/INVENTORY.md` |
