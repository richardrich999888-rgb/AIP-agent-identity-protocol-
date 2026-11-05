# SYNTRIASS "wow moments" — master loop

One item per iteration. An item is ticked only with a commit SHA, test counts
and result-file paths. BLOCKED items say exactly what a human must do.

AIP working branch: `feature/wow-demos` from `feature/syntriass-runtime-v02`
@ `2883da7`. OVERLAY working branch: `feature/wow-demos`, base chosen in W4.1
(recommended `claude/cbom-dashboard-ai-analysis-uujp2g` @ `eccb668`); needs
push access (attached read-only today).

Facts behind these items: `docs/demos/INVENTORY.md`.

## W0 — Inventory and foundations
- [x] W0.1 Inventory both repositories → `docs/demos/INVENTORY.md`
- [ ] W0.2 `demos/` common harness: offline check, hardware report, result-file writer (JSON: timestamps, commit SHAs, hardware), recorded-vs-live label helper
- [ ] W0.3 Offline model set (Qwen2.5 1.5B, one 7B-class, one non-Chinese model), hash-verified, licences in `demos/MODELS.md`; download is a user-run connected staging step. **Disk: 12 GB free here**

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
- [ ] W3.0 **BLOCKED: companion file `AIRON_Teach_Demo_Claude_Code_Loop.md` is not in either repository.** Needed to expand W3.A1 … W3.G4

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
- [ ] W7.2 `demos/launch.sh` modes (customer-<sector>, security, pq, investor-3min)
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
| 1 | W0.1 inventory | DONE; 4 corrections to the brief (snifferdog head moved to `ab16159`; "~2,540 tests" is whole-repo, CBOM-path ~646/875; scene 3 is recorded by default; AIP-only events omitted); W3 companion file missing | `docs/demos/INVENTORY.md` |
