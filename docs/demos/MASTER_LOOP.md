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
- [ ] W0.3 **Revised 2026-11-06 — waiting.** Extend, do not fork, the teaching session's `deploy/syntriass/models.manifest.json` (add 7B-class, IBM Granite, Mistral to `not_yet_pinned` if absent) and write the staging script on top of `deploy/syntriass/resolve_model.py`; packages via `deploy/syntriass/setup_env.sh`. Starts after PR "Model resolver, dataset setup, pinned Python env" (`fix/model-resolver-and-setup`) merges into the runtime line and `feature/wow-demos` is rebased. **As of 2026-11-06 that PR is not open yet** (only #13 targets the runtime line). Licence/hash findings already gathered are kept outside git for that step

## W1 — Pull the plug
- [x] W1.1 Cloud-API comparison app (no embedded key; fails cleanly offline) — `demos/pull-the-plug/cloud_app.py`; 11/11 tests local (2 offline-namespace tests SKIPPED on CI runners)
- [x] W1.2 Live meter (strategy, model calls, ms, CPU-s, bytes out, ₹/answer at a configurable rate) — `demos/pull-the-plug/meter.py`; tested against a stand-in runtime in the real `Response` shape with a schema-drift guard; **real-binary run deferred to W1.4** (needs W0.3 models)
- [x] W1.3 Side-by-side local page (no CDN) — `demos/pull-the-plug/server.py` + `page.html`; 32/32 tests incl. real-browser check (0 external requests, 0 page errors) and end-to-end offline run (local 0 bytes out, cloud `no_route`); local side still the stand-in until W1.4
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
| 6 | W1.3 side-by-side page | DONE; also fixed `cloud_app` reading proxies from ambient env instead of its config | `demos/pull-the-plug/` |
| 5 | W1.2 fix | Meter read the `serve --eval` envelope `{"id","response"}` as the Response (found while building W1.3); now unwraps it, reports `{"error"}` as a runtime failure, still reads `ask`'s bare Response; drift guard pins the envelope; mutation check: 2 tests fail without the fix | `demos/pull-the-plug/meter.py` |
| — | Trivy (inherited) | 4 HIGH misconfig findings (KSV-0009/0010/0118/0121) in retained render `validation/enterprise/results/HELM_20261028T103133Z/template-enabled.yaml`; no CVEs (job scans secret+misconfig only). Tracked in **issue #15**; fix owned by the teaching-demo session, not started as of 2026-11-06 10:45 UTC; not duplicated here | issue #15 |
| 4 | W1.2 live meter | DONE; runtime-reported vs meter-measured fields kept separate; no rupee figure without an operator rate; offline bytes out 0 even when the runtime tries the network. PR #14 (model resolver) now open, not merged | `demos/pull-the-plug/meter.py` |
| 3 | W1.1 cloud-API app | DONE; offline failure now names a proxy in the path (`via_proxy`) instead of a bare `connection_refused` | `demos/pull-the-plug/` |
| — | PR #13 CI | 3 red checks all inherited from base `2883da7` (trivy: 4 HIGH in retained Helm render; `vanian-sovereign` agent_execution needs user namespaces the runner lacks). Commented on PR; fixes proposed, not applied | PR #13 comment |
| 2 | W0.2 harness | DONE; 12/12 tests incl. live offline refusal on this host and namespaced offline run; memory label fixed to round down (15 not 16) | `demos/common/` |
| 1 | W0.1 inventory | DONE; 4 corrections to the brief (snifferdog head moved to `ab16159`; "~2,540 tests" is whole-repo, CBOM-path ~646/875; scene 3 is recorded by default; AIP-only events omitted); W3 companion file missing | `docs/demos/INVENTORY.md` |
