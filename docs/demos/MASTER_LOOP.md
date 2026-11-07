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
- [x] W2.1 Agent with a hidden undeclared action its own log omits (from `validation/rbi_demo/run.sh`) — `demos/lying-agent/agent.py` + independent `ground_truth.py`; 8/8 tests
- [x] W2.2 Show own log vs signed observation vs independent cross-check; offline verify; one-byte tamper fails — `observe.py` + `show.py`; 5/5 lying runs detected and attributed (Sniffer Dog + auditd), 1/1 honest clean; evidence `demos/lying-agent/evidence/2026-11-06/` from clean commit `aab3e12`
- [x] W2.3 `demos/lying-agent/run.sh` (5 min), explainer, acceptance test (always detected; reproducible verdict) — 25 s machine time; acceptance 10/10 lying detected + 10/10 honest clean from clean commit `24d72c4` (`evidence/acceptance-2026-11-07/`); a failed batch (auditd down after restart) kept beside it

## W3 — The AI asks the teacher + knowledge pack
- [—] W3 **Tracked in the teaching-demo loop** (separate session, own branch, checklist `docs/demo/TEACH_DEMO_LOOP.md`). Not built here; that session's files are not edited from this loop.

## W4 — Quantum X-ray (OVERLAY)
- [x] W4.1 Build the CBOM engine; record the real executed test count — on `eccb668`: core crates 149, lib (full features, includes non-CBOM code) 1,867, CBOM integration 38 → 2,054 executed, 0 failed. After this branch's two fixes: lib 1,871/1,871
- [x] W4.2 Synthetic sample image with planted mixed cryptography — OVERLAY `d1adc90` (`demos/quantum-xray/make_sample.sh --image`, 1.2 MB `FROM scratch`); ground truth checked by openssl, not the engine. Found 2 engine defects (nginx directives skipped; bare `TLSv1` Unknown), fixed with regression tests in `92c8b02`, `07d0319`
- [x] W4.3 Scan → CycloneDX 1.6 CBOM → one-page report; control mapping only with cited evidence — OVERLAY `6072578` `report.py`; no control marked met (no verified CNSA 2.0 / IR 8547 pack ships); `syntriass-compliance` self-assessment not shown
- [x] W4.4 `demos/quantum-xray/run.sh` + acceptance test (every planted weakness found, nothing invented) — OVERLAY `6072578`, clean tree: `ACCEPTANCE: PASS` 4/4 planted found, 0 invented; full scan 5 ms over 8 files; 9/9 unit tests. **Committed locally only — not pushed (no OVERLAY write access yet)**

## W6 — Reproducible benchmark package
- [ ] W6.1 Package the capability benchmark for one-command offline rerun
- [ ] W6.2 `demos/benchmark/REPRODUCE.md` with expected ranges and the "must not say" list
- [ ] W6.3 Fresh-machine rerun; record differences honestly

## W5 — Post-quantum in one switch (OVERLAY; "proof of concept")
- [x] W5.1 Two containers, unmodified TCP client/server — OVERLAY `demos/pq-switch/`: same host `nc` (sha256 `2a6fac3d…`) as server and client, `FROM scratch` image, `--internal` network (no route out, checked by acceptance)
- [x] W5.2 Packet captures before/after; app binary hash unchanged — baseline: data in clear on the wire, 918 B; overlay: delivered, not on the wire, 14,146 B; same exe sha256 in all 6 phases; pcaps in `evidence/2026-11-07-13c0fb1/`
- [x] W5.3 Fail-closed check (identity removed → refused, not downgraded) — identity removed (with and without a fallback PSK), plaintext client, impostor: none delivered; with identity removed the client sends 0 payload bytes. **Finding: refusal is silent to the app** (exit 0; waits for its own idle timeout)
- [x] W5.4 Measured overhead; `demos/pq-switch/run.sh` — n=20 per mode, timed runs captured: median added 0.0 / 2.5 / 3.1 ms over 3 runs, not separable from ~70 ms `docker exec` noise; +13.2 KB per connection. `ACCEPTANCE: PASS` from clean OVERLAY `13c0fb1`; 9/9 unit tests. **Local only — not pushed (no OVERLAY write access)**

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
| 11 | W5.1–W5.4 PQ switch (OVERLAY, local, proof of concept) | DONE; caught and fixed in my own harness: capture on the bridge device saw no container traffic (meaningless 'no marker'), a cleanup bug that exited silently, seeds visible on the docker command line (now mode-600 env files), timed runs not captured (now judged). Overlay finding: refusals are silent to the client program | OVERLAY `demos/pq-switch/README.md` |
| 10 | W4.1–W4.4 Quantum X-ray (OVERLAY, local) | DONE; first full scan read 0 files (scanner rightly won't follow the `/proc/<pid>/root` symlink) and acceptance FAILED — fixed in `run.sh` by scanning the container's top-level dirs. Engine gaps reported, not changed: recommendations omit 3DES and TLS 1.0/1.1 and list the one RSA key as 5 entries; RC4 flagged quantum-vulnerable, 3DES not; container mode reads cert dirs only | OVERLAY `demos/quantum-xray/README.md` |
| — | Owner decisions 2026-11-05 | Corrections accepted as source of truth; W3 handed to the teaching-demo loop; release loop stays paused; no branch deletions | `INVENTORY.md` §Source of truth |
| 9 | W2.3 run.sh/explainer/acceptance | DONE; one batch re-run because its tree was dirty (mode bits), one batch FAILED correctly when auditd was down — both recorded | `demos/lying-agent/evidence/acceptance-2026-11-07/` |
| 8 | W2.2 observe/verify/tamper | DONE; found and fixed: hard-coded "log doesn't mention it" claim, port-vs-timestamp false match, keys left behind on a failed run, over-broad mode guard | `demos/lying-agent/evidence/2026-11-06/` |
| 7 | W2.1 lying agent + ground truth | DONE; caught a mode-revealing path leaking into the self-log, now refused by the harness | `demos/lying-agent/` |
| 6 | W1.3 side-by-side page | DONE; also fixed `cloud_app` reading proxies from ambient env instead of its config | `demos/pull-the-plug/` |
| 5 | W1.2 fix | Meter read the `serve --eval` envelope `{"id","response"}` as the Response (found while building W1.3); now unwraps it, reports `{"error"}` as a runtime failure, still reads `ask`'s bare Response; drift guard pins the envelope; mutation check: 2 tests fail without the fix | `demos/pull-the-plug/meter.py` |
| — | Trivy (inherited) | 4 HIGH misconfig findings (KSV-0009/0010/0118/0121) in retained render `validation/enterprise/results/HELM_20261028T103133Z/template-enabled.yaml`; no CVEs (job scans secret+misconfig only). Tracked in **issue #15**; fix owned by the teaching-demo session, not started as of 2026-11-06 10:45 UTC; not duplicated here | issue #15 |
| 4 | W1.2 live meter | DONE; runtime-reported vs meter-measured fields kept separate; no rupee figure without an operator rate; offline bytes out 0 even when the runtime tries the network. PR #14 (model resolver) now open, not merged | `demos/pull-the-plug/meter.py` |
| 3 | W1.1 cloud-API app | DONE; offline failure now names a proxy in the path (`via_proxy`) instead of a bare `connection_refused` | `demos/pull-the-plug/` |
| — | PR #13 CI | 3 red checks all inherited from base `2883da7` (trivy: 4 HIGH in retained Helm render; `vanian-sovereign` agent_execution needs user namespaces the runner lacks). Commented on PR; fixes proposed, not applied | PR #13 comment |
| 2 | W0.2 harness | DONE; 12/12 tests incl. live offline refusal on this host and namespaced offline run; memory label fixed to round down (15 not 16) | `demos/common/` |
| 1 | W0.1 inventory | DONE; 4 corrections to the brief (snifferdog head moved to `ab16159`; "~2,540 tests" is whole-repo, CBOM-path ~646/875; scene 3 is recorded by default; AIP-only events omitted); W3 companion file missing | `docs/demos/INVENTORY.md` |
