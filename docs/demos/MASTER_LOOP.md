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
- [x] W0.3 Models staged with provenance — `demos/models/stage.py` on top of PR #14's resolver (merged into this branch `1d83db5`, PR #14 itself still unmerged; owner chose to proceed 2026-11-08). Each file pinned to a Hugging Face revision, SHA-256 checked, licence re-read from the live card (refused unless Apache-2.0, not gated): Qwen2.5-1.5B Q4/Q8 (Apache-2.0, LICENSE file read; hashes = the teaching session's manifest, unedited) and **IBM Granite 3.3-2B Q4_K_M** (Apache-2.0 per card; no LICENSE file in the repo; pinned in `demos/models/extra-models.json` — the record to add to the manifest). llama-server built from the same llama.cpp source the benchmark used (llama-cpp-python 0.3.16 sdist `34ed0f9b…`, `4227c9b`). `demos/models/PROVENANCE-2026-11-08.json`. 7B-class and Mistral not staged (disk). Needed one host added to the environment allowlist: `us.aws.cdn.hf.co`

## W1 — Pull the plug
- [x] W1.1 Cloud-API comparison app (no embedded key; fails cleanly offline) — `demos/pull-the-plug/cloud_app.py`; 11/11 tests local (2 offline-namespace tests SKIPPED on CI runners)
- [x] W1.2 Live meter (strategy, model calls, ms, CPU-s, bytes out, ₹/answer at a configurable rate) — `demos/pull-the-plug/meter.py`; tested against a stand-in runtime in the real `Response` shape with a schema-drift guard; **real-binary run deferred to W1.4** (needs W0.3 models)
- [x] W1.3 Side-by-side local page (no CDN) — `demos/pull-the-plug/server.py` + `page.html`; 32/32 tests incl. real-browser check (0 external requests, 0 page errors) and end-to-end offline run (local 0 bytes out, cloud `no_route`); local side still the stand-in until W1.4
- [x] W1.4 `demos/pull-the-plug/run.sh` + acceptance test (offline: cited answer, 0 bytes out, cloud side fails) — real runtime + local model in a no-route namespace, 5 fixed questions (3 cited facts, a restricted secret withheld, no cross-tenant citation): **PASS on Qwen2.5-1.5B Q4 and on IBM Granite 3.3-2B** from clean `64d6f40`; 0 bytes out; cloud side `dns_unavailable`. Median per answer: Qwen 6.1 s / 15.7 CPU-s, Granite 9.8 s / 27.7 CPU-s (4 vCPU, no GPU). `demos/pull-the-plug/evidence/2026-11-08-64d6f40-*`

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
- [ ] W6.1 Package the capability benchmark for one-command offline rerun — **BLOCKED**: every phase starts a local model server; the wrapper waits for PR #14 (`resolve_model.py`) to merge and for staged weights (W0.3). No `run.sh` shipped meanwhile (it would hard-code model paths, which PR #14 removes)
- [x] W6.2 `demos/benchmark/REPRODUCE.md` with expected ranges and the "must not say" list — `summarize.py` recomputes the table from the recorded files (3/3 tests, added to the demos CI job). Agrees on every count and all 4 CIs; **disagrees on the candidate's CPU-s/task: ≤ 0.01 is the capability path only, 3.05 across all 40 items**. No variance measured (1 run per system), so no range is invented
- [ ] W6.3 Fresh-machine rerun; record differences honestly — **BLOCKED** on W6.1 and models

## W5 — Post-quantum in one switch (OVERLAY; "proof of concept")
- [x] W5.1 Two containers, unmodified TCP client/server — OVERLAY `demos/pq-switch/`: same host `nc` (sha256 `2a6fac3d…`) as server and client, `FROM scratch` image, `--internal` network (no route out, checked by acceptance)
- [x] W5.2 Packet captures before/after; app binary hash unchanged — baseline: data in clear on the wire, 918 B; overlay: delivered, not on the wire, 14,146 B; same exe sha256 in all 6 phases; pcaps in `evidence/2026-11-07-13c0fb1/`
- [x] W5.3 Fail-closed check (identity removed → refused, not downgraded) — identity removed (with and without a fallback PSK), plaintext client, impostor: none delivered; with identity removed the client sends 0 payload bytes. **Finding: refusal is silent to the app** (exit 0; waits for its own idle timeout)
- [x] W5.4 Measured overhead; `demos/pq-switch/run.sh` — n=20 per mode, timed runs captured: median added 0.0 / 2.5 / 3.1 ms over 3 runs, not separable from ~70 ms `docker exec` noise; +13.2 KB per connection. `ACCEPTANCE: PASS` from clean OVERLAY `13c0fb1`; 9/9 unit tests. **Local only — not pushed (no OVERLAY write access)**

## W7 — One-USB demo kit
- [~] W7.1 Offline bundle with checksums; clean-machine no-network install test — `demos/kit/`: 6.3 MB kit, 177 files, `SHA256SUMS` + `MANIFEST.json` (both commits, binary hashes, host needs); install test PASS from kit `9fe94a0`/`3d63f95` (`demos/kit/evidence/2026-11-07-9fe94a0/`): no-network namespace, archive + 177 files verified, one flipped byte refused, pq and quantum pass from the kit. **Not a clean machine** (same host). **security runs in the host network namespace**: its process-connector sensor only works in the initial netns (first attempt failed for that reason; sensor not weakened)
- [x] W7.2 `demos/launch.sh` modes (customer-<sector>, security, pq, investor-3min); a `teach` mode prints **"not ready"** until the teaching-demo loop reports ready, and calls that loop's own script after — `demos/launch.py` (`7ccbd4d`): security, pq, quantum READY and run the real demos; customer-<sector>, investor-3min NOT READY (W1.4); teach not ready. Result file per run; 6 tests in CI
- [x] W7.3 10 consecutive passes per mode → `docs/demos/REHEARSAL_LOG.md` — every READY mode 10/10 from clean AIP `7ccbd4d` / OVERLAY `3d63f95`: quantum (1.0 s median), security (24.8 s), pq (35.4 s); 30 result files in `demos/rehearsal-evidence/2026-11-07/`. NOT READY modes not rehearsed

## W8 — Buyer evidence pack
- [x] W8.1 One-page security note per product — `docs/demos/buyer-pack/SECURITY_NOTES.md` (Sniffer Dog, Overlay, CBOM engine, runtime); every claim cites a file; "cannot prove" per product
- [x] W8.2 SBOM / AIBOM / CBOM; licence list — `demos/evidence-pack/build_pack.sh` → `demos/evidence-pack/out/`: SBOMs scoped to shipped binaries (AIP 77, overlay 150 components); licences: third-party all permissive-optioned, **AIP's 8 own crates `LicenseRef-Proprietary` with no LICENSE file**; CBOM from 3 sources (**binscan misses ML-KEM/X25519/Ed25519/ML-DSA/AES-GCM; a floor, not an inventory**); AIBOM of the scripted test agent (0/15 fields independently backed)
- [~] W8.3 Hardware sizing from measured runs on ≥2 machines — **PARTIAL: one machine** (`docs/demos/buyer-pack/SIZING.md`); a second machine is needed
- [x] W8.4 Buyer questionnaire, each answer available / partial / planned — `docs/demos/buyer-pack/QUESTIONNAIRE.md`, 17 questions (5 available, 9 partial, 3 planned)

## W9 — Recording kit
- [x] W9.1 Terminal recordings + screenshot sequences + narration scripts (no synthetic voice/video) — `demos/recording/`: live runs of security, pq, quantum recorded with util-linux `script` (replay: `scriptreplay`), 7 screenshots rendered only from each run's own files (offline, external requests blocked), `NARRATION.md` per mode with do-not-say lists and the RECORDED-label rule; recorded from clean AIP `80e8135` / OVERLAY `3d63f95`. Model modes and teach not recorded (NOT READY)

## Blocked — what each needs (2026-11-07)

| Item | Blocked on | Who can unblock |
|---|---|---|
| W0.3 models, W1.4 Pull the plug, W6.1 / W6.3 benchmark rerun, `customer-<sector>` and `investor-3min` modes | PR #14 (model resolver) is open, not merged; then weights staged from a connected machine, with each licence checked on its model card | Owner: review/merge #14; run the staging download (or allow this session to fetch the pinned files) |
| `customer-<sector>` content | What each sector's script shows is not defined | Owner: name the sectors and the story for each |
| W7.1 clean machine, W8.3 second machine | Only this sandbox has been available | Owner: a second machine, or approval to use a fresh cloud session as one (the kit would have to be handed to it, since OVERLAY is unpushed) |
| Everything OVERLAY (W4, W5, kit's overlay part) | Commits are local only | Owner: write access to OVERLAY |
| W3 and `teach` | The teaching-demo loop | That session reports ready |
| PR #13 red checks | trivy: #15 (#17 partial); `vanian-sovereign`: #16; `aip-edge` flake: #18 / #19 | Merging #16, #19 and a trivy fix into the base |

## Iteration log
| # | Item | Result | Evidence |
|---|---|---|---|
| 15 | W9.1 recording kit | DONE for every READY mode; launcher now streams output live (first recordings only showed the result at the end). Caught myself writing an unchecked commit id into the narration; replaced with the one in the result files | `demos/recording/` |
| 14 | W8 buyer evidence pack | W8.1, W8.2, W8.4 DONE; W8.3 PARTIAL (one machine). Found: AIP crates proprietary with no LICENSE file; `binscan` misses most algorithms actually in the binaries; my own first drafts mislabelled the Noise hash (BLAKE2, really SHA-256) and the runtime RSS (~6, really 6.2–7.2 MiB) — both corrected against the source before commit | `docs/demos/buyer-pack/`, `demos/evidence-pack/out/` |
| 13 | W7.1–W7.3 kit, launcher, rehearsals | DONE except W7.1's clean machine; found and fixed: kit result files recorded no commit (harness now reads the kit MANIFEST), install test's mode selection bug; security mode cannot run in a separate network namespace (sensor limit, labelled). 30/30 rehearsal runs passed | `demos/kit/`, `docs/demos/REHEARSAL_LOG.md` |
| — | CI flake (PR #13) — **cause found elsewhere** | `aip-edge --test end_to_end` failed 2 of 9 observed runs on PR #13 (`1cf9178`, `74893f2`). **Root cause is a product bug, not a test flake** (issue #18, fix in PR #19 by another session): `/proc/net/tcp` is read in several `read()` calls, so under socket churn one socket's row repeats and was counted as 2–4 corroborations; PR #19 shows base 4/60 failing under loopback churn, fix 0/200. **My earlier lead (nested `cargo build` without `--locked`) was wrong**; my local attempts used CPU load, which PR #19 also refuted, not socket churn. Nothing changed here; it clears when #19 merges into the base | issue #18, PR #19 |
| 12 | W6.2 benchmark REPRODUCE.md | DONE; recomputed the published table from result files: counts and CIs match (bootstrap reproduces them; no committed CI script existed); candidate 'CPU-s per task ≤ 0.01' covers only the 30 capability items, 3.05 over all 40 (probes go to the model). W6.1/W6.3 BLOCKED on PR #14 + models | `demos/benchmark/` |
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
