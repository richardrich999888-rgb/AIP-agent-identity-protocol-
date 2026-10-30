# AIP 1.0-rc — completion loop

One item per iteration. An item is ticked only with a commit SHA, a CI run URL
or retained receipt, and test counts. `BLOCKED_BY_INFRASTRUCTURE` and
`BLOCKED_BY_EXTERNAL_APPROVAL` are final states for this sandbox, not failures
to hide.

Working branch: `claude/release-completion-loop`, based on
`origin/fix/vanian-end-to-end-green` @ `4d0ce1e` (production sources identical
to validation candidate `9ed1662`).

## Iteration 1 — ground truth (verified 2026-10-30)

| Claim | Verified | Evidence |
|---|---|---|
| `main` at `872dbf3` (2026-06-19) | YES | `git log -1 origin/main` |
| Candidate `9ed1662` on `fix/vanian-end-to-end-green`, head `4d0ce1e` | YES; `9ed1662` is the parent of `4d0ce1e`, which changes only docs/evidence | `git log 9ed1662..4d0ce1e` (1 commit); PR #12 body |
| Draft PR #12 → `integration/vanian-enterprise-service-delivery` (`a933fdc`) | YES: open, draft, `mergeable_state: clean`, 24 commits, 748 files | GitHub API, PR #12 |
| All seven workflows passed on `9ed1662` | YES: CI 40854983581, same-run 40854983596, real-agent contracts 40854983590, enterprise 40854983680, RBI 40854983605, Agent Zero 40854983707, interoperability 40854983593 — all `success` | GitHub Actions API |
| Same seven on publication head `4d0ce1e` | YES (not stated in the prompt): 40858045183, 40858045115, 40858045007, 40858045141, 40858045231, 40858045203, 40858045161 — all `success` | GitHub Actions API |
| Debug 3304/0/10; release 3306/0/8; 14 PostgreSQL | YES, as recorded in `validation/final_acceptance/REPORT.md` and `ci/candidate-9ed1662-workspace.json` on that branch | not re-derived from logs in this iteration |
| Newest commit `57ac0d1` on `integration/snifferdog-complete-enterprise-validation` (29 Oct) | YES | `git log -1` |
| The two lines have diverged | YES, but less than implied: snifferdog has **5** commits not in `fix` (7625b1d, e4cd07d, 8d38d77, d5c39dd, 57ac0d1); `fix` has **46** not in snifferdog | `git rev-list --left-right --count` |
| Other live branches (6 listed) | YES, at the stated heads; `claude/strategic-validation-loop` is `504c15b`. **Correction:** there are **20** remote branches, not 11 — 10 more are unlisted (see A1) | `git branch -r` |
| Acceptance: 11 PASS / 4 BLOCKED (collector key boundary, customer installation, separate administration, independent bank acceptance) | YES | `validation/final_acceptance/REPORT.md` line 70 |
| `PRODUCT_READINESS.md` milestone PARTIAL | YES; "Production blockers and external validation" section at line 126 | file on `fix` |

**Discovered overlap (affects A2/A3):** `9ed1662` repair 4 fixed the
connector/scheduler adjacent-batch split with a bounded queue, one monotonic
cutoff and 50 ms holdback. `claude/strategic-validation-loop` (`5b146be`)
fixed the same defect differently (connector-first drain + collector
previous-batch carry), and `5590075` adds worker-thread binding and an
inter-batch drain. These touch the same files (`aip-probe/src/{sensors,main}.rs`,
`aip-observe/src/{probe,linux}.rs`, `aip-collector/src/sink.rs`) and must be
reconciled deliberately, not textually merged.

## Phase A — consolidate the code line
- [x] A1. Branch inventory → `docs/release/BRANCH_INVENTORY.md` (all 20 remote branches) — 5 with unique work, 14 contained; `codex/val-ladder-sync` awaits owner decision
- [ ] A2. `release/aip-1.0-rc` from the `9ed1662` line; reviewed merge of `integration/snifferdog-complete-enterprise-validation`; workspace CI 0 failed
- [ ] A3. Fold in remaining keep-branches one at a time (incl. reconciling the strategic-loop probe fixes with repair 4)
- [ ] A4. All seven workflows on the RC head → `validation/final_acceptance/RC_REPORT.md`
- [ ] A5. PR `release/aip-1.0-rc → main` (not merged until Phase C passes)

## Phase B — software production blockers
- [ ] B1. Two-host key custody with automated probe-cannot-read-collector-key test and shared-key refusal
- [ ] B2. Durable probe outage handling, failed-send resend, forward clock-discontinuity detection
- [ ] B3. Capacity, loss and restart tests; evidence-store backup/restore with continuity
- [ ] B4. Bounded collector workers and back-pressure
- [ ] B5. TLS/mTLS, OIDC, rate limits, per-tenant trust policy, reviewed enrolment
- [ ] B6. HSM/KMS backends (PKCS#11 + one cloud KMS); rotation tests
- [ ] B7. Product-level same-run signed bundle via audit export, verified by `aip-verify`
- [ ] B8. Live coverage monitor for `/v1/coverage`

## Phase C — release engineering
- [ ] C1. Sigstore signing for archive, .deb, images, SDKs, Helm chart
- [ ] C2. CycloneDX SBOMs, image scanning, `cargo deny`, pinning in CI
- [ ] C3. Platform matrix: Ubuntu 22.04/24.04, RHEL 9 install/upgrade/uninstall; sensor-by-kernel table
- [ ] C4. Signed air-gap bundle with no-network install test
- [ ] C5. 1.0.0-rc versioning of OpenAPI and SDKs; changelog; upgrade notes

## Phase D — make the blocked gates closable on a customer site
- [ ] D1. `deploy/pilot/` installer for probe host and separately administered collector host
- [ ] D2. `pilot-acceptance` script emitting a signed acceptance receipt
- [ ] D3. Customer runbook and security questionnaire answers (incl. DPDP Act notes)
- [ ] D4. Update `PRODUCT_READINESS.md` and the acceptance matrix

## Phase E — FinTrust Agent Payments (after A–C green)
- [ ] E1. Spending-mandate object with per-hop attenuation
- [ ] E2. Pre-signing policy check for stablecoin transfers; refusals as evidence
- [ ] E3. Testnet on-chain reconciliation: MATCH / MISMATCH / CANNOT_PROVE
- [ ] E4. AP2-style mandate and x402 request adapter (testnet/synthetic only)

## Iteration log
| # | Item | Result | Evidence |
|---|---|---|---|
| 1 | Ground-truth verification + checklist seed | DONE, 2 corrections (divergence size; 20 branches) and 1 overlap recorded | this file |
| 2 | A1 branch inventory | DONE (docs only; no CI-affecting change) | `docs/release/BRANCH_INVENTORY.md` |
