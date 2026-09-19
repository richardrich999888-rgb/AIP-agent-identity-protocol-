# ENGINEERING MATURITY — SOURCE MAPPING

**Companion to** `docs/ENGINEERING_MATURITY_AND_STRATEGIC_READINESS.md`
**Date:** 2026-09-07
**Purpose:** every material claim in the addendum, traced to its source, with
its evidence type and status. A claim that is not in this table should be
treated as unsupported.

**Branch under assessment:** `claude/codebase-production-readiness-wm6idp`
at `12767ea`. Paths are relative to that tree unless stated otherwise.

---

## 0. Reproduction record for this addendum

| step | command | result |
|---|---|---|
| Acquire the tree without touching the working copy | `git archive 12767ea \| tar -x -C <scratch>` | clean; no checkout, no merge, no branch switch |
| Verify checkpoint identity | `git ls-remote origin` | `12767eab64ff…` = `refs/heads/claude/codebase-production-readiness-wm6idp` |
| Verify `ff52dc2` | `git merge-base --is-ancestor ff52dc2 12767ea` | ancestor confirmed |
| Verify audit baseline | `git merge-base --is-ancestor 82da7a6 12767ea` | ancestor confirmed; **125 commits** between them |
| Verify `main` distance | `git rev-list --count 872dbf3..12767ea` | **228** |
| Full suite, first attempt | `cargo test --workspace --no-fail-fast` | **964 passed / 32 failed** — all 32 the same environment cause (see §5) |
| Build the helper binaries | `cargo build -p aip-edge-observer -p aip-edge-workload` | ok |
| Full suite, second attempt | `cargo test --workspace --no-fail-fast` | **1,691 passed / 0 failed / 6 ignored / 165 test binaries / 0 warnings / exit 0** |

Toolchain: `cargo 1.94.1` / `rustc 1.94.1`. Host: Linux 6.18.44-fc-v24, x86_64,
uid 0, `perf_event_paranoid = 2`.

The second run's binaries include `build_boundary`, `key_custody`,
`managed_signing`, `replay_ingest` and `temporal_bound` — the `aip-service`
suites — confirming **CODE-PROVEN** that the single workspace root now spans the
protocol and the tier that serves it (audit blocker **B-10**).

---

## 1. Checkpoint and provenance claims

| claim | source | evidence type | status |
|---|---|---|---|
| Production branch head is `12767ea` | `git ls-remote origin` | EXECUTION-PROVEN | verified |
| `12767ea` closes the observer-integrity boundary in production | commit message + `docs/OBSERVATION_INTEGRITY_DECISION_RECORD.md` | CODE-PROVEN | verified |
| `ff52dc2` is the observation-integrity / validation work | `git log`; *"validation: correct the A3S evaluation, and cross-check the interference finding"* | CODE-PROVEN | verified |
| `main` is `872dbf3` and untouched | `git ls-remote origin`; `git rev-list --count` | EXECUTION-PROVEN | verified |
| The assessed capability exists only on the unmerged branch | 228-commit distance; crate inventory absent from `main` | CODE-PROVEN | verified — this is the audit's finding **D-1**, unchanged |
| Skills 16–24 are implemented | `.claude/skills/16-…` … `24-…`; crates `aip-system`, `aip-execution`, `aip-platform`, `aip-observation`, `aip-effect`, `aip-edge*`, `aip-uas`, `aip-robotics` | CODE-PROVEN | verified |
| Skills 25–30 exist as **specifications only** | `.claude/skills/25-…` … `30-…` present; **no corresponding crates exist** | CODE-PROVEN | verified — no implementation claimed |

---

## 2. Maturity-dimension claims

| # | claim | source | evidence type | status |
|---|---|---|---|---|
| A1 | 28-crate workspace with explicit boundaries | root `Cargo.toml` members list | CODE-PROVEN | verified |
| A2 | Verticals add no signer, verdict class or engine | `aip-uas/tests/no_second_architecture.rs`; `aip-robotics/tests/cross_vertical.rs` | TEST-PROVEN | verified |
| B1 | Prefix-free, domain-separated canonical encoding | `aip-types/src/canonical.rs`; forensic audit Report 05 §2.2 | CODE-PROVEN | verified |
| B2 | 26 distinct domain tags | `aip-nexora/tests/audit.rs::DOMAINS`; `INVENTION_REGISTER.md` IR-09 | TEST-PROVEN | verified |
| B3 | RFC 6962 Merkle with leaf/node domain separation | `aip-nexora/src/merkle.rs`; audit Report 04 §5 | CODE-PROVEN | verified |
| B4 | **No post-quantum cryptography on this branch** | `INVENTION_REGISTER.md` closing section; audit Report 05 §6 | CODE-PROVEN | verified |
| C1 | 34 established AIRI properties with cited tests | `docs/architecture/AIRI_LIMITATIONS.md` §1 | TEST-PROVEN | verified |
| C2 | Rust/Python byte parity across 9 vectors | `aip-airi/tests/parity_vectors.rs`; `sdk/python/tests/test_canonical_parity.py` | EXECUTION-PROVEN | verified |
| C3 | Model-invocation claims are structurally self-reported | `AIRI_SPECIFICATION.md` §4 (`is_externally_observable`); validation §10 | CODE-PROVEN | verified |
| D1 | Live perf-tracepoint capture on kernel 6.18.44-fc-v24 | `validation/observation_integrity/results/*/environment.txt`, `*_sniffer_dog.jsonl` | EXECUTION-PROVEN | verified |
| D2 | `# CONFIG_KPROBES is not set` on the validation host | `environment.txt`; `AIRI_REAL_WORLD_VALIDATION.md` §11.1 | EXECUTION-PROVEN | verified — a stated environmental constraint |
| E1 | Interference reproduced: 8 execs → 0 observed, loss 0 | `results/20260907T154934Z/verdict.json` | EXECUTION-PROVEN | verified |
| E2 | Mitigation detects the gate | `results/20260907T_fix_verified/verdict.json`: `arm_a="verified"`, `arm_b="integrity_unknown"`, `fix_detected_the_gate: true` | EXECUTION-PROVEN | verified |
| E3 | Two independently built experiments agree | `validation/observation_integrity/README.md` (2a ambiguity-exclusion, 2b minimal-cause) | EXECUTION-PROVEN | verified |
| E4 | Suppression is total within the confirmed window (15/15 execs missed) | `harness/window_analysis.py` + audit-subsystem ground truth | EXECUTION-PROVEN | verified |
| E5 | `OBSERVE_PROTOCOL_VERSION` bumped 8 → 9, once | `aip-observe/src/observed.rs:51` | CODE-PROVEN | verified |
| E6 | `IntegrityUnknown` is code `0x06`, non-`Active`, fails `permits_attested_use` | `aip-observe/src/health.rs:44,55` | CODE-PROVEN | verified |
| E7 | A blinded observer cannot accuse | `aip-reconcile` `t03d`/`t03e`; `aip-observe/tests/observer_integrity.rs` | TEST-PROVEN | verified — the `observer_integrity` binary ran and passed in §0 |
| F1 | The verifier re-derives rather than trusts | `aip-nexora/src/verify.rs` (`rederive`, `ClaimNotDerivable`) | CODE-PROVEN | verified |
| F2 | 20 adversarial NEXORA cases A–T | `aip-nexora/tests/adversarial.rs` | TEST-PROVEN | verified |
| F3 | 8 mutations of a live package refused by a separate verifier process | `ghost-demo/tests/live_nexora.rs::g14_05` | EXECUTION-PROVEN | verified |
| G1 | Three-process live reference reaches `VERIFIED_EXECUTION` | `aip-edge/tests/end_to_end.rs`; `LINUX_EDGE_REFERENCE.md` | EXECUTION-PROVEN | verified |
| G2 | Process instance is `(pid, pid_start_time_ticks, boot_id)` | `aip-types` `ProcessInstance`; `INVENTION_REGISTER.md` IR-06 | CODE-PROVEN | verified |
| H1 | 10 adversarial scenarios executed, 10 passed | `AIRI_REAL_WORLD_VALIDATION.md` §9–10; `validation/reports/AIRI_VALIDATION_MATRIX.{csv,json}` | EXECUTION-PROVEN | verified |
| H2 | `REAL_WORLD_VALIDATION_PROVEN` is **withheld** | same document, §10 acceptance table | DOCUMENTED | verified — deliberately not claimed |
| I1 | 2 of 11 UAS telemetry sources can produce an `ObservationRecord` | `UAS_ACCOUNTABILITY_PROFILE.md` §4; ADR-005 | CODE-PROVEN | verified |
| I2 | No UAS quantity reaches `Proven` under any declared source set | same, §5 | CODE-PROVEN | verified |
| J1 | `unobserved_boundaries_to_outcome() == 5` | `ROBOTICS_ACCOUNTABILITY_PROFILE.md` §3 | CODE-PROVEN | verified |
| J2 | Onboard sources capped at `Corroborative`; agreement does not raise the ceiling | same, §4, §10 (`ceiling_after_agreement`) | CODE-PROVEN | verified |
| J3 | The live robotics run proves the companion computer, not the machine | same, §11 | EXECUTION-PROVEN | verified — scope explicitly stated in the profile |
| K1 | **No robot was involved** | same, §12.6 | DOCUMENTED | verified — quoted verbatim |
| L1 | `effect_establishable()` is false for all nine safety responses | same, §9 | CODE-PROVEN | verified |
| M1 | Hardware attestation is **PROPOSED**, not implemented | `docs/architecture/ADR-002-HARDWARE-ATTESTATION.md`; `INVENTION_REGISTER.md` IR-04 | DOCUMENTED | verified |
| N1 | TLS, rate limiting, KMS/HSM, backups, DR/BCP, metrics, runbook are open | `docs/PRODUCTION_READINESS.md` | DOCUMENTED | verified |
| N2 | CI runs fmt/clippy/test/`cargo audit`/`cargo deny`; security workflow runs gitleaks and trivy | `.github/workflows/{ci,security,release}.yml` | CODE-PROVEN | verified |
| O1 | A3S Observer 0.11.0 (`06105bb`, MIT) built from source and run as an independent witness | `validation/external/a3s_observer/STATUS.md`; `AIRI_REAL_WORLD_VALIDATION.md` §2–3 | EXTERNAL-CORROBORATED | verified |
| O2 | **No third-party security assessment has been performed** | `docs/PRODUCTION_READINESS.md` (listed as a pre-deployment blocker) | DOCUMENTED | verified |

---

## 3. TRL claims

Every TRL figure in the addendum is an **engineering assessment**, not a
certification. No certifying body has assessed this programme.

| claim | supporting evidence | status |
|---|---|---|
| Overall ≈ TRL 5 | rows D1, E1–E2, G1, H1 above (validation in a relevant environment for *software* autonomy) | asserted as an assessment |
| Software core ≈ TRL 5 approaching 6 | rows C1–C3, D1, E2, H1; gap to 6 is a non-synthetic agent under load (row H2) | asserted as an assessment |
| Linux runtime ≈ TRL 5 | rows D1, G1; single host / single kernel | asserted as an assessment |
| Observation-integrity mechanism ≈ TRL 5 | rows E1–E7; not exercised outside the reproduction environment | asserted as an assessment |
| NEXORA ≈ TRL 5 | rows F1–F3; no external verifier deployment | asserted as an assessment |
| UAS ≈ TRL 4 | rows I1–I2; no PX4, no SITL, no airframe | asserted as an assessment |
| Robotics ≈ TRL 4 | rows J1–J3; no hardware | asserted as an assessment |
| Physical accountability ≈ TRL 2–3 | rows K1, L1, M1 — nothing physical observed | asserted as an assessment |
| Integrated product ≈ TRL 4–5 | the software chain runs end to end; the physical half does not exist | asserted as an assessment |
| **Not TRL 6/7/8/9** | row N1 (no operational deployment), row O2 (no independent assessment), row K1 (no physical validation) | asserted, with the disqualifying evidence named |

---

## 4. Commercial, IP and valuation claims

| claim | source | evidence type | status |
|---|---|---|---|
| USD 10M Pre-Series A | operator direction, recorded in the addendum | **TARGET** | **not committed capital; no term sheet, no indication of interest evidenced** |
| Illustrative next round USD 8–10M at USD 40–60M pre-money | operator direction | **PLANNING ASSUMPTION** | **illustrative; contingent on milestone evidence** |
| ₹30–50+ Cr engineering/technology reference range | operator direction | **INTERNAL PLANNING RANGE** | **not a third-party valuation or fairness opinion** |
| ₹30–35 Cr pre-money target; ₹25 Cr floor; ₹40 Cr+ strategic premium | operator direction | **INTERNAL PLANNING RANGE** | same |
| ₹50–80 / ₹75–120 / ₹150+ / ₹300+ Cr milestone ladder | operator direction | **INTERNAL PLANNING RANGE** | same; each rung is gated on named evidence that does not yet exist |
| Two pending Indian patent applications | operator statement; `reports_and_patents/PATENT_DOSSIER_CCVL_AIP.md` maps to application 2 | **PENDING APPLICATION** | **No filing receipt, application number or filing date appears in the repository.** No dossier for application 1 (hardware monitoring / physical containment) was located |
| Repository states provisional filings exist re: delegation-bound audit binding | `README.md`; `docs/idex_open_challenge/04_INNOVATION_AND_IP.md` | DOCUMENTED | verified as a repository assertion; not independently confirmed |
| Patent subject matter is **not** implemented in current code | `docs/IP/INVENTION_REGISTER.md` closing section | CODE-PROVEN | verified — PQC, hardware-backed key storage, kernel-resident eBPF/XDP sensing and field deployment are all absent |
| Copyright owner recorded as K. NAGA SRI GANESH | `README.md`; commit `6c407d0` | DOCUMENTED | verified as a repository record; the corporate relationship to the Vanian entity is not asserted here |
| No defence deployment exists | absence of any such evidence in the repository | UNKNOWN → treated as **not demonstrated** | no pilot, trial or contract evidenced |
| No customer exists | same | **TARGET MARKET, not customer** | explicitly not converted |

---

## 5. The 32-failure first run, recorded rather than omitted

All 32 failures in the first `cargo test --workspace` run panicked at
`aip-standalone/aip-edge/tests/common/mod.rs:58` with:

> `reference transport: aip-edge-observer was not found next to … ; build it
> with 'cargo build -p aip-edge-observer'`

They span `aip-edge` (`adversarial`, `end_to_end`, `lifecycle`, `nexora`) and
the effect/observation suites that use the same reference transport. After
`cargo build -p aip-edge-observer -p aip-edge-workload`, the full suite passed
1,691 / 0.

**Classification: not a product defect; a test-harness ordering sensitivity.**
It is recorded because (a) the forensic audit's own rule is that findings are
not lost, and (b) a live-kernel suite whose result depends on build ordering is
a CI maturity item, listed in the addendum at §P.3.13.

---

## 6. Forensic-audit findings: status at `12767ea`

**The original findings are not altered.** This table records subsequent work
against them, and its authority is the repository's own reconciliation document
plus the spot checks named beside each row.

| audit ID | original finding | status at `12767ea` | evidence |
|---|---|---|---|
| B-1 | verifier had no clock | **CLOSED in `aip-protocol`** (R16) | `FINAL_AUDIT_RECONCILIATION.md` P0-1; DOCUMENTED + TEST-PROVEN |
| B-1a | `aip-service` supplied no verification time | **CLOSED** — `evidence.rs:430` sets `ctx.verification_time_ms = Some(req.verification_time_ms.unwrap_or_else(now_ms))`, so **omitting the field now means "apply the bound the service knows", not "apply no bound"** | CODE-PROVEN; `aip-service/tests/temporal_bound.rs` ran and passed in §0 |
| B-2 | delegation issuer unbound to previous grantee | **CLOSED, unconditional** | `FINAL_AUDIT_RECONCILIATION.md` P0-2 |
| — | (new) chain verified from an unauthenticated root | **CLOSED** — found by the programme itself | `FINAL_AUDIT_RECONCILIATION.md` P0-3 |
| B-3 | containment unreachable from engine output | **ACCEPTED / JUSTIFIED** — a design decision was taken and recorded, not a silent fix | `FINAL_AUDIT_RECONCILIATION.md` §13 |
| B-4 | bundle verified against a self-supplied key | **PARTIALLY ADDRESSED** — reframed as a container-integrity check; **the signer's identity is still unanchored** | `FINAL_AUDIT_RECONCILIATION.md` bundle section; carried forward in the addendum §P.2.9 |
| B-5 | private keys written with default permissions | **PARTIALLY FIXED** — `aip-core/src/store.rs:362-367` sets mode `0o600` via `PermissionsExt`; a passphrase-wrapped key backend exists (`WrappedFileCustodian`); **the plaintext backend still stores a base64 seed at rest, and no KMS/HSM is used** | CODE-PROVEN |
| B-6 | service mints a new identity on an unreadable key | **CLOSED** — `keys.rs::load_or_create_plaintext` creates a key **only when the file is absent**; an existing file that fails `check_secret_file`, base64 decoding, or the 32-byte length check returns `Err(CustodyError)` rather than regenerating. `ServiceKey::generate()` survives only in `development_key()` | CODE-PROVEN |
| B-7 | private seeds accepted in HTTP bodies | **still present by design in managed/dev mode**, with redacting `Debug` | CODE-PROVEN (grep) |
| B-8 | packet replay undetected | `aip-service/tests/replay_ingest.rs` exists and passes; protocol-layer replay not re-verified here | partially addressed |
| B-9 | `Reconciliation` constructible outside the engine | **CLOSED** — `#[non_exhaustive]` with a crate-private `provenance` field | CODE-PROVEN (`result.rs:700,710`); `FINAL_AUDIT_RECONCILIATION.md` §14 |
| B-10 | `aip-service` in no workspace | **CLOSED** — one workspace root; service suites ran in the §0 command | CODE-PROVEN + EXECUTION-PROVEN |
| B-11 | observer-directed verdicts lack a structural precondition | not re-verified for this addendum | open unless shown otherwise |

**One row above is explicitly not re-verified** (B-11) and one is only
partially so (B-8). They are listed that way rather than assumed closed. The
absence of a finding from this table is not evidence that the corresponding
property holds — the same caveat the repository's own reconciliation document
carries.

---

## 7. What this source map does not establish

- That no further defects exist. Every row is a statement about one named
  property with one named source.
- That any repository document is correct merely because it is in the
  repository. Rows marked **DOCUMENTED** were not independently verified.
- That the validation host is representative. It is one kernel, one
  architecture, one machine, without `CONFIG_KPROBES`.
- That any commercial figure in §4 is anything other than an internal planning
  input.
