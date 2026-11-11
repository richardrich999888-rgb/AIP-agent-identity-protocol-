# Buyer evidence pack — bounded current claims

**P0-049 release status: NOT READY.** Use this with the completion matrix and
independent-verification guide. This is a pointer pack, not a distributable kit.

| Claim | Inspectable evidence | Limit |
|---|---|---|
| AIRON can validate a bounded capability against independent signed test cases | C1 code, 14 targeted tests, `evidence/p0-049-iteration-1/scoreboard/` | Synthetic engineer-generated tests; not external expert approval |
| A failing capability remains visibly rejected | Transformer `val-09` stays 11/12 and exit 3; failed input/trace/review questions retained | Known failure is demonstrated, not fixed by this iteration |
| Passing homework cannot activate a rule | CLI test attempts activation after scoreboard success and is refused | Full authenticated teaching approval experience remains incomplete |
| Model-free capability testing | Recorder uses no model paths; zero calls; unavailable model binaries in CLI test | Does not prove model-assisted drafting or full offline installation |
| Bounded results reproduce on a separate runner | Clean source and CI merge trees match; same capability hashes/outcomes; `scoreboard-ci/` | CI is connected; measurements remain separate; no external-evaluator acceptance |
| Suite signatures can be checked independently of the Rust runtime | `verify_suite_signatures.py`; six suites verified; altered label refused | Synthetic test-key trust only; unsigned diagnostics are not authenticated by this check |
| Retained observer records can be cryptographically verified | Reverified 7 batches/86 events/1 health record; tampered copy rejected | Health is ContinuityUnverified; no complete-coverage or new live-sensor claim |
| Historical offline inference exists | W `demos/pull-the-plug/evidence/2026-11-08-64d6f40-*` | Not remeasured here; complete bundle and independent-host proof absent |
| PQ Overlay and Quantum X-ray underlying source exists | Accessible OVERLAY base `eccb668` | Original demo commits unavailable; PQ is a PROOF OF CONCEPT |

Existing W buyer material remains at `docs/demos/buyer-pack/` on `6ad92ae`:
security notes, questionnaire, one-machine sizing and `demos/evidence-pack/out/`.
Do not broaden those SBOM/AIBOM/CBOM scopes to an expanded kit that has not been
built. Its AIBOM describes a scripted test agent, and binary scanning is not a
complete algorithm inventory. Full dependency/licence manifests for the final
distribution remain required; no new product licensing decision is made here.

Draft delivery is [PR #21](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/pull/21),
implementation `84d889f`. The scoreboard CI passes; existing Trivy findings and
the initial SQLite dependency advisory failed security/supply-chain gates.
Iteration 2 (`9e3909e`) updates SQLite/rustix and preserves audit failure exits;
local checks now pass, with old-database access restrictions verified. Trivy
findings and final remote CI reconciliation remain open. See the final report and
retained scanner output. This evidence does not support a claim
that the complete repository's CI is green.

No TRL promotion, certification, autonomous learning, security accreditation,
production readiness, universal agent coverage or guaranteed three-minute runtime
is asserted by this evidence pack.
