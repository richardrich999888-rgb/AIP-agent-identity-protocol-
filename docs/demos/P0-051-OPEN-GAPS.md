# P0-051 open acceptance requirements

**NOT READY.** Bounded component passes do not satisfy release acceptance. The
[release matrix](P0-051-RELEASE-GAP-MATRIX.md) is the requirement-level ledger.

| Priority / phase | Precise unfinished gate | Required next evidence or dependency |
|---|---|---|
| P0 correctness | Sandbox probe-to-launch race, executable TOCTOU, filesystem/resource isolation | Per-execution setup/launch acknowledgement and supported-host adversarial evidence; preserve CANNOT_PROVE |
| P0 security CI | Four HIGH Trivy findings in retained historical Helm output; track current-head main CI separately | Review actual supported deployment privileges and fix/qualify them without rewriting original evidence, suppressing findings or disabling sensors |
| A / C1 | Explicit mapping and separate example validation now exist; full C1 remains partial | Bind the reviewed map digest into authenticated C2 authorization. Complete PDF/DOCX extraction-to-corpus binding and E1; no inferred labels or automatic activation |
| A / C2 | Complete signed expert authority is not implemented end-to-end | Tenant/expert/capability/version/source/suite/scope/time/trust-anchor binding; forged/wrong/expired/revoked authority rejection |
| A / lifecycle | Authenticated activation, supersession, safe rollback and revocation across all entry points | Cross-tenant/domain displacement fixed by `ee3850c`; complete authenticated actor/authority checks, no unvalidated/unapproved active state, atomic storage failure handling and rejection below the policy floor |
| B / W3.D5 | No accepted `syntriass pack export/verify/import` | Real signed synthetic `.pack`; offline separate-process verification; all specified integrity, authority, source, version, model, validation, replay/rollback tests; inactive import |
| C / D1–D6 | Live meter, variation experience, UI scope refusal, real model swap/revalidation, every-answer signed receipt | Staged verified models/runtime, measured calls/CPU/RSS/time/network; correct withholding and independent receipt verification |
| C / E1–E3 | Local teaching screen, login/roles/clearance, accessibility/errors | ASK/TEACH/QUESTIONS/TEST/APPROVE/USE/EXPORT/VERIFY; vendored assets; real auth; keyboard and failure-state acceptance |
| C / F1–F3 | Local REST/OpenAPI, MCP, Python/TypeScript examples | Actual authenticated offline interfaces preserving all teaching and evidence gates |
| C / G1–G4 | Six-act live workflow, second synthetic sector, twenty runs, offline capture | Complete preceding gates; motors/transformers are not two sectors; retain each failure and full signed output |
| D / observer | Final honest/liar/bypass/interruption/restart sequence not rerun here | Original signed archives; actual native effects, omitted agent log and independent audit; offline verifier and tamper refusal; supported kernels/load |
| D / independence | No separately administered collector/agent hosts and keys | Authorized distinct administrators/hosts/keys; no independence claim from a different process or same account |
| E / W4–W5 | Original six demo revisions unavailable; no accepted replacement | Accessible reviewed replacement source, real synthetic scan/CBOM/ranking/planted weaknesses; hybrid PQ transport, captures, identity/downgrade refusal, unchanged app hash and measured overhead; PROOF OF CONCEPT |
| F / payloads | Complete USB profiles are not built | All AIRON/observer/Overlay binaries, verified weights/inference, pinned dependencies, documents/UI/tools, public trust, launcher and provenance; no secrets |
| F / manifests | Final SBOM/AIBOM/CBOM/licence inventory and offline installer incomplete | Hash every component, verified pre-install integrity, ephemeral credentials and no installation downloads |
| F / install | No genuinely separate clean supported machine installation | Complete kit plus a distinct clean host; independent external network boundary compatible with the initial-netns sensor; packet captures and counters |
| G / investor | Exact Pull the Plug → Teach One Rule → Catch the Lying Agent not accepted | Live three-scene launch, measured duration; disclose overruns; visibly label recordings |
| H / customer modes | Banking, defence, manufacturing and healthcare whole modes not accepted | Synthetic data only; problem/behavior/evidence/boundary/limitations; NOT READY when a dependency is missing |
| I / W6.1/W6.3/W8.3 | One-command complete benchmark, second-machine results and sizing incomplete | Pinned datasets/model/binary/runtime, baseline/capability comparison, raw errors/limits and labelled hardware; no invented ranges |
| I / rehearsals | No final-release consecutive runs credited | Ten per required mode, twenty for W3; failure resets count; retain full evidence and failed attempts |
| J / evaluator | No independent final installation/live-demo reproduction | Hash/install/run/inspect/signature/tamper/citation/outcome/limitations/test checks on supported offline hardware |

OVERLAY git cloning returned `could not read Username`; authorized connector
inspection works, but does not supply the missing original commits. Recover only
from an authorized existing copy or implement a reviewed replacement with fresh
provenance. This iteration did neither.

No purchase, licence change, outreach, repository publication, destructive change,
production deployment or patent change is needed to continue the next bounded
software item. Independent host/evaluator access is a later external dependency;
it has not been silently replaced with a fresh directory or a connected CI VM.

## P0-051 iteration 4 — policy-bound approval

Source `00c06de1503785470a73a7a2f0890ad8f9c1ce84` adds optional strict expert
authority grants and v2 Ed25519 approvals. Approval/activation/rollback/use enforce
key, tenant/domain, scope/version, clearance, expiry and revocation. Policy removal
cannot downgrade a v2 approval. Native CLI rechecks source dependencies.

Local runtime **201 pass**, teaching Python **445 pass**; teaching CI **303 Rust /
267 focused Python pass** (overlapping counts). Holdout **12/12**, attacks **26/26**
including six nonactivation probes; rejected control remains **11/12**. Independent
verification of original local/offline/hosted signatures passes; six tamper controls
reject. Full evidence, commands, source/host hashes, CI and failed recorder attempts
are in [iteration 4](evidence/p0-051-iteration-4/README.md). Native policy setup is
in [APPROVAL-AUTHORITY.md](APPROVAL-AUTHORITY.md).

**NOT READY. C2 remains partial.** Actor/role strings do not authenticate operators;
C1 session/full-document/example-map approval binding, policy rollback resistance,
per-approval revocation and transactional writes remain open. Strict policy must
be explicitly configured; legacy mode is not C2-qualified. Packs, models, UI/API,
OVERLAY, clean-host installation and independent demo acceptance remain open.
No new qualifying rehearsal: the offline 33-test component run on this same host
counts as zero demos. No live investor runtime, second host or sensor qualification.

## Iteration 5 checkpoint — 13 November 2026

Source `2d3a22697acbdcf4c3343a70f130f841bd722491` prepares an **unsigned** teaching
review commitment only after fresh native signed-suite and example replay. It
binds full source, session, answers, example map, suite/trust, capability and
native results. Separate-process verification requires an external digest and
never authorizes activation. 472 local Python tests pass, including 27 new tests;
12/12 holdout and 26/26 adversarial (six nonactivation probes included) remain
passing, while the control remains rejected at 11/12. Counts overlap.

[Original inputs, replay, measurements and limitations](evidence/p0-051-iteration-5/README.md).
No qualifying rehearsal or clean-machine credit. Release **NOT READY**. Next:
bind this review digest into the expert approval signature and enforce fresh
replay at native approval. Existing native approval does not consume it yet.
