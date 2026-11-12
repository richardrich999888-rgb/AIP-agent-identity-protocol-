# P0-051 open acceptance requirements

**NOT READY.** Bounded component passes do not satisfy release acceptance. The
[release matrix](P0-051-RELEASE-GAP-MATRIX.md) is the requirement-level ledger.

| Priority / phase | Precise unfinished gate | Required next evidence or dependency |
|---|---|---|
| P0 correctness | Sandbox probe-to-launch race, executable TOCTOU, filesystem/resource isolation | Per-execution setup/launch acknowledgement and supported-host adversarial evidence; preserve CANNOT_PROVE |
| P0 security CI | Four HIGH Trivy findings in retained historical Helm output; main CI must be reconciled | Review actual supported deployment privileges and fix/qualify them without rewriting original evidence, suppressing findings or disabling sensors |
| A / C1 | Session examples have binary labels; capabilities have multiple outcomes. No reviewed mapping exists | Explicit reviewed outcome mapping, separate example results, positive/negative/mutation tests; no guessed labels. TXT integration passes; PDF/DOCX extraction-to-corpus binding remains open |
| A / C2 | Complete signed expert authority is not implemented end-to-end | Tenant/expert/capability/version/source/suite/scope/time/trust-anchor binding; forged/wrong/expired/revoked authority rejection |
| A / lifecycle | Authenticated activation, supersession, safe rollback and revocation across all entry points | No unvalidated/unapproved active state; atomic failure handling; reject unauthorized activation and rollback below policy floor |
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
