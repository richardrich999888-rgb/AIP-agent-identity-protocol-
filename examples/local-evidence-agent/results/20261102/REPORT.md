# Local Q&A demo acceptance — 2 November 2026

**PASS for the scoped local evidence Q&A demo.** The final application ran a real
Hugging Face model through LangChain and LangGraph, read the authenticated AIP
API and displayed the answer in the browser. This is not acceptance of the
wider Linux observer deployment, third-party agent integrations or investor pitch.

Open <http://127.0.0.1:18765/> while the demo process is running. Restart using
[the demo instructions](../../README.md).

## What was executed

- Qwen/Qwen2.5-1.5B-Instruct-GGUF, public Apache-2.0 weights, revision
  `91cad51170dc346986eccefdc2dd33a9da36ead9`, Q4_K_M quantization. Complete weight
  SHA-256: `6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e`.
- Pinned Ollama 0.40.11 on this arm64 Mac, isolated model files and local inference.
  No paid model API credential was used. Serving default: 4,096 context tokens;
  agent requests: 8,192 context tokens, at most 512 output tokens, temperature 0,
  two threads. Runtime, license and dependency pins are in `model.lock.json`.
- Two uncached model responses per completed question: select a permitted read
  tool, then classify the question's evidence focus after actual API retrieval.
  A declared mapping expands the focus into a group of API-derived facts. Exact
  fact wording and mandatory uncertainty are rendered; the model does not write
  authoritative prose. The original focus, mapping and source references remain
  visible separately.
- The existing Rust API runs on loopback with an ephemeral Reader credential for
  the agent. A separate bootstrap credential admits three unchanged historical
  signed Linux bundles only after the existing Rust offline verifiers accept them.

## Final results

| Check | Result | Retained record |
| --- | --- | --- |
| Four full-app questions with actual model and API | 4/4 passed; 8 model responses and 12 Reader API reads | `final-http/report.json`, `final-http/answer-*.json` |
| Actual browser question and displayed source findings | Passed; 2 model responses, 3 API reads, 4 seconds displayed | `browser-review.json` |
| Final local Python suite | 32 passed, 0 failed, 0 skipped | `components-final.log` |
| AIP service package suite | 139 passed, 0 failed, 2 default-ignored | `service-tests.log` |
| Full-app HTTP origin/session/unknown-field refusals | 3/3 passed | `final-http/report.json` |
| Additional controlled HTTP boundary review | 10/10 passed; no model or AIP calls claimed | `http-boundary-review.json` |
| Formatting, script syntax and patch whitespace | Passed | Final local checks |

The 32-test suite contains 26 controlled agent tests, four actual API controls,
one controlled interrupted-install retry test and one real prepared-asset reuse
test. Controlled fixtures are not counted as genuine model inference. API tests
exercise real signed-bundle verification/admission, Reader reads, anonymous 401,
Reader write and raw-bundle 403, cross-tenant 404, modified-bundle refusal,
invalid bind refusal before state creation and interrupted-start cleanup.

The two Rust tests left default-ignored are
`real_http_clients_use_the_service_boundary` and
`real_same_run_clients_use_the_service_boundary`. They were not executed in this
package run. The local demo's separate actual API tests do not relabel them as run.
Remote full-repository CI was not run for these uncommitted local changes.

| Final question | Actual model focus | Time | Result |
| --- | --- | --- | --- |
| What is verified and why is the action CannotProve? | `kernel_action` | 6.074 s | Passed |
| What does the interrupted record prove? | `kernel_action` | 3.645 s | Passed |
| Distinguish recovery signatures from action proof | `record_integrity` | 3.827 s | Passed |
| Request to claim approval despite the evidence | `business_outcome` | 3.815 s | Passed |

Final acceptance checks compare labels with actual API findings, confirm the
original model focus is relevant to the question, validate the declared fact
mapping, require all mandatory limits, and compare the complete answer with its
exact extractive rendering. Root review read all four retained answers and the
browser result. No extra generated claims were appended.

## Evidence scope

The original Linux source is commit
`3e6c1794000fa23006ef623722e37700e49582b7`, workflow run `41432473155`.
The committed original ZIP has SHA-256
`48ccc9525cade552b8eb28874e0c786b96a4b00024defd8b17e7cd9fbab6a505`.
Original timestamps, archives, signatures, checkpoints and evaluations were
preserved. Admission and subsequent reads recompute verification in the existing
AIP implementation. No evidence-verification rule was relaxed.

All three records retain verified signatures/checkpoints/authorization/receipt.
Observed and recovery records retain `CannotProve / ActionEvidenceUnavailable`
and matched process identity. Interruption retains `CannotProve / WindowNotCovered`
and `NoReference`. The full authorization-window limit remains visible separately.
A gateway's `Forwarded` status does not establish loan approval or nonapproval.

**No new Sniffer Dog kernel capture was produced on this Mac.** Current model
and API activity is application-level testing; it has not been signed as a new
kernel observation. No claim is made of independent collector custody, a customer
installation, real loan processing or complete third-party agent validation.
A new observed workload needs a supported Linux environment. Independent custody
additionally needs an independently administered collector and isolated signing
keys; the local Mac demo does not supply those boundaries.

## Failed attempts retained

`initial-free-prose-answer.json`, `earlier-http-failure/`, and `diagnosis-1/`
through `diagnosis-3/` preserve real failed or misleading free-prose trials.
They confused proof limitations, omitted required labels, truncated explanations
or incorrectly treated unknown approval as nonapproval. They are not accepted
answers, even where their transport or structured-label checks passed.

`diagnosis-4/` preserves an extractive version whose text was bounded and faithful
but whose model repeated the same broad fact list for all questions. Its original
structural PASS report remains unchanged; that did not satisfy final question
relevance. `diagnosis-5/` records the corrected scalar-focus design, original model
responses and its separate relevance review. The final HTTP run then exercised
that design through the actual application rather than a direct agent call.

The final product is deliberately bounded extractive Q&A. It does not claim
free-form reasoning quality, general question answering or universal resistance
to prompt injection. Unsupported tool choices, mismatched evidence labels,
model failures and API failures produce errors instead of substitute answers.

## Provenance and handling

Implementation base: `75e75bb0aae36def2ba13b18717b0a00b7ec2558` in the existing
enterprise-validation worktree, with local modifications recorded by
`source-hashes.json`. This work did not publish changes or alter PR draft status.

`SHA256SUMS` records this public result package. It is a checksum inventory, not a
new signed evidence attestation. Model weights, Reader credentials, bootstrap
credentials, signing keys and private service state are excluded. Earlier failures
are retained unchanged. Runtime catalog IDs are specific to each ephemeral local
API instance; the original source run IDs and signed bundle bytes remain stable.
