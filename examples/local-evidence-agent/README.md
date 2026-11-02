# VANIAN local evidence assistant

A local Q&A agent built with LangChain's chat-model and tool interfaces and a
LangGraph workflow. It runs the public Apache-2.0 Qwen2.5-1.5B-Instruct model
from Hugging Face on this Mac, reads the existing authenticated AIP API, and
answers questions about signed execution records. The model identifies the question’s evidence focus; a declared mapping selects
the corresponding API fact group. The browser renders its exact wording alongside
mandatory evidence limits and the actual tool-call trace. This is explicitly
labelled extractive Q&A, not freely generated explanatory prose.

## Start the demo

From the repository root:

```sh
./examples/local-evidence-agent/run.sh
```

Open **http://127.0.0.1:18765**. Stop the foreground launcher with Control-C.
The launcher stops only its own API and model processes. It refuses occupied
ports instead of taking over another service. Default ports are 18765 for the
screen, 18880 for AIP and 11436 for the isolated model endpoint; `--port`,
`--api-port` and `--model-port` override them.

The initial setup needs networking to download pinned public packages and model
weights. After preparation, ordinary runs reuse those local assets. The script
checks them again before use; an already built checkout can start directly:

```sh
/private/tmp/vanian-local-evidence-agent-assets/venv/bin/python \
  examples/local-evidence-agent/demo.py
```

This tested profile requires macOS arm64, Python 3.12, the Rust toolchain and the
reviewed Ollama 0.40.11 executable at `/usr/local/bin/ollama`. The executable's
hash, Hugging Face revision, weight hash, license and dependencies are pinned
in `model.lock.json` and `requirements.lock`. A different platform or executable
needs a reviewed configuration; a version string alone does not bypass the pin.
Assets occupy about 1.2 GB plus the Python environment. Set `VANIAN_DEMO_ASSETS`
for the launcher, or `--assets` for `demo.py`, to use another prepared folder.
The serving default uses a 4,096-token context; the agent explicitly requests
8,192 context tokens and at most 512 output tokens at temperature zero.
No model API credential is required. User Ollama models and account files are
not used. Private API state lives under the ignored `.local/evidence-agent/`.

## A short demonstration

1. Select **Observed Linux task** and ask: “Explain what this run verifies and
   why the kernel action is CannotProve.”
2. Expand the tool trace to show the real Reader API calls and the two local
   model responses. Inspect the model’s selected focus, its mapped facts and the limits always included.
3. Select **Interrupted Linux observer** and ask why coverage is unavailable.
4. Select **Recovered Linux observer** and inspect its preserved signature and
   action-proof findings. Ask whether these records prove a loan was approved.

The agent can choose between listing the known recorded runs and inspecting a
specific run. The screen selects a particular record. Every completed answer
requires two actual, uncached local model responses and real read-only API
calls. A malformed tool request or invalid fact selection is refused. There is no
answer if the model or API fails. Wording comes from API-derived facts as part
of the declared extractive design, not a hidden fallback for failed inference.

## What is live and what is recorded

The model, LangChain/LangGraph workflow, API authorization, API recomputation
and browser interaction run locally. The API imports the exact preserved Linux
records from the committed `3e6c179` governance run after the existing Rust
verifier checks their signatures, checkpoints and reconciliation. The three
profiles are observed execution, observer interruption and fresh recovery.
Their IDs, source revision and original workflow are visible in the public
catalog. Historical timestamps and original evidence remain unchanged.

The Mac session does not produce a new Sniffer Dog Linux kernel capture. The
agent's API-read trace and model timing statistics are application records.
Existing `CannotProve`, `ActionEvidenceUnavailable` and `WindowNotCovered`
findings retain their meanings. Verified signatures do not establish loan
approval, file contents, independent collector administration or a business
outcome. The model classifies the question’s evidence focus; it does not author proof claims. Earlier real
free-form answer trials misinterpreted unknown outcomes and are retained in
the validation history. The final extractive design prevents those generated
claims by limiting output to an evidence-focus identifier, validating it, and
rendering the corresponding declared group of API-derived facts. The original
model focus, host mapping and mandatory limits are separately visible. It is a bounded evidence assistant, not
a general-purpose chatbot or a general prompt-injection defense.

The agent receives only an ephemeral Reader credential. Bootstrap uses a
separate machine credential. Actual startup checks exercise anonymous refusal,
Reader write/raw-bundle refusal and cross-tenant refusal. API, model and screen
bind only to loopback. No network proxy or LangSmith tracing receives questions
or credentials. The demo is a trusted local process, without a separate OS
security boundary against the machine's owner.

## Reproduce validation

```sh
VANIAN_LOCAL_AGENT_REQUIRE_API=1 \
VANIAN_MODEL_TEST_ASSETS=/private/tmp/vanian-local-evidence-agent-assets \
/private/tmp/vanian-local-evidence-agent-assets/venv/bin/python \
  -m unittest discover -s examples/local-evidence-agent -p '*test*.py' -v
```

With the demo running, execute genuine model/API cases and preserve every
answer in a new directory:

```sh
/private/tmp/vanian-local-evidence-agent-assets/venv/bin/python \
  examples/local-evidence-agent/validate_live.py --out /private/tmp/vanian-demo-new-check
```

The output directory must be new. Read the actual selections and answers as well as the
machine checks. Controlled model fixtures in the component suite are labelled
separately from real inference. Local validation does not close the wider
project's security-scan, independent-custody or customer-installation gates.

Upstream sources: [Qwen model and license](https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF),
[LangGraph tool workflow](https://docs.langchain.com/oss/python/langgraph/quickstart).

## Recorded local result

The final local run passed four genuine model/API questions, browser interaction
and all 32 local checks. The AIP package suite passed 139 tests with two
default-ignored. [Read the detailed results and retained failed attempts](results/20261102/REPORT.md).

## Fresh Linux observation

The existing **Genuine same-run execution assurance** workflow has a manual
`local_evidence_agent` input. When enabled, it prepares the exact Linux Qwen
runtime, runs this same assistant as a restricted user with only local model/API
access, and observes the actual execution with Sniffer Dog. It keeps the process
alive until all four answer-file paths have signed process-bound observations,
then checks the complete interval through process exit. All six configured
mechanisms must have signed Active coverage. The hold is an observation gate,
not a claim about ordinary application latency.

The original signed archives and public controller trust records are uploaded
as separate artifacts. A second runner verifies them with networking disabled.
Model outputs and their file hashes remain controller application records;
collector signatures cover kernel observations, not the meaning of an answer.
The three historical API inputs remain unchanged.

After retrieving and checking the exact workflow commit/artifact provenance,
verify the original public directory with its separately approved trust file:

```sh
python3 examples/local-evidence-agent/fresh_verify.py \
  --package /absolute/path/to/capture/public \
  --trust /absolute/path/to/controller-trust.json \
  --tools target/debug --output /absolute/path/to/new-offline-result.json
```

Start the Mac demo with the same two inputs to display the verified Linux run:

```sh
./examples/local-evidence-agent/run.sh \
  --fresh-evidence /absolute/path/to/capture/public \
  --fresh-trust /absolute/path/to/controller-trust.json
```

The trust file must be outside the public capture. It must come from the approved
controller/workflow, not an untrusted sender supplying both evidence and trust.
The demo rechecks originals before becoming ready; it never accepts an uploaded
JSON report as proof. Its fresh-capture panel is separate from the historical
API records. Observation API admission is not claimed, and the 512 KiB ingestion
limit is not enlarged or bypassed.

A disposable hosted Ubuntu runner supplies the initial privileged sensor test.
Independent collector administration/key custody, installed customer-host
operation and external acceptance still require their separate validation.

## Verified fresh Linux result

The same Qwen/LangChain/LangGraph assistant executed four real questions under
Sniffer Dog in [workflow 41508547378](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/41508547378).
The retained capture contains 93 signed batches, 3,372 kernel events and 56
events bound to the measured agent process, with all six sensor types covering
the full task. Separate network-disabled Linux verification and independent
Mac verification passed with identical reports. Eight model responses and
twelve Reader API reads are separately identified as controller application
records. [Results, originals, reproduction and remaining gates](results/linux-observation/REPORT.md).
