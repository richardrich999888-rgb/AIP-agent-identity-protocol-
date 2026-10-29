# Genuine combined-source run

Candidate: `42d0d96c9cc9d3075c792a195cc74e4171b0e817`, checked out directly, not a synthetic merge (`direct-checkout.log`).
Workflow: https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/40850559136
Job: `123368675522`, all execution steps succeeded.
Public artifact: `12887496072`, `same-run-evidence-40850559136`, 1,216,398 ZIP bytes; GitHub-published ZIP SHA256 `d5773c236c73451f40dc0350e769786dc628aec381bfc53c64574cb16f765cb9`. This ZIP digest is provider metadata; retained individual original bytes are independently hashed in `originals/files.json`.

| Profile | Run ID | Batches / events / health | Actual task | Coverage / verdict |
| --- | --- | --- | --- | --- |
| Observed | `same-run-ccc66ce5081bd888d786e371` | 34 / 1011 / 3 | Two genuine local-model calls, one actual approved read-only tool call | Signed Active coverage encloses task; `CannotProve`, `ActionEvidenceUnavailable`, identity `Match(7)`, temporal `WithinWindow` |
| Interruption | `same-run-b912e08ee557fc7be6515008` | 9 / 283 / 3 | Probe terminated before a fresh genuine agent; two model calls and one actual tool call | No task coverage or process binding; `CannotProve`, `WindowNotCovered`, `NoReference`, `Indeterminate`; no backfill |
| Fresh recovery | `same-run-2756716e614d0bdca038bb3b` | 34 / 1045 / 4 | Fresh trust/capture epoch; two model calls and one actual tool call | Signed Active coverage encloses task; `CannotProve`, `ActionEvidenceUnavailable`, identity `Match(7)`, temporal `WithinWindow` |

Every profile has independently issued valid authorization, one signed `Forwarded` receipt and one signed controlled-parameter-mismatch `Refused` receipt. Gateway comparison is `Agrees`; this does not upgrade the kernel action verdict. The exact nested availability field remains unchanged in retained evaluations; use the top-level reconciliation reason for the distinctions above.

All three profiles passed exact-bundle API admission/retrieval, Python SDK, compiled TypeScript SDK, official restricted MCP client, OpenAPI, cross-tenant refusal, Reader write/raw refusal, signed runtime verdict retrieval and actual browser console checks. Each retained `enterprise-clients.json` identifies its own run, artifact and exact bundle hash. Screenshots are from these genuine profiles. Cleanup errors are empty in all three manifests.

The existing native archive verifier and execution-assurance evaluator were rerun independently on these exact originals under the separately retained parent public anchors, checkpoints and run trust. The derived verification directory retains the commands and results. Embedded bundle keys were not substituted as trust. Seven archive mutations per profile were refused under the external checkpoint; prefix/suffix truncation need that checkpoint even when the remaining signatures individually verify.

`originals/` contains only the workflow's explicitly public artifact paths. Files larger than 64 KiB with JSON/JSONL suffixes are losslessly compressed with deterministic gzip metadata. Decompress to a temporary directory before using the original verifier commands. `files.json` names every original/retained file, its original byte size, original SHA256 and compression. Signed contents, task windows, scope, health records and original verdicts were not rewritten. Parent public anchors/checkpoints remain outside each `public/run-bundle.json`.

These are ephemeral CI controller-approved software anchors, not institutionally approved keys. Signing custody is local UID isolation on a shared kernel/root. Process-instance binding is supported; logical subagent attribution, invisible application parameters, complete action execution, financial settlement, separate administration and independent bank acceptance are not established. All loan documents are synthetic; no bank transaction or cloud-model credential was used.
