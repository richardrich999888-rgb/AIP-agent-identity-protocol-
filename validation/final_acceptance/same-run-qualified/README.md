# Corrected combined-source genuine profiles

Source: `9ed1662af95ce83bbbee69c9387d5bd638713575`, direct checkout (`direct-checkout.log`).
Workflow: https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/40854983596
Job123383585902: all steps succeeded.
Public artifact12888619380:1223840 ZIP bytes, GitHub-published SHA256 `2fdbaca4bc39acc5580e2ce7a497aa31f49c5e254ec40a597225b67e55b87c3c`. Individual original bytes are independently hashed in `originals/files.json`; the ZIP hash is provider metadata, not an independently recomputed ZIP digest.

| Profile | Actual run ID | Batches / events / health | Exact supported result |
| --- | --- | --- | --- |
| Observed | `same-run-2b87f14b39d1320c9d9c2b7e` | 37 / 1046 / 4 | Signed Active coverage encloses task; identity Match7, WithinWindow; CannotProve/ActionEvidenceUnavailable |
| Interrupted | `same-run-162f9a0599c3ebdbe5f04d2c` | 11 / 311 / 3 | Probe terminated before task; no task coverage/binding; CannotProve/WindowNotCovered, NoReference, Indeterminate |
| Fresh recovery | `same-run-e5dfb539bfaf22608e2c95c0` | 35 / 1062 / 4 | Fresh trust/capture; signed Active task coverage, identity Match7, WithinWindow; CannotProve/ActionEvidenceUnavailable |

Each genuine task used two actual local-model calls and one approved read-only tool invocation on synthetic documents. Each profile retained one Forwarded and one parameter-mismatch Refused signed receipt. Authorization, archive integrity, external checkpoint and signed reconciliation verify; gateway comparison agrees without upgrading the kernel action verdict. Final signed health seals the final batch in each profile. Cleanup error lists are empty.

All ten API/SDK/MCP/browser and role/tenant checks in each profile passed, and each client progress record reached COMPLETE. Exact run/artifact/bundle hashes are in each original `enterprise-clients.json`. The pinned browser asserted exact rendered JSON and captured the retained screenshot. No newer local browser, fixture tool response or simulated kernel evidence substituted for these runs.

Independent native re-verification of all originals under separately retained parent public trust/checkpoints passes, reproduces each original evaluation exactly, and reconstructs agent/tool process bindings from signed kernel records. Mutation controls remain refused under those external checkpoints. The repeatable tracked-gzip verifier and exact commands are in `verification/`. `originals/files.json` records original paths, sizes, hashes and deterministic gzip restoration; original signed contents and verdicts are unchanged.

**Custody remains BLOCKED.** Probe and collector share root in this hosted profile, so collector key inaccessibility from the probe is not enforced. These are ephemeral CI operator anchors, not institutionally approved authority. See `../infrastructure/probe-key-boundary.md`. Mathematical verification and software-path success cannot establish independent administration, logical subagent attribution, complete unseen action execution, financial settlement or bank acceptance.

Earlier successful42d profiles and later failed ba8417e browser records remain separately retained. They are never mixed into this source's run evidence.
