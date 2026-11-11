# P0-048-A iteration 001 evidence

Review date: 12 November 2026 (Asia/Kolkata); host command timestamps use UTC.
Source: `4d0ce1e32c8dedde4e3a930abc2becf1f56b864e`.
This directory contains **audit/portable-test evidence**, not a new signed
execution capture. It does not close P0-048-B through L.

## Provenance

- `revisions.json`: all 37 advertised branch heads captured after fetching.
- `inventory.json`: deterministic structural inventory for ten relevant trees;
  Git object IDs, SHA-256, dependency declarations, workflow/build references.
  Identical parsed blobs are stored once under `configuration_objects`.
- `ancestry.json`: exact revision ancestor relationships, not assumptions from
  branch names. All six requested branches and seven PR heads are covered.
- `provider-review.json`: original public PR metadata and PR-triggered workflow
  API results; baseline CI jobs and newer Security job failures.
- `additional-ci.json`: runtime/demo-head workflow query results. Empty
  PR-triggered lookup is not a global assertion about all workflow triggers.
- `checks.json`, `python-*.log`: fresh commands, environment versions, return
  codes, successful runs, prior failed invocations and blocked commands.
- `inventory-check.json`: reproducibility, source links and rehashed retained
  original bytes. Hash success is not a fresh signature or origin verification.
- `SHA256SUMS`: local content identity for this iteration's evidence files,
  excluding itself. It is not an independently signed release approval.

## Exact acquisition and reproduction commands

Run from the repository root. The initial clone was made with
`git clone --no-checkout https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-.git vanian`.
An earlier mirror-host attempt could not authenticate and was not used.

```sh
git fetch origin '+refs/heads/*:refs/remotes/origin/*'
git checkout -b codex/p0-048-snifferdog-enterprise-assurance origin/fix/vanian-end-to-end-green
python3 validation/p0_048/inventory.py --refs-only > validation/p0_048/iteration-001/revisions.json
python3 validation/p0_048/inventory.py --revisions validation/p0_048/iteration-001/revisions.json > validation/p0_048/iteration-001/inventory.json
python3 validation/p0_048/check_inventory.py > validation/p0_048/iteration-001/inventory-check.json
python3 -m py_compile validation/p0_048/inventory.py validation/p0_048/check_inventory.py
git diff --check
```

For reproduction, use the committed revisions file; do not overwrite it with
new branch heads. Run output comparison in a new temporary location if
preserving the committed audit artifacts. Both scripts are stdlib-only and
read Git objects/files without installing or running product code.

GitHub connector operations: `get_repo`, `get_pr_info` for
`[8,9,11,12,16,17,19]`, `fetch_commit_workflow_runs` for each exact head plus
runtime/demo heads, and `fetch_workflow_run_jobs` for runs `40858045183`,
`41513004226`, `42360677570`. Arguments and returned IDs/refs are recoverable
from the JSON. These are observations of historical CI, not new executions.

## Fresh portable tests

```sh
PYTHONPATH=validation/enterprise:integrations/interoperability/src python3 -m unittest -v validation.enterprise.test_combined_contracts validation.enterprise.test_packaging validation.interoperability.test_spire_cli
PYTHONPATH=validation/enterprise:integrations/interoperability/src python3 -m unittest -v validation.enterprise.test_agent_harness validation.enterprise.same_run_controls_test validation.enterprise.test_sql_provisioning
```

| Check | Actual result | Scope |
|---|---|---|
| First final command (`python-3.log`) | 28 passed, no skipped | Combined console/API contracts; packaging mutation/path/config negatives; mocked SPIRE CLI parsing/readiness and diagnostic non-disclosure |
| Second final command (`python-4.log`) | 15 passed, no skipped | Agent-harness/model-provenance negative fixtures and SQL schema parity |
| Earlier invocations (`python-1.log`, `python-2.log`) | FAILED with import errors | `PYTHONPATH` omitted `validation/enterprise`, so imports of `openapi_contract` / `prepare_local_model` failed. Corrected invocation only; no source/assertion change. These attempts are not added to final test totals. |
| `cargo test --workspace --locked --offline` | BLOCKED before execution | `cargo`/`rustc` absent. No fresh native suite, formatting, Clippy, crypto verifier or sensor test claim. |
| `python3 -m pytest -q integrations/interoperability/tests` | BLOCKED before collection | pytest absent. Existing installed JWT/crypto libraries do not supply a test runner. |
| Audit inventory reproduction and independent byte checks | PASS | Ten trees; 1,291 configuration references / 199 distinct blobs, 160 local report links, and 131 historical original files. See `inventory-check.json`; hashes do not establish signatures or observation truth. |
| Python syntax and Git whitespace checks | PASS | Audit scripts compile; staged content has no whitespace errors. These are not Rust formatting/Clippy or semantic security analysis. |

The existing Python environment was used; its installed dependency versions
are recorded in `checks.json`. This is not a clean locked-environment install
test. Packaging tests use deliberately small fixture ELF files, not native
release binaries. No new adversarial product test was needed for a source fix,
because this iteration changes no production code. Existing portable negative
tests were rerun without modifying them.

## Historical acceptance evidence remains scoped

The baseline's final matrix has 11 scoped PASS and four BLOCKED gates.
The new hash check reads original (decompressed where necessary) bytes from
`validation/final_acceptance/same-run-qualified/originals/files.json` and checks
the recorded hashes/sizes. It neither re-signs nor repairs anything. Original
positive/recovery verdicts remain `CannotProve / ActionEvidenceUnavailable`;
interruption remains `CannotProve / WindowNotCovered`.

Independent signing custody, clean host/systemd install, separate
administration and bank acceptance remain blocked. No claim about production
customers, certification, regulator approval or all-framework success is made.
The old wow-demo ten-rehearsal summaries do not replace their missing full
signed archives. No sensor, firewall, systemd unit or enforcement was activated.

## Publication

Only the requested feature branch and a draft PR against
`fix/vanian-end-to-end-green` are authorized for this iteration. Main and
production settings remain unchanged. CI observed after publication must be
reported separately from the baseline and these local tests; unstarted/queued,
skipped or blocked checks are never counted as passes.
