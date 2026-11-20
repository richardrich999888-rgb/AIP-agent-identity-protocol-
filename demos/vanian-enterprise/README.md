# VANIAN enterprise lab (item 6.1a)

The commands are run from this directory, as root, on a Linux host. Tools
and run outputs go into `.lab/` (git-ignored), or `$VANIAN_LAB_DIR`.

| Script | Does |
|---|---|
| `check.sh` | Preflight. Reports root, cargo, go, python ≥ 3.11, unshare, tracefs, docker, CAP_SYS_RESOURCE, and whether the tools are built. Changes nothing. Exits 1 if a required item is missing. |
| `setup.sh` | Mounts tracefs if absent. Builds the release `aip-probe`, `aip-collector` and `aip-observe-verify`. Builds OPA `v1.22.4` and **checks its module hash against the pin**. Creates the LiteLLM venv from `research/oss/litellm/requirements-core.lock.txt`, and **fails if `litellm_enterprise` is present**. |
| `test.sh` | Runs every suite the lab depends on: the Rego policy, the command-center server suite (offline in a netns, with live OPA, verifier and LiteLLM; **a SKIPPED test fails it**), the LiteLLM acceptance (offline), `revocation_gap` and `live_sensors`. |
| `run.sh` | The live part that exists on this branch: the observer-kill run (3.4b). |
| `verify.sh` | Reports each of the 12 capabilities as VERIFIED / PARTIAL / NOT_AVAILABLE / NOT_IMPLEMENTED / FAIL from the latest test and run outputs. **Exits 0 only if all 12 are VERIFIED.** |
| `reset.sh` | Stops lab processes and deletes run outputs. Keeps the tools. |
| `compose.yaml` | The mock model as a service, on a digest-pinned image, for real hosts. OPA and LiteLLM are deliberately not services: see the comments in the file. |

Order: `./check.sh && ./setup.sh && ./test.sh && ./run.sh && ./verify.sh`.

The recorded run on 21 Nov 2026 in the cloud session container, with
outputs in `docs/enterprise-wow/evidence/6.1a/`:

- `setup.sh` exit 0 (about 1 min, with a warm cargo cache);
- `test.sh`: 5/5 suites PASS;
- `run.sh`: 7/7 checks;
- `verify.sh`: **0/12 VERIFIED, 0 FAIL, exit 1**. Five are NOT_AVAILABLE
  (P0-059), two NOT_IMPLEMENTED and five PARTIAL.

The scripts do not hide that exit 1. It is the true state of this branch.

The native fallback for the mock model is:
`python3 research/oss/litellm/mock_openai.py 8900`.

Not here yet (6.1b): `RECORDING_GUIDE.md` and `NARRATION.md`, which belong
to the recording (7.2), and verify coverage of capabilities 1–5, 7 and 9,
which needs P0-059 and the gateway.
