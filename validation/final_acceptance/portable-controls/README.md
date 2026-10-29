# Portable controls on the combined recovery source

Source commit: `3a5550560ff6d26ad1fd53964deb013fa207b8a0`.
The repository source hashes below were unchanged before and after the three
test suites, executed from 2026-10-29T09:31:39.993666Z to
2026-10-29T09:31:43.334655Z. Every suite returned exit code 0.

| Retained log | Tests | Result |
| --- | ---: | --- |
| `merged-model-cleanup.log` | 11 | PASS: model metadata/blob controls, runtime publication boundaries, actual read-only SQLite subprocess, bootstrap connection closure |
| `merged-spire.log` | 3 | PASS: pinned SPIRE response parsing and refusal of malformed/ambiguous tokens without echoing input |
| `merged-contracts.log` | 3 | PASS: deployment/run routes, console disconnect cleanup, compiled customer TypeScript client path/build ordering |
| `merged-policy-sanitization.log` | 2 | PASS: additional local behavior checks described below |

The first three suites ran with Python 3.12 from the local enterprise environment:

```sh
python3.12 -m unittest discover -s validation/enterprise -p same_run_controls_test.py -v
python3.12 -m unittest discover -s validation/interoperability -p test_spire_cli.py -v
python3.12 -m unittest discover -s validation/enterprise -p test_combined_contracts.py -v
```

The combined contract test additionally requires its existing PyYAML dependency
and Node.js. The retained logs record the exact interpreter path used.

The two additional local checks completed at 2026-10-29T09:31:55.161299Z. They
validated 256 generated disposable passwords for both agent and privileged
operator accounts by executing the exact `validate_user_password` and sequential
character methods from pinned ContextForge source
`ff6a566a4b5c098093db90bbb4d5df483e108026`, with its documented 12/22-character
defaults and original common-password set. This extracted-method check did not
initialize the gateway service or test password storage. A second check passed
fixed and Pydantic-style HTTP 422 bodies containing a synthetic sensitive-input
marker through the actual runner's `request(..., safe_error=True)` function:
only the fixed error classes were returned, without raw inputs. These were
ad hoc behavior checks, separate from the 17 repository regression tests.

## Tested source SHA-256

| Path | SHA-256 |
| --- | --- |
| `validation/enterprise/same_run_validation.py` | `30f2804023a91787c37bae9bab1241a2423c4f3ff1a210eea1d3dfb88752d722` |
| `validation/enterprise/same_run_controls_test.py` | `352efae229862264cc5fef708ab692c3d3faf0854cba07c6b68a59dae7b8aa76` |
| `validation/enterprise/prepare_local_model.py` | `520b02d0451ff477fef5191b27c6dca9708bc7a45624d62ff12351012525810e` |
| `validation/enterprise/test_combined_contracts.py` | `4d92cfac6f98ee895b6712c71c7fe39e49aef377ea459a1d417737f324163111` |
| `validation/interoperability/test_spire_cli.py` | `b04a2cc602a842153e53a18da11fb2d5857d39ba6a24dc4d5b9c8ebe4cb00748` |
| `.github/workflows/same-run-validation.yml` | `895f2f7256657a43c5e9ccb6f0b68f86bc28ed3bb6f6e049dc24f67158597649` |
| Pinned ContextForge `mcpgateway/services/password_policy_service.py` | `a47c3b85344afa71dcdeebc29799bb9fda264fc880aaa9f95b351d8af575e1f2` |

## Retained log integrity

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `merged-model-cleanup.log` | 2433 | `42089a3be564efb79a7c2a9da12cf2220e68477222fb50d7ac3bbf467df001b2` |
| `merged-spire.log` | 918 | `4199c987d3e1159257936b3457ce0c84ac6af594f3989cae9cf4a7b2bbfa4f05` |
| `merged-contracts.log` | 892 | `1f883e47e59783a4eef90fab2af9e298e1befe2ceafe301253f11cd34ed8c047` |
| `merged-policy-sanitization.log` | 991 | `9ced67685096676fd0f4392ea837c9ed4a2bd0e844ff56b344274e724595ea31` |

## Scope and limitations

- These checks ran locally on macOS. They do not establish a fresh genuine
  Linux model/authority/gateway/kernel/collector/API/client execution on this
  merged source, or satisfy that separate end-to-end acceptance gate.
- The SQLite bootstrap helper has one workload call and explicitly closes the
  connection after committing. Its portable regression checks connection
  closure and the two synthetic rows; it does not perform a Linux mount/unmount.
- The custody review preserves the runner's explicit
  `LOCAL_ISOLATION_SHARED_KERNEL_AND_ROOT` classification. Separate
  administrative custody and resistance to trusted host root remain incomplete.
- Public retention selects signed archives, public trust/checkpoints, receipts,
  synthetic results and fixed numeric probe diagnostics. The reviewed paths do
  not copy private key files, raw framework logs or process environments into
  public evidence. These logs contain no generated passwords or private keys.
- An unvalidated cleanup edge remains: diagnostic/archive/checkpoint retention
  in `finally` includes some I/O and JSON operations outside the per-step cleanup
  wrapper. A failure in those operations could prevent later cleanup steps or
  final manifest publication. No such failure was reproduced here; the portable
  bootstrap regression does not cover that exceptional path.
