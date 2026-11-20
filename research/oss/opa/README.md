# OPA, pinned and smoke-tested (enterprise WOW loop, item 1.2)

## Pin and provenance

| Field | Value |
|---|---|
| Version | `v1.22.4`, commit `ba39415db4b3c90cd68942a74b3cc2223ec2b23c` (the same pin as `../survey.json`) |
| How obtained | `GOTOOLCHAIN=auto go install github.com/open-policy-agent/opa@v1.22.4`, through proxy.golang.org. The proxy's `.info` for v1.22.4 names that commit and `refs/tags/v1.22.4`. |
| Why not the release binary | github.com release downloads return 403 from this container. openpolicyagent.org downloads do not connect. |
| Checksum chain | The module hash embedded in the binary (`go version -m`) is `h1:/sKtqt7GVSvXQn1sML2PSzl8tD/mTHF2pzQC3x1CV8k=`. It equals the entry for `github.com/open-policy-agent/opa v1.22.4` in the public checksum database (`sum.golang.org/lookup`, record 71238748). The `go` command verifies every dependency against the same database. |
| Toolchain | go1.26.11 (`go.mod` requires 1.26.0; the host has 1.24.7, so `GOTOOLCHAIN=auto` fetched it, also checksum-verified). |
| Binary | SHA-256 `976c068bc6192e408b5ae16ec1f98479f42befe2c12bc3a10925a650dd57b0e1`, 59,880,479 bytes. **Not reproducible as a file hash:** it is a local build without release ldflags (`Build Commit` is empty in `opa version`), so it will not match the project's published release checksum. |
| Not committed | The binary and OPA's source. Only the policy, tests, script and results here are in git. |

## What was run

| Check | Command | Result |
|---|---|---|
| Format and strict compile | `opa fmt --diff policy/` and `opa check --strict policy/` | no diff; check ok |
| Policy unit tests | `opa test -v policy/*.rego` | **10/10 PASS** |
| Mutations | `mutations.txt`: four edits to the policy, each run against the same tests | each detected (M1 9 fail, M2–M4 1 fail each) |
| Live server | `./smoke.sh /path/to/opa` | 5/5 decisions as expected over HTTP; after stop, curl exit 7 (connection refused); exit 0. Output in `smoke-run.txt`. |
| OPA's own tests | `go test -count=1 ./v1/ast/... ./v1/rego/...` in the verified module source | 6 packages ok, 0 FAIL, 2 with no test files; exit 0. `upstream-tests.txt` |
| Default REST writes | see `default-write-check.txt` | unauthenticated data and policy writes accepted (finding below) |

The smoke policy (`policy/mcp_call.rego`) has the shape the demo's gateway
would ask for:

- default deny;
- an exact (agent, server, tool) allowlist, with no prefix match;
- revocation overrides the allowlist;
- malformed input is refused with a reason.

The data under `data.inventory` is a fixture, not real agents.

## What this does not show

- **OPA enforces nothing.** A gateway that ignores `allow`, or treats an
  unreachable OPA as allow, makes the policy advisory. The smoke run shows that
  when OPA is down the caller gets no decision at all (connection refused). Failing
  closed on that is the caller's job, and no caller exists yet. Until a
  gateway enforces OPA's answer and a test shows a refused call that never
  reaches the tool, any OPA feature is **ADVISORY, not PREVENTION**.
- OPA ran as root (it warns about this). A lab service should run it as an
  unprivileged user.
- **Measured: the default server accepts unauthenticated writes.**
  `default-write-check.txt` records the run:
  - `PUT /v1/data/inventory/revoked` with `[]` returned 204, after which the
    revoked agent's call was **allowed**;
  - `PUT /v1/policies/x` returned 200.

  Anyone who can reach the port can therefore un-revoke an agent. Lab use
  must do one of two things:
  - run OPA with `--authentication=token --authorization=basic` and a
    system authz policy (not tested here);
  - embed OPA as a Go library, or run it in a sandbox where only the gateway
    can connect.

  A test must show the write being refused before any OPA-backed control is
  called enforcement.
- Only the `v1/ast` and `v1/rego` packages of OPA's own suite were run, not
  the whole suite.
