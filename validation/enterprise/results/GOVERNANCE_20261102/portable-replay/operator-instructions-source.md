## Portable replay of the retained governance run

The new `validation/enterprise/replay_retained_governance.py` launcher accepts
explicit package, repository, prepared OPA executable and fresh output paths.
It supports this exact reviewed source3e6c179/run41432473155 dataset, rather
than accepting arbitrary replay programs from an evidence sender. It pins the
package inventory, complete original ZIP, member manifest and all three frozen
scripts; checks every original member's safe path, regular type, size, CRC and
SHA; and loads only the pinned public modules. The original scripts and signed
evidence are unchanged. Only known path assignments in new derived copies are
replaced, with exact-once transformations and before/after hashes retained.

Prepare the four trusted Rust tools from a checkout whose Rust/Cargo sources
match source3e6c179. This build phase may retrieve Cargo dependencies:

```sh
cargo build --locked -p aip-observe-verify -p aip-corroborate -p aip-mcp-gateway \
  --bin aip-observe-verify --bin aip-corroborate \
  --bin aip-tool-receipt --bin aip-execution-assurance
```

Prepare the platform-pinned OPA executable separately while networking is
available. This command downloads only the public pinned OPA asset/license;
it does not prepare the SDK or Collector:

```sh
python3.12 integrations/governance/opa.py prepare --root /absolute/prepared-opa
```

Then disconnect networking or use the offline validation environment. On
Linux amd64, run from the trusted checkout:

```sh
python3.12 validation/enterprise/replay_retained_governance.py \
  --package "$PWD/validation/enterprise/results/GOVERNANCE_20261102/genuine-3e6c179" \
  --repo "$PWD" \
  --opa /absolute/prepared-opa/opa-1.22.0-linux_amd64 \
  --out /absolute/fresh-governance-replay
```

For Darwin arm64, select `opa-1.22.0-darwin_arm64` instead. The output parent
must exist; the output directory itself must not exist. Input/output symlinks,
modified or unexpected package files, unsafe/duplicate ZIP members and missing
or changed assets are refused. The operator explicitly trusts the local Rust
executables and host; source comparisons plus executable hashes provide
provenance rather than build attestation. No SDK, Collector, agent, model or
network service is required during verification. OPA executes locally against
the original root-controller proposal/context; it does not sign authorization.

Inspect `portable-replay-result.json`, `path-transformations.json`, each frozen
script's stdout/stderr and the fresh `independent-offline/` reports. `PASS`
means all three unchanged replay scripts succeeded. It does not mean an
interrupted interval became covered: positive/recovery have six-sensor task
coverage; interruption correctly remains uncovered/NoReference. Canonical
kernel `CannotProve` findings, same-artifact anchor/checkpoint custody, and
unsigned controller OPA/telemetry limits remain. Legacy frozen field names
mentioning Mac/Darwin are preserved; the launcher/new receipts record the
actual host and verified platform asset.

Validation of the launcher: actual complete three-profile replay passed with
the current four compiled Rust tools and pinned Darwin OPA, including an output
path containing spaces and apostrophes. Fifteen focused controls passed,
covering pinned-file changes, late script substitution, unsafe/duplicate ZIP
members, symlink ancestry, unexpected import payloads, wrong OPA, existing
output refusal, path-only reversible transforms and primary failure retention.
These controls include synthetic malformed packages; they are not additional
genuine agent runs. Original retained package bytes and previous receipts are
unchanged.
