# VANIAN upstream evidence verification

The private console can run the original Sniffer Dog observer verifier and AIP run evaluator on four retained historical lab captures. Each result is computed on demand by an unchanged Rust executable compiled to WebAssembly. The captures stay separate from tenant data and synthetic dashboard aggregates.

## Verify the console from the AIP repository

Use a Linux host with a readable `/proc`, loopback HTTP and HTTPS, Node 22.13 or newer, npm, OpenSSL and Chromium’s system libraries. The default native build also uses Git, tar, a C linker and Rust 1.99.1. Its AIP checkout must contain commit `d8ea36255d311b10b9b5b6e844336058622d45c6`. A shallow clone may need `git fetch --depth=1 origin d8ea36255d311b10b9b5b6e844336058622d45c6`. First-time installation and Rust crate downloads need registry access.

```sh
cd apps/vanian-console
npm ci
npx playwright install chromium
rustup toolchain install 1.99.1 --profile minimal
npm run verify:aip-console
```

The command finds the enclosing Git repository, extracts the pinned native source into a temporary directory and builds the two verifiers with the upstream lockfile. It compiles the fresh self-process capture helper against the resulting libraries. It type-checks and builds the application, then runs the native and HTTPS adapter suite and all Playwright tests against the built Worker with isolated D1 databases. A missing prerequisite, skipped test or unsuccessful result exits nonzero. No customer telemetry or credentials are required.

For a standalone console checkout, set `AIP_CHECKOUT` to the upstream Git checkout. For a prebuilt installation, point `OBSERVER_VERIFIER`, `AIP_EVALUATOR` and `SELF_SAMPLE_GENERATOR` at trusted executables built from that same revision and this console’s `tests/support/observe_self.rs`. The command prints each executable’s SHA-256 and runs the identical checks. A preinstalled Chromium can be selected with `VANIAN_CHROMIUM=/absolute/path/to/chromium`. On Linux systems missing browser libraries, use Playwright’s documented `npx playwright install --with-deps chromium` during host setup.

## Integration

1. Put `public/upstream-replay/` under the application’s first-party static root, preserving its filenames.
2. Render the supplied `NativeResearchPanel` on the evidence verification screen. Its default selection opens the process lifecycle capture. The optional `initialSample="same-run"` opens the authority case.
3. The browser module also exposes `startReplay(sample, integrityCheck, optionalAbortSignal)`. It checks pinned asset hashes and executes the appropriate verifier in a dedicated worker with an in-memory file system. Results are used only after a complete verifier response.
4. `bridge/cli.mjs` exposes the same native executables at a customer site via an operator-invoked command. Binary paths and separately provisioned trust material are supplied by a trusted operator. This command reads local archives. It does not run sensors or change policy.

## Captures and guarantees

| Capture | Native result | Scope |
| --- | --- | --- |
| t09 | One verified batch with fork, exec and exit events | The process events carry no logical agent binding. The observer signs ContinuityUnverified and makes zero coverage assertions. |
| t15 | One verified batch with dropped activity and Degraded sensor health | Zero kernel events, one lost event, zero coverage assertions. |
| same-run | Verified authorization, forwarded gateway receipt and signed reconciliation with CannotProve / ActionEvidenceUnavailable | The observed gateway request does not establish the business effect. |
| same-run-interruption | Verified authorization and signed reconciliation with CannotProve / WindowNotCovered | An interruption leaves the observation window uncovered. |

The capture date is 14 November 2026. Collector attestation time and kernel monotonic timestamps have distinct fields. Both kernel cases leave clock synchronization unstated. All public keys in the bundled captures are lab anchors. Customer archives require independently provisioned institution-owned anchors.

## Upstream interface

The source workspace is pinned to commit `d8ea36255d311b10b9b5b6e844336058622d45c6`. The recorded observation source commit is `5be83a87bec680d26510c2be93e66fdfda008b1e`. The upstream observer reads signed JSONL batches and sensor health envelopes. Exit 0 and a clean report allow the bridge to render verified facts. Exit 1 carries verification findings. Exit 2 or malformed output is an operational error. AIP reads a public run bundle on standard input and its trust configuration from `AIP_RUN_TRUST_FILE`.

Operator examples with Node 22.13 or later

```sh
node bridge/cli.mjs observe \
  --binary /opt/vanian/bin/aip-observe-verify \
  --observer "$OBSERVER_ID" --key-version "$KEY_VERSION" --key "$TRUSTED_PUBLIC_KEY_HEX" \
  --batches /srv/vanian/exports/batches.jsonl --health /srv/vanian/exports/health.jsonl

node bridge/cli.mjs evaluate \
  --binary /opt/vanian/bin/aip-execution-assurance \
  --bundle /srv/vanian/exports/run-bundle.json --trust /etc/vanian/trust.json
```

The bridge snapshots regular files into a private temporary directory. It bounds size and execution time, consumes stdout from a fixed argument list and never takes executable paths from archive contents. Its output carries input SHA-256 digests. Customer presentation must enforce the owning tenant's permissions and retention policy.

## Rebuild

Use a clean checkout of the pinned AIP repository, Rust 1.99.1 and its wasm32-wasip1 standard library. The crate lockfile and repository license are preserved.

```sh
cd "$AIP_CHECKOUT"
cargo build --locked --bin aip-observe-verify --bin aip-execution-assurance
CARGO_PROFILE_RELEASE_STRIP=symbols CARGO_PROFILE_RELEASE_OPT_LEVEL=s \
  cargo build --release --locked --target wasm32-wasip1 \
    --bin aip-observe-verify --bin aip-execution-assurance
cd "$INTEGRATION_ROOT"
python3 replay-source/package-assets.py "$AIP_CHECKOUT" "$AIP_CHECKOUT/target/wasm32-wasip1/release"
npm ci --prefix replay-source --no-fund --no-audit
replay-source/node_modules/.bin/esbuild replay-source/worker.mjs --bundle --format=esm --minify --outfile=public/upstream-replay/worker.mjs
npm run verify:aip-console
```

The 16 checks include the compiled worker, exact persisted outputs from the native comparators, changed bytes, alternate public keys, missing gateway receipts, refused input selection, a changed deployed asset and both native adapters. The upstream six-check observation and six-check authority harnesses were also rerun. Their original paper-trail scopes, source revisions and capture limitations are preserved. These checks do not establish customer deployment qualification.

Source and capture paths are recorded in `tests/golden/native-transcript.json` and `replay-source/package-assets.py`. Third-party attribution is distributed alongside the browser binaries.

## Tenant-bound HTTP adapter

`bridge/service.mjs` is a Node 22.13+ operator-side reader for signed observer archives and AIP run bundles. It binds to loopback. Place the operator's authenticated HTTPS endpoint in front of it for the hosted console. The reader does not start a probe or infer current sensor connectivity.

1. Build the two native binaries from the pinned AIP workspace. Install them in an operator-owned directory.
2. Create a restricted configuration using `bridge/service.config.example.json`. Provision each subject, role, tenant, operator-owned archive path and independently trusted public key. Omit an unavailable native source. Keep the example placeholders out of production.
3. Supply a strong service credential through the process environment or the operator's secret manager as `VANIAN_BRIDGE_TOKEN`. Start `node bridge/service.mjs /etc/vanian/reader.json`. The server defaults to `127.0.0.1:8874`.
4. Configure the console’s `VANIAN_API_ORIGIN` with the HTTPS reader endpoint and `VANIAN_API_TOKEN` with the matching credential. `VANIAN_LIVE_MEMBERS` maps the authenticated Site subject to its tenant and role. The reader independently checks the same subject, role and tenant on every call.

| Read endpoint | Evidence returned |
| --- | --- |
| `/v1/overview`, `/v1/posture` | Time-scoped signed observations, sample and kernel event counts, unknown agent bindings and date series. |
| `/v1/agents/lineage` | Record-scoped process relationships attested in signed observations, bounded by the actual PID evidence. |
| `/v1/snifferdog/events`, `/v1/runtime`, `/v1/attribution` | Verified kernel events and process samples. Source mechanism, PID scope, collector timestamp and unresolved logical identity stay separate. |
| `/v1/evidence`, `/v1/verification` | A complete archived observation chain, verifier status, key identity, digest, observed-item count, health and signed coverage assertions. |
| `/v1/identity` | Signed AIP run evaluation including its authorized identity, gateway receipt state and actual reconciliation verdict. |

An authenticated archive still labels the live sensor connection offline. Only the last collector attestation time describes the evidence on display. Full acquisition, first-party streaming, institutional enrollment, SSO, billing and other analytics are outside this adapter. Unknown modules return HTTP 501. Missing, partial, unverifiable or unavailable inputs return HTTP 503, without row counts or previous records. The known bundled historical captures are refused on live routes. The service projects allowlisted fields; raw process paths and prompts are never exposed by these routes. Remove or replace operator files atomically for a clean rollover.

The review command exercises the actual native collector by measuring the test process under an ephemeral lab key. The TLS contract test trusts its short-lived local certificate only in the test subprocess. It covers valid native-backed reads, group scoping, incorrect tenant and credentials, and a required signed health file becoming incomplete. The test removes the private key and records when it finishes.

The event projection includes a record-scoped 2D/3D graph. Kernel fork edges use the signed parent and child PID. Process samples connect only the measured PID to that sample. No graph promotes a PID into a logical AI agent, and unmatched scope or selection produces an empty graph.

The overview service aggregates the entire filtered archive before pagination. It exposes signed records, kernel events, process samples and unbound observations, daily counts and type breakdowns. Home and Security Posture share the same measured data. Agent Lineage renders the available process relationships with their original evidence references. No application discovery, logical agent binding or continuous sensor coverage is inferred from these counts.
