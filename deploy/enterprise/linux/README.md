# Linux runtime package

## Compatibility status

The source supports Linux perf tracepoints, proc connector, fanotify and
AF_PACKET. Source `c683134c59b50950e4eab176d37292683c61930d` passed actual
full-sensor installation and service qualification in
[run 45433545896](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/45433545896)
on one disposable x86_64 Linux runner, kernel `7.0.0-1014-aws`, systemd 255.
All seven sensors produced controlled positive events and all nine forbidden
operations were denied. Filtering, delivery outage/replay, service restart and
state-preserving uninstall/reinstall passed. The archive contains 59 signed
batches, five health records and 721 kernel events, verified by a separate job
with networking disabled. See the
[exact evidence manifest](../../../validation/customer_pilot/evidence/c683134/manifest.json).

This was a controlled OS workload with a separate collector account under the
same host administration. Genuine AI-agent runs are recorded separately in the
[pilot report](../../../validation/customer_pilot/REPORT.md); they do not qualify
AI operation under this exact full-sensor profile. Customer readiness and
independent custody remain unproven. Historical Linux 6.18.44 development
evidence does not qualify a distribution, Kubernetes runtime or production workload.

Hosted enterprise CI built an actual x86_64 Linux archive from PR review tree
`076b22c` on 28 October 2026. Its downloaded digest, manifest, payload modes and
ELF architecture passed verification; see `docs/enterprise/VALIDATION_REPORT.md`
and `validation/enterprise/results/CI_20261028T103950Z/` for exact provenance.
That historical archive verification was an evaluation build, not an
institution-approved signed release or installation test. The later disposable
installation above has its own exact source and evidence.

The package builder accepts x86_64 and aarch64 Linux GNU targets and validates
each input's ELF architecture. This is a packaging target check, not a
compatibility certification. Build on the oldest approved distribution and
retain compiler, libc, kernel and dependency records. Dynamic-library and
kernel compatibility must be established on each candidate host.

Requirements: Python **3.9+**, systemd (including `LoadCredential`, normally
systemd 247+), root for installation, and separate approved hosts. Probe sensor
requirements are discovered on the actual node. `socksend` requires the
`sock/sock_send_length` tracepoint (normally Linux 6.4+). Proc connector requires
`CONFIG_CONNECTOR`/`CONFIG_PROC_EVENTS` and `CAP_NET_ADMIN` in the initial
network namespace. Perf sensors require readable tracefs plus `CAP_PERFMON`
or equivalent host policy. AF_PACKET requires `CAP_NET_RAW`.

The installer trims the default unit's capabilities to the configured sensors.
It refuses `fanotify` by default: that sensor requires `CAP_SYS_ADMIN` and a
host-mount view. An explicit digest-bound full-sensor path is available only for
approved disposable-runner qualification; it does not authorize customer use. Selecting an unavailable sensor makes the real daemon fail
startup. A successful file preflight does not prove sensor availability,
binding completeness or healthy observation coverage.

The customer pilot changes add bounded durable buffering and an explicit
process-instance filter. Use `AIP_PROBE_SPOOL_DIR` below
`/var/lib/aip-probe`, with positive `AIP_PROBE_SPOOL_MAX_BYTES` and
`AIP_PROBE_SPOOL_MAX_BATCHES` limits. `AIP_PROBE_FILTER_PATH` must name an
operator-controlled file below `/etc/aip`. The host preflight requires exact
root-owned mode `0600` or `0640` and a maximum size of 256 KiB, then delegates
schema validation to the installed `aip-probe validate-filter` command. Before
the binary is installed it reports `FILTER_SCHEMA_DEFERRED`; rerun preflight
after installation and check actual service-user readability before startup.

The full-sensor profile and its qualification procedure are in
[FULL_SENSOR_REVIEW.md](FULL_SENSOR_REVIEW.md). The user approved disposable
GitHub Actions testing on 24 November 2026. `review-probe-unit` writes the exact
unit, configuration and AppArmor policy digests without installing or starting
anything. Installation requires all three approved digests, the trusted archive
digest and `--disposable-runner-validation`; it installs the exact
reviewed bytes and leaves service startup to the acceptance harness. The
validation receipt explicitly makes no independent-custody claim. Customer
approval and actual host qualification remain separate gates. The default
installation still refuses fanotify.

## Build a verifiable package

On a connected approved build machine, from a clean reviewed source commit:

```sh
cargo build --release --locked --target x86_64-unknown-linux-gnu \
  -p aip-probe --bin aip-probe -p aip-collector --bin aip-collector \
  -p aip-observe-verify --bin aip-observe-verify
python3 deploy/enterprise/linux/package.py build \
  --bin-dir target/x86_64-unknown-linux-gnu/release \
  --target x86_64-unknown-linux-gnu \
  --source-commit "$(git rev-parse HEAD)" \
  --output dist/vanian-runtime-x86_64-linux.tar
```

Retain the successful build transcript and exact source SHA. The manifest's
source SHA is supplied by the operator; the package cannot prove binary build
provenance. The emitted SHA-256 covers the entire archive, and the manifest
covers each approved file's bytes and mode. Identical input files yield an
identical uncompressed tar archive. The package contains **no keys**.

Publish the archive digest through the institution's independently
authenticated release-approval channel. A digest copied beside an untrusted
archive is not an authenticity check. The package is anchored by that
independently supplied digest; it is not itself a digitally signed release.
Use the institution's release-signing process when a signed artifact is
required. The repository's existing Sigstore release workflow does not yet
publish these runtime packages.

Copy the reviewed `package.py` separately or extract it only after verifying
the archive against the independently obtained digest with a trusted host
utility. Do not run an installer obtained from an unverified archive as root.

```sh
python3 package.py verify --archive vanian-runtime-x86_64-linux.tar \
  --expected-sha256 "$INSTITUTION_APPROVED_ARCHIVE_SHA256"
```

The verifier rejects extra files, duplicate names, symlinks, path traversal,
setuid modes, invalid ELF targets, altered bytes and expansion limits. It
does not extract a tar archive into a filesystem.

## Install on separate hosts

Copy `deploy/pilot/probe.env.example` or `collector.env.example` into an
institution-controlled configuration file and replace every placeholder.
The validator accepts a restricted `KEY=value` syntax: no shell expansion,
quotes, inline comments or spaces. It never sources the file as a shell.
Use full paths below `/var/lib/aip-probe` or `/var/lib/aip-collector` for
writable keys/state, matching the systemd sandbox. An API key or evidence
passphrase does not belong in the probe configuration.

Validate the probe's configuration and host separately:

```sh
python3 package.py preflight --role probe --config probe.env --config-only
sudo python3 package.py preflight --role probe --config probe.env
sudo python3 package.py install --role probe --config probe.env \
  --archive vanian-runtime-x86_64-linux.tar \
  --expected-sha256 "$INSTITUTION_APPROVED_ARCHIVE_SHA256" --confirm-separate-host
```

On the independently administered collector host:

```sh
sudo python3 package.py preflight --role collector --config collector.env
sudo python3 package.py install --role collector --config collector.env \
  --archive vanian-runtime-x86_64-linux.tar \
  --expected-sha256 "$INSTITUTION_APPROVED_ARCHIVE_SHA256" --confirm-separate-host
```

Installation writes the selected daemon, offline verifier, reviewed
installer, systemd unit and supplied configuration. The explicitly approved
full-sensor profile also installs its exact enforcing AppArmor policy; it creates the selected
service account/state directory and reloads systemd. It refuses an existing
installation or other role on the same host. It does **not** start services.
The confirmation records an operator assertion, not independently verified
administrative separation. Review DNS and routing to ensure the collector
endpoint is genuinely off-host; the local/loopback check is only a guardrail.

Follow the bootstrap and acceptance procedure in
`../runbooks/OPERATIONS.md`. The collector generates its wrapped evidence key
on first start on the collector host, using a systemd credential supplied at
`/etc/aip/collector-passphrase`. Keep it root-owned and mode `0600`, supplied
by the institution's secret manager. The collector service user receives the
credential through systemd, not a plain persistent environment variable.
Do not set `AIP_COLLECTOR_PASSPHRASE_FILE` in this package's configuration;
the installed unit always requires the named systemd credential.

State is retained under `/var/lib/aip-collector` or `/var/lib/aip-probe`.
Memory is bounded to 512 MiB, tasks to 128, file descriptors to 8192 and CPU
to one core per unit. These are initial conservative limits, not measured
capacity claims. Resource pressure may cause loss or restart: observe signed
health and coverage and tune only after institution-specific tests.

## Uninstall and upgrade

Copy the installed tool to an operator-controlled path before uninstalling
if it will be needed for reinstall:

```sh
sudo python3 /opt/vanian/snifferdog/package.py uninstall
```

The tool disables/stops the selected service, checks installed file hashes,
removes only its recorded software/unit files and receipt, and reloads
systemd. It retains **all** keys, evidence, configuration, credentials, service
accounts, trust anchors and state. It refuses locally modified software;
review and archive those changes first. Data deletion is a separate
institution-controlled retention procedure.

For upgrade, approve a new archive digest, back up and verify state, record a
coverage maintenance window, uninstall software, then install the new package
with the identical retained config. Drain any outstanding queue with the
matching protocol binaries before a protocol upgrade; do not relabel queued
records or change their original bytes. Preserve collector chain state, wrapped
key, Noise key, probe transport key and auditor trust anchors. Start manually
and prove restart continuity before accepting the rollout. No automatic
rollback, migration, high availability or no-downtime upgrade is claimed.

The full-sensor approval gate also requires `--approved-probe-apparmor-sha256`.
AppArmor must be enabled with its parser available and the exact policy loaded
in enforce mode. The v2 package binds policy bytes to the archive and receipt;
legacy v1 packages cannot activate this profile. See [the full-sensor review](FULL_SENSOR_REVIEW.md)
for the retained failures, passing disposable qualification and remaining
customer gates: independent collector custody, scoped AI execution under the
final profile, live queue-limit/storage-failure/corrupt-spool tests, sustained
capacity/loss measurements and persistent-host recovery. Security-owner review
must address broad host read access: the private-read canary succeeded.
Filtering is a retention boundary, not read isolation.
