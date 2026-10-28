# Observer-only installation acceptance and operations

This runbook supplements `deploy/pilot/RUNBOOK.md`, which remains the authority
for incident triage, uncertainty, SIEM and regulatory handoff. Complete these
steps on the actual approved Linux hosts; a packaging test or old sealed
archive does not satisfy them.

## Bootstrap without sharing evidence keys

1. Approve a low-criticality monitored host and a genuinely separate collector
   host, their administrators, internal time sources and collection boundaries.
   The collector's evidence key never belongs on the workload host.
2. Install software following `../linux/README.md`. On the collector host,
   have the secret manager provision root-owned mode-0600
   `/etc/aip/collector-passphrase`. Maintain an encrypted, independently
   administered backup; copying a passphrase into an example is forbidden.
3. Bootstrap the probe transport key under its service account using the
   implemented `aip-probe enroll --probe-id ID --key-path ABSOLUTE_PATH`
   command. It emits a public-only record without opening sensors or connecting.
   Generate the native allow-list using `integrations/service_delivery/enrollments.py`
   after institutional approval. See `docs/enterprise/INSTALLATION.md` for exact
   commands. No temporary collector pin or sensor startup is needed for enrollment.
4. On the collector host, provision `/etc/aip/probes.json` as a nonempty JSON
   array whose entries are exactly `probe_id` and `transport_pubkey_hex`.
   Protect ownership and permissions; this allow-list determines which probes
   may submit. Start the collector with `systemctl start aip-collector`.
   It generates its own wrapped evidence and Noise transport keys, and
   publishes only `state/observer.pub` and `state/noise.pub`.
5. Pin the real collector `noise.pub` in each probe's
   `AIP_PROBE_COLLECTOR_NOISE_PUBKEY`, revalidate configuration, and
   start the probe with `systemctl start aip-probe`. Independently agree the
   observer public key fingerprint with the auditor. These are different
   public keys for different purposes; no evidence private key is copied.
6. Require successful sensor-open logs, authenticated batch acknowledgments,
   durable signed archive growth, fresh signed health and offline verification.
   Only then enable each service at boot with `systemctl enable aip-probe`
   or `systemctl enable aip-collector` on its respective host.

## Acceptance evidence

Record source SHA, approved archive digest, OS/kernel/architecture/runtime,
selected sensors and capability sets, installation/preflight transcript,
clock synchronization, service status and exact trust-anchor fingerprints.
Run the actual approved real-agent harness and RBI rehearsal on dedicated
Linux infrastructure before claiming their acceptance criteria. The RBI
interference experiment attaches test eBPF programs: run it only on the
authorized disposable demonstration host, not a bank production node.

The existing `integrations/agents/run.sh` now builds all four named binaries
by exit status, requires the collector's synchronized clock and stops writers
before verification/export. Its execution needs root, tracefs, the pinned
LangGraph venv and a synchronized Linux clock. Its collector is a separate
process on the same host: it validates software behavior but does not prove
a two-host administrative boundary or a signed real-agent authorization
reconciliation verdict. Preserve that distinction in every transcript.

## Health checks and silence

Use `systemctl is-active aip-probe` or `aip-collector` for **process state**.
That is not observation coverage. Review journal output for sensor-open
errors, connection failures, authenticated batch acknowledgments, archive
write errors and clock/continuity refusals. Do not expose collector keys or
transport credentials in a health endpoint or log aggregator.

On the collector host, `state/health.archive.jsonl` is refreshed approximately
every 30 seconds and signed. The daemon does **not** provide an HTTP health
endpoint. Monitor file age and growth separately from process liveness; raise
an operational alert if freshness exceeds the institution's threshold (for
example, 90 seconds), but do not turn an unsigned filesystem mtime into a
cryptographic coverage claim.

Copy a stable snapshot of batch/health archives and run:

```sh
aip-observe-verify --observer-id "$APPROVED_OBSERVER_ID" --key-version 1 \
  --pubkey-file "$INDEPENDENT_PUBLIC_ANCHOR_FILE" \
  --batches attested.archive.jsonl --health health.archive.jsonl --json
```

Require a zero exit code and inspect stated coverage, continuity and clock
fields. Signature verification establishes who signed those bytes; it does
not establish business transaction completion or a trustworthy compromised
kernel. `CANNOT_PROVE`, `IntegrityUnknown`, missing coverage and stale health
remain explicit uncertainty. A monitoring silence is an uncovered interval,
not proof that the agent did nothing.

## Reliability, backup and restore

The collector fsyncs each archived attestation before acknowledgement and
persists continuity state. The probe currently has **no durable resend
buffer**: collector downtime can lose observations and must be reported as a
gap. The collector uses one blocking thread per connection; systemd's task
limit bounds process resource use but is **not** a validated bounded worker
pool or high-availability service. Restrict network ingress to approved probe
hosts and test pressure/loss/restart behavior before an institutional pilot.

Back up the complete collector state and archive consistently, wrapped key,
Noise key, config and independently held public anchors. Encrypt backups,
apply retention/legal hold and test restore on a separate approved host.
Never restore an older state over a newer archive to silence continuity
refusal. A refused strict-continuity startup is an incident requiring the
recorded policy, not a reason to delete the checkpoint.

The service database has a separate real restore drill,
`deploy/sql/restore_drill.sh`, which must run against the institution's
PostgreSQL setup. It does not back up or prove restore of collector files.

## Key custody and collection scope

The collector daemon is wired to `CollectorKey::production` and the wrapped
file custodian. `aip-hsm` implements PKCS#11 and has SoftHSM tests, but this
daemon package does not expose a PKCS#11/HSM configuration switch. A certified
bank HSM, KMS adapter, key ceremony and key backup are not validated by this
installer. Gateway and service signing keys are separate authorities too.

The host sensor has no per-agent process filter. Procfs executable/path hashes,
network addresses, process/container identifiers and file-event metadata can
be operationally sensitive even without payload bytes. No transaction
payload, model prompt or response is collected by default. Approve host and
mount/interface scope with the institution's privacy officer before startup.
