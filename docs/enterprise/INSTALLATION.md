# Customer installation — engineering evaluation

Install **vanian-snifferdog-agent** on an approved Linux workload host and **vanian-evidence-collector** on a genuinely separate host administered by the institution's security/audit team. Both reuse the existing native daemons and offline observer verifier. Initial mode is OBSERVER_ONLY. A package install establishes software presence only.

The new Debian packaging has been built/extracted/tested using real x86_64 Linux release binaries. It has not been installed on a clean systemd host. There is no qualified distribution/kernel support matrix or approved published release yet. Aarch64 packaging is implemented but unexecuted. RPM, hardware collector HSM, high availability and automatic rollback remain unsupported. Review [readiness](PRODUCT_READINESS.md) before an institutional evaluation.

## Obtain and verify

Obtain the DEB and its approved SHA-256 through the institution's independently authenticated release-approval process. A checksum delivered only alongside an untrusted package establishes no origin. These engineering artifacts are not signed releases. Runtime package publication, complete third-party notices and approved proprietary license terms are release gates.

```sh
printf '%s  %s\n' "$INDEPENDENTLY_APPROVED_SHA256" vanian-snifferdog-agent_amd64.deb | sha256sum -c -
sudo apt install ./vanian-snifferdog-agent_amd64.deb
```

On the collector host use the corresponding approved `vanian-evidence-collector_amd64.deb`. The maintainer scripts create the dedicated account/state directory and reload systemd. They neither start nor enable a service. Probe and collector packages conflict to prevent accidental same-host installation. Retained configuration from the opposite role also blocks installation. The native dependencies include Python 3.9+, systemd 247+, passwd, libgcc-s1 and the GNU libc version actually required by the supplied binaries.

## Bootstrap and configure

On the probe host, bootstrap **only its transport authentication key**, using the implemented command. It requires no collector pin, sensors or network:

```sh
sudo -u aip-probe /opt/vanian/snifferdog/bin/aip-probe enroll \
  --probe-id agent-linux-01 \
  --key-path /var/lib/aip-probe/transport.key.json > public-enrollment.json
```

Retain the private key on that host. The JSON output contains the public key and explicitly states observation `NOT_STARTED` and workload binding `NOT_ESTABLISHED`. The command refuses symlinks, overly readable or mismatched existing keys and does not replace an existing valid key. Protect the parent state directory; reusing the key is not proof of a logical agent's identity.

Transfer the public record through the institution's approved enrollment channel. On an operator machine with the reviewed source:

```sh
python3 integrations/service_delivery/enrollments.py \
  --record public-enrollment.json --output probes.json
```

Approve the resulting native allow-list and provision it as `/etc/aip/probes.json` on the collector. Provision root-owned mode-0600 `/etc/aip/collector-passphrase` through the institution's secret manager. It is delivered to the service through systemd LoadCredential; it must never be copied to the probe host or kit.

Edit the shipped environment examples under `/usr/share/doc/vanian-snifferdog-agent/` and `/usr/share/doc/vanian-evidence-collector/`. Configure the real independently selected collector endpoint and its public Noise pin. See the [bootstrap runbook](../../deploy/enterprise/runbooks/OPERATIONS.md) for collector key generation, clock checks and the distinct observer-signing anchor. Then, on the respective hosts:

```sh
sudo vanian-evidence-collector configure --config collector.env --confirm-separate-host
sudo vanian-snifferdog-agent configure --config probe.env --confirm-separate-host
```

Configuration performs actual host prerequisites before writing on `/`. It validates the existing strict daemon configuration, writes a root-owned config, a capability override for exactly the selected supported sensors and a startup hash check. Selecting fanotify remains unsupported by this installer because it requires separately reviewed host privileges. Configuration remains a plan: the confirmation is an operator assertion of administration separation. Services remain stopped. Changed configuration fails the startup check until revalidated. Use `--replace-config` for an explicitly approved configuration change; locally modified capability overrides are preserved for review.

## Start and verify

After credentials, scope, clocks and transport pins are approved, explicitly start the collector first and then the probe on their respective hosts:

```sh
sudo systemctl start aip-collector
sudo systemctl start aip-probe
```

Review sensor-open failures, batch acknowledgments, signed archive growth and fresh signed health. `systemctl is-active` proves process state only. Copy a stable archive snapshot and verify using the independently supplied observer public anchor:

```sh
/opt/vanian/snifferdog/bin/aip-observe-verify \
  --observer-id "$APPROVED_OBSERVER_ID" --key-version 1 \
  --pubkey-file "$INDEPENDENT_OBSERVER_ANCHOR" \
  --batches attested.archive.jsonl --health health.archive.jsonl --json
```

Inspect coverage, continuity and clock results even when signatures verify. Enable at boot only after acceptance (`systemctl enable aip-probe` or `aip-collector`). The full real-agent authorization/gateway/kernel/collector/reconciliation/API flow remains a separate same-run gate. Missing health or coverage is not a clean execution finding.

## Upgrade and remove

Record a maintenance/coverage gap and back up all state, wrapped keys, transport keys, anchors and checkpoints before upgrading. Debian upgrades stop the service and leave it stopped for explicit revalidation and restart. No automatic rollback or migration is implemented.

```sh
sudo apt remove vanian-snifferdog-agent
```

Removal stops/disables the role and removes package-owned software. Configuration, capability overrides, accounts, keys and evidence remain, including on purge. Data retention/legal hold and secure deletion are separate institution operations. Do not mix DEB-managed and tar-managed ownership. Use the original [tar installer](../../deploy/enterprise/linux/README.md) and its retained-data uninstall for existing tar installations.

## Build and container preparation

Build the three existing release binaries and verified tar as documented in the Linux package guide, then wrap the same approved archive:

```sh
python3 deploy/enterprise/linux/deb.py --archive runtime.tar \
  --expected-sha256 "$APPROVED_RUNTIME_SHA256" --role probe \
  --version 0.4.0~eval.1 --output vanian-snifferdog-agent_amd64.deb
python3 deploy/enterprise/linux/deb.py --archive runtime.tar \
  --expected-sha256 "$APPROVED_RUNTIME_SHA256" --role collector \
  --version 0.4.0~eval.1 --output vanian-evidence-collector_amd64.deb
python3 deploy/enterprise/linux/container_context.py --archive runtime.tar \
  --expected-sha256 "$APPROVED_RUNTIME_SHA256" --role collector \
  --base-image "$APPROVED_BASE_IMAGE_AT_SHA256_DIGEST" --output collector-context
docker build --tag vanian-collector-evaluation collector-context
```

The container preparation validates digest syntax and copies only the selected role plus verifier; it does not qualify the base image. Collector images run as UID/GID 10001, with separately mounted config, passphrase and persistent state. Probe containers require approved host PID/network/proc/tracefs access and selected sensor capabilities. The existing default-disabled Helm chart references these `/usr/local/bin` entry points. No Docker image or Kubernetes runtime was built/executed here; two containers or nodes are not evidence of separate administration.
