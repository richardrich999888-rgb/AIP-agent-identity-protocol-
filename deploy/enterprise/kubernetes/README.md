# Kubernetes collector template — runtime unvalidated

This chart renders the collector only. Enabling `probe.enabled` explicitly
fails: the previous elevated host-probe template was never runtime validated
and has been retired. Install sensors using the reviewed
[Linux systemd deployment](../linux/README.md), on an approved Linux host.
The chart does not provide a Kubernetes sensor installation route.

The collector remains an opt-in deployment template, not a validated Kubernetes
release. It runs as a nonroot user with the default seccomp profile, no added
capabilities, no service-account token, and no host namespaces or host mounts.
An institution must supply a reviewed, scanned/signed immutable image containing
`/usr/local/bin/aip-collector`, configuration and retained storage. Rendering
does not qualify an image, a cluster, evidence custody or kernel observation.

Place the collector in a separate administrative domain from monitored hosts,
ideally a separate cluster/host. Namespaces, PVCs and different nodes do not
separate a cluster administrator. Different node labels and the explicit
`confirmSeparateAdministration` assertion are guardrails, not proof of custody.

Create the collector ConfigMap from the daemon environment keys in
`deploy/pilot/collector.env.example`, using `/var/lib/aip-collector` paths, strict
continuity and required clock discipline. Keep secrets out of ConfigMaps.
Provision a Secret with `collector-passphrase` and a ConfigMap with `probes.json`.
Apply institution policy for Secret access and encryption at rest.

```sh
helm lint deploy/enterprise/kubernetes/chart
helm template vanian-runtime deploy/enterprise/kubernetes/chart \
  --set collector.enabled=true \
  --set collector.image='registry.bank.internal/vanian-collector@sha256:<approved-digest>' \
  --set collector.configMap=approved-collector-environment \
  --set collector.allowListConfigMap=approved-probes \
  --set collector.passphraseSecret=approved-collector-passphrase \
  --set confirmSeparateAdministration=true
```

Replace the digest placeholder and provision configuration before use. Defaults
render no runtime pods. Cluster application requires institution image, storage
and node-policy review. No cluster has been applied or runtime tested by these
render checks.

Readiness tests only transport-listener reachability. Use signed health/archive
checks in `../runbooks/OPERATIONS.md` for coverage, continuity and authorization;
alert on silence. The collector PVC uses `helm.sh/resource-policy: keep` so
uninstall retains keys and evidence. Independently verify storage retention,
reclaim policy and restoration, and control adoption of retained PVCs on upgrade.
Restrict collector ingress and host-probe egress with actual network/firewall
controls. No automatic firewall changes are made by the chart.

The 28 October 2026 Helm result remains a historical static render check. Its
original elevated manifest and four HIGH findings are preserved, unchanged, in
the [retired evidence archive](../../../validation/enterprise/results/HELM_20261028T103133Z/RETIRED_TEMPLATE.md).
That historical result does not qualify the retired sensor template.
