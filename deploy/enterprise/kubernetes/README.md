# Kubernetes node-sensor template — runtime unvalidated

This Helm chart is an opt-in **deployment template**, not a supported or
validated Kubernetes release. No node runtime, cluster, image build or
privileged installation has been exercised in this run. Both components are
disabled by default. Enabling them requires institution-supplied immutable
images, configuration and an explicit trust-boundary confirmation.

Helm 3.18.6 lint/render checks, six invalid-configuration refusals and static
rendered-YAML assertions passed on 28 October 2026. The exact commands and
public fixture output are retained under
`validation/enterprise/results/HELM_20261028T103133Z/`. Rendering does not
qualify images, node privileges, the collection pipeline or the cluster.

Use this only after the Linux VM deployment passes on an approved test node.
The images must contain `/usr/local/bin/aip-probe` or
`/usr/local/bin/aip-collector` for the intended Linux architecture, built from
the reviewed source commit and scanned/signed by the institution. This chart
does not publish an image or verify its supply-chain signature.

The probe needs `hostPID`, `hostNetwork`, host procfs/tracefs and scoped
capabilities on deliberately labeled nodes. This is elevated host access,
not a typical unprivileged workload deployment. Container security policy,
SELinux/AppArmor, tracefs, proc connector and kernel support can prevent it
from working. The daemon refuses unavailable configured sensors; verify
actual open, identity binding and signed coverage before accepting the node.
Fanotify is excluded from this chart; adding it requires an approved mount
and `CAP_SYS_ADMIN` design, not a permissive pod flag.

Place the collector in a separate administrative domain from the monitored
nodes, ideally a separate cluster/host. Different pods, namespaces, PVCs or
nodes do not establish separation from a cluster administrator. The chart
requires different node-label values and an operator assertion, which are
guardrails rather than proof of that trust boundary.

Create the ConfigMaps from the validated **real daemon environment keys** in
`deploy/pilot/*.env.example`. Do not include secrets in ConfigMaps. The probe
configuration must refer to `/var/lib/aip-probe/transport.key.json` and pin the
real collector Noise public key. The collector configuration must use
`/var/lib/aip-collector` paths, a strict continuity policy and required clock
discipline. Provision a separate Secret with `collector-passphrase` and an
allow-list ConfigMap with `probes.json`. Enable encryption-at-rest and access
control for Kubernetes Secrets through the institution's policy.

```sh
helm lint deploy/enterprise/kubernetes/chart
helm template vanian-runtime deploy/enterprise/kubernetes/chart \
  --set probe.enabled=true \
  --set probe.image='registry.bank.internal/vanian-probe@sha256:<approved-digest>' \
  --set probe.configMap=approved-probe-environment \
  --set confirmSeparateAdministration=true
```

This command requires replacing the digest placeholder and preparing the
ConfigMap; do not deploy literal examples. Default chart rendering produces
no runtime pods. Cluster application is an institution-approved action after
image, capability and node-policy review.

The collector's readiness probe only tests its transport listener. It does
not verify signed health, coverage, authorization, evidence continuity or
readiness of a business transaction. The sensor has no HTTP health endpoint;
pod state likewise is not an assertion of healthy coverage. Use the signed
health/archive checks in `../runbooks/OPERATIONS.md`, alert on silence, and
keep the API/MCP/SDK outside the kernel observer's privilege boundary.

The collector PVC is annotated `helm.sh/resource-policy: keep` so Helm
uninstall retains its keys and evidence. Probe host-path state also remains
on each node. Verify the storage provider's retention/reclaim policy and
restoration independently; do not delete retained volumes to make a new
installation start. Reusing a retained PVC across an upgrade requires an
explicit institution-controlled adoption/restore procedure.

Restrict collector ingress and probe egress with the actual CNI/network and
host firewall controls. Standard pod NetworkPolicies may not cover
`hostNetwork` traffic; this chart does not pretend they do. No sensor-to-cloud
egress, containment action, banking API intercept or automatic firewall
mutation is configured here.
