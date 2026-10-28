# Production and operational gaps

The integration is an engineering evaluation. Final status is determined by
actual retained run records and exact-revision CI, not by the architecture or
by combining historical component successes.

| Gate | Requirement / present limit |
| --- | --- |
| Same-run autonomous execution | Fresh genuine model/tool/kernel/receipt/authority/API/client run must pass; failed attempts remain visible |
| Independent administration | Separate control of the collector host, signing keys and durable storage is required for independent custody and resistance to workload-host root/kernel compromise; one-VM isolation cannot establish this |
| Institution-owned identity/keys | Operator-reviewed issuer, authority, gateway, collector/reconciler anchors, rotation/revocation, secret-manager custody and retention; ephemeral CI keys are not institutional enrollment |
| Logical-agent delegation | Physical process binding and gateway principal checks do not prove in-process sub-agent delegation |
| Business effect | Read result and inspectable synthetic output are not loan approval, settlement or authoritative bank outcome proof |
| Authorization completeness | Missing signed completeness prevents automatic unauthorized/unattributed-effect conclusions |
| Genuine swarms | Agent Zero, DeerFlow and OpenHands must execute actual tasks; installation or LangGraph execution cannot validate those frameworks |
| Live negative and performance coverage | Actual workload interruption/recovery, concurrency/soak, loss and matched observed/unobserved overhead measurements remain separate gates |
| Clean host | Real supported Linux installation, startup, restart continuity, backup/recovery and retained-data uninstall under actual separation |
| Installed sensor profile | The current installer refuses fanotify; the full hosted six-sensor profile needs a reviewed installer/systemd deployment change for `CAP_SYS_ADMIN` and host-mount visibility, followed by actual installed-service validation |
| Release delivery | Independently approved/signed package provenance; checksum alongside an untrusted package is insufficient |
| Enterprise deployment | Production identity/ingress, database/RLS operational qualification, quotas, backups, HA, auditing and institutional data protection |
| Kubernetes and air gap | Render/lint or procedure documentation is not runtime qualification |
| Independent assessment | External technical/security review with original public evidence and approved anchors |
| Regulated use | No regulatory approval, RBI-authorized pilot, independent certification or production-readiness claim |

The public repository can allocate disposable GitHub-hosted Linux runners for
the first integration; no SSH connection is required. Each runner must provide
root-controlled provisioning, tracefs/perf and all six configured sensors,
process connector in the initial network namespace, fanotify access to the
workload mount, cgroup v2 CPU/memory/task controllers, network namespaces and
UID firewall rules, synchronized time and working audit capture. The detailed
requirements are in [BANK_PILOT_DEPLOYMENT.md](BANK_PILOT_DEPLOYMENT.md). A
separate collector trust domain is a custody requirement, not a prerequisite
for executing the clearly labeled local-isolation profile.

The initial public local model needs no API credential and incurs no cloud API
spending. If a different remote model is used, require approved restricted
secrets, exact model/endpoint configuration, expiry, a tested hard spend limit
and controlled egress. Never substitute a canned response when access fails.

No extra dashboard, blockchain component or agent-identity protocol is needed
for the first integration. The remaining work concerns existing trust-boundary
connections and execution/operational evidence.
