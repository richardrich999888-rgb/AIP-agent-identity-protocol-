# Security, privacy and assessment boundaries

The initial runtime deployment is OBSERVER_ONLY. No containment daemon,
process kill, firewall change, banking data mutation or transaction gate is
installed. Monitoring failure withdraws evidence coverage; it must not become
a fabricated execution or unauthorized-activity finding.

## Authorities and credentials

The monitored workload cannot possess the collector's signing authority. The
probe holds only its transport-authentication key. Pin collector transport and
evidence public keys independently; they serve different purposes. The
collector daemon uses wrapped-file custody today. PKCS#11/SoftHSM mechanisms
elsewhere in the repository do not establish this daemon's bank HSM/KMS
integration, certification or key ceremony.

Reader credentials can query scoped metadata, verification and existing
signed verdicts. A service middleware denies mutation and raw packet/archive
retrieval/export to Reader, including future mutation routes. Machine and
Admin remain broader legacy roles; fine-grained per-workload ABAC, OIDC/mTLS,
immediate hot credential reload and institutional enrollment are not completed
by this change. API keys are hashed at rest. Rotate through an approved file
replacement and service restart, testing new/old credentials separately.

Collector archive anchors are configured per tenant/observer/key version on
the service, never accepted from an uploader. Legacy signed-verdict filing
uses submitter-supplied reconciler anchors; an institution must independently
approve the anchors before treating a filed verdict as its own authority.
MCP cannot file artifacts, configure anchors, export raw records or call an
arbitrary URL. Stdio launcher ownership and a dedicated Reader credential
form its local trust boundary. There is no remote shared MCP authorization
implementation.

## Network and denial of service

Use reviewed institutional TLS ingress. The service's existing ingress limits
bound body size, in-flight work and timeouts; per-client rate limiting and
slow-client protection belong at the institutional reverse proxy. The example
client always validates TLS, refuses redirects and bounds reads/timeouts.
The collector's thread-per-connection design, missing durable probe resend
buffer and evaluation-scale API tenant scans remain capacity/availability
limitations. Systemd resource limits do not prove an application worker pool
or zero event loss. Restrict collector ingress to approved probe hosts and
watch signed health for gaps.

## Data boundaries

No model prompts/responses or transaction payloads are collected by default
by the kernel sensors. Paths, hashes, process/container identities, network
endpoints and file metadata can still be sensitive. Current sensor scope is
host-wide rather than a per-agent process allowlist. Approve host, interface,
mount and retention scope before starting. The local loan example contains
only synthetic test data; its model text is test application output, not
independent evidence.

The console stores its Reader token only in memory, serves a restrictive CSP,
uses textContent for records, omits credentials from URLs and offers no raw
export. Server read audit logs record tenant/key IDs, route templates and
status rather than transaction bodies or secrets. Secure logs with the same
institutional access/retention policy as the records they describe.

Institution-owned encryption at rest, encrypted off-host backups, legal-hold
procedures, secure deletion approvals and data residency must be provisioned
by the deployment owner. Application-level database encryption is not claimed.
The software uninstall preserves keys, evidence and configuration.

## Supply chain and independent review

Cargo uses one locked workspace. The real gateway test pins ContextForge's
source revision and upstream dependency lock. MCP has an exact tested Python
dependency lock; an air-gap operator must acquire matching platform wheels
and independently approve checksums/provenance. Runtime packages are verified
against an independently approved digest and manifest. They are not currently
published/signed by the repository's existing Sigstore release workflow.

Existing audit/deny/gitleaks/trivy workflows are source artifacts, not a claim
that this branch's scans or an image scan passed. A bank must retain actual
dependency/SBOM/license and image scan results for its release. No independent
security assessment, certification, regulatory approval, production HSM
qualification or two-host institutional deployment was performed by these
local tests. Provide the source commit, exact reproduction commands, signed
test evidence, threat boundaries, findings/remediation and the known gaps to
a qualified assessor before a regulated rollout.
