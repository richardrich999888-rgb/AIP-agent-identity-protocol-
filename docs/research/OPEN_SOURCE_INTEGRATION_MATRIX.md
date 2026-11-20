# Open-source integration matrix (enterprise WOW loop, item 1.1)

Surveyed 20 Nov 2026 from the cloud session container. **Every pin, license
class and directory below comes from `research/oss/survey.json`**, produced by
`python3 -I research/oss/survey.py research/oss/survey.json` (exit 0, 17/17
candidates resolved). That script resolves each release tag to a commit with
`git ls-remote`, fetches that commit's tree with `--depth 1
--filter=blob:none`, and hashes and classifies every license file by fixed
signature strings. Its pure functions have 15 unit tests (`research/oss/test_survey.py`, 15 passed).

Architecture and security wording is quoted or paraphrased from each
project's README **at the pinned commit**, read from that fetch. Nothing here
was taken from memory. Where a fact was not checked, the cell says so.

What this item did **not** do: run any project's tests (that is 1.2 for OPA,
1.3 for LiteLLM, 1.4 for the P2 set), or obtain legal advice. A license
"class" is a signature match on the file text, not a legal opinion.

Network limits that shaped the method: `github.com` web pages and
`api.github.com` return 403 through this container's proxy, while `git` over
HTTPS, `raw.githubusercontent.com` and PyPI work. GitHub release metadata
(release notes, "latest" flags, stars) was therefore not read; "release"
means the newest stable-looking tag, cross-checked with PyPI where the
project publishes there (LiteLLM 1.110.2, OpenLIT 1.45.0, Phoenix 22.0.0 all
match).

## "OpenLoop": not identified unambiguously

A web search finds at least two unrelated projects with this name:
`openloop-team/openloop` ("the open-source control plane for shared AI
agents") and openloop.sh (an agent that controls a Windows PC from a phone).
Neither is a known governance component. The first is the closer match and
is surveyed below, flagged **AMBIGUOUS**. Whoever wrote the brief should say
which project was meant.

## Ranking for this demo

The criterion is fit for an **offline, single-host lab** that needs policy
enforcement (P0), usage and cost capture (P0), and optional telemetry export.
Footprint and license constraints weigh as much as features.

| Rank | Project | Verdict | Why, in one line |
|---|---|---|---|
| 1 | OPA | **ADOPT (P0)** | Apache-2.0, one Go binary, no datastore. It decides; our gateway must enforce. |
| 2 | LiteLLM (core) | **ADOPT core only (P0)** | MIT core. `enterprise/` is under a separate license that forbids production use without a subscription. Postgres-free cost capture is unproven until 1.3. |
| 3 | OpenTelemetry Collector | DEFER to 1.4 (P2) | Apache-2.0 Go binary. Useful only as an export pipe; the demo does not need it to work. |
| 4 | OpenInference | DEFER (P2) | Apache-2.0 instrumentation packages. Relevant only if 4.x adds a framework agent. |
| 5 | OpenLLMetry | DEFER (P2) | Apache-2.0. Overlaps OpenInference. Pick one if 4.x needs instrumentation. |
| 6 | Falco | DEFER to 1.4 (P2) | Apache-2.0. Kernel driver or eBPF probe. Overlaps Sniffer Dog; useful as an independent second witness. |
| 7 | OpenLIT | DEFER to 1.4 (P2) | Apache-2.0, but the platform's compose needs ClickHouse. |
| 8 | SPIRE | REFERENCE ONLY | Apache-2.0 workload attestation. It overlaps AIP identity and ExecutionBinding; integrating it is not a weekend task. |
| 9 | OpenFGA | REFERENCE ONLY | Apache-2.0. Its compose uses Postgres. Relationship-based authorization is not on the P0 path. |
| 10 | Docker MCP Gateway | REFERENCE ONLY | MIT. A docker CLI plugin that runs each MCP server in a container. A design reference for isolation, not a replacement for our gateway. |
| 11 | Microsoft MCP Gateway | REFERENCE ONLY | MIT, .NET. Its README's architecture diagram places it in a Kubernetes cluster. |
| 12 | MCP Context Forge (IBM) | REFERENCE ONLY | Apache-2.0, Python 3.12+. Broad scope (tools, agents, REST, A2A). Too large to adopt in the window. |
| 13 | Lasso MCP Gateway | REJECT | MIT, small (43 files). The latest tag's commit is dated 24 Dec 2025, the oldest in the set. |
| 14 | Langfuse | REJECT for this demo | MIT core plus `ee/` under an enterprise license. Its compose needs Postgres, ClickHouse, Redis and MinIO. |
| 15 | Arize Phoenix | REJECT for embedding | The server's `LICENSE` is Elastic-2.0, which forbids offering it as a hosted or managed service. Its client and OTel packages are Apache-2.0. Local use is allowed. |
| 16 | OpenLoop (`openloop-team`) | NOT RELEVANT (AMBIGUOUS) | An agent runtime (Postgres + Redis), not a governance or monitoring component. |

On "replace our gateway": the plan carries forward a governed MCP gateway
from P0-059. Its properties (SO_PEERCRED binding, signed requests, exact-call
allowlist) are **not re-verified here**, because P0-059 is not on the remote
(item 0.1). No surveyed gateway was checked for equivalent properties either.
The REFERENCE ONLY verdicts mean "read for design ideas", not "known to be
weaker".

## Per-project record

Effort is an **estimate** to a working integration in this lab, not a
measurement. Commit dates are the pinned commit's committer date.

### OPA

| Field | Value |
|---|---|
| Repository / pin | `open-policy-agent/opa`, tag `v1.22.4`, commit `ba39415db4b3` (2026-11-12) |
| License | `LICENSE`: Apache-2.0. Vendored internals under `internal/`: BSD and Apache-2.0. `internal/providers/aws/NOTICE.txt` (AWS SDK notice) must be kept with redistributed binaries. |
| Obligations | Apache-2.0: keep the license and NOTICE files and state changes. No enterprise directories. |
| Architecture | Go (`go 1.26.0` in `go.mod`). General-purpose policy engine; policies in Rego. |
| Security model | README: "Your service _enforces_ the decisions by accepting or rejecting requests accordingly." OPA only decides. **Without an enforcement point in our code, an OPA integration is ADVISORY, not PREVENTION.** |
| Dependencies / local | Single binary; no datastore. |
| Effort (estimate) | Small: run as a sidecar or library and call it from the gateway's decision path. |
| Maintenance risk | Low: CNCF graduated (README); pinned commit is 8 days old. |
| Tests run | None in 1.1. Item 1.2 runs them. |

### LiteLLM

| Field | Value |
|---|---|
| Repository / pin | `BerriAI/litellm`, tag `v1.110.2`, commit `c3cafa378264` (2026-11-19). Equal to the PyPI version. |
| License | `LICENSE`: MIT. **`enterprise/LICENSE.md`: "The BerriAI Enterprise license"** (unrecognised by signature; read in full). Sub-packages `litellm-proxy-extras` and `vscode-extension` are MIT; `terraform/provider` is Apache-2.0. Two `license_cache.json` files matched the GPL signature: they are license-checker data, not the project's license. |
| Obligations | MIT core: keep the notice. The enterprise license says the software "may only be used in production" under a BerriAI subscription. It allows copying and modification "for development and testing purposes" without one, and forbids distribution. **Rule for this loop: import nothing from `enterprise/`.** Any feature that needs it is out of scope. |
| Architecture | Python (`>=3.10, <3.16`). Two modes: an SDK and a proxy server ("AI Gateway"). |
| Security model | README: virtual keys, spend tracking and guardrails in the proxy. Whether any of these work without Postgres is **not established** (1.3). |
| Dependencies / local | `docker-compose.yml`: litellm, db (Postgres), prometheus. |
| Effort (estimate) | Small for the SDK path; medium if the proxy needs Postgres. |
| Maintenance risk | Medium: very high release rate (1,664 tags); enterprise gating can move features out of the MIT core between versions. Pin exactly. |
| Tests run | None in 1.1. Item 1.3 runs them. |

### OpenTelemetry Collector (core and contrib)

| Field | Value |
|---|---|
| Repository / pin | `open-telemetry/opentelemetry-collector` `v0.165.0` `e883d737e499` (2026-11-06); `-contrib` `v0.165.1` `6083b2c53d78` (2026-11-09) |
| License | Apache-2.0 for both; contrib has a `NOTICE`. |
| Architecture | Go (`go 1.26.0`). Pipeline of receivers, processors and exporters. |
| Dependencies / local | Single binary per distribution. |
| Effort (estimate) | Small as an OTLP fan-out. |
| Maintenance risk | Low (CNCF). Pre-1.0 version numbers: configuration can change between minors. |
| Tests run | None. |

### Falco

| Field | Value |
|---|---|
| Repository / pin | `falcosecurity/falco` `0.45.2` `7625e203c17c` (2026-10-29) |
| License | `LICENSE` and `COPYING`: Apache-2.0. |
| Architecture | C++. README: "a kernel monitoring and detection agent that observes events, such as syscalls, based on custom rules". Drivers live in `falcosecurity/libs`, not surveyed. |
| Dependencies / local | A kernel driver or eBPF probe, root. 0.4 found tracefs absent by default in this container. Falco's own driver was **not** tried. |
| Effort (estimate) | Medium. |
| Maintenance risk | Low (CNCF graduated, README). |
| Tests run | None. 1.4 if time permits. |

### OpenLIT

| Field | Value |
|---|---|
| Repository / pin | `openlit/openlit` `py-1.45.0` `fcebb5543846` (2026-08-02). The Python SDK tag; equal to PyPI. The platform is tagged separately (`openlit-2.2.0`) in the same repository. |
| License | Apache-2.0: root, `sdk/python`, `sdk/typescript`. |
| Architecture | TypeScript platform plus Python and TypeScript SDKs. README: "OpenTelemetry-native Observability SDKs". |
| Dependencies / local | `docker-compose.yml`: clickhouse, openlit. |
| Effort (estimate) | Medium (ClickHouse). |
| Maintenance risk | Medium: the SDK tag is 3.5 months older than the others. |
| Tests run | None. |

### Langfuse

| Field | Value |
|---|---|
| Repository / pin | `langfuse/langfuse` `v4.83.0` `fe82bdc24d3b` (2026-11-19) |
| License | `LICENSE`: MIT. **`ee/LICENSE`: Langfuse Enterprise license** (read in full). Its preamble says the MIT core "can be used and run without infringing" it. Enterprise directories: `ee`, `web/src/ee`, `worker/src/ee`. |
| Obligations | The enterprise license requires an agreement with Langfuse GmbH or ClickHouse, Inc. for use. It allows copying and modification for development and testing. |
| Dependencies / local | `docker-compose.build.yml`: langfuse-web, langfuse-worker, langfuse-ai-gateway, clickhouse, minio, redis, postgres. |
| Verdict reason | Four backing services for a trace viewer the demo does not need. |
| Tests run | None. |

### Arize Phoenix and OpenInference

| Field | Value |
|---|---|
| Phoenix pin | `Arize-ai/phoenix` `arize-phoenix-v22.0.0` `7efbcc340104` (2026-11-19). Equal to PyPI. |
| Phoenix license | Root `LICENSE` and `packages/phoenix-evals/LICENSE`: **Elastic-2.0**. Its limitations include: "You may not provide the software to third parties as a hosted or managed service". `packages/phoenix-client`, `packages/phoenix-otel` and the `js/packages` CLI, config and evals: Apache-2.0. `packages/phoenix-sqlean/LICENSE`: unrecognised (a copyright header; not read further). |
| Phoenix local | Python `>=3.11, <3.16`. `docker-compose.yml`: phoenix, db. |
| OpenInference pin | `Arize-ai/openinference`, default-branch head `74b34f9343b1` (2026-11-19). A monorepo of per-package tags, so no single release applies. |
| OpenInference license | Apache-2.0: root and every surveyed package `LICENSE` (38 files). |
| Tests run | None. |

### OpenLLMetry

| Field | Value |
|---|---|
| Pin | `traceloop/openllmetry` `v0.63.1` `864f85910812` (2026-11-16) |
| License | Apache-2.0. |
| Architecture | Python instrumentation for LLM SDKs over OpenTelemetry. README: its semantic conventions "are now part of OpenTelemetry". |
| Tests run | None. |

### SPIRE

| Field | Value |
|---|---|
| Pin | `spiffe/spire` `v1.16.0` `872c1d55b4d5` (2026-11-05) |
| License | Apache-2.0. |
| Architecture | Go (`go 1.27.3`). README: "a toolchain of APIs for establishing trust between software systems"; exposes the SPIFFE Workload API. |
| Verdict reason | Workload attestation overlaps AIP identity and ExecutionBinding. A real integration means server, agent and attestor plugins: weeks, not a weekend. |
| Tests run | None. |

### OpenFGA

| Field | Value |
|---|---|
| Pin | `openfga/openfga` `v1.22.1` `44054f542f64` (2026-10-28) |
| License | Apache-2.0. |
| Architecture | Go (`go 1.26.0`). README: an authorization engine "inspired by Google Zanzibar". |
| Dependencies / local | `docker-compose.yaml`: postgres, migrate, openfga. Other datastores were not checked. |
| Tests run | None. |

### MCP gateways

| Project | Pin | License | Architecture (README at pin) | Local |
|---|---|---|---|---|
| Docker MCP Gateway | `docker/mcp-gateway` `v0.44.3` `7e0f34277c91` (2026-10-26) | MIT | Go (`go 1.26.10`). A docker CLI plugin; "each local MCP server … runs in an isolated Docker container". Secrets through Docker Desktop. | Docker daemon (works here per 0.4) |
| Microsoft MCP Gateway | `microsoft/mcp-gateway` `v1.0.1` `6485ecb51543` (2026-11-16) | MIT (`NOTICE` is Apache-2.0 text) | C#. "Each request carries its protocol metadata and is independently authorized"; the architecture diagram places it in a Kubernetes cluster. | .NET + Kubernetes (not checked here) |
| MCP Context Forge | `IBM/mcp-context-forge` `v1.1.1` `dbc643befb6f` (2026-11-10) | Apache-2.0 | Python (`>=3.12,<3.15`). Tools gateway, agent gateway (A2A), REST gateway with "rate limiting, auth, retries", OTel tracing. | Several compose files (nginx, gateway, pg-upgrade) |
| Lasso MCP Gateway | `lasso-security/mcp-gateway` `v1.2.0` `c8b73bb4e022` (2025-12-24) | MIT | Python (`>=3.10`). Reads `mcp.json`; plugins, including a "basic guardrail for token masking". 43 files. | pip |

None was run in 1.1.

### OpenLoop (AMBIGUOUS)

| Field | Value |
|---|---|
| Pin | `openloop-team/openloop` `v0.1.1` `c96ac3c32029` (2026-09-01); 5 tags in total |
| License | Apache-2.0. |
| Architecture | Python (`>=3.11`). README: "Persistent, asynchronous teammates … each with their own memory, tools, model policy, budget, approval rules, and audit trail." |
| Local | `docker-compose.yml`: postgres, redis, runtime. |
| Verdict reason | It is an agent platform. It could serve as a *subject* the console observes, not as a component of the console. Early-stage (v0.1.x). |

## Consequences for the loop

- **1.2 (OPA)** proceeds: pin `v1.22.4` / `ba39415db4b3`. Prefer the release binary with its published checksum. Building from source needs Go 1.26, which is not checked here.
- **1.3 (LiteLLM)** proceeds: pin `litellm==1.110.2`. Hard rule: no import from `enterprise/` or `litellm_enterprise`.
- **1.4**: the candidates are OTel Collector, Falco and OpenLIT, in that order, only if Phase 1 is done by Sat 06:00 IST.
- Everything marked REFERENCE ONLY, REJECT or NOT RELEVANT is out of the build.
