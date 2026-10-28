# Enterprise delivery inventory — 28 October 2026

Inventory recorded before implementing this delivery increment. GitHub was refreshed at the start of the assignment. No PR is merged into main.

| Work | Exact head / actual base | Reuse decision |
|---|---|---|
| Draft #6 | `65b6ff7fdad5ae70546a57216a497399091c7dc7` / `claude/skill-25-implementation-xbz0t3` at `061cebc975d81c8126d5f66d96f5384d11be0620` | Already preserved by #8; retain real-agent harness and startup race fix |
| Draft #7 | `bd15b8e627e5ef67ba259559ed81feb6894cde48` / `codex/snifferdog-real-agent-swarm-validation` at `5489260b96124b95a7973233e69d9e5a44cb6bf5` | Already preserved by #8; reuse all enterprise interfaces and packaging |
| Draft #8 | `e3aa195def7524d6ec84d37a934beebe18b6c794` | Combines #6 and #7; same-run institutional acceptance remains open |
| Draft #9 | `9d52c68c93e634479dd82b012f7ef941b796d551` / #8 | This integration starts here; preserve native authority verifier, genuine ADK/A2A/ACS/gateway evidence and uncertainty |
| Draft #10 | `52a18830f6607ac6677e6fcbb6f6a085ac5d413f` / `feature/snifferdog-enterprise-integration` at `bd15b8e627e5ef67ba259559ed81feb6894cde48` | Import its ten exact file blobs, retaining the existing planner, posture report and tests; reconcile on `integration/vanian-enterprise-service-delivery` |

| Product / source | Already implemented and tested | Missing or blocked before this increment |
|---|---|---|
| `aip-probe`, `aip-transport` | Linux sensors, pinned Noise transport and probe authentication; historical Linux evidence | Fresh observation blocked here: process metadata, sensor capabilities and tracefs unavailable; no same-run inference from old archives |
| `aip-collector`, `aip-observe-verify` | Collector-owned wrapped-file signing, sequence/continuity, signed health and offline verification | No second independently administered host; no validated daemon HSM backend, HA or bounded worker pool |
| `aip-authorize`, `aip-reconcile` | Native signatures, delegation, evidence/coverage-aware verdicts; exact offline authority-reference verifier | No institutional same-run authority/collector/kernel join for the live model operation |
| `deploy/enterprise/linux/package.py`, pilot systemd units | Deterministic verified tar, ELF guard, strict config, role-separated staging install, retained-data uninstall; 16 fixture packaging tests | No DEB/RPM distribution or clean supported host installation; no runtime package release signature |
| `deploy/enterprise/kubernetes` | Default-disabled Helm, immutable images, explicit separate-admin assertion and retained PVC; historical lint/render | No built runtime image or qualified cluster/kernel combination; containers do not prove separate administration |
| `integrations/mcp-gateway` | Actual ContextForge, MCP server and model calls; real forwarding and offline-verified native receipts; adversarial checks | Institutional authorization and supported logical-agent binding remain incomplete; compatibility only for tested profiles |
| `aip-service`, `docs/enterprise/openapi.yaml` | Existing authenticated tenant-scoped API, RBAC, bounded reads, archive admission/verification, console; real HTTP/SDK/MCP fixture tests | No fresh same-run evidence; no distinct deployment enrollment registry; API health is not live signed coverage |
| `sdk/python`, `sdk/typescript`, `integrations/evidence-mcp` | Typed/scoped retrieval and official MCP-client tests; bounded transports and credential callbacks | Registry publication/release approval; actual same-run retrieval acceptance |
| `integrations/service_delivery` (#10) | Offline planning and Reader posture summary, 22 unit contracts | No installable onboarding bundle or authenticated assurance progression; configuration never establishes runtime assurance |
| Console / existing SIEM outputs | Existing real API console and sentinel/CEF references | Same-run population, institution operations and performance qualification |
| Network connector | No vendor-neutral authenticated ingestion implementation in these branches | Remains deferred behind execution/install/onboarding priorities; no vendor certification, TLS interception or network-only execution proof |

Current host prerequisite check was executed again and failed closed. It captured no kernel events and signed no observation evidence. The requested two-host execution and clean-host installation cannot be completed in this workspace. Runnable delivery components can still be built and their package/onboarding/security behavior tested, while those acceptance gates stay open.

WitnessAI's public platform brief describes network connectors, APIs and deployment choices. This assignment reuses those customer delivery principles only; no proprietary source or interface is imported. See the sourced comparison retained from #10 in `SERVICE_DELIVERY_MODEL.md`.
