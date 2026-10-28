# VANIAN strategic validation — engineering baseline

Source-grounded. Every claim here was read from the repository or measured on
this host, not taken from the directive or a README.

## What this invocation is validating

- **Branch:** `claude/strategic-validation-loop`, created from the most
  complete development branch found on the remote:
  `origin/integration/snifferdog-complete-enterprise-validation`.
- **Commit:** `4ca5a4d` ("Retain genuine coverage failure and fail-closed
  kernel query diagnostics"), 2026-10-29 — the newest and most complete head.
- **Workspace:** 54 members (`aip-standalone/Cargo.toml`).

## How the branches actually line up (vs. the directive's assumptions)

The directive referenced PRs #5–#11 and claimed directories
(`integrations/real_agents`, an MCP gateway, SDKs). The session was initially
dropped on a **stale checkout at `872dbf3`** (the main merge) with only 8
crates in `aip-standalone` and no `validation/`, `integrations/` or Sniffer Dog
crates at all. That checkout is **not** the product; it is an early main.

Survey of the real remote branches (read with `git ls-tree`, not assumed):

| Branch | Head | Date | real_agents | mcp-gateway | Completeness |
|---|---|---|---|---|---|
| `integration/snifferdog-complete-enterprise-validation` | `4ca5a4d` | 2026-10-29 | yes | `aip-mcp-gateway` | **most complete (base used)** |
| `codex/snifferdog-real-agent-swarm-validation` | `65b6ff7` | 2026-10-28 | yes | yes | complete |
| `feature/snifferdog-enterprise-integration` | `bd15b8e` | 2026-10-28 | yes | yes | complete |
| `codex/rbi-demo-preflight-2026-10-27` | `0991fb1` | 2026-10-27 | partial | yes | complete-ish |
| `claude/codebase-production-readiness-wm6idp` | `4ee39f3` | 2026-09-17 | **no** | no | superseded (33 crates) |
| `codex/val-ladder-sync` | `ae46a3a` | 2026-06-03 | no | no | early (8 crates) |

Unmerged work is preserved: I branched *from* the integration head and modified
nothing on the source branches.

## Host and kernel — the observation ceiling

Measured on this host:

- Kernel `6.18.44-fc-v180`, root.
- **`# CONFIG_KPROBES is not set`** — kprobe-based eBPF kernel-function
  observation (Tetragon-class) is impossible here, exactly as in prior
  sessions. `/sys/kernel/tracing/kprobe_events` is absent.
- `CONFIG_UPROBE_EVENTS=y`, `CONFIG_FTRACE_SYSCALLS=y`, tracefs mounted.

**Consequence:** Sniffer Dog's `aip-probe` sensors in scope here are
`sched` (fork/exec), `sockstate`, `socksend`, `connector` (netlink) — all
`perf_event_open` tracepoints or netlink, none kprobe-dependent, so they run.
This is sufficient for the Phase 1 real-agent observation chain. Any claim that
would need kprobes (certain syscall-level attribution) is out of reach on this
kernel and must be marked BLOCKED, not asserted.

## The real-agent harness that actually exists

`integrations/agents/` — a genuine Phase 1 harness, read in full:

- **Subject:** `agent_subject.py` — a real **LangGraph** agent, `plan → act →
  report`. By deliberate design it uses **no LLM** (pure-Python graph nodes),
  because the observer watches execution from the kernel, not model I/O; the
  explicit graph is the independent ground truth. The `act` node spawns
  `child_action.py` as a **real separate process** that writes a marked file
  and opens one outbound TCP connection.
- **Observation:** `aip-probe` (holds no key) → `aip-collector` (holds the only
  key, wrapped at rest; Noise_NK confidential transport) → signed
  attested-batch archive.
- **Offline verification:** `aip-observe-verify` — separate binary, given two
  files and the published `observer.pub`, no network, no trust in the daemon.
- **Lineage (Phase 3 partial):** `aip-lineage` re-verifies the archive under
  the anchor, then derives start-verified parent→child edges; fails closed.

The harness is explicit about what it does and does **not** prove: it stops at
"the real agent's execution is in the signed evidence and verifies offline"
plus observed lineage. The `VERIFIED_EXECUTION` reconciler verdict (join against
a signed `ExpectedExecution` from a decision point) is Phase 3 proper and is
**not** claimed by this script.

There is a **pre-existing sealed results bundle** at
`integrations/agents/results/sealed/`. Per the anti-fabrication rule, it is
treated as historical and is **not** evidence of a live run; this invocation
re-runs the harness from scratch and keeps the fresh output separate.

## What can and cannot run in this environment

- **CAN:** build the four Rust binaries; create the pinned langgraph venv
  (pypi reachable); run the Phase 1 harness end to end (root + tracefs +
  working perf/netlink sensors).
- **CANNOT without external provision:** a genuinely *model-backed* agent task
  (no LLM credentials, no local model) — but the Phase 1 harness is designed to
  not need one, so this does not block Phase 1. A kprobe-dependent observation.
  An independently administered off-host collector (the collector here runs on
  the same host, in a separate process holding the only key — process-separated,
  not host-separated; that distinction is kept honest in the readiness files).

## First test selected for execution

`integrations/agents/run.sh` — the Phase 1 real-agent observation + offline
verification + lineage chain, re-run live on `4ca5a4d`. It is the smallest
genuine autonomous-agent workload that actually runs here and exercises the
authorization-free observation half of the evidence chain end to end.

Status of everything else is tracked in `STATUS.json` / `TEST_MATRIX.csv` and
is `NOT_RUN` until actually executed.
