# P0-057 baseline audit — 14 November 2026 IST

Status: research/evaluation; enterprise acceptance NOT MET.

The verified default branch is `main` at `872dbf375838cff464eb019488c63d948015e9b8`.
It lacks the combined enterprise work. The new branch
`codex/p0-057-independent-agent-assurance` starts at P0-048 PR #20 head
`61dd73013d02ea7869de104d953f330098df1c32` (tree
`c2a7ad38b63d94b61b765a88b313c4283694c564`). This preserves its five commits
above PR #12. Fresh clone was clean before branch creation; no existing
uncommitted work was present. No branch was merged, overwritten or force-pushed.

All 40 advertised remote heads and all PR head refs were fetched. The connected
provider returned 18 open PRs in one page of 100. The reproducible inventory
indexes every captured tree and parses/hashes dependency manifests, build and
deployment configurations, license policies and upstream locks across all 40.
It contains 305 unique configuration objects. Targeted human review follows
process measurement, lifecycle/socket attribution, authority, same-run
composition, signed archive verification, packaging, CI and prior qualification.
This is a complete structural inventory of the captured refs, not a claim of
exhaustive vulnerability discovery or manual line-by-line review of all code.

## Reconciled P0-048 evidence

PID/start/boot identity, pidfd checks, signed collector archives, coverage checks,
socket deduplication and stale connector-event refusal already exist. They must
be reused. The prior native qualification executed ten exact Linux assertions
and checked two signed archives; its fixture clock/custody limits remain.

Fresh provider inspection of exact base `61dd730` found:

| Workflow run | Outcome |
|---|---|
| [43168207745](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/43168207745), full CI | success |
| [43168207575](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/43168207575), required native qualification | success |
| [43168207586](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/43168207586), same-run assurance | success |
| [43168207704](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/43168207704), RBI rehearsal | success |
| [43168207563](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/43168207563), harness contracts | success |
| [43168207784](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/43168207784), Security | failure; Gitleaks and Trivy failed, dependency audit passed under existing policy |

These are existing provider results, not fresh P0-057 executions. They supersede
the older P0-048 report's pending status only for these exact runs.

## Priority gaps

1. Executable measurement/cache consistency: `readlink`, path metadata and a
   separate path reopen for hashing can straddle exec in the same live PID.
   Cache comparison omits device ID and change time. Reproduce before fixing.
2. Logical agent identity remains distinct from process identity; same-interpreter
   concurrent agents require verified launch/request commitments, not PID labels.
3. Existing same-run evaluation preserves `CannotProve / ActionEvidenceUnavailable`
   for the tool effect despite signed authority, gateway agreement and process
   matches. Do not promote this to proof of a file/network business action.
4. Collector/probe share administrator/root in retained hosted evidence.
   Two-host independent administration, key custody and external acceptance are
   unavailable. Remote replay alone cannot close this gap.
5. Security findings, full discovery/overhead matrix, clean customer-host install,
   upstream task acceptance and live five-scene demonstration remain open.

## Evidence and ownership

[`validation/p0_057/iteration-001`](../../validation/p0_057/iteration-001) contains
captured refs, PRs/workflows, ancestry/overlap, deterministic compressed inventory,
original command output and toolchain provenance. `audit.py --refs` reproduces
the inventory without trusting moving refs. Older evidence remains untouched.

The root workspace declares `LicenseRef-Proprietary`; repository visibility is
not a redistribution license. Existing VANIAN native authority/observation and
enterprise adapters are the foundation. SYNTRIASS AIRON teaching/native-runtime
work on #21/#22 is a separate product boundary and is not imported here.
Upstream license declarations/pins are recorded, not a legal ownership or vendor
endorsement determination. Current advisory clearance and institutional identity
enrollment have not been established by this audit.
