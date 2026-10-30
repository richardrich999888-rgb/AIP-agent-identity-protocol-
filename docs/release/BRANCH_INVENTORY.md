# Branch inventory (A1)

Generated 2026-10-30 against `origin/fix/vanian-end-to-end-green` @ `4d0ce1e`
(the RC line; production sources identical to validation candidate `9ed1662`).
"Ahead" = commits on the branch not reachable from that head; "patch-unique" =
`git cherry` `+` lines (work not present under another SHA).

Reproduce:

```sh
F=origin/fix/vanian-end-to-end-green
for b in $(git branch -r | grep -v HEAD); do
  echo "$b ahead=$(git rev-list --count $F..$b) behind=$(git rev-list --count $b..$F)"
done
git cherry $F <branch>
```

No branch is deleted by this item. Every **Retire** below is a recommendation
that needs the owner's explicit approval (loop rule 7).

## Branches with work not in the RC line (5)

| Branch | Head | Date | Ahead | Purpose | Recommendation |
|---|---|---|---|---|---|
| `integration/snifferdog-complete-enterprise-validation` | `57ac0d1` | 10-29 | 5 (all patch-unique) | Genuine execution proofs and container observation boundaries (`7625b1d`), bounded exec-witness acquisition + native JSON agent output (`e4cd07d`), receipt state across ContextForge manager refresh (`8d38d77`), verified core execution + component CI evidence (`d5c39dd`), bounded Agent Zero diagnostics (`57ac0d1`) | **Merge** — A2, reviewed merge commit |
| `claude/strategic-validation-loop` | `504c15b` | 10-29 | 9 | Strategic validation programme: connector-first drain + collector previous-batch divergence carry (`5b146be`), worker-thread binding + inter-batch drain + honest lineage gate (`5590075`), M1–M3 evidence | **Merge (reconcile)** — A3. `5b146be`'s drain-order/carry overlaps `9ed1662` repair 4 (bounded queue, monotonic cutoff, 50 ms holdback) in the same files. Keep one boundary mechanism with both regression suites passing; the thread-binding fix is independent and must be kept |
| `claude/real-agent-acceptance-n5ysvd` | `2052a25` | 10-29 | 10 (9 patch-unique + 1 merge) | Real-agent acceptance package; runtime kernel-capability probes (`fd61cab`); console/readback failure diagnostics; interference repro build fix | **Cherry-pick** its 9 own commits in A3. Do not merge the branch: it sits on an older PR #12 base (`a6da6e5`, two merge bases with the RC line) and merges an *earlier* snifferdog head, so a branch merge would re-introduce superseded versions (e.g. `sdk/typescript/*`) |
| `codex/val-ladder-sync` | `ae46a3a` | 06-03 | 29 (contains all of `codex/aip-v4-accountability`) | June pre-`main` line: AEGIS/PQC "TRL-4/5" crates (`aegis-quantum`), hybrid PQC paths, agent passport, Python SDK integrations, chaos harness, validation ladder, **pitch decks, founder details, website preview** | **Owner decision required** — excluded from the RC by default. It contains branding/marketing and post-quantum claims that this codebase's own rules prohibit without implementation evidence. Not merged, not deleted, until the owner decides |
| `codex/aip-v4-accountability` | `73bf70c` | 06-03 | 7 | AIP v4 accountability protocol, EvidencePacket viewer, AEGIS PQC/eBPF/TRL work | **Subsumed** by `codex/val-ladder-sync` (all 7 commits contained); same owner decision |

## Branches fully contained in the RC line (14) — no unique commits

| Branch | Head | Date | Behind RC | Recommendation |
|---|---|---|---|---|
| `main` | `872dbf3` | 06-19 | 420 | Target of A5 PR. **Keep** |
| `integration/vanian-enterprise-service-delivery` | `a933fdc` | 10-28 | 24 | Base of PR #12. **Keep** until PR #12 is resolved |
| `feature/vanian-agent-governance-interoperability` | `9d52c68` | 10-28 | 46 | Retire (contained) |
| `feature/customer-service-delivery-model` | `52a1883` | 10-28 | 48 | Retire (contained) |
| `feature/snifferdog-enterprise-integration` | `bd15b8e` | 10-28 | 62 | Retire (contained) |
| `codex/snifferdog-real-agent-swarm-validation` | `65b6ff7` | 10-28 | 63 | Retire (contained) |
| `codex/rbi-demo-preflight-2026-10-27` | `0991fb1` | 10-27 | 90 | Retire (contained) |
| `codex/accountability-test-gaps-2026-10-20` | `65eb9e6` | 10-20 | 94 | Retire (contained) |
| `claude/skill-25-implementation-xbz0t3` | `061cebc` | 10-26 | 81 | Retire (contained) |
| `claude/aip-security-architecture-audit-zpf9b3` | `4ee05ea` | 09-21 | 98 | Retire (contained) |
| `claude/codebase-production-readiness-wm6idp` | `4ee39f3` | 09-17 | 184 | Retire (contained) |
| `claude/vanian-audit-maturity-addendum-n5ysvd` | `e05ec3b` | 09-14 | 185 | Retire (contained) |
| `claude/autonomous-accountability-skills-16-30` | `27610ad` | 09-07 | 259 | Retire (contained) |
| `import/orbitaltrust-accountability-layer` | `6cc439f` | 08-28 | 419 | Retire (contained) |

Plus this loop's working branch `claude/release-completion-loop` (`c6efee1`,
1 ahead: the checklist).

## Consequences for A2/A3

1. A2 merges 5 commits, not a broad divergence.
2. A3 order: (a) cherry-pick the 9 `real-agent-acceptance` commits;
   (b) reconcile the strategic-loop probe changes with repair 4 as a
   deliberate design change with both regression suites;
   (c) `codex/val-ladder-sync` only if the owner opts in.
3. Containment means the 14 retire candidates lose no work if deleted. Their
   open PRs, if any, should be checked before deletion.
