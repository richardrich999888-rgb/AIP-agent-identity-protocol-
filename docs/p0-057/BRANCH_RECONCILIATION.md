# P0-057 branch reconciliation

Pinned baseline: `61dd73013d02ea7869de104d953f330098df1c32`.
All references below were captured on 14 November 2026; moving branches may advance.
No automatic merge is authorized by this report.

| Workstream | PR and captured head | Relation to baseline / disposition |
|---|---|---|
| P0-048 | #20 `61dd73013d02ea7869de104d953f330098df1c32` | Exact base; preserve native fixes and all failures |
| Enterprise integration | #7 `bd15b8e627e5ef67ba259559ed81feb6894cde48` | Ancestor; inherited, do not reimplement |
| Real-agent observation | #8 `ab161597ea05d52813619d9962f8956811d2daf1` | Diverged: 51 baseline-only / 20 head-only commits, nine overlapping changed paths; review individual changes before porting |
| Governance interoperability | #9 `9d52c68c93e634479dd82b012f7ef941b796d551` | Ancestor; inherited |
| Enterprise service delivery | #11 `a933fdc327e8744dc8a8441ea3d5b2d75063b91f` | Ancestor; inherited |
| End-to-end assurance | #12 `4d0ce1e32c8dedde4e3a930abc2becf1f56b864e` | Ancestor; inherited same-run engine and retained qualification |
| AIRON teaching | #21 `42c1038f1ef7454821a9ecf32454f07554422866` | Diverged: 5 / 104 commits; separate SYNTRIASS work, retain unchanged |
| AIRON native interface | #22 `f1ba9fc2072dac1431543fd4961baaa2762b8ea9` | Diverged: 5 / 101 commits; separate owner-local bridge, not enterprise authentication |

The exact merge bases, changed paths and overlaps are in
[`ancestry.json`](../../validation/p0_057/iteration-001/ancestry.json).
An overlap is a reconciliation candidate, not a claimed textual merge conflict.
No merge was attempted. The API's stored PR base SHA is historical metadata;
ancestry is calculated from fetched immutable objects instead.

Source and license inventories are retained for every remote tree, including
unrequested branches. Later OPA/OTel/governance and genuine model evidence on #8
must not be silently substituted for the baseline's runtime or mixed into a
single-run claim. #17's seccomp-only hardening and #21's security classification
are review inputs, not evidence that this baseline's cluster deployment passes.

At each publication re-fetch the target ref and use an ordinary fast-forward
push or an expected-SHA ref update. A concurrent advance requires reconciliation;
never reset it or replace another workstream's code.

## Concurrent advance during this iteration

P0-048 advanced to `d2883d7d565901a46e134a22f702eb793db72497` through
`ce7925c649fe3268ef0ba40b321058216c5e0c27` after the initial capture. Its 40
changed paths are CI/scanner classification and retained evidence; none overlaps
the new P0-057 runtime files. They were inspected but not automatically merged
or cherry-picked. The target's recorded base remains `61dd730`. PR #23 targets
the advancing P0-048 branch; GitHub tests its synthetic merge where the workflow
uses default checkout. The required native workflow checks out exact P0-057
head `5be83a8` and records it in its signed-evidence artifact's source manifest.

Shell Git push lacked credentials. The connected provider published Git blobs,
trees and commits with expected-head non-forced ref updates. Remote trees were
checked against local trees before adopting each publication commit locally.
Audit local `dbb509b` equals remote `ceb7682` at tree `228dc116`; implementation
local `17523ef` equals remote `5be83a8` at tree `fe4a962`. No existing remote
commit was rewritten. The full mapping is in the iteration-002 provider record.

Diagnostic local `1b4f8c39ac1ef01a63c057dfb548b0142d82c281` equals remote
`5a7d2625a861821e74f979cd0700fbbe6dbe1de1` at tree
`d9c2ada9464fc7e25b34c6637b91a1c61358600f`. It adds failure diagnostics to the
existing same-run harness. The final evidence checkpoint includes all required
programme documents with explicit open gates and adds the portable diagnostic
test to CI. It does not merge #8/#21/#22 or mark their work accepted.
