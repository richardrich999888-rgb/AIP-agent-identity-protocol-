# Superseded candidate 0176ac2

All 22 configured jobs finished: 14 successful, 5 failed, 3 gated/skipped. The suite failed.

Workspace debug: 3256 passed, 64 failed, 7 ignored; release: 3258 passed, 64 failed, 5 ignored. Each profile additionally has 2 passing and 2 ignored doctests. The 9 failing targets in each profile share aip-edge sibling executable discovery failure; the corrected candidate is tracked separately. Coverage stopped with 795 passed, 12 failed, 1 ignored.

The focused release regression passed all 20 g14_04 repetitions. RBI live rehearsal and tamper control passed; see 0176ac2-rbi-summary.json. Genuine same-run execution, interruption and recovery passed, and public artifact 14711343289 was preserved.

Strict gitleaks, Trivy and cargo-deny gates remain failed. No separate collector custody, full sensor installation or customer readiness is claimed.
