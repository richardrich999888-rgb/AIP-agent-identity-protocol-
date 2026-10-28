# Enterprise design-partner readiness — evidence-backed

Source: `4ca5a4d`. 

## VERIFIED (reproducible evidence this invocation)
- A real agent's execution is independently observed from the kernel and sealed
  into collector-signed evidence that verifies **offline** under a published
  key, with tamper rejection (M1 + negative controls).

## PARTIAL (component- or limited-integration level only)
- Reconciler `VERIFIED_EXECUTION` verdict: exists as `aip-reconcile` component
  tests; not exercised end-to-end against a live agent here (M2 NOT_RUN).
- MCP gateway signed tool-receipt (`aip-mcp-gateway`, `integrations/mcp-gateway`)
  present in-tree; not run in the same-run chain here.
- SDKs (`sdk/`), evidence API/MCP, enterprise console: present in-tree; not
  installation-tested this invocation.

## BLOCKED (environment / external provision)
- Independently administered **off-host collector** custody — not available in
  a single sandbox host.
- **NTP-synchronized clock** for the collector's default posture — no time
  daemon / NTP egress here.
- Genuinely **model-backed** agent task — no LLM credentials / local model
  (M1 deliberately needs none; a model-driven pilot workflow would need one).
- **kprobe** syscall-level sensors — kernel built without `CONFIG_KPROBES`.

## 30-day evaluation structure (unchanged, gated by the above)
Week 1 environment qualification + controlled install; Week 2 integrate one
approved agent workflow; Week 3 measurement + negative tests + performance;
Week 4 independent verification + acceptance review.

**Pilot readiness verdict: PARTIAL** — the independent-evidence core is
demonstrable live; installation, same-run authz/receipt/reconcile, and
host-separated custody are not yet evidenced here.
