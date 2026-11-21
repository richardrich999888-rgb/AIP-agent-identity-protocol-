"""Live 3.1b + 3.2: the native gate enforces, and holds sensitive calls for approval (native, not P0-059).

    VANIAN_OPA_BIN=…/opa GATE_VENV/bin/python command-center/lab/live_gate.py OUT_DIR

Generates fresh Ed25519 keys and writes a registry and an operator-signed
revocation list. Starts the TEST DATA tool server, then the gate on
loopback. Then it sends signed calls over HTTP and checks, for each one,
the gate's answer **and** the tool server's hit list. A refused call must
not appear in the hit list. Exit 0 only if every check passes.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "server"))
import agent_registry as ar  # noqa: E402
import eventstore  # noqa: E402
import gate as gate_mod  # noqa: E402
import gate_http  # noqa: E402
import lab_pair  # noqa: E402
import opa_gate  # noqa: E402
import signing  # noqa: E402
import tool_server  # noqa: E402

POLICY = HERE.parent / "policy"
# Lab-issued grants (not AIP tokens); the gate derives every chain from these and the parent links.
GRANTS = {"orchestrator": "root-1", "recon-reporter": "hop-1", "payments-agent": "hop-pay", "retired-agent": "hop-revoked"}


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def main(out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    opa_bin = os.environ.get("VANIAN_OPA_BIN")
    if not opa_bin or not Path(opa_bin).is_file():
        print("VANIAN_OPA_BIN not set: live gate run SKIPPED")
        return 2
    k = {n: signing.generate() for n in ("orchestrator", "recon-reporter", "payments-agent", "retired-agent", "ops-1", "mallory")}
    ag = lambda n, parent=None: {"public_key_hex": k[n][1].hex(), "owner": "alice", "framework": "scripted-test-agent",
                                "host": "lab", "runtime": "python3.11", "parent": parent, "responsible_human": "alice"}
    reg_doc = {"agents": {"orchestrator": ag("orchestrator"), "recon-reporter": ag("recon-reporter", "orchestrator"),
                          "payments-agent": ag("payments-agent", "orchestrator"),
                          "retired-agent": ag("retired-agent", "orchestrator")},
               "operators": {"ops-1": {"public_key_hex": k["ops-1"][1].hex()}}}
    lst = {"revoked_jtis": ["hop-revoked"], "issued_at_ms": now_ms(), "operator_id": "ops-1"}
    rev_doc = {"list": lst, "signature_hex": signing.sign(signing.DOMAIN_REVOCATIONS, lst, k["ops-1"][0])}
    (out / "registry.json").write_text(json.dumps(reg_doc, indent=1))
    (out / "revocations.json").write_text(json.dumps(rev_doc, indent=1))
    (out / "grants.json").write_text(json.dumps(GRANTS, indent=1))
    reg, revoked = ar.load(out / "registry.json", out / "revocations.json")
    grants = ar.load_grants(out / "grants.json", reg)

    tport = lab_pair.free_port()
    tsrv, hits = tool_server.serve(tport)
    threading.Thread(target=tsrv.serve_forever, daemon=True).start()
    store = eventstore.EventStore(out / "events.db")
    fwd = gate_http.http_forwarder(f"http://127.0.0.1:{tport}")

    def start(opa_path):
        gt = gate_mod.Gate(reg, revoked, opa_gate.OpaGate(opa_path, POLICY), store, fwd, now_ms, grants=grants)
        port = lab_pair.free_port()
        srv = gate_http.serve(gt, port)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, f"http://127.0.0.1:{port}/call"

    def call(url, agent=None, server=None, tool=None, jtis=None, signer=None, envelope=None, args=None, depth=None):
        chain = list(jtis) if jtis is not None else ["root-1", GRANTS.get(agent, "none")]
        r = {"agent_id": agent, "server": server, "tool": tool, "args": args or {"n": 1}, "authority_jtis": chain,
             "delegation_depth": len(chain) - 1 if depth is None else depth, "nonce": secrets.token_hex(16),
             "issued_at_ms": now_ms()}
        e = envelope or {"request": r, "signature_hex": signing.sign(signing.DOMAIN_REQUEST, r, k[signer or agent][0])}
        req = urllib.request.Request(url, data=json.dumps(e).encode(), headers={"content-type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.load(resp), e
        except urllib.error.HTTPError as err:
            return err.code, json.load(err), e

    srv, url = start(opa_bin)
    steps, checks = [], {}

    def step(name, expect_status, expect_outcome, expect_hits_delta, **kw):
        before = len(hits)
        status, body, e = call(url, **kw)
        delta = len(hits) - before
        ok = status == expect_status and body["outcome"] == expect_outcome and delta == expect_hits_delta
        steps.append({"step": name, "http": status, "outcome": body["outcome"], "reasons": body["reasons"],
                      "forwarded": body["forwarded"], "tool_server_hits_delta": delta})
        checks[name] = ok
        return e

    allowed = step("allowed call is forwarded", 200, "ALLOW", 1, agent="recon-reporter", server="fs", tool="read_file")
    step("explicitly denied tool never reaches the tool server", 403, "DENY", 0, agent="recon-reporter", server="shell", tool="exec")
    step("forged identity (#6) refused, not forwarded", 403, "DENY", 0, agent="recon-reporter", server="fs", tool="read_file", signer="mallory")
    step("revoked authority refused, not forwarded", 403, "DENY", 0, agent="retired-agent", server="fs", tool="read_file")
    step("chain that omits the agent's grant refused (2.4)", 403, "DENY", 0, agent="retired-agent", server="fs",
         tool="read_file", jtis=("root-1",), depth=1)
    step("understated delegation depth refused (2.4)", 403, "DENY", 0, agent="recon-reporter", server="fs",
         tool="read_file", depth=0)
    step("sensitive call held for approval, not forwarded", 202, "PENDING_APPROVAL", 0, agent="payments-agent",
         server="payments", tool="settle_batch")
    step("replayed request refused", 403, "DENY", 0, agent="recon-reporter", server="fs", tool="read_file", envelope=allowed)

    # 3.2: approval with real enforcement.
    held = step("settlement above threshold is held", 202, "PENDING_APPROVAL", 0, agent="payments-agent",
                server="payments", tool="settle_batch", args={"amount": 50_000})
    step("retry without approval is not forwarded", 403, "DENY", 0, envelope=held)
    rsha = signing.digest(signing.DOMAIN_REQUEST, held["request"])

    def approval(signer):
        a = {"request_sha256": rsha, "operator_id": "ops-1", "decision": "APPROVE",
             "decided_at_ms": now_ms(), "expires_at_ms": now_ms() + 60_000}
        return {"approval": a, "signature_hex": signing.sign(signing.DOMAIN_APPROVAL, a, k[signer][0])}

    step("forged approval is not forwarded", 403, "DENY", 0, envelope={**held, "approval": approval("mallory")})
    step("operator-signed approval forwards the held call", 200, "ALLOW", 1, envelope={**held, "approval": approval("ops-1")})
    step("approval cannot be reused", 403, "DENY", 0, envelope={**held, "approval": approval("ops-1")})
    step("settlement under threshold is allowed", 200, "ALLOW", 1, agent="payments-agent", server="payments",
         tool="settle_batch", args={"amount": 500})
    srv.shutdown()
    srv, url = start(str(out / "no-such-opa"))
    step("OPA unreachable: DENY, not forwarded", 403, "DENY", 0, agent="recon-reporter", server="fs", tool="read_file")
    srv.shutdown()
    tsrv.shutdown()

    decisions = [e.event for e in store.events(kind=gate_mod.DECISION_KIND)]
    checks["every call recorded as a gate.decision"] = len(decisions) == len(steps)
    checks["tool server saw exactly the allowed calls"] = hits == [("fs", "read_file"), ("payments", "settle_batch"),
                                                                    ("payments", "settle_batch")]
    approved = [d for d in decisions if d.get("approved_by")]
    checks["the approved forward names its operator"] = [d["approved_by"] for d in approved] == ["ops-1"]
    checks["allowed decision carries the OPA bundle hash"] = bool(decisions and decisions[0].get("bundle_sha256"))
    checks["store chain intact"] = store.verify() == []
    store.close()
    result = {"label": "live lab run; tool server replies are TEST DATA", "steps": steps, "tool_server_hits": hits,
              "checks": checks}
    (out / "result.json").write_text(json.dumps(result, indent=1) + "\n")
    for n, v in checks.items():
        print(f"{'ok  ' if v else 'FAIL'} {n}")
    failed = [n for n, v in checks.items() if not v]
    print(f"checks: {len(checks) - len(failed)} passed, {len(failed)} failed")
    return 0 if not failed else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(Path(sys.argv[1])))
