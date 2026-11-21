"""A real three-process agent tree for the live orphan run (item 2.4). Lab helper; TEST keys only.

    python orphan_tree.py orchestrator WORK    # spawns the child, then waits
    python orphan_tree.py child WORK           # spawns the grandchild, then waits
    python orphan_tree.py grandchild WORK      # calls the gate when asked

The grandchild is the only process that signs. Each time a file
WORK/call-<n> appears, it signs a request with its own TEST key
(WORK/grandchild.key, generated fresh by the run), presents the authority
chain in WORK/chain.json and posts it to the URL in WORK/gate_url (re-read
every call, so the gate can be restarted with a new revocation list). It
writes WORK/result-<n>.json atomically. Every process exits when WORK/stop
exists. Nothing here decides anything; the gate does.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "server"))
POLL_S = 0.05
CALL_TIMEOUT_S = 10


def _spawn(role: str, work: Path) -> None:
    p = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), role, str(work)])
    (work / f"{role}.pid").write_text(str(p.pid))


def _wait_stop(work: Path) -> None:
    while not (work / "stop").exists():
        time.sleep(POLL_S)


def _call(work: Path) -> dict:
    import signing
    key = bytes.fromhex((work / "grandchild.key").read_text().strip())
    req = {"agent_id": (work / "agent_id").read_text().strip(), "server": "fs", "tool": "read_file", "args": {"n": 1},
           "authority_jtis": json.loads((work / "chain.json").read_text()), "delegation_depth": 2,
           "nonce": secrets.token_hex(16), "issued_at_ms": time.time_ns() // 1_000_000}
    env = {"request": req, "signature_hex": signing.sign(signing.DOMAIN_REQUEST, req, key)}
    r = urllib.request.Request((work / "gate_url").read_text().strip(), data=json.dumps(env).encode(),
                               headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=CALL_TIMEOUT_S) as resp:
            return {"http": resp.status, **json.load(resp)}
    except urllib.error.HTTPError as e:
        return {"http": e.code, **json.load(e)}


def grandchild(work: Path) -> None:
    n = 1
    while not (work / "stop").exists():
        if (work / f"call-{n}").exists():
            out = {"pid": os.getpid(), "ppid": os.getppid(), **_call(work)}
            tmp = work / f"result-{n}.tmp"
            tmp.write_text(json.dumps(out))
            tmp.rename(work / f"result-{n}.json")
            n += 1
        time.sleep(POLL_S)


def main(role: str, work: Path) -> None:
    if role == "orchestrator":
        _spawn("child", work)
        _wait_stop(work)
    elif role == "child":
        _spawn("grandchild", work)
        _wait_stop(work)
    elif role == "grandchild":
        grandchild(work)
    else:
        sys.exit(f"unknown role {role!r}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], Path(sys.argv[2]))
