#!/usr/bin/env python3
"""Retain tampering controls against the recorded C1 replay, in fresh directories."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent
REPO = Path.cwd()
SOURCE = ROOT / "ci/session-scoreboard-evidence/corrected-validation"
BINARY = REPO / "target/debug/syntriass"
TRUST = SOURCE / "expert-public.json"
runs = []
for attack, expected in (("one-byte-suite", 2), ("wrong-authority", 3),
                         ("changed-map", 2), ("false-saved-verdict", 0)):
    work = ROOT / "replay-attacks" / attack
    work.mkdir(parents=True, exist_ok=False)
    evidence = work / "inputs"
    shutil.copytree(SOURCE, evidence)
    trust = TRUST
    if attack == "one-byte-suite":
        path = evidence / "suite.json"
        raw = path.read_bytes()
        suite = json.loads(raw)
        signature = suite["signature_hex"].encode()
        offset = raw.index(signature)
        changed = raw[:offset] + (b"1" if raw[offset:offset+1] == b"0" else b"0") + raw[offset+1:]
        assert len(raw) == len(changed) and sum(a != b for a, b in zip(raw, changed)) == 1
        path.write_bytes(changed)
    elif attack == "wrong-authority":
        trust = work / "wrong-trust.json"
        trust.write_text(json.dumps({name: "00" * 32 for name in json.loads(TRUST.read_text())}))
    elif attack == "changed-map":
        path = evidence / "example-map.json"
        value = json.loads(path.read_text())
        value["bindings"]["capability_hash"] = "0" * 64
        path.write_text(json.dumps(value))
    else:
        for name in ("result.json", "scoreboard.json", "bound-capability.json"):
            (evidence / name).write_text('{"status":"REJECTED","passed":false}')
    command = ["env", "-u", "CM_IN_NETNS", "bash", "research/compute-memory/bench/offline.sh",
               "python3", str(ROOT / "replay_retained_session.py"), "--repo", str(REPO),
               "--binary", str(BINARY), "--binary-sha256", hashlib.sha256(BINARY.read_bytes()).hexdigest(),
               "--folder", str(evidence), "--trusted-keys", str(trust), "--out", str(work / "replayed")]
    result = subprocess.run(command, capture_output=True, timeout=120)
    (work / "stdout.txt").write_bytes(result.stdout)
    (work / "stderr.txt").write_bytes(result.stderr)
    runs.append({"name": attack, "command": command, "actual_exit": result.returncode, "expected_exit": expected})
    (ROOT / "replay-attack-results.json").write_text(json.dumps(runs, indent=2) + "\n")
    assert result.returncode == expected, (attack, result.returncode, result.stdout, result.stderr)
    observed = json.loads((work / "replayed/result.json").read_text())
    assert not observed["activation_performed"] and not observed["approval_performed"]
    if attack == "wrong-authority":
        assert observed["status"] == "REJECTED_BY_SUITE" and not observed["validation"]["passed"]
        assert observed["validation"]["expert_passed"] == 0
    print(attack, result.returncode)
