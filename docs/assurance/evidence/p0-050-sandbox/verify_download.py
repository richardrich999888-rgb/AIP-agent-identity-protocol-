"""Recheck retained CI bytes and signatures with a separately built local CLI.

Invoke after independently selecting the public material and verifying the
original archive digest. This synthetic trial does not authenticate an expert.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

base = Path(__file__).resolve().parent
binary = Path(sys.argv[1]).resolve(strict=True)
runtime = Path(sys.argv[2]).resolve(strict=True)
out = Path(sys.argv[3]).resolve()
out.mkdir(parents=True, exist_ok=False)
ci = base / "ci/original"
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(base / "ci/teaching-original.zip") == "9616c688579d411080e9303f1b427b806f7bfb607200217f3608ef7765094dec"
packet = ci / "sandbox-evidence"
assert sha(packet / "public.json") == "f203443e3abe7d0b12ff57b0a8bc51722f0fc56112167b72a1b8292f6c4b32d1"
assert sha(packet / "authorized.json") == "2b7b1cdcb2e6f6df189d43956b5fcfcb38ea486c01560fa3a673920fa708c6ac"
for name, expected in json.loads((packet / "receipt.json").read_text())["files_sha256"].items():
    assert Path(name).name == name
    assert sha(packet / name) == expected, name
rows = []


def check(name, command, expected):
    start = time.monotonic()
    result = subprocess.run(command, capture_output=True, timeout=120)
    (out / (name + ".stdout")).write_bytes(result.stdout)
    (out / (name + ".stderr")).write_bytes(result.stderr)
    rows.append(dict(name=name, command=command, exit_code=result.returncode,
                     expected_exit=expected, duration_seconds=time.monotonic() - start))
    assert result.returncode == expected, name
    return result.stdout.decode()


try:
    for name, public, bundle, exit_code in [
        ("original", "public.json", "authorized.json", 0),
        ("one-byte-tamper", "public.json", "tampered-exit.json", 1),
        ("wrong-anchor", "wrong-public.json", "authorized.json", 1),
    ]:
        output = check(name, [str(binary), "verify", "--public", str(packet / public),
                              "--bundle", str(packet / bundle)], exit_code)
        if exit_code == 0:
            assert "independent observation: CannotProve" in output
        else:
            assert "REJECTED:" in output
    evidence = ci / "exclusion-evidence"
    trust = {
        "tenant": "halvorn-power",
        "task": "Distribution transformer insulation acceptance per Halvorn HU-TX-2 rev A",
        "expert_id": "expert:p0-049-synthetic-evaluator",
        "public_key_hex": "5a08d0b1bf400a7f9c74cfe1b3d7e53afe87d6490b1f8e9620eda6580f21ddc4",
        "capability_sha256": "076c4bee1b9f8e55a6b8971b50ec246d6d12ff6298d3a061b9e84695b36d2ea9",
        "binary_sha256": sha(runtime),
    }
    (out / "teaching-trust.json").write_text(json.dumps(trust, indent=2) + "\n")
    repo = base.parents[3]
    check("teaching", [sys.executable, str(repo / "research/capability-learning/harness/verify_applicability.py"),
                       "--evidence", str(evidence), "--trust", str(out / "teaching-trust.json"),
                       "--binary", str(runtime), "--out", str(out / "teaching-replay")], 0)
finally:
    (out / "commands.json").write_text(json.dumps({"vanian_sha256": sha(binary),
        "syntriass_sha256": sha(runtime), "commands": rows,
        "network_devices": Path("/proc/net/dev").read_text(),
        "python": sys.version,
        "routes": Path("/proc/net/route").read_text(),
        "claim": "Synthetic runner/suite checks; no independent key custody, expert authentication or full offline installation."
    }, indent=2) + "\n")
print("PASS: original signature, one-byte rejection, wrong-anchor rejection, signed 38-case teaching replay")
