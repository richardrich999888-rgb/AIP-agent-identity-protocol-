#!/usr/bin/env python3
"""Retain a synthetic real-CLI runner bundle; this is not a Sniffer Dog demo.

Run on a supported unprivileged Linux host. CI invokes this inside
with_cgroup.sh. No package downloads or private keys enter the output archive.
The public anchors need independent authentication before third-party reliance.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    commands = []
    metadata = {
        "started_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "uid": os.getuid(),
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
        "binary_sha256": sha(binary),
        "recorder_sha256": sha(Path(__file__)),
        "model": "Synthetic commitment only; no model was loaded or invoked.",
        "claim": "Runner attestation only; independent observation CANNOT_PROVE.",
        "custody": "Synthetic keys generated under one uid; no independent administration.",
        "commands": commands,
        "status": "INCOMPLETE",
    }

    def run(name, arguments, expected_exit):
        command = [str(binary), *map(str, arguments)]
        entry = {"command": command, "expected_exit": expected_exit}
        commands.append(entry)
        start = time.monotonic()
        with (out / (name + ".stdout")).open("xb") as stdout, (
            out / (name + ".stderr")
        ).open("xb") as stderr:
            result = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=120)
        entry.update(exit_code=result.returncode, duration_seconds=time.monotonic() - start)
        require(result.returncode == expected_exit, f"{name}: unexpected exit {result.returncode}")
        return (out / (name + ".stdout")).read_text()

    try:
        require(os.getuid() != 0, "Must exercise the unprivileged execution path")
        program = Path("/bin/echo")
        tools = [
            {"id": tool, "program": str(program), "program_sha256": sha(program),
             "fixed_args": [], "timeout_ms": 5000}
            for tool in ("echo", "forbidden")
        ]
        write_json(out / "tools.json", tools)
        with tempfile.TemporaryDirectory(prefix="p050-synthetic-keys-") as state:
            run("init", ["init", "--state", state, "--tools", out / "tools.json",
                         "--grant", "echo", "--model-sha256", "00" * 32], 0)
            shutil.copyfile(Path(state) / "public.json", out / "public.json")
            run("authorized", ["act", "--state", state, "--tool", "echo",
                               "--evidence", out / "authorized.json", "--", "p050 sandbox ok"], 0)
            record = json.loads((out / "authorized.json").read_bytes())["run_record"]
            require(record["exit"] == {"Code": 0}, "Tool did not exit successfully")
            require(record["stdout_sha256"] == list(hashlib.sha256(b"p050 sandbox ok\n").digest()),
                    "Signed stdout digest differs from the actual tool's expected output")
            require(record["program_sha256"] == list(bytes.fromhex(sha(program))),
                    "Signed program digest differs from the pinned tool")
            denied = run("unauthorized", ["act", "--state", state, "--tool", "forbidden",
                                          "--evidence", out / "forbidden.json", "--", "must not run"], 1)
            require("DENIED by AIP decision point" in denied, "Expected policy denial")
            require(not (out / "forbidden.json").exists(), "Denied action produced evidence")

        # Verification runs after the private state has been removed, in a new
        # CLI process with only retained public material. This is not a second host.
        verified = run("verify-original", ["verify", "--public", out / "public.json",
                                           "--bundle", out / "authorized.json"], 0)
        require("AUTHORIZED_AND_RUNNER_ATTESTED exit=Code(0)" in verified, "Wrong verdict")
        require("independent observation: CannotProve" in verified, "Observation was overclaimed")
        original = (out / "authorized.json").read_bytes()
        require(original.count(b'"Code": 0') == 1, "Ambiguous exit-code mutation")
        tampered = original.replace(b'"Code": 0', b'"Code": 1', 1)
        require(sum(a != b for a, b in zip(original, tampered)) == 1, "Not a one-byte attack")
        (out / "tampered-exit.json").write_bytes(tampered)
        rejected = run("verify-tampered", ["verify", "--public", out / "public.json",
                                          "--bundle", out / "tampered-exit.json"], 1)
        require("REJECTED:" in rejected, "Tampering was not rejected")
        wrong = json.loads((out / "public.json").read_text())
        wrong["runner_pub"] = wrong["institution_pub"]
        write_json(out / "wrong-public.json", wrong)
        rejected = run("verify-wrong-anchor", ["verify", "--public", out / "wrong-public.json",
                                               "--bundle", out / "authorized.json"], 1)
        require("REJECTED:" in rejected, "Wrong trust anchor was not rejected")
        metadata["status"] = "PASS"
    finally:
        metadata["files_sha256"] = {p.name: sha(p) for p in sorted(out.iterdir()) if p.is_file()}
        write_json(out / "receipt.json", metadata)
    print(json.dumps({"status": "PASS", "evidence": str(out), "observation": "CANNOT_PROVE"}))


if __name__ == "__main__":
    main()
