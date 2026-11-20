"""Run unchanged real reference tests from a non-Cargo-layout directory.

This tests executable discovery, not a synthetic replacement for observation.
Cargo and dependencies must already be available; builds are locked/offline.
"""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import sys

package, test = sys.argv[1:]
command = ["cargo", "test", "--locked", "--offline", "-p", package,
           "--test", test, "--no-run", "--message-format=json"]
result = subprocess.run(command, capture_output=True, text=True)
print(result.stderr, end="", flush=True)
if result.returncode:
    raise SystemExit(result.returncode)
executables = {v["executable"] for line in result.stdout.splitlines()
               if (v := json.loads(line)).get("reason") == "compiler-artifact"
               and v.get("target", {}).get("name") == test and v.get("executable")}
assert len(executables) == 1, executables
with tempfile.TemporaryDirectory(prefix="aip-relocated-tests-") as directory:
    target = Path(directory) / "opaque" / "build" / package / "hash" / "out" / "test"
    target.parent.mkdir(parents=True)
    shutil.copy2(executables.pop(), target)
    print(json.dumps({"command": command, "relocated_executable": str(target)}), flush=True)
    raise SystemExit(subprocess.run([str(target), "--test-threads=1", "--nocapture"]).returncode)
