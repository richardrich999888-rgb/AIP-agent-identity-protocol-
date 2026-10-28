"""Offline container compatibility check. This is NOT an autonomous workload."""
import asyncio
import json
import os
from pathlib import Path
from agent_zero_runtime import configure

for path in (os.environ["HOME"], "/tmp/framework", "/tmp/framework-logs"):
    Path(path).mkdir(parents=True, exist_ok=True)
assert os.geteuid() == 10001
assert not Path("/var/run/docker.sock").exists()
try:
    Path("/opt/framework/.write-check").touch()
except PermissionError:
    pass
else:
    raise AssertionError("framework source must be read-only")
slot = {"provider": "openai", "name": "offline-smoke-no-model-call",
        "api_base": "http://127.0.0.1:9/v1"}
context = configure({"preset": {"name": "Default", "chat": slot, "utility": slot,
                               "embedding": {**slot, "name": "offline-embedding-no-call"}}}, slot["name"])
from plugins._code_execution.helpers.shell_local import LocalInteractiveSession

async def check_shell():
    shell = LocalInteractiveSession(cwd="/work")
    await shell.connect()
    try:
        await shell.send_command("python -c 'from pathlib import Path; Path(\"/work/smoke.txt\").write_text(\"real local tool\")'")
        for _ in range(20):
            await shell.read_output(timeout=0.25)
            if Path("/work/smoke.txt").exists():
                break
        assert Path("/work/smoke.txt").read_text() == "real local tool"
    finally:
        await shell.close()

asyncio.run(check_shell())
context.kill_process()
print(json.dumps({"status": "PASS", "kind": "offline container/tool smoke",
                  "autonomous_workload_executed": False, "model_calls": 0}))
