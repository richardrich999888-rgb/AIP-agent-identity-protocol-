"""Credential-free checks of pinned public APIs inside the workload container.

These commands are deliberate component tests, not model-chosen actions or
kernel evidence. The controller must run with network none and its existing
read-only source, unprivileged UID, capability and mount restrictions.
"""
import errno
import importlib.metadata
import json
import math
import os
from pathlib import Path
import platform
import re
import shlex
import subprocess
import sys
import time
import tomllib



def child_hold_seconds():
    value = float(os.environ.get("SNIFFERDOG_SMOKE_CHILD_HOLD_SECONDS", "0"))
    if not math.isfinite(value) or not 0 <= value <= 3:
        raise ValueError("component child hold must be finite and between zero and three seconds")
    return value


def wait_start_gate():
    requested = os.environ.get("SNIFFERDOG_SMOKE_START_FILE")
    if requested is None:
        return {"state": "NOT_REQUESTED"}
    if requested != "/input/start":
        raise ValueError("component start gate must use the controller's /input/start")
    target = Path(requested)
    if not target.parent.is_dir() or os.access(target.parent, os.W_OK):
        raise ValueError("component gate directory must be read-only to the workload")
    deadline = time.monotonic() + 120
    while not target.exists():
        if target.is_symlink():
            raise ValueError("component gate must not be a symbolic link")
        if time.monotonic() >= deadline:
            raise TimeoutError("component start gate was not released")
        time.sleep(0.05)
    if target.is_symlink() or not target.is_file():
        raise ValueError("component gate must be a controller-created regular file")
    return {"state": "RELEASED_CONTROLLER_READONLY_INPUT", "wait_budget_seconds": 120}


def container_boundary(framework):
    if framework not in ("agent_zero", "deerflow", "openhands"):
        raise ValueError("unsupported framework")
    for name in (os.environ["HOME"], "/tmp/framework", "/tmp/framework-logs"):
        Path(name).mkdir(parents=True, exist_ok=True)
    if os.geteuid() != 10001 or os.getegid() != 10001:
        raise AssertionError("smoke requires the unprivileged workload UID/GID")
    if Path("/var/run/docker.sock").exists():
        raise AssertionError("workload must not receive the Docker socket")
    expected = Path("/opt/framework/backend/.venv" if framework == "deerflow"
                    else "/opt/framework/.venv")
    if Path(sys.prefix).resolve() != expected.resolve():
        raise AssertionError("smoke interpreter does not match the framework virtual environment")
    try:
        Path("/opt/framework/.write-check").touch()
    except OSError as error:
        if error.errno not in (errno.EACCES, errno.EROFS):
            raise
    else:
        raise AssertionError("framework source must be read-only")


def source_project_metadata(path):
    """Read virtual app metadata separately from installed distributions."""
    with Path(path).open("rb") as source:
        project = tomllib.load(source)["project"]
    if any(not isinstance(project.get(key), str) or not project[key].strip()
           for key in ("name", "version")):
        raise ValueError("source project name/version must be explicit strings")
    return {"name": project["name"], "version": project["version"],
            "origin": "SOURCE_PYPROJECT_NOT_INSTALLED_DISTRIBUTION"}


def framework_metadata(framework):
    packages = {"agent_zero": ("litellm", "langchain-core", "pydantic", "ipython"),
                "deerflow": ("deerflow-harness", "langchain-core"),
                "openhands": ("openhands-sdk", "openhands-tools", "openhands-workspace",
                              "openhands-agent-server")}[framework]
    versions = {name: importlib.metadata.version(name) for name in packages}
    if framework == "openhands" and versions["openhands-sdk"] != versions["openhands-tools"]:
        raise AssertionError("SDK and built-in tool releases must match")
    revision = subprocess.run(["git", "-c", "safe.directory=/opt/framework", "rev-parse", "HEAD"],
                              cwd="/opt/framework", capture_output=True, text=True,
                              timeout=10, check=True).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", revision) or revision != os.environ["FRAMEWORK_COMMIT"]:
        raise AssertionError("actual upstream revision does not match the built pin")
    return {"upstream_source_commit": revision, "python": platform.python_version(),
            "python_executable": sys.executable, "versions": versions,
            **({"source_project": source_project_metadata("/opt/framework/backend/pyproject.toml")}
               if framework == "deerflow" else {})}


def _command_for(path, *, text=None):
    # Verify child PATH as well as the top-level interpreter. The expected
    # venv prefix is public test configuration, never a credential.
    payload = (repr(text) if text is not None else
               "json.dumps({'component':'actual-upstream-tool','pid':os.getpid(),'python':sys.executable})")
    code = ("import json,os,sys,time; from pathlib import Path; "
            f"assert Path(sys.prefix).resolve()==Path({sys.prefix!r}).resolve(); "
            f"Path({path!r}).write_text({payload}); time.sleep({child_hold_seconds()!r})")
    return "python -c " + shlex.quote(code)


def smoke_native_initialization(framework):
    """Construct the real reviewed native runtime without sending a prompt."""
    from launch import DiagnosticJournal
    from native_frameworks import (MODEL, configuration, deerflow_configuration,
                                   initialize, safe_failure)
    config = configuration(framework, MODEL, "http://127.0.0.1:11434")
    native_path = Path("/work/native-deerflow-smoke.yaml")
    if framework == "deerflow":
        native_path.write_text(json.dumps(deerflow_configuration(config)))
    journal_path = Path("/work/native-initialization-smoke.jsonl")
    try:
        with DiagnosticJournal(journal_path) as journal:
            resources = initialize(config, journal, 60, deerflow_config_path=str(native_path))
            try:
                progress = resources["progress"]
                if progress.calls or progress.completed or progress.finished or progress.final:
                    raise AssertionError("initialization must not execute an agent turn")
                if framework == "deerflow":
                    models = resources["client"].list_models()["models"]
                    if not any(item["name"] == MODEL for item in models):
                        raise AssertionError("actual native model configuration changed")
                    from deerflow.runtime.checkpointer import get_checkpointer, reset_checkpointer
                    try:
                        checkpointer = get_checkpointer()
                        if checkpointer.get_tuple({"configurable": {
                                "thread_id": "offline-native-component-smoke", "checkpoint_ns": ""}}) is not None:
                            raise AssertionError("component checkpoint thread must be fresh")
                        database = Path("/work/deerflow-state/database/deerflow.db")
                        if database.is_symlink() or not database.is_file():
                            raise AssertionError("actual SQLite checkpoint database was not created in workload storage")
                    finally:
                        reset_checkpointer()
                else:
                    from openhands.sdk.llm import Message, TextContent
                    count = resources["conversation"].agent.llm.get_token_count([
                        Message(role="user", content=[TextContent(text="offline tokenizer component check")])])
                    if type(count) is not int or count <= 0:
                        raise AssertionError("actual configured SDK token counter did not return a positive count")
            finally:
                if framework == "openhands":
                    resources["conversation"].close()
    except Exception as error:
        # Retain bounded original stage records and safe source locations in
        # the existing smoke output artifact; no exception text/config/locals.
        rows = [json.loads(line) for line in journal_path.read_text().splitlines()] if journal_path.is_file() else []
        print(json.dumps({"status": "FAIL", "kind": "native initialization smoke",
                          "failure": safe_failure(error, "native_initialization_smoke"),
                          "self_reported_records": rows}), flush=True)
        raise RuntimeError("native initialization smoke failed") from None
    return {"native_initialization": "PASS", "native_model_invocation": "NOT_INVOKED",
            "native_lazy_graph_and_agent_turn": "NOT_EXERCISED",
            **({"native_conversation_close": "PASS", "native_sdk_offline_token_counter": "PASS",
                "native_model_tokenization_accuracy": "NOT_ESTABLISHED"} if framework == "openhands" else
               {"native_sqlite_checkpoint_open_fresh_read_close": "PASS"})}


def smoke_deerflow():
    from deerflow.client import DeerFlowClient
    from deerflow.sandbox.local import LocalSandboxProvider

    # This local execution is inside the controller's restricted container,
    # never on the operator host. It does not use an AIO/Docker provider.
    config = Path("/work/deerflow-smoke.yaml")
    config.write_text(json.dumps({"models": [{"name": "offline-no-model-call",
        "use": "langchain_openai:ChatOpenAI", "model": "offline-no-model-call",
        "api_key": "offline-not-a-secret", "base_url": "http://127.0.0.1:9/v1"}],
        "sandbox": {"use": "deerflow.sandbox.local:LocalSandboxProvider", "allow_host_bash": True}}))
    client = DeerFlowClient(config_path=str(config), model_name="offline-no-model-call",
                           subagent_enabled=False)
    if not any(model["name"] == "offline-no-model-call" for model in client.list_models()["models"]):
        raise AssertionError("resolved embedded client configuration changed")
    provider = LocalSandboxProvider()
    try:
        sandbox_id = provider.acquire(thread_id="offline-component-smoke")
        sandbox = provider.get(sandbox_id)
        if sandbox is None:
            raise AssertionError("actual local sandbox was not acquired")
        target = "/mnt/user-data/workspace/deerflow-smoke.txt"
        sandbox.write_file(target, "real pinned local file API")
        if sandbox.read_file(target) != "real pinned local file API":
            raise AssertionError("upstream file API did not round-trip")
        output = "/mnt/user-data/workspace/deerflow-command.json"
        sandbox.execute_command(_command_for(output), timeout=15)
        value = json.loads(sandbox.read_file(output))
        if value["component"] != "actual-upstream-tool" or value["pid"] <= 0:
            raise AssertionError("actual upstream command did not produce its output")
    finally:
        provider.shutdown()
    return {"embedded_client_config": "PASS", "local_terminal_and_file": "PASS",
            "local_execution_scope": "unprivileged workload container only",
            "model_invocation": "NOT_INVOKED", **smoke_native_initialization("deerflow")}


def smoke_openhands():
    from openhands.sdk import LLM, Agent, Conversation, Tool
    from openhands.tools.file_editor import FileEditorAction, FileEditorExecutor, FileEditorTool
    from openhands.tools.task_tracker import TaskTrackerTool
    from openhands.tools.terminal import TerminalAction, TerminalExecutor, TerminalTool

    llm = LLM(model="openai/offline-no-model-call", api_key="offline-not-a-secret",
              base_url="http://127.0.0.1:9/v1")
    Agent(llm=llm, tools=[Tool(name=tool.name) for tool in
                         (TerminalTool, FileEditorTool, TaskTrackerTool)])
    # Preserve the generic SDK check; the reviewed native lifecycle is checked below.
    if not callable(Conversation):
        raise AssertionError("pinned Conversation API is unavailable")
    editor = FileEditorExecutor(workspace_root="/work")
    target = "/work/openhands-editor-smoke.txt"
    created = editor(FileEditorAction(command="create", path=target, file_text="original component text"))
    viewed = editor(FileEditorAction(command="view", path=target))
    changed = editor(FileEditorAction(command="str_replace", path=target,
                                     old_str="original", new_str="edited"))
    if any(item.is_error for item in (created, viewed, changed)):
        raise AssertionError("actual pinned file editor refused component operations")
    if Path(target).read_text() != "edited component text":
        raise AssertionError("actual pinned file editor did not edit its file")
    terminal = TerminalExecutor(working_dir="/work")
    try:
        output = "/work/openhands-terminal-smoke.json"
        observation = terminal(TerminalAction(command=_command_for(output), timeout=15))
        if observation.is_error or observation.exit_code != 0:
            raise AssertionError("actual pinned terminal command failed")
        value = json.loads(Path(output).read_text())
        if value["component"] != "actual-upstream-tool" or value["pid"] <= 0:
            raise AssertionError("actual pinned terminal did not produce its output")
        backend = "tmux" if terminal.is_pooled else type(terminal.session).__name__
    finally:
        terminal.close()
    return {"sdk_agent_config": "PASS", "file_editor_create_view_replace": "PASS",
            "terminal": "PASS", "terminal_backend": backend, "model_invocation": "NOT_INVOKED",
            **smoke_native_initialization("openhands")}
