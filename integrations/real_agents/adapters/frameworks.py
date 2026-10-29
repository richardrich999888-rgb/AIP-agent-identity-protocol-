#!/usr/bin/env python3
"""The five upstream frameworks behind one launcher interface.

This module runs INSIDE the untrusted workload sandbox, beside
``launch.py``. It holds no observer key, no signed-archive mount, no Docker
socket and no access to the controller's control directory.

Everything returned from here is SELF_REPORTED. A framework saying it did
something is not evidence that it did; the controller's acceptance predicate
is satisfied only by the independently observed effect named in
``EffectSpec``. That asymmetry is the whole point of the module's shape: an
adapter declares what the run should make true in the world, and something
other than the adapter checks it.

Every public API used here was verified by signature inspection against the
exact pinned artifact recorded in ``frameworks.lock.json``. No API is
assumed from documentation or memory.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

# One OpenAI-compatible endpoint serves every framework. It is the locally
# provisioned, content-pinned CPU model from
# ``validation/enterprise/prepare_local_model.py`` -- never a cloud account,
# and never a credential read from the environment of the host.
MODEL_BASE_ENV = "AIP_MODEL_BASE_URL"
MODEL_ID_ENV = "AIP_MODEL_ID"
# The endpoint is local and unauthenticated. Upstream OpenAI clients refuse to
# start without *some* key, so a fixed non-secret placeholder is sent. It is
# not a credential and must never be replaced by one.
LOCAL_PLACEHOLDER_KEY = "local-pinned-model-no-credential"


class AdapterRefused(Exception):
    """The adapter will not run. Never degrade into a weaker run instead."""


@dataclass(frozen=True)
class EffectSpec:
    """What an *independent* observer must be able to confirm afterwards.

    `kind` selects the controller-side checker. `detail` carries the exact
    operand that checker needs -- an absolute path, an HTTP request line, a
    git ref. Nothing here is produced by the framework, so a framework cannot
    widen its own acceptance criterion.
    """

    kind: str
    detail: dict
    corroborating_source: str


@dataclass(frozen=True)
class Adapter:
    name: str
    #: Imperative English handed verbatim to the model. Kept in the adapter so
    #: the task and the effect it is checked against cannot drift apart.
    task: Callable[[Path], str]
    #: Declared, independently checkable consequence of a successful run.
    effect: Callable[[Path], EffectSpec]
    run: Callable[["RunContext"], object]
    #: Minimum runtime facts the adapter needs; a missing one is a refusal,
    #: never a silent downgrade.
    requires: tuple[str, ...] = field(default=())


@dataclass
class RunContext:
    """Everything an adapter may touch. Deliberately small."""

    work: Path
    model_id: str
    model_base_url: str
    timeout_s: int
    emit: Callable[[str, object], None]
    extra: dict = field(default_factory=dict)

    def effect_dir(self) -> Path:
        path = self.work / "effect"
        path.mkdir(parents=True, exist_ok=True)
        return path


# --------------------------------------------------------------------------
# smolagents -- huggingface/smolagents, PyPI wheel 1.26.0
#
# Verified surface (inspect.signature, wheel 1.26.0):
#   CodeAgent(tools, model, prompt_templates, additional_authorized_imports,
#             planning_interval, executor, executor_type, executor_kwargs, ...)
#   CodeAgent.run(task: str, stream=False, reset=True, images=None,
#                 additional_args=None, max_steps=None, return_full_result=None)
#   OpenAIServerModel(model_id, api_base, api_key, organization, project, ...)
#   RunResult fields: output, state, steps, token_usage, timing
# --------------------------------------------------------------------------
SMOLAGENTS_TOKEN = "SMOLAGENTS-CODE-ACTION-OK"


def _smolagents_task(work: Path) -> str:
    target = work / "effect" / "smolagents-effect.txt"
    return (
        "Write a file using Python code. The file path must be exactly "
        f"{target}. Its entire contents must be exactly the single line "
        f"{SMOLAGENTS_TOKEN} with no leading or trailing text. "
        "Use open() and write(). Then give the final answer 'written'."
    )


def _smolagents_effect(work: Path) -> EffectSpec:
    return EffectSpec(
        kind="file_exact_content",
        detail={"path": str(work / "effect" / "smolagents-effect.txt"),
                "content": SMOLAGENTS_TOKEN + "\n", "allow_trailing_newline": True},
        corroborating_source="controller filesystem inspection plus kernel exec/write observation",
    )


def _run_smolagents(ctx: RunContext):
    from smolagents import CodeAgent, OpenAIServerModel  # pinned 1.26.0

    model = OpenAIServerModel(
        model_id=ctx.model_id,
        api_base=ctx.model_base_url,
        api_key=LOCAL_PLACEHOLDER_KEY,
    )
    # `executor_type="local"` runs generated code in this sandboxed process.
    # That is deliberate: the effect must be a real syscall made by a real
    # process the observer can see, not a simulated one. The sandbox, not the
    # framework, is what bounds it.
    agent = CodeAgent(
        tools=[],
        model=model,
        executor_type="local",
        additional_authorized_imports=["pathlib", "os"],
    )
    result = agent.run(_smolagents_task(ctx.work), return_full_result=True)
    ctx.emit("framework_result", {
        "output": str(getattr(result, "output", result))[:4096],
        "steps": len(getattr(result, "steps", []) or []),
        "token_usage": str(getattr(result, "token_usage", None))[:512],
    })
    return getattr(result, "output", result)


# --------------------------------------------------------------------------
# aider -- Aider-AI/aider, PyPI wheel aider-chat 0.86.2
#
# Verified surface (`aider --help`, `aider --version` on wheel 0.86.2):
#   --model, --openai-api-base, --message/-m, --message-file/-f,
#   --yes-always, --auto-test, --test-cmd, --exit, --dry-run
# Driven as a subprocess rather than through its Python internals, because the
# CLI is the interface upstream documents and version-stabilises.
# --------------------------------------------------------------------------
AIDER_MARKER = "AIDER-EDIT-OK"


def _aider_task(work: Path) -> str:
    return (
        "In calc.py, fix the add function so it returns the sum of a and b "
        f"instead of their difference. Also add the module-level constant "
        f"MARKER = \"{AIDER_MARKER}\". Change nothing else."
    )


def _aider_effect(work: Path) -> EffectSpec:
    return EffectSpec(
        kind="git_commit_and_test",
        detail={"repo": str(work / "effect" / "repo"),
                "must_contain": [AIDER_MARKER, "return a + b"],
                "file": "calc.py",
                "test_cmd": [sys.executable, "-m", "pytest", "-q", "test_calc.py"]},
        corroborating_source="independent git diff/log in the synthetic repository plus an independent test run",
    )


def _seed_aider_repo(repo: Path) -> None:
    """A synthetic repository with one genuinely failing test.

    The test fails before the run and must pass after it, so a no-op edit
    cannot satisfy the predicate.
    """
    repo.mkdir(parents=True, exist_ok=True)
    (repo / "calc.py").write_text("def add(a, b):\n    return a - b\n")
    (repo / "test_calc.py").write_text(
        "from calc import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n")
    env = {"PATH": os.defpath, "HOME": str(repo),
           "GIT_AUTHOR_NAME": "synthetic", "GIT_AUTHOR_EMAIL": "synthetic@invalid",
           "GIT_COMMITTER_NAME": "synthetic", "GIT_COMMITTER_EMAIL": "synthetic@invalid"}
    for argv in (["git", "init", "-q", "-b", "main"], ["git", "add", "-A"],
                 ["git", "commit", "-q", "-m", "synthetic baseline"]):
        subprocess.run(argv, cwd=repo, env=env, check=True, capture_output=True, timeout=60)


def _run_aider(ctx: RunContext):
    repo = ctx.effect_dir() / "repo"
    _seed_aider_repo(repo)
    aider = ctx.extra.get("aider_binary")
    if not aider:
        raise AdapterRefused("aider binary path was not provisioned")
    argv = [
        str(aider), "--model", ctx.model_id,
        "--openai-api-base", ctx.model_base_url,
        "--message", _aider_task(ctx.work),
        "--yes-always", "--no-check-update", "--no-analytics",
        "--no-show-model-warnings", "--no-gitignore",
        "calc.py",
    ]
    completed = subprocess.run(
        argv, cwd=repo, timeout=ctx.timeout_s, capture_output=True, text=True,
        env={"PATH": os.defpath, "HOME": str(repo),
             "OPENAI_API_KEY": LOCAL_PLACEHOLDER_KEY,
             "AIDER_ANALYTICS": "false"})
    # Returncode is a framework assertion. It is recorded, never trusted:
    # acceptance is the independent git diff plus the independent test run.
    ctx.emit("framework_result", {"returncode": completed.returncode,
                                  "stdout_tail": completed.stdout[-4096:],
                                  "stderr_tail": completed.stderr[-4096:]})
    return {"returncode": completed.returncode}


# --------------------------------------------------------------------------
# goose -- aaif-goose/goose, Rust binary v1.57.0
#
# NOT RUNNABLE YET, and the adapter says so rather than substituting
# something weaker. Two facts block it:
#   1. There is no PyPI package. PyPI 'goose-ai' 0.1.0 is an unrelated upload
#      and must never be installed in its place.
#   2. The headless invocation contract is unverified. The upstream README
#      advertises a CLI and an embedding API but confirms no non-interactive
#      flag, so any argv written here would be invented.
# --------------------------------------------------------------------------
def _goose_task(work: Path) -> str:
    return ("Call the registered read-only MCP tool to read synthetic loan 1 "
            "and report what it returned. Do not modify any record.")


def _goose_effect(work: Path) -> EffectSpec:
    return EffectSpec(
        kind="gateway_receipt",
        detail={"tool": "same-run-loan-read", "mutation_forbidden": True},
        corroborating_source="signed MCP gateway receipt joined to the signed authority expectation",
    )


def _run_goose(ctx: RunContext):
    raise AdapterRefused(
        "goose has no verified non-interactive invocation contract: "
        "aaif-goose/goose v1.57.0 ships a Rust CLI with no PyPI package, and "
        "its headless flag set is unverified. Refusing rather than inventing "
        "an argv. PyPI 'goose-ai' is a different project and is not a substitute.")


# --------------------------------------------------------------------------
# browser-use -- browser-use/browser-use, PyPI wheel 0.13.14
#
# Verified surface (inspect.signature, wheel 0.13.14):
#   Agent(task, llm, browser_profile, browser_session, browser, tools, ...)
#   Agent.run(max_steps=500, on_step_start=None, on_step_end=None)
#       -> AgentHistoryList   (async)
#   ChatOpenAI(model, ..., api_key, organization, project, base_url, ...)
#   Browser(..., executable_path, headless, args, chromium_sandbox, ...)
# 0.13.14 does NOT depend on playwright; it drives Chromium over CDP through
# cdp-use 1.4.5, so the Chromium binary is provisioned by the controller.
# --------------------------------------------------------------------------
BROWSER_PATH = "/vanian-browser-effect"


def _browser_task(work: Path) -> str:
    base = "http://127.0.0.1:19997"
    return (f"Open {base}{BROWSER_PATH} and report the single word shown on "
            "the page. Visit no other address.")


def _browser_effect(work: Path) -> EffectSpec:
    return EffectSpec(
        kind="http_access_log",
        detail={"path": BROWSER_PATH, "method": "GET",
                "log": str(work / "effect" / "http-access.log")},
        corroborating_source="access log written by the local HTTP server itself, which the agent cannot write",
    )


def _run_browser_use(ctx: RunContext):
    import asyncio

    from browser_use import Agent, Browser, ChatOpenAI  # pinned 0.13.14

    chromium = ctx.extra.get("chromium_path")
    if not chromium:
        raise AdapterRefused("no Chromium binary was provisioned for browser-use")
    llm = ChatOpenAI(model=ctx.model_id, base_url=ctx.model_base_url,
                     api_key=LOCAL_PLACEHOLDER_KEY)
    browser = Browser(executable_path=str(chromium), headless=True,
                      chromium_sandbox=False)
    agent = Agent(task=_browser_task(ctx.work), llm=llm, browser=browser)

    async def drive():
        try:
            return await agent.run(max_steps=12)
        finally:
            close = getattr(browser, "stop", None) or getattr(browser, "close", None)
            if close is not None:
                outcome = close()
                if asyncio.iscoroutine(outcome):
                    await outcome

    history = asyncio.run(drive())
    ctx.emit("framework_result", {"history_type": type(history).__name__,
                                  "repr_head": repr(history)[:4096]})
    return {"history": type(history).__name__}


# --------------------------------------------------------------------------
# open-interpreter -- the ORIGINAL Python project, PyPI wheel 0.4.3
#
# Verified surface (inspect.signature, wheel 0.4.3, after remediation):
#   interpreter.auto_run (default False), interpreter.offline,
#   interpreter.verbose, interpreter.max_output, interpreter.safe_mode
#   interpreter.llm.api_base / .api_key / .model / .context_window / .max_tokens
#   interpreter.chat(message=None, display=True, stream=False, blocking=True)
#
# KNOWN DEFECT, remediated by pin: 0.4.3's
# interpreter/core/utils/system_debug_info.py line 4 imports pkg_resources,
# which setuptools>=81 removed, so the package does not import on a current
# environment. The lock pins setuptools<81.
#
# NOTE ON IDENTITY: openinterpreter/openinterpreter is now a Rust rewrite with
# no Python API. This adapter targets the original Python artifact and says so.
# --------------------------------------------------------------------------
OI_TOKEN = "OPEN-INTERPRETER-EXEC-OK"


def _oi_task(work: Path) -> str:
    target = work / "effect" / "open-interpreter-effect.txt"
    return (f"Run a shell command that writes exactly {OI_TOKEN} into the file "
            f"{target}. Use printf or echo with a redirect. Then stop.")


def _oi_effect(work: Path) -> EffectSpec:
    return EffectSpec(
        kind="file_exact_content",
        detail={"path": str(work / "effect" / "open-interpreter-effect.txt"),
                "content": OI_TOKEN + "\n", "allow_trailing_newline": True},
        corroborating_source="controller filesystem inspection plus independent process-exec evidence for the shell",
    )


def _run_open_interpreter(ctx: RunContext):
    from interpreter import interpreter  # pinned 0.4.3 + setuptools<81

    interpreter.offline = True
    interpreter.verbose = False
    # Approval is granted here once, explicitly, for a disposable sandbox.
    # This is the "real approved command execution" case, not an unbounded
    # one: the sandbox and the controller's limits are what bound it.
    interpreter.auto_run = True
    interpreter.llm.model = "openai/" + ctx.model_id
    interpreter.llm.api_base = ctx.model_base_url
    interpreter.llm.api_key = LOCAL_PLACEHOLDER_KEY
    messages = interpreter.chat(_oi_task(ctx.work), display=False, stream=False,
                                blocking=True)
    ctx.emit("framework_result", {"message_count": len(messages or []),
                                  "tail": json.dumps(messages or [], default=str)[-4096:]})
    return {"message_count": len(messages or [])}


ADAPTERS: dict[str, Adapter] = {
    "smolagents": Adapter("smolagents", _smolagents_task, _smolagents_effect,
                          _run_smolagents, requires=("model_endpoint",)),
    "aider": Adapter("aider", _aider_task, _aider_effect, _run_aider,
                     requires=("model_endpoint", "aider_binary", "git")),
    "goose": Adapter("goose", _goose_task, _goose_effect, _run_goose,
                     requires=("model_endpoint", "goose_binary", "mcp_gateway")),
    "browser_use": Adapter("browser_use", _browser_task, _browser_effect,
                           _run_browser_use,
                           requires=("model_endpoint", "chromium_path", "local_http_server")),
    "open_interpreter": Adapter("open_interpreter", _oi_task, _oi_effect,
                                _run_open_interpreter, requires=("model_endpoint",)),
}


def adapter(name: str) -> Adapter:
    """Look up one adapter. An unknown name is a refusal, not a default."""
    try:
        return ADAPTERS[name]
    except KeyError:
        raise AdapterRefused(
            f"unsupported framework {name!r}; known: {sorted(ADAPTERS)}") from None


def effect_contract(name: str, work: Path) -> dict:
    """The acceptance contract, emitted BEFORE the agent runs.

    Writing it first matters: a contract published after the fact could have
    been chosen to match whatever happened.
    """
    found = adapter(name)
    spec = found.effect(work)
    return {"framework": name, "task": found.task(work), "requires": list(found.requires),
            "effect": {"kind": spec.kind, "detail": spec.detail,
                       "corroborating_source": spec.corroborating_source},
            "provenance": "CONTROLLER_DECLARED_BEFORE_RUN"}
