"""Configure the pinned upstream runtime without falling back to another model."""
import asyncio
import hashlib
import math
import os
import sys
from pathlib import Path


def diagnostic_settings(actual, memory_disabled):
    """Only resolved non-secret model settings; never endpoints/keys/headers."""
    result = {"scope": "resolved_pre_initialization_configuration",
              "memory": "DISABLED_UNVALIDATED" if memory_disabled else "UNCHANGED_UNVALIDATED",
              "embedding_validation": "NOT_ESTABLISHED"}
    for slot in ("chat", "utility"):
        value = actual[slot + "_model"]
        safe = {name: value[name] for name in ("provider", "name")
                if type(value.get(name)) is str and 0 < len(value[name]) <= 256
                and value[name].isprintable()}
        for name in ("ctx_length",):
            number = value.get(name)
            if type(number) is int and 0 <= number <= 1_000_000:
                safe[name] = number
        kwargs = value.get("kwargs", {})
        if not isinstance(kwargs, dict):
            kwargs = {}
        for name in ("temperature", "num_ctx", "num_predict"):
            number = kwargs.get(name)
            if type(number) in (int, float) and -1 <= number <= 1_000_000 and math.isfinite(number):
                safe[name] = number
        safe["native_json_object_requested"] = kwargs.get("response_format") == {"type": "json_object"}
        result[slot] = safe
    return result


REVIEWED_PROFILE = "tiny-local-coding-v1"
CODE_TOOL = "plugin:_code_execution:code_execution_tool"


def reviewed_profile_settings(config):
    """Explicit opt-in only; generic and historical profiles stay unchanged."""
    selected = config.get("reviewed_profile")
    if selected is None:
        return None
    if selected != REVIEWED_PROFILE or config.get("disable_memory") is not True:
        raise ValueError("unknown reviewed Agent Zero profile or memory policy")
    supplied = config.get("settings", {}).get("agent_profile", "tiny-local")
    if supplied != "tiny-local":
        raise ValueError("reviewed profile cannot select a different agent")
    return {"agent_profile": "tiny-local", "mcp_servers": '{"mcpServers":{}}'}


async def verify_reviewed_context(context):
    """Actual pinned framework catalog/prompt rendering; no model invocation."""
    from helpers import skills, tool_policy
    if context.config.profile != "tiny-local":
        raise ValueError("reviewed Tiny Local profile did not take effect")
    agent = context.agent0
    catalog = tool_policy.get_tool_catalog(agent)
    allowed = sorted(item["id"] for item in catalog if item.get("available") and
                     tool_policy.resolve_tool(agent, item["name"], canonical_id=item["id"]).allowed)
    if allowed != [CODE_TOOL] or not tool_policy.resolve_tool(agent, "response").allowed:
        raise ValueError("reviewed code-only tool policy did not take effect")
    if skills.list_skills(agent=agent) or skills.get_active_skills(agent):
        raise ValueError("reviewed skill visibility policy did not take effect")
    rendered = "\n\n".join(await agent.get_system_prompt(agent.loop_data))
    if ("## Tiny Local Output Rule" not in rendered or
            "code_execution_tool" not in rendered or
            'Use exactly these top-level fields: `"tool_name"` and `"tool_args"`.' not in rendered):
        raise ValueError("reviewed Tiny Local prompt contract did not render")
    return {"source_authority": "framework_configuration_check_not_kernel_observation",
            "reviewed_profile": REVIEWED_PROFILE, "agent_profile": context.config.profile,
            "allowed_configurable_tools": allowed, "framework_required_response": True,
            "visible_skills": 0, "active_skills": 0,
            "rendered_prompt_bytes": len(rendered.encode()),
            "rendered_prompt_sha256": hashlib.sha256(rendered.encode()).hexdigest(),
            "model_calls_claimed": False, "task_acceptance": False}


def configure(config, requested_model, *, on_configured=None):
    for name in ("plugins", "agents", "chats", "projects"):
        Path("/opt/framework/usr", name).mkdir(parents=True, exist_ok=True)
    os.chdir("/opt/framework")
    sys.path.insert(0, os.getcwd())
    from helpers import runtime, settings, plugins
    from plugins._model_config.helpers import model_config
    from initialize import initialize_agent
    from agent import AgentContext

    # Upstream tests this flag, not /.dockerenv, before choosing local tools.
    runtime.args["dockerized"] = True
    preset = config["preset"]
    if preset.get("name") != "Default":
        raise ValueError("provide an explicit complete Default model preset")
    for slot in ("chat", "utility", "embedding"):
        value = preset[slot]
        if not value.get("provider") or not value.get("name") or not value.get("api_base"):
            raise ValueError(f"explicit provider, model and approved endpoint required: {slot}")
    if preset["chat"]["name"] != requested_model:
        raise ValueError("requested model does not match the configured chat model")
    reviewed = reviewed_profile_settings(config)
    settings.set_settings_delta({**config.get("settings", {}), **(reviewed or {}), "workdir_path": "/work",
                                "update_check_enabled": False, "rfc_auto_docker": False,
                                "root_password": settings.PASSWORD_PLACEHOLDER}, apply=False)
    model_config.save_presets([preset])
    plugins.save_plugin_config("_model_config", "", "", {"model_preset": "Default"})
    plugins.save_plugin_config("_code_execution", "", "", {"ssh_enabled": False})
    if config.get("disable_memory") is True:
        # Explicit narrow workload profile. An unused embedding slot is not
        # evidence of embedding capability or validated memory behavior.
        plugins.toggle_plugin("_memory", False)
        if plugins.get_toggle_state("_memory") != "disabled":
            raise ValueError("explicit memory-disabled profile did not take effect")
    if reviewed is not None:
        # Official profile-scoped configuration APIs, with no parser/tool
        # execution changes. The response tool is framework-required.
        plugins.save_plugin_config("_tool_access", "", "tiny-local", {
            "mode": "custom", "default": "block", "mcp_default": "block",
            "allowed": [CODE_TOOL], "blocked": []})
        # Skills is always enabled upstream; restrict its existing visibility
        # owner rather than attempting to disable or replace the plugin.
        plugins.save_plugin_config("_skills", "", "tiny-local", {
            "active_skills": [], "visibility_policy": {
                "mode": "custom", "default": "block", "allowed": [], "blocked": []}})
    actual = model_config.get_config()
    for slot in ("chat", "utility", "embedding"):
        for field in ("provider", "name", "api_base"):
            if actual[slot + "_model"][field] != preset[slot][field]:
                raise ValueError(f"upstream model configuration changed {slot}.{field}")
    if on_configured is not None:
        on_configured(diagnostic_settings(actual, config.get("disable_memory") is True))
    context = AgentContext(initialize_agent())
    if reviewed is not None:
        try:
            verified = asyncio.run(verify_reviewed_context(context))
            if on_configured is not None:
                on_configured(verified)
        except BaseException:
            context.kill_process()
            raise
    return context
