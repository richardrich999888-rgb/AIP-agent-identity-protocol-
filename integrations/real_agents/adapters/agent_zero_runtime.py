"""Configure the pinned upstream runtime without falling back to another model."""
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
    settings.set_settings_delta({**config.get("settings", {}), "workdir_path": "/work",
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
    actual = model_config.get_config()
    for slot in ("chat", "utility", "embedding"):
        for field in ("provider", "name", "api_base"):
            if actual[slot + "_model"][field] != preset[slot][field]:
                raise ValueError(f"upstream model configuration changed {slot}.{field}")
    if on_configured is not None:
        on_configured(diagnostic_settings(actual, config.get("disable_memory") is True))
    return AgentContext(initialize_agent())
