"""Configure the pinned upstream runtime without falling back to another model."""
import os
import sys
from pathlib import Path


def configure(config, requested_model):
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
    return AgentContext(initialize_agent())
