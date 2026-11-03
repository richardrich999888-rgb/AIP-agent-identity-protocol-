import asyncio
from types import SimpleNamespace

import pytest
pytest.importorskip("google.adk")

from vanian_interop.google_adk import VanianAdkPlugin


def test_observer_only_hook_does_not_gate_on_sink_failure(caplog):
    def failed_sink(event):
        raise OSError("private sink detail")
    plugin = VanianAdkPlugin("bank", failed_sink)
    context = SimpleNamespace(invocation_id="i", agent_name="a", function_call_id="c")
    result = asyncio.run(plugin.before_tool_callback(tool=SimpleNamespace(name="read"),
        tool_args={"id": 1}, tool_context=context))
    assert result is None and plugin.dropped_events == 1
    assert "coverage is incomplete" in caplog.text and "private sink detail" not in caplog.text


def test_tool_errors_are_metadata_and_never_success_or_secret_content():
    records = []
    plugin = VanianAdkPlugin("bank", records.append)
    context = SimpleNamespace(invocation_id="i", agent_name="a", function_call_id="c")
    result = asyncio.run(plugin.on_tool_error_callback(tool=SimpleNamespace(name="read"),
        tool_args={}, tool_context=context, error=ValueError("secret")))
    assert result is None and records[0].event_kind == "tool.error"
    assert "secret" not in records[0].native_json


def test_non_json_framework_argument_records_gap_without_gating():
    plugin = VanianAdkPlugin("bank", lambda event: None)
    context = SimpleNamespace(function_call_id="c")
    assert asyncio.run(plugin.before_tool_callback(tool=SimpleNamespace(name="read"),
        tool_args={"opaque": object()}, tool_context=context)) is None
    assert plugin.dropped_events == 1
