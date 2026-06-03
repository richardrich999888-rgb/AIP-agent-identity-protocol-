from __future__ import annotations

from typing import Any, Dict, Optional

from airon_aip.identity import AgentIdentity

try:  # pragma: no cover - optional dependency
    from langchain_core.callbacks import BaseCallbackHandler
except Exception:  # pragma: no cover - optional dependency
    BaseCallbackHandler = object  # type: ignore


def aip_runnable_config(identity: AgentIdentity, *, extra_metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    metadata = identity.public_metadata()
    if extra_metadata:
        metadata.update(extra_metadata)
    return {
        "metadata": metadata,
        "tags": ["airon-aip", f"aip-agent:{identity.agent_id}", f"aip-jti:{identity.jti}"],
    }


def wrap_runnable(runnable: Any, identity: AgentIdentity, *, extra_metadata: Optional[Dict[str, Any]] = None) -> Any:
    """Attach AIP metadata/tags to a LangChain Runnable using with_config()."""

    if not hasattr(runnable, "with_config"):
        raise TypeError("LangChain runnable must expose with_config()")
    return runnable.with_config(aip_runnable_config(identity, extra_metadata=extra_metadata))


class AipCallbackHandler(BaseCallbackHandler):  # type: ignore[misc]
    """LangChain callback handler that exposes persistent AIP metadata."""

    def __init__(self, identity: AgentIdentity) -> None:
        super().__init__()
        self.identity = identity
        self.events: list[Dict[str, Any]] = []

    def _record(self, event: str, **payload: Any) -> None:
        self.events.append(
            {
                "event": event,
                "identity": self.identity.public_metadata(),
                "payload": payload,
            }
        )

    def on_chain_start(self, serialized: Dict[str, Any], inputs: Dict[str, Any], **kwargs: Any) -> None:
        self._record("chain_start", serialized=serialized, inputs_shape=list(inputs.keys()), kwargs=kwargs)

    def on_llm_start(self, serialized: Dict[str, Any], prompts: list[str], **kwargs: Any) -> None:
        self._record("llm_start", serialized=serialized, prompt_count=len(prompts), kwargs=kwargs)

    def on_tool_start(self, serialized: Dict[str, Any], input_str: str, **kwargs: Any) -> None:
        self._record("tool_start", serialized=serialized, input_preview=input_str[:256], kwargs=kwargs)
