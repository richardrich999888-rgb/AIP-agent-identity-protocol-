"""Reference adapters.

An adapter is a thin translator from some framework's, runtime's, or client
library's vocabulary into AIRI events. Adapters are **integration surfaces,
not trust anchors**: none of them is authoritative, none holds a key of its
own, and nothing downstream grants anything on the strength of which adapter
produced an event.

Three are shipped, one per boundary the specification separates:

``framework``  agent orchestration callbacks  (LangChain / LangGraph shape)
``model``      model and inference provenance (hosted APIs, vLLM, PyTorch, JAX)
``tool``       tool, API and subprocess invocation, with the three layers kept
               apart: requested invocation, runtime execution, external effect
"""

from .framework import FrameworkAdapter
from .model import ModelAdapter, describe_local_runtime
from .tool import ToolAdapter, ToolCall

__all__ = [
    "FrameworkAdapter",
    "ModelAdapter",
    "describe_local_runtime",
    "ToolAdapter",
    "ToolCall",
]
