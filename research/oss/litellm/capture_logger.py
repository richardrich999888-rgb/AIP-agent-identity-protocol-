"""LiteLLM CustomLogger adapter: append each call's UsageRecord to a JSONL file.

LiteLLM calls these hooks with keyword arguments, and it swallows any
exception they raise ("[Non-Blocking]", visible only with debug logging).
A hook with the wrong parameter names therefore silently records nothing.
That happened during item 1.3. So the adapter counts what it wrote, and the
caller must compare that count with the number of calls it made.
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path

# The capture rules live in command-center/server/llm_capture.py (moved in 4.1a).
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "command-center" / "server"))

from litellm.integrations.custom_logger import CustomLogger

from llm_capture import to_record  # noqa: E402


class UsageCapture(CustomLogger):
    """Writes one JSON line per success or failure event."""

    def __init__(self, path: Path) -> None:
        super().__init__()
        self._path = path
        self._lock = threading.Lock()
        self.written = 0

    def _write(self, kwargs: dict, succeeded: bool) -> None:
        line = to_record(kwargs, succeeded).to_json()
        with self._lock, self._path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
            self.written += 1

    def log_success_event(self, kwargs, response_obj, start_time, end_time):  # noqa: D102 (LiteLLM hook)
        self._write(kwargs, True)

    def log_failure_event(self, kwargs, response_obj, start_time, end_time):  # noqa: D102 (LiteLLM hook)
        self._write(kwargs, False)
