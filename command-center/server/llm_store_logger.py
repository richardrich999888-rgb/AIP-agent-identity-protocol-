"""LiteLLM CustomLogger that writes usage into the event store (item 4.1a).

This is an adapter only: the rules are in llm_capture.to_record, the mapping
in finops_events.usage_event, and persistence in eventstore.EventStore.
LiteLLM swallows hook exceptions (finding in research/oss/litellm), so the
adapter counts `seen` and `stored`. The caller compares `seen` with the
calls it made.
"""

from __future__ import annotations

import datetime as dt
import threading
from typing import Callable

from litellm.integrations.custom_logger import CustomLogger

from eventstore import EventStore
from finops_events import to_ms, usage_event
from llm_capture import to_record


def _aware(t: object) -> object:
    # LiteLLM passes naive local datetimes; make them aware in local time
    # explicitly, at this boundary, so that finops_events stays strict.
    if isinstance(t, dt.datetime) and t.tzinfo is None:
        return t.astimezone()
    return t


class StoreUsageLogger(CustomLogger):
    """Appends one `llm.usage` event per LiteLLM success or failure event."""

    def __init__(self, store: EventStore, clock_ms: Callable[[], int]) -> None:
        super().__init__()
        self._store, self._clock = store, clock_ms
        self._lock = threading.Lock()
        self.seen = 0
        self.stored = 0

    def _handle(self, kwargs: dict, end_time: object, ok: bool) -> None:
        ev = usage_event(to_record(kwargs, ok), to_ms(_aware(end_time)))
        with self._lock:
            self.seen += 1
            if self._store.append(ev, self._clock()).inserted:
                self.stored += 1

    def log_success_event(self, kwargs, response_obj, start_time, end_time):  # noqa: D102 (LiteLLM hook)
        self._handle(kwargs, end_time, True)

    def log_failure_event(self, kwargs, response_obj, start_time, end_time):  # noqa: D102 (LiteLLM hook)
        self._handle(kwargs, end_time, False)
