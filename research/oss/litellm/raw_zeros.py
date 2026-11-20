"""Print what LiteLLM 1.110.2 itself logs for calls where nothing was measured.

This is the evidence behind capture.py's rules. It prints, for each case,
LiteLLM's own standard_logging_object fields (not capture.py's output).

    unshare -n VENV/bin/python raw_zeros.py --isolated
"""

import json
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from acceptance import EVENT_WAIT_S, POLL_S, loopback_up, outside_resolves  # noqa: E402

if sys.argv[1:] == ["--isolated"]:
    loopback_up()
    assert not outside_resolves(), "not isolated"

import mock_openai  # noqa: E402

srv = mock_openai.serve(0)
threading.Thread(target=srv.serve_forever, daemon=True).start()
import litellm  # noqa: E402
from litellm.integrations.custom_logger import CustomLogger  # noqa: E402

seen = []


class Raw(CustomLogger):
    def log_success_event(self, kwargs, response_obj, start_time, end_time):
        seen.append(kwargs["standard_logging_object"])

    def log_failure_event(self, kwargs, response_obj, start_time, end_time):
        seen.append(kwargs["standard_logging_object"])


litellm.callbacks = [Raw()]
for case, model in (("unpriced model", "mock-2"), ("provider sent no usage", "mock-no-usage"), ("provider HTTP 500", "mock-error")):
    n = len(seen)
    try:
        litellm.completion(model="openai/" + model, api_base=f"http://127.0.0.1:{srv.server_address[1]}/v1",
                           api_key="sk-test-not-a-secret", messages=[{"role": "user", "content": "hello there agent"}], num_retries=0)
    except Exception:
        pass
    deadline = time.monotonic() + EVENT_WAIT_S
    while len(seen) == n and time.monotonic() < deadline:
        time.sleep(POLL_S)
    o = seen[-1]
    print(json.dumps({"case": case, "status": o.get("status"), "prompt_tokens": o.get("prompt_tokens"),
                      "completion_tokens": o.get("completion_tokens"), "total_tokens": o.get("total_tokens"),
                      "response_cost": o.get("response_cost"),
                      "response_cost_failure_debug_info_present": o.get("response_cost_failure_debug_info") is not None}))
srv.shutdown()
