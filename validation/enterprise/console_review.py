"""Serve real signed evaluation fixtures for a bounded manual browser review.

Invoked through the existing ignored Rust real_http_clients test, with
AIP_ENTERPRISE_CLIENT_SMOKE pointing at this script. Test credentials only.
"""
import os
import time

print("CONSOLE_REVIEW_URL=" + os.environ["VANIAN_TEST_BASE_URL"] + "/console", flush=True)
time.sleep(60)
