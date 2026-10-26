#!/usr/bin/env python3
"""Require the RBI honest-path state after the pilot's offline verification.

The generic pilot permits a degraded control. RBI promises Active with coverage.
This checks that extra claim; it does not replace cryptographic verification.
"""

import json
from pathlib import Path
import sys


def check_control(path):
    records = [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]
    if not records:
        raise ValueError("control health archive is empty")
    health = records[-1]["health"]
    if health["state"] != "Active":
        raise ValueError(f"RBI honest path requires Active, got {health['state']!r}")
    coverage = health["attested_coverage"]
    if not isinstance(coverage, dict) or not coverage:
        raise ValueError("RBI honest path requires attested coverage")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("usage: check_control.py CONTROL_HEALTH_ARCHIVE")
        check_control(sys.argv[1])
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
    print("PASS: recorded control is Active with attested coverage")
