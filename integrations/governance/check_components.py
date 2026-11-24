#!/usr/bin/env python3
"""CI component gate: real upstream engines are mandatory; skipped tests fail."""
import json
import os
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent


def main():
    if not all(os.environ.get(key) for key in ('AIP_OPA_BINARY', 'AIP_GOVERNANCE_TEST_ROOT')):
        raise SystemExit('prepared OPA and OpenTelemetry test assets are required')
    suite = unittest.defaultTestLoader.discover(str(HERE / 'tests'))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(json.dumps({'classification': 'FRAMEWORK_COMPONENT_CONTROLS_NOT_AGENT_EXECUTION',
        'tests': result.testsRun, 'failures': len(result.failures),
        'errors': len(result.errors), 'skipped': len(result.skipped),
        'status': 'PASS' if result.wasSuccessful() and not result.skipped else 'FAIL'}))
    return int(not result.wasSuccessful() or bool(result.skipped) or result.testsRun == 0)


if __name__ == '__main__':
    sys.exit(main())
