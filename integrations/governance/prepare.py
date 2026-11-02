#!/usr/bin/env python3
"""Explicit public-asset bootstrap; runtime integrations never download assets."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from integrations.governance import opa, telemetry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    root.mkdir(mode=0o755, parents=True, exist_ok=True)
    engine = opa.prepare_engine(root / 'opa').resolve(strict=True)
    telemetry.prepare_telemetry(root / 'otel')
    report = {'classification': 'EXPLICIT_PUBLIC_GOVERNANCE_ASSET_BOOTSTRAP',
        'model_or_production_credentials_used': False,
        'opa_engine': str(engine.relative_to(root)),
        'opa': opa.verify_engine(engine),
        'telemetry': telemetry.verify_telemetry(root / 'otel'),
        'workload_execution_claimed': False,
        'independent_administrative_custody_claimed': False}
    destination = root / 'assets-manifest.json'
    destination.write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    destination.chmod(0o644)
    print(json.dumps(report, allow_nan=False))


if __name__ == '__main__':
    main()
