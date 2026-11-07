#!/usr/bin/env python3
"""Generate the seeded datasets and verify every split against its pinned digest.

Why this exists: `.gitignore` carries a blanket `*.jsonl`, so the sidecar's
training data is not in the repository even though that dataset's
`MANIFEST.json` is. On a fresh clone the sidecar cannot start, and the failure
surfaces several layers away as "sidecar reply missing or oversized".

The datasets are seeded, so rather than committing large files the fix is to
regenerate and prove the result is byte-identical to what the published
figures were measured on. The tracked `MANIFEST.json` pins a SHA-256 per
split, which makes that provable rather than assumed.

Fails closed. A split whose digest differs is a different dataset, so it is
reported and the process exits non-zero; it is never accepted with a warning.

  --check      verify only; do not write (default)
  --generate   regenerate missing or mismatched datasets, then verify

Exit codes:
  0  every pinned split present and matching
  3  a dataset is missing (and --generate was not given)
  4  a split is present but does not match its pinned digest
  2  caller or repository error
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

EXIT_OK, EXIT_USAGE, EXIT_MISSING, EXIT_MISMATCH = 0, 2, 3, 4

#: dataset directory -> generator module path, relative to the repository root.
#: Listed explicitly: a dataset with no generator cannot be regenerated, and
#: silently skipping it would reintroduce exactly the failure this file exists
#: to remove.
DATASETS = {
    "research/system-one/data/maintenance-priority-v2":
        "research/system-one/datasets/maintenance_priority.py",
}


class Refused(Exception):
    def __init__(self, message: str, code: int):
        super().__init__(message)
        self.code = code


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def pinned(directory: Path) -> dict:
    """The tracked manifest's per-split digests.

    Read from git, not from the working tree: a regenerated run rewrites
    MANIFEST.json, so comparing against the on-disk copy would compare a file
    with itself and pass unconditionally.
    """
    relative = directory.relative_to(ROOT) / "MANIFEST.json"
    result = subprocess.run(["git", "show", f"HEAD:{relative.as_posix()}"],
                            cwd=ROOT, capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise Refused(f"no tracked MANIFEST.json at {relative}: "
                      f"{result.stderr.strip()}", EXIT_USAGE)
    try:
        return json.loads(result.stdout)["files"]
    except (ValueError, KeyError) as error:
        raise Refused(f"tracked MANIFEST.json at {relative} has no usable "
                      f"'files' map: {error}", EXIT_USAGE) from None


def generate(directory: Path, generator: Path) -> None:
    if not generator.is_file():
        raise Refused(f"generator missing: {generator}", EXIT_USAGE)
    result = subprocess.run([sys.executable, "-I", str(generator), str(directory)],
                            cwd=ROOT, capture_output=True, text=True, timeout=900)
    if result.returncode:
        raise Refused(f"generator failed: {generator}\n{result.stderr.strip()[:2000]}",
                      EXIT_USAGE)


def verify(directory: Path) -> list[tuple[str, str, str]]:
    """Returns the splits that do not match, as (split, expected, actual)."""
    bad = []
    for split, expected in sorted(pinned(directory).items()):
        target = directory / f"{split}.jsonl"
        actual = sha256_file(target) if target.is_file() else "ABSENT"
        if actual != expected:
            bad.append((split, expected, actual))
    return bad


def run(do_generate: bool) -> int:
    worst = EXIT_OK
    for relative, generator_relative in DATASETS.items():
        directory = ROOT / relative
        generator = ROOT / generator_relative
        bad = verify(directory)
        if bad and do_generate:
            print(f"verify_datasets: regenerating {relative} "
                  f"({len(bad)} split(s) missing or mismatched)")
            generate(directory, generator)
            bad = verify(directory)
        if not bad:
            count = len(pinned(directory))
            print(f"verify_datasets: ok  {relative}  "
                  f"{count}/{count} splits match their pinned digests")
            continue
        absent = all(actual == "ABSENT" for _, _, actual in bad)
        for split, expected, actual in bad:
            print(f"verify_datasets: FAIL {relative}/{split}.jsonl"
                  f"\n    pinned: {expected}"
                  f"\n    actual: {actual}", file=sys.stderr)
        if absent and not do_generate:
            print(f"verify_datasets: run"
                  f"\n    deploy/syntriass/setup_env.sh"
                  f"\n  or, for the data only,"
                  f"\n    python3 -I deploy/syntriass/verify_datasets.py --generate",
                  file=sys.stderr)
            worst = max(worst, EXIT_MISSING)
        else:
            print("verify_datasets: a regenerated split that does not match its "
                  "pinned digest is a DIFFERENT dataset. Do not use it for any "
                  "measurement; the generator or its seed has changed.",
                  file=sys.stderr)
            worst = max(worst, EXIT_MISMATCH)
    return worst


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="verify only (default)")
    group.add_argument("--generate", action="store_true",
                       help="regenerate missing or mismatched datasets, then verify")
    args = parser.parse_args(argv)
    try:
        return run(args.generate)
    except Refused as error:
        print(f"verify_datasets: {error}", file=sys.stderr)
        return error.code


if __name__ == "__main__":
    sys.exit(main())
