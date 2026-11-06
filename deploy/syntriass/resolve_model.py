#!/usr/bin/env python3
"""Resolve a pinned model, or the bundled llama-server, from the offline bundle.

Replaces the absolute paths that were hard-coded in five scripts
(`/home/claude/vanian-build/...`), which made every one of them unrunnable on
any machine but the original build host.

Resolution order, highest precedence first. The first two preserve overrides
that already existed, so no caller loses a knob:

  1. `MODELS` / `LLAMA_SERVER`   — explicit absolute override
  2. `$SYNTRIASS_BUNDLE/models`  — a staged bundle in a non-default place
  3. `/opt/syntriass/current/`   — where README.md section 3 installs it

Integrity: SHA-256 against `models.manifest.json`, which subsumes the
documented size. A file whose digest differs is NOT the pinned artifact and is
refused outright — never used with a warning, because a demo that silently
runs different weights produces numbers nobody can reproduce.

Hashing a 1.8 GiB file costs real time, so `path` does not hash by default.
`--verify` hashes, and `verify` hashes every staged model. Anything that
records a measurement must use `--verify`.

Exit codes are the contract:
  0  resolved (and verified, if asked)
  2  caller error — unknown logical name, bad arguments
  3  not staged — bundle or file absent; message says how to stage it
  4  integrity failure — present but not the pinned bytes
  5  provenance incomplete — source or licence unverified (staging only)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "models.manifest.json"
UNVERIFIED = "UNVERIFIED_NO_NETWORK"

EXIT_OK, EXIT_USAGE, EXIT_NOT_STAGED, EXIT_INTEGRITY, EXIT_PROVENANCE = 0, 2, 3, 4, 5


class Refused(Exception):
    """Resolution failed. `code` is the process exit code."""

    def __init__(self, message: str, code: int):
        super().__init__(message)
        self.code = code


def manifest() -> dict:
    try:
        return json.loads(MANIFEST.read_text())
    except FileNotFoundError:
        raise Refused(f"models manifest missing: {MANIFEST}", EXIT_USAGE) from None
    except ValueError as error:
        raise Refused(f"models manifest is not valid JSON: {MANIFEST}: {error}",
                      EXIT_USAGE) from None


def entry(logical_name: str, data: dict | None = None) -> dict:
    data = data or manifest()
    for candidate in data["models"]:
        if candidate["logical_name"] == logical_name:
            return candidate
    known = ", ".join(sorted(c["logical_name"] for c in data["models"]))
    blocked = data.get("not_yet_pinned", {})
    extra = ""
    if blocked:
        extra = (f"\n  Not yet pinned ({blocked.get('tracked_as', 'see manifest')}): "
                 + "; ".join(blocked.get("requested", []))
                 + f"\n  Reason: {blocked.get('reason', '')}")
    raise Refused(f"unknown model '{logical_name}'.\n  Pinned: {known}{extra}",
                  EXIT_USAGE)


def bundle_root() -> Path:
    """The staged bundle's root, by precedence. Existence is checked by callers."""
    override = os.environ.get("SYNTRIASS_BUNDLE")
    if override:
        return Path(override)
    return Path(manifest()["bundle_layout"]["root_default"])


def models_dir() -> Path:
    """Directory holding the GGUF files. `MODELS` still wins, as before."""
    override = os.environ.get("MODELS")
    if override:
        return Path(override)
    return bundle_root() / manifest()["bundle_layout"]["models_subdir"]


def _staging_help(target: Path) -> str:
    return (f"\n  Expected at: {target}"
            f"\n  Stage the bundle: deploy/syntriass/README.md sections 2-3"
            f"\n  Or point at an existing one: SYNTRIASS_BUNDLE=/path/to/bundle"
            f"\n  Or override this directory only: MODELS=/path/to/models")


def file_sha256(path: Path) -> str:
    """Streamed, so a 1.8 GiB model does not have to fit in memory."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def resolve(logical_name: str, *, verify: bool = False) -> Path:
    """Absolute path to a staged, pinned model. Raises `Refused` otherwise."""
    record = entry(logical_name)
    directory = models_dir()
    target = directory / record["file"]
    if not directory.is_dir():
        raise Refused(
            f"model directory not staged: {directory}" + _staging_help(target),
            EXIT_NOT_STAGED)
    if not target.is_file():
        present = sorted(p.name for p in directory.glob("*.gguf"))
        raise Refused(
            f"model '{logical_name}' is not staged." + _staging_help(target)
            + f"\n  Staged in that directory: {present or 'none'}",
            EXIT_NOT_STAGED)
    if verify:
        actual = file_sha256(target)
        if actual != record["sha256"]:
            raise Refused(
                f"model '{logical_name}' is NOT the pinned artifact; refusing to use it."
                f"\n  File:     {target}"
                f"\n  Expected: {record['sha256']}"
                f"\n  Actual:   {actual}"
                f"\n  Pinned by: {record['sha256_provenance']}"
                f"\n  Re-stage the file; a demo must never run unpinned weights.",
                EXIT_INTEGRITY)
    return target


def llama_server() -> Path:
    """The bundled llama-server wrapper. `LLAMA_SERVER` still wins."""
    override = os.environ.get("LLAMA_SERVER")
    candidate = Path(override) if override else (
        bundle_root() / manifest()["bundle_layout"]["llama_server"])
    if not candidate.is_file():
        raise Refused(
            f"llama-server not staged: {candidate}"
            f"\n  Stage the bundle: deploy/syntriass/README.md sections 2-3"
            f"\n  Or override: LLAMA_SERVER=/path/to/llama-server",
            EXIT_NOT_STAGED)
    if not os.access(candidate, os.X_OK):
        raise Refused(f"llama-server is not executable: {candidate}", EXIT_NOT_STAGED)
    return candidate


def provenance_gaps(logical_name: str) -> list[str]:
    """Fields a staging download must not proceed without."""
    record = entry(logical_name)
    return [field for field in ("source_url", "licence")
            if record.get(field, UNVERIFIED) == UNVERIFIED]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    one = sub.add_parser("path", help="absolute path to a pinned model")
    one.add_argument("logical_name")
    one.add_argument("--verify", action="store_true", help="hash the file (slow, authoritative)")

    sha = sub.add_parser("sha", help="pinned SHA-256 of a model")
    sha.add_argument("logical_name")

    sub.add_parser("dir", help="absolute path to the staged models directory")
    sub.add_parser("server", help="absolute path to the bundled llama-server")
    sub.add_parser("list", help="pinned logical names, one per line")
    sub.add_parser("verify", help="hash every staged model against the manifest")

    gaps = sub.add_parser("provenance", help="exit 5 if source or licence is unverified")
    gaps.add_argument("logical_name")

    args = parser.parse_args(argv)
    try:
        if args.command == "path":
            print(resolve(args.logical_name, verify=args.verify))
        elif args.command == "sha":
            print(entry(args.logical_name)["sha256"])
        elif args.command == "dir":
            directory = models_dir()
            if not directory.is_dir():
                raise Refused(f"model directory not staged: {directory}"
                              + _staging_help(directory / "<model>.gguf"),
                              EXIT_NOT_STAGED)
            print(directory)
        elif args.command == "server":
            print(llama_server())
        elif args.command == "list":
            for record in manifest()["models"]:
                print(record["logical_name"])
        elif args.command == "verify":
            data = manifest()
            failures = 0
            for record in data["models"]:
                name = record["logical_name"]
                try:
                    resolve(name, verify=True)
                    print(f"ok        {name}")
                except Refused as error:
                    failures = max(failures, error.code)
                    print(f"FAILED    {name}: {error}", file=sys.stderr)
            return failures
        elif args.command == "provenance":
            missing = provenance_gaps(args.logical_name)
            if missing:
                raise Refused(
                    f"model '{args.logical_name}' has unverified provenance: "
                    + ", ".join(missing)
                    + "\n  " + manifest()["provenance_rule"],
                    EXIT_PROVENANCE)
            print("ok")
    except Refused as error:
        print(f"resolve_model: {error}", file=sys.stderr)
        return error.code
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
