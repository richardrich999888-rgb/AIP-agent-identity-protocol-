#!/usr/bin/env python3
"""Export exact, allowlisted RBI diagnostics/public evidence for CI upload.

Run after the rehearsal (including failure). Never chmod the original collector
state or copy a directory tree: that tree also holds private credentials.
Exporting evidence makes no statement that it passed verification.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

# Each entry was already intended for the RBI public artifact. No glob, recursive
# copy, keyfile, passphrase, environment dump, unsigned spool or private state.
PUBLIC_FILES = (
    "rbi-clock.txt", "rbi-build.log",
    "rbi-rehearsal/transcript.txt", "rbi-rehearsal/clock.log", "rbi-rehearsal/build.log",
    "rbi-rehearsal/system_run.log", "rbi-rehearsal/control_check.log",
    "rbi-rehearsal/act3_destination.log", "rbi-rehearsal/act4_toolcall.log",
    "rbi-rehearsal/act4b_gateway.out", "rbi-rehearsal/act4b_gateway.err",
    "rbi-rehearsal/act4b_receipt_check.err", "rbi-rehearsal/receipts.jsonl",
    "rbi-rehearsal/system/transcript.txt", "rbi-rehearsal/system/build.log",
    "rbi-rehearsal/system/host.txt", "rbi-rehearsal/system/summary.json",
    "rbi-rehearsal/system/health.A.control.jsonl",
    "rbi-rehearsal/system/health.B.under_attack.jsonl",
    "rbi-rehearsal/system/health.C.recovery.jsonl",
    "rbi-rehearsal/system/offline_verify.txt", "rbi-rehearsal/system/offline_verify_tampered.txt",
    "rbi-rehearsal/system/work/collector.log", "rbi-rehearsal/system/work/probe.log",
    "rbi-rehearsal/system/work/attack.log",
    "rbi-rehearsal/system/work/state/health.archive.jsonl",
    "rbi-rehearsal/system/work/state/attested.archive.jsonl",
    "rbi-rehearsal/system/work/state/observer.pub",
)
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024


class Refused(ValueError):
    pass


def source_member(source: Path, name: str) -> Path | None:
    current = source
    for part in Path(name).parts:
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(metadata.st_mode):
            raise Refused("symlink in public source path")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise Refused("public source must be a regular file with exactly one link")
    if metadata.st_size > MAX_FILE_BYTES:
        raise Refused("public source exceeds file size limit")
    return current


def collect(source: Path, destination: Path) -> dict:
    source = source.resolve(strict=True)
    if not source.is_dir():
        raise Refused("source directory required")
    destination.mkdir(mode=0o755, parents=False, exist_ok=False)
    destination.chmod(0o755)
    report = {"schema": "aip-rbi-public-export-v1", "verification_claim": False,
              "files": {}, "missing": [], "refused": {}}
    total = 0
    for name in PUBLIC_FILES:
        try:
            path = source_member(source, name)
            if path is None:
                report["missing"].append(name)
                continue
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            with os.fdopen(os.open(path, flags), "rb") as original:
                metadata = os.fstat(original.fileno())
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise Refused("opened source is not a regular file with exactly one link")
                if metadata.st_size > MAX_FILE_BYTES or total + metadata.st_size > MAX_TOTAL_BYTES:
                    raise Refused("public export exceeds size limit")
                target = destination / name
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                # New directories/files only. Original root-owned0600 archives
                # and every credential retain their original permissions.
                for parent in target.parents:
                    if parent == destination:
                        break
                    parent.chmod(0o755)
                digest = hashlib.sha256(); count = 0
                with target.open("xb") as copied:
                    while chunk := original.read(1024 * 1024):
                        count += len(chunk)
                        if count > MAX_FILE_BYTES or total + count > MAX_TOTAL_BYTES:
                            raise Refused("public source grew beyond size limit")
                        copied.write(chunk); digest.update(chunk)
                    copied.flush(); os.fsync(copied.fileno())
                after = os.fstat(original.fileno())
                if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
                        metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns):
                    target.unlink()
                    raise Refused("public source changed during export")
                target.chmod(0o444)
                total += count
                report["files"][name] = {"bytes": count, "sha256": digest.hexdigest()}
        except (OSError, Refused) as error:
            # Preserve other available diagnostics and explicitly report this
            # refusal. The workflow still fails and uploads this manifest.
            target = destination / name
            if target.is_file() and not target.is_symlink():
                target.unlink()
            report["refused"][name] = type(error).__name__ + ": " + str(error)
    report["status"] = "PARTIAL_REFUSED" if report["refused"] else "EXPORTED_AVAILABLE_FILES"
    manifest = destination / "export-manifest.json"
    manifest.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    manifest.chmod(0o444)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--github-output", type=Path, help="Actions step output file for a completed fresh export")
    args = parser.parse_args()
    report = collect(args.source, args.output)
    # Publish permission is emitted only after this attempt created the directory
    # and completed its manifest. Partial refusals retain diagnostics but fail.
    if args.github_output is not None:
        with args.github_output.open("a") as output:
            output.write("export_ready=true\n")
    print(json.dumps({"status": report["status"], "copied": len(report["files"]),
                      "missing": len(report["missing"]), "refused": len(report["refused"]),
                      "verification_claim": False}))
    return int(bool(report["refused"]))


if __name__ == "__main__":
    raise SystemExit(main())
