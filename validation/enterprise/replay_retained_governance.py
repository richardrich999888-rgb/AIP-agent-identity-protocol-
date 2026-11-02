#!/usr/bin/env python3
"""Offline replay of the one reviewed 3e6c179 retained governance package.

Trust this launcher, the explicit local Rust tools and the host running them.
Package hashes pin reviewed bytes; they do not establish independent custody.
No assets are downloaded and no agent, model, SDK or Collector is started.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import stat
import subprocess
import sys
import time
import zipfile

SOURCE = "3e6c1794000fa23006ef623722e37700e49582b7"
ZIP_SHA = "48ccc9525cade552b8eb28874e0c786b96a4b00024defd8b17e7cd9fbab6a505"
INVENTORY_SHA = "a75cf817cdd11cac2d1e20d52f8af1cddc4942f1c0b107e27080f70299be5109"
MEMBERS_SHA = "74210bc296597020f44ca288864216b4ef731ec127835a70ee3c058ecb81019a"
SCRIPTS = {
    "verify-original-core.py": "ea53514ca5ee3d54daf37c6c28fc76f1677b0e4adf78004236f07e8e67930b6b",
    "verify-physical-scope-and-audit.py": "ba6442d13299d44c84e7d37efca0fd6832c1bfe2ef3484688d19f733600a8a79",
    "verify-policy-and-collector-links.py": "e6e973239a64c81ab391e258e8d6fc5bc70124a9bafac2a9744cea006eba6d57",
}
TOOLS = ("aip-observe-verify", "aip-execution-assurance", "aip-tool-receipt", "aip-corroborate")
OLD_REPO = "/Users/richardrich/.codex/worktrees/snifferdog-complete-enterprise-validation/AIP"
OLD_ROOT = "/private/tmp/snifferdog-gov-3e6c179-41432473155"
OLD_SNAPSHOT = "/private/tmp/snifferdog-gov-3e6c179-replay-source"
MAX_FILE = 16 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def checked_path(value, *, directory=False, fresh=False):
    path = Path(os.path.abspath(value))
    for part in (path, *path.parents):
        require(not part.is_symlink(), "symlink path refused")
    if fresh:
        require(not path.exists(), "output directory already exists")
        require(path.parent.is_dir(), "output parent must exist")
    else:
        require(path.is_dir() if directory else path.is_file(), "required regular path missing")
    return path


def relative(value):
    require(isinstance(value, str) and value and "\\" not in value, "unsafe member path")
    require(all(p not in ("", ".", "..") for p in value.split("/")), "unsafe member path")
    path = PurePosixPath(value)
    require(not path.is_absolute(), "absolute member path refused")
    return Path(*path.parts)


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON object key")
            result[key] = value
        return result

    def constant(_value):
        raise ValueError("non-finite JSON value")

    return json.loads(raw, object_pairs_hook=unique, parse_constant=constant)


def pinned_bytes(path, digest):
    """Hash the bytes actually used, rather than an earlier path inspection."""
    checked_path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_FILE, "non-regular or oversized pinned file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        require((info.st_dev, info.st_ino) == (opened.st_dev, opened.st_ino), "pinned file changed before reading")
        raw = stream.read(MAX_FILE + 1)
    require(len(raw) <= MAX_FILE and hashlib.sha256(raw).hexdigest() == digest, "pinned file hash mismatch")
    return raw


def read_json(path):
    require(path.stat().st_size <= MAX_FILE, "oversized JSON file")
    return strict_json(path.read_bytes())


def save(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def verify_package(package):
    """Pin the inventory itself, then every file it names, before loading code."""
    inventory = package / "package-files.sha256.json"
    checked_path(inventory)
    rows = strict_json(pinned_bytes(inventory, INVENTORY_SHA))["files"]
    require(len(rows) == 102, "retained package file count mismatch")
    expected = {"package-files.sha256.json"}
    for row in rows:
        name = row["path"]
        path = package / relative(name)
        require(name not in expected, "duplicate inventory path")
        expected.add(name)
        checked_path(path)
        require(stat.S_ISREG(path.lstat().st_mode), "non-regular package file")
        require(path.stat().st_size == row["bytes"] <= MAX_FILE, "package file size mismatch")
        require(sha(path) == row["sha256"], "package file hash mismatch")
    actual = set()
    for path in package.rglob("*"):
        require(not path.is_symlink(), "package symlink refused")
        require(path.is_file() or path.is_dir(), "special package path refused")
        if path.is_file():
            actual.add(path.relative_to(package).as_posix())
    require(actual == expected, "unexpected or missing package file")
    require(sha(package / "original-member-inventory.json") == MEMBERS_SHA, "member manifest hash mismatch")
    require(sha(package / "original-artifact.zip") == ZIP_SHA, "original ZIP hash mismatch")
    for name, digest in SCRIPTS.items():
        require(sha(package / "replay-source" / name) == digest, "frozen replay script hash mismatch")
    return rows


def extract_originals(package, target):
    manifest = strict_json(pinned_bytes(package / "original-member-inventory.json", MEMBERS_SHA))
    rows = {row["member"]: row for row in manifest["members"]}
    require(len(rows) == len(manifest["members"]) == 154, "original member count mismatch")
    with zipfile.ZipFile(io.BytesIO(pinned_bytes(package / "original-artifact.zip", ZIP_SHA))) as archive:
        entries = archive.infolist()
        require(len(entries) == len(set(archive.namelist())) == 154, "duplicate ZIP member")
        require(set(archive.namelist()) == set(rows), "ZIP member manifest differs")
        require(sum(e.file_size for e in entries) < MAX_FILE, "expanded ZIP size exceeds bound")
        for entry in entries:
            rel = relative(entry.filename)
            require(stat.S_IFMT(entry.external_attr >> 16) in (0, stat.S_IFREG), "non-regular ZIP member")
            row = rows[entry.filename]
            require(entry.file_size == row["bytes"] <= MAX_FILE, "ZIP member size differs")
            raw = archive.read(entry)  # zipfile also verifies each original CRC.
            require(f"{entry.CRC:08x}" == row["zip_crc32"], "ZIP member CRC differs")
            require(hashlib.sha256(raw).hexdigest() == row["sha256"], "ZIP member SHA differs")
            path = target / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(raw)
        require(archive.testzip() is None, "original ZIP CRC failed")


def rust_tools(repo):
    # Explicit operator-supplied compiled tools are trusted. Source comparison
    # and recorded executable hashes are provenance, not build attestation.
    git = ["git", "-c", "core.fsmonitor=false", "-C", str(repo)]
    paths = ["aip-standalone", "Cargo.toml", "Cargo.lock"]
    subprocess.run(git + ["diff", "--no-ext-diff", "--no-textconv", "--exit-code", SOURCE, "--", *paths],
                   check=True, capture_output=True, timeout=30, env={"PATH": os.defpath})
    status = subprocess.run(git + ["status", "--porcelain", "--untracked-files=all", "--", *paths],
                            check=True, capture_output=True, timeout=30, env={"PATH": os.defpath})
    require(not status.stdout, "Rust source has local or untracked changes")
    result = {}
    for name in TOOLS:
        path = checked_path(repo / "target/debug" / name)
        require(stat.S_ISREG(path.lstat().st_mode) and os.access(path, os.X_OK), "Rust tool not executable")
        result[name] = {"path": str(path), "sha256": sha(path)}
    return result


def verify_opa(path, snapshot):
    lock = read_json(snapshot / "integrations/governance/opa.lock.json")
    arch = {"x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(platform.machine())
    key = platform.system().lower() + "_" + str(arch)
    require(key in lock["assets"], "OPA platform not pinned")
    asset = lock["assets"][key]
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o022 and os.access(path, os.X_OK),
            "OPA must be a protected executable regular file")
    require(info.st_size == asset["bytes"] and sha(path) == asset["sha256"], "OPA pin mismatch")
    return {"path": str(path), "platform": key, "version": lock["version"], "sha256": asset["sha256"]}


def transformed_scripts(package, repo, opa, out, snapshot):
    """Only replace exact known path assignments in fixed-SHA reviewed code."""
    def assignment(name, value):
        return name + "=Path(" + repr(str(value)) + ")"

    replacements = {
        "verify-original-core.py": [
            (assignment("REPO", OLD_REPO), assignment("REPO", repo)),
            (assignment("ROOT", OLD_ROOT + "/original"), assignment("ROOT", out / "original")),
            (assignment("ZIP", OLD_ROOT + "/original-artifact.zip"), assignment("ZIP", package / "original-artifact.zip")),
            (assignment("OUT", OLD_ROOT + "/independent-offline"), assignment("OUT", out / "independent-offline")),
        ],
        "verify-physical-scope-and-audit.py": [
            (assignment("REPO", OLD_REPO), assignment("REPO", repo)),
            ("sys.path.insert(0," + repr(OLD_SNAPSHOT + "/integrations/real_agents") + ")",
             "sys.path.insert(0," + repr(str(snapshot / "integrations/real_agents")) + ")"),
            (assignment("ROOT", OLD_ROOT), assignment("ROOT", out)),
        ],
        "verify-policy-and-collector-links.py": [
            (assignment("ROOT", OLD_ROOT), assignment("ROOT", out)),
            (assignment("SNAPSHOT", OLD_SNAPSHOT), assignment("SNAPSHOT", snapshot)),
            (assignment("OPA_ENGINE", "/private/tmp/snifferdog-opa-adapter-bootstrap/opa-1.22.0-darwin_arm64"),
             assignment("OPA_ENGINE", opa)),
        ],
    }
    target = out / "derived-path-configured-scripts"
    target.mkdir()
    transforms = []
    for name, pairs in replacements.items():
        original = pinned_bytes(package / "replay-source" / name, SCRIPTS[name]).decode("utf-8")
        adapted = original
        for before, after in pairs:
            require(adapted.count(before) == 1, "expected path assignment not unique")
            adapted = adapted.replace(before, after, 1)
        path = target / name
        with path.open("x") as stream:
            stream.write(adapted)
        transforms.append({"script": name, "original_sha256": SCRIPTS[name], "derived_sha256": sha(path),
                           "replacements": [{"original": a, "derived": b} for a, b in pairs]})
    save(out / "path-transformations.json", {"classification": "DERIVED_PATH_CONFIGURATION_ONLY",
         "method": "EXACT_ONCE_KNOWN_ASSIGNMENTS_IN_FIXED_SHA_REVIEWED_SCRIPTS", "scripts": transforms})
    return [target / name for name in SCRIPTS]


def replay(package, repo, opa, out):
    rows = verify_package(package)
    require(not out.is_relative_to(package), "output must be outside retained package")
    tools = rust_tools(repo)
    snapshot_input = package / "replay-source/exact-public-source"
    opa_identity = verify_opa(opa, snapshot_input)
    out.mkdir(mode=0o700)
    result = {"classification": "PORTABLE_REPLAY_OF_FIXED_RETAINED_GOVERNANCE_DATASET", "status": "PENDING",
              "source_commit": SOURCE, "run_id": 41432473155, "original_zip_sha256": ZIP_SHA,
              "actual_platform": platform.platform(), "rust_tools": tools, "OPA": opa_identity,
              "network_or_model_or_sdk_or_collector_started": False, "commands": [],
              "limits": ["Trust the launcher, explicit compiled Rust tools and local host. Hashes do not attest their build or independent custody.",
                         "Public anchors/checkpoints came in the same original GitHub artifact; separate CLI paths do not establish institution custody.",
                         "Frozen script labels mentioning Mac/Darwin are historical labels. Actual platform and verified OPA asset are recorded here and in new command receipts.",
                         "All predicates are the unchanged fixed-SHA scripts. Controller telemetry remains unsigned application metadata; core CannotProve limits remain."]}
    try:
        extract_originals(package, out / "original")
        snapshot = out / "exact-public-source"
        prefix = "replay-source/exact-public-source/"
        for row in rows:
            if row["path"].startswith(prefix):
                path = snapshot / relative(row["path"][len(prefix):])
                raw = pinned_bytes(package / row["path"], row["sha256"])
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("xb") as stream:
                    stream.write(raw)
        scripts = transformed_scripts(package, repo, opa, out, snapshot)
        for script in scripts:
            began = time.monotonic()
            completed = subprocess.run([sys.executable, "-I", "-B", str(script)], cwd=out,
                                       env={"PATH": os.defpath}, capture_output=True, timeout=600)
            stdout, stderr = out / (script.name + ".stdout.txt"), out / (script.name + ".stderr.txt")
            stdout.write_bytes(completed.stdout)
            stderr.write_bytes(completed.stderr)
            result["commands"].append({"script": script.name, "exit_code": completed.returncode,
                "seconds": time.monotonic() - began, "stdout_sha256": sha(stdout), "stderr_sha256": sha(stderr),
                "environment_keys": ["PATH"], "python_flags": ["-I", "-B"]})
            require(completed.returncode == 0, "frozen replay failed; inspect retained command stderr")
        require(verify_package(package) == rows, "retained package changed during replay")
        require(rust_tools(repo) == tools, "Rust source/tools changed during replay")
        require(verify_opa(opa, snapshot_input) == opa_identity, "OPA changed during replay")
        result["status"] = "PASS"
    except Exception as exc:
        result.update(status="FAIL", failure_type=type(exc).__name__, failure=str(exc))
        raise
    finally:
        save(out / "portable-replay-result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, help="unchanged fixed retained package directory")
    parser.add_argument("--repo", required=True, help="trusted checkout with four compiled target/debug Rust tools")
    parser.add_argument("--opa", required=True, help="already prepared platform-pinned OPA executable")
    parser.add_argument("--out", required=True, help="fresh directory under an existing parent")
    args = parser.parse_args()
    try:
        require(sys.version_info >= (3, 12) and __debug__, "requires Python3.12+ without optimization")
        result = replay(checked_path(args.package, directory=True), checked_path(args.repo, directory=True),
                        checked_path(args.opa), checked_path(args.out, fresh=True))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, zipfile.BadZipFile) as exc:
        print("Replay refused: " + type(exc).__name__ + ": " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps({"status": result["status"], "out": str(Path(args.out).absolute()),
                      "profiles": 3, "source_commit": SOURCE}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
