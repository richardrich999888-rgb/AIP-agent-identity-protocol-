#!/usr/bin/env python3
"""Offline, stdlib-only packaging for the existing Linux probe/collector.

This tool does not sign observations, open kernel sensors, or start services.
Package verification must use an independently obtained archive digest.
"""

import argparse
import hashlib
import io
import ipaddress
import json
import os
import platform
from pathlib import Path, PurePosixPath
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile

REPO = Path(__file__).resolve().parents[3]
FORMAT = "vanian-runtime-package-v1"
BINARIES = ("aip-probe", "aip-collector", "aip-observe-verify")
TARGETS = {"x86_64-unknown-linux-gnu": 62, "aarch64-unknown-linux-gnu": 183}
MAX_FILE = 256 * 1024 * 1024
MAX_TOTAL = 768 * 1024 * 1024
SENSORS = {
    "sched": ("sched/sched_process_fork", "sched/sched_process_exec"),
    "cgroup": ("cgroup/cgroup_mkdir", "cgroup/cgroup_rmdir", "cgroup/cgroup_attach_task"),
    "sockstate": ("sock/inet_sock_set_state",),
    "socksend": ("sock/sock_send_length",),
    "connector": (), "fanotify": (), "afpacket": (),
}
PROBE_KEYS = {
    "ID", "COLLECTOR_ENDPOINT", "COLLECTOR_NOISE_PUBKEY", "KEY_PATH", "SENSORS",
    "FANOTIFY_PATH", "AFPACKET_INTERFACE", "BATCH_INTERVAL_MS",
}
COLLECTOR_KEYS = {
    "OBSERVER_ID", "KEY_VERSION", "KEY_PATH", "PASSPHRASE_FILE", "CONTINUITY",
    "STATE_DIR", "LISTEN", "PROBES_PATH", "NOISE_KEY_PATH", "ATTESTED_ARCHIVE_PATH",
    "REQUIRE_SYNCED_CLOCK", "CLOCK_MAX_ERROR_MS",
}


def fail(message):
    raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def elf_check(data, target):
    if (len(data) < 64 or data[:6] != b"\x7fELF\x02\x01"
            or int.from_bytes(data[18:20], "little") != TARGETS[target]):
        fail(f"binary is not a 64-bit little-endian Linux ELF for {target}")


def build(args):
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_commit):
        fail("source-commit must be the complete reviewed 40-character Git SHA")
    payload = {}
    for name in BINARIES:
        path = Path(args.bin_dir) / name
        if path.is_symlink() or not path.is_file():
            fail(f"missing regular executable {path}")
        if not os.access(path, os.X_OK):
            fail(f"binary is not executable: {path}")
        data = path.read_bytes()
        elf_check(data, args.target)
        payload[f"bin/{name}"] = (data, 0o755)
    for role in ("probe", "collector"):
        for relative in (f"systemd/aip-{role}.service", f"{role}.env.example"):
            payload[relative] = ((REPO / "deploy/pilot" / relative).read_bytes(), 0o644)
    payload["package.py"] = (Path(__file__).read_bytes(), 0o755)
    manifest = {
        "format": FORMAT, "source_commit": args.source_commit,
        "target": args.target, "mode": "OBSERVER_ONLY",
        "provenance": "operator-supplied source commit; binary provenance requires the reviewed build transcript",
        "files": {name: {"sha256": digest(data), "mode": mode}
                  for name, (data, mode) in sorted(payload.items())},
    }
    payload["manifest.json"] = (canonical(manifest), 0o644)
    output = Path(args.output)
    if output.exists():
        fail(f"refusing to replace {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    # A fixed order/mtime/uid makes the same input bytes reproducible.
    with output.open("xb") as stream:
        with tarfile.open(fileobj=stream, mode="w") as archive:
            for name, (data, mode) in sorted(payload.items()):
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime = len(data), mode, 0
                archive.addfile(info, io.BytesIO(data))
    print(json.dumps({"archive": str(output), "sha256": digest(output.read_bytes()),
                      "source_commit": args.source_commit, "target": args.target}))


def verified_package(path, expected):
    if not re.fullmatch(r"[0-9a-fA-F]{64}", expected or ""):
        fail("an independently obtained --expected-sha256 is required (64 hex digits)")
    if Path(path).stat().st_size > MAX_TOTAL:
        fail("package is larger than the permitted size")
    raw = Path(path).read_bytes()
    if digest(raw) != expected.lower():
        fail("archive SHA-256 differs from the trusted value")
    files, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for member in archive:
            name = member.name
            parts = PurePosixPath(name).parts
            if (not member.isfile() or name in files or name.startswith("/")
                    or ".." in parts or "\\" in name or str(PurePosixPath(name)) != name
                    or member.size > MAX_FILE or member.size < 0):
                fail(f"unsafe or repeated package member: {name!r}")
            total += member.size
            if len(files) >= 32 or total > MAX_TOTAL:
                fail("package expansion limit exceeded")
            files[name] = (archive.extractfile(member).read(), member.mode)
    try:
        manifest = json.loads(files["manifest.json"][0])
        if (manifest["format"] != FORMAT or manifest["mode"] != "OBSERVER_ONLY"
                or manifest["target"] not in TARGETS
                or not re.fullmatch(r"[0-9a-f]{40}", manifest["source_commit"])):
            fail("unsupported manifest or operating mode")
        expected_names = {"package.py"}
        expected_names.update(f"bin/{name}" for name in BINARIES)
        expected_names.update(f"systemd/aip-{role}.service" for role in ("probe", "collector"))
        expected_names.update(f"{role}.env.example" for role in ("probe", "collector"))
        if set(manifest["files"]) != expected_names or set(files) != expected_names | {"manifest.json"}:
            fail("package does not contain exactly the approved runtime files")
        for name, record in manifest["files"].items():
            data, mode = files[name]
            approved_mode = 0o755 if name.startswith("bin/") or name == "package.py" else 0o644
            if (record != {"sha256": digest(data), "mode": approved_mode}
                    or mode != approved_mode):
                fail(f"manifest integrity/mode check failed: {name}")
        for name in BINARIES:
            elf_check(files[f"bin/{name}"][0], manifest["target"])
        return manifest, files
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        fail(f"invalid manifest: {error}")


def parse_config(path, role):
    """A deliberately restricted EnvironmentFile subset; never source a shell."""
    config = {}
    for number, line in enumerate(Path(path).read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=([^\r\n]+)", line)
        if not match:
            fail(f"invalid configuration at line {number}")
        key, value = match.groups()
        if key in config:
            fail(f"duplicate configuration key {key}")
        # Shell expansions, inline comments, quotes and whitespace are refused
        # so the validator and systemd cannot read the same file differently.
        if not re.fullmatch(r"[A-Za-z0-9_./,:@%+\[\]-]+", value):
            fail(f"unsupported characters or unresolved placeholder in {key}")
        prefix = f"AIP_{role.upper()}_"
        keys = PROBE_KEYS if role == "probe" else COLLECTOR_KEYS
        if key != "RUST_LOG" and (not key.startswith(prefix) or key[len(prefix):] not in keys):
            fail(f"unknown or cross-role configuration key {key}")
        config[key] = value
    prefix = f"AIP_{role.upper()}_"
    required = ("ID", "COLLECTOR_ENDPOINT", "COLLECTOR_NOISE_PUBKEY", "KEY_PATH", "SENSORS") if role == "probe" else (
        "OBSERVER_ID", "KEY_PATH", "STATE_DIR", "LISTEN", "PROBES_PATH", "NOISE_KEY_PATH")
    for key in required:
        if prefix + key not in config:
            fail(f"missing required {prefix + key}")
    for key, value in config.items():
        if key.endswith(("_PATH", "_DIR", "_FILE")):
            p = Path(value)
            if not p.is_absolute() or ".." in p.parts:
                fail(f"{key} must be an absolute path without traversal")
    if role == "probe":
        if not re.fullmatch(r"[0-9a-fA-F]{64}", config[prefix + "COLLECTOR_NOISE_PUBKEY"]):
            fail("collector Noise public key must have 64 hex digits")
        sensors = config[prefix + "SENSORS"].split(",")
        if not sensors or len(set(sensors)) != len(sensors) or set(sensors) - set(SENSORS):
            fail("unknown, duplicate or empty sensor selection")
        if "fanotify" in sensors:
            # The shipped pilot systemd unit lacks CAP_SYS_ADMIN and hides
            # mounts. Never install a sensor/unit combination that cannot run.
            fail("fanotify needs an institution-reviewed systemd override; not supported by this installer")
        endpoint = config[prefix + "COLLECTOR_ENDPOINT"]
        host, separator, port = endpoint.rpartition(":")
        if not separator or not host or not port.isdigit() or not 1 <= int(port) <= 65535:
            fail("collector endpoint must be host:port (IPv6 in brackets)")
        host = host.strip("[]")
        try:
            loopback = ipaddress.ip_address(host).is_loopback or ipaddress.ip_address(host).is_unspecified
        except ValueError:
            # Config validation is offline and must not block on reverse DNS.
            # Aliases/routing still need actual host preflight and institution
            # review; a hostname guard cannot prove separate administration.
            loopback = host.lower() in {"localhost", "localhost.localdomain", socket.gethostname().lower()}
        if loopback:
            fail("enterprise collector endpoint must be a separate host")
        if int(config.get(prefix + "BATCH_INTERVAL_MS", "2000")) < 100:
            fail("batch interval must be at least 100 ms")
    else:
        if prefix + "PASSPHRASE_FILE" in config:
            fail("this installer requires the systemd collector-passphrase credential, not PASSPHRASE_FILE")
        if config.get(prefix + "CONTINUITY", "strict") != "strict":
            fail("enterprise installation requires strict continuity")
        if config.get(prefix + "REQUIRE_SYNCED_CLOCK", "1") not in {"1", "true"}:
            fail("enterprise installation requires synchronized collector clock")
        for key in ("KEY_VERSION", "CLOCK_MAX_ERROR_MS"):
            if int(config.get(prefix + key, "1")) < 1:
                fail(f"{prefix + key} must be positive")
        if config[prefix + "KEY_PATH"] == config[prefix + "NOISE_KEY_PATH"]:
            fail("evidence-signing and Noise transport keys must be separate files")
    # Keep writable files inside the paths the reused systemd sandbox permits.
    state_root = Path(f"/var/lib/aip-{role}")
    for key, value in config.items():
        if key.endswith(("KEY_PATH", "STATE_DIR", "ATTESTED_ARCHIVE_PATH")):
            if not Path(value).is_relative_to(state_root):
                fail(f"{key} must be below {state_root} for the shipped unit")
    return config


def preflight(args):
    config = parse_config(args.config, args.role)
    if args.config_only:
        print("CONFIG_VALIDATED: no sensors opened; runtime capabilities not established")
        return
    if platform.system() != "Linux":
        fail("BLOCKED: Linux is required; no runtime validation was performed")
    if not Path("/run/systemd/system").is_dir() or shutil.which("systemctl") is None:
        fail("BLOCKED: systemd host and systemctl are required")
    if args.role == "probe":
        trace_root = Path("/sys/kernel/tracing/events")
        for sensor in config["AIP_PROBE_SENSORS"].split(","):
            for tracepoint in SENSORS[sensor]:
                for item in ("id", "format"):
                    if not os.access(trace_root / tracepoint / item, os.R_OK):
                        fail(f"BLOCKED: unreadable tracepoint {tracepoint}/{item}")
        print("PREREQUISITES_PRESENT: actual sensor open/coverage must still pass under the service identity")
    else:
        result = subprocess.run(["timedatectl", "show", "--property=NTPSynchronized", "--value"],
                                capture_output=True, text=True, timeout=10, check=False)
        if result.returncode or result.stdout.strip() != "yes":
            fail("BLOCKED: clock synchronization not established")
        print("PREREQUISITES_PRESENT: collector independently checks kernel clock discipline at startup")


def safe_destination(root, absolute):
    path = root / absolute.lstrip("/")
    current = root
    for part in Path(absolute.lstrip("/")).parts:
        if part in {"..", "."}:
            fail("unsafe installation path")
        current = current / part
        if current.is_symlink():
            fail(f"refusing symbolic link in installation path: {current}")
    return path


def installation_root(args):
    root = Path(args.root).absolute()
    if root == Path("/"):
        if platform.system() != "Linux" or os.geteuid() != 0:
            fail("live installation/uninstallation requires Linux and root")
    elif not root.is_dir() or root.is_symlink():
        fail("staging root must be an existing non-symlink directory")
    # Reject symlinks in ancestors too; stage mode must not escape its tree.
    if root.resolve() != root:
        fail("installation root must be canonical, without symbolic links")
    return root


def render_unit(role, template, config):
    """Reuse the pilot unit and one hardening/capability policy across formats."""
    unit = template.decode().replace("/usr/local/bin/", "/opt/vanian/snifferdog/bin/")
    unit = unit.replace("[Service]\n", "[Service]\nMemoryMax=512M\nTasksMax=128\nLimitNOFILE=8192\nCPUQuota=100%\nUMask=0077\n")
    if role == "collector":
        unit = unit.replace("LoadCredential=collector-passphrase\n",
                            "LoadCredential=collector-passphrase:/etc/aip/collector-passphrase\n")
    else:
        sensors = config.get("AIP_PROBE_SENSORS", "").split(",")
        capabilities = probe_capabilities([sensor for sensor in sensors if sensor])
        unit = re.sub(r"(?m)^(AmbientCapabilities|CapabilityBoundingSet)=.*$",
                      lambda match: match.group(1) + "=" + " ".join(capabilities), unit)
    return unit.encode()


def probe_capabilities(sensors):
    capabilities = []
    if any(SENSORS[sensor] for sensor in sensors):
        capabilities.append("CAP_PERFMON")
    if "connector" in sensors:
        capabilities.append("CAP_NET_ADMIN")
    if "afpacket" in sensors:
        capabilities.append("CAP_NET_RAW")
    return capabilities


def install(args):
    manifest, package = verified_package(args.archive, args.expected_sha256)
    root = installation_root(args)
    config = parse_config(args.config, args.role)
    if root == Path("/"):
        machine = {"x86_64": "x86_64", "aarch64": "aarch64"}.get(platform.machine())
        if not manifest["target"].startswith(str(machine) + "-"):
            fail("package target does not match this host")
        preflight(argparse.Namespace(config=args.config, role=args.role, config_only=False))
        if not args.confirm_separate_host:
            fail("confirm separate administrative collector/workload hosts with --confirm-separate-host")
    receipt_path = safe_destination(root, "/etc/aip/vanian-runtime-install.json")
    if receipt_path.exists():
        fail("runtime role already installed; uninstall software first, preserving keys/evidence/config")
    other = "collector" if args.role == "probe" else "probe"
    for location in (f"/etc/aip/{other}.env", f"/etc/systemd/system/aip-{other}.service"):
        if safe_destination(root, location).exists():
            fail("probe and collector must be installed on separate hosts")
    mapping = {
        f"/opt/vanian/snifferdog/bin/aip-{args.role}": package[f"bin/aip-{args.role}"],
        "/opt/vanian/snifferdog/bin/aip-observe-verify": package["bin/aip-observe-verify"],
        "/opt/vanian/snifferdog/package.py": package["package.py"],
    }
    mapping[f"/etc/systemd/system/aip-{args.role}.service"] = (
        render_unit(args.role, package[f"systemd/aip-{args.role}.service"][0], config), 0o644)
    config_path = f"/etc/aip/{args.role}.env"
    previous_config = safe_destination(root, config_path)
    if previous_config.exists():
        if previous_config.read_bytes() != Path(args.config).read_bytes():
            fail("existing configuration differs; retain and review it before installation")
    else:
        mapping[config_path] = (Path(args.config).read_bytes(), 0o600)
    # All target checks precede writes. No extraction or arbitrary package path
    # is ever passed to a shell or used as a destination.
    for location in mapping:
        if safe_destination(root, location).exists():
            fail(f"refusing to overwrite existing {location}")
    if root == Path("/"):
        import grp
        import pwd
        try:
            account = pwd.getpwnam(f"aip-{args.role}")
        except KeyError:
            subprocess.run(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir",
                            f"/var/lib/aip-{args.role}", "--shell", "/usr/sbin/nologin",
                            f"aip-{args.role}"], check=True)
            account = pwd.getpwnam(f"aip-{args.role}")
        if account.pw_uid == 0:
            fail("runtime service account must not be root")
        if grp.getgrnam(f"aip-{args.role}").gr_gid != account.pw_gid:
            fail("service account must have its same-named primary group")
    state = safe_destination(root, f"/var/lib/aip-{args.role}")
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root == Path("/"):
        os.chown(state, account.pw_uid, account.pw_gid)
        os.chmod(state, 0o700)
    installed = {}
    for location, (data, mode) in mapping.items():
        target = safe_destination(root, location)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data)
        target.chmod(mode)
        if not location.endswith(".env"):
            installed[location] = digest(data)
    receipt_path.write_bytes(canonical({"format": FORMAT, "role": args.role,
        "source_commit": manifest["source_commit"], "archive_sha256": args.expected_sha256.lower(),
        "installed": installed, "mode": "OBSERVER_ONLY"}))
    receipt_path.chmod(0o600)
    if root == Path("/"):
        subprocess.run(["systemctl", "daemon-reload"], check=True)
    print("INSTALLED: services are not started; finish credentials, allow-list and operator acceptance")


def uninstall(args):
    root = installation_root(args)
    receipt_path = safe_destination(root, "/etc/aip/vanian-runtime-install.json")
    receipt = json.loads(receipt_path.read_text())
    role = receipt.get("role")
    if role not in {"probe", "collector"} or receipt.get("format") != FORMAT:
        fail("invalid installation receipt")
    allowed = {f"/opt/vanian/snifferdog/bin/aip-{role}", "/opt/vanian/snifferdog/bin/aip-observe-verify",
               "/opt/vanian/snifferdog/package.py", f"/etc/systemd/system/aip-{role}.service"}
    if set(receipt["installed"]) != allowed:
        fail("installation receipt contains unexpected paths")
    # Refuse before deleting anything if a local administrator changed a file.
    for location, expected in receipt["installed"].items():
        target = safe_destination(root, location)
        if not target.is_file() or digest(target.read_bytes()) != expected:
            fail(f"local change or missing file at {location}; review before uninstall")
    if root == Path("/"):
        subprocess.run(["systemctl", "disable", "--now", f"aip-{role}.service"], check=True)
    for location in receipt["installed"]:
        safe_destination(root, location).unlink()
    receipt_path.unlink()
    if root == Path("/"):
        subprocess.run(["systemctl", "daemon-reload"], check=True)
    print("UNINSTALLED software only: retained config, accounts, credentials, trust anchors, keys and all evidence")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("build")
    command.add_argument("--bin-dir", required=True)
    command.add_argument("--source-commit", required=True)
    command.add_argument("--target", choices=TARGETS, required=True)
    command.add_argument("--output", required=True)
    for name in ("verify", "install"):
        command = commands.add_parser(name)
        command.add_argument("--archive", required=True)
        command.add_argument("--expected-sha256", required=True)
        if name == "install":
            command.add_argument("--role", choices=("probe", "collector"), required=True)
            command.add_argument("--config", required=True)
            command.add_argument("--root", default="/", help="existing staging directory for packaging tests only")
            command.add_argument("--confirm-separate-host", action="store_true")
    command = commands.add_parser("preflight")
    command.add_argument("--role", choices=("probe", "collector"), required=True)
    command.add_argument("--config", required=True)
    command.add_argument("--config-only", action="store_true")
    command = commands.add_parser("uninstall")
    command.add_argument("--root", default="/")
    args = parser.parse_args()
    try:
        if args.command == "verify":
            manifest, _ = verified_package(args.archive, args.expected_sha256)
            print(json.dumps({"status": "PACKAGE_VERIFIED", "manifest": manifest}))
        else:
            globals()[args.command](args)
    except (ValueError, OSError, KeyError, tarfile.TarError, subprocess.SubprocessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
