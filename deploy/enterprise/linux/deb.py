#!/usr/bin/env python3
"""Build role-separated DEBs from an independently approved runtime archive.

The archive verifier, configuration semantics and unit hardening are reused
from package.py. No daemon is started by installation or configuration.
"""
from __future__ import annotations

import argparse
import grp
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("vanian_runtime_package", HERE / "package.py")
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
PRODUCTS = {"probe": "vanian-snifferdog-agent", "collector": "vanian-evidence-collector"}


def put(root, path, content, mode=0o644):
    destination = runtime.safe_destination(root, path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(content)
    destination.chmod(mode)


def build(args):
    manifest, files = runtime.verified_package(args.archive, args.expected_sha256)
    if files["package.py"][0] != (HERE / "package.py").read_bytes():
        raise ValueError("archive installer differs from this reviewed Debian builder")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[+~][a-z0-9.]+)?", args.version) or len(args.version) > 64:
        raise ValueError("explicit Debian evaluation version required")
    if not shutil.which("dpkg-deb"):
        raise ValueError("dpkg-deb is required")
    output = Path(args.output).absolute()
    if output.exists():
        raise ValueError("refusing to replace an existing DEB")
    role, product = args.role, PRODUCTS[args.role]
    architecture = {"x86_64-unknown-linux-gnu": "amd64", "aarch64-unknown-linux-gnu": "arm64"}[manifest["target"]]
    other = PRODUCTS["collector" if role == "probe" else "probe"]
    with tempfile.TemporaryDirectory(prefix="vanian-deb-") as directory:
        root = Path(directory)
        glibc_versions = []
        for binary in (f"aip-{role}", "aip-observe-verify"):
            put(root, f"/opt/vanian/snifferdog/bin/{binary}", files[f"bin/{binary}"][0], 0o755)
            binary_path = root / f"opt/vanian/snifferdog/bin/{binary}"
            versions = subprocess.run(["readelf", "--version-info", str(binary_path)],
                                      check=True, capture_output=True, text=True).stdout
            glibc_versions.extend(tuple(int(part) for part in value.split("."))
                                  for value in re.findall(r"GLIBC_([0-9.]+)", versions))
            needed = subprocess.run(["readelf", "-d", str(binary_path)],
                                    check=True, capture_output=True, text=True).stdout
            libraries = set(re.findall(r"Shared library: \[([^]]+)\]", needed))
            if libraries - {"libc.so.6", "libm.so.6", "libgcc_s.so.1", "ld-linux-x86-64.so.2", "ld-linux-aarch64.so.1"}:
                raise ValueError("unqualified dynamic library; review Debian dependencies before packaging")
        if not glibc_versions:
            raise ValueError("GNU libc version requirements could not be established")
        glibc_minimum = ".".join(str(part) for part in max(glibc_versions))
        # Only this role's binaries are shipped; the shared verifier has no key.
        for name in ("package.py", "deb.py"):
            put(root, f"/usr/lib/vanian/runtime/{name}", (HERE / name).read_bytes(), 0o755)
        unit = runtime.render_unit(role, files[f"systemd/aip-{role}.service"][0], {}).decode()
        unit = unit.replace("[Unit]\n", f"[Unit]\nConditionPathExists=/etc/aip/{role}.configured.json\n")
        unit = unit.replace("[Service]\n", f"[Service]\nExecStartPre=/usr/sbin/{product} check\n")
        put(root, f"/lib/systemd/system/aip-{role}.service", unit.encode())
        launcher = ("#!/usr/bin/python3\nimport sys\nsys.path.insert(0, '/usr/lib/vanian/runtime')\n"
                    f"from deb import configure_cli\nraise SystemExit(configure_cli('{role}'))\n")
        put(root, f"/usr/sbin/{product}", launcher.encode(), 0o755)
        put(root, f"/usr/share/doc/{product}/{role}.env.example", files[f"{role}.env.example"][0])
        put(root, f"/usr/share/doc/{product}/runtime-manifest.json", runtime.canonical(manifest))
        put(root, f"/usr/share/doc/{product}/delivery-tool-sha256.json", runtime.canonical({
            name: runtime.digest((HERE / name).read_bytes()) for name in ("package.py", "deb.py")}))
        put(root, f"/usr/share/doc/{product}/copyright", (
            "VANIAN source declares LicenseRef-Proprietary in Cargo.toml.\n"
            "This unpublished engineering artifact contains no distribution license grant.\n"
            "An institution-approved license and complete dependency notices are required before release.\n").encode())
        put(root, f"/usr/share/doc/{product}/THIRD_PARTY_LICENSES.md",
            (runtime.REPO / "THIRD_PARTY_LICENSES.md").read_bytes())
        control = (f"Package: {product}\nVersion: {args.version}\nArchitecture: {architecture}\n"
                   "Maintainer: VANIAN Engineering <engineering@vanian.invalid>\n"
                   f"Conflicts: {other}\nDepends: python3 (>= 3.9), systemd (>= 247), passwd, libc6 (>= {glibc_minimum}), libgcc-s1\n"
                   "Section: admin\nPriority: optional\n"
                   f"Description: VANIAN observer-only {role} engineering evaluation\n"
                   " No automatic start. Configure approved separate-host evidence collection.\n")
        put(root, "/DEBIAN/control", control.encode())
        opposite = "collector" if role == "probe" else "probe"
        preinst = ("#!/bin/sh\nset -eu\n"
            "if [ -e /etc/aip/vanian-runtime-install.json ]; then\n"
            "  echo 'Remove the tar-managed software with its retained-data uninstall first' >&2; exit 1\nfi\n"
            f"if [ -e /etc/aip/{opposite}.env ]; then\n"
            "  echo 'Probe and collector require separate approved hosts' >&2; exit 1\nfi\n")
        postinst = ("#!/bin/sh\nset -eu\nif [ \"$1\" = configure ]; then\n"
            f"  if ! getent passwd aip-{role} >/dev/null; then\n"
            f"    useradd --system --user-group --no-create-home --home-dir /var/lib/aip-{role} --shell /usr/sbin/nologin aip-{role}\n  fi\n"
            f"  [ \"$(id -u aip-{role})\" != 0 ]\n  [ \"$(id -gn aip-{role})\" = aip-{role} ]\n"
            f"  install -d -m 0700 -o aip-{role} -g aip-{role} /var/lib/aip-{role}\n"
            "  if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi\nfi\n"
            "echo 'Software installed. Service remains stopped; configure and validate before enabling.'\n")
        prerm = ("#!/bin/sh\nset -eu\n"
            "if [ \"$1\" = remove ] || [ \"$1\" = upgrade ]; then\n"
            f"  if [ -d /run/systemd/system ]; then systemctl stop aip-{role}.service; fi\nfi\n"
            "if [ \"$1\" = remove ] && [ -d /run/systemd/system ]; then\n"
            f"  systemctl disable aip-{role}.service\nfi\n")
        postrm = ("#!/bin/sh\nset -eu\n"
                  "if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi\n"
                  "echo 'Retained configuration, service account, keys and evidence. Secure deletion is a separate institution operation.'\n")
        for name, script in {"preinst": preinst, "postinst": postinst, "prerm": prerm, "postrm": postrm}.items():
            put(root, f"/DEBIAN/{name}", script.encode(), 0o755)
            subprocess.run(["sh", "-n", str(root / "DEBIAN" / name)], check=True)
        for path in sorted(root.rglob("*"), reverse=True):
            os.utime(path, (0, 0))
        os.utime(root, (0, 0))
        output.parent.mkdir(parents=True, exist_ok=True)
        # dpkg generates its own metadata; no shell extraction is used.
        subprocess.run(["dpkg-deb", "--root-owner-group", "-Zxz", "--build", str(root), str(output)],
                       env={**os.environ, "SOURCE_DATE_EPOCH": "0"}, check=True, stdout=subprocess.PIPE)
    print(json.dumps({"product": product, "version": args.version, "architecture": architecture,
        "sha256": runtime.digest(output.read_bytes()), "archive_sha256": args.expected_sha256.lower(),
        "source_commit": manifest["source_commit"], "mode": "OBSERVER_ONLY",
        "release_authenticity": "REQUIRES_INDEPENDENT_APPROVAL", "runtime_validation": "NOT_EXECUTED",
        "distribution_license": "REQUIRES_APPROVED_TERMS_AND_COMPLETE_NOTICES"}))


def configuration_paths(root, role):
    return (runtime.safe_destination(root, f"/etc/aip/{role}.env"),
            runtime.safe_destination(root, f"/etc/aip/{role}.configured.json"))


def check_configuration(root, role):
    config, marker = configuration_paths(root, role)
    parsed = runtime.parse_config(config, role)
    record = json.loads(marker.read_text())
    if record != {"schema": "vanian.deb.configuration.v1", "role": role,
                  "config_sha256": runtime.digest(config.read_bytes()), "mode": "OBSERVER_ONLY"}:
        raise ValueError("configuration changed; validate it again before starting")
    return parsed


def configure(args, role):
    root = runtime.installation_root(args)
    parsed = runtime.parse_config(args.config, role)
    if not args.confirm_separate_host:
        raise ValueError("explicit separate-host administration confirmation required")
    if root == Path("/"):
        runtime.preflight(argparse.Namespace(config=args.config, role=role, config_only=False))
        account = pwd.getpwnam(f"aip-{role}")
        if account.pw_uid == 0 or grp.getgrnam(f"aip-{role}").gr_gid != account.pw_gid:
            raise ValueError("a dedicated non-root runtime account is required")
    config, marker = configuration_paths(root, role)
    other = runtime.safe_destination(root, f"/etc/aip/{'collector' if role == 'probe' else 'probe'}.env")
    if other.exists():
        raise ValueError("probe and collector must use separate hosts")
    data = Path(args.config).read_bytes()
    if config.exists() and config.read_bytes() != data and not args.replace_config:
        raise ValueError("existing configuration differs; explicit --replace-config required")
    unit_path = f"/etc/systemd/system/aip-{role}.service.d/10-vanian-capabilities.conf"
    override = runtime.safe_destination(root, unit_path)
    if override.exists():
        previous = override.read_bytes()
        old_capabilities = (runtime.probe_capabilities(runtime.parse_config(config, role)["AIP_PROBE_SENSORS"].split(","))
                            if role == "probe" and config.exists() else [])
        expected = capability_override(old_capabilities)
        if previous != expected:
            raise ValueError("locally modified capability override; review before replacement")
    capabilities = runtime.probe_capabilities(parsed["AIP_PROBE_SENSORS"].split(",")) if role == "probe" else []
    # A failed partial reconfiguration cannot pass the startup hash check.
    put(root, f"/etc/aip/{role}.env", data, 0o640)
    put(root, unit_path, capability_override(capabilities))
    put(root, f"/etc/aip/{role}.configured.json", runtime.canonical({
        "schema": "vanian.deb.configuration.v1", "role": role,
        "config_sha256": runtime.digest(data), "mode": "OBSERVER_ONLY"}), 0o640)
    if root == Path("/"):
        for file in (config, marker):
            os.chown(file, 0, account.pw_gid)
        subprocess.run(["systemctl", "daemon-reload"], check=True)
    print("CONFIGURATION_VALID: service not started; signed health and runtime acceptance remain required")


def capability_override(capabilities):
    joined = " ".join(capabilities)
    return (f"[Service]\nAmbientCapabilities=\nCapabilityBoundingSet=\n"
            f"AmbientCapabilities={joined}\nCapabilityBoundingSet={joined}\n").encode()


def configure_cli(role):
    parser = argparse.ArgumentParser(description=f"Configure {PRODUCTS[role]} without starting it")
    sub = parser.add_subparsers(dest="command", required=True)
    command = sub.add_parser("configure")
    command.add_argument("--config", required=True)
    command.add_argument("--confirm-separate-host", action="store_true")
    command.add_argument("--replace-config", action="store_true")
    command.add_argument("--root", default="/", help="staging tests only; cannot establish installation")
    sub.add_parser("check")
    args = parser.parse_args()
    try:
        if args.command == "check":
            check_configuration(Path("/"), role)
        else:
            configure(args, role)
        return 0
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        print(f"CONFIGURATION REFUSED: {error}", file=sys.stderr)
        return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--role", choices=PRODUCTS, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", required=True)
    try:
        build(parser.parse_args())
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"DEB BUILD REFUSED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
