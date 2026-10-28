#!/usr/bin/env python3
"""Controller on a disposable Linux host. Never run agents on macOS.

Exit 0: requested command passed its stated gates. Run exit 1: failed stages.
Exit 2: blocked preflight/configuration. A run is never assignment completion.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import platform
import re
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from audit_crosscheck import AuditCrosscheck, parse_status

from evidence import (ARCHIVES, Refused, acceptance, anchors_args, command, covered,
                      mutations, records, sha256, summarize, verify)

HERE = Path(__file__).resolve().parent


def now():
    return time.time_ns() // 1_000_000


def save(path, value):
    path = Path(path)
    tmp = path.with_suffix(path.suffix + ".new")
    tmp.write_text(json.dumps(value, indent=2) + "\n")
    tmp.replace(path)


def protected(path):
    path = Path(path).resolve(strict=True)
    if path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
        raise Refused(f"requires root custody: {path}")
    return path


def remote(config, action, token):
    c = config["collector"]
    mode = c.get("mode", "off-host")
    if mode == "local-isolated":
        # Explicitly scoped to a nonprivileged container under a trusted host
        # kernel. This is not off-host custody and cannot resist host root.
        helper, control = protected(c["helper"]), protected(c["config"])
        output = command([sys.executable, helper, control],
                         input=json.dumps({"action": action, "token": token}), timeout=60)
        return json.loads(output)
    if mode != "off-host":
        raise Refused("unknown collector isolation mode")
    # SSH assembles remote commands through a shell. Restrict every argument
    # to a safe alphabet before passing it, rather than quoting JSON as shell.
    for value in (c["ssh"], c["helper"], c["config"]):
        if not re.fullmatch(r"[A-Za-z0-9_@./-]+", value) or value.startswith("-"):
            raise Refused("invalid collector SSH alias or absolute path")
    output = command(["ssh", "-oBatchMode=yes", "-oStrictHostKeyChecking=yes",
                      "-oConnectTimeout=10", c["ssh"], "sudo", "-n", "python3",
                      c["helper"], c["config"]],
                     input=json.dumps({"action": action, "token": token}), timeout=60)
    return json.loads(output)


def validate_collector_boundary(config, response, local_id):
    if not response["clock_synchronized"]:
        raise Refused("collector clock is not synchronized")
    mode = config["collector"].get("mode", "off-host")
    if mode == "off-host":
        if response["machine_id"] == local_id:
            raise Refused("off-host collector must be on a distinct host")
        return "OFF_HOST; separately provisioned trust anchor"
    if mode == "local-isolated":
        if response["machine_id"] != local_id:
            raise Refused("local collector returned a different machine identity")
        return "ISOLATED_FROM_CONTAINER; shared kernel and host root trusted; not off-host custody"
    raise Refused("unknown collector isolation mode")


def snapshot(config, directory, token, *, stop=False):
    response = remote(config, "stop" if stop else "snapshot", token)
    for name in ARCHIVES:
        data = base64.b64decode(response["files"][name], validate=True)
        (Path(directory) / name).write_bytes(data)
    return {"run_id": token, "collector_machine_id": response["machine_id"],
            "sha256": response["sha256"], "received_at_ms": now(),
            "provenance": ("root-controlled local isolated collector; trusts this host kernel"
                if config["collector"].get("mode") == "local-isolated" else
                "controller custody over pinned-host-key SSH; not an observer signature")}


def preflight(config):
    if platform.system() != "Linux":
        raise Refused("Linux kernel observation required; this host is " + platform.system())
    if os.geteuid() != 0:
        raise Refused("controller must run as root on the disposable validation host")
    if not Path("/sys/fs/cgroup/cgroup.controllers").exists():
        raise Refused("cgroup v2 is required")
    events = Path("/sys/kernel/tracing/available_events").read_text()
    for event in ("sched:sched_process_exec", "sched:sched_process_fork", "sock:sock_send_length"):
        if event not in events:
            raise Refused(f"required kernel tracepoint unavailable: {event}")
    if command(["timedatectl", "show", "--property=NTPSynchronized", "--value"]).strip() != "yes":
        raise Refused("probe host clock is not synchronized")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", config["image"]):
        raise Refused("pin a locally built Docker image by its immutable image ID")
    if not 1 <= config["timeout_s"] <= 3600 or not 1 <= config["memory_mb"] <= 16384:
        raise Refused("invalid runtime or memory bound")
    if not 0 < config["cpus"] <= 8 or not 16 <= config["pids_limit"] <= 1024:
        raise Refused("invalid CPU or process bound")
    if not config["model"] or "REPLACE" in config["model"]:
        raise Refused("a real model identifier is required")
    pins = json.loads((HERE / "frameworks.lock.json").read_text())
    framework = pins[config["framework"]]
    labels = json.loads(command(["docker", "image", "inspect", "--format",
                                "{{json .Config.Labels}}", config["image"]]))
    if not labels or labels.get("org.opencontainers.image.revision") != framework["commit"]:
        raise Refused("image does not identify the pinned framework source")
    network = json.loads(command(["docker", "network", "inspect", config["network"]]))[0]
    if network["Driver"] != "bridge" or network["Internal"] is not True:
        raise Refused("agent network must be an internal bridge with a separate restricted egress proxy")
    for path in (config["model_env"], config["probe_env"], config["model_config"], config["policy_check"]):
        protected(path)
    # Institution-controlled check must exercise the egress policy AND a hard
    # expenditure cap on the model proxy. An env name is not proof of a cap.
    command([config["policy_check"]], timeout=60)
    for binary in ("aip-probe", "aip-observe-verify", "aip-lineage", "aip-sentinel-feed", "aip-corroborate"):
        if not os.access(Path(config["tools"]) / binary, os.X_OK):
            raise Refused(f"build required binary: {binary}")
    parse_status(command(["auditctl", "-s"]))
    command(["ausearch", "--version"])
    return framework


def proc_identity(pid):
    base = Path(f"/proc/{pid}")
    stat = (base / "stat").read_text().rsplit(")", 1)[1].split()
    return {"provenance": "CONTROLLER_MEASURED_PROCFS", "process": {
        "pid": pid, "pid_start_time_ticks": int(stat[19]),
        "boot_id": list(uuid.UUID(Path("/proc/sys/kernel/random/boot_id").read_text().strip()).bytes)},
        "container": {k + "_ns_inode": (base / "ns" / k).stat().st_ino for k in ("pid", "mnt", "net")}}


def terminate(process):
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def read_env(path):
    # Plain KEY=value only, no shell evaluation, expansion, or sourced scripts.
    env = {}
    for line in Path(path).read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        if not re.fullmatch(r"AIP_PROBE_[A-Z_]+", key):
            raise Refused("probe environment contains an unsupported variable")
        env[key] = value
    return env


def tamper(archive, tools, anchor, checkpoint):
    archive = Path(archive)
    verify(archive, tools, anchor, checkpoint)
    result = {}
    with tempfile.TemporaryDirectory(prefix="snifferdog-tamper-") as tmp:
        tmp = Path(tmp)
        (tmp / ARCHIVES[1]).write_bytes((archive / ARCHIVES[1]).read_bytes())
        for name, data in mutations((archive / ARCHIVES[0]).read_bytes()).items():
            (tmp / ARCHIVES[0]).write_bytes(data)
            # Record both checks: a prefix/suffix deletion can remain a valid
            # signed window. The separately held checkpoint closes that gap.
            raw = subprocess.run([str(Path(tools) / "aip-observe-verify"), *anchors_args(anchor),
                                  "--batches", str(tmp / ARCHIVES[0]), "--health",
                                  str(tmp / ARCHIVES[1]), "--json"], capture_output=True, timeout=120)
            if raw.returncode not in (0, 1):
                raise Refused(f"verifier invocation failed during mutation {name}")
            try:
                verify(tmp, tools, anchor, checkpoint)
            except Refused:
                result[name] = {"checkpoint_rejected": True, "signature_chain_rejected": raw.returncode == 1}
            else:
                raise Refused(f"mutation accepted: {name}")
    return result


def run(config, out, checkpoint_path):
    out = Path(out).resolve()
    checkpoint_path = Path(checkpoint_path).resolve()
    if checkpoint_path.is_relative_to(out) or checkpoint_path.exists():
        raise Refused("checkpoint must be a new file held outside the exported run directory")
    out.mkdir(parents=True, exist_ok=False)
    os.chmod(out, 0o700)
    status = {"status": "PREFLIGHT", "assignment_complete": False, "started_ms": now(),
              "framework": config["framework"], "model": config["model"],
              "logical_agent_attribution": "CANNOT_PROVE", "authority": "CANNOT_PROVE",
              "reconciliation": "CANNOT_PROVE", "failures": []}
    save(out / "status.json", status)
    probe = None
    audit = AuditCrosscheck()
    collector_started = container_created = False
    token = "sd-" + uuid.uuid4().hex
    logs = []
    code = 1
    try:
        pin = preflight(config)
        status["source"] = pin
        status["aip_commit"] = command(["git", "rev-parse", "HEAD"], cwd=HERE).strip()
        status["kernel"] = platform.release()
        remote_status = remote(config, "status", token)
        local_id = Path("/etc/machine-id").read_text().strip()
        status["collector_trust_boundary"] = validate_collector_boundary(config, remote_status, local_id)
        if remote_status["state"] != "inactive":
            raise Refused("dedicated collector service must be inactive")
        task = Path(config["task"]).read_text()
        status["task_sha256"] = sha256(config["task"])
        status["image"] = config["image"]
        status["run_id"] = token
        control, workspace, archive = out / "input", out / "work", out / "evidence"
        for directory in (control, workspace, archive):
            directory.mkdir()
        os.chown(workspace, 10001, 10001)
        save(control / "request.json", {"framework": config["framework"], "model": config["model"],
             "timeout_s": config["timeout_s"], "prompt": task, "run_id": token})
        probe_env = read_env(config["probe_env"])
        # Fanotify must watch the real bind-mounted work filesystem.
        probe_env.update(AIP_PROBE_FANOTIFY_PATH=str(workspace),
                         AIP_PROBE_SENSORS="sched,cgroup,connector,fanotify,sockstate,socksend",
                         AIP_PROBE_BATCH_INTERVAL_MS="1000")
        collector_started = True
        remote(config, "start", token)
        def log(name):
            stream = (out / name).open("w")
            logs.append(stream)
            return stream
        probe = subprocess.Popen([str(Path(config["tools"]) / "aip-probe")],
                                 env={"PATH": os.environ["PATH"], **probe_env},
                                 stdout=log("probe.log"), stderr=subprocess.STDOUT)
        # Readiness is verified signed health, never a grep of daemon output.
        ready = False
        for _ in range(15):
            if probe.poll() is not None:
                raise Refused("probe stopped before readiness")
            time.sleep(3)
            try:
                cp = snapshot(config, archive, token)
                verify(archive, config["tools"], config["anchor"], cp)
                health = records(archive / ARCHIVES[1])
                h = health[-1]["health"]
                w = h.get("attested_coverage")
                ready = bool(w and now() - h["emitted_at_ms"] < 45000 and covered(
                    health, w["from_ms"], w["to_ms"], ["SchedTracepoint", "Fanotify", "SockSendTracepoint"]))
            except (Refused, FileNotFoundError):
                continue
            if ready:
                break
        if not ready:
            raise Refused("no fresh verified Active health with required sensors")
        audit.start()
        create = ["docker", "create", "--name", token, "--user", "10001:10001",
                  "--cap-drop=ALL", "--security-opt=no-new-privileges", "--read-only",
                  "--pids-limit", str(config["pids_limit"]), "--memory", f'{config["memory_mb"]}m',
                  "--cpus", str(config["cpus"]), "--network", config["network"],
                  "--env-file", config["model_env"], "--tmpfs", "/tmp:rw,nosuid,size=1g,mode=1777",
                  "--tmpfs", "/opt/framework/usr:rw,nosuid,size=1g,uid=10001,gid=10001",
                  "--mount", f"type=bind,src={control},dst=/input,readonly",
                  "--mount", f"type=bind,src={workspace},dst=/work",
                  "--mount", f'type=bind,src={config["model_config"]},dst=/model-config,readonly',
                  config["image"]]
        command(create)
        container_created = True
        start = now()
        command(["docker", "start", token])
        pid = int(command(["docker", "inspect", "--format", "{{.State.Pid}}", token]))
        launch = proc_identity(pid)
        launch["probe_id"] = probe_env["AIP_PROBE_ID"]
        save(out / "launch.json", launch)
        status.update(status="RUNNING", launch=launch, workload_from_ms=start,
                      live_evidence="PENDING_OFFLINE_VERIFICATION")
        save(out / "status.json", status)
        (control / "start").touch()
        started = time.monotonic()
        last_refresh = 0.0
        samples = []
        while command(["docker", "inspect", "--format", "{{.State.Running}}", token]).strip() == "true":
            if probe.poll() is not None:
                raise Refused("observer or independent tracer exited during workload")
            if time.monotonic() - started > config["timeout_s"]:
                raise Refused("workload exceeded runtime budget")
            samples.append({"time_ms": now(), "docker_stats": json.loads(command([
                "docker", "stats", "--no-stream", "--format", "{{json .}}", token]))})
            status["last_sample"] = samples[-1]
            if time.monotonic() - last_refresh >= 15:
                last_refresh = time.monotonic()
                try:
                    live_cp = snapshot(config, archive, token)
                    verify(archive, config["tools"], config["anchor"], live_cp)
                    status["summary"] = summarize(records(archive / ARCHIVES[0]),
                        records(archive / ARCHIVES[1]), launch, start, now())
                    status["live_evidence"] = "SIGNED_SNAPSHOT_VERIFIED; final checkpoint pending"
                except (Refused, OSError, ValueError, KeyError, subprocess.SubprocessError):
                    status.pop("summary", None)
                    status["live_evidence"] = "INTEGRITY_UNKNOWN; current snapshot unavailable or rejected"
            save(out / "status.json", status)
            time.sleep(2)
        end = now()
        exit_code = int(command(["docker", "inspect", "--format", "{{.State.ExitCode}}", token]))
        status.update(status="VERIFYING", workload_to_ms=end, workload_exit=exit_code)
        save(out / "status.json", status)
        save(out / "performance.json", {"elapsed_seconds": time.monotonic() - started,
             "samples": samples, "observer_overhead_percent": None, "collector_latency_ms": None,
             "task_impact_percent": None, "reason": "no matched unobserved baseline or collector timing sample"})
        # Wait for a signed health epoch enclosing the end, while both writers
        # continue. Recovery never stretches across an interrupted interval.
        for _ in range(15):
            time.sleep(3)
            cp = snapshot(config, archive, token)
            verify(archive, config["tools"], config["anchor"], cp)
            if covered(records(archive / ARCHIVES[1]), start, end,
                       ["SchedTracepoint", "Fanotify", "SockSendTracepoint"]):
                break
        save(out / "audit-status.json", audit.export(out / "auditd.log"))
        audit.close()
        terminate(probe)
        cp = snapshot(config, archive, token, stop=True)
        collector_started = False
        save(checkpoint_path, cp)
        report = verify(archive, config["tools"], config["anchor"], cp)
        save(out / "verification.json", report)
        summary = summarize(records(archive / ARCHIVES[0]), records(archive / ARCHIVES[1]), launch, start, end)
        # These older CLIs accept --pubkey-file only. Write the independently
        # provisioned anchor, never a key selected by the incoming archive.
        (out / "observer.pub").write_text(config["anchor"]["public_key"] + "\n")
        common = ["--observer-id", config["anchor"]["observer_id"], "--key-version",
                  str(config["anchor"]["key_version"]), "--pubkey-file", out / "observer.pub",
                  "--batches", archive / ARCHIVES[0]]
        (out / "lineage.txt").write_text(command([Path(config["tools"]) / "aip-lineage", *common]))
        # Existing bridge verifies signed AIP evidence before OT conversion.
        (out / "sentinel-feed-report.txt").write_text(command([
            Path(config["tools"]) / "aip-sentinel-feed", *common, "--out", out / "effects.jsonl"]))
        comparison = json.loads(command([Path(config["tools"]) / "aip-corroborate", *common,
            "--external", out / "auditd.log", "--source", "auditd",
            "--from-ms", start, "--to-ms", end, "--json"]))
        save(out / "corroboration.json", comparison)
        save(out / "tamper.json", tamper(archive, config["tools"], config["anchor"], cp))
        failures = acceptance(summary, comparison, exit_code)
        # A returned LLM response is not independent task acceptance. Until an
        # evaluator inspects output, do not grant overall integration success.
        status.update(summary=summary, failures=failures,
                      observation_validation="PASSED" if not failures else "FAILED",
                      task_acceptance="PENDING_INDEPENDENT_REVIEW", status="REVIEW_REQUIRED")
        code = 1  # task acceptance and logical delegation remain open
    except (Refused, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        status["status"] = "BLOCKED" if status["status"] == "PREFLIGHT" else "FAILED"
        status["failures"].append(str(exc))
        code = 2 if status["status"] == "BLOCKED" else 1
    finally:
        if container_created:
            try:
                command(["docker", "rm", "--force", token])
            except (Refused, subprocess.SubprocessError) as exc:
                status["failures"].append(f"container cleanup: {exc}")
                code = 1
        try:
            audit.close()
        except (Refused, subprocess.SubprocessError) as exc:
            status["failures"].append(f"audit rule cleanup: {exc}")
            code = 1
        terminate(probe)
        if collector_started:
            try:
                cp = snapshot(config, out / "evidence", token, stop=True)
                if not checkpoint_path.exists():
                    save(checkpoint_path, cp)
            except (Refused, OSError, KeyError, subprocess.SubprocessError) as exc:
                status["failures"].append(f"collector cleanup/export: {exc}")
                code = 1
        for stream in logs:
            stream.close()
        status["finished_ms"] = now()
        save(out / "status.json", status)
    return code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("preflight", "run"):
        p = sub.add_parser(action)
        p.add_argument("--config", type=Path, required=True)
        if action == "run":
            p.add_argument("--out", type=Path, required=True)
            p.add_argument("--checkpoint", type=Path, required=True)
    for action in ("verify", "tamper"):
        p = sub.add_parser(action)
        for option in ("archive", "tools", "anchor", "checkpoint"):
            p.add_argument("--" + option, type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action in ("preflight", "run"):
            config = json.loads(args.config.read_text())
            if args.action == "run":
                return run(config, args.out, args.checkpoint)
            print(json.dumps(preflight(config), indent=2))
        else:
            result = (verify if args.action == "verify" else tamper)(
                args.archive, args.tools, json.loads(args.anchor.read_text()),
                json.loads(args.checkpoint.read_text()))
            print(json.dumps(result, indent=2))
        return 0
    except (Refused, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
