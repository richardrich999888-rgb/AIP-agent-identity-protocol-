#!/usr/bin/env python3
"""Run real SPIRE locally and verify its JWT-SVID using a separately exported bundle.

The attested workload is the spire-agent CLI executable, NOT the Python agent.
No logical-agent binding or kernel event observation is claimed. All servers
are terminated before public test credentials are exported.
"""
import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))


def parse_join_token(output):
    """Read only the single token line from the pinned SPIRE CLI output."""
    lines = [line for line in output.splitlines() if line.startswith("Token:")]
    match = re.fullmatch(r"Token: ([!-~]{1,1024})", lines[0]) if len(lines) == 1 else None
    if match is None:
        raise ValueError("invalid SPIRE join-token response")
    return match.group(1)


class SpireReadinessError(RuntimeError):
    def __init__(self, diagnostics):
        self.diagnostics = diagnostics
        super().__init__("SPIRE JWT-SVID readiness failed: " + json.dumps(diagnostics, sort_keys=True))


def classify_cli_stderr(stderr):
    """Return only allowlisted labels; inspect at most 4 KiB, retain no body.

    SPIRE v1.15.3 pkg/agent/endpoints/workload/handler.go emits the exact
    PermissionDenied/no-identity and Unavailable gRPC statuses below. These
    categories are diagnostics, never evidence that a particular root cause
    occurred in an earlier run or a reason to accept unverified credentials.
    """
    if not isinstance(stderr, (str, bytes)):
        return "unclassified_cli_failure"
    bounded = stderr[:4096]
    if isinstance(bounded, str):
        bounded = bounded.encode("utf-8", errors="replace")
    bounded = bounded[:4096].decode("utf-8", errors="replace")
    if re.search(r"\bcode = PermissionDenied desc = no identity issued\b", bounded):
        return "no_identity_issued"
    if re.search(r"\bcode = Unavailable\b|\bconnection refused\b", bounded, re.IGNORECASE):
        return "connection_refused_or_unavailable"
    if re.search(r"\bcode = PermissionDenied\b|\bpermission denied\b", bounded, re.IGNORECASE):
        return "permission_denied"
    return "unclassified_cli_failure"


def await_jwt_svid(agent, agent_socket, processes):
    """Await CLI JSON for at most 60 seconds; trust validation remains in main.

    SPIRE 1.15.3 documents a 5-second entry sync interval with backoff. The
    previous 30 short polls did not allow a dependable synchronization window;
    discarded stderr means the earlier failure's exact cause remains unknown.
    Diagnostics contain fixed classes and numbers only, never command/output.
    """
    started = time.monotonic()
    deadline = started + 60.0
    attempts, last_returncode, last_error_class = 0, None, "not_attempted"

    def diagnostics(result_class, process_returncodes):
        return {"result_class": result_class, "last_error_class": last_error_class,
                "last_returncode": last_returncode, "process_returncodes": process_returncodes,
                "attempts": attempts, "elapsed_ms": int(max(0, time.monotonic() - started) * 1000)}

    def refuse(result_class, process_returncodes):
        raise SpireReadinessError(diagnostics(result_class, process_returncodes)) from None

    while True:
        process_returncodes = [process.poll() for process in processes]
        if any(code is not None for code in process_returncodes):
            refuse("process_exited", process_returncodes)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            refuse("readiness_timeout", process_returncodes)
        attempts += 1
        last_returncode = None
        fetched = None
        try:
            result = subprocess.run([agent, "api", "fetch", "jwt", "-socketPath", agent_socket,
                "-audience", "vanian-interop-lab", "-output", "json"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                timeout=min(15.0, remaining), check=False)
            last_returncode = result.returncode
            if result.returncode:
                last_error_class = classify_cli_stderr(result.stderr)
            else:
                try:
                    fetched = json.loads(result.stdout)
                    last_error_class = "none"
                except (ValueError, TypeError):
                    last_error_class = "invalid_cli_json"
        except subprocess.TimeoutExpired:
            last_error_class = "fetch_timeout"
        except (OSError, UnicodeError):
            last_error_class = "fetch_execution_error"
            refuse("fetch_execution_error", [process.poll() for process in processes])
        process_returncodes = [process.poll() for process in processes]
        if any(code is not None for code in process_returncodes):
            refuse("process_exited", process_returncodes)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            refuse("readiness_timeout", process_returncodes)
        if fetched is not None:
            return fetched, diagnostics("cli_json_ready", process_returncodes)
        time.sleep(min(0.2, remaining))


def main():
    import jwt
    from vanian_interop.identity import JwtTrust, verify_identity

    parser = argparse.ArgumentParser()
    parser.add_argument("--spire-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    server = str((args.spire_directory / "bin/spire-server").resolve())
    agent = str((args.spire_directory / "bin/spire-agent").resolve())
    for binary in (server, agent):
        os.chmod(binary, 0o755)
    args.output.mkdir(parents=True, exist_ok=False)
    processes, handles = [], []
    public, readiness = {}, None
    with tempfile.TemporaryDirectory(prefix="vj-") as directory:
        root = Path(directory)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]
        repo = HERE.parents[2]
        for role in ("server", "agent"):
            (root / f"{role}-data").mkdir()
            template = (repo / f"validation/external/spiffe/conf/{role}.conf").read_text()
            config = template.replace("__RUN__", str(root)).replace("__WORK__", str(root)).replace("__PORT__", str(port))
            (root / f"{role}.conf").write_text(config)
        def call(binary, *arguments):
            try:
                return subprocess.check_output([binary, *arguments], stderr=subprocess.DEVNULL, text=True, timeout=15)
            except subprocess.CalledProcessError as error:
                raise RuntimeError(f"SPIRE command exited with return code {error.returncode}") from None
            except subprocess.TimeoutExpired:
                raise RuntimeError("SPIRE command timed out") from None
        def launch(binary, role, *arguments):
            handle = (root / f"{role}.log").open("w"); handles.append(handle)
            process = subprocess.Popen([binary, "run", "-config", str(root / f"{role}.conf"), *arguments], stdout=handle, stderr=handle)
            processes.append(process)
            for _ in range(300):
                if (root / f"{role}-api.sock").exists(): return
                if process.poll() is not None:
                    raise RuntimeError(f"SPIRE {role} exited before socket readiness (return code {process.returncode})")
                time.sleep(.1)
            raise RuntimeError(f"SPIRE {role} socket readiness timeout")
        try:
            launch(server, "server")
            server_socket, agent_socket = str(root / "server-api.sock"), str(root / "agent-api.sock")
            (root / "bundle.crt").write_text(call(server, "bundle", "show", "-socketPath", server_socket))
            token = parse_join_token(call(server, "token", "generate", "-socketPath", server_socket))
            launch(agent, "agent", "-joinToken", token)
            digest = hashlib.sha256(Path(agent).read_bytes()).hexdigest()
            registration = call(server, "entry", "create", "-socketPath", server_socket,
                "-parentID", "spiffe://aip.local/spire/agent/join_token/" + token,
                "-spiffeID", "spiffe://aip.local/workload/interop-cli", "-selector", f"unix:uid:{os.getuid()}",
                "-selector", "unix:sha256:" + digest)
            try:
                fetched, readiness = await_jwt_svid(agent, agent_socket, processes)
            except SpireReadinessError as error:
                readiness = error.diagnostics
                raise
            bundle = json.loads(call(server, "bundle", "show", "-socketPath", server_socket, "-format", "spiffe"))
            # SPIRE 1.15.3 PrintProto emits [JWTSVIDResponse, JWTBundlesResponse].
            # Trust the separately administered server export, never a token's
            # embedded keys nor an arbitrary fetched workload bundle.
            if not isinstance(fetched, list) or len(fetched) != 2 or len(fetched[0]["svids"]) != 1:
                raise ValueError("unsupported SPIRE CLI response shape")
            svid = fetched[0]["svids"][0]
            keys = {jwk["kid"]: jwt.PyJWK.from_dict(jwk).key for jwk in bundle["keys"]
                    if jwk.get("use") == "jwt-svid"}
            now_ms = time.time_ns() // 1_000_000
            trust = JwtTrust("aip.local", "vanian-interop-lab", "synthetic-bank", keys,
                algorithms=("RS256", "ES256", "ES384"))
            identity = verify_identity(svid["svid"], trust, jwt_svid=True, now_ms=now_ms)
            if identity.subject != "spiffe://aip.local/workload/interop-cli" or svid["spiffe_id"] != identity.subject:
                raise ValueError("wrong attested workload subject")
            public = {"status": "PARTIALLY_VERIFIED", "identity": asdict(identity),
                      "bundle": bundle, "workload_sha256": digest,
                      "verified_at_ms": now_ms, "spire_version": call(server, "-version").strip(),
                      "scope": "SPIRE CLI workload only; no ADK logical-agent or independent kernel binding"}
        finally:
            for process in reversed(processes):
                process.terminate()
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
            for handle in handles: handle.close()
            if readiness is not None:
                (args.output / "spire-readiness.json").write_text(json.dumps(readiness, indent=2) + "\n")
        # No join token, private signing material, node store, or raw service log retained.
    (args.output / "spire-public.json").write_text(json.dumps(public, indent=2) + "\n")
    print(json.dumps({"output": str(args.output), "status": public["status"]}))


if __name__ == "__main__": main()
