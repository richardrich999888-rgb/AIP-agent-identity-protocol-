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
import socket
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
import jwt
from vanian_interop.identity import JwtTrust, verify_identity


def main():
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
    public = {}
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
            return subprocess.check_output([binary, *arguments], stderr=subprocess.PIPE, text=True, timeout=15)
        def launch(binary, role, *arguments):
            handle = (root / f"{role}.log").open("w"); handles.append(handle)
            process = subprocess.Popen([binary, "run", "-config", str(root / f"{role}.conf"), *arguments], stdout=handle, stderr=handle)
            processes.append(process)
            for _ in range(300):
                if (root / f"{role}-api.sock").exists(): return
                if process.poll() is not None: raise RuntimeError(f"SPIRE {role} failed: " + (root / f"{role}.log").read_text())
                time.sleep(.1)
            raise RuntimeError(f"SPIRE {role} readiness timeout: " + (root / f"{role}.log").read_text())
        try:
            launch(server, "server")
            server_socket, agent_socket = str(root / "server-api.sock"), str(root / "agent-api.sock")
            (root / "bundle.crt").write_text(call(server, "bundle", "show", "-socketPath", server_socket))
            token = call(server, "token", "generate", "-socketPath", server_socket).split("Token: ")[1].strip()
            launch(agent, "agent", "-joinToken", token)
            digest = hashlib.sha256(Path(agent).read_bytes()).hexdigest()
            registration = call(server, "entry", "create", "-socketPath", server_socket,
                "-parentID", "spiffe://aip.local/spire/agent/join_token/" + token,
                "-spiffeID", "spiffe://aip.local/workload/interop-cli", "-selector", f"unix:uid:{os.getuid()}",
                "-selector", "unix:sha256:" + digest)
            fetched = None
            for _ in range(30):
                try:
                    fetched = json.loads(call(agent, "api", "fetch", "jwt", "-socketPath", agent_socket,
                        "-audience", "vanian-interop-lab", "-output", "json")); break
                except subprocess.CalledProcessError:
                    time.sleep(.2)
            if fetched is None: raise RuntimeError("no JWT-SVID issued")
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
        # No join token, private signing material, node store, or raw service log retained.
    (args.output / "spire-public.json").write_text(json.dumps(public, indent=2) + "\n")
    print(json.dumps({"output": str(args.output), "status": public["status"]}))


if __name__ == "__main__": main()
