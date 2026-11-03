#!/usr/bin/env python3
"""Actual pinned OPA over mTLS. Decisions are references, not AIP authority."""
import argparse
from dataclasses import asdict
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
from cryptography.hazmat.primitives.asymmetric import ec
from vanian_interop.identity import JwtTrust, verify_identity
from vanian_interop.policy import OpaAdapter
from vanian_interop.transport import PinnedHttps
from lab_tls import create_pki


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--opa", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    binary = args.opa.resolve(); binary.chmod(0o755)
    with tempfile.TemporaryDirectory(prefix="vanian-opa-") as temp:
        temp = Path(temp); create_pki(temp)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]
        base = f"https://127.0.0.1:{port}"
        log = (args.output / "opa.log").open("w")
        process = subprocess.Popen([str(binary), "run", "--server", "--addr", f"127.0.0.1:{port}",
            "--authentication=tls", "--min-tls-version=1.3", "--tls-cert-file", str(temp / "server.pem"),
            "--tls-private-key-file", str(temp / "server.key"), "--tls-ca-cert-file", str(temp / "ca.pem"),
            str(HERE / "policy/vanian.rego")], stdout=log, stderr=log)
        transport = PinnedHttps(base, ca_file=str(temp / "ca.pem"), client_cert=str(temp / "client.pem"), client_key=str(temp / "client.key"))
        try:
            for _ in range(100):
                try: transport.request("GET", base + "/health"); break
                except Exception:
                    if process.poll() is not None: raise RuntimeError("OPA exited")
                    time.sleep(.05)
            else: raise RuntimeError("OPA readiness timeout")
            key = ec.generate_private_key(ec.SECP256R1()); now = int(time.time())
            trust = JwtTrust("https://identity.bank.example", "opa-lab", "synthetic-bank", {"lab": key.public_key()})
            token = jwt.encode({"iss": trust.issuer, "aud": trust.audience, "sub": "research-agent", "iat": now, "exp": now+120}, key,
                               algorithm="ES256", headers={"kid": "lab", "typ": "at+jwt"})
            identity = verify_identity(token, trust)
            adapter = OpaAdapter(base + "/v1/data/vanian/decision", transport, engine_version="1.21.4",
                                 policy_version="synthetic-research-v1", authority="ephemeral-lab-policy-service")
            records = []
            for action, expected in [("research.read", "ALLOW"), ("payment.write", "DENY")]:
                record = adapter.evaluate(identity, resource="synthetic-loans", action=action,
                    request_id=action, execution_context_ref=None, arguments={"record_id": "SYN-001"})
                assert record.decision == expected
                records.append(record.to_dict())
            bad = PinnedHttps(base, ca_file=str(temp / "ca.pem"))
            try:
                try: bad.request("POST", base + "/v1/data/vanian/decision", body={"input": {}})
                except Exception: missing_cert_refused = True
                else: missing_cert_refused = False
            finally: bad.close()
            assert missing_cert_refused
            (args.output / "result.json").write_text(json.dumps({"status": "PARTIALLY_VERIFIED", "decisions": records,
                "missing_client_certificate_refused": missing_cert_refused, "authorization": "NO_SIGNED_EXPECTED_EXECUTION",
                "version": subprocess.check_output([str(binary), "version"], text=True)}, indent=2) + "\n")
        finally:
            transport.close(); process.terminate(); process.wait(timeout=10); log.close()
    print("Actual OPA mTLS allow, deny and missing-client-certificate checks passed")


if __name__ == "__main__": main()
