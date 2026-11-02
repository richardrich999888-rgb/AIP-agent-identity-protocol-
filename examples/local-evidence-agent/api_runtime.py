"""Actual loopback AIP API with verified historical Linux records.

This starts no observer, model, Docker workload or managed evidence signer.
Only the bootstrap controller receives a filing credential. The agent gets a
Reader credential and the existing SDK's metadata/evaluation/verdict routes.
"""
from __future__ import annotations

import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
import zipfile


SOURCE = "3e6c1794000fa23006ef623722e37700e49582b7"
WORKFLOW_RUN = 41432473155
ZIP_SHA256 = "48ccc9525cade552b8eb28874e0c786b96a4b00024defd8b17e7cd9fbab6a505"
ZIP_PATH = "validation/enterprise/results/GOVERNANCE_20261102/genuine-3e6c179/original-artifact.zip"
PROFILES = ("same-run", "same-run-interruption", "same-run-recovery")
LABELS = {"same-run": "Observed Linux task", "same-run-interruption": "Interrupted Linux observer",
          "same-run-recovery": "Recovered Linux observer"}
MAX_BYTES = 16 * 1024 * 1024


class RuntimeSetupError(RuntimeError):
    """Fixed, credential-free setup failures safe for the local operator."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def _require(condition, message):
    if not condition:
        raise RuntimeSetupError(message)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            _require(key not in value, "Duplicate JSON object key refused")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique)


def _save(path, value):
    raw = json.dumps(value, indent=2, allow_nan=False).encode() + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)


class APIProcess:
    """Context manager; credentials stay in process memory, never public JSON.

    ``runs``/``seeded_runs`` is a public catalog, not an API replacement. Agent
    tools must retrieve actual metadata/evaluation/verdict through VanianClient.
    ``root`` may exist; each invocation creates a new private child directory.
    """

    def __init__(self, repo: Path, root: Path, port: int = 18880, *,
                 fresh_evidence: Path | None = None, fresh_trust: Path | None = None):
        _require(type(port) is int and 0 <= port <= 65535, "Invalid local API port")
        _require((fresh_evidence is None) == (fresh_trust is None),
                 "Fresh evidence requires its separate operator trust configuration")
        self.repo, self.root = Path(repo).resolve(strict=True), Path(root).absolute()
        self.port = port
        self.base_url = ""
        self.reader_token = ""
        self.runs = []
        self.seeded_runs = self.runs
        self.auth_checks = {}
        self.fresh_observation = None
        self._fresh_evidence = Path(fresh_evidence).absolute() if fresh_evidence is not None else None
        self._fresh_trust = Path(fresh_trust).absolute() if fresh_trust is not None else None
        self._process = None
        self._log = None
        self._private = None
        self._operator_token = ""
        self._other_token = ""
        self._started = False
        self._opener = build_opener(ProxyHandler({}), _NoRedirect())

    def __enter__(self):
        return self.start()

    def __exit__(self, *_exc):
        self.close()

    def _sdk(self, token):
        sdk = str(self.repo / "sdk/python")
        if sdk not in sys.path:
            sys.path.insert(0, sdk)
        from vanian import VanianClient
        client = VanianClient(self.base_url, lambda: token, allow_loopback_http=True,
                              retries=0, max_response_bytes=MAX_BYTES)
        client._opener = self._opener  # Direct loopback only; never an inherited proxy.
        return client

    def _request(self, path, *, token=None, body=None, method=None):
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = Request(self.base_url + path, data=body, headers=headers, method=method)
        try:
            with self._opener.open(request, timeout=10) as reply:
                raw = reply.read(MAX_BYTES + 1)
                _require(len(raw) <= MAX_BYTES, "API response exceeds local demo bound")
                return reply.status, _json(raw)
        except HTTPError as error:
            code = error.code
            error.close()
            return code, None

    def _verify_record(self, profile, files):
        private = self._private / "retained" / profile
        private.mkdir(parents=True, mode=0o700)
        for name, raw in files.items():
            path = private / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.write_bytes(raw)
            path.chmod(0o600)
        bundle_raw = files["public/run-bundle.json"]
        bundle, checkpoint = _json(bundle_raw), _json(files["checkpoint.json"])
        anchor = _json(files["observer-anchor.json"])
        for name in ("attested.archive.jsonl", "health.archive.jsonl"):
            raw = files["public/" + name]
            _require(_sha(raw) == checkpoint["sha256"][name], "Historical checkpoint digest differs")
            field = "batches_jsonl" if name.startswith("attested") else "health_jsonl"
            _require(bundle[field].encode() == raw, "Historical bundle archive bytes differ")
        commands = [
            [self.repo / "target/debug/aip-observe-verify", "--observer-id", anchor["observer_id"],
             "--key-version", str(anchor["key_version"]), "--pubkey", anchor["public_key"],
             "--batches", private / "public/attested.archive.jsonl", "--health", private / "public/health.archive.jsonl", "--json"],
            [self.repo / "target/debug/aip-execution-assurance", "evaluate"],
        ]
        reports = []
        for index, args in enumerate(commands):
            env = {"PATH": os.defpath}
            if index:
                env["AIP_RUN_TRUST_FILE"] = str(private / "run-trust.json")
            completed = subprocess.run([str(x) for x in args], input=bundle_raw if index else None,
                                       env=env, capture_output=True, timeout=120)
            _require(completed.returncode == 0, "Existing Rust verifier refused historical evidence")
            reports.append(_json(completed.stdout))
        archive, evaluation = reports
        _require(not archive["findings"] and archive["batches"]["records"] and archive["health"]["records"],
                 "Historical archive verification was incomplete")
        _require(evaluation == _json(files["public/evaluation.json"]), "Historical evaluation differs from original")
        _require(all(evaluation[k] for k in ("archive_integrity_verified", "authorization_verified", "checkpoint_verified",
                                          "gateway_receipt_verified", "signed_reconciliation_verified")),
                 "Historical signed bundle verification was incomplete")
        _save(private / "local-verification.json", {"archive": archive, "evaluation": evaluation,
              "classification": "HISTORICAL_LINUX_EVIDENCE_REVERIFIED_ON_LOCAL_HOST", "current_host_kernel_capture": False})
        return {"profile": profile, "raw": bundle_raw, "bundle": bundle, "evaluation": evaluation,
                "trust": _json(files["run-trust.json"])}

    def _historical_records(self):
        archive_path = self.repo / ZIP_PATH
        _require(archive_path.is_file() and not archive_path.is_symlink(), "Committed historical ZIP is missing")
        _require(archive_path.stat().st_size == 1192822, "Historical ZIP size differs")
        raw = archive_path.read_bytes()
        _require(_sha(raw) == ZIP_SHA256, "Historical ZIP SHA differs from reviewed original")
        import io
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            names = archive.namelist()
            _require(len(names) == len(set(names)) == 154 and archive.testzip() is None, "Historical ZIP CRC/member check failed")
            _require(sum(e.file_size for e in archive.infolist()) < MAX_BYTES, "Historical expanded archive exceeds bound")
            for entry in archive.infolist():
                path = PurePosixPath(entry.filename)
                _require(not path.is_absolute() and ".." not in path.parts and
                         stat.S_IFMT(entry.external_attr >> 16) in (0, stat.S_IFREG), "Unsafe historical ZIP member")
            selected = ("run-trust.json", "observer-anchor.json", "checkpoint.json", "public/run-bundle.json",
                        "public/evaluation.json", "public/attested.archive.jsonl", "public/health.archive.jsonl")
            return [self._verify_record(profile, {name: archive.read(profile + "/" + name) for name in selected})
                    for profile in PROFILES]

    def _verify_fresh_observation(self):
        """A trusted local verifier approves the separate original package.

        No JSON file supplied by the package becomes a verification result.
        The explicit operator trust file is a separate required input. This
        observation-only record never becomes a fabricated RunBundle.
        """
        if self._fresh_evidence is None:
            return None
        helper = Path(__file__).with_name("fresh_verify.py")
        _require(helper.is_file() and not helper.is_symlink(), "Fresh evidence verifier is unavailable")
        spec = importlib.util.spec_from_file_location("local_evidence_fresh_verifier", helper)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        result = module.verify_fresh(self._fresh_evidence, self._fresh_trust, self.repo / "target/debug")
        _require(isinstance(result, dict) and result.get("status") == "PASS",
                 "Fresh original evidence did not pass offline verification")
        _require(len(json.dumps(result, allow_nan=False).encode()) <= 256 * 1024,
                 "Fresh public verification summary exceeds its bound")
        public = dict(result)
        public["api_admission"] = {
            "status": "NOT_REQUESTED",
            "description": "Offline-verified original capture; not admitted through /v1/observations",
            "decoded_archive_limit_bytes": 512 * 1024,
            "source_authority": "LOCAL_DEMO_DISPLAY_CONFIGURATION_NOT_KERNEL_EVIDENCE",
        }
        return public

    def _listener_is_loopback(self):
        if sys.platform == "darwin":
            lsof = shutil.which("lsof")
            _require(lsof is not None, "Local listener inspection requires lsof")
            reply = subprocess.run([lsof, "-nP", "-a", "-p", str(self._process.pid), "-iTCP", "-sTCP:LISTEN", "-Fn"],
                                   capture_output=True, timeout=10)
            addresses = {line[1:] for line in reply.stdout.decode().splitlines() if line.startswith("n")}
            return reply.returncode == 0 and addresses == {f"127.0.0.1:{self.port}"}
        if sys.platform.startswith("linux"):
            inodes = set()
            for fd in Path(f"/proc/{self._process.pid}/fd").iterdir():
                try:
                    value = os.readlink(fd)
                    if value.startswith("socket:["):
                        inodes.add(value[8:-1])
                except FileNotFoundError:
                    pass
            listeners = []
            for line in Path(f"/proc/{self._process.pid}/net/tcp").read_text().splitlines()[1:]:
                fields = line.split()
                if fields[3] == "0A" and fields[9] in inodes:
                    address, port = fields[1].split(":")
                    listeners.append((socket.inet_ntoa(bytes.fromhex(address)[::-1]), int(port, 16)))
            for line in Path(f"/proc/{self._process.pid}/net/tcp6").read_text().splitlines()[1:]:
                fields = line.split()
                if fields[3] == "0A" and fields[9] in inodes:
                    listeners.append(("unexpected IPv6 listener", int(fields[1].split(":")[1], 16)))
            return listeners == [("127.0.0.1", self.port)]
        raise RuntimeSetupError("Local listener inspection supports Mac and Linux only")

    def start(self):
        _require(not self._started, "Local API context cannot be reused")
        self._started = True
        try:
            binary = self.repo / "target/debug/airon-aip"
            _require(binary.is_file() and os.access(binary, os.X_OK), "Build the actual airon-aip API first")
            _require(b"AIP_BIND_ADDRESS" in binary.read_bytes(), "Rebuild airon-aip with the loopback binding setting")
            if self.root.exists():
                _require(self.root.is_dir() and not self.root.is_symlink(), "Local state root must be a real directory")
            else:
                self.root.mkdir(parents=True, mode=0o700)
            self._private = Path(tempfile.mkdtemp(prefix="api-", dir=self.root))
            records = self._historical_records()  # Verify before starting/admitting anything.
            self.fresh_observation = self._verify_fresh_observation()
            self._tenant = "local-evidence-" + secrets.token_hex(8)
            other_tenant = "other-" + secrets.token_hex(8)
            self._operator_token, self.reader_token, self._other_token = [secrets.token_urlsafe(40) for _ in range(3)]
            _save(self._private / "keys.json", {"keys": [
                {"key_id": name, "tenant_id": tenant, "role": role, "secret_sha256": _sha(token.encode())}
                for name, tenant, role, token in [("operator-bootstrap", self._tenant, "machine", self._operator_token),
                    ("agent-reader", self._tenant, "reader", self.reader_token),
                    ("other-reader", other_tenant, "reader", self._other_token)]]})
            _save(self._private / "trust.json", {"tenants": [{"tenant_id": self._tenant, "trust": row["trust"]} for row in records]})
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", self.port))
                self.port = reservation.getsockname()[1]
            self.base_url = f"http://127.0.0.1:{self.port}"
            env = {"PATH": os.defpath, "AIP_BIND_ADDRESS": "127.0.0.1", "AIP_PORT": str(self.port),
                   "AIP_KEY_PATH": str(self._private / "service.key"), "AIP_KEY_PASSPHRASE": secrets.token_urlsafe(48),
                   "AIP_REVOCATION_LOG_PATH": str(self._private / "revocations.jsonl"),
                   "AIP_VAULT_PATH": str(self._private / "evidence.jsonl"), "AIP_ARTIFACT_PATH": str(self._private / "artifacts.jsonl"),
                   "AIP_API_KEYS_PATH": str(self._private / "keys.json"), "AIP_RUN_TRUST_PATH": str(self._private / "trust.json"),
                   "AIP_STORE_BACKEND": "jsonl"}
            self._log = (self._private / "service.log").open("xb")
            self._process = subprocess.Popen([str(binary)], env=env, stdin=subprocess.DEVNULL,
                                             stdout=self._log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                _require(self._process.poll() is None, "Actual local API exited during startup")
                try:
                    status, access = self._request("/v1/access", token=self.reader_token)
                    if status == 200 and access["role"] == "reader" and access["tenant_id"] == self._tenant:
                        break
                except (OSError, URLError, TimeoutError):
                    pass
                time.sleep(0.1)
            else:
                raise RuntimeSetupError("Actual local API did not become ready")
            _require(self._listener_is_loopback(), "Actual API listener is not exclusively loopback")
            reader = self._sdk(self.reader_token)
            for row in records:
                status, admitted = self._request("/v1/runs", token=self._operator_token, body=row["raw"], method="POST")
                _require(status == 200 and admitted["bundle_sha256"] == _sha(row["raw"]), "Historical API admission failed")
                artifact_id = admitted["run_artifact_id"]
                _require(reader.get_run_metadata(artifact_id) == admitted and reader.evaluate_run(artifact_id) == row["evaluation"],
                         "Actual Reader SDK metadata/evaluation differs")
                _require(reader.get_run_verdict(artifact_id) == row["bundle"]["signed_reconciliation"], "Actual Reader signed verdict differs")
                self.runs.append({"id": artifact_id, "run_artifact_id": artifact_id, "profile": row["profile"],
                    "label": LABELS[row["profile"]], "agent_id": row["bundle"]["agent_id"], "run_id": row["bundle"]["run_id"],
                    "evidence_source": "HISTORICAL_SIGNED_LINUX_CAPTURE", "source_commit": SOURCE,
                    "workflow_run_id": WORKFLOW_RUN, "current_host_kernel_capture": False})
            first = self.runs[0]["run_artifact_id"]
            connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
            try:
                # Offer a large upload but wait for its authorization response
                # before sending body bytes. An early-close TCP reset is not
                # an HTTP refusal and is never counted as a passing check.
                connection.putrequest("POST", "/v1/runs")
                connection.putheader("Authorization", "Bearer " + self.reader_token)
                connection.putheader("Content-Type", "application/json")
                connection.putheader("Content-Length", str(len(records[0]["raw"])))
                connection.putheader("Expect", "100-continue")
                connection.endheaders()
                response = connection.getresponse()
                upload_preflight_refused = response.status == 403
                response.read(65536)
            finally:
                connection.close()
            checks = {"anonymous_denied": self._request("/v1/access")[0] == 401,
                      "reader_write_denied": self._request("/v1/runs", token=self.reader_token, body=b"{}", method="POST")[0] == 403,
                      "reader_large_upload_preflight_denied": upload_preflight_refused,
                      "reader_raw_bundle_denied": self._request("/v1/runs/" + first, token=self.reader_token)[0] == 403,
                      "cross_tenant_denied": self._request("/v1/runs/" + first + "/metadata", token=self._other_token)[0] == 404}
            _require(all(checks.values()), "Actual API credential boundary check failed")
            self.auth_checks = {name: "PASS" for name in checks}
            _save(self._private / "public-summary.json", self.public_summary())
            self._operator_token = self._other_token = ""  # Bootstrap authority never reaches the agent.
            return self
        except BaseException:
            self.close()
            raise

    def public_summary(self):
        return {"classification": "LOCAL_MAC_OR_LINUX_API_HISTORICAL_EVIDENCE_DEMO", "base_url": self.base_url,
                "runs": self.runs, "auth_checks": self.auth_checks, "historical_original_zip_sha256": ZIP_SHA256,
                "fresh_observation": self.fresh_observation,
                "current_host_kernel_capture": False, "managed_evidence_signing": False,
                "credential_scope": "Reader only for agent; separate bootstrap machine credential never returned",
                "scope": "API run records retain their original historical Linux evidence. Optional fresh_observation is a separate offline-verified Linux capture, not an admitted RunBundle or independent custody."}

    def close(self):
        if self._process is not None:
            if self._process.poll() is None:
                self._process.terminate()
                try:
                    self._process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    self._process.wait(timeout=5)
            self._process = None
        if self._log is not None:
            self._log.close()
            self._log = None
        self.reader_token = self._operator_token = self._other_token = ""
