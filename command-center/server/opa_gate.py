"""OPA decision adapter for the gate (enterprise WOW loop, item 3.1a). Stdlib only.

On each call, `OpaGate.decide(request)`:

1. reads the bundle files (`*.rego` except `*_test.rego`, plus `data.json`)
   once, hashes exactly those bytes (`bundle_sha256`), and writes them into
   a private temporary directory, so the hash names what was evaluated
   even if the source directory changes concurrently;
2. runs `opa eval` on that copy, with the request on stdin and a timeout;
3. accepts only a well-formed decision: `outcome` in OUTCOMES and `reasons`
   a list of strings, where a non-empty `reasons` requires DENY.

**Fail closed.** Each of the following returns DENY with a reason naming
the failure. None raises to the caller:

- binary missing;
- timeout or non-zero exit;
- unparseable output;
- undefined result;
- malformed decision;
- unreadable bundle;
- a request that is not JSON.

`opa eval` is used instead of an OPA server: there is then no listening
socket, and no management API that accepts unauthenticated policy or data
writes (finding in research/oss/opa/README.md). The cost is one process
start per decision.

This module decides. The gate that calls it enforces: it forwards only on
ALLOW, and it holds on PENDING_APPROVAL (3.2).
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

OUTCOMES = ("ALLOW", "DENY", "PENDING_APPROVAL")
QUERY = "data.vanian.gate.decision"
BUNDLE_DOMAIN = b"vanian-policy-bundle/v1\n"
INPUT_DOMAIN = b"vanian-gate-input/v1\n"
DEFAULT_TIMEOUT_S = 5.0
MAX_OUTPUT_BYTES = 1 << 20


class BundleError(ValueError):
    """The policy directory is not a usable bundle."""


@dataclass(frozen=True)
class GateDecision:
    """One decision. `bundle_sha256` is None only when the bundle could not be read."""

    outcome: str
    reasons: tuple[str, ...]
    bundle_sha256: str | None
    input_sha256: str | None
    engine_ok: bool  # False: this DENY is fail-closed, not a policy result

    @property
    def forward(self) -> bool:
        """True only for ALLOW: the one outcome on which a gate may forward a call."""
        return self.outcome == "ALLOW"


def read_bundle(policy_dir: Path) -> dict[str, bytes]:
    """Relative path → bytes for every bundle file. Raise BundleError if unusable."""
    if not policy_dir.is_dir():
        raise BundleError(f"not a directory: {policy_dir}")
    files = {
        p.relative_to(policy_dir).as_posix(): p.read_bytes()
        for p in sorted(policy_dir.rglob("*"))
        if p.is_file() and ((p.suffix == ".rego" and not p.name.endswith("_test.rego")) or p.name == "data.json")
    }
    if not any(k.endswith(".rego") for k in files):
        raise BundleError("no policy (.rego) files")
    if "data.json" not in files:
        raise BundleError("no top-level data.json")
    return files


def bundle_hash(files: dict[str, bytes]) -> str:
    """SHA-256 over (path, SHA-256(content)) pairs in path order, domain separated."""
    h = hashlib.sha256(BUNDLE_DOMAIN)
    for path in sorted(files):
        h.update(path.encode() + b"\0" + hashlib.sha256(files[path]).digest() + b"\n")
    return h.hexdigest()


def parse_decision(stdout: bytes) -> tuple[str, tuple[str, ...]] | str:
    """(outcome, reasons) from `opa eval --format=json` output, or an error string."""
    if len(stdout) > MAX_OUTPUT_BYTES:
        return "policy output too large"
    try:
        doc = json.loads(stdout)
        value = doc["result"][0]["expressions"][0]["value"]
    except (json.JSONDecodeError, UnicodeDecodeError):
        return "policy output not JSON"
    except (KeyError, IndexError, TypeError):
        return "policy result undefined"
    if not isinstance(value, dict) or set(value) != {"outcome", "reasons"}:
        return "policy output malformed"
    outcome, reasons = value["outcome"], value["reasons"]
    if outcome not in OUTCOMES or not isinstance(reasons, list) or not all(isinstance(r, str) for r in reasons):
        return "policy output malformed"
    if reasons and outcome != "DENY":
        return "policy output inconsistent: reasons without DENY"
    return outcome, tuple(reasons)


class OpaGate:
    """Decides gated calls with a pinned `opa` binary and a policy directory."""

    def __init__(self, opa_bin: Path | str, policy_dir: Path | str, timeout_s: float = DEFAULT_TIMEOUT_S) -> None:
        self._opa = str(opa_bin)
        self._dir = Path(policy_dir)
        self._timeout = timeout_s

    def decide(self, request: object) -> GateDecision:
        """Decide one request. Never raises; any failure is a fail-closed DENY."""
        try:
            stdin = json.dumps(request, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        except (TypeError, ValueError):
            return GateDecision("DENY", ("request is not JSON",), None, None, False)
        input_sha = hashlib.sha256(INPUT_DOMAIN + stdin).hexdigest()
        try:
            files = read_bundle(self._dir)
        except (BundleError, OSError) as e:
            return GateDecision("DENY", (f"policy bundle unusable: {e}",), None, input_sha, False)
        digest = bundle_hash(files)
        work = Path(tempfile.mkdtemp(prefix="vanian-opa-"))
        try:
            for rel, data in files.items():
                (work / rel).parent.mkdir(parents=True, exist_ok=True)
                (work / rel).write_bytes(data)
            proc = subprocess.run(
                [self._opa, "eval", "--format=json", "--stdin-input", "--data", str(work), QUERY],
                input=stdin, capture_output=True, timeout=self._timeout, check=False,
            )
        except FileNotFoundError:
            return GateDecision("DENY", ("policy engine unavailable: binary not found",), digest, input_sha, False)
        except subprocess.TimeoutExpired:
            return GateDecision("DENY", ("policy engine unavailable: timeout",), digest, input_sha, False)
        except OSError as e:
            return GateDecision("DENY", (f"policy engine unavailable: {type(e).__name__}",), digest, input_sha, False)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        if proc.returncode != 0:
            return GateDecision("DENY", (f"policy engine failed: exit {proc.returncode}",), digest, input_sha, False)
        parsed = parse_decision(proc.stdout)
        if isinstance(parsed, str):
            return GateDecision("DENY", (parsed,), digest, input_sha, False)
        return GateDecision(parsed[0], parsed[1], digest, input_sha, True)
