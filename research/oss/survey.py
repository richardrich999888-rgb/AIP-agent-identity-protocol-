"""Pin each open-source candidate to a commit and record its license files.

For every candidate this resolves a release tag to a commit with
`git ls-remote`, fetches that commit's tree only (`--depth 1
--filter=blob:none`), and reads the license files and any directory named
`enterprise` or `ee`. Each license file is hashed (SHA-256) and classified by
fixed signature strings. A file matching no signature is reported as
UNRECOGNISED with its first line; nothing is guessed.

It reads only public git data. It records no claims about architecture or
security; those are written by hand in the matrix, citing this output.

    python3 research/oss/survey.py OUT.json [WORKDIR]
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

GIT_TIMEOUT_S = 300
LICENSE_NAME = re.compile(r"^(licen[cs]e|copying|notice)([._-].*)?$", re.IGNORECASE)
ENTERPRISE_DIR = re.compile(r"^(enterprise|ee)$", re.IGNORECASE)
MAX_LICENSE_DEPTH = 4  # path components; deeper files are vendored deps
TOP_EXTENSIONS = 6

# Ordered: the first signature found wins. Strings are verbatim from the
# license texts, compared after collapsing whitespace.
SIGNATURES: tuple[tuple[str, str], ...] = (
    ("GNU AFFERO GENERAL PUBLIC LICENSE", "AGPL"),
    ("GNU LESSER GENERAL PUBLIC LICENSE", "LGPL"),
    ("GNU GENERAL PUBLIC LICENSE", "GPL"),
    ("Elastic License 2.0", "Elastic-2.0"),
    ("Business Source License", "BUSL"),
    ("Server Side Public License", "SSPL"),
    ("Mozilla Public License Version 2.0", "MPL-2.0"),
    ("Apache License Version 2.0", "Apache-2.0"),
    ("Apache License, Version 2.0", "Apache-2.0"),
    ("Permission is hereby granted, free of charge", "MIT"),
    ("Redistribution and use in source and binary forms", "BSD"),
)


@dataclass(frozen=True)
class Candidate:
    """One project to pin. `tag` None pins the default branch head."""

    name: str
    repo: str
    tag: str | None


CANDIDATES: tuple[Candidate, ...] = (
    Candidate("OpenLIT", "openlit/openlit", "py-1.45.0"),
    Candidate("LiteLLM", "BerriAI/litellm", "v1.110.2"),
    Candidate("OPA", "open-policy-agent/opa", "v1.22.4"),
    Candidate("Falco", "falcosecurity/falco", "0.45.2"),
    Candidate("OpenTelemetry Collector", "open-telemetry/opentelemetry-collector", "v0.165.0"),
    Candidate("OpenTelemetry Collector Contrib", "open-telemetry/opentelemetry-collector-contrib", "v0.165.1"),
    Candidate("OpenLoop (ambiguous name)", "openloop-team/openloop", "v0.1.1"),
    Candidate("Langfuse", "langfuse/langfuse", "v4.83.0"),
    Candidate("Arize Phoenix", "Arize-ai/phoenix", "arize-phoenix-v22.0.0"),
    Candidate("SPIRE", "spiffe/spire", "v1.16.0"),
    Candidate("OpenFGA", "openfga/openfga", "v1.22.1"),
    Candidate("MCP Context Forge", "IBM/mcp-context-forge", "v1.1.1"),
    Candidate("Microsoft MCP Gateway", "microsoft/mcp-gateway", "v1.0.1"),
    Candidate("Docker MCP Gateway", "docker/mcp-gateway", "v0.44.3"),
    Candidate("Lasso MCP Gateway", "lasso-security/mcp-gateway", "v1.2.0"),
    Candidate("OpenLLMetry", "traceloop/openllmetry", "v0.63.1"),
    Candidate("OpenInference", "Arize-ai/openinference", None),
)


def classify(text: str) -> str:
    """Return the license class of `text` by the first matching signature."""
    flat = " ".join(text.split())
    for needle, label in SIGNATURES:
        if needle in flat:
            return label
    return "UNRECOGNISED"


def resolve(ls_remote: str, tag: str | None) -> str:
    """Commit for `tag` (peeled when annotated) or HEAD, from ls-remote output.

    Raises LookupError when the ref is absent: a missing pin is an error, not
    a fallback to some other ref.
    """
    refs = dict(
        (ref, sha) for sha, ref in (line.split("\t", 1) for line in ls_remote.splitlines() if "\t" in line)
    )
    if tag is None:
        if "HEAD" not in refs:
            raise LookupError("HEAD not advertised")
        return refs["HEAD"]
    name = f"refs/tags/{tag}"
    sha = refs.get(name + "^{}") or refs.get(name)
    if sha is None:
        raise LookupError(f"tag {tag} not found")
    return sha


def license_paths(paths: list[str]) -> list[str]:
    """License-like files at most MAX_LICENSE_DEPTH deep, outside vendor dirs."""
    out = []
    for p in paths:
        parts = p.split("/")
        if len(parts) > MAX_LICENSE_DEPTH or any(x in ("vendor", "node_modules", "third_party") for x in parts):
            continue
        if LICENSE_NAME.match(parts[-1]):
            out.append(p)
    return sorted(out)


def enterprise_dirs(paths: list[str]) -> list[str]:
    """Directories named `enterprise` or `ee`, up to three levels deep."""
    found = set()
    for p in paths:
        parts = p.split("/")[:-1]
        for i, part in enumerate(parts[:3]):
            if ENTERPRISE_DIR.match(part):
                found.add("/".join(parts[: i + 1]))
    return sorted(found)


def extensions(paths: list[str]) -> list[tuple[str, int]]:
    """Most common file extensions, ties broken by name for determinism."""
    c = Counter(Path(p).suffix.lower() or "(none)" for p in paths)
    return sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP_EXTENSIONS]


def git(*args: str, cwd: Path | None = None) -> str:
    """Run git, returning stdout; raise with stderr on failure."""
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=GIT_TIMEOUT_S)
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip()[:300]}")
    return r.stdout


def survey(c: Candidate, work: Path) -> dict:
    """Pin one candidate and read its license files."""
    url = f"https://github.com/{c.repo}"
    commit = resolve(git("ls-remote", url, "HEAD", "refs/tags/*"), c.tag)
    d = work / c.repo.replace("/", "__")
    d.mkdir(parents=True, exist_ok=True)
    git("init", "-q", cwd=d)
    git("fetch", "-q", "--depth", "1", "--filter=blob:none", url, commit, cwd=d)
    paths = git("ls-tree", "-r", "--name-only", commit, cwd=d).splitlines()
    licenses = []
    for p in license_paths(paths):
        blob = subprocess.run(
            ["git", "cat-file", "blob", f"{commit}:{p}"], cwd=d, capture_output=True, timeout=GIT_TIMEOUT_S, check=True
        ).stdout
        text = blob.decode("utf-8", "replace")
        first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
        licenses.append(
            {"path": p, "bytes": len(blob), "sha256": hashlib.sha256(blob).hexdigest(), "class": classify(text), "first_line": first[:120]}
        )
    return {
        "name": c.name,
        "repo": c.repo,
        "tag": c.tag,
        "commit": commit,
        "commit_date": git("log", "-1", "--format=%cI", commit, cwd=d).strip(),
        "files": len(paths),
        "licenses": licenses,
        "enterprise_dirs": enterprise_dirs(paths),
        "extensions": extensions(paths),
    }


def main(argv: list[str]) -> int:
    """Survey every candidate; a failed candidate is recorded, not dropped."""
    if len(argv) not in (2, 3):
        print(__doc__, file=sys.stderr)
        return 2
    work = Path(argv[2]) if len(argv) == 3 else Path(tempfile.mkdtemp(prefix="oss-survey-"))
    rows = []
    for c in CANDIDATES:
        try:
            rows.append(survey(c, work))
        except (RuntimeError, LookupError, subprocess.SubprocessError) as e:
            rows.append({"name": c.name, "repo": c.repo, "tag": c.tag, "error": str(e)})
        print(f"{c.repo}: {'error' if 'error' in rows[-1] else 'ok'}", file=sys.stderr)
    Path(argv[1]).write_text(json.dumps(rows, indent=1, sort_keys=True) + "\n")
    return 1 if any("error" in r for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
