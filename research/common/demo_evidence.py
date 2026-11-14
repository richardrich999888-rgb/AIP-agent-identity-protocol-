#!/usr/bin/env python3
"""Shared emitter for the demo result files under ``docs/demo/results/``.

Why this exists (loop item X2): every emitted number must carry the hardware
it was measured on, and an explicit warning that it may not be merged with the
figures in ``research/compute-memory/BASELINES.md`` and ``V02_REPORT.md``,
which were measured on a different machine. The first result file carried that
stamp by hand. A second hand-written copy is how two result files come to
disagree about the machine they were produced on, so the stamp lives here and
is read from ``/proc`` at emit time.

No randomness, no network, no model call. Pure except for reading ``/proc``,
the git commit and the clock, each of which is an input to the record.
"""

from __future__ import annotations

import json
import platform
import subprocess
import time
from pathlib import Path
from typing import Any

#: Schema tag of every file this module writes. Bumping it is a breaking
#: change for anything that reads result files.
SCHEMA = "syntriass.demo.item_evidence/1"

#: The machine the published v0.2 figures were measured on. Stated in full so
#: a reader comparing two result files can see at a glance whether they are
#: comparable, rather than having to find the report.
PUBLISHED_BENCH_MACHINE = (
    "V02_REPORT.md and BASELINES.md figures were measured on 2 vCPU Xeon "
    "(AVX-512) / 8 GB. Nothing here may be merged with those."
)


def _proc_field(path: str, key: str) -> str:
    """First value of ``key`` in a ``/proc`` file, or "" when absent."""
    try:
        text = Path(path).read_text()
    except OSError:
        return ""
    for line in text.splitlines():
        name, _, value = line.partition(":")
        if name.strip() == key:
            return value.strip()
    return ""


def _cores() -> int:
    """Logical CPUs as the kernel reports them, not as a library guesses."""
    try:
        return sum(
            1
            for line in Path("/proc/cpuinfo").read_text().splitlines()
            if line.startswith("processor")
        )
    except OSError:
        return 0


def _ram_mib() -> int:
    """Total RAM in MiB, from MemTotal (reported in kB)."""
    total = _proc_field("/proc/meminfo", "MemTotal")
    digits = "".join(c for c in total if c.isdigit())
    return int(digits) // 1024 if digits else 0


def _gpu() -> str:
    """Report a GPU only if one is actually present.

    `none` is a measured absence here, not a placeholder: the container has no
    DRM render node, which is what a CPU-only claim rests on.
    """
    nodes = sorted(p.name for p in Path("/dev/dri").glob("render*")) if Path("/dev/dri").is_dir() else []
    return ", ".join(nodes) if nodes else "none"


def hardware() -> dict[str, Any]:
    """The live machine, read at emit time."""
    return {
        "cpu_model": _proc_field("/proc/cpuinfo", "model name"),
        "cores": _cores(),
        "ram_mib": _ram_mib(),
        "gpu": _gpu(),
        "kernel": platform.release(),
        "NOT_the_published_bench_machine": PUBLISHED_BENCH_MACHINE,
    }


def git(*args: str, repo: Path | None = None) -> str:
    """Run git and return stdout stripped, or "" if git fails.

    Used for the commit and branch recorded in every result file. A failure
    yields "" rather than an exception: a result file that records no commit
    is honest, one that fails to be written at all loses the measurement.
    """
    try:
        out = subprocess.run(
            ["git", *args],
            cwd=str(repo) if repo else None,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return ""
    return out.stdout.strip() if out.returncode == 0 else ""


def evidence(
    *,
    item: str,
    acceptance_criterion: str,
    result: str,
    repo: Path,
    **sections: Any,
) -> dict[str, Any]:
    """Assemble a result record.

    ``result`` is one of the loop's verdicts (MET / PARTIAL / NOT_MET /
    BLOCKED / NOT_EXECUTED); it is not validated here because a caller that
    invents a verdict has a problem this function cannot fix, and refusing to
    write the record would lose the measurement with it.

    ``commit`` is the HEAD the run was made from, and ``tree_dirty`` says
    whether that commit identifies the code that ran. Re-run a recorder on a
    clean tree if the result is to be cited as reproducible.
    """
    record = {
        "schema": SCHEMA,
        "item": item,
        # The HEAD the run was made from. It precedes the commit that records
        # the result, because the result file is written before it is
        # committed; there is no way round that regress, so it is stated
        # rather than papered over.
        "commit": git("rev-parse", "HEAD", repo=repo),
        # Whether that commit actually identifies the code that ran. On a
        # dirty tree it does not, and a result file that implies otherwise is
        # worse than one that admits it.
        "tree_dirty": git("status", "--porcelain", repo=repo) != "",
        "branch": git("rev-parse", "--abbrev-ref", "HEAD", repo=repo),
        "recorded_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "hardware": hardware(),
        "acceptance_criterion": acceptance_criterion,
        "result": result,
    }
    record.update(sections)
    return record


def write(path: Path, record: dict[str, Any]) -> Path:
    """Write a result record as pretty JSON with a trailing newline."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2, sort_keys=False) + "\n")
    return path
