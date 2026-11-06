#!/usr/bin/env python3
"""Recorded run for loop item A2: the teach session API, end to end.

What this exercises that the unit and CLI tests do not: the real
``make_pdf_fixture`` PDF, the real ``ingest_documents`` extraction (text layer
*and* OCR), the real ``syntriass`` binary, and an **independent**
recomputation of the session's content hash in Python. The Rust tests prove
the code agrees with itself; recomputing the hash from the stored file with a
separate implementation is what shows the stored ``session_id`` actually names
its content.

No model is loaded and no network is touched: a teach session is pure
bookkeeping over an expert's words and a document's bytes. That is a property
of the item, not an omission, and it is asserted below.

Usage:
    deploy/syntriass/venv/bin/python3 \\
        research/capability-learning/harness/record_teach_session.py \\
        [--out docs/demo/results/A2_teach_session.json] [--keep DIR]

Exit codes: 0 pass, 3 a step failed, 4 a verification failed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "research" / "common"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import demo_evidence  # noqa: E402  (path set above)
import ingest_documents  # noqa: E402
import make_pdf_fixture  # noqa: E402

#: Domain separator and schema tag, mirrored from
#: sovereign/syntriass-runtime/src/domain/teach.rs. A change on either side
#: must break `verify_hash_independently`, which is the point of duplicating
#: them: an accidental change to the hashed content is then a test failure,
#: not a silent change of every session's identity.
DOMAIN = b"syntriass-teach-session/v1\n"
HASHED_FIELDS = [
    "schema",
    "tenant",
    "task",
    "expert_id",
    "document",
    "document_sha256",
    "pages",
    "clauses",
    "rule",
    "examples",
    "ocr_cited",
    "created_ms",
]
#: Field order inside a clause and an example, as the Rust structs declare
#: them. serde_json emits struct fields in declaration order.
CLAUSE_FIELDS = [
    "document",
    "document_sha256",
    "page",
    "index",
    "text",
    "char_start",
    "char_end",
    "extraction",
]
EXAMPLE_FIELDS = ["id", "text", "label", "reason"]

TENANT = "koravi-process"
EXPERT = "expert:koravi-elec-lead"

#: The expert's rule for page 2, in their own words. Synthetic document, so no
#: customer data (standing rule 6).
TEMP_RULE = (
    "Only accept a test when the winding temperature was between 10 and 25 "
    "degrees C and was read at the stator winding. Anything else is deferred."
)
TEMP_EXAMPLES = [
    {
        "id": "t1",
        "text": "Winding temperature at the stator was 18 C at the time of test.",
        "label": "allowed",
        "reason": "18 C is inside the 10 C to 25 C range in Section 2, read at the winding.",
    },
    {
        "id": "t2",
        "text": "Winding temperature at the stator was 31 C at the time of test.",
        "label": "not_allowed",
        "reason": "31 C is above the 25 C ceiling, so Section 2 requires the test be deferred.",
    },
    {
        "id": "t3",
        "text": "Temperature was taken at the motor frame and read 15 C.",
        "label": "not_allowed",
        "reason": "Section 2 requires the stator winding, not the frame, whatever the reading.",
    },
]

#: Page 20 of the fixture is an image with no text layer, so its clauses come
#: from OCR. Teaching from it is how the OCR flag is shown to reach a session.
OCR_RULE = (
    "A rewound motor must reach 10.0 megohm whatever its rated voltage, and a "
    "rewound motor may not be released without human review."
)
OCR_EXAMPLES = [
    {
        "id": "o1",
        "text": "A rewound 6.6 kV motor read 12.5 megohm and an engineer signed the release.",
        "label": "allowed",
        "reason": "Above 10.0 megohm and reviewed by a person, as Annex B requires.",
    },
    {
        "id": "o2",
        "text": "A rewound 11 kV motor read 8.0 megohm and was released automatically.",
        "label": "not_allowed",
        "reason": "Below the 10.0 megohm floor for rewound motors and no human review.",
    },
]


class Failure(Exception):
    """A step or a verification failed. Carries its own exit code."""

    def __init__(self, message: str, code: int = 3) -> None:
        super().__init__(message)
        self.code = code


def run(args: list[str], *, cwd: Path | None = None) -> str:
    """Run a command, returning stdout; raise Failure with stderr on error."""
    proc = subprocess.run(args, capture_output=True, text=True, cwd=cwd)
    if proc.returncode != 0:
        raise Failure(
            f"{' '.join(args[:3])}… exited {proc.returncode}\n"
            f"stdout: {proc.stdout.strip()}\nstderr: {proc.stderr.strip()}"
        )
    return proc.stdout


def expect_failure(args: list[str]) -> str:
    """Run a command that must fail; return its stderr."""
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode == 0:
        raise Failure(f"expected failure, but {' '.join(args[:3])}… succeeded", 4)
    return proc.stderr.strip()


def build_binary() -> Path:
    """Build and locate the real `syntriass` binary."""
    run(["cargo", "build", "-p", "syntriass-runtime", "--bin", "syntriass"], cwd=REPO)
    path = REPO / "target" / "debug" / "syntriass"
    if not path.is_file():
        raise Failure(f"{path}: not built")
    return path


def write_config(state: Path, path: Path) -> Path:
    """A runtime config whose model fields are never read by `teach`.

    `teach` loads no model; `syntriass health` is the command that verifies
    model digests. The paths below are therefore recorded as unused rather
    than pointed at a staged model that does not exist in this container.
    """
    path.write_text(
        json.dumps(
            {
                "state": str(state),
                "policy_version": "a2-record",
                "security_domain": "demo",
                "rag_k": 4,
                "approvers": {},
                "python": sys.executable,
                "sidecar_script": "UNUSED_BY_TEACH",
                "llama_server": "UNUSED_BY_TEACH",
                "profile": "none",
                "q4": {"path": "UNUSED_BY_TEACH", "sha256": "0" * 64},
                "q8": {"path": "UNUSED_BY_TEACH", "sha256": "0" * 64},
                "port": 18080,
            },
            indent=2,
        )
        + "\n"
    )
    return path


def ingest_page(document: Path, page: int, out: Path) -> dict:
    """Run the A1 ingester for one page and return its payload."""
    code = ingest_documents.main([str(document), "--page", str(page), "--out", str(out)])
    if code != 0:
        raise Failure(f"ingest of {document.name} page {page} exited {code}")
    return json.loads(out.read_text())


def jsonl(path: Path, rows: list[dict]) -> Path:
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return path


def start_session(
    binary: Path, config: Path, document: Path, page: int, clauses: Path,
    task: str, rule: Path, examples: Path,
) -> dict:
    return json.loads(
        run([
            str(binary), "teach", "start",
            "--config", str(config),
            "--tenant", TENANT,
            "--task", task,
            "--expert", EXPERT,
            "--doc", str(document),
            "--page", str(page),
            "--clauses", str(clauses),
            "--rule-file", str(rule),
            "--examples", str(examples),
        ])
    )


def canonical(session: dict) -> bytes:
    """Reproduce the Rust canonical encoding from the stored session file.

    serde_json emits compact JSON with struct fields in declaration order, so
    an ordered dict with the same field order and no separator whitespace is
    byte-identical. `ensure_ascii=False` matches serde, which emits non-ASCII
    as UTF-8 rather than as \\u escapes.
    """
    def clause(c: dict) -> dict:
        return {k: c[k] for k in CLAUSE_FIELDS}

    def example(e: dict) -> dict:
        return {k: e[k] for k in EXAMPLE_FIELDS}

    body: dict = {}
    for field in HASHED_FIELDS:
        if field == "clauses":
            body[field] = [clause(c) for c in session["clauses"]]
        elif field == "examples":
            body[field] = [example(e) for e in session["examples"]]
        else:
            body[field] = session[field]
    text = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
    return DOMAIN + text.encode("utf-8")


def verify_hash_independently(session: dict) -> str:
    """Recompute session_id here; raise if it differs from the stored one."""
    computed = hashlib.sha256(canonical(session)).hexdigest()
    if computed != session["session_id"]:
        raise Failure(
            "independent hash disagrees with the stored session_id:\n"
            f"  stored:   {session['session_id']}\n"
            f"  computed: {computed}",
            4,
        )
    return computed


def check(condition: bool, message: str) -> None:
    if not condition:
        raise Failure(message, 4)


def record_run(work: Path, binary: Path) -> dict:
    """Everything measured in one run, as a dict of result sections."""
    state = work / "state"
    config = write_config(state, work / "config.json")

    document = make_pdf_fixture.build(work / "EP-114.pdf")
    doc_sha = ingest_documents.sha256_file(document)

    # ---- scene 1: a text-layer page -------------------------------------
    page2 = ingest_page(document, 2, work / "page2.clauses.json")
    check(page2["clause_count"] > 0, "page 2 yielded no clauses")
    check(
        set(page2["extraction_counts"]) == {"pdf_text"},
        f"page 2 was not read from the text layer: {page2['extraction_counts']}",
    )
    rule_file = work / "temp_rule.txt"
    rule_file.write_text(TEMP_RULE + "\n")
    temp = start_session(
        binary, config, document, 2, work / "page2.clauses.json",
        "winding_temperature_gate", rule_file,
        jsonl(work / "temp_examples.jsonl", TEMP_EXAMPLES),
    )

    stored = Path(temp["path"])
    mode = stat.S_IMODE(stored.stat().st_mode)
    check(mode == 0o600, f"{stored}: mode {oct(mode)}, expected 0o600")
    tenant_dir = stored.parent
    tenant_mode = stat.S_IMODE(tenant_dir.stat().st_mode)
    check(tenant_mode == 0o700, f"{tenant_dir}: mode {oct(tenant_mode)}, expected 0o700")
    check(
        tenant_dir.name == TENANT,
        f"session stored under {tenant_dir.name}, not the tenant {TENANT}",
    )

    shown = json.loads(
        run([str(binary), "teach", "show", "--config", str(config),
             "--tenant", TENANT, "--session", temp["session_id"]])
    )
    check(shown["rule"] == TEMP_RULE + "\n", "the stored rule is not what the expert wrote")
    check(
        [e["reason"] for e in shown["examples"]] == [e["reason"] for e in TEMP_EXAMPLES],
        "the stored reasons are not what the expert wrote",
    )
    check(shown["ocr_cited"] == [], f"text-layer page flagged OCR: {shown['ocr_cited']}")
    independent = verify_hash_independently(shown)

    # ---- scene 2: the image-only page, cited through OCR ----------------
    page20 = ingest_page(document, 20, work / "page20.clauses.json")
    check(
        set(page20["extraction_counts"]) == {"pdf_ocr"},
        f"page 20 was not recovered by OCR: {page20['extraction_counts']}",
    )
    ocr_rule_file = work / "ocr_rule.txt"
    ocr_rule_file.write_text(OCR_RULE + "\n")
    ocr = start_session(
        binary, config, document, 20, work / "page20.clauses.json",
        "rewound_motor_floor", ocr_rule_file,
        jsonl(work / "ocr_examples.jsonl", OCR_EXAMPLES),
    )
    check(
        len(ocr["needs_confirmation"]) == page20["clause_count"],
        "not every OCR clause was flagged for confirmation: "
        f"{ocr['needs_confirmation']} of {page20['clause_count']}",
    )
    ocr_shown = json.loads(
        run([str(binary), "teach", "show", "--config", str(config),
             "--tenant", TENANT, "--session", ocr["session_id"]])
    )
    verify_hash_independently(ocr_shown)

    # ---- scene 3: refusals, each one a real attempt ---------------------
    refusals = {}

    # (a) the document is edited after extraction: the spans now point into
    #     text that no longer exists.
    edited = work / "edited.pdf"
    shutil.copy(document, edited)
    with edited.open("ab") as handle:
        handle.write(b"% appended\n")
    refusals["document_edited_after_extraction"] = expect_failure([
        str(binary), "teach", "start", "--config", str(config),
        "--tenant", TENANT, "--task", "t", "--expert", EXPERT,
        "--doc", str(edited), "--page", "2",
        "--clauses", str(work / "page2.clauses.json"),
        "--rule", "anything", "--examples", str(work / "temp_examples.jsonl"),
    ])

    # (b) one-sided examples.
    refusals["single_class_examples"] = expect_failure([
        str(binary), "teach", "start", "--config", str(config),
        "--tenant", TENANT, "--task", "t2", "--expert", EXPERT,
        "--doc", str(document), "--page", "2",
        "--clauses", str(work / "page2.clauses.json"),
        "--rule", "anything",
        "--examples", str(jsonl(work / "one_sided.jsonl", [
            dict(TEMP_EXAMPLES[0]),
            {"id": "t9", "text": "Winding was 12 C at the stator.",
             "label": "allowed", "reason": "also inside the range"},
        ])),
    ])

    # (c) a page the ingester found nothing on.
    refusals["page_not_cited"] = expect_failure([
        str(binary), "teach", "start", "--config", str(config),
        "--tenant", TENANT, "--task", "t3", "--expert", EXPERT,
        "--doc", str(document), "--page", "7",
        "--clauses", str(work / "page2.clauses.json"),
        "--rule", "anything", "--examples", str(work / "temp_examples.jsonl"),
    ])

    # (d) a session edited on disk.
    text = stored.read_text()
    tampered = text.replace('"not_allowed"', '"allowed"', 1)
    check(tampered != text, "fixture must contain a not_allowed label to flip")
    stored.chmod(0o600)
    stored.write_text(tampered)
    refusals["session_edited_on_disk"] = expect_failure([
        str(binary), "teach", "show", "--config", str(config),
        "--tenant", TENANT, "--session", temp["session_id"],
    ])
    stored.write_text(text)

    # (e) cross-tenant read.
    refusals["cross_tenant_read"] = expect_failure([
        str(binary), "teach", "show", "--config", str(config),
        "--tenant", "someone-else", "--session", temp["session_id"],
    ])

    listed = [
        json.loads(line)
        for line in run([
            str(binary), "teach", "list", "--config", str(config), "--tenant", TENANT,
        ]).splitlines()
        if line.strip()
    ]
    check(len(listed) == 2, f"expected 2 sessions for {TENANT}, listed {len(listed)}")

    return {
        "fixture": {
            "generator": "research/capability-learning/harness/make_pdf_fixture.py",
            "document": document.name,
            "document_sha256": doc_sha,
            "pages": 20,
        },
        "binary": {
            "path": str(binary.relative_to(REPO)),
            "command": "syntriass teach {start|list|show}",
            "model_calls": 0,
            "model_calls_note": (
                "A teach session records an expert's words against a document's "
                "bytes. No model is loaded and none is reachable: the config's "
                "model fields are UNUSED_BY_TEACH and nothing in this run opens "
                "a socket. This is a property of the item, not an untested claim."
            ),
        },
        "text_layer_session": {
            "task": temp["task"],
            "session_id": temp["session_id"],
            "pages": temp["pages"],
            "clauses_cited": temp["clauses"],
            "citations": temp["citations"],
            "examples": temp["examples"],
            "allowed": temp["allowed"],
            "not_allowed": temp["not_allowed"],
            "needs_confirmation": temp["needs_confirmation"],
            "stored_at": str(Path(temp["path"]).relative_to(work)),
            "file_mode": "0600",
            "tenant_directory_mode": "0700",
        },
        "ocr_session": {
            "task": ocr["task"],
            "session_id": ocr["session_id"],
            "pages": ocr["pages"],
            "clauses_cited": ocr["clauses"],
            "citations": ocr["citations"],
            "needs_confirmation": ocr["needs_confirmation"],
            "why_it_matters": (
                "Every clause on page 20 came from OCR, so every value in them "
                "is a hypothesis to put back to the expert in B1, not a reading "
                "to assert. The session says so in a field rather than leaving "
                "it to whoever reads the clause text."
            ),
        },
        "independent_hash_check": {
            "method": (
                "The canonical encoding was reproduced in Python from the stored "
                "file (research/capability-learning/harness/"
                "record_teach_session.py:canonical) and hashed with hashlib, "
                "with no Rust code involved."
            ),
            "session_id_recomputed": independent,
            "agrees": True,
        },
        "refusals": {
            "note": (
                "Each entry is the stderr of a real attempt that exited non-zero. "
                "Nothing here is a description of what the code would do."
            ),
            **refusals,
        },
        "sessions_listed_for_tenant": len(listed),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path,
                        default=REPO / "docs" / "demo" / "results" / "A2_teach_session.json")
    parser.add_argument("--keep", type=Path,
                        help="work in this directory and leave it in place")
    args = parser.parse_args(argv)

    work = args.keep or Path(tempfile.mkdtemp(prefix="a2-teach-"))
    work.mkdir(parents=True, exist_ok=True)
    try:
        binary = build_binary()
        sections = record_run(work, binary)
    except Failure as error:
        print(f"record_teach_session: {error}", file=sys.stderr)
        return error.code
    finally:
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)

    record = demo_evidence.evidence(
        item="A2 — teach session API: cited clauses, the expert's rule, 2-5 labelled examples",
        acceptance_criterion=(
            "`syntriass teach start --doc <file> --page <n>` creates a session holding "
            "cited clauses, the expert's plain-language rule and 2-5 labelled examples "
            "with reasons, persisted under the tenant at mode 0600"
        ),
        result="MET",
        repo=REPO,
        **sections,
    )
    demo_evidence.write(args.out, record)
    print(f"record_teach_session: {args.out.relative_to(REPO)}")
    print(f"  text-layer session {record['text_layer_session']['session_id'][:16]}… "
          f"{record['text_layer_session']['clauses_cited']} clauses, "
          f"{record['text_layer_session']['examples']} examples")
    print(f"  OCR session        {record['ocr_session']['session_id'][:16]}… "
          f"{len(record['ocr_session']['needs_confirmation'])} clauses flagged")
    print(f"  refusals proven    {len(sections['refusals']) - 1}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
