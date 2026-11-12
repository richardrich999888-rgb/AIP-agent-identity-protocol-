#!/usr/bin/env python3
"""Recompute an answered teaching session's signed-suite scoreboard offline.

This diagnostic regenerates the draft/questions from a runtime-verified stored
session; it never accepts a supplied IR, scoreboard or pass label. The existing
compiler and native validator run in disposable state. Original lifecycle state
is not written. No signing key, model, approval or activation is used.

The first integration supports the existing synthetic UTF-8 TXT corpus format.
Session examples use binary labels, whereas capabilities have multiple outcomes;
their agreement remains NOT_MEASURED until an expert-reviewed mapping exists.
Question links identify actual review candidates, not proven causes of failure.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time

import apply_answers as B
import draft_from_session as D
import ingest_documents as I
import question_generator as Q
from ir_compiler import compile_ir


class Refused(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field: " + key)
        result[key] = value
    return result


def parse(raw):
    require(len(raw) <= 4 * 1024 * 1024, "input exceeds 4 MiB")
    def invalid(value):
        raise Refused("non-finite JSON number: " + value)
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)
    # JSON numeric exponents can overflow even without a NaN/Infinity token.
    json.dumps(value, allow_nan=False)
    return value


def write(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n")


def link_questions(board, questions, answered):
    """Resolve field suggestions to exact regenerated qids, without diagnosis."""
    edits = {}
    for edit in answered["edits"]:
        edits.setdefault(edit["qid"], []).append(edit)
    owners = {e["path"]: e["sentence"] for e in answered["elements"] if e["path"]}
    for row in board["cases"]:
        fields = {q["field_path"] for q in row["review_questions"]}
        row["session_questions"] = []
        if row["passed"] is not False:
            continue
        for q in questions["questions"]:
            if q["field_path"] not in fields:
                continue
            # Rule order is preserved by the compiler. Other field families
            # may describe an earlier missing guard, so keep all candidates.
            owner = owners.get(row["fired_step"]) if (row["fired_step"] or "").startswith("rules[") else None
            relation = "fired_rule_author" if owner == q["clause"] and q["field_path"].startswith("rules[]") else "field_review_candidate"
            row["session_questions"].append({
                "qid": q["qid"], "question": q["question"], "field_path": q["field_path"],
                "citation": q["citation"], "quote": q["quote"], "relation": relation,
                "edits": edits.get(q["qid"], []), "root_cause_established": False,
            })
        row["unlinked_review_fields"] = sorted(fields - {q["field_path"] for q in row["session_questions"]})
    return board


def checked_rows(board, suite):
    """A success exit alone cannot turn omitted or substituted rows into passes."""
    rows = board["cases"]
    require(len(rows) == len(suite["cases"]), "native scoreboard row count mismatch")
    for index, (row, case) in enumerate(zip(rows, suite["cases"])):
        require(row["origin"] == "suite" and row["index"] == index, "native scoreboard row identity mismatch")
        for field, expected in (("id", case["id"]), ("input", case["text"]),
                                ("expected", case["expected"]), ("counterexample", case["counterexample"])):
            require(row[field] == expected, "native scoreboard changed " + field)
    require(board["activation_performed"] is False and board["stored_executable"] is False,
            "diagnostic must not activate a capability")
    require(board["stored_state"] == "PROPOSED", "diagnostic changed lifecycle state")


def score(*, binary, config, tenant, session_id, session_task, task, answers, document, suite, out):
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {"schema": "syntriass.teach-session-scoreboard/v1", "status": "INCOMPLETE",
              "activation_performed": False, "approval_performed": False, "model_calls": 0,
              "expert_identity_verified": False, "evidence_kind": "unsigned diagnostic; signed expert suite retained",
              "commands": [], "examples": {"status": "NOT_MEASURED",
                  "reason": "Binary session labels need an expert-reviewed capability-outcome mapping."}}
    started = time.monotonic()

    def run(name, args, expected=(0,)):
        command = [str(binary), *map(str, args)]
        entry = {"name": name, "command": command}
        report["commands"].append(entry)
        t0 = time.monotonic()
        result = subprocess.run(command, capture_output=True, timeout=120)
        entry.update(exit_status=result.returncode, wall_seconds=time.monotonic() - t0)
        (out / (name + ".stdout")).write_bytes(result.stdout)
        (out / (name + ".stderr")).write_bytes(result.stderr)
        require(result.returncode in expected, name + " refused; inspect retained stdout/stderr")
        return result

    try:
        binary = binary.resolve(strict=True)
        config = config.resolve(strict=True)
        cfg = parse(config.read_bytes())
        snapshots = {"task.json": task.read_bytes(), "answers.json": answers.read_bytes(),
                     "suite.json": suite.read_bytes()}
        values = {name: parse(raw) for name, raw in snapshots.items()}
        spec, answers_doc, signed_suite = (values[n] for n in ("task.json", "answers.json", "suite.json"))
        for name, raw in snapshots.items():
            (out / name).write_bytes(raw)
        source = document.read_bytes()
        require(len(source) <= 4 * 1024 * 1024, "source exceeds 4 MiB")
        require(document.suffix.lower() == ".txt", "this integration requires a UTF-8 TXT corpus document")
        source_text = source.decode("utf-8")
        require(spec["tenant"] == tenant, "task tenant mismatch")
        require(cfg["policy_version"] == spec["policy_version"], "task policy mismatch")
        require(cfg["security_domain"] == spec["domain"], "task security domain mismatch")
        require(document.name == Path(spec["doc_file"]).name, "task source filename mismatch")
        header, body = source_text.split("\n", 1)
        parts = header.split("|", 3)
        require(len(parts) == 4 and parts[0].strip() == tenant and parts[1].strip() == spec["doc_id"],
                "source tenant/document identity mismatch")
        require(signed_suite["tenant"] == tenant, "suite tenant mismatch")
        require(signed_suite["task"] == spec["intended_task"], "suite task mismatch")
        trust = cfg["experts"].get(signed_suite["expert_id"])
        require(trust is not None, "suite expert is not configured as trusted")
        write(out / "expert-public.json", {signed_suite["expert_id"]: trust})
        session = parse(run("session", ["teach", "show", "--config", config, "--tenant", tenant,
                                        "--session", session_id]).stdout)
        require(session["tenant"] == tenant and session["session_id"] == session_id, "stored session identity mismatch")
        require(session["task"] == session_task, "stored session task mismatch")
        require(session["document"] == document.name and session["document_sha256"] == sha(source),
                "source changed since the teaching session")
        source_dir = out / "source"
        source_dir.mkdir()
        source_path = source_dir / document.name
        source_path.write_bytes(source)
        clauses = {(c.page, c.index): asdict(c) for c in I.ingest(source_path, pages=session["pages"])}
        seen = set()
        for clause in session["clauses"]:
            key = clause["page"], clause["index"]
            require(key not in seen and clauses.get(key) == clause, "cited clause does not match the source span")
            seen.add(key)
        require(bool(seen), "session cites no clauses")
        draft = D.draft(session, spec)
        questions = Q.generate(draft, spec)
        answered = B.apply(draft, spec, answers_doc)
        for name, value in (("draft", draft), ("questions", questions), ("answered", answered)):
            write(out / (name + ".json"), value)
        require(answered["status"] == "COMPILES" and not answered["unanswered"]
                and not answered["numbers_without_cited_provenance"], "teaching answers are incomplete or unsupported")
        require(signed_suite["expert_id"] not in (session["expert_id"], answered["author"]),
                "suite evaluator must differ from the session and answer authors")
        cap = compile_ir(answered["ir"], {**spec, "proposed_by": answered["author"], "demo_ids": []}).capability
        write(out / "candidate.json", cap)
        with tempfile.TemporaryDirectory(prefix="syntriass-session-score-") as temp:
            scratch = Path(temp)
            # No keys are generated or copied. These commands cannot invoke a
            # model; the profile is also explicitly disabled in scratch state.
            local_cfg = {**cfg, "state": str(scratch / "state"), "profile": "none", "approvers": {}}
            local_config = scratch / "config.json"
            write(local_config, local_cfg)
            run("ingest", ["ingest", "--config", local_config, source_path])
            proposal = parse(run("propose", ["cap-propose", "--config", local_config,
                                             "--file", out / "candidate.json"]).stdout)
            records = list((scratch / "state/capabilities").glob("*.json"))
            require(len(records) == 1, "diagnostic must propose exactly one scratch capability")
            record_raw = records[0].read_bytes()
            record = parse(record_raw)
            require(record["capability"]["dependencies"]["knowledge"] == {spec["doc_id"]: sha(body.encode())},
                    "runtime source binding differs from the cited source")
            result = run("native-scoreboard", ["cap-scoreboard", "--config", local_config,
                         "--hash", proposal["hash"], "--suite", out / "suite.json"], (0, 3))
            require(records[0].read_bytes() == record_raw, "scoreboard changed the proposed record")
            (out / "proposed-record.json").write_bytes(record_raw)
        board = parse(result.stdout)
        checked_rows(board, signed_suite)
        require(board["validation"]["passed"] == (result.returncode == 0), "native verdict/exit mismatch")
        write(out / "scoreboard.json", link_questions(board, questions, answered))
        report.update(status="PASS_SIGNED_SUITE" if result.returncode == 0 else "REJECTED_BY_SUITE",
                      exit_status=result.returncode, validation=board["validation"],
                      session_id=session_id, session_task=session_task, tenant=tenant,
                      source_sha256=sha(source), binary_sha256=sha(binary.read_bytes()),
                      input_sha256={name: sha(raw) for name, raw in snapshots.items()},
                      draft_sha256=B.draft_digest(draft), questions_sha256=B.questions_digest(questions),
                      capability_hash=proposal["hash"], original_lifecycle_written=False,
                      limitation="Same-host diagnostic with configured public trust. No authenticated expert approval, "
                                 "example-label mapping, PDF/DOCX scoring, UI or full teaching acceptance.")
    except (OSError, ValueError, KeyError, TypeError, I.IngestError, subprocess.SubprocessError) as error:
        report.update(status="REFUSED", exit_status=2, error=str(error))
        if isinstance(error, B.AnswersRefused):
            report["answer_errors"] = error.errors
    finally:
        report["wall_seconds"] = time.monotonic() - started
        write(out / "result.json", report)
        files = sorted(p for p in out.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
        (out / "SHA256SUMS").write_text("".join(f"{sha(p.read_bytes())}  {p.relative_to(out)}\n" for p in files))
    return report


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "config", "task", "answers", "document", "suite", "out"):
        ap.add_argument("--" + name, required=True, type=Path)
    for name in ("tenant", "session", "session-task"):
        ap.add_argument("--" + name, required=True)
    args = vars(ap.parse_args())
    args["session_id"] = args.pop("session")
    try:
        report = score(**args)
    except OSError as error:
        ap.exit(2, f"score_teaching_session: {error}\n")
    print(json.dumps({k: report[k] for k in ("status", "exit_status", "examples")}, indent=2))
    return report["exit_status"]


if __name__ == "__main__":
    raise SystemExit(main())
