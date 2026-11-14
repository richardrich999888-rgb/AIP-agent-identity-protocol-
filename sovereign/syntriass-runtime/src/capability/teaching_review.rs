//! Verify pinned review bytes and replay native gates before issuing approval.
//! The local policy, stored session and corpus are trusted installation inputs.
use super::{
    artifact::Capability,
    lifecycle::Record,
    suite::ExpertSuite,
    validate::{label, validate, ValidationReport},
};
use crate::{adapters::teach_store::TeachStore, domain::teach::TeachSession, learning};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Component, Path};
use vanian_sovereign::adapters::sqlite_corpus::SqliteCorpus;

pub struct VerifiedReview {
    digest: String,
    capability_hash: String,
    validation_report_hash: String,
}
impl VerifiedReview {
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn capability_hash(&self) -> &str {
        &self.capability_hash
    }
    pub fn validation_report_hash(&self) -> &str {
        &self.validation_report_hash
    }
}
fn require(ok: bool, reason: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(reason.into())
    }
}
fn sha(raw: &[u8]) -> String {
    hex::encode(aip_crypto::sha256(raw))
}
fn parse<T: DeserializeOwned>(raw: &[u8]) -> Result<T, String> {
    serde_json::from_slice(raw).map_err(|e| e.to_string())
}
fn read(root: &Path, name: &str) -> Result<Vec<u8>, String> {
    let mut path = root.to_path_buf();
    for part in Path::new(name).components() {
        let Component::Normal(part) = part else {
            return Err("unsafe review path".into());
        };
        path.push(part);
        let meta = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        require(
            !meta.file_type().is_symlink(),
            "linked review input refused",
        )?;
    }
    require(
        std::fs::metadata(&path).map_err(|e| e.to_string())?.len() <= 4 * 1024 * 1024,
        "review input too large",
    )?;
    std::fs::read(path).map_err(|e| e.to_string())
}
fn same_report(mut a: ValidationReport, mut b: ValidationReport) -> bool {
    // Timing is measured per replay, not a correctness field. Everything else must match.
    a.wall_micros = 0;
    b.wall_micros = 0;
    a == b
}

pub fn verify(
    root: &Path,
    pin: &str,
    record: &Record,
    experts: &BTreeMap<String, Vec<u8>>,
    corpus: &SqliteCorpus,
    sessions: &Path,
) -> Result<VerifiedReview, String> {
    let raw = read(root, "teaching-review.json")?;
    let mut signed = b"syntriass.teaching-review/v1\n".to_vec();
    signed.extend(&raw);
    require(sha(&signed) == pin, "review commitment mismatch")?;
    let review: Value = parse(&raw)?;
    require(
        serde_json::to_vec(&review).map_err(|e| e.to_string())? == raw,
        "review must be canonical JSON",
    )?;
    require(
        review["schema"] == "syntriass.teaching-review/v1"
            && review["authority"] == "UNSIGNED_REVIEW_REQUIRES_EXPERT_APPROVAL",
        "unsupported review format",
    )?;
    let files = review["files"].as_object().ok_or("missing review files")?;
    let source = review["source_file"]
        .as_str()
        .ok_or("missing source file")?;
    require(
        source.starts_with("source/") && Path::new(source).components().count() == 2,
        "invalid source path",
    )?;
    let names = [
        "session.stdout",
        "task.json",
        "answers.json",
        "suite.json",
        "example-map.json",
        "expert-public.json",
        "draft.json",
        "questions.json",
        "answered.json",
        "proposed-record.json",
        "scoreboard.json",
        "bound-capability.json",
        "example-cases.jsonl",
        "native-examples.stdout",
        "native-scoreboard.stdout",
        source,
    ];
    require(
        files.len() == names.len() && names.iter().all(|n| files.contains_key(*n)),
        "incomplete review inventory",
    )?;
    let mut snapshot = BTreeMap::new();
    for name in names {
        let bytes = read(root, name)?;
        require(
            files[name].as_str() == Some(sha(&bytes).as_str()),
            "review input changed",
        )?;
        snapshot.insert(name, bytes);
    }
    let session: TeachSession = parse(&snapshot["session.stdout"])?;
    require(session.intact(), "session content changed")?;
    let stored = TeachStore::open(sessions)
        .map_err(|e| e.to_string())?
        .get(&session.tenant, &session.session_id)
        .map_err(|e| e.to_string())?;
    require(
        stored == session
            && review["session_id"] == session.session_id
            && review["session_task"] == session.task,
        "stored session mismatch",
    )?;
    let cap: Capability = parse(&snapshot["bound-capability.json"])?;
    let proposed: Record = parse(&snapshot["proposed-record.json"])?;
    require(
        proposed.capability == cap
            && proposed.capability_hash == cap.content_hash()
            && proposed.state == super::lifecycle::State::Proposed
            && proposed.approval.is_none(),
        "review proposed record disagrees with capability",
    )?;
    require(
        cap == record.capability
            && cap.content_hash() == record.capability_hash
            && review["capability_hash"] == record.capability_hash,
        "review capability mismatch",
    )?;
    require(
        review["tenant"] == cap.required.tenant
            && session.tenant == cap.required.tenant
            && review["capability_id"] == cap.id
            && review["capability_version"] == cap.version
            && review["required"]
                == serde_json::to_value(&cap.required).map_err(|e| e.to_string())?,
        "review scope mismatch",
    )?;
    require(
        source == format!("source/{}", session.document)
            && sha(&snapshot[source]) == session.document_sha256
            && review["source_sha256"] == session.document_sha256,
        "review source mismatch",
    )?;
    let text = std::str::from_utf8(&snapshot[source]).map_err(|e| e.to_string())?;
    let (header, body) = text.split_once('\n').ok_or("invalid source document")?;
    let parts: Vec<_> = header.splitn(4, '|').collect();
    require(
        parts.len() == 4
            && parts[0].trim() == cap.required.tenant
            && cap.dependencies.knowledge.len() == 1
            && cap.dependencies.knowledge.get(parts[1].trim()) == Some(&sha(body.as_bytes())),
        "source dependency mismatch",
    )?;
    let mut bound = cap.clone();
    learning::bind_evidence(&mut bound, corpus).map_err(|e| e.to_string())?;
    require(bound == cap, "current corpus differs from review")?;
    let suite: ExpertSuite = parse(&snapshot["suite.json"])?;
    require(
        suite.expert_id != session.expert_id && suite.expert_id != cap.proposed_by,
        "suite evaluator is not independent",
    )?;
    let key = experts
        .get(&suite.expert_id)
        .ok_or("suite expert not trusted")?;
    let public: Value = parse(&snapshot["expert-public.json"])?;
    require(
        public[&suite.expert_id] == hex::encode(key),
        "review evaluator trust changed",
    )?;
    let reader = learning::evidence_reader(&cap).map_err(|e| e.to_string())?;
    let tenant_of = |d: &str| {
        corpus
            .document_digest(&reader, d)
            .ok()
            .flatten()
            .map(|_| cap.required.tenant.clone())
    };
    let fresh = validate(&cap, &suite, key, &tenant_of);
    let reviewed: ValidationReport =
        serde_json::from_value(review["validation"].clone()).map_err(|e| e.to_string())?;
    require(
        fresh.passed
            && same_report(fresh.clone(), reviewed)
            && record
                .validation
                .as_ref()
                .is_some_and(|r| same_report(fresh.clone(), r.clone())),
        "native suite replay disagrees with review or stored validation",
    )?;
    for file in ["scoreboard.json", "native-scoreboard.stdout"] {
        let board: Value = parse(&snapshot[file])?;
        let reported: ValidationReport =
            serde_json::from_value(board["validation"].clone()).map_err(|e| e.to_string())?;
        require(
            same_report(fresh.clone(), reported),
            "retained scoreboard disagrees with replay",
        )?;
    }
    let map: Value = parse(&snapshot["example-map.json"])?;
    require(
        map["schema"] == "syntriass.teach-example-map/v1",
        "unsupported example map",
    )?;
    let bindings = &map["bindings"];
    require(
        bindings["session_id"] == session.session_id
            && bindings["capability_hash"] == record.capability_hash
            && bindings["source_sha256"] == session.document_sha256,
        "example map scope mismatch",
    )?;
    for (field, file) in [
        ("task_sha256", "task.json"),
        ("answers_sha256", "answers.json"),
        ("suite_sha256", "suite.json"),
    ] {
        require(
            bindings[field] == sha(&snapshot[file]),
            "example map input mismatch",
        )?;
    }
    require(
        map["review"]["who"] == session.expert_id || map["review"]["who"] == cap.proposed_by,
        "unknown example reviewer",
    )?;
    let outcomes = map["outcomes"]
        .as_object()
        .ok_or("missing mapped outcomes")?;
    for refusal in [
        "NOT_APPLICABLE",
        "AMBIGUOUS",
        "EVIDENCE_REQUIRED",
        cap.procedure.missing_input_outcome.as_str(),
    ] {
        require(
            outcomes.get(refusal).is_none_or(|x| x == "withheld"),
            "refusal mapped to decision",
        )?;
    }
    let compiled = cap.compile().map_err(|e| format!("{e:?}"))?;
    let rows = review["examples"]["cases"]
        .as_array()
        .ok_or("missing example cases")?;
    require(
        rows.len() == session.examples.len()
            && rows.len() >= 2
            && review["examples"]["status"] == "PASSED",
        "incomplete examples",
    )?;
    require(
        review["examples"]["passed"].as_u64() == Some(rows.len() as u64)
            && review["examples"]["total"].as_u64() == Some(rows.len() as u64)
            && review["examples"]["withheld"] == 0
            && review["examples"]["independent_suite_cases_added"] == 0,
        "example counts disagree with replay",
    )?;
    for (example, row) in session.examples.iter().zip(rows) {
        let got = label(&cap.execute(&compiled, &example.text));
        require(
            !got.starts_with("FAILED:")
                && ![
                    "NOT_APPLICABLE",
                    "AMBIGUOUS",
                    "EVIDENCE_REQUIRED",
                    cap.procedure.missing_input_outcome.as_str(),
                ]
                .contains(&got.as_str()),
            "native example withheld",
        )?;
        require(
            outcomes.get(&got).and_then(Value::as_str) == Some(example.label.as_str())
                && row["id"] == example.id
                && row["input"] == example.text
                && row["expected"] == example.label.as_str()
                && row["native_outcome"] == got
                && row["mapped_label"] == example.label.as_str()
                && row["passed"] == true,
            "native example replay failed",
        )?;
    }
    Ok(VerifiedReview {
        digest: pin.into(),
        capability_hash: record.capability_hash.clone(),
        validation_report_hash: super::lifecycle::report_hash(
            record
                .validation
                .as_ref()
                .ok_or("stored validation missing")?,
        ),
    })
}
