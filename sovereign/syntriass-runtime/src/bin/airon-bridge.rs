//! Owner-local JSON contract for AIRON. No proprietary source is copied to AIRON.
//! The OS account and its private configuration are the trust root. This is not
//! a network authentication service. Generative inference is deliberately absent.
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::{self, Read},
    path::{Path, PathBuf},
};
use syntriass_runtime::{
    adapters::{meter::ProcMeter, store::FileStore},
    app::{verify_audit_chain, Config, ModelProvider, Runtime},
    capability::authority::ApprovalPolicy,
    controller::Tier,
    domain::maintenance::Reading,
    ports::{Interpretation, InterpreterPort, ScopedGenerator, SlmRequest},
};
use vanian_sovereign::{
    adapters::sqlite_corpus::SqliteCorpus,
    domain::corpus::{Classification, Document, Ident, Principal},
    ports::{CorpusStore, PortError, PortErrorKind},
};

#[derive(Deserialize)]
struct Settings {
    state: PathBuf,
    policy_version: String,
    security_domain: String,
    approvers: BTreeMap<String, String>,
    approval_policy: Option<ApprovalPolicy>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    tenant: String,
    clearance: String,
    can_ingest: bool,
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Search {
        query: String,
        limit: usize,
    },
    Ingest {
        doc_id: String,
        title: String,
        classification: String,
        body: String,
    },
    Delete {
        doc_id: String,
    },
    Execute {
        capability_id: String,
        text: String,
    },
    Snapshot {},
}

// An explicit disabled port is fail-closed, never a synthetic model response.
struct Disabled;
fn unavailable() -> PortError {
    PortError::new(
        PortErrorKind::Inference,
        "generative/interpretation path unavailable in deterministic bridge",
    )
}
impl InterpreterPort for Disabled {
    fn interpret(&self, _: &str) -> Result<Interpretation, PortError> {
        Err(unavailable())
    }
    fn slm_request(&self, _: &str) -> Result<SlmRequest, PortError> {
        Err(unavailable())
    }
    fn slm_parse(&self, _: &str) -> Result<Option<Vec<Reading>>, PortError> {
        Err(unavailable())
    }
}
impl ModelProvider for Disabled {
    fn configured(&self, _: Tier) -> bool {
        false
    }
    fn with<'a>(
        &'a self,
        _: Tier,
        _: &mut dyn FnMut(&dyn ScopedGenerator) -> Result<(), PortError>,
    ) -> Result<f64, PortError> {
        Err(unavailable())
    }
    fn model_sha256(&self, _: Tier) -> Option<String> {
        None
    }
}

fn private_file(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let meta = path.symlink_metadata()?;
    if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
        return Err("configuration must be a regular owner-only file".into());
    }
    Ok(std::fs::read(path)?)
}

fn run() -> Result<Value, Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: airon-bridge CONFIG IDENTITY_FILE".into());
    }
    let cfg: Settings = serde_json::from_slice(&private_file(Path::new(&args[1]))?)?;
    let who: Identity = serde_json::from_slice(&private_file(Path::new(&args[2]))?)?;
    let p = Principal {
        tenant: Ident::new(&who.tenant)?,
        clearance: Classification::parse(&who.clearance)?,
    };
    let mut bytes = Vec::new();
    io::stdin().take(1_100_001).read_to_end(&mut bytes)?;
    if bytes.len() > 1_100_000 {
        return Err("request exceeds contract size".into());
    }
    let req: Request = serde_json::from_slice(&bytes)?;
    let mut corpus = SqliteCorpus::open(&cfg.state.join("corpus.db"))?;
    let result = match req {
        Request::Ingest {
            doc_id,
            title,
            classification,
            body,
        } => {
            let classification = Classification::parse(&classification)?;
            if !who.can_ingest || classification.rank() > p.clearance.rank() {
                return Err("ingestion outside configured authority".into());
            }
            let doc = Document {
                tenant: p.tenant.clone(),
                doc_id: Ident::new(&doc_id)?,
                title,
                classification,
                body,
            };
            json!({"outcome":format!("{:?}", corpus.ingest(&doc)?)})
        }
        Request::Search { query, limit } => {
            if query.len() > 4096 || limit == 0 || limit > 20 {
                return Err("search bounds exceeded".into());
            }
            let hits: Vec<Value> = corpus.search(&p, &query, limit)?.into_iter().map(|h| json!({
                "doc_id":h.doc_id.as_str(), "title":h.title, "classification":h.classification,
                "text":h.text, "bm25":h.bm25,
                "body_sha256":corpus.document_digest(&p, h.doc_id.as_str()).ok().flatten().map(hex::encode)
            })).collect();
            json!({"hits":hits, "snapshot_sha256":hex::encode(corpus.snapshot_digest(&p)?)})
        }
        Request::Delete { doc_id } => {
            if !who.can_ingest {
                return Err("deletion outside configured authority".into());
            }
            json!({"deleted":corpus.delete(&p, &Ident::new(&doc_id)?)?})
        }
        Request::Snapshot {} => json!({"sha256":hex::encode(corpus.snapshot_digest(&p)?)}),
        Request::Execute {
            capability_id,
            text,
        } => {
            if text.len() > 4096 {
                return Err("execution input exceeds bound".into());
            }
            let audit = cfg.state.join("audit.jsonl");
            if audit.exists() {
                verify_audit_chain(&audit).map_err(|e| format!("audit integrity: {e}"))?;
            }
            let approvers = cfg
                .approvers
                .into_iter()
                .map(|(k, v)| Ok((k, hex::decode(v)?)))
                .collect::<Result<_, hex::FromHexError>>()?;
            let store = FileStore::open(&cfg.state.join("capabilities"))?;
            let meter = ProcMeter::default();
            let rt = Runtime::new(
                Config {
                    policy_version: cfg.policy_version,
                    security_domain: cfg.security_domain,
                    audit_log: audit,
                    rag_k: 3,
                    approvers,
                    approval_policy: cfg.approval_policy,
                    instruments: BTreeMap::new(),
                },
                &corpus,
                &Disabled,
                &Disabled,
                &store,
                &meter,
            );
            serde_json::to_value(rt.invoke(&p, &capability_id, &text)?)?
        }
    };
    Ok(
        json!({"schema":"syntriass-airon-bridge/v1", "result":result, "independent_execution":"CANNOT_PROVE"}),
    )
}

fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("airon-bridge: {error}");
            std::process::exit(2);
        }
    }
}
