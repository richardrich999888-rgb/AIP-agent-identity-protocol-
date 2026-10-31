//! `syntriass` — offline intelligence runtime CLI.
//!
//! ```text
//! syntriass ingest  --config CFG FILE...          add documents (tenant|doc_id|class|title header)
//! syntriass ask     --config CFG TEXT             one request as the calling OS user (uid map)
//! syntriass serve   --config CFG --eval           JSONL requests on stdin → JSONL responses
//!                                                 EVALUATION HARNESS: principals come from the
//!                                                 input lines, not from authentication
//! syntriass audit-verify --config CFG             verify the audit hash chain
//! ```
//!
//! Run inside a network namespace with only loopback (see
//! `research/compute-memory/bench/offline.sh`); the runtime itself opens only
//! loopback connections to the model server it started.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Value};
use syntriass_runtime::adapters::meter::ProcMeter;
use syntriass_runtime::adapters::pool::{Pool, TierSlot};
use syntriass_runtime::adapters::sidecar::Sidecar;
use syntriass_runtime::adapters::store::FileStore;
use syntriass_runtime::adapters::supervisor::Profile;
use syntriass_runtime::app::{verify_audit_chain, Config, Runtime};
use vanian_sovereign::adapters::sqlite_corpus::SqliteCorpus;
use vanian_sovereign::domain::corpus::{Classification, Document, Ident, Principal};
use vanian_sovereign::ports::CorpusStore;

#[derive(Deserialize)]
struct ModelRef {
    path: PathBuf,
    sha256: String,
}

#[derive(Deserialize)]
struct FileConfig {
    state: PathBuf,
    policy_version: String,
    security_domain: String,
    rag_k: usize,
    /// approver id → public key hex
    approvers: BTreeMap<String, String>,
    python: PathBuf,
    sidecar_script: PathBuf,
    llama_server: PathBuf,
    /// "memory" | "balanced" | "speed" | "none"
    profile: String,
    q4: ModelRef,
    q8: ModelRef,
    port: u16,
}

fn die(m: impl std::fmt::Display) -> ! {
    eprintln!("syntriass: {m}");
    std::process::exit(2)
}

fn load_cfg(p: &Path) -> FileConfig {
    let b = std::fs::read(p).unwrap_or_else(|e| die(format!("{}: {e}", p.display())));
    serde_json::from_slice(&b).unwrap_or_else(|e| die(format!("config: {e}")))
}

fn profile(c: &FileConfig) -> Option<Profile> {
    match c.profile.as_str() {
        "memory" => Some(Profile::memory(&c.q4.path, &c.q4.sha256)),
        "balanced" => Some(Profile::balanced(&c.q4.path, &c.q4.sha256)),
        "speed" => Some(Profile::speed(&c.q8.path, &c.q8.sha256)),
        "none" => None,
        other => die(format!("unknown profile {other}")),
    }
}

fn parse_doc(text: &str, file: &str) -> Document {
    let (head, body) = text
        .split_once('\n')
        .unwrap_or_else(|| die(format!("{file}: missing header")));
    let f: Vec<&str> = head.splitn(4, '|').collect();
    if f.len() != 4 {
        die(format!("{file}: header must be tenant|doc_id|class|title"));
    }
    Document {
        tenant: Ident::new(f[0].trim()).unwrap_or_else(|e| die(e)),
        doc_id: Ident::new(f[1].trim()).unwrap_or_else(|e| die(e)),
        classification: Classification::parse(f[2].trim()).unwrap_or_else(|e| die(e)),
        title: f[3].trim().into(),
        body: body.into(),
    }
}

fn principal_from(v: &Value) -> Result<Principal, String> {
    let t = v["tenant"].as_str().ok_or("principal.tenant")?;
    let c = v["clearance"].as_str().ok_or("principal.clearance")?;
    Ok(Principal {
        tenant: Ident::new(t).map_err(|e| e.to_string())?,
        clearance: Classification::parse(c).map_err(|e| e.to_string())?,
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    let cfg_path = args
        .iter()
        .position(|a| a == "--config")
        .and_then(|i| args.get(i + 1))
        .unwrap_or_else(|| die("--config required"));
    let c = load_cfg(Path::new(cfg_path));
    std::fs::create_dir_all(&c.state).unwrap_or_else(|e| die(e));
    let mut corpus = SqliteCorpus::open(&c.state.join("corpus.db")).unwrap_or_else(|e| die(e));
    let audit = c.state.join("audit.jsonl");
    match cmd {
        "ingest" => {
            for f in args
                .iter()
                .skip(2)
                .filter(|a| !a.starts_with("--") && *a != cfg_path)
            {
                let t = std::fs::read_to_string(f).unwrap_or_else(|e| die(format!("{f}: {e}")));
                let d = parse_doc(&t, f);
                let o = corpus.ingest(&d).unwrap_or_else(|e| die(e));
                println!(
                    "{}",
                    json!({"doc": d.doc_id.as_str(), "tenant": d.tenant.as_str(), "outcome": format!("{o:?}")})
                );
            }
        }
        "audit-verify" => match verify_audit_chain(&audit) {
            Ok(n) => println!("{}", json!({"records": n, "chain": "ok"})),
            Err(e) => die(format!("audit chain broken: {e}")),
        },
        "ask" | "serve" => {
            let eval = args.iter().any(|a| a == "--eval");
            if cmd == "serve" && !eval {
                die("serve requires --eval (evaluation harness); use `ask` for authenticated requests");
            }
            let meter = ProcMeter::default();
            let (sidecar, health) =
                Sidecar::start(&c.python, &c.sidecar_script, &c.state.join("sidecar.log"))
                    .unwrap_or_else(|e| die(e));
            meter.track("sidecar", sidecar.pid());
            let work = c.state.join("work");
            std::fs::create_dir_all(&work).unwrap_or_else(|e| die(e));
            let pool = Pool {
                binary: c.llama_server.clone(),
                workdir: work,
                small: profile(&c).map(|p| TierSlot::new(p, c.port)),
                large: None,
                meter: &meter,
            };
            let store = FileStore::open(&c.state.join("capabilities")).unwrap_or_else(|e| die(e));
            let approvers = c
                .approvers
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        hex::decode(v).unwrap_or_else(|e| die(format!("approver key {k}: {e}"))),
                    )
                })
                .collect();
            let rt_cfg = Config {
                policy_version: c.policy_version.clone(),
                security_domain: c.security_domain.clone(),
                audit_log: audit.clone(),
                rag_k: c.rag_k,
                approvers,
            };
            let rt = Runtime::new(rt_cfg, &corpus, &sidecar, &pool, &store, &meter);
            eprintln!("{}", json!({"sidecar": health, "profile": c.profile}));
            if cmd == "ask" {
                let text = args
                    .iter()
                    .skip(2)
                    .filter(|a| !a.starts_with("--") && *a != cfg_path)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" ");
                let uid = vanian_sovereign::app::current_uid().unwrap_or_else(|e| die(e));
                let p = vanian_sovereign::app::principal_for_uid(&c.state, uid)
                    .unwrap_or_else(|e| die(e));
                let r = rt.handle(&p, &text).unwrap_or_else(|e| die(e));
                println!("{}", serde_json::to_string(&r).unwrap_or_default());
            } else {
                let stdin = std::io::stdin();
                let mut out = std::io::stdout().lock();
                for line in stdin.lock().lines() {
                    let line = line.unwrap_or_else(|e| die(e));
                    if line.trim().is_empty() {
                        continue;
                    }
                    let reply = (|| -> Result<Value, String> {
                        let v: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
                        let p = principal_from(&v["principal"])?;
                        let text = v["text"].as_str().ok_or("text")?;
                        let r = match v["capability"].as_str() {
                            Some(id) => rt.invoke(&p, id, text),
                            None => rt.handle(&p, text),
                        }
                        .map_err(|e| e.to_string())?;
                        Ok(json!({"id": v["id"], "response": r}))
                    })()
                    .unwrap_or_else(|e| json!({"error": e}));
                    writeln!(out, "{reply}").unwrap_or_else(|e| die(e));
                    out.flush().unwrap_or_else(|e| die(e));
                }
            }
            pool.shutdown().unwrap_or_else(|e| die(e));
        }
        _ => die("usage: syntriass {ingest|ask|serve --eval|audit-verify} --config CFG"),
    }
}
