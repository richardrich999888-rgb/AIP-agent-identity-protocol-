//! `syntriass` — offline intelligence runtime CLI.
//!
//! ```text
//! syntriass ingest  --config CFG FILE...          add documents (tenant|doc_id|class|title header)
//! syntriass ask     --config CFG TEXT             one request as the calling OS user (uid map)
//! syntriass serve   --config CFG --eval           JSONL requests on stdin → JSONL responses
//!                                                 EVALUATION HARNESS: principals come from the
//!                                                 input lines, not from authentication
//! syntriass audit-verify --config CFG             verify the audit hash chain
//! syntriass keygen --id ID --out KEYFILE          Ed25519 key pair (file mode 0600)
//! syntriass suite-sign --key KEYFILE --cases JSONL --suite-id S --tenant T --task X --out SUITE
//! syntriass cap-propose  --config CFG --file CAP.json            → PROPOSED (evidence bound from corpus)
//! syntriass cap-validate --config CFG --hash H --suite SUITE     → VALIDATED | REJECTED (trusted experts only)
//! syntriass cap-approve  --config CFG --hash H --key KEYFILE [--consequential]
//! syntriass cap-transition --config CFG --hash H --to STATE --role ROLE --actor A --reason R
//! syntriass cap-list     --config CFG
//! syntriass cap-activate --config CFG --hash H --actor A --reason R [--supersede]   (one ACTIVE version per id)
//! syntriass cap-rollback --config CFG --to H --actor APPROVER --reason R         SUPERSEDED → ACTIVE, current → SUSPENDED
//! syntriass exp-record   --config CFG --file EXP.json      record an experience as the calling OS user (uid map)
//! syntriass cap-review   --config CFG --hash H             active capability vs verified experience (read-only)
//! syntriass cap-upgrade-check --config CFG --from H1 --to H2 --suite SUITE   regressions / fixes / scope changes
//! syntriass cap-history  --config CFG --id ID              versions, transitions, audited uses per version
//! syntriass health --config CFG [--quick]                   install/health checks; exit 1 if any fails
//!                                                           (--quick: skip model hashing, reported as unverified)
//! syntriass cap-check --file CAP.json --cases JSONL [--instruments KEYS.json]
//!                                                 dry run: compile + label each case (no state change);
//!                                                 a case may carry a signed "record" (S1)
//! syntriass record-sign --key INSTRUMENT_KEY --in RECORDS.jsonl   sign measurement records (S1)
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
use syntriass_runtime::adapters::experience_store::ExperienceLog;
use syntriass_runtime::adapters::meter::ProcMeter;
use syntriass_runtime::adapters::pool::{Pool, TierSlot};
use syntriass_runtime::adapters::sidecar::Sidecar;
use syntriass_runtime::adapters::store::FileStore;
use syntriass_runtime::adapters::supervisor::Profile;
use syntriass_runtime::app::{verify_audit_chain, Config, Runtime};
use syntriass_runtime::capability::artifact::Capability;
use syntriass_runtime::capability::artifact::Execution;
use syntriass_runtime::capability::evidence::MeasurementRecord;
use syntriass_runtime::capability::experience::Experience;
use syntriass_runtime::capability::lifecycle::{Record, Role, State};
use syntriass_runtime::capability::memory;
use syntriass_runtime::capability::suite::{ExpertSuite, SuiteCase};
use syntriass_runtime::learning;
use syntriass_runtime::ports::CapabilityStore;
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
    /// expert id → public key hex (trust anchors for validation suites)
    #[serde(default)]
    experts: BTreeMap<String, String>,
    /// instrument id → public key hex (who may sign measurement records, S1)
    #[serde(default)]
    instruments: BTreeMap<String, String>,
    python: PathBuf,
    sidecar_script: PathBuf,
    llama_server: PathBuf,
    /// "memory" | "balanced" | "speed" | "none"
    profile: String,
    q4: ModelRef,
    q8: ModelRef,
    port: u16,
    /// Optional larger model for one-step escalation (loaded on demand, port + 1).
    /// Any GGUF model the configured llama-server can run; hash-verified before load.
    #[serde(default)]
    large: Option<ModelRef>,
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

fn opt<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn req<'a>(args: &'a [String], name: &str) -> &'a str {
    opt(args, name).unwrap_or_else(|| die(format!("{name} required")))
}

#[derive(serde::Serialize, Deserialize)]
struct KeyFile {
    id: String,
    public_hex: String,
    private_hex: String,
}

fn read_key(path: &str) -> KeyFile {
    let b = std::fs::read(path).unwrap_or_else(|e| die(format!("{path}: {e}")));
    serde_json::from_slice(&b).unwrap_or_else(|e| die(format!("{path}: {e}")))
}

fn hexkey(v: &str) -> Vec<u8> {
    hex::decode(v).unwrap_or_else(|e| die(format!("key: {e}")))
}

fn keys(m: &BTreeMap<String, String>) -> BTreeMap<String, Vec<u8>> {
    m.iter().map(|(k, v)| (k.clone(), hexkey(v))).collect()
}

/// Installation health: configuration files, permissions, models (hash),
/// hardware fit for the configured profile, capability tamper state, audit
/// chain, and absence of a default route. Each verdict is a pure function in
/// `domain::health`; this function only gathers the inputs.
fn health(
    c: &FileConfig,
    audit: &Path,
    quick: bool,
) -> Vec<syntriass_runtime::domain::health::Check> {
    use std::os::unix::fs::PermissionsExt;
    use syntriass_runtime::adapters::supervisor::file_sha256;
    use syntriass_runtime::domain::health as h;
    let rd = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
    let hw = h::hardware(&rd("/proc/cpuinfo"), &rd("/proc/meminfo"));
    let mut out = vec![
        h::cpu_ok(&hw),
        h::offline(&rd("/proc/net/route"), &rd("/proc/net/ipv6_route")),
    ];
    let mode = std::fs::metadata(&c.state)
        .map(|m| m.permissions().mode())
        .unwrap_or(0o777);
    out.push(h::private_mode(mode, "state"));
    for (what, p) in [
        ("llama_server", &c.llama_server),
        ("python", &c.python),
        ("sidecar_script", &c.sidecar_script),
    ] {
        out.push(h::Check::new(
            &format!("file:{what}"),
            p.is_file(),
            p.display().to_string(),
        ));
    }
    out.push(h::Check::new(
        "corpus",
        c.state.join("corpus.db").is_file(),
        "corpus.db present and opened at startup",
    ));
    let mut models: Vec<(&str, &ModelRef)> = match c.profile.as_str() {
        "memory" | "balanced" => vec![("q4", &c.q4)],
        "speed" => vec![("q8", &c.q8)],
        _ => vec![],
    };
    if let Some(l) = &c.large {
        models.push(("large", l));
    }
    for (what, m) in models {
        let size = std::fs::metadata(&m.path).map(|x| x.len());
        match size {
            Err(e) => out.push(h::Check::new(
                &format!("model:{what}"),
                false,
                format!("{}: {e}", m.path.display()),
            )),
            Ok(n) => {
                out.push(h::memory_fits(&hw, n, what));
                if quick {
                    out.push(h::Check::new(
                        &format!("model:{what}"),
                        false,
                        "hash NOT verified (--quick)",
                    ));
                } else {
                    let ok = file_sha256(&m.path).map(|x| x == m.sha256).unwrap_or(false);
                    out.push(h::Check::new(
                        &format!("model:{what}"),
                        ok,
                        format!(
                            "sha256 {} {}",
                            if ok { "matches" } else { "MISMATCH" },
                            m.path.display()
                        ),
                    ));
                }
            }
        }
    }
    match FileStore::open(&c.state.join("capabilities")).and_then(|s| Ok((s.tampered()?, s.all()?)))
    {
        Ok((t, all)) => {
            let active = all.iter().filter(|r| r.executable()).count();
            out.push(h::Check::new(
                "capabilities",
                t.is_empty(),
                format!(
                    "{} records, {active} executable, tampered: {t:?}",
                    all.len()
                ),
            ));
        }
        Err(e) => out.push(h::Check::new("capabilities", false, e.to_string())),
    }
    out.push(match verify_audit_chain(audit) {
        Ok(n) => h::Check::new("audit_chain", true, format!("{n} records verify")),
        Err(e) if !audit.exists() => {
            h::Check::new("audit_chain", true, format!("no audit log yet ({e})"))
        }
        Err(e) => h::Check::new("audit_chain", false, e),
    });
    out
}

fn record(c: &FileConfig, hash: &str) -> Record {
    FileStore::open(&c.state.join("capabilities"))
        .and_then(|s| s.all())
        .unwrap_or_else(|e| die(e))
        .into_iter()
        .find(|r| r.capability_hash == hash)
        .unwrap_or_else(|| die(format!("no record {hash}")))
}

fn parse_enum<T: serde::de::DeserializeOwned>(v: &str) -> T {
    serde_json::from_value(Value::String(v.into())).unwrap_or_else(|e| die(format!("{v}: {e}")))
}

/// Commands that need no runtime config.
fn standalone(cmd: &str, args: &[String]) -> bool {
    match cmd {
        "keygen" => {
            let kp = aip_crypto::generate_ed25519_keypair();
            let k = KeyFile {
                id: req(args, "--id").into(),
                public_hex: hex::encode(&kp.public_key),
                private_hex: hex::encode(&kp.private_key),
            };
            let out = req(args, "--out");
            write_private(
                Path::new(out),
                &serde_json::to_vec_pretty(&k).unwrap_or_default(),
            );
            println!("{}", json!({"id": k.id, "public_hex": k.public_hex}));
            true
        }
        "suite-sign" => {
            let k = read_key(req(args, "--key"));
            let cases_path = req(args, "--cases");
            let cases: Vec<SuiteCase> = std::fs::read_to_string(cases_path)
                .unwrap_or_else(|e| die(format!("{cases_path}: {e}")))
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    let v: Value = serde_json::from_str(l).unwrap_or_else(|e| die(e));
                    let s = |f: &str| {
                        v[f].as_str()
                            .unwrap_or_else(|| die(format!("case.{f}")))
                            .to_string()
                    };
                    SuiteCase {
                        id: s("id"),
                        text: s("text"),
                        expected: s("label"),
                        counterexample: v["counterexample"].as_bool().unwrap_or(false),
                    }
                })
                .collect();
            let suite = ExpertSuite::sign(
                req(args, "--suite-id"),
                req(args, "--tenant"),
                req(args, "--task"),
                &k.id,
                cases,
                &hexkey(&k.private_hex),
            )
            .unwrap_or_else(|e| die(format!("{e:?}")));
            let out = req(args, "--out");
            std::fs::write(out, serde_json::to_vec_pretty(&suite).unwrap_or_default())
                .unwrap_or_else(|e| die(e));
            println!(
                "{}",
                json!({"suite": suite.suite_id, "hash": suite.hash(), "cases": suite.cases.len()})
            );
            true
        }
        "record-sign" => {
            // Sign unsigned measurement records (one JSON per line) with an instrument key.
            let k = read_key(req(args, "--key"));
            let input = req(args, "--in");
            for l in std::fs::read_to_string(input)
                .unwrap_or_else(|e| die(format!("{input}: {e}")))
                .lines()
                .filter(|l| !l.trim().is_empty())
            {
                let mut r: MeasurementRecord =
                    serde_json::from_str(l).unwrap_or_else(|e| die(format!("record: {e}")));
                if r.instrument_id != k.id {
                    die(format!(
                        "record {} names instrument {}, key is {}",
                        r.record_id, r.instrument_id, k.id
                    ));
                }
                r.signature_hex = String::new();
                let r = r.sign(&hexkey(&k.private_hex)).unwrap_or_else(|e| die(e));
                println!("{}", serde_json::to_string(&r).unwrap_or_default());
            }
            true
        }
        "cap-check" => {
            use syntriass_runtime::capability::validate::label;
            let f = req(args, "--file");
            let cap: Capability = serde_json::from_slice(
                &std::fs::read(f).unwrap_or_else(|e| die(format!("{f}: {e}"))),
            )
            .unwrap_or_else(|e| die(format!("{f}: {e}")));
            let compiled = match cap.compile() {
                Ok(c) => c,
                Err(e) => {
                    println!("{}", json!({"compiled": false, "error": format!("{e:?}")}));
                    return true;
                }
            };
            let cp = req(args, "--cases");
            // Optional instrument trust anchors for cases that carry a signed record.
            let instruments: BTreeMap<String, Vec<u8>> = opt(args, "--instruments")
                .map(|f| {
                    keys(
                        &serde_json::from_slice(
                            &std::fs::read(f).unwrap_or_else(|e| die(format!("{f}: {e}"))),
                        )
                        .unwrap_or_else(|e| die(format!("{f}: {e}"))),
                    )
                })
                .unwrap_or_default();
            for l in std::fs::read_to_string(cp)
                .unwrap_or_else(|e| die(format!("{cp}: {e}")))
                .lines()
            {
                if l.trim().is_empty() {
                    continue;
                }
                let v: Value = serde_json::from_str(l).unwrap_or_else(|e| die(e));
                let text = v["text"].as_str().unwrap_or_default();
                let exec = match v.get("record").filter(|x| !x.is_null()) {
                    None => cap.execute(&compiled, text),
                    Some(x) => {
                        let rec: MeasurementRecord = serde_json::from_value(x.clone())
                            .unwrap_or_else(|e| die(format!("record: {e}")));
                        match rec.verify(&cap.required.tenant, &instruments) {
                            Ok(()) => cap.execute_with_record(&compiled, text, &rec),
                            Err(e) => Execution::Failed(format!("record rejected: {e:?}")),
                        }
                    }
                };
                println!(
                    "{}",
                    json!({"id": v["id"], "got": label(&exec), "expected": v["label"]})
                );
            }
            true
        }
        _ => false,
    }
}

fn write_private(p: &Path, b: &[u8]) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(p)
        .unwrap_or_else(|e| die(format!("{}: {e}", p.display())));
    f.write_all(b).unwrap_or_else(|e| die(e));
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    if standalone(cmd, &args) {
        return;
    }
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
        "cap-propose" => {
            let f = req(&args, "--file");
            let cap: Capability = serde_json::from_slice(&std::fs::read(f).unwrap_or_else(|e| die(format!("{f}: {e}"))))
                .unwrap_or_else(|e| die(format!("{f}: {e}")));
            let mut store = FileStore::open(&c.state.join("capabilities")).unwrap_or_else(|e| die(e));
            let h = learning::propose(&mut store, &corpus, cap).unwrap_or_else(|e| die(e));
            println!("{}", json!({"hash": h, "state": "PROPOSED"}));
        }
        "cap-validate" => {
            let sp = req(&args, "--suite");
            let suite: ExpertSuite = serde_json::from_slice(&std::fs::read(sp).unwrap_or_else(|e| die(format!("{sp}: {e}"))))
                .unwrap_or_else(|e| die(format!("{sp}: {e}")));
            let mut store = FileStore::open(&c.state.join("capabilities")).unwrap_or_else(|e| die(e));
            let r = learning::validate_record(&mut store, &corpus, req(&args, "--hash"), &suite, &keys(&c.experts), "validator:runtime", learning::now_ms())
                .unwrap_or_else(|e| die(e));
            println!("{}", serde_json::to_string(&r).unwrap_or_default());
        }
        "cap-approve" => {
            let k = read_key(req(&args, "--key"));
            let trusted = c.approvers.get(&k.id).unwrap_or_else(|| die(format!("{} is not a configured approver", k.id)));
            let mut store = FileStore::open(&c.state.join("capabilities")).unwrap_or_else(|e| die(e));
            learning::approve_record(&mut store, req(&args, "--hash"), &k.id, &hexkey(&k.private_hex), &hexkey(trusted), args.iter().any(|a| a == "--consequential"), learning::now_ms())
                .unwrap_or_else(|e| die(e));
            println!("{}", json!({"hash": req(&args, "--hash"), "state": "APPROVED", "approver": k.id}));
        }
        "cap-transition" => {
            let to: State = parse_enum(req(&args, "--to"));
            let role: Role = parse_enum(req(&args, "--role"));
            let mut store = FileStore::open(&c.state.join("capabilities")).unwrap_or_else(|e| die(e));
            learning::transition(&mut store, req(&args, "--hash"), to, req(&args, "--actor"), role, learning::now_ms(), req(&args, "--reason"))
                .unwrap_or_else(|e| die(e));
            println!("{}", json!({"hash": req(&args, "--hash"), "state": to}));
        }
        "cap-list" => {
            let store = FileStore::open(&c.state.join("capabilities")).unwrap_or_else(|e| die(e));
            for r in store.all().unwrap_or_else(|e| die(e)) {
                println!("{}", json!({"id": r.capability.id, "version": r.capability.version, "hash": r.capability_hash, "state": r.state, "executable": r.executable()}));
            }
        }
        "cap-activate" => {
            let mut store = FileStore::open(&c.state.join("capabilities")).unwrap_or_else(|e| die(e));
            let sup = learning::activate(&mut store, req(&args, "--hash"), req(&args, "--actor"), args.iter().any(|a| a == "--supersede"), learning::now_ms(), req(&args, "--reason"))
                .unwrap_or_else(|e| die(e));
            println!("{}", json!({"hash": req(&args, "--hash"), "state": "ACTIVE", "superseded": sup}));
        }
        "cap-rollback" => {
            let mut store = FileStore::open(&c.state.join("capabilities")).unwrap_or_else(|e| die(e));
            let sus = learning::rollback(&mut store, req(&args, "--to"), req(&args, "--actor"), learning::now_ms(), req(&args, "--reason"))
                .unwrap_or_else(|e| die(e));
            println!("{}", json!({"hash": req(&args, "--to"), "state": "ACTIVE", "suspended": sus}));
        }
        "exp-record" => {
            let f = req(&args, "--file");
            let e: Experience = serde_json::from_slice(&std::fs::read(f).unwrap_or_else(|e| die(format!("{f}: {e}"))))
                .unwrap_or_else(|e| die(format!("{f}: {e}")));
            let uid = vanian_sovereign::app::current_uid().unwrap_or_else(|e| die(e));
            let p = vanian_sovereign::app::principal_for_uid(&c.state, uid).unwrap_or_else(|e| die(e));
            ExperienceLog::open(&c.state.join("experiences.jsonl"))
                .record(&e, p.tenant.as_str(), &c.security_domain)
                .unwrap_or_else(|e| die(e));
            println!("{}", json!({"experience": e.id, "recorded_by_tenant": p.tenant.as_str(), "verification": e.verification}));
        }
        "cap-review" => {
            let rec = record(&c, req(&args, "--hash"));
            let exps = ExperienceLog::open(&c.state.join("experiences.jsonl"))
                .for_tenant(&rec.capability.required.tenant)
                .unwrap_or_else(|e| die(e));
            let r = memory::review(&rec.capability, &exps).unwrap_or_else(|e| die(e));
            println!("{}", serde_json::to_string(&r).unwrap_or_default());
        }
        "cap-upgrade-check" => {
            let (old, new) = (record(&c, req(&args, "--from")), record(&c, req(&args, "--to")));
            let sp = req(&args, "--suite");
            let suite: ExpertSuite = serde_json::from_slice(&std::fs::read(sp).unwrap_or_else(|e| die(format!("{sp}: {e}"))))
                .unwrap_or_else(|e| die(format!("{sp}: {e}")));
            let key = keys(&c.experts).remove(&suite.expert_id).unwrap_or_else(|| die(format!("{} is not a trusted expert", suite.expert_id)));
            let r = memory::upgrade_check(&old.capability, &new.capability, &suite, &key);
            println!("{}", serde_json::to_string(&r).unwrap_or_default());
        }
        "cap-history" => {
            let id = req(&args, "--id");
            let store = FileStore::open(&c.state.join("capabilities")).unwrap_or_else(|e| die(e));
            let mut uses: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
            if let Ok(log) = std::fs::read_to_string(&audit) {
                for l in log.lines() {
                    let Ok(v) = serde_json::from_str::<Value>(l) else { continue };
                    if let Some(h) = v["capability_hash"].as_str() {
                        let o = v["outcome"]["decision"].as_str().map(String::from).unwrap_or_else(|| v["outcome"].to_string());
                        *uses.entry(h.into()).or_default().entry(o).or_default() += 1;
                    }
                }
            }
            for r in store.all().unwrap_or_else(|e| die(e)).into_iter().filter(|r| r.capability.id == id) {
                let u = uses.remove(&r.capability_hash).unwrap_or_default();
                println!("{}", json!({"version": r.capability.version, "hash": r.capability_hash, "state": r.state,
                    "executable": r.executable(), "uses": u.values().sum::<usize>(), "outcomes": u,
                    "history": r.history, "approved_by": r.approval.as_ref().map(|a| a.approver_id.clone()),
                    "suite": r.validation.as_ref().map(|v| v.suite_hash.clone())}));
            }
        }
        "health" => {
            let checks = health(&c, &audit, args.iter().any(|a| a == "--quick"));
            let ok = checks.iter().all(|k| k.ok);
            println!("{}", json!({"ok": ok, "checks": checks}));
            if !ok {
                std::process::exit(1);
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
                large: c
                    .large
                    .as_ref()
                    .map(|m| TierSlot::new(Profile::large_on_demand(&m.path, &m.sha256), c.port + 1)),
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
                instruments: keys(&c.instruments),
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
                        let record: Option<MeasurementRecord> = match v.get("record") {
                            None | Some(Value::Null) => None,
                            Some(x) => Some(serde_json::from_value(x.clone()).map_err(|e| format!("record: {e}"))?),
                        };
                        let r = match v["capability"].as_str() {
                            Some(id) => rt.invoke(&p, id, text),
                            None => rt.handle_with_record(&p, text, record.as_ref()),
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
        _ => die("usage: syntriass {ingest|ask|serve --eval|audit-verify|keygen|suite-sign|cap-propose|cap-validate|cap-approve|cap-transition|cap-list|cap-activate|cap-rollback|exp-record|cap-review|cap-upgrade-check|cap-history|health} …"),
    }
}
