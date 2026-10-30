//! `vanian` — CLI over [`vanian_sovereign::app`]. Parsing and printing only.
//!
//! Exit codes: 0 success; 1 refused/denied/rejected (a security outcome);
//! 2 usage or operational error.

use std::path::PathBuf;
use std::process::ExitCode;

use vanian_sovereign::agent::evidence::Verdict;
use vanian_sovereign::app::{self, ActOutcome};
use vanian_sovereign::domain::grounding::Validation;
use vanian_sovereign::ports::IngestOutcome;
use vanian_sovereign::rag::Outcome;

const USAGE: &str = "usage:
  vanian init   --state DIR --tools tools.json --grant id[,id..] --model-sha256 HEX
  vanian ingest --state DIR FILE...
  vanian ask    --state DIR --endpoint IP:PORT [--k N] [--show-withheld yes] [--format json] QUESTION
  vanian act    --state DIR --tool ID --evidence OUT.json [-- ARG...]
  vanian verify --public public.json --bundle bundle.json";

struct Args {
    flags: Vec<(String, String)>,
    positional: Vec<String>,
}

fn parse(argv: &[String]) -> Result<Args, String> {
    let mut flags = Vec::new();
    let mut positional = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if a == "--" {
            positional.extend(argv[i + 1..].iter().cloned());
            break;
        } else if let Some(name) = a.strip_prefix("--") {
            let v = argv.get(i + 1).ok_or(format!("--{name} needs a value"))?;
            flags.push((name.to_string(), v.clone()));
            i += 2;
        } else {
            positional.push(a.clone());
            i += 1;
        }
    }
    Ok(Args { flags, positional })
}

impl Args {
    fn get(&self, k: &str) -> Result<&str, String> {
        self.flags
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.as_str())
            .ok_or(format!("missing --{k}"))
    }
    fn opt(&self, k: &str) -> Option<&str> {
        self.get(k).ok()
    }
}

fn run(cmd: &str, a: &Args) -> Result<ExitCode, String> {
    match cmd {
        "init" => {
            let model: [u8; 32] = hex::decode(a.get("model-sha256")?)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or("--model-sha256 must be 64 hex chars")?;
            let grants: Vec<String> = a.get("grant")?.split(',').map(str::to_string).collect();
            let p = app::init(
                &PathBuf::from(a.get("state")?),
                &PathBuf::from(a.get("tools")?),
                &grants,
                model,
            )?;
            println!(
                "initialised: agent={} decision_point={} runner={}",
                p.agent_id, p.decision_point_id, p.runner_id
            );
            Ok(ExitCode::SUCCESS)
        }
        "ingest" => {
            let state = PathBuf::from(a.get("state")?);
            for f in &a.positional {
                match app::ingest_file(&state, &PathBuf::from(f))? {
                    (id, IngestOutcome::Indexed) => println!("ingested {id}"),
                    (id, IngestOutcome::Quarantined { marker }) => {
                        println!("QUARANTINED {id} (instruction-like text: {marker:?}); stored, not retrievable")
                    }
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        "ask" => {
            let k: usize = a
                .opt("k")
                .unwrap_or("4")
                .parse()
                .map_err(|_| "--k must be an integer")?;
            let q = a.positional.join(" ");
            let (p, ans) = app::ask(&PathBuf::from(a.get("state")?), a.get("endpoint")?, &q, k)?;
            let (status, detail) = describe(&ans.outcome);
            if a.opt("format") == Some("json") {
                let v = serde_json::json!({
                    "principal": {"tenant": p.tenant.as_str(), "clearance": format!("{:?}", p.clearance)},
                    "sources": ans.sources.iter().map(|s| serde_json::json!({
                        "index": s.index, "doc_id": s.doc_id, "title": s.title,
                        "classification": format!("{:?}", s.classification)})).collect::<Vec<_>>(),
                    "model_called": ans.model_called(),
                    "status": status,
                    "detail": detail,
                    "answer": ans.released(),
                    "citations": match &ans.outcome {
                        Outcome::Validated(Validation::Released { citations, .. }) => {
                            citations.iter().copied().collect::<Vec<_>>()
                        }
                        _ => vec![],
                    },
                    "raw_model_output": ans.raw_model_output,
                });
                println!("{v}");
                return Ok(ExitCode::SUCCESS);
            }
            println!(
                "principal: tenant={} clearance={:?}",
                p.tenant.as_str(),
                p.clearance
            );
            println!("authorized sources retrieved: {}", ans.sources.len());
            for s in &ans.sources {
                println!(
                    "  [S{}] {} ({:?}) {}",
                    s.index, s.doc_id, s.classification, s.title
                );
            }
            println!("model called: {}", ans.model_called());
            println!("status: {status} {detail}");
            match ans.released() {
                Some(t) => println!("---\n{t}"),
                None => println!("--- NO ANSWER RELEASED"),
            }
            if ans.released().is_none() && a.opt("show-withheld") == Some("yes") {
                if let Some(raw) = &ans.raw_model_output {
                    println!("--- withheld model output (audit only, NOT an answer) ---\n{raw}");
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        "act" => {
            let out = PathBuf::from(a.get("evidence")?);
            match app::act(
                &PathBuf::from(a.get("state")?),
                a.get("tool")?,
                a.positional.clone(),
                &app::default_unshare(),
            )? {
                ActOutcome::Denied { reason } => {
                    println!("DENIED by AIP decision point: {reason}");
                    println!("nothing was executed");
                    Ok(ExitCode::from(1))
                }
                ActOutcome::Executed { bundle, output } => {
                    std::fs::write(
                        &out,
                        serde_json::to_vec_pretty(&bundle).map_err(|e| e.to_string())?,
                    )
                    .map_err(|e| e.to_string())?;
                    println!(
                        "AUTHORIZED decision={}",
                        hex::encode(bundle.expected_execution.decision_id)
                    );
                    println!("exit: {:?}", bundle.run_record.exit);
                    println!("stdout:\n{}", String::from_utf8_lossy(&output.stdout));
                    println!("evidence written: {}", out.display());
                    Ok(ExitCode::SUCCESS)
                }
            }
        }
        "verify" => match app::verify(
            &PathBuf::from(a.get("public")?),
            &PathBuf::from(a.get("bundle")?),
        )? {
            Verdict::Rejected(r) => {
                println!("REJECTED: {r:?}");
                Ok(ExitCode::from(1))
            }
            Verdict::AuthorizedAndRunnerAttested { exit, observation } => {
                println!("AUTHORIZED_AND_RUNNER_ATTESTED exit={exit:?}");
                println!("independent observation: {observation:?}");
                println!("NOTE: execution is attested by the runner, not independently observed.");
                Ok(ExitCode::SUCCESS)
            }
        },
        _ => Err(USAGE.into()),
    }
}

/// Stable status label and detail for an answer outcome.
fn describe(o: &Outcome) -> (&'static str, String) {
    match o {
        Outcome::NoAuthorizedSource => ("NO_AUTHORIZED_SOURCE", String::new()),
        Outcome::Validated(Validation::Released { citations, .. }) => {
            ("RELEASED", format!("cites {citations:?}"))
        }
        Outcome::Validated(Validation::Abstained) => ("ABSTAINED", "sources insufficient".into()),
        Outcome::Validated(Validation::Withheld(r)) => ("WITHHELD", format!("{r:?}")),
    }
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = argv.first() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    match parse(&argv[1..]).and_then(|a| run(cmd, &a)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}
