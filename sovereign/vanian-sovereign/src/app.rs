//! Composition root: wires ports to adapters for the `vanian` CLI.
//!
//! Every function here is orchestration only. Policy lives in [`crate::policy`]
//! and [`aip_authorize`]; IO lives in [`crate::adapters`].
//!
//! # State directory
//!
//! ```text
//! <state>/
//!   keys/{institution,agent,decision-point,runner}.key   owner-only (0600)
//!   public.json        ids + public keys (safe to give an auditor)
//!   root-token.json    institution → agent ScopedToken
//!   tools.json         tool manifests (operator-controlled)
//!   principals.json    OS uid → tenant + clearance
//!   corpus.db          SQLite FTS5 corpus
//!   consumed.log       one-shot decision log
//! ```
//!
//! # Role collapse in this slice (stated, not hidden)
//!
//! The institution issuer, decision point, runner and agent keys are
//! distinct, but all four are generated and held on one host under one uid,
//! and `act` runs the decision point and runner in the agent's process.
//! Separating them into independently administered daemons is required
//! before any claim of separation of duties.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aip_authorize::{AuthorizationRequest, Decision, DecisionPoint, DecisionPointTrustAnchors};
use aip_types::{CapabilityScope, ProvenanceTriple, ScopedToken};
use serde::{Deserialize, Serialize};

use crate::adapters::llama_http::LlamaHttp;
use crate::adapters::sandbox::{RunOutput, SandboxRunner};
use crate::adapters::sqlite_corpus::SqliteCorpus;
use crate::agent::evidence::{verify_bundle, EvidenceBundle, RunnerAnchor, Verdict};
use crate::agent::replay::FileReplayGuard;
use crate::agent::tool::{action_for, ToolInvocation, ToolManifest};
use crate::domain::corpus::{Classification, Document, Ident, Principal};
use crate::policy::egress::LoopbackEndpoint;
use crate::ports::{CorpusStore, GenerationParams};
use crate::rag::{self, RagAnswer};

/// Expectation lifetime requested by `act` (ms). Short: authorize-then-run.
pub const ACT_TTL_MS: u64 = 60_000;
/// Decision point policy ceiling (ms).
pub const DP_MAX_TTL_MS: u64 = 300_000;
/// Root token lifetime (ms): 30 days.
pub const ROOT_TOKEN_TTL_MS: u64 = 30 * 24 * 3_600_000;

/// Application error: a message for the operator.
pub type AppResult<T> = Result<T, String>;

/// Wall clock in Unix ms.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Serialize, Deserialize)]
struct SecretKey {
    id: String,
    private_key_hex: String,
}

/// Public identities: what an auditor receives.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicIdentities {
    pub institution_id: String,
    pub institution_pub: String,
    pub agent_id: String,
    pub agent_pub: String,
    pub decision_point_id: String,
    pub decision_point_pub: String,
    pub runner_id: String,
    pub runner_pub: String,
}

/// uid → principal mapping entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalEntry {
    pub tenant: String,
    pub clearance: String,
}

fn rd<T: for<'de> Deserialize<'de>>(p: &Path) -> AppResult<T> {
    let b = std::fs::read(p).map_err(|e| format!("read {}: {e}", p.display()))?;
    serde_json::from_slice(&b).map_err(|e| format!("parse {}: {e}", p.display()))
}

fn wr<T: Serialize>(p: &Path, v: &T) -> AppResult<()> {
    let b = serde_json::to_vec_pretty(v).map_err(|e| e.to_string())?;
    std::fs::write(p, b).map_err(|e| format!("write {}: {e}", p.display()))
}

fn sha(b: &[u8]) -> [u8; 32] {
    aip_crypto::sha256(b)
}

fn save_secret(state: &Path, name: &str, id: &str, private_key: &[u8]) -> AppResult<()> {
    let p = state.join("keys").join(format!("{name}.key"));
    let body = serde_json::to_vec(&SecretKey {
        id: id.into(),
        private_key_hex: hex::encode(private_key),
    })
    .map_err(|e| e.to_string())?;
    aip_crypto::custody::write_owner_only_file(&p, &body).map_err(|e| format!("{e:?}"))
}

fn load_secret(state: &Path, name: &str) -> AppResult<(String, Vec<u8>)> {
    let p = state.join("keys").join(format!("{name}.key"));
    aip_crypto::custody::check_secret_file(&p).map_err(|e| format!("{}: {e:?}", p.display()))?;
    let s: SecretKey = rd(&p)?;
    Ok((
        s.id,
        hex::decode(s.private_key_hex).map_err(|e| e.to_string())?,
    ))
}

/// Create identities, the root authority token and a default uid mapping.
///
/// `granted_tools` are the tool ids the institution delegates to the agent;
/// any other manifest in `tools.json` is present but **not authorized**.
/// `model_sha256` binds the agent identity's provenance to the model weights.
pub fn init(
    state: &Path,
    tools_json: &Path,
    granted_tools: &[String],
    model_sha256: [u8; 32],
) -> AppResult<PublicIdentities> {
    if state.join("public.json").exists() {
        return Err(format!(
            "{} already initialised; refusing to overwrite keys",
            state.display()
        ));
    }
    std::fs::create_dir_all(state.join("keys")).map_err(|e| e.to_string())?;
    let tools: Vec<ToolManifest> = rd(tools_json)?;
    for t in &tools {
        t.validate()
            .map_err(|e| format!("tool {}: {e}", t.id.as_str()))?;
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let prov = |role: &str| ProvenanceTriple {
        model_commitment: if role == "agent" {
            model_sha256
        } else {
            sha(role.as_bytes())
        },
        environment_commitment: sha(&std::fs::read(tools_json).unwrap_or_default()),
        toolchain_commitment: sha(&std::fs::read(&exe).unwrap_or_default()),
    };

    let inst_kp = aip_crypto::generate_ed25519_keypair();
    let inst_id = aip_crypto::derive_aip_id(&inst_kp.public_key, &prov("institution"));
    let (agent_doc, agent_kp) =
        aip_core::create_identity(prov("agent"), None).map_err(|e| format!("{e:?}"))?;
    let dp_kp = aip_crypto::generate_ed25519_keypair();
    let dp_id = aip_crypto::derive_aip_id(&dp_kp.public_key, &prov("decision-point"));
    let run_kp = aip_crypto::generate_ed25519_keypair();
    let run_id = aip_crypto::derive_aip_id(&run_kp.public_key, &prov("runner"));

    let mut allowed = Vec::new();
    for g in granted_tools {
        let id = Ident::new(g).map_err(|e| e.to_string())?;
        if !tools.iter().any(|t| t.id == id) {
            return Err(format!("granted tool {g} has no manifest"));
        }
        allowed.push(action_for(&id));
    }
    let root = aip_core::capability::issue_scoped_token(
        &inst_id,
        &inst_kp.private_key,
        &agent_doc.id,
        CapabilityScope {
            allowed,
            denied: vec![],
        },
        Some(ROOT_TOKEN_TTL_MS),
    )
    .map_err(|e| format!("{e:?}"))?;

    save_secret(state, "institution", &inst_id, &inst_kp.private_key)?;
    save_secret(state, "agent", &agent_doc.id, &agent_kp.private_key)?;
    save_secret(state, "decision-point", &dp_id, &dp_kp.private_key)?;
    save_secret(state, "runner", &run_id, &run_kp.private_key)?;
    wr(&state.join("root-token.json"), &root)?;
    std::fs::copy(tools_json, state.join("tools.json")).map_err(|e| e.to_string())?;

    let pubs = PublicIdentities {
        institution_id: inst_id,
        institution_pub: hex::encode(&inst_kp.public_key),
        agent_id: agent_doc.id,
        agent_pub: hex::encode(&agent_kp.public_key),
        decision_point_id: dp_id,
        decision_point_pub: hex::encode(&dp_kp.public_key),
        runner_id: run_id,
        runner_pub: hex::encode(&run_kp.public_key),
    };
    wr(&state.join("public.json"), &pubs)?;
    Ok(pubs)
}

/// Resolve the calling OS user to a principal. The OS login is the
/// authenticator in this slice; an unmapped uid gets no access.
pub fn principal_for_uid(state: &Path, uid: u32) -> AppResult<Principal> {
    let map: BTreeMap<String, PrincipalEntry> = rd(&state.join("principals.json"))?;
    let e = map
        .get(&uid.to_string())
        .ok_or_else(|| format!("uid {uid} is not a mapped principal; access denied"))?;
    Ok(Principal {
        tenant: Ident::new(&e.tenant).map_err(|e| e.to_string())?,
        clearance: Classification::parse(&e.clearance).map_err(|e| e.to_string())?,
    })
}

/// Current real uid (from procfs; avoids an extra libc dependency).
pub fn current_uid() -> AppResult<u32> {
    let s = std::fs::read_to_string("/proc/self/status").map_err(|e| e.to_string())?;
    s.lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| "cannot read uid".into())
}

/// Ingest a document file. Front matter: first line `tenant|doc_id|class|title`.
pub fn ingest_file(state: &Path, file: &Path) -> AppResult<String> {
    let text = std::fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?;
    let (head, body) = text.split_once('\n').ok_or("missing header line")?;
    let f: Vec<&str> = head.splitn(4, '|').collect();
    if f.len() != 4 {
        return Err(format!(
            "{}: header must be tenant|doc_id|class|title",
            file.display()
        ));
    }
    let doc = Document {
        tenant: Ident::new(f[0].trim()).map_err(|e| e.to_string())?,
        doc_id: Ident::new(f[1].trim()).map_err(|e| e.to_string())?,
        classification: Classification::parse(f[2].trim()).map_err(|e| e.to_string())?,
        title: f[3].trim().to_string(),
        body: body.to_string(),
    };
    let mut c = SqliteCorpus::open(&state.join("corpus.db")).map_err(|e| e.to_string())?;
    c.ingest(&doc).map_err(|e| e.to_string())?;
    Ok(doc.doc_id.as_str().to_string())
}

/// Grounded question for the calling OS user.
pub fn ask(
    state: &Path,
    endpoint: &str,
    question: &str,
    k: usize,
) -> AppResult<(Principal, RagAnswer)> {
    let principal = principal_for_uid(state, current_uid()?)?;
    let ep = LoopbackEndpoint::parse(endpoint)
        .map_err(|e| format!("inference endpoint refused: {e}"))?;
    let llm = LlamaHttp::new(ep, Duration::from_secs(300));
    let corpus = SqliteCorpus::open(&state.join("corpus.db")).map_err(|e| e.to_string())?;
    let a = rag::answer(
        &principal,
        question,
        &corpus,
        &llm,
        k,
        &GenerationParams::default(),
    )
    .map_err(|e| e.to_string())?;
    Ok((principal, a))
}

/// Outcome of `act`.
pub enum ActOutcome {
    Denied {
        reason: String,
    },
    Executed {
        bundle: Box<EvidenceBundle>,
        output: Box<RunOutput>,
    },
}

fn hexkey(s: &str) -> AppResult<Vec<u8>> {
    hex::decode(s).map_err(|e| e.to_string())
}

/// Request authorization for a tool and, if granted, run it in the sandbox.
pub fn act(state: &Path, tool: &str, args: Vec<String>, unshare: &Path) -> AppResult<ActOutcome> {
    let pubs: PublicIdentities = rd(&state.join("public.json"))?;
    let tools: Vec<ToolManifest> = rd(&state.join("tools.json"))?;
    let root: ScopedToken = rd(&state.join("root-token.json"))?;
    let tool_id = Ident::new(tool).map_err(|e| e.to_string())?;
    let manifest = tools
        .iter()
        .find(|t| t.id == tool_id)
        .ok_or_else(|| format!("no manifest for tool {tool}"))?;
    let inv = ToolInvocation { tool_id, args };

    let (dp_id, dp_priv) = load_secret(state, "decision-point")?;
    let dp = DecisionPoint::new(
        &dp_id,
        &dp_priv,
        &hexkey(&pubs.decision_point_pub)?,
        DP_MAX_TTL_MS,
    )
    .map_err(|e| format!("{e:?}"))?
    .trust_issuer(&pubs.institution_id, &hexkey(&pubs.institution_pub)?);

    let binding = aip_core::execution_binding::collect_self_binding(&pubs.agent_id)
        .map_err(|e| format!("{e:?}"))?;
    let req = AuthorizationRequest {
        agent_id: pubs.agent_id.clone(),
        root_token: root,
        delegation_chain: vec![],
        action_kind: manifest.action_kind(),
        parameters: manifest.parameters(&inv).map_err(|e| e.to_string())?,
        execution_binding: binding.clone(),
        requested_ttl_ms: ACT_TTL_MS,
    };
    let ee = match dp.authorize(&req) {
        Decision::Denied(d) => {
            return Ok(ActOutcome::Denied {
                reason: format!("{:?}: {}", d.reason, d.detail),
            })
        }
        Decision::Authorized(ee) => *ee,
    };

    let (runner_id, runner_priv) = load_secret(state, "runner")?;
    let workdir = state.join("work");
    std::fs::create_dir_all(&workdir).map_err(|e| e.to_string())?;
    let runner = SandboxRunner {
        runner_id,
        runner_private_key: runner_priv,
        decision_anchors: DecisionPointTrustAnchors::new()
            .trust(&pubs.decision_point_id, &hexkey(&pubs.decision_point_pub)?),
        unshare_path: unshare.to_path_buf(),
        workdir,
    };
    let mut guard = FileReplayGuard::new(state.join("consumed.log"));
    let output = runner
        .run(manifest, &inv, &ee, &binding, &mut guard, &now_ms)
        .map_err(|e| format!("runner refused: {e}"))?;
    let bundle = EvidenceBundle {
        expected_execution: ee,
        run_record: output.record.clone(),
    };
    Ok(ActOutcome::Executed {
        bundle: Box::new(bundle),
        output: Box::new(output),
    })
}

/// Offline verification from public material only.
pub fn verify(public_json: &Path, bundle_json: &Path) -> AppResult<Verdict> {
    let pubs: PublicIdentities = rd(public_json)?;
    let bundle: EvidenceBundle = rd(bundle_json)?;
    let dp = DecisionPointTrustAnchors::new()
        .trust(&pubs.decision_point_id, &hexkey(&pubs.decision_point_pub)?);
    let runner = RunnerAnchor {
        runner_id: pubs.runner_id,
        public_key: hexkey(&pubs.runner_pub)?,
    };
    Ok(verify_bundle(&bundle, &dp, &runner))
}

/// Default path of util-linux unshare.
pub fn default_unshare() -> PathBuf {
    PathBuf::from("/usr/bin/unshare")
}
