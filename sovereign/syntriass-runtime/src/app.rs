//! Orchestration: one request through authorization, strategy selection,
//! execution, validation, cost accounting and audit. No policy lives here —
//! routing is [`crate::controller`], decisions are [`crate::domain`] and
//! capabilities, retrieval ACL and grounding are the Sovereign slice's.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use vanian_sovereign::adapters::sqlite_corpus::SqliteCorpus;
use vanian_sovereign::domain::corpus::{Classification, Principal};
use vanian_sovereign::ports::{GenerationParams, PortError, PortErrorKind};
use vanian_sovereign::rag::{self, Outcome as RagOutcome};

use crate::capability::artifact::Execution;
use crate::capability::lifecycle::Record;
use crate::controller::{
    escalate, is_question, route, Candidate, Features, Refusal, Strategy, Tier, Withhold,
};
use crate::domain::maintenance::{decide, Decision};
use crate::domain::scope::CacheScope;
use crate::ports::{
    CapabilityStore, GenStats, InterpreterPort, Meter, ResourceSnapshot, ScopedGenerator,
    ScopedInference,
};

/// Supplies generative models, possibly loading them on demand.
pub trait ModelProvider {
    /// Is a tier configured (it may still need loading)?
    fn configured(&self, tier: Tier) -> bool;
    /// Run `f` with the tier's generator, loading it if needed. Returns the
    /// load time spent in this call (0 if already resident).
    fn with<'a>(
        &'a self,
        tier: Tier,
        f: &mut dyn FnMut(&dyn ScopedGenerator) -> Result<(), PortError>,
    ) -> Result<f64, PortError>;
    /// Model SHA-256 for a tier, if configured.
    fn model_sha256(&self, tier: Tier) -> Option<String>;
}

/// Static configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub policy_version: String,
    pub security_domain: String,
    pub audit_log: PathBuf,
    pub rag_k: usize,
    /// approver id → Ed25519 public key (operator-configured trust anchors).
    pub approvers: BTreeMap<String, Vec<u8>>,
}

/// What the caller receives.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Outcome {
    Decision { label: String, detail: Value },
    Answer { text: String, sources: Vec<String> },
    Withheld { reason: String },
    Refused { refusal: Refusal },
}

/// Measured cost of one request.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Cost {
    pub wall_ms: f64,
    /// CPU seconds consumed per component during this request.
    pub cpu_s: BTreeMap<String, f64>,
    /// Resident memory per component after the request (MiB).
    pub rss_mib: BTreeMap<String, f64>,
    pub model_calls: usize,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub cached_tokens: u64,
    pub model_load_ms: f64,
    pub interpreter_calls: usize,
    /// Small → large retries in this request (failed attempt's cost included above).
    #[serde(default)]
    pub escalations: usize,
}

/// Full response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub strategy: Strategy,
    pub outcome: Outcome,
    pub cost: Cost,
    /// Content hash of the capability that decided, if any.
    pub capability_hash: Option<String>,
    pub audit_hash: String,
}

/// The runtime.
pub struct Runtime<'a> {
    pub cfg: Config,
    pub corpus: &'a SqliteCorpus,
    pub interpreter: &'a dyn InterpreterPort,
    pub models: &'a dyn ModelProvider,
    pub store: &'a dyn CapabilityStore,
    pub meter: &'a dyn Meter,
    audit_prev: RefCell<String>,
}

fn clearance_label(c: Classification) -> &'static str {
    match c {
        Classification::Public => "public",
        Classification::Internal => "internal",
        Classification::Restricted => "restricted",
    }
}

fn rank(label: &str) -> Option<i64> {
    Classification::parse(label).ok().map(Classification::rank)
}

fn other(m: impl Into<String>) -> PortError {
    PortError::new(PortErrorKind::InvalidInput, m)
}

impl<'a> Runtime<'a> {
    pub fn new(
        cfg: Config,
        corpus: &'a SqliteCorpus,
        interpreter: &'a dyn InterpreterPort,
        models: &'a dyn ModelProvider,
        store: &'a dyn CapabilityStore,
        meter: &'a dyn Meter,
    ) -> Self {
        let prev = last_audit_hash(&cfg.audit_log).unwrap_or_else(|| "genesis".into());
        Self {
            cfg,
            corpus,
            interpreter,
            models,
            store,
            meter,
            audit_prev: RefCell::new(prev),
        }
    }

    /// The cache scope for a principal and model.
    pub fn scope(&self, p: &Principal, model_sha: &str) -> Result<CacheScope, PortError> {
        let snap = hex::encode(self.corpus.snapshot_digest(p)?);
        CacheScope::new(
            model_sha,
            &format!("embedded-in-gguf:{model_sha}"),
            &self.cfg.policy_version,
            &snap,
            &format!("{}:{}", p.tenant.as_str(), clearance_label(p.clearance)),
            &self.cfg.security_domain,
        )
        .map_err(|e| other(format!("scope: {e:?}")))
    }

    /// Why a record may not run for this principal right now (`None` = may run).
    fn ineligible(&self, r: &Record, p: &Principal) -> Option<String> {
        if !r.executable() {
            return Some(format!("state {:?}", r.state));
        }
        // Explicit (not `?`): a record without an approval must never be
        // reported as eligible, even if `executable()` changes later.
        let Some(a) = r.approval.as_ref() else {
            return Some("no approval".into());
        };
        if a.capability_hash != r.capability_hash {
            return Some("approval is for different content".into());
        }
        // Consequential capabilities would need AIP action authorization bound to
        // the capability version, inputs and scope, executed by the authorized
        // runner. That path is not integrated in this runtime, so they are
        // disabled (fail closed) rather than run without it.
        if a.consequential {
            return Some("consequential capabilities are disabled: AIP action authorization is not integrated in this runtime".into());
        }
        match self.cfg.approvers.get(&a.approver_id) {
            Some(pk) if a.verify(pk) => {}
            _ => return Some("approval not signed by a trusted approver".into()),
        }
        let req = &r.capability.required;
        if req.tenant != p.tenant.as_str() || req.security_domain != self.cfg.security_domain {
            return Some("not authorized for this tenant or domain".into());
        }
        if rank(&req.min_clearance).is_none_or(|need| p.clearance.rank() < need) {
            return Some("clearance below requirement".into());
        }
        None
    }

    /// Dependency check for an eligible capability (`Some(reason)` = stale).
    fn stale(&self, r: &Record, p: &Principal) -> Result<Option<String>, PortError> {
        let d = &r.capability.dependencies;
        if d.policy_version != self.cfg.policy_version {
            return Ok(Some(format!(
                "policy {} ≠ {}",
                d.policy_version, self.cfg.policy_version
            )));
        }
        for (doc, want) in &d.knowledge {
            match self.corpus.document_digest(p, doc)? {
                Some(h) if &hex::encode(h) == want => {}
                Some(_) => return Ok(Some(format!("evidence {doc} changed"))),
                None => return Ok(Some(format!("evidence {doc} not readable"))),
            }
        }
        if let Some(m) = &d.execution_model_sha256 {
            if self.models.model_sha256(Tier::Small).as_deref() != Some(m) {
                return Ok(Some(
                    "execution model changed; compatibility re-validation required".into(),
                ));
            }
        }
        Ok(None)
    }

    fn candidates(
        &self,
        p: &Principal,
        text: &str,
    ) -> Result<(Vec<Candidate>, Vec<Record>), PortError> {
        let mut c = vec![];
        let mut recs = vec![];
        for r in self.store.all()? {
            if self.ineligible(&r, p).is_some() {
                continue; // invisible to this caller
            }
            let applies = r.capability.compile().is_ok() && r.capability.applies(text);
            if !applies {
                continue;
            }
            let stale = self.stale(&r, p)?;
            c.push(Candidate {
                id: r.capability.id.clone(),
                hash: r.capability_hash.clone(),
                stale,
            });
            recs.push(r);
        }
        Ok((c, recs))
    }

    /// Explicit invocation of one capability by id (Scene 5): refused unless
    /// it is ACTIVE, trusted, authorized for the caller and current.
    pub fn invoke(
        &self,
        p: &Principal,
        capability_id: &str,
        text: &str,
    ) -> Result<Response, PortError> {
        let t0 = Instant::now();
        let before = self.meter.snapshot();
        let recs: Vec<Record> = self
            .store
            .all()?
            .into_iter()
            .filter(|r| r.capability.id == capability_id)
            .collect();
        let usable = recs.iter().find(|r| self.ineligible(r, p).is_none());
        let (strategy, outcome, hash) = match usable {
            None => {
                let why = recs
                    .iter()
                    .filter_map(|r| self.ineligible(r, p))
                    .next()
                    .unwrap_or_else(|| "no such capability".into());
                let r = Refusal::NotPermitted {
                    id: capability_id.into(),
                    reason: why,
                };
                (
                    Strategy::Refuse(r.clone()),
                    Outcome::Refused { refusal: r },
                    None,
                )
            }
            Some(r) => match self.stale(r, p)? {
                Some(why) => (
                    Strategy::Refuse(Refusal::CapabilityStale {
                        id: r.capability.id.clone(),
                        reason: why.clone(),
                    }),
                    Outcome::Refused {
                        refusal: Refusal::CapabilityStale {
                            id: r.capability.id.clone(),
                            reason: why,
                        },
                    },
                    None,
                ),
                None => {
                    let (o, h) = self.run_capability(r, text);
                    (
                        Strategy::Capability {
                            id: r.capability.id.clone(),
                            hash: r.capability_hash.clone(),
                        },
                        o,
                        h,
                    )
                }
            },
        };
        self.finish(
            p,
            text,
            strategy,
            outcome,
            Cost::default(),
            hash,
            t0,
            before,
        )
    }

    fn run_capability(&self, r: &Record, text: &str) -> (Outcome, Option<String>) {
        let o = match r.capability.compile() {
            Err(e) => Outcome::Withheld {
                reason: format!("capability no longer compiles: {e:?}"),
            },
            Ok(c) => match r.capability.execute(&c, text) {
                Execution::Decided {
                    outcome,
                    values,
                    step,
                } => Outcome::Decision {
                    label: outcome,
                    detail: json!({"values": values, "step": step}),
                },
                Execution::Ambiguous { input } => Outcome::Withheld {
                    reason: format!("input {input} appears with different values; clarify"),
                },
                Execution::Failed(m) => Outcome::Withheld {
                    reason: format!("evaluation failed: {m}"),
                },
                Execution::NotApplicable => Outcome::Withheld {
                    reason: "capability does not apply".into(),
                },
            },
        };
        (o, Some(r.capability_hash.clone()))
    }

    /// Handle one request from an authenticated principal.
    pub fn handle(&self, p: &Principal, text: &str) -> Result<Response, PortError> {
        let t0 = Instant::now();
        let before = self.meter.snapshot();
        let mut cost = Cost::default();
        let (caps, recs) = self.candidates(p, text)?;
        let mut feats = Features {
            capabilities: caps,
            interpretation: None,
            is_question: is_question(text),
            small_model: self.models.configured(Tier::Small),
            large_model: self.models.configured(Tier::Large),
        };
        if feats.capabilities.is_empty() {
            feats.interpretation = Some(self.interpreter.interpret(text)?);
            cost.interpreter_calls += 1;
        }
        let strategy = route(&feats);
        let mut cap_hash = None;
        let outcome = match &strategy {
            Strategy::Capability { hash, .. } => {
                let r = recs
                    .iter()
                    .find(|r| &r.capability_hash == hash)
                    .ok_or_else(|| other("capability vanished"))?;
                let (o, h) = self.run_capability(r, text);
                cap_hash = h;
                o
            }
            Strategy::Exact => decision(
                &feats
                    .interpretation
                    .as_ref()
                    .map(|i| decide(&i.rules))
                    .unwrap_or(Decision::Abstain),
                "exact rules",
            ),
            Strategy::Interpreter => decision(
                &feats
                    .interpretation
                    .as_ref()
                    .map(|i| decide(&i.interp))
                    .unwrap_or(Decision::Abstain),
                "compact interpreter",
            ),
            Strategy::ModelExtraction(tier) => self.model_extraction(p, text, *tier, &mut cost)?,
            Strategy::GroundedQa(tier) => self.grounded(p, text, *tier, &mut cost)?,
            Strategy::Refuse(r) => Outcome::Refused { refusal: r.clone() },
        };
        let (strategy, outcome) =
            match escalate(&strategy, withhold_kind(&outcome), feats.large_model) {
                Some(next) => {
                    cost.escalations += 1;
                    let o = match &next {
                        Strategy::ModelExtraction(t) => {
                            self.model_extraction(p, text, *t, &mut cost)?
                        }
                        Strategy::GroundedQa(t) => self.grounded(p, text, *t, &mut cost)?,
                        _ => return Err(other("escalation to a non-model strategy")),
                    };
                    (next, o)
                }
                None => (strategy, outcome),
            };
        self.finish(p, text, strategy, outcome, cost, cap_hash, t0, before)
    }

    fn record_calls(cost: &mut Cost, calls: &[GenStats]) {
        for c in calls {
            cost.model_calls += 1;
            cost.prompt_tokens += c.prompt_tokens;
            cost.completion_tokens += c.completion_tokens;
            cost.cached_tokens += c.cached_tokens;
        }
    }

    fn model_extraction(
        &self,
        p: &Principal,
        text: &str,
        tier: Tier,
        cost: &mut Cost,
    ) -> Result<Outcome, PortError> {
        let req = self.interpreter.slm_request(text)?;
        let mut raw = String::new();
        let mut calls = vec![];
        let load = self.models.with(tier, &mut |g| {
            let scope = self.scope(p, &g.model_sha256())?;
            let params = GenerationParams {
                max_tokens: req.max_tokens,
                response_schema: Some(req.schema.clone()),
                ..GenerationParams::default()
            };
            let (out, st) = g.generate(&scope, &req.messages, &params)?;
            raw = out;
            calls.push(st);
            Ok(())
        })?;
        cost.model_load_ms += load;
        Self::record_calls(cost, &calls);
        cost.interpreter_calls += 2;
        Ok(match self.interpreter.slm_parse(&raw)? {
            None => Outcome::Withheld {
                reason: "model output did not parse".into(),
            },
            Some(rd) => decision(&decide(&rd), "model extraction"),
        })
    }

    fn grounded(
        &self,
        p: &Principal,
        text: &str,
        tier: Tier,
        cost: &mut Cost,
    ) -> Result<Outcome, PortError> {
        let mut result = None;
        let mut calls = vec![];
        let load = self.models.with(tier, &mut |g| {
            let inf = ScopedInference {
                generator: g,
                scope: self.scope(p, &g.model_sha256())?,
                calls: RefCell::new(vec![]),
            };
            result = Some(rag::answer(
                p,
                text,
                self.corpus,
                &inf,
                self.cfg.rag_k,
                &GenerationParams::default(),
            )?);
            calls.extend(inf.calls.into_inner());
            Ok(())
        })?;
        cost.model_load_ms += load;
        Self::record_calls(cost, &calls);
        let a = result.ok_or_else(|| other("no answer"))?;
        let sources: Vec<String> = a.sources.iter().map(|s| s.doc_id.clone()).collect();
        Ok(match (&a.outcome, a.released()) {
            (RagOutcome::NoAuthorizedSource, _) => Outcome::Withheld {
                reason: NO_AUTHORIZED_SOURCE.into(),
            },
            (_, Some(t)) if crate::domain::answer_check::unfinished_calculation(text, t) => {
                Outcome::Withheld {
                    reason: format!(
                        "calculation not completed: the authorised source gives the rule \"{t}\" ({}), but the value for this request was not computed",
                        sources.join(", ")
                    ),
                }
            }
            (_, Some(t)) => Outcome::Answer {
                text: t.to_string(),
                sources,
            },
            (RagOutcome::Validated(v), None) => Outcome::Withheld {
                reason: format!("{v:?}"),
            },
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn finish(
        &self,
        p: &Principal,
        text: &str,
        strategy: Strategy,
        outcome: Outcome,
        mut cost: Cost,
        capability_hash: Option<String>,
        t0: Instant,
        before: Vec<(String, ResourceSnapshot)>,
    ) -> Result<Response, PortError> {
        cost.wall_ms = t0.elapsed().as_secs_f64() * 1000.0;
        let after = self.meter.snapshot();
        for (n, s) in &after {
            let b = before
                .iter()
                .find(|(m, _)| m == n)
                .map(|(_, s)| s.cpu_s)
                .unwrap_or(0.0);
            cost.cpu_s
                .insert(n.clone(), ((s.cpu_s - b) * 1000.0).round() / 1000.0);
            cost.rss_mib
                .insert(n.clone(), (s.rss_mib * 10.0).round() / 10.0);
        }
        let audit_hash = self.audit(p, text, &strategy, &outcome, &capability_hash, &cost)?;
        Ok(Response {
            strategy,
            outcome,
            cost,
            capability_hash,
            audit_hash,
        })
    }

    /// Append a hash-chained audit record. The request text is stored only as
    /// a hash (it may be confidential); the outcome label is stored.
    fn audit(
        &self,
        p: &Principal,
        text: &str,
        s: &Strategy,
        o: &Outcome,
        cap: &Option<String>,
        cost: &Cost,
    ) -> Result<String, PortError> {
        let prev = self.audit_prev.borrow().clone();
        let body = json!({
            "prev": prev,
            "principal_scope": format!("{}:{}", p.tenant.as_str(), clearance_label(p.clearance)),
            "request_sha256": hex::encode(aip_crypto::sha256(text.as_bytes())),
            "strategy": s,
            "outcome": match o { Outcome::Decision { label, .. } => json!({"decision": label}), Outcome::Answer { sources, .. } => json!({"answer_sources": sources}), Outcome::Withheld { reason } => json!({"withheld": reason}), Outcome::Refused { refusal } => json!({"refused": refusal}) },
            "capability_hash": cap,
            "cost": cost,
            // No independent observer is attached to this runtime.
            "observation": "CannotProve",
        });
        let line = body.to_string();
        let h = hex::encode(aip_crypto::sha256(line.as_bytes()));
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.cfg.audit_log)
            .map_err(|e| PortError::new(PortErrorKind::Storage, e.to_string()))?;
        writeln!(f, "{line}").map_err(|e| PortError::new(PortErrorKind::Storage, e.to_string()))?;
        *self.audit_prev.borrow_mut() = h.clone();
        Ok(h)
    }
}

/// Classify a withheld model outcome for [`escalate`]. Only reasons a
/// stronger model could plausibly fix are `ModelQuality`.
fn withhold_kind(o: &Outcome) -> Option<Withhold> {
    match o {
        Outcome::Withheld { reason } if reason == NO_AUTHORIZED_SOURCE => {
            Some(Withhold::NotModelFixable)
        }
        Outcome::Withheld { .. } => Some(Withhold::ModelQuality),
        _ => None,
    }
}

const NO_AUTHORIZED_SOURCE: &str = "no authorized source";

fn decision(d: &Decision, via: &str) -> Outcome {
    Outcome::Decision {
        label: d.label(),
        detail: json!({"via": via}),
    }
}

fn last_audit_hash(path: &std::path::Path) -> Option<String> {
    let s = std::fs::read_to_string(path).ok()?;
    let last = s.lines().last()?;
    Some(hex::encode(aip_crypto::sha256(last.as_bytes())))
}

/// Verify an audit log's hash chain. Returns the number of records.
pub fn verify_audit_chain(path: &std::path::Path) -> Result<usize, String> {
    let s = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut prev = "genesis".to_string();
    for (i, line) in s.lines().enumerate() {
        let v: Value = serde_json::from_str(line).map_err(|e| format!("record {i}: {e}"))?;
        if v["prev"].as_str() != Some(prev.as_str()) {
            return Err(format!("record {i}: chain broken"));
        }
        prev = hex::encode(aip_crypto::sha256(line.as_bytes()));
    }
    Ok(s.lines().count())
}
