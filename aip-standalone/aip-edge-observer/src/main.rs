//! `aip-edge-observer` — the independent observer of the Linux edge reference.
//!
//! **Process B. The witness.** It holds the collector signing key, measures
//! the kernel directly, and attests batches. It is told a pid to look at and
//! nothing else: it receives no expectation, no authorization and no claim,
//! and it has no way to author one.
//!
//! # What this process cannot do, by construction
//!
//! It cannot sign an AIRI event or construct an `ExpectedExecution`, because
//! `aip-airi` and `aip-authorize` are not in its dependency graph. An observer
//! that could do either would be able to write both sides of the comparison
//! the verifier performs.
//!
//! # Where the key lives
//!
//! The Ed25519 key is generated inside this process and **only the public half
//! is ever written out**, into `observer.json`. The driver, the workload and
//! anything else on this host see a public key. That is the property the whole
//! evidence model rests on, and here it is a fact about which bytes reach the
//! filesystem rather than a promise.
//!
//! In production the collector is off the observed host entirely
//! (`OBSERVER_ATTESTATION.md` §3). Running it as a second process on the same
//! host is the *reference* topology: it establishes the process boundary, and
//! it does not establish the host boundary. A root-compromised host reaches
//! this process's memory, and nothing here claims otherwise.
//!
//! ```text
//! ready            → generate the key, announce the public half and the
//!                    probe's declared mechanisms
//! epoch            → attest an empty batch, opening a coverage epoch
//! observe <pid> [agent] [decision-hex]
//!                  → measure that instance under a pidfd anchor, read its
//!                    socket rows from the kernel table, attest the result.
//!                    The optional agent and decision are recorded as a
//!                    *claim* — the probe never checks one and never upgrades
//!                    one — so the verifier has a join key. A claim carries no
//!                    authorization meaning and this process still has no way
//!                    to construct an authorization.
//! health           → emit a signed health record
//! quit
//! ```

#![forbid(unsafe_code)]

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use aip_edge_contract as contract;
use aip_observe::{
    AgentClaim, CollectorSigner, ObservedEffect, ObserverAttestor, ProcfsProbe, SocketProtocol,
    SourceMechanism,
};

/// The mechanisms this reference observer is provisioned for.
///
/// Polling only: `PidFdAnchored` for the instance and `ProcNetTable` for its
/// sockets. Deliberately *not* the kernel-pushed tracepoint sources — they
/// need `tracefs` mounted and `perf_event_open` permission, and a reference
/// that silently needs either is a reference that fails on most hosts for
/// reasons unrelated to what it is demonstrating.
///
/// This list is the **single authoritative capability declaration** for the
/// deployment (Skill 22 Phase 7). It is declared to the probe, published in
/// `observer.json`, and projected by the verifier into its
/// `ObservationProfile`. There is no second place that says what this
/// deployment can see.
const DECLARED: [SourceMechanism; 2] =
    [SourceMechanism::PidFdAnchored, SourceMechanism::ProcNetTable];

/// TCP `ESTABLISHED`, from the kernel socket table.
const TCP_ESTABLISHED: u8 = aip_observe::tcp_state::ESTABLISHED;

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("aip-edge-observer: {e}");
            std::process::exit(2);
        }
    };
    let mut o = Observer::new(args);
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let reply = o.dispatch(line);
        println!("{reply}");
        let _ = std::io::stdout().flush();
        if line.split_whitespace().next() == Some(contract::CMD_QUIT) {
            break;
        }
    }
}

struct Args {
    dir: PathBuf,
    observer_id: String,
    probe_id: String,
}

fn parse_args() -> Result<Args, String> {
    let mut dir = None;
    let mut observer_id = "edge-reference-collector".to_string();
    let mut probe_id = "edge-reference-probe".to_string();
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--dir" => dir = Some(PathBuf::from(it.next().ok_or("--dir needs a path")?)),
            "--observer" => observer_id = it.next().ok_or("--observer needs an id")?,
            "--probe" => probe_id = it.next().ok_or("--probe needs an id")?,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(Args {
        dir: dir.ok_or("--dir is required")?,
        observer_id,
        probe_id,
    })
}

struct Observer {
    args: Args,
    /// `None` until `ready`. The key does not exist before it is needed and
    /// never leaves this struct.
    signer: Option<CollectorSigner>,
    probe: Option<ProcfsProbe>,
    next_batch: u8,
}

impl Observer {
    fn new(args: Args) -> Self {
        Self {
            args,
            signer: None,
            probe: None,
            next_batch: 1,
        }
    }

    fn dispatch(&mut self, line: &str) -> String {
        let mut parts = line.split_whitespace();
        let verb = parts.next().unwrap_or_default();
        let rest: Vec<&str> = parts.collect();
        let outcome = match verb {
            contract::CMD_READY => self.ready(),
            contract::CMD_EPOCH => self.epoch(),
            contract::CMD_OBSERVE => self.observe(&rest),
            contract::CMD_HEALTH => self.health(),
            contract::CMD_QUIT => Ok("bye".to_string()),
            other => Err(format!("unknown verb {other}")),
        };
        match outcome {
            Ok(s) => format!("{} {s}", contract::REPLY_OK),
            Err(e) => format!("{} {e}", contract::REPLY_ERR),
        }
    }

    /// Generate the collector key, provision the probe, and publish the
    /// **public** key and the declared mechanism set.
    fn ready(&mut self) -> Result<String, String> {
        if self.signer.is_some() {
            return Err("already ready".into());
        }
        let kp = aip_crypto::generate_ed25519_keypair();
        let mut signer =
            CollectorSigner::new(&self.args.observer_id, 1, &kp.private_key, &kp.public_key)
                .map_err(|e| format!("{e:?}"))?;
        // Provenance gating: this collector accepts batches only from a probe
        // an operator registered, and only claiming the mechanisms that probe
        // was provisioned for. A host-side party cannot label a fabricated
        // report as kernel-sourced.
        signer.require_registered_probes();
        signer.register_probe(&self.args.probe_id, &DECLARED);

        let mut probe = ProcfsProbe::new(&self.args.probe_id);
        for m in DECLARED {
            probe.declare_source(m);
        }

        let announcement = contract::ObserverAnnouncement {
            version: contract::EDGE_PROTOCOL_VERSION,
            observer_id: self.args.observer_id.clone(),
            key_version: signer.key_version(),
            public_key: signer.public_key().to_vec(),
            probe_id: self.args.probe_id.clone(),
            declared_mechanism_codes: DECLARED.iter().map(|m| m.code()).collect(),
        };
        write_json(
            &self.args.dir.join(contract::OBSERVER_ANNOUNCEMENT),
            &announcement,
        )?;

        self.signer = Some(signer);
        self.probe = Some(probe);
        Ok(format!(
            "observer {} key_version 1 mechanisms {}",
            self.args.observer_id,
            DECLARED.len()
        ))
    }

    /// An empty batch that opens the chain. Coverage begins with the batch
    /// *after* it: a single batch vouches for no interval.
    fn epoch(&mut self) -> Result<String, String> {
        let now = now_ms();
        let id = self.batch_id();
        let (signer, probe) = self.parts()?;
        let batch = probe.batch(id, now.saturating_sub(2_000), now.saturating_sub(1_000), vec![]);
        let attested = signer.attest(batch).map_err(|e| format!("{e:?}"))?;
        append_json(&self.args.dir.join(contract::BATCHES_JSONL), &attested)?;
        Ok(format!("epoch sequence {}", attested.sequence))
    }

    /// Measure one process instance and its sockets, and attest what was seen.
    ///
    /// The measurement is taken under a pidfd anchor, so the reads are proven
    /// to describe one instance that was still alive when they completed —
    /// pid reuse cannot slide a different process in between them.
    ///
    /// The anchored instance is recorded first even when it holds no socket,
    /// because "the instance was seen and had no such connection" is a more
    /// informative and no less honest observation than an empty batch.
    fn observe(&mut self, args: &[&str]) -> Result<String, String> {
        let pid: u32 = args
            .first()
            .ok_or("expected <pid>")?
            .parse()
            .map_err(|e| format!("pid: {e}"))?;
        // The correlation hint, when the orchestration supplies one. It is
        // recorded verbatim inside the signed bytes as
        // `AgentAttribution::Claimed`, which is a statement that *someone said
        // so*, not that it is true. `aip-observe` is explicit that this "is
        // present only so the reconciler can join; it carries no authorization
        // meaning and the observer never reads an ExpectedExecution".
        let claim = match args.get(1) {
            Some(agent) => Some(AgentClaim {
                agent_id: (*agent).to_string(),
                claim_source: "aip-edge orchestration".into(),
                decision_id: match args.get(2) {
                    Some(hex) => Some(parse_hex16(hex)?),
                    None => None,
                },
            }),
            None => None,
        };
        let from = now_ms();
        let id = self.batch_id();
        let (signer, probe) = self.parts()?;
        if let Some(c) = claim.as_ref() {
            probe.register_claim(pid, c.clone());
        }

        // An instance that ended between the driver's command and this
        // measurement is a *fact about the run*, not a failure of the
        // observer. Refusing the command outright would leave no attested
        // record of the interval at all, and a verifier would then be reading
        // silence — which is exactly the state this architecture refuses to
        // let anyone interpret. So the observer attests an empty batch: "I
        // looked, over this window, and there was nothing of this instance to
        // see." Availability, not occurrence.
        let measured = match probe.observe_sockets(pid) {
            Ok(v) => Some(v),
            // Two distinct absences, both recorded rather than raised:
            // `ProcessNotVisible` is "there is nothing at this pid" (exited,
            // never existed, or outside this PID namespace) and
            // `InstanceEnded` is "it was there and went away mid-measurement,
            // so what was read may describe nothing". Neither is a statement
            // about whether the workload did anything, and both must produce
            // an attested window rather than silence.
            Err(aip_observe::ProbeError::ProcessNotVisible { .. })
            | Err(aip_observe::ProbeError::InstanceEnded { .. }) => None,
            Err(e) => return Err(format!("{e}")),
        };
        let Some((process, effects, _malformed)) = measured else {
            let to = now_ms().max(from + 1);
            let batch = probe.batch(id, from, to, vec![]);
            let attested = signer.attest(batch).map_err(|e| format!("{e:?}"))?;
            append_json(&self.args.dir.join(contract::BATCHES_JSONL), &attested)?;
            return Ok(format!(
                "observed sequence {} established 0 instance-absent",
                attested.sequence
            ));
        };
        let wall = now_ms();
        let mut observations = vec![probe.observation_with(
            process.clone(),
            ObservedEffect::ProcessPresent,
            SourceMechanism::PidFdAnchored,
            claim.as_ref(),
            wall,
        )];
        let mut established = 0usize;
        for e in effects {
            if matches!(
                e,
                ObservedEffect::SocketObserved {
                    protocol: SocketProtocol::Tcp | SocketProtocol::Tcp6,
                    state: TCP_ESTABLISHED,
                    ..
                }
            ) {
                established += 1;
                observations.push(probe.observation_with(
                    process.clone(),
                    e,
                    SourceMechanism::ProcNetTable,
                    claim.as_ref(),
                    wall,
                ));
            }
        }
        let to = now_ms().max(from + 1);
        let batch = probe.batch(id, from, to, observations);
        let attested = signer.attest(batch).map_err(|e| format!("{e:?}"))?;
        append_json(&self.args.dir.join(contract::BATCHES_JSONL), &attested)?;
        Ok(format!(
            "observed sequence {} established {established}",
            attested.sequence
        ))
    }

    fn health(&mut self) -> Result<String, String> {
        let at = now_ms();
        let signer = self.signer.as_ref().ok_or("not ready")?;
        let health = signer.health(at).map_err(|e| format!("{e:?}"))?;
        append_json(&self.args.dir.join(contract::HEALTH_JSONL), &health)?;
        Ok(format!("health at {at}"))
    }

    fn batch_id(&mut self) -> [u8; 16] {
        let id = [self.next_batch; 16];
        self.next_batch = self.next_batch.wrapping_add(1);
        id
    }

    fn parts(&mut self) -> Result<(&mut CollectorSigner, &mut ProcfsProbe), String> {
        match (self.signer.as_mut(), self.probe.as_mut()) {
            (Some(s), Some(p)) => Ok((s, p)),
            _ => Err("not ready: send `ready` first".into()),
        }
    }
}

/// Parse 32 hex characters into 16 bytes. Refuses anything else rather than
/// padding or truncating: a decision id of the wrong length is not a decision
/// id, and half of one would join against the wrong record.
fn parse_hex16(s: &str) -> Result<[u8; 16], String> {
    if s.len() != 32 {
        return Err(format!("expected 32 hex characters, got {}", s.len()));
    }
    let raw = (0..32)
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect::<Result<Vec<u8>, String>>()?;
    raw.try_into().map_err(|_| "expected 16 bytes".to_string())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    std::fs::write(path, bytes).map_err(|e| format!("{}: {e}", path.display()))
}

fn append_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let mut line = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    line.push(b'\n');
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(&line).map_err(|e| e.to_string())
}
