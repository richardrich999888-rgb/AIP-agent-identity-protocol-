//! `aip-edge-workload` — the autonomous workload of the Linux edge reference.
//!
//! **Process A. The subject under scrutiny.** It holds an agent key, performs
//! real Linux actions, and authors AIRI events about what it believes it did.
//! Everything it says about itself is a self-report; nothing it produces is
//! evidence that anything occurred.
//!
//! # What this process cannot do, by construction
//!
//! It cannot sign an observation, verify an attested batch, construct an
//! `ObservationRecord`, or assess an effect — because `aip-observe`,
//! `aip-observation` and `aip-effect` are not in its dependency graph. See
//! the manifest for the argument; the point is that this is a property of the
//! build, not of the code below behaving itself.
//!
//! # Determinism
//!
//! The process is a synchronous command loop over stdin. It never polls, never
//! sleeps, and never acts except when told to, so the driver can place kernel
//! activity exactly between two batch boundaries. Its only randomness is key
//! generation and the execution id, both of which are identity rather than
//! behaviour.
//!
//! ```text
//! identity                        → announce agent id, public key, execution id
//! connect <ip:port> [decision]    → really open a TCP connection and hold it
//! claim   <ip:port> [decision]    → author a success self-report and do nothing
//! quit
//! ```
//!
//! `claim` exists so the reference can demonstrate the case the whole system
//! is built for: a workload that says it succeeded when it did not. It is a
//! reference workload, not a test double — the events it emits are real,
//! correctly signed AIRI events, indistinguishable from honest ones except by
//! independent observation.

#![forbid(unsafe_code)]

use std::io::{BufRead, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};

use aip_airi::{
    parameter_commitment, sign_airi_event, AgentStart, AiriEvent, AiriPayload, FrameworkIdentity,
    ReportedOutcome, ToolInvocation, ToolReport, AIRI_EVENT_VERSION,
};
use aip_core::create_identity;
use aip_crypto::sha256;
use aip_edge_contract as contract;
use aip_types::{AlgorithmId, KeyPair, ProvenanceTriple, Signature};

/// The action class this workload performs, in the decision point's
/// vocabulary. Matches `aip_authorize::net_connect_action()`; the constant is
/// repeated rather than imported because importing `aip-authorize` would give
/// the subject a view of the authorization vocabulary it has no need for.
const ACTION_KIND: &str = "ghost.net.connect.v1";

/// Framework identity of this reference adapter. Not a real framework: the
/// honest label for a hand-written adapter is its own name.
const FRAMEWORK: &str = "aip-edge-reference";

fn main() {
    let dir = match parse_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("aip-edge-workload: {e}");
            std::process::exit(2);
        }
    };
    let mut w = Workload::new(dir);
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let reply = w.dispatch(line);
        println!("{reply}");
        let _ = std::io::stdout().flush();
        if line.split_whitespace().next() == Some(contract::CMD_QUIT) {
            break;
        }
    }
}

fn parse_dir() -> Result<PathBuf, String> {
    let mut it = std::env::args().skip(1);
    let mut dir = None;
    while let Some(a) = it.next() {
        match a.as_str() {
            "--dir" => dir = Some(PathBuf::from(it.next().ok_or("--dir needs a path")?)),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    dir.ok_or_else(|| "--dir is required".to_string())
}

/// The workload's own state. Its identity, its AIRI chain position, and the
/// connections it is holding open so an observer can see them.
struct Workload {
    dir: PathBuf,
    identity: Option<(String, KeyPair)>,
    execution_id: [u8; 16],
    sequence: u64,
    prev_event_hash: [u8; 32],
    /// Connections held open deliberately. Dropping one closes it, and a
    /// closed socket is gone from the kernel table before the observer reads
    /// it — so the reference holds them for the process's lifetime.
    held: Vec<TcpStream>,
}

impl Workload {
    fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            identity: None,
            // The AIRI execution instance. Chosen here because AIRI owns this
            // identifier; Skill 17 and Skill 20 reuse it verbatim rather than
            // minting one of their own.
            execution_id: random_16(),
            sequence: 0,
            prev_event_hash: [0u8; 32],
            held: Vec::new(),
        }
    }

    fn dispatch(&mut self, line: &str) -> String {
        let mut parts = line.split_whitespace();
        let verb = parts.next().unwrap_or_default();
        let rest: Vec<&str> = parts.collect();
        let outcome = match verb {
            contract::CMD_IDENTITY => self.identity_cmd(),
            contract::CMD_CONNECT => self.act(&rest, true),
            contract::CMD_CLAIM => self.act(&rest, false),
            contract::CMD_QUIT => Ok("bye".to_string()),
            other => Err(format!("unknown verb {other}")),
        };
        match outcome {
            Ok(s) => format!("{} {s}", contract::REPLY_OK),
            Err(e) => format!("{} {e}", contract::REPLY_ERR),
        }
    }

    /// Generate this workload's identity and publish the public half.
    ///
    /// The private key is generated here and stays here. The driver learns an
    /// AIP-ID and a public key, which is exactly what a verifier needs and
    /// exactly what it must not be able to sign with.
    fn identity_cmd(&mut self) -> Result<String, String> {
        if self.identity.is_some() {
            return Err("identity already established".into());
        }
        // Provenance from the executable's own path bytes: deterministic for a
        // given build, and honest — this workload has no model, no environment
        // capture and no toolchain attestation to commit to, so it commits to
        // what it actually knows.
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let tag = exe.to_string_lossy().into_owned();
        let provenance = ProvenanceTriple {
            model_commitment: sha256(format!("edge-workload-model:{tag}").as_bytes()),
            environment_commitment: sha256(format!("edge-workload-env:{tag}").as_bytes()),
            toolchain_commitment: sha256(format!("edge-workload-toolchain:{tag}").as_bytes()),
        };
        let (doc, kp) = create_identity(provenance, None).map_err(|e| format!("{e:?}"))?;
        let agent_id = doc.id.clone();

        let announcement = contract::WorkloadAnnouncement {
            version: contract::EDGE_PROTOCOL_VERSION,
            agent_id: agent_id.clone(),
            public_key: kp.public_key.clone(),
            execution_id: self.execution_id,
            self_reported_pid: std::process::id(),
        };
        write_json(
            &self.dir.join(contract::WORKLOAD_ANNOUNCEMENT),
            &announcement,
        )?;
        self.identity = Some((agent_id.clone(), kp));

        // Sequence 0 of the chain: the execution started. Emitted here so the
        // chain has a root before any action is claimed against it.
        self.emit(
            AiriPayload::AgentExecutionStarted(AgentStart {
                agent_role: Some("linux-edge-reference-workload".into()),
                framework_run_id: None,
            }),
            None,
        )?;
        Ok(format!("agent {agent_id} pid {}", std::process::id()))
    }

    /// Perform (or merely claim) the reference action.
    ///
    /// `really` is the whole point of this function. With `true` the process
    /// opens a real TCP connection and holds it, and the AIRI events describe
    /// something that happened. With `false` it emits **the same events** and
    /// does nothing — a correctly signed, chain-linked, structurally perfect
    /// account of an action that never occurred. No verifier can tell the two
    /// apart from the events alone, which is why the events alone are never
    /// enough.
    fn act(&mut self, args: &[&str], really: bool) -> Result<String, String> {
        let addr = args.first().ok_or("expected <ip:port>")?;
        let decision_id = match args.get(1) {
            Some(hex) => Some(parse_hex16(hex)?),
            None => None,
        };
        let (ip, port) = parse_v4(addr)?;
        let commitment = parameter_commitment(&contract::connect_parameter_bytes(ip, port));

        if really {
            let stream = TcpStream::connect(addr).map_err(|e| format!("connect: {e}"))?;
            // Say hello so the connection is unambiguously established at both
            // ends before the driver asks anyone to look at it.
            let mut s = stream;
            use std::io::Write as _;
            s.write_all(b"aip-edge-workload\n")
                .map_err(|e| format!("write: {e}"))?;
            self.held.push(s);
        }

        self.emit(
            AiriPayload::ToolInvocationRequested(ToolInvocation {
                tool_id: "net:tcp:connect".into(),
                action_kind: ACTION_KIND.into(),
                parameter_commitment: commitment,
                tool_call_id: None,
                target: Some(addr.to_string()),
            }),
            decision_id,
        )?;
        // The report says Success in both branches. That is not a bug in the
        // reference; it is the reference.
        self.emit(
            AiriPayload::ToolExecutionReported(ToolReport {
                tool_id: "net:tcp:connect".into(),
                parameter_commitment: commitment,
                outcome: ReportedOutcome::Success,
                result_commitment: None,
                transport_status: Some(0),
            }),
            decision_id,
        )?;
        Ok(if really {
            format!("connected {addr}")
        } else {
            format!("claimed {addr}")
        })
    }

    /// Sign one AIRI event onto the chain and append it to `claims.jsonl`.
    fn emit(&mut self, payload: AiriPayload, decision_id: Option<[u8; 16]>) -> Result<(), String> {
        let (agent_id, kp) = self
            .identity
            .as_ref()
            .ok_or("no identity: send `identity` first")?;
        // The workload's own view of the process it runs in. Self-reported and
        // labelled as such by `AiriEvent::runtime_binding`'s documentation; it
        // is carried so a verifier can compare it with a measurement, never so
        // it can stand in for one.
        let runtime_binding = aip_core::execution_binding::collect_self_binding(agent_id).ok();
        let event = AiriEvent {
            version: AIRI_EVENT_VERSION,
            agent_id: agent_id.clone(),
            execution_id: self.execution_id,
            parent_execution_id: None,
            decision_id,
            sequence: self.sequence,
            prev_event_hash: self.prev_event_hash,
            emitted_at_ms: now_ms(),
            framework: FrameworkIdentity {
                name: FRAMEWORK.into(),
                version: env!("CARGO_PKG_VERSION").into(),
                adapter_version: env!("CARGO_PKG_VERSION").into(),
            },
            runtime_binding,
            payload,
            // Placeholder. `sign_airi_event` overwrites it wholesale; it is
            // here only because the struct is total and there is no partial
            // constructor. A zeroed signature never verifies, so an event that
            // escaped before signing would be refused rather than trusted.
            signature: Signature {
                algorithm: AlgorithmId::Ed25519,
                signer_id: agent_id.clone(),
                timestamp: 0,
                nonce: [0u8; 16],
                payload_hash: [0u8; 32],
                signature_bytes: Vec::new(),
            },
        };
        let signed = sign_airi_event(&kp.private_key, agent_id, event)
            .map_err(|e| format!("sign: {e:?}"))?;
        self.prev_event_hash = signed.event_hash();
        self.sequence += 1;
        append_json(&self.dir.join(contract::CLAIMS_JSONL), &signed)
    }
}

// ─── Small helpers ───

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 16 random bytes from the same OS source the rest of the workspace uses.
fn random_16() -> [u8; 16] {
    aip_core::capability::random_jti()
}

fn parse_v4(addr: &str) -> Result<([u8; 4], u16), String> {
    let sa: std::net::SocketAddrV4 = addr
        .parse()
        .map_err(|e| format!("expected an IPv4 <ip:port>: {e}"))?;
    Ok((sa.ip().octets(), sa.port()))
}

fn parse_hex16(s: &str) -> Result<[u8; 16], String> {
    let raw = (0..s.len())
        .step_by(2)
        .map(|i| {
            s.get(i..i + 2)
                .ok_or_else(|| "odd-length hex".to_string())
                .and_then(|b| u8::from_str_radix(b, 16).map_err(|e| e.to_string()))
        })
        .collect::<Result<Vec<u8>, String>>()?;
    raw.try_into()
        .map_err(|_| "expected 16 bytes of hex".to_string())
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
