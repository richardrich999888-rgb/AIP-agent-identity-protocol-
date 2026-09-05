//! ghost-demo — live end-to-end demonstrator of action-level evidence.
//!
//! **NOT_PRODUCTION_CAPABILITY.** This crate wires the real components
//! together on one Linux host so a person can watch one authorized action be
//! independently observed and reconciled, and watch each negative case land
//! in the right class. It is a demonstrator: every trust boundary that the
//! architecture requires to be a *separate process on separate trust* — the
//! decision point, the collector, the verifier — runs here in one process,
//! which is exactly what production must not do. Nothing here is fixture
//! data: the agent is a real child process, the connection is a real TCP
//! connection, the observation is read from the real kernel socket table
//! under a real pidfd anchor, and the reconciliation is the real engine.
//!
//! The action class is the only observable one: an established TCP
//! connection to `(protocol, remote_addr, remote_port)`, read by polling
//! `/proc/net/tcp` joined to `/proc/<pid>/fd`. Socket-level metadata; not a
//! kernel-pushed event; nothing about payload.

use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};

use aip_authorize::{
    net_connect_action, net_connect_parameters, ActionParameters, AuthorizationRequest, Decision,
    DecisionPoint, DecisionPointTrustAnchors, Denial, ExpectedExecution, NetProtocol,
};
use aip_core::capability::issue_scoped_token;
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_core::execution_binding::collect_binding_for_pid;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_observe::{
    AgentClaim, AttestedBatch, CollectorSigner, ObservedEffect, ObserverAttestor,
    ObserverTrustAnchors, ProbeError, ProcfsProbe, SignedSensorHealth, SocketProtocol,
    SourceMechanism,
};
use aip_reconcile::{
    reconcile_expectation, reconcile_observation, ExpectedSideCoverage, ObservationTarget,
    ObserverEvidence, ObserverSequence, Reconciliation, ReconciliationContext, TCP_ESTABLISHED,
};
use aip_types::{CapabilityScope, ExecutionBinding, KeyPair, ProvenanceTriple};

pub const TTL_MS: u64 = 60_000;
const MAX_TTL_MS: u64 = 3_600_000;
const HEALTH_MAX_AGE_MS: u64 = 60_000;
pub const OBSERVER_ID: &str = "demo-collector";
pub const PROBE_ID: &str = "demo-probe";

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn provenance(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("demo-model-{tag}").as_bytes()),
        environment_commitment: sha256(format!("demo-env-{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("demo-toolchain-{tag}").as_bytes()),
    }
}

// ─── Authorization side ───

/// A root issuer, an orchestrator, an agent identity and a decision point.
/// In production these are separate parties; here they share a process.
pub struct Authority {
    dp: DecisionPoint,
    pub anchors: DecisionPointTrustAnchors,
    pub agent_id: String,
    pub agent_kp: KeyPair,
    root: aip_types::ScopedToken,
    hop: aip_types::DelegationToken,
}

impl Authority {
    pub fn new() -> Self {
        let scope = CapabilityScope {
            allowed: vec![net_connect_action()],
            denied: vec![],
        };
        let cfo_kp = generate_ed25519_keypair();
        let cfo_id = derive_aip_id(&cfo_kp.public_key, &provenance("cfo"));
        let (orch, orch_kp) = create_identity(provenance("orchestrator"), None).unwrap();
        let (agent, agent_kp) = create_identity(provenance("agent"), None).unwrap();
        let root = issue_scoped_token(
            &cfo_id,
            &cfo_kp.private_key,
            &orch.id,
            scope.clone(),
            Some(MAX_TTL_MS),
        )
        .unwrap();
        let hop = create_delegation(&root, &orch_kp.private_key, &agent.id, scope).unwrap();
        let dp_kp = generate_ed25519_keypair();
        let dp_id = derive_aip_id(&dp_kp.public_key, &provenance("decision-point"));
        let dp = DecisionPoint::new(&dp_id, &dp_kp.private_key, &dp_kp.public_key, MAX_TTL_MS)
            .unwrap()
            .trust_issuer(&cfo_id, &cfo_kp.public_key)
            .trust_issuer(&orch.id, &orch_kp.public_key);
        let anchors = DecisionPointTrustAnchors::new().trust(&dp_id, &dp_kp.public_key);
        Self {
            dp,
            anchors,
            agent_id: agent.id,
            agent_kp,
            root,
            hop,
        }
    }

    /// Authorize `binding` to hold an established TCP connection to `remote`.
    pub fn authorize_connect(
        &self,
        binding: ExecutionBinding,
        remote: SocketAddrV4,
        now: u64,
    ) -> Result<ExpectedExecution, Denial> {
        let params = connect_params(remote);
        let req = AuthorizationRequest {
            agent_id: self.agent_id.clone(),
            root_token: self.root.clone(),
            delegation_chain: vec![self.hop.clone()],
            action_kind: net_connect_action(),
            parameters: params,
            execution_binding: binding,
            requested_ttl_ms: TTL_MS,
        };
        match self.dp.authorize_at(&req, now) {
            Decision::Authorized(ee) => Ok(*ee),
            Decision::Denied(d) => Err(d),
        }
    }

    /// Collect the Stage 1 binding of `pid` naming this agent. A self-report
    /// in production terms (the party under scrutiny hands it to the decision
    /// point); the observer measures the same facts independently.
    pub fn binding_for(&self, pid: u32) -> ExecutionBinding {
        collect_binding_for_pid(&self.agent_id, pid).expect("collect binding")
    }
}

impl Default for Authority {
    fn default() -> Self {
        Self::new()
    }
}

pub fn connect_params(remote: SocketAddrV4) -> ActionParameters {
    net_connect_parameters(NetProtocol::Tcp, &remote.ip().octets(), remote.port()).unwrap()
}

// ─── Observation side ───

/// A host-side probe and an (in-process, for the demo) collector.
pub struct Observer {
    pub probe: ProcfsProbe,
    pub signer: CollectorSigner,
    pub anchors: ObserverTrustAnchors,
    next_batch: u8,
}

impl Observer {
    pub fn new() -> Self {
        let kp = generate_ed25519_keypair();
        let mut signer =
            CollectorSigner::new(OBSERVER_ID, 1, &kp.private_key, &kp.public_key).unwrap();
        signer.register_probe(PROBE_ID, &SourceMechanism::ALL);
        let mut probe = ProcfsProbe::new(PROBE_ID);
        probe.declare_source(SourceMechanism::PidFdAnchored);
        probe.declare_source(SourceMechanism::ProcNetTable);
        let anchors = ObserverTrustAnchors::new().trust(OBSERVER_ID, 1, &kp.public_key);
        Self {
            probe,
            signer,
            anchors,
            next_batch: 1,
        }
    }

    fn batch_id(&mut self) -> [u8; 16] {
        let id = [self.next_batch; 16];
        self.next_batch += 1;
        id
    }

    /// An empty batch that opens the chain. Coverage begins with the batch
    /// after it (Skill 6 epoch semantics).
    pub fn epoch_start(&mut self, now: u64) -> AttestedBatch {
        let id = self.batch_id();
        self.signer
            .attest(self.probe.batch(id, now - 2_000, now - 1_000, vec![]))
            .unwrap()
    }

    /// Read the socket table for `pid` under a pidfd anchor and attest every
    /// established TCP connection as one observation. Returns the batch and
    /// how many established connections it carries.
    pub fn observe_connections(
        &mut self,
        pid: u32,
        claim: Option<&AgentClaim>,
    ) -> Result<(AttestedBatch, usize), ProbeError> {
        let from = now_ms();
        let (process, effects, _malformed) = self.probe.observe_sockets(pid)?;
        let wall = now_ms();
        // The anchored instance itself is recorded first, so a window with no
        // connection still shows *that the instance was seen* — the negative
        // "seen, but no such connection" is more informative than an empty
        // batch, and no less honest.
        let mut obs = vec![self.probe.observation_with(
            process.clone(),
            ObservedEffect::ProcessPresent,
            SourceMechanism::PidFdAnchored,
            claim,
            wall,
        )];
        let mut n = 0usize;
        for e in effects {
            if matches!(
                e,
                ObservedEffect::SocketObserved {
                    protocol: SocketProtocol::Tcp | SocketProtocol::Tcp6,
                    state: TCP_ESTABLISHED,
                    ..
                }
            ) {
                n += 1;
                obs.push(self.probe.observation_with(
                    process.clone(),
                    e,
                    SourceMechanism::ProcNetTable,
                    claim,
                    wall,
                ));
            }
        }
        let to = now_ms().max(from + 1);
        let id = self.batch_id();
        let b = self
            .signer
            .attest(self.probe.batch(id, from, to, obs))
            .unwrap();
        Ok((b, n))
    }

    pub fn health(&self, at: u64) -> SignedSensorHealth {
        self.signer.health(at).unwrap()
    }
}

impl Default for Observer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── The controlled agent process ───

pub struct Agent {
    child: Child,
    /// The accepted server side of the agent's connection, held so the
    /// connection stays ESTABLISHED for the observation.
    _accepted: Option<TcpStream>,
    pub pid: u32,
}

impl Agent {
    /// Spawn the agent binary and have it connect to `listener`. Returns once
    /// the connection is accepted and the agent has said hello.
    pub fn connect(agent_bin: &str, listener: &TcpListener) -> Agent {
        let target = listener.local_addr().unwrap();
        let mut child = Command::new(agent_bin)
            .arg(target.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn agent");
        let (accepted, _) = listener.accept().expect("accept");
        let mut line = String::new();
        BufReader::new(accepted.try_clone().unwrap())
            .read_line(&mut line)
            .expect("hello");
        assert_eq!(line.trim(), "ghost-demo-agent connected");
        let pid = child.id();
        // Keep stdin open so the child stays alive; drop it on `Drop`.
        let _ = &mut child;
        Agent {
            child,
            _accepted: Some(accepted),
            pid,
        }
    }

    /// Spawn the agent binary, have it connect to `listener`, say hello and
    /// close the connection immediately. Returns once the peer has closed:
    /// by then no ESTABLISHED row for it exists in any table.
    pub fn connect_then_close(agent_bin: &str, listener: &TcpListener) -> Agent {
        let target = listener.local_addr().unwrap();
        let child = Command::new(agent_bin)
            .args(["--connect-close", &target.to_string()])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn agent");
        let (accepted, _) = listener.accept().expect("accept");
        let mut reader = BufReader::new(accepted);
        let mut line = String::new();
        reader.read_line(&mut line).expect("hello");
        assert_eq!(line.trim(), "ghost-demo-agent connected");
        // Drain to EOF: the agent has closed its end.
        let mut rest = String::new();
        let _ = reader.read_line(&mut rest);
        let pid = child.id();
        Agent {
            child,
            _accepted: None,
            pid,
        }
    }

    /// Spawn the agent binary without any connection.
    pub fn idle(agent_bin: &str) -> Agent {
        let child = Command::new(agent_bin)
            .arg("--idle")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn idle agent");
        let pid = child.id();
        Agent {
            child,
            _accepted: None,
            pid,
        }
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ─── Scenarios ───

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    /// The honest case: authorized connection, made, observed, reconciled.
    Positive,
    /// A. Expected but not executed: the agent never connects.
    ExpectedNotExecuted,
    /// B. Executed but not expected: an observation with no expectation.
    ExecutedNotExpected,
    /// C. Expected action, different parameters: authorized port differs.
    DifferentParameters,
    /// D. Correct action from the wrong process instance.
    WrongInstance,
    /// E. Observation lost: the probe reports counted loss over the window.
    LostObservation,
    /// F. Replayed evidence: the attested batch offered against a second,
    ///    different decision — and duplicated in the evidence set.
    ReplayedEvidence,
    /// G. Tampered evidence: a byte of the attested observation altered.
    TamperedEvidence,
    /// T-A. The connection is established and attested **before** the
    /// decision is issued, and stays open into the authorized window.
    PreExistingConnection,
    /// T-C. The connection is made and closed inside the window, before any
    /// poll of the socket table could see it.
    ConnectThenClose,
}

impl Scenario {
    pub const ALL: [Scenario; 10] = [
        Scenario::Positive,
        Scenario::ExpectedNotExecuted,
        Scenario::ExecutedNotExpected,
        Scenario::DifferentParameters,
        Scenario::WrongInstance,
        Scenario::LostObservation,
        Scenario::ReplayedEvidence,
        Scenario::TamperedEvidence,
        Scenario::PreExistingConnection,
        Scenario::ConnectThenClose,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            Scenario::Positive => "positive: authorized connection observed",
            Scenario::ExpectedNotExecuted => "A. expected but not executed",
            Scenario::ExecutedNotExpected => "B. executed but not expected",
            Scenario::DifferentParameters => "C. expected action, different parameters",
            Scenario::WrongInstance => "D. correct action, wrong process instance",
            Scenario::LostObservation => "E. observation lost",
            Scenario::ReplayedEvidence => "F. replayed evidence",
            Scenario::TamperedEvidence => "G. tampered evidence",
            Scenario::PreExistingConnection => {
                "T-A. connection established and attested before authorization"
            }
            Scenario::ConnectThenClose => "T-C. connection made and closed before any poll",
        }
    }
}

/// One scenario's outcome, with the facts a reader needs to check it.
pub struct Demo {
    pub scenario: Scenario,
    pub reconciliation: Reconciliation,
    pub note: String,
}

fn ctx(a: &Authority, o: &Observer, at: u64) -> ReconciliationContext {
    ReconciliationContext {
        decision_point_anchors: a.anchors.clone(),
        observer_anchors: o.anchors.clone(),
        verification_time_ms: at,
        health_max_age_ms: HEALTH_MAX_AGE_MS,
        window_tolerance_ms: 0,
        expected_side: ExpectedSideCoverage::Unknown,
        agent_public_key: Some(a.agent_kp.public_key.clone()),
    }
}

fn claim(a: &Authority, ee: &ExpectedExecution) -> AgentClaim {
    AgentClaim {
        agent_id: a.agent_id.clone(),
        claim_source: "ghost-demo".into(),
        decision_id: Some(ee.decision_id),
    }
}

fn v4(listener: &TcpListener) -> SocketAddrV4 {
    match listener.local_addr().unwrap() {
        std::net::SocketAddr::V4(a) => a,
        _ => panic!("demo listener is IPv4"),
    }
}

/// Run one scenario against a freshly spawned agent. Linux only: needs
/// procfs, pidfd and the kernel socket tables.
pub fn run(scenario: Scenario, agent_bin: &str) -> Demo {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let remote = v4(&listener);
    let a = Authority::new();
    let mut o = Observer::new();

    match scenario {
        Scenario::Positive => {
            let agent = Agent::connect(agent_bin, &listener);
            let binding = a.binding_for(agent.pid);
            let now = now_ms();
            let ee = a.authorize_connect(binding, remote, now).unwrap();
            let b1 = o.epoch_start(now);
            let c = claim(&a, &ee);
            let (b2, n) = o.observe_connections(agent.pid, Some(&c)).unwrap();
            let at = now_ms().max(b2.batch.claimed_to_ms);
            let ev = ObserverEvidence {
                batches: vec![b1, b2],
                health: o.health(at),
            };
            let r = reconcile_expectation(&ee, Some(&ev), &ctx(&a, &o, at));
            Demo {
                scenario,
                reconciliation: r,
                note: format!(
                    "agent pid {} → {remote}; {n} established connection(s) read from the socket table",
                    agent.pid
                ),
            }
        }
        Scenario::ExpectedNotExecuted => {
            let agent = Agent::idle(agent_bin);
            let binding = a.binding_for(agent.pid);
            let now = now_ms();
            let ee = a.authorize_connect(binding, remote, now).unwrap();
            let b1 = o.epoch_start(now);
            let c = claim(&a, &ee);
            let (b2, n) = o.observe_connections(agent.pid, Some(&c)).unwrap();
            let at = now_ms().max(b2.batch.claimed_to_ms);
            let ev = ObserverEvidence {
                batches: vec![b1, b2],
                health: o.health(at),
            };
            let r = reconcile_expectation(&ee, Some(&ev), &ctx(&a, &o, at));
            Demo {
                scenario,
                reconciliation: r,
                note: format!(
                    "agent pid {} never connected; {n} established connection(s); polled coverage cannot support PHANTOM_CLAIM",
                    agent.pid
                ),
            }
        }
        Scenario::ExecutedNotExpected => {
            let agent = Agent::connect(agent_bin, &listener);
            let now = now_ms();
            let b1 = o.epoch_start(now);
            let c = AgentClaim {
                agent_id: a.agent_id.clone(),
                claim_source: "ghost-demo".into(),
                decision_id: None,
            };
            let (b2, n) = o.observe_connections(agent.pid, Some(&c)).unwrap();
            let at = now_ms().max(b2.batch.claimed_to_ms);
            let seq = b2.sequence;
            let ev = ObserverEvidence {
                batches: vec![b1, b2],
                health: o.health(at),
            };
            let r = reconcile_observation(
                &ev,
                ObservationTarget::Observation {
                    batch_sequence: ObserverSequence(seq),
                    index: 0,
                },
                &ctx(&a, &o, at),
            );
            Demo {
                scenario,
                reconciliation: r,
                note: format!(
                    "agent pid {} connected with no decision; {n} connection(s); expected-side completeness is unknown",
                    agent.pid
                ),
            }
        }
        Scenario::DifferentParameters => {
            let agent = Agent::connect(agent_bin, &listener);
            let binding = a.binding_for(agent.pid);
            let now = now_ms();
            let other = SocketAddrV4::new(*remote.ip(), remote.port().wrapping_add(1).max(1));
            let ee = a.authorize_connect(binding, other, now).unwrap();
            let b1 = o.epoch_start(now);
            let c = claim(&a, &ee);
            let (b2, n) = o.observe_connections(agent.pid, Some(&c)).unwrap();
            let at = now_ms().max(b2.batch.claimed_to_ms);
            let ev = ObserverEvidence {
                batches: vec![b1, b2],
                health: o.health(at),
            };
            let r = reconcile_expectation(&ee, Some(&ev), &ctx(&a, &o, at));
            Demo {
                scenario,
                reconciliation: r,
                note: format!("authorized {other}, agent connected to {remote}; {n} connection(s)"),
            }
        }
        Scenario::WrongInstance => {
            // The decision is bound to an idle instance; a different instance
            // makes the connection and claims that decision.
            let bound = Agent::idle(agent_bin);
            let actor = Agent::connect(agent_bin, &listener);
            let binding = a.binding_for(bound.pid);
            let now = now_ms();
            let ee = a.authorize_connect(binding, remote, now).unwrap();
            let b1 = o.epoch_start(now);
            let c = claim(&a, &ee);
            let (b2, n) = o.observe_connections(actor.pid, Some(&c)).unwrap();
            let at = now_ms().max(b2.batch.claimed_to_ms);
            let ev = ObserverEvidence {
                batches: vec![b1, b2],
                health: o.health(at),
            };
            let r = reconcile_expectation(&ee, Some(&ev), &ctx(&a, &o, at));
            Demo {
                scenario,
                reconciliation: r,
                note: format!(
                    "decision bound to pid {}, connection made by pid {} (same binary); {n} connection(s)",
                    bound.pid, actor.pid
                ),
            }
        }
        Scenario::LostObservation => {
            let agent = Agent::connect(agent_bin, &listener);
            let binding = a.binding_for(agent.pid);
            let now = now_ms();
            let ee = a.authorize_connect(binding, remote, now).unwrap();
            o.probe.enable_loss_counter();
            let b1 = o.epoch_start(now);
            // The source reports loss before the batch that would carry the
            // observation: whatever it carries, the window is degraded.
            o.probe.record_lost_events(1);
            let c = claim(&a, &ee);
            let (b2, n) = o.observe_connections(agent.pid, Some(&c)).unwrap();
            let at = now_ms().max(b2.batch.claimed_to_ms);
            let ev = ObserverEvidence {
                batches: vec![b1, b2],
                health: o.health(at),
            };
            let r = reconcile_expectation(&ee, Some(&ev), &ctx(&a, &o, at));
            Demo {
                scenario,
                reconciliation: r,
                note: format!(
                    "{n} connection(s) observed, but the probe reported 1 lost event over the window"
                ),
            }
        }
        Scenario::ReplayedEvidence => {
            let agent = Agent::connect(agent_bin, &listener);
            let binding = a.binding_for(agent.pid);
            let now = now_ms();
            let ee1 = a.authorize_connect(binding.clone(), remote, now).unwrap();
            let ee2 = a.authorize_connect(binding, remote, now).unwrap();
            let b1 = o.epoch_start(now);
            let c = claim(&a, &ee1);
            let (b2, _n) = o.observe_connections(agent.pid, Some(&c)).unwrap();
            let at = now_ms().max(b2.batch.claimed_to_ms);
            // Evidence produced under decision 1, offered twice, against
            // decision 2.
            let ev = ObserverEvidence {
                batches: vec![b1, b2.clone(), b2],
                health: o.health(at),
            };
            let r = reconcile_expectation(&ee2, Some(&ev), &ctx(&a, &o, at));
            Demo {
                scenario,
                reconciliation: r,
                note: "the batch claimed under decision 1 was duplicated and offered against decision 2"
                    .into(),
            }
        }
        Scenario::PreExistingConnection => {
            // 1. The connection exists and is observed/attested first …
            let agent = Agent::connect(agent_bin, &listener);
            let binding = a.binding_for(agent.pid);
            let t0 = now_ms();
            let b1 = o.epoch_start(t0);
            let (b2, n_before) = o.observe_connections(agent.pid, None).unwrap();
            // … 2. then the decision is issued …
            std::thread::sleep(std::time::Duration::from_millis(20));
            let now = now_ms().max(b2.batch.claimed_to_ms + 1);
            let ee = a.authorize_connect(binding, remote, now).unwrap();
            // … 3. and the still-open connection is observed again inside the
            // window, now under the decision's claim.
            let c = claim(&a, &ee);
            let (b3, n_after) = o.observe_connections(agent.pid, Some(&c)).unwrap();
            let at = now_ms().max(b3.batch.claimed_to_ms);
            let ev = ObserverEvidence {
                batches: vec![b1, b2, b3],
                health: o.health(at),
            };
            let r = reconcile_expectation(&ee, Some(&ev), &ctx(&a, &o, at));
            Demo {
                scenario,
                reconciliation: r,
                note: format!(
                    "connection to {remote} observed ({n_before}) and attested before the decision at {now}; observed again ({n_after}) inside the window"
                ),
            }
        }
        Scenario::ConnectThenClose => {
            let b1 = o.epoch_start(now_ms());
            // The window opens now; the agent connects and closes inside it.
            // The decision is signed at `now` for the binding of the process
            // that did it (the process stays alive, idle, after closing).
            let now = now_ms();
            let agent = Agent::connect_then_close(agent_bin, &listener);
            let binding = a.binding_for(agent.pid);
            let ee = a.authorize_connect(binding, remote, now).unwrap();
            // The connection is already closed: no poll can see it.
            let c = claim(&a, &ee);
            let (b2, n) = o.observe_connections(agent.pid, Some(&c)).unwrap();
            let at = now_ms().max(b2.batch.claimed_to_ms);
            let ev = ObserverEvidence {
                batches: vec![b1, b2],
                health: o.health(at),
            };
            let r = reconcile_expectation(&ee, Some(&ev), &ctx(&a, &o, at));
            Demo {
                scenario,
                reconciliation: r,
                note: format!(
                    "agent pid {} connected to {remote} and closed before the table was read; {n} established connection(s) in the poll",
                    agent.pid
                ),
            }
        }
        Scenario::TamperedEvidence => {
            let agent = Agent::connect(agent_bin, &listener);
            let binding = a.binding_for(agent.pid);
            let now = now_ms();
            let ee = a.authorize_connect(binding, remote, now).unwrap();
            let b1 = o.epoch_start(now);
            let c = claim(&a, &ee);
            let (mut b2, _n) = o.observe_connections(agent.pid, Some(&c)).unwrap();
            let at = now_ms().max(b2.batch.claimed_to_ms);
            let health = o.health(at);
            // After attestation: move the observed connection to another port.
            for obs in &mut b2.batch.observations {
                if let ObservedEffect::SocketObserved { remote, .. } = &mut obs.effect {
                    remote.port ^= 1;
                }
            }
            let ev = ObserverEvidence {
                batches: vec![b1, b2],
                health,
            };
            let r = reconcile_expectation(&ee, Some(&ev), &ctx(&a, &o, at));
            Demo {
                scenario,
                reconciliation: r,
                note: "remote port flipped inside the attested batch after signing".into(),
            }
        }
    }
}

/// Run every scenario.
pub fn run_all(agent_bin: &str) -> Vec<Demo> {
    Scenario::ALL.iter().map(|s| run(*s, agent_bin)).collect()
}
