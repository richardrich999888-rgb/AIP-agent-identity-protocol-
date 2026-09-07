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
    fs_write_action, fs_write_parameters, net_connect_action, net_connect_parameters,
    net_send_action, net_send_parameters, process_exec_action, process_exec_parameters,
    ActionParameters, AuthorizationRequest, Decision, DecisionPoint, DecisionPointTrustAnchors,
    Denial, ExpectedExecution, NetProtocol,
};
use aip_core::capability::issue_scoped_token;
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_core::execution_binding::collect_binding_for_pid;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_observe::{
    boot_clock_anchor, AgentClaim, AttestedBatch, CollectorSigner, FanotifyWatch, ObservedEffect,
    ObserverAttestor, ObserverTrustAnchors, ProbeError, ProcessTracer, ProcfsProbe,
    SignedSensorHealth, SockSendTracer, SockStateTracer, SocketProtocol, SourceMechanism, WireTap,
    FAN_CLOSE_WRITE,
};
use aip_reconcile::{
    reconcile_expectation, reconcile_observation, ExpectedSideCoverage, ObservationTarget,
    ObserverEvidence, ObserverSequence, Reconciliation, ReconciliationContext, TCP_ESTABLISHED,
};
use aip_types::{CapabilityScope, ExecutionBinding, KeyPair, ProvenanceTriple};

pub const TTL_MS: u64 = 60_000;
const MAX_TTL_MS: u64 = 3_600_000;
pub const HEALTH_MAX_AGE_MS: u64 = 60_000;
pub const OBSERVER_ID: &str = "demo-collector";
/// Images the exec scenarios run and authorize. Hashed by content.
pub const SLEEP_BIN: &str = "/bin/sleep";
pub const TRUE_BIN: &str = "/bin/true";
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
    /// issuer AIP-ID → public key, for a verifier that must check the chain.
    pub issuer_keys: std::collections::HashMap<String, Vec<u8>>,
}

impl Authority {
    pub fn new() -> Self {
        let scope = CapabilityScope {
            allowed: vec![
                net_connect_action(),
                process_exec_action(),
                net_send_action(),
                fs_write_action(),
            ],
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
        let issuer_keys = std::collections::HashMap::from([
            (cfo_id, cfo_kp.public_key.clone()),
            (orch.id, orch_kp.public_key.clone()),
        ]);
        Self {
            dp,
            anchors,
            agent_id: agent.id,
            agent_kp,
            root,
            hop,
            issuer_keys,
        }
    }

    /// The authority chain behind every decision this instance makes, and
    /// the issuer keys that check it. A NEXORA package carries both so a
    /// verifier elsewhere can follow the chain without asking anyone.
    pub fn authority(&self) -> (aip_types::ScopedToken, Vec<aip_types::DelegationToken>) {
        (self.root.clone(), vec![self.hop.clone()])
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

    /// Authorize `binding` to send application bytes on a TCP connection to
    /// `remote` (`ghost.net.send.v1`): the endpoint is authorized, the byte
    /// count is not part of it, and nothing about the bytes is.
    pub fn authorize_send(
        &self,
        binding: ExecutionBinding,
        remote: SocketAddrV4,
        now: u64,
    ) -> Result<ExpectedExecution, Denial> {
        let params =
            net_send_parameters(NetProtocol::Tcp, &remote.ip().octets(), remote.port()).unwrap();
        let req = AuthorizationRequest {
            agent_id: self.agent_id.clone(),
            root_token: self.root.clone(),
            delegation_chain: vec![self.hop.clone()],
            action_kind: net_send_action(),
            parameters: params,
            execution_binding: binding,
            requested_ttl_ms: TTL_MS,
        };
        match self.dp.authorize_at(&req, now) {
            Decision::Authorized(ee) => Ok(*ee),
            Decision::Denied(d) => Err(d),
        }
    }

    /// Authorize `binding` to complete a write to the file at `path`
    /// (`ghost.fs.write.v1`): the path bytes are authorized, nothing about
    /// the content is.
    pub fn authorize_write(
        &self,
        binding: ExecutionBinding,
        path: &str,
        now: u64,
    ) -> Result<ExpectedExecution, Denial> {
        let req = AuthorizationRequest {
            agent_id: self.agent_id.clone(),
            root_token: self.root.clone(),
            delegation_chain: vec![self.hop.clone()],
            action_kind: fs_write_action(),
            parameters: fs_write_parameters(path).expect("absolute path"),
            execution_binding: binding,
            requested_ttl_ms: TTL_MS,
        };
        match self.dp.authorize_at(&req, now) {
            Decision::Authorized(ee) => Ok(*ee),
            Decision::Denied(d) => Err(d),
        }
    }

    /// Authorize `binding` to spawn a child executing an image with this
    /// content hash.
    pub fn authorize_exec(
        &self,
        binding: ExecutionBinding,
        exe_sha256: [u8; 32],
        now: u64,
    ) -> Result<ExpectedExecution, Denial> {
        let req = AuthorizationRequest {
            agent_id: self.agent_id.clone(),
            root_token: self.root.clone(),
            delegation_chain: vec![self.hop.clone()],
            action_kind: process_exec_action(),
            parameters: exec_params(exe_sha256),
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

/// The process-execution parameters: the executable's **content** hash
/// (Stage 1 identity rule: never a path), through the shared vocabulary.
pub fn exec_params(exe_sha256: [u8; 32]) -> ActionParameters {
    process_exec_parameters(exe_sha256)
}

/// SHA-256 of a file's contents, as the observer will hash `/proc/<pid>/exe`.
pub fn hash_binary(path: &str) -> [u8; 32] {
    aip_core::execution_binding::hash_file_contents(std::path::Path::new(path))
        .expect("hash binary")
}

// ─── Observation side ───

/// A host-side probe and an (in-process, for the demo) collector.
pub struct Observer {
    pub probe: ProcfsProbe,
    pub signer: CollectorSigner,
    pub anchors: ObserverTrustAnchors,
    /// The kernel-pushed socket-state source, when this observer has one.
    tracer: Option<SockStateTracer>,
    /// The kernel-pushed fork/exec source, when this observer has one.
    process_tracer: Option<ProcessTracer>,
    /// The device-layer tap (`AF_PACKET`, headers only), when this observer
    /// has one. Bound to every device so loopback traffic is seen.
    wire_tap: Option<WireTap>,
    /// The kernel-pushed socket-send source (`sock:sock_send_length`), when
    /// this observer has one.
    send_tracer: Option<SockSendTracer>,
    /// The fanotify watch on the mount that holds the temp directory, when
    /// this observer has one (`FAN_CLOSE_WRITE`, `FAN_REPORT_PIDFD`).
    fanotify: Option<FanotifyWatch>,
    next_batch: u8,
}

/// Directory the file scenarios write into: under the temp directory, on
/// whatever mount holds it.
pub fn demo_dir() -> std::path::PathBuf {
    let nonce: String = aip_core::capability::random_jti()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    std::env::temp_dir().join(format!("ghost-demo-{}-{nonce}", std::process::id()))
}

/// Can this host provide the fanotify mount watch? `Err` names what is
/// missing (`CAP_SYS_ADMIN`, or a refused mark).
pub fn fanotify_available() -> Result<(), String> {
    let dir = std::env::temp_dir();
    FanotifyWatch::open(dir.to_str().unwrap_or("/tmp"), FAN_CLOSE_WRITE)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Can this host provide the socket-send tracepoint? `Err` names what is
/// missing (tracefs, the tracepoint on kernels before 6.4, perf permission).
pub fn send_tracer_available() -> Result<(), String> {
    SockSendTracer::open()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Can this host provide the kernel-pushed sources (socket state and
/// fork/exec)? `Err` names what is missing (tracefs, perf permission).
/// Nothing is simulated when it cannot.
pub fn tracer_available() -> Result<(), String> {
    SockStateTracer::open().map_err(|e| e.to_string())?;
    ProcessTracer::open().map(|_| ()).map_err(|e| e.to_string())
}

/// Can this host provide the device-layer tap? `Err` names what is missing
/// (`CAP_NET_RAW`). Nothing is simulated when it cannot.
pub fn wire_tap_available() -> Result<(), String> {
    WireTap::open(None).map(|_| ()).map_err(|e| e.to_string())
}

impl Observer {
    /// Polling only: `PidFdAnchored` process facts and `ProcNetTable` socket
    /// rows. This is the Stage 7 observer, kept as it was.
    pub fn new() -> Self {
        Self::build(None, None, None, None, None)
    }

    /// Polling plus the kernel-pushed `sock:inet_sock_set_state` and
    /// `sched` tracepoints through `perf_event_open`, plus the device-layer
    /// tap where the host permits it (the tap is optional: without it the
    /// wire question is simply `Unavailable`). Fails where the tracepoints
    /// are not permitted.
    pub fn with_tracer() -> Result<Self, String> {
        Self::with_sources(true, true)
    }

    /// As [`Observer::with_tracer`] but never opens the tap, so the wire
    /// question is `Unavailable` by construction.
    pub fn with_tracer_no_tap() -> Result<Self, String> {
        Self::with_sources(false, true)
    }

    /// Polling plus the fanotify mount watch only: what the file scenarios
    /// need. Fails where the host does not permit fanotify.
    pub fn with_fanotify() -> Result<Self, String> {
        let watch = FanotifyWatch::open(
            std::env::temp_dir().to_str().unwrap_or("/tmp"),
            FAN_CLOSE_WRITE,
        )
        .map_err(|e| e.to_string())?;
        Ok(Self::build(None, None, None, None, Some(watch)))
    }

    /// Every source an observer opens is a host-wide stream it must drain
    /// every batch, and an undrained stream reports loss, which degrades
    /// the observer (correctly). A scenario therefore opens only what it
    /// needs: the two tracepoint sources always, the device tap and the
    /// send tracepoint on request.
    fn with_sources(tap: bool, send: bool) -> Result<Self, String> {
        let tracer = SockStateTracer::open().map_err(|e| e.to_string())?;
        let process_tracer = ProcessTracer::open().map_err(|e| e.to_string())?;
        let wire_tap = if tap { WireTap::open(None).ok() } else { None };
        // Optional like the tap: where the tracepoint does not exist the
        // send class is simply unobservable.
        let send_tracer = if send {
            SockSendTracer::open().ok()
        } else {
            None
        };
        // The mount-wide fanotify watch is opened only by the file scenarios
        // (`with_fanotify`): every source an observer opens costs a drain per
        // batch, and a watch over every write on the host is the heaviest.
        Ok(Self::build(
            Some(tracer),
            Some(process_tracer),
            wire_tap,
            send_tracer,
            None,
        ))
    }

    fn build(
        tracer: Option<SockStateTracer>,
        process_tracer: Option<ProcessTracer>,
        wire_tap: Option<WireTap>,
        send_tracer: Option<SockSendTracer>,
        fanotify: Option<FanotifyWatch>,
    ) -> Self {
        let kp = generate_ed25519_keypair();
        let mut signer =
            CollectorSigner::new(OBSERVER_ID, 1, &kp.private_key, &kp.public_key).unwrap();
        signer.register_probe(PROBE_ID, &SourceMechanism::ALL);
        let mut probe = ProcfsProbe::new(PROBE_ID);
        probe.declare_source(SourceMechanism::PidFdAnchored);
        probe.declare_source(SourceMechanism::ProcNetTable);
        if process_tracer.is_some() {
            probe.declare_source(SourceMechanism::SchedTracepoint);
        }
        if tracer.is_some() {
            probe.declare_source(SourceMechanism::SockStateTracepoint);
            // The perf ring reports loss; from here on "no loss" is a counted
            // zero rather than an absence.
            probe.enable_loss_counter();
        }
        if wire_tap.is_some() {
            probe.declare_source(SourceMechanism::WireTapAfPacket);
            probe.enable_loss_counter();
        }
        if send_tracer.is_some() {
            probe.declare_source(SourceMechanism::SockSendTracepoint);
            probe.enable_loss_counter();
        }
        if fanotify.is_some() {
            probe.declare_source(SourceMechanism::Fanotify);
            probe.enable_loss_counter();
        }
        // Every kernel-stamped source needs the clock anchor for its events
        // to be placed on the wall clock the decision point speaks; without
        // it a matching event is `KernelTimeUnanchored`, never verified.
        if tracer.is_some()
            || process_tracer.is_some()
            || wire_tap.is_some()
            || send_tracer.is_some()
            || fanotify.is_some()
        {
            if let Ok(anchor) = boot_clock_anchor() {
                probe.declare_clock_anchor(anchor);
            }
        }
        let anchors = ObserverTrustAnchors::new().trust(OBSERVER_ID, 1, &kp.public_key);
        Self {
            probe,
            signer,
            anchors,
            tracer,
            process_tracer,
            wire_tap,
            send_tracer,
            fanotify,
            next_batch: 1,
        }
    }

    /// Whether this observer has the device-layer tap open.
    pub fn has_wire_tap(&self) -> bool {
        self.wire_tap.is_some()
    }

    /// Move every socket transition the kernel has reported so far into the
    /// probe (anchoring `connect()` initiations to their instance), and
    /// account for any loss the perf ring reported.
    pub fn drain_kernel_events(&mut self) {
        // Re-anchor the three clocks for this batch: a suspend since the last
        // anchor would otherwise shift the boot↔monotonic relation silently.
        if self.tracer.is_some()
            || self.process_tracer.is_some()
            || self.wire_tap.is_some()
            || self.send_tracer.is_some()
            || self.fanotify.is_some()
        {
            if let Ok(anchor) = boot_clock_anchor() {
                self.probe.declare_clock_anchor(anchor);
            }
        }
        // A short wait lets in-flight events from a just-completed action
        // land in the rings before the batch closes: a source is drained until
        // it has been quiet past the short deadline, and never beyond the hard
        // deadline whatever keeps arriving (host-wide sources fire for every
        // process). What is left in a ring is carried by a later batch, placed
        // by its kernel stamp.
        if let Some(tracer) = self.tracer.as_mut() {
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(50);
            let hard_deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                match tracer.next_event(10) {
                    Ok(Some(ev)) => {
                        self.probe.ingest_socket_event(ev);
                        if std::time::Instant::now() >= hard_deadline {
                            break;
                        }
                    }
                    Ok(None) => {
                        if std::time::Instant::now() >= deadline {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let lost = tracer.take_lost();
            if lost > 0 {
                self.probe.record_lost_events(lost);
            }
        }
        if let Some(tracer) = self.process_tracer.as_mut() {
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(50);
            let hard_deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                match tracer.next_event(10) {
                    Ok(Some(ev)) => {
                        self.probe.ingest_sched_event(ev);
                        if std::time::Instant::now() >= hard_deadline {
                            break;
                        }
                    }
                    Ok(None) => {
                        if std::time::Instant::now() >= deadline {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let lost = tracer.take_lost();
            if lost > 0 {
                self.probe.record_lost_events(lost);
            }
        }
        if let Some(tap) = self.wire_tap.as_mut() {
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(50);
            let hard_deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                match tap.next_event(10) {
                    Ok(Some(ev)) => {
                        self.probe.ingest_wire_event(ev);
                        if std::time::Instant::now() >= hard_deadline {
                            break;
                        }
                    }
                    Ok(None) => {
                        if std::time::Instant::now() >= deadline {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let lost = tap.take_lost();
            if lost > 0 {
                self.probe.record_lost_events(lost);
            }
        }
        if let Some(tracer) = self.send_tracer.as_mut() {
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(50);
            let hard_deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                match tracer.next_event(10) {
                    Ok(Some(ev)) => {
                        self.probe.ingest_send_event(ev);
                        if std::time::Instant::now() >= hard_deadline {
                            break;
                        }
                    }
                    Ok(None) => {
                        if std::time::Instant::now() >= deadline {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let lost = tracer.take_lost();
            if lost > 0 {
                self.probe.record_lost_events(lost);
            }
        }
        if let Some(watch) = self.fanotify.as_mut() {
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(50);
            let hard_deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                match watch.next_event(10) {
                    Ok(Some(obs)) => {
                        self.probe.ingest_file_event(obs);
                        if std::time::Instant::now() >= hard_deadline {
                            break;
                        }
                    }
                    Ok(None) => {
                        if std::time::Instant::now() >= deadline {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let lost = watch.take_lost();
            if lost > 0 {
                self.probe.record_lost_events(lost);
            }
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
        self.drain_kernel_events();
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
        // The host-side claim for this pid is registered with the probe so
        // kernel events about the pid carry it too — as a claim, nothing more.
        if let Some(c) = claim {
            self.probe.register_claim(pid, c.clone());
        }
        self.drain_kernel_events();
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

    /// Spawn the agent binary and have it spawn `program` as its own child.
    /// Returns once the agent has reported the child's pid.
    pub fn spawning(agent_bin: &str, program: &str, args: &[&str]) -> (Agent, u32) {
        let mut child = Command::new(agent_bin)
            .arg("--spawn")
            .arg(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn agent");
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .expect("spawned line");
        let child_pid: u32 = line
            .trim()
            .strip_prefix("spawned ")
            .and_then(|p| p.parse().ok())
            .expect("child pid");
        let pid = child.id();
        (
            Agent {
                child,
                _accepted: None,
                pid,
            },
            child_pid,
        )
    }

    /// Spawn the agent binary and have it write one line to `path`, close
    /// the file and stay alive. Returns once it has reported the write.
    pub fn writing(agent_bin: &str, path: &str) -> Agent {
        let mut child = Command::new(agent_bin)
            .args(["--write", path])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn agent");
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .expect("wrote line");
        assert!(line.starts_with("wrote "), "{line}");
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
    /// T-P. The positive case with the kernel-pushed source: the transition
    /// itself is the evidence.
    PositiveTransition,
    /// X-P. The agent spawns a child executing the authorized image.
    ExecPositive,
    /// X-A. The agent spawns a child executing a different image.
    ExecWrongBinary,
    /// X-B. A different instance of the same binary spawns the authorized
    /// image under the bound instance's decision.
    ExecByOtherInstance,
    /// X-C. The spawn happens, and is attested, before the decision is issued.
    ExecBeforeAuthorization,
    /// S-P. The agent's hello on its connection verifies as a send to the
    /// authorized endpoint (`ghost.net.send.v1`).
    SendPositive,
    /// S-A. The send is authorized to a different endpoint than the one the
    /// agent sends to.
    SendWrongEndpoint,
    /// F-P. The agent completes a write to the authorized path
    /// (`ghost.fs.write.v1`).
    FileWritePositive,
    /// F-A. The write is authorized for a different path than the one the
    /// agent writes.
    FileWriteWrongPath,
    /// F-N. The write is authorized and the agent never writes: not
    /// observed, never a phantom.
    FileWriteNotDone,
}

impl Scenario {
    pub const ALL: [Scenario; 20] = [
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
        Scenario::PositiveTransition,
        Scenario::ExecPositive,
        Scenario::ExecWrongBinary,
        Scenario::ExecByOtherInstance,
        Scenario::ExecBeforeAuthorization,
        Scenario::SendPositive,
        Scenario::SendWrongEndpoint,
        Scenario::FileWritePositive,
        Scenario::FileWriteWrongPath,
        Scenario::FileWriteNotDone,
    ];

    /// Scenarios that need the kernel-pushed socket-state source.
    pub fn needs_tracer(&self) -> bool {
        matches!(
            self,
            Scenario::PreExistingConnection
                | Scenario::ConnectThenClose
                | Scenario::PositiveTransition
                | Scenario::ExecPositive
                | Scenario::ExecWrongBinary
                | Scenario::ExecByOtherInstance
                | Scenario::ExecBeforeAuthorization
                | Scenario::SendPositive
                | Scenario::SendWrongEndpoint
        )
    }

    /// Scenarios that need the socket-send tracepoint.
    pub fn needs_send(&self) -> bool {
        matches!(self, Scenario::SendPositive | Scenario::SendWrongEndpoint)
    }

    /// Scenarios that need the device tap (the wire question).
    pub fn needs_wire_tap(&self) -> bool {
        matches!(self, Scenario::PositiveTransition)
    }

    /// Scenarios that need the fanotify mount watch (and nothing else
    /// beyond polling).
    pub fn needs_fanotify(&self) -> bool {
        matches!(
            self,
            Scenario::FileWritePositive | Scenario::FileWriteWrongPath | Scenario::FileWriteNotDone
        )
    }

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
            Scenario::PositiveTransition => {
                "T-P. authorized connection, kernel-reported transition"
            }
            Scenario::ExecPositive => "X-P. authorized image executed by a child of the agent",
            Scenario::ExecWrongBinary => "X-A. child executes a different image",
            Scenario::ExecByOtherInstance => "X-B. another instance spawns the authorized image",
            Scenario::ExecBeforeAuthorization => "X-C. spawn attested before the decision",
            Scenario::SendPositive => "S-P. authorized send, kernel-reported byte count",
            Scenario::SendWrongEndpoint => "S-A. send authorized to a different endpoint",
            Scenario::FileWritePositive => "F-P. authorized file write, kernel-bound writer",
            Scenario::FileWriteWrongPath => "F-A. write authorized for a different path",
            Scenario::FileWriteNotDone => "F-N. write authorized, never done",
        }
    }
}

/// Everything a NEXORA package is assembled from, for the scenarios that
/// carry it. These are the live run's own artifacts — the decision point's
/// signed expectation, the collector's signed batches and health, and the
/// keys a verifier would have to hold — not a reconstruction of them.
pub struct ProofInputs {
    pub expectation: ExpectedExecution,
    pub evidence: ObserverEvidence,
    /// The verification time the live reconciliation was drawn at.
    pub at: u64,
    pub decision_point_anchors: DecisionPointTrustAnchors,
    pub observer_anchors: ObserverTrustAnchors,
    pub issuer_keys: std::collections::HashMap<String, Vec<u8>>,
    pub root: aip_types::ScopedToken,
    pub chain: Vec<aip_types::DelegationToken>,
    pub agent_id: String,
    pub agent_public_key: Vec<u8>,
}

/// One scenario's outcome, with the facts a reader needs to check it.
pub struct Demo {
    pub scenario: Scenario,
    pub reconciliation: Reconciliation,
    pub note: String,
    /// What a NEXORA package would be built from, for the scenarios that
    /// supply it. `None` means this scenario has not been wired for the
    /// proof layer, never that a package could be assembled without them.
    pub inputs: Option<ProofInputs>,
}

fn proof_inputs(
    a: &Authority,
    o: &Observer,
    ee: &ExpectedExecution,
    ev: &ObserverEvidence,
    at: u64,
) -> ProofInputs {
    let (root, chain) = a.authority();
    ProofInputs {
        expectation: ee.clone(),
        evidence: ev.clone(),
        at,
        decision_point_anchors: a.anchors.clone(),
        observer_anchors: o.anchors.clone(),
        issuer_keys: a.issuer_keys.clone(),
        root,
        chain,
        agent_id: a.agent_id.clone(),
        agent_public_key: a.agent_kp.public_key.clone(),
    }
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

fn scenario_slug(s: Scenario) -> &'static str {
    match s {
        Scenario::FileWritePositive => "f-p",
        Scenario::FileWriteWrongPath => "f-a",
        Scenario::FileWriteNotDone => "f-n",
        _ => "other",
    }
}

/// Run one scenario against a freshly spawned agent. Linux only: needs
/// procfs, pidfd and the kernel socket tables. Opens the device-layer tap
/// where the host permits it.
pub fn run(scenario: Scenario, agent_bin: &str) -> Demo {
    run_with(scenario, agent_bin, true)
}

/// As [`run`], but never opens the device-layer tap.
pub fn run_without_wire_tap(scenario: Scenario, agent_bin: &str) -> Demo {
    run_with(scenario, agent_bin, false)
}

/// Live scenarios share one kernel, one set of tracepoints and one mount
/// watch; running several at once on a small host starves each other's
/// rings and turns kernel loss into false negatives. They run one at a time
/// per process; the test harness may still schedule them in parallel.
static LIVE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn run_with(scenario: Scenario, agent_bin: &str, tap: bool) -> Demo {
    let _one_at_a_time = LIVE.lock().unwrap_or_else(|e| e.into_inner());
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let remote = v4(&listener);
    let a = Authority::new();
    let mut o = if scenario.needs_tracer() {
        Observer::with_sources(tap && scenario.needs_wire_tap(), scenario.needs_send())
            .expect("kernel socket-state source unavailable on this host")
    } else if scenario.needs_fanotify() {
        Observer::with_fanotify().expect("fanotify unavailable on this host")
    } else {
        Observer::new()
    };

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
                inputs: Some(proof_inputs(&a, &o, &ee, &ev, at)),
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
                inputs: Some(proof_inputs(&a, &o, &ee, &ev, at)),
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
                inputs: None,
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
                inputs: None,
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
                inputs: None,
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
                inputs: None,
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
                inputs: None,
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
                inputs: None,
                scenario,
                reconciliation: r,
                note: format!(
                    "connection to {remote} observed ({n_before}) and attested before the decision at {now}; observed again ({n_after}) inside the window"
                ),
            }
        }
        Scenario::PositiveTransition => {
            let b1 = o.epoch_start(now_ms());
            let now = now_ms();
            let agent = Agent::connect(agent_bin, &listener);
            let binding = a.binding_for(agent.pid);
            let ee = a.authorize_connect(binding, remote, now).unwrap();
            let c = claim(&a, &ee);
            let (b2, n) = o.observe_connections(agent.pid, Some(&c)).unwrap();
            let at = now_ms().max(b2.batch.claimed_to_ms);
            let wire = b2
                .batch
                .kernel_events
                .iter()
                .filter(|e| e.mechanism == SourceMechanism::WireTapAfPacket)
                .count();
            let events = b2.batch.kernel_events.len() - wire;
            let ev = ObserverEvidence {
                batches: vec![b1, b2],
                health: o.health(at),
            };
            let r = reconcile_expectation(&ee, Some(&ev), &ctx(&a, &o, at));
            Demo {
                inputs: None,
                scenario,
                reconciliation: r,
                note: format!(
                    "agent pid {} → {remote}; {n} established connection(s) in the table, {events} kernel socket transition(s) captured, {wire} wire segment(s) captured (tap {})",
                    agent.pid,
                    if o.has_wire_tap() { "open" } else { "not open" }
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
                inputs: None,
                scenario,
                reconciliation: r,
                note: format!(
                    "agent pid {} connected to {remote} and closed before the table was read; {n} established connection(s) in the poll",
                    agent.pid
                ),
            }
        }
        Scenario::ExecPositive => {
            let b1 = o.epoch_start(now_ms());
            let now = now_ms();
            // The agent process exists first (idle), gets its decision, then
            // is asked to spawn. The demo agent cannot be told to spawn after
            // start, so the sequence is: authorize a *fresh* agent's binding
            // at `now`, then let it spawn — its binding is collected right
            // after spawn and is stable (start tick, exe) from exec onward.
            let (agent, child_pid) = Agent::spawning(agent_bin, SLEEP_BIN, &["30"]);
            let binding = a.binding_for(agent.pid);
            let ee = a
                .authorize_exec(binding, hash_binary(SLEEP_BIN), now)
                .unwrap();
            let c = claim(&a, &ee);
            let (b2, _) = o.observe_connections(agent.pid, Some(&c)).unwrap();
            let at = now_ms().max(b2.batch.claimed_to_ms);
            let events = b2.batch.kernel_events.len();
            let ev = ObserverEvidence {
                batches: vec![b1, b2],
                health: o.health(at),
            };
            let r = reconcile_expectation(&ee, Some(&ev), &ctx(&a, &o, at));
            Demo {
                inputs: None,
                scenario,
                reconciliation: r,
                note: format!(
                    "agent pid {} spawned pid {child_pid} running {SLEEP_BIN}; {events} kernel event(s) captured",
                    agent.pid
                ),
            }
        }
        Scenario::ExecWrongBinary => {
            let b1 = o.epoch_start(now_ms());
            let now = now_ms();
            let (agent, child_pid) = Agent::spawning(agent_bin, SLEEP_BIN, &["30"]);
            let binding = a.binding_for(agent.pid);
            // Authorized: /bin/true. Executed: sleep.
            let ee = a
                .authorize_exec(binding, hash_binary(TRUE_BIN), now)
                .unwrap();
            let c = claim(&a, &ee);
            let (b2, _) = o.observe_connections(agent.pid, Some(&c)).unwrap();
            let at = now_ms().max(b2.batch.claimed_to_ms);
            let ev = ObserverEvidence {
                batches: vec![b1, b2],
                health: o.health(at),
            };
            let r = reconcile_expectation(&ee, Some(&ev), &ctx(&a, &o, at));
            Demo {
                inputs: None,
                scenario,
                reconciliation: r,
                note: format!(
                    "authorized {TRUE_BIN}; agent pid {} spawned pid {child_pid} running {SLEEP_BIN}",
                    agent.pid
                ),
            }
        }
        Scenario::ExecByOtherInstance => {
            let b1 = o.epoch_start(now_ms());
            let now = now_ms();
            let bound = Agent::idle(agent_bin);
            let (actor, child_pid) = Agent::spawning(agent_bin, SLEEP_BIN, &["30"]);
            let binding = a.binding_for(bound.pid);
            let ee = a
                .authorize_exec(binding, hash_binary(SLEEP_BIN), now)
                .unwrap();
            let c = claim(&a, &ee);
            let (b2, _) = o.observe_connections(actor.pid, Some(&c)).unwrap();
            let at = now_ms().max(b2.batch.claimed_to_ms);
            let ev = ObserverEvidence {
                batches: vec![b1, b2],
                health: o.health(at),
            };
            let r = reconcile_expectation(&ee, Some(&ev), &ctx(&a, &o, at));
            Demo {
                inputs: None,
                scenario,
                reconciliation: r,
                note: format!(
                    "decision bound to pid {}, spawn of pid {child_pid} made by pid {} (same binary)",
                    bound.pid, actor.pid
                ),
            }
        }
        Scenario::ExecBeforeAuthorization => {
            let t0 = now_ms();
            let b1 = o.epoch_start(t0);
            let (agent, child_pid) = Agent::spawning(agent_bin, SLEEP_BIN, &["30"]);
            let binding = a.binding_for(agent.pid);
            // The spawn is observed and attested first …
            let (b2, _) = o.observe_connections(agent.pid, None).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(20));
            // … then the decision is issued …
            let now = now_ms().max(b2.batch.claimed_to_ms + 1);
            let ee = a
                .authorize_exec(binding, hash_binary(SLEEP_BIN), now)
                .unwrap();
            // … and the still-running child is observed again inside the window.
            let c = claim(&a, &ee);
            let (b3, _) = o.observe_connections(agent.pid, Some(&c)).unwrap();
            let at = now_ms().max(b3.batch.claimed_to_ms);
            let ev = ObserverEvidence {
                batches: vec![b1, b2, b3],
                health: o.health(at),
            };
            let r = reconcile_expectation(&ee, Some(&ev), &ctx(&a, &o, at));
            Demo {
                inputs: None,
                scenario,
                reconciliation: r,
                note: format!(
                    "agent pid {} spawned pid {child_pid} and it was attested before the decision at {now}",
                    agent.pid
                ),
            }
        }
        Scenario::SendPositive | Scenario::SendWrongEndpoint => {
            let b1 = o.epoch_start(now_ms());
            let now = now_ms();
            let target = if scenario == Scenario::SendWrongEndpoint {
                SocketAddrV4::new(*remote.ip(), remote.port().wrapping_add(1).max(1))
            } else {
                remote
            };
            // The agent connects and says hello: one send on the connection.
            let agent = Agent::connect(agent_bin, &listener);
            let binding = a.binding_for(agent.pid);
            let ee = a.authorize_send(binding, target, now).unwrap();
            let c = claim(&a, &ee);
            let (b2, _) = o.observe_connections(agent.pid, Some(&c)).unwrap();
            let at = now_ms().max(b2.batch.claimed_to_ms);
            let sends = b2
                .batch
                .kernel_events
                .iter()
                .filter(|e| e.mechanism == SourceMechanism::SockSendTracepoint)
                .count();
            let ev = ObserverEvidence {
                batches: vec![b1, b2],
                health: o.health(at),
            };
            let r = reconcile_expectation(&ee, Some(&ev), &ctx(&a, &o, at));
            Demo {
                inputs: None,
                scenario,
                reconciliation: r,
                note: format!(
                    "agent pid {} sent its hello to {remote}; authorized send to {target}; {sends} send event(s) captured (send tracer {})",
                    agent.pid,
                    if o.send_tracer.is_some() { "open" } else { "not open" }
                ),
            }
        }
        Scenario::FileWritePositive | Scenario::FileWriteWrongPath | Scenario::FileWriteNotDone => {
            let dir = demo_dir();
            std::fs::create_dir_all(&dir).expect("demo dir");
            let written = dir.join(format!("{}.txt", scenario_slug(scenario)));
            let authorized = if scenario == Scenario::FileWriteWrongPath {
                dir.join("elsewhere.txt")
            } else {
                written.clone()
            };
            let b1 = o.epoch_start(now_ms());
            let now = now_ms();
            let agent = if scenario == Scenario::FileWriteNotDone {
                Agent::idle(agent_bin)
            } else {
                Agent::writing(agent_bin, written.to_str().unwrap())
            };
            let binding = a.binding_for(agent.pid);
            let ee = a
                .authorize_write(binding, authorized.to_str().unwrap(), now)
                .unwrap();
            let c = claim(&a, &ee);
            let (b2, _) = o.observe_connections(agent.pid, Some(&c)).unwrap();
            let at = now_ms().max(b2.batch.claimed_to_ms);
            let files = b2
                .batch
                .kernel_events
                .iter()
                .filter(|e| e.mechanism == SourceMechanism::Fanotify)
                .count();
            let ev = ObserverEvidence {
                batches: vec![b1, b2],
                health: o.health(at),
            };
            let r = reconcile_expectation(&ee, Some(&ev), &ctx(&a, &o, at));
            let _ = std::fs::remove_dir_all(&dir);
            Demo {
                inputs: None,
                scenario,
                reconciliation: r,
                note: format!(
                    "agent pid {} {}; authorized write to {}; {files} file event(s) captured on the mount (fanotify {})",
                    agent.pid,
                    if scenario == Scenario::FileWriteNotDone {
                        "wrote nothing".to_string()
                    } else {
                        format!("wrote {}", written.display())
                    },
                    authorized.display(),
                    if o.fanotify.is_some() { "open" } else { "not open" }
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
                inputs: None,
                scenario,
                reconciliation: r,
                note: "remote port flipped inside the attested batch after signing".into(),
            }
        }
    }
}

/// Run every scenario the host supports. Scenarios that need the kernel
/// socket-state source are skipped (and named) where it is unavailable.
pub fn run_all(agent_bin: &str) -> (Vec<Demo>, Vec<(Scenario, String)>) {
    let tracer = tracer_available();
    let fanotify = fanotify_available();
    let mut demos = Vec::new();
    let mut skipped = Vec::new();
    for s in Scenario::ALL {
        match (&tracer, s.needs_tracer(), &fanotify, s.needs_fanotify()) {
            (Err(why), true, _, _) => skipped.push((s, why.clone())),
            (_, _, Err(why), true) => skipped.push((s, why.clone())),
            _ => demos.push(run(s, agent_bin)),
        }
    }
    (demos, skipped)
}
