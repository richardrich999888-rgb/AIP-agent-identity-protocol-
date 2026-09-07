//! The reference run: three processes, one authorized action, one report.
//!
//! # Why the orchestration is here and not in the binary
//!
//! The tests drive the same function the binary does. A reference whose
//! demonstration path and whose test path are different code is a reference
//! that demonstrates something the tests never checked, and the divergence is
//! always discovered later than it should be.
//!
//! The binary in `src/bin/aip-edge.rs` therefore contains argument parsing and
//! printing, and nothing else.
//!
//! # The sequence, and why every step blocks
//!
//! ```text
//!  1  spawn observer          → ready      key generated, public half published
//!  2  spawn workload          → identity   AIP-ID and execution id published
//!  3  driver measures the workload's process instance     ← verifier side
//!  4  decision point authorizes that instance for one endpoint
//!  5  observer                → epoch      opens a coverage epoch
//!  6  workload                → connect    a real TCP connection, held open
//!  7  observer                → observe    measures the instance and its sockets
//!  8  observer                → health     signs coverage
//!  9  verifier reconciles, then assembles Skills 17-21 from the same batches
//! ```
//!
//! Steps 6 and 7 are the reason the whole protocol is synchronous. The driver
//! does not resume until the workload's reply proves the connection exists, so
//! the observation in step 7 is taken while it exists — by construction, not
//! by a sleep that is usually long enough. There is no timing assumption in
//! this file and no retry.
//!
//! # What the driver holds, and what it does not
//!
//! It holds trust anchors, a platform registry and two pipes. It holds no
//! collector key — that is inside process B — and no agent key — that is
//! inside process A. It measures the workload's process instance itself,
//! because a decision point binds what it authorizes and must not take the
//! subject's word for which process it is.

use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::path::PathBuf;

use aip_authorize::{
    net_connect_action, net_connect_parameters, ActionParameters, AuthorizationRequest, Decision,
    DecisionPoint, DecisionPointTrustAnchors, ExpectedExecution, NetProtocol,
};
use aip_core::capability::issue_scoped_token;
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_edge_contract as contract;
use aip_effect::EffectWindow;
use aip_execution::{EffectOutcome, ExecutionProfile, RuntimeAction, RuntimeDeclaration};
use aip_observation::ObservationRecord;
use aip_observe::{AttestedBatch, ObservedExecution, ObserverTrustAnchors, SignedSensorHealth};
use aip_platform::{PlatformBinding, PlatformRegistry};
use aip_reconcile::{
    reconcile_expectation, ExpectedSideCoverage, ObserverEvidence, Reconciliation,
    ReconciliationContext,
};
use aip_system::{PlatformId, SystemExecution, SystemId};
use aip_types::{CapabilityScope, ExecutionBinding, KeyPair, ProvenanceTriple};

use crate::correlate::{observation_record, subject_from_expectation, ObservationSubject};
use crate::effect::{assess_effect, physical_effect_finding, requested_effect, EffectInputs};
use crate::error::EdgeError;
use crate::platform::{bind_platform, observed_boot_from, register_measured_host, verifier_boot_id};
use crate::profile::profile_from_codes;
use crate::reference::EdgeReference;
use crate::transport::{read_batches, read_health, sibling_binary, Peer};

/// Authorization TTL for the reference. Long enough that a slow host cannot
/// expire an expectation mid-run; short enough to be a real bound.
const TTL_MS: u64 = 300_000;
const MAX_TTL_MS: u64 = 3_600_000;
/// Health older than this is stale and reduces availability. Never extends it.
const HEALTH_MAX_AGE_MS: u64 = 60_000;
/// Slack when comparing a probe-claimed window with the authorized one. A
/// filter, not evidence.
const WINDOW_TOLERANCE_MS: u64 = 5_000;

/// How this run should differ from the honest one.
///
/// Each variant is a stimulus the reference applies to the **real** path: the
/// same three processes, the same kernel, the same engine. None of them
/// fabricates evidence; they change what actually happens and then report what
/// the architecture actually says about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    /// The workload really connects and the observer really looks.
    Honest,
    /// The workload emits a signed success self-report and opens no
    /// connection. Everything else is unchanged.
    SelfReportOnly,
    /// The observer is killed before it can look. No batch covers the action.
    ObserverLost,
    /// The workload exits before the observation is taken.
    WorkloadExitsFirst,
    /// The verifier registers, and correlates against, a boot the observer did
    /// not measure.
    WrongBoot,
    /// The verifier's registry names a platform other than the authorized one.
    WrongPlatform,
    /// The observation offered is one taken of a *different* process instance
    /// on this host — the driver's own.
    CrossExecutionInjection,
    /// The batch is replayed: the same attested batch is offered twice.
    ReplayedObservation,
}

impl Scenario {
    pub fn label(self) -> &'static str {
        match self {
            Self::Honest => "honest: authorized connection, observed",
            Self::SelfReportOnly => "self-report only: the workload says it connected",
            Self::ObserverLost => "observer lost before the observation",
            Self::WorkloadExitsFirst => "workload exits before the observation",
            Self::WrongBoot => "correlated against a boot the observer did not measure",
            Self::WrongPlatform => "registry resolves a platform other than the authorized one",
            Self::CrossExecutionInjection => "an observation of another process instance",
            Self::ReplayedObservation => "the same attested batch offered twice",
        }
    }
}

/// Everything a run needs that is not a scenario.
pub struct RunConfig {
    /// State directory for the reference transport. Created if absent.
    pub dir: PathBuf,
    pub system_id: SystemId,
    /// The platform the verifier authorizes the execution for.
    pub authorized_platform: PlatformId,
    /// The platform the verifier's registry actually resolves the measured
    /// boot to. Equal to `authorized_platform` except under
    /// [`Scenario::WrongPlatform`].
    pub registered_platform: PlatformId,
    pub scenario: Scenario,
}

/// What one run produced, plus the raw material a test needs to press further.
pub struct RunOutcome {
    pub reference: EdgeReference,
    pub batches: Vec<AttestedBatch>,
    pub health: Vec<SignedSensorHealth>,
    pub observer_anchors: ObserverTrustAnchors,
    pub dp_anchors: DecisionPointTrustAnchors,
    pub subject: ObservationSubject,
    pub expectation: ExpectedExecution,
    pub registry: PlatformRegistry,
    pub workload_pid: u32,
    pub observer_pid: u32,
    /// The endpoint the action was authorized for.
    pub endpoint: SocketAddrV4,
    /// Correlated `(record, observation)` pairs, for the effect layer.
    pub correlated: Vec<(ObservationRecord, ObservedExecution)>,
}

/// The decision point and the authority chain behind it.
///
/// In production these are separate parties on separate hosts. Here they share
/// the verifier process, which is a property of the *reference*, not of the
/// architecture, and is stated rather than hidden.
struct Authority {
    dp: DecisionPoint,
    anchors: DecisionPointTrustAnchors,
    root: aip_types::ScopedToken,
    hop: aip_types::DelegationToken,
}

impl Authority {
    fn for_agent(agent_id: &str) -> Result<Self, EdgeError> {
        let scope = CapabilityScope {
            allowed: vec![net_connect_action()],
            denied: vec![],
        };
        let provenance = |tag: &str| ProvenanceTriple {
            model_commitment: sha256(format!("edge-{tag}-model").as_bytes()),
            environment_commitment: sha256(format!("edge-{tag}-env").as_bytes()),
            toolchain_commitment: sha256(format!("edge-{tag}-toolchain").as_bytes()),
        };
        let issuer_kp = generate_ed25519_keypair();
        let issuer_id = derive_aip_id(&issuer_kp.public_key, &provenance("issuer"));
        let (orch, orch_kp): (aip_types::AgentIdentityDocument, KeyPair) =
            create_identity(provenance("orchestrator"), None)
                .map_err(|e| EdgeError::Transport(format!("orchestrator identity: {e:?}")))?;
        let root = issue_scoped_token(
            &issuer_id,
            &issuer_kp.private_key,
            &orch.id,
            scope.clone(),
            Some(MAX_TTL_MS),
        )
        .map_err(|e| EdgeError::Transport(format!("root token: {e:?}")))?;
        let hop = create_delegation(&root, &orch_kp.private_key, agent_id, scope)
            .map_err(|e| EdgeError::Transport(format!("delegation: {e:?}")))?;
        let dp_kp = generate_ed25519_keypair();
        let dp_id = derive_aip_id(&dp_kp.public_key, &provenance("decision-point"));
        let dp = DecisionPoint::new(&dp_id, &dp_kp.private_key, &dp_kp.public_key, MAX_TTL_MS)
            .map_err(|e| EdgeError::Transport(format!("decision point: {e:?}")))?
            .trust_issuer(&issuer_id, &issuer_kp.public_key)
            .trust_issuer(&orch.id, &orch_kp.public_key);
        let anchors = DecisionPointTrustAnchors::new().trust(&dp_id, &dp_kp.public_key);
        Ok(Self {
            dp,
            anchors,
            root,
            hop,
        })
    }

    fn authorize(
        &self,
        agent_id: &str,
        binding: ExecutionBinding,
        remote: SocketAddrV4,
        now: u64,
    ) -> Result<ExpectedExecution, EdgeError> {
        let params: ActionParameters =
            net_connect_parameters(NetProtocol::Tcp, &remote.ip().octets(), remote.port())
                .map_err(|e| EdgeError::Transport(format!("parameters: {e:?}")))?;
        let req = AuthorizationRequest {
            agent_id: agent_id.to_owned(),
            root_token: self.root.clone(),
            delegation_chain: vec![self.hop.clone()],
            action_kind: net_connect_action(),
            parameters: params,
            execution_binding: binding,
            requested_ttl_ms: TTL_MS,
        };
        match self.dp.authorize_at(&req, now) {
            Decision::Authorized(ee) => Ok(*ee),
            Decision::Denied(d) => Err(EdgeError::Transport(format!("denied: {d:?}"))),
        }
    }
}

/// Run the reference once.
///
/// Every artifact in the returned outcome is derived from what actually
/// happened on this host during this call. Nothing is a fixture except the
/// *expectation*, which is a fixture in the same sense a decision is: someone
/// decided it, and the reference is what checks whether it was honoured.
pub fn run(config: &RunConfig) -> Result<RunOutcome, EdgeError> {
    std::fs::create_dir_all(&config.dir)
        .map_err(|e| EdgeError::Transport(format!("{}: {e}", config.dir.display())))?;
    let dir_arg = config.dir.to_string_lossy().into_owned();

    // The endpoint the action is about. Port 0 lets the kernel choose a free
    // one, so concurrent runs cannot collide — the reference must be safe to
    // run from a parallel test harness.
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .map_err(|e| EdgeError::Transport(format!("listener: {e}")))?;
    let endpoint = match listener
        .local_addr()
        .map_err(|e| EdgeError::Transport(format!("local_addr: {e}")))?
    {
        std::net::SocketAddr::V4(a) => a,
        other => {
            return Err(EdgeError::Transport(format!(
                "expected an IPv4 listener, got {other}"
            )))
        }
    };

    // ── 1. The observer, in its own process ──────────────────────────────
    let observer_bin = sibling_binary("aip-edge-observer")?;
    let mut observer = Peer::spawn("observer", &observer_bin, &["--dir", &dir_arg])?;
    observer.command(contract::CMD_READY)?;
    let observer_pid = observer.pid();
    let announcement: contract::ObserverAnnouncement =
        crate::transport::read_json(&config.dir.join(contract::OBSERVER_ANNOUNCEMENT))?;
    let observer_anchors = ObserverTrustAnchors::new().trust(
        &announcement.observer_id,
        announcement.key_version,
        &announcement.public_key,
    );
    // Phase 7: the profile is projected from the observer's own declaration
    // and from nothing else.
    let profile = profile_from_codes(
        &announcement.observer_id,
        &announcement.declared_mechanism_codes,
    )?;

    // ── 2. The workload, in its own process ──────────────────────────────
    let workload_bin = sibling_binary("aip-edge-workload")?;
    let mut workload = Peer::spawn("workload", &workload_bin, &["--dir", &dir_arg])?;
    workload.command(contract::CMD_IDENTITY)?;
    let workload_pid = workload.pid();
    let claimed: contract::WorkloadAnnouncement =
        crate::transport::read_json(&config.dir.join(contract::WORKLOAD_ANNOUNCEMENT))?;

    // ── 3. The verifier measures the instance itself ─────────────────────
    //
    // `workload.pid()` is what the OS told this process when it forked, not
    // what the child said about itself. The decision point binds that.
    let binding = aip_core::execution_binding::collect_binding_for_pid(
        &claimed.agent_id,
        workload_pid,
    )
    .map_err(|e| EdgeError::Transport(format!("collect binding: {e:?}")))?;

    // ── 4. Authorization ─────────────────────────────────────────────────
    let authority = Authority::for_agent(&claimed.agent_id)?;
    let now = now_ms();
    let expectation = authority.authorize(&claimed.agent_id, binding.clone(), endpoint, now)?;

    // ── 5. Coverage epoch ────────────────────────────────────────────────
    observer.command(contract::CMD_EPOCH)?;

    // ── 6. The action ────────────────────────────────────────────────────
    let decision_hex: String = expectation
        .decision_id
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let verb = match config.scenario {
        Scenario::SelfReportOnly => contract::CMD_CLAIM,
        _ => contract::CMD_CONNECT,
    };
    workload.command(&format!("{verb} {endpoint} {decision_hex}"))?;
    // Accept the connection so the reference holds both ends. Only meaningful
    // when one was actually made; under `SelfReportOnly` there is nothing to
    // accept and nothing waits for it.
    let _accepted: Option<TcpStream> = if matches!(config.scenario, Scenario::SelfReportOnly) {
        None
    } else {
        Some(
            listener
                .accept()
                .map_err(|e| EdgeError::Transport(format!("accept: {e}")))?
                .0,
        )
    };

    // Scenario stimuli that must happen between the action and the look.
    let mut observer = match config.scenario {
        Scenario::ObserverLost => {
            observer.kill()?;
            None
        }
        _ => Some(observer),
    };
    let mut workload = Some(workload);
    if matches!(config.scenario, Scenario::WorkloadExitsFirst) {
        workload.take().expect("workload").quit()?;
    }

    // ── 7. The observation ───────────────────────────────────────────────
    let mut observed_target = workload_pid;
    if matches!(config.scenario, Scenario::CrossExecutionInjection) {
        // Offer an observation of a genuinely different instance: this very
        // process. Real evidence, real signature, wrong subject.
        observed_target = std::process::id();
    }
    if let Some(o) = observer.as_mut() {
        // The orchestration supplies the correlation hint: which agent this pid
        // claims to be, under which decision. Both are the *verifier's* values,
        // taken from the decision it just issued — the observer is not being
        // asked to believe them, it is being asked to record that they were
        // said, so the reconciler has a join key. A claim is not authorization
        // and the observer still holds no means to construct one.
        //
        // A refusal here is a fact about the run, not an error: under
        // `WorkloadExitsFirst` the instance is gone and the probe says so.
        let _ = o.command(&format!(
            "{} {observed_target} {} {decision_hex}",
            contract::CMD_OBSERVE,
            claimed.agent_id
        ));
        let _ = o.command(contract::CMD_HEALTH);
    }

    // ── 8. Read what the observer produced ───────────────────────────────
    let mut batches = read_batches(&config.dir).unwrap_or_default();
    if matches!(config.scenario, Scenario::ReplayedObservation) {
        if let Some(last) = batches.last().cloned() {
            batches.push(last);
        }
    }
    let health = read_health(&config.dir).unwrap_or_default();

    // ── 9. Verification and assembly ─────────────────────────────────────
    let measured_boot = verifier_boot_id()?;
    let correlation_boot = if matches!(config.scenario, Scenario::WrongBoot) {
        // A boot this host is not running. Nothing the observer measured can
        // match it, so no record may be built against it.
        let mut b = measured_boot;
        b[0] ^= 0xFF;
        b
    } else {
        measured_boot
    };

    let registry = register_measured_host(
        PlatformRegistry::new(),
        correlation_boot,
        config.registered_platform.clone(),
        None,
        0,
    )?;

    let subject = subject_from_expectation(
        &expectation,
        &authority.anchors,
        config.system_id.clone(),
        claimed.execution_id,
        correlation_boot,
    )?;

    // Correlated records, each through `ObservationRecord::from_attested`.
    //
    // Deduplicated on `(collector sequence, index within batch)`. The sequence
    // is assigned by the collector and is unique per attested batch, so two
    // entries sharing one are the *same observation offered twice* — a
    // duplicate or a replay. Counting both would inflate `supporting` in the
    // effect finding: one connection observed once would read as two
    // independent corroborations, which is evidence inflation performed by the
    // verifier's own loop rather than by an attacker. Detecting the replay is
    // `aip-reconcile`'s job and it keeps it; not double-counting is this
    // loop's job.
    let mut seen: std::collections::HashSet<(u64, usize)> = std::collections::HashSet::new();
    let mut correlated: Vec<(ObservationRecord, ObservedExecution)> = Vec::new();
    for batch in &batches {
        for index in 0..batch.batch.observations.len() {
            if !seen.insert((batch.sequence, index)) {
                continue;
            }
            if let Ok(record) = observation_record(batch, &observer_anchors, index, &subject) {
                correlated.push((record, batch.batch.observations[index].clone()));
            }
        }
    }

    // Skill 19, from the batch that actually carried a correlated record.
    let platform_binding = resolve_platform(
        &batches,
        &observer_anchors,
        &subject,
        &registry,
        &config.authorized_platform,
        now,
    );

    // Skill 21, over the same records.
    let requested = requested_effect(endpoint.ip().octets(), endpoint.port());
    let window = collector_window(&batches);
    let inputs = EffectInputs {
        requested: &requested,
        subject: &subject,
        window,
        profile: &profile,
        // One effect was requested in this execution, so an admitted
        // observation can only be about it: `EffectBinding::Exact`.
        requested_effects_in_execution: 1,
    };
    let assessment = assess_effect(
        &inputs,
        &correlated,
        endpoint.ip().octets(),
        endpoint.port(),
    )?;

    // Skill 17 and Skill 18.
    let system_execution = SystemExecution::new(
        config.system_id.clone(),
        &claimed.agent_id,
        claimed.execution_id,
        now,
    )
    .map_err(|e| EdgeError::Transport(format!("system execution: {e:?}")))?
    .on_platform(config.authorized_platform.clone())
    .citing(aip_system::AuthorityContext {
        decision_id: Some(expectation.decision_id),
        root_token_jti: None,
    })
    .bound_to(binding.clone());

    let execution_profile = ExecutionProfile::new(system_execution.clone(), now)
        .claiming_decision(expectation.decision_id)
        .with_runtime(
            RuntimeDeclaration::new()
                .declared("linux-edge-reference")
                // `selected` is the workload's own word. There is deliberately
                // no code path that copies it into `observed` or `evidenced`.
                .selected("linux-edge-reference"),
        )
        .with_effect(EffectOutcome::reported(
            requested.clone(),
            RuntimeAction {
                parameter_commitment: requested.parameter_commitment,
                // The reference's equivalent of a 200. It reaches
                // `NotEvaluated` and stops there.
                transport_status: Some(0),
                result_commitment: None,
                reported_at_ms: now,
            },
        ));

    // The existing engine. The only verdict in this reference.
    let reconciliation = reconcile(&expectation, &batches, &health, &observer_anchors, &authority);

    let physical = physical_effect_finding(&profile);
    let records: Vec<ObservationRecord> = correlated.iter().map(|(r, _)| r.clone()).collect();
    // Observations the *verified* batches carried, deduplicated the same way
    // the correlated set is. Counting unverified bytes here would let an
    // untrusted batch inflate a number a reader compares against a trusted one.
    let observations_offered = {
        let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
        batches
            .iter()
            .filter(|b| aip_observe::verify_attested_batch(b, &observer_anchors).is_ok())
            .filter(|b| seen.insert(b.sequence))
            .map(|b| b.batch.observations.len() as u32)
            .sum()
    };
    let reference = EdgeReference::new(
        system_execution,
        execution_profile,
        platform_binding,
        profile,
        records,
        observations_offered,
        &assessment,
        physical,
        reconciliation,
        expectation.clone(),
    );

    // Shut the children down. A failure here is reported, not swallowed: a
    // reference that leaves processes behind is a reference nobody can run
    // twice.
    if let Some(w) = workload {
        w.quit()?;
    }
    if let Some(o) = observer {
        o.quit()?;
    }

    Ok(RunOutcome {
        reference,
        batches,
        health,
        observer_anchors,
        dp_anchors: authority.anchors,
        subject,
        expectation,
        registry,
        workload_pid,
        observer_pid,
        endpoint,
        correlated,
    })
}

/// Resolve the platform from the first batch carrying a correlated record.
///
/// Falls back to `None` — and therefore to `NotEvaluated` — when no batch
/// does. Absence of observation is not evidence of location.
fn resolve_platform(
    batches: &[AttestedBatch],
    anchors: &ObserverTrustAnchors,
    subject: &ObservationSubject,
    registry: &PlatformRegistry,
    authorized_platform: &PlatformId,
    at_ms: u64,
) -> PlatformBinding {
    for batch in batches {
        for index in 0..batch.batch.observations.len() {
            if observation_record(batch, anchors, index, subject).is_err() {
                continue;
            }
            if let Ok(Some(boot)) = observed_boot_from(batch, anchors, index) {
                return bind_platform(
                    subject.execution_id,
                    Some(boot),
                    Some(authorized_platform),
                    registry,
                    at_ms,
                );
            }
        }
    }
    bind_platform(
        subject.execution_id,
        None,
        Some(authorized_platform),
        registry,
        at_ms,
    )
}

/// The window an effect could have occurred in, from the **collector's** signed
/// clock and never the agent's.
///
/// An empty batch set yields an empty window `[u64::MAX, 0]`, which contains
/// nothing. That is the honest default: with no attested clock there is no
/// interval a verifier may vouch for, and a wide-open window would admit an
/// observation from any moment.
fn collector_window(batches: &[AttestedBatch]) -> EffectWindow {
    let from = batches.iter().map(|b| b.attested_at_ms).min();
    let to = batches.iter().map(|b| b.attested_at_ms).max();
    match (from, to) {
        (Some(f), Some(t)) => EffectWindow {
            from_ms: f,
            to_ms: t,
        },
        _ => EffectWindow {
            from_ms: u64::MAX,
            to_ms: 0,
        },
    }
}

/// Drive the existing reconciliation engine. No wrapper logic, no fallback.
fn reconcile(
    expectation: &ExpectedExecution,
    batches: &[AttestedBatch],
    health: &[SignedSensorHealth],
    anchors: &ObserverTrustAnchors,
    authority: &Authority,
) -> Reconciliation {
    let ctx = ReconciliationContext {
        decision_point_anchors: authority.anchors.clone(),
        observer_anchors: anchors.clone(),
        verification_time_ms: now_ms(),
        health_max_age_ms: HEALTH_MAX_AGE_MS,
        window_tolerance_ms: WINDOW_TOLERANCE_MS,
        // Nothing attests that the set of expectations held here is complete,
        // so absence of an expectation is just absence. `UNATTRIBUTED_EFFECT`
        // stays unreachable, which is correct: no producer of a decision-point
        // coverage statement exists.
        expected_side: ExpectedSideCoverage::Unknown,
        agent_public_key: None,
    };
    let evidence = health.last().map(|h| ObserverEvidence {
        batches: batches.to_vec(),
        health: h.clone(),
    });
    reconcile_expectation(expectation, evidence.as_ref(), &ctx)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
