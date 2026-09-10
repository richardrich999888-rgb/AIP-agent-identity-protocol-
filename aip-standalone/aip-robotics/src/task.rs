//! Tasks: what one is, what makes it authoritative, and what state may be
//! asserted about it.
//!
//! # A plan aboard the robot is a file
//!
//! Exactly as for a UAS mission (ADR-005's neighbour argument): a task plan the
//! robot is carrying is evidence that the robot has a file. It becomes
//! authoritative in one way — its digest is committed into `ActionParameters`,
//! and a decision point signs that set as
//! `ExpectedExecution.parameter_digest`. **No new authorization engine, no new
//! signer, no new trust anchor.**
//!
//! # Cancellation
//!
//! No revocation list. An expectation is bounded, so a task stops being
//! authorized when the last expectation committing to it expires and no
//! further one is issued. Cancelling is declining to authorize, which is a
//! decision point's existing power; a second cancellation channel would be a
//! second place for authority to live.
//!
//! # States, and why `COMPLETED` is unreachable
//!
//! Each state names the evidence tier that would justify asserting it. The
//! states about the robot's *body* — aborted, recovering, completed — need a
//! physical observation, which no mechanism provides, so they resolve to
//! `Unknown` for every real robot. A robot that emits a completion event has
//! emitted a completion event.

use aip_crypto::sha256;
use aip_types::canonical::{put_domain, put_str, put_u16, put_u32, put_u64, put_u8};
use serde::{Deserialize, Serialize};

use crate::action::RobotAction;
use crate::error::RoboticsError;
use crate::{ROBOTICS_PROFILE_DOMAIN, ROBOTICS_PROFILE_VERSION};

/// The reserved `ActionParameters` key carrying the task commitment.
///
/// Versioned in the key itself, so a decision point that signed a v1 task can
/// never be read as having signed a v2 one.
pub const TASK_PARAMETER_KEY: &str = "aip.robotics.task.v1";

/// The interval a task is authorized for. Half-open `[from, until)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskWindow {
    pub from_ms: u64,
    pub until_ms: u64,
}

impl TaskWindow {
    pub fn contains(&self, t_ms: u64) -> bool {
        t_ms >= self.from_ms && t_ms < self.until_ms
    }
    pub fn is_valid(&self) -> bool {
        self.until_ms > self.from_ms
    }
}

/// What evidence a task state would need before a verifier may assert it.
///
/// Ordered; each tier subsumes the ones before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TaskEvidence {
    /// Someone's declaration. Enough for a plan.
    Declared,
    /// A decision point's signature. Recomputable by a third party.
    DecisionSigned,
    /// An anchored observer measured the autonomy execution.
    ExecutionObserved,
    /// An independent mechanism measured the robot's physical state.
    ///
    /// **Unreachable in this build**, computed from the class table.
    PhysicallyObserved,
}

impl TaskEvidence {
    pub fn code(self) -> u8 {
        match self {
            Self::Declared => 0x01,
            Self::DecisionSigned => 0x02,
            Self::ExecutionObserved => 0x03,
            Self::PhysicallyObserved => 0x04,
        }
    }

    /// Whether this tier is reachable at all in this build.
    pub fn is_reachable(self) -> bool {
        match self {
            Self::PhysicallyObserved => {
                aip_observation::ObservationClass::PhysicalEffect.is_implemented()
            }
            _ => true,
        }
    }
}

/// The state of a task, as claimed or as evidence supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaskState {
    Planned,
    Authorized,
    Started,
    Executing,
    Degraded,
    Paused,
    AbortRequested,
    Aborted,
    Recovering,
    Completed,
    Unknown,
}

impl TaskState {
    pub const ALL: [TaskState; 11] = [
        Self::Planned,
        Self::Authorized,
        Self::Started,
        Self::Executing,
        Self::Degraded,
        Self::Paused,
        Self::AbortRequested,
        Self::Aborted,
        Self::Recovering,
        Self::Completed,
        Self::Unknown,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::Planned => 0x01,
            Self::Authorized => 0x02,
            Self::Started => 0x03,
            Self::Executing => 0x04,
            Self::Degraded => 0x05,
            Self::Paused => 0x06,
            Self::AbortRequested => 0x07,
            Self::Aborted => 0x08,
            Self::Recovering => 0x09,
            Self::Completed => 0x0A,
            Self::Unknown => 0xFF,
        }
    }

    /// The weakest evidence that would justify asserting this state.
    ///
    /// `Paused` and `Degraded` sit at `ExecutionObserved` because both are
    /// statements about the autonomy runtime — what it stopped doing, and what
    /// coverage the verifier lost. `Aborted`, `Recovering` and `Completed` are
    /// statements about the robot's body: an aborted task whose arm kept moving
    /// is the case that matters, and no amount of software observation
    /// distinguishes it from one that stopped.
    pub fn evidence_required(self) -> TaskEvidence {
        match self {
            Self::Planned | Self::Unknown => TaskEvidence::Declared,
            Self::Authorized | Self::AbortRequested => TaskEvidence::DecisionSigned,
            Self::Started | Self::Executing | Self::Degraded | Self::Paused => {
                TaskEvidence::ExecutionObserved
            }
            Self::Aborted | Self::Recovering | Self::Completed => TaskEvidence::PhysicallyObserved,
        }
    }

    /// Whether this state is about the robot's body rather than its software.
    pub fn is_physical_claim(self) -> bool {
        matches!(self.evidence_required(), TaskEvidence::PhysicallyObserved)
    }

    /// What may be asserted, given a claim and the available evidence.
    ///
    /// Returns `Unknown` whenever the claim outruns the evidence. It may only
    /// echo or weaken — never strengthen, never substitute a neighbouring state
    /// for looking close.
    pub fn assertable(claimed: TaskState, available: TaskEvidence) -> TaskState {
        if available >= claimed.evidence_required() && claimed.evidence_required().is_reachable() {
            claimed
        } else {
            TaskState::Unknown
        }
    }

    pub fn reachable_in_this_build(self) -> bool {
        self.evidence_required().is_reachable()
    }
}

/// One task, as a document a decision point can commit to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskPlan {
    pub version: u16,
    /// The task, reusing `aip-system`'s mission identifier: a task is the
    /// robotics word for the context an execution served, and minting a second
    /// identifier for it would be a parallel identity system.
    task_id: aip_system::MissionId,
    /// The plan's revision. Two revisions are two documents with two digests.
    pub revision: u32,
    /// The robot the task is for.
    system_id: aip_system::SystemId,
    /// The chassis or cell, when the deployment names one.
    pub platform_id: Option<aip_system::PlatformId>,
    pub window: TaskWindow,
    /// The workspace the task is authorized to operate in.
    ///
    /// A free-form identifier the deployment resolves, hashed into the
    /// preimage. This crate does not model geometry: a workspace with a shape
    /// would need a position to compare it against, and no position is
    /// establishable.
    workspace_id: String,
    /// The actions the task authorizes. Sorted and deduplicated.
    authorized_actions: Vec<RobotAction>,
}

impl TaskPlan {
    pub fn new(
        task_id: aip_system::MissionId,
        revision: u32,
        system_id: aip_system::SystemId,
        window: TaskWindow,
        workspace_id: &str,
        authorized_actions: &[RobotAction],
    ) -> Result<Self, RoboticsError> {
        if !window.is_valid() {
            return Err(RoboticsError::Malformed {
                reason: "a task window must be non-empty and forward in time",
            });
        }
        if workspace_id.is_empty() || workspace_id.len() > 128 {
            return Err(RoboticsError::Malformed {
                reason: "workspace id must be 1-128 bytes",
            });
        }
        if authorized_actions.is_empty() {
            return Err(RoboticsError::Malformed {
                reason: "a task must authorize at least one action",
            });
        }
        let mut actions = authorized_actions.to_vec();
        actions.sort_unstable();
        actions.dedup();
        Ok(Self {
            version: ROBOTICS_PROFILE_VERSION,
            task_id,
            revision,
            system_id,
            platform_id: None,
            window,
            workspace_id: workspace_id.to_owned(),
            authorized_actions: actions,
        })
    }

    pub fn on_platform(mut self, platform: aip_system::PlatformId) -> Self {
        self.platform_id = Some(platform);
        self
    }

    pub fn task_id(&self) -> &aip_system::MissionId {
        &self.task_id
    }
    pub fn system_id(&self) -> &aip_system::SystemId {
        &self.system_id
    }
    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }
    pub fn authorized_actions(&self) -> &[RobotAction] {
        &self.authorized_actions
    }

    /// Whether the plan authorizes `action`. A set membership test: nothing is
    /// inferred, because authorizing `Pick` does not authorize `Place`.
    pub fn authorizes(&self, action: RobotAction) -> bool {
        self.authorized_actions.contains(&action)
    }

    pub fn applies_at(&self, t_ms: u64) -> bool {
        self.window.contains(t_ms)
    }

    pub fn check_version(&self) -> Result<(), RoboticsError> {
        if self.version != ROBOTICS_PROFILE_VERSION {
            return Err(RoboticsError::UnsupportedVersion {
                found: self.version,
                supported: ROBOTICS_PROFILE_VERSION,
            });
        }
        Ok(())
    }

    /// Domain-tagged, injective canonical bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, ROBOTICS_PROFILE_DOMAIN);
        // Structure discriminant inside the shared domain: 0x01 is a task plan.
        put_u8(&mut buf, 0x01);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, self.task_id.as_str());
        put_u32(&mut buf, self.revision);
        put_str(&mut buf, self.system_id.as_str());
        match &self.platform_id {
            Some(p) => {
                put_u8(&mut buf, 1);
                put_str(&mut buf, p.as_str());
            }
            None => put_u8(&mut buf, 0),
        }
        put_u64(&mut buf, self.window.from_ms);
        put_u64(&mut buf, self.window.until_ms);
        put_str(&mut buf, &self.workspace_id);
        put_u32(&mut buf, self.authorized_actions.len() as u32);
        for a in &self.authorized_actions {
            put_u8(&mut buf, a.code());
        }
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }

    /// The `(key, value)` pair to add to `ActionParameters` so a decision point
    /// signs this task.
    pub fn authorization_parameter(&self) -> (String, Vec<u8>) {
        (TASK_PARAMETER_KEY.to_owned(), self.digest().to_vec())
    }

    /// Whether `parameter_value` commits to this exact plan.
    ///
    /// Verifies nothing about the signature: the caller must already have
    /// verified the `ExpectedExecution` carrying the parameter digest.
    pub fn is_committed_by(&self, parameter_value: Option<&[u8]>) -> bool {
        match parameter_value {
            Some(v) => v == self.digest(),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(revision: u32, workspace: &str, actions: &[RobotAction]) -> TaskPlan {
        TaskPlan::new(
            aip_system::MissionId::parse("task:palletise-4").unwrap(),
            revision,
            aip_system::SystemId::parse("robot:cell-3-arm-1").unwrap(),
            TaskWindow {
                from_ms: 1_000,
                until_ms: 100_000,
            },
            workspace,
            actions,
        )
        .unwrap()
    }

    #[test]
    fn self_reported_task_completion_is_never_asserted() {
        for tier in [
            TaskEvidence::Declared,
            TaskEvidence::DecisionSigned,
            TaskEvidence::ExecutionObserved,
            TaskEvidence::PhysicallyObserved,
        ] {
            assert_eq!(
                TaskState::assertable(TaskState::Completed, tier),
                TaskState::Unknown,
                "COMPLETED became assertable at {tier:?}"
            );
        }
    }

    #[test]
    fn every_physical_state_is_unreachable() {
        for s in [
            TaskState::Aborted,
            TaskState::Recovering,
            TaskState::Completed,
        ] {
            assert!(s.is_physical_claim(), "{s:?}");
            assert!(!s.reachable_in_this_build(), "{s:?}");
        }
    }

    #[test]
    fn software_states_are_assertable_from_observed_execution() {
        for s in [
            TaskState::Started,
            TaskState::Executing,
            TaskState::Degraded,
            TaskState::Paused,
        ] {
            assert_eq!(
                TaskState::assertable(s, TaskEvidence::ExecutionObserved),
                s,
                "{s:?}"
            );
            assert_eq!(
                TaskState::assertable(s, TaskEvidence::DecisionSigned),
                TaskState::Unknown,
                "{s:?}"
            );
        }
    }

    #[test]
    fn an_abort_request_is_weaker_than_an_abort() {
        assert!(
            TaskState::AbortRequested.evidence_required() < TaskState::Aborted.evidence_required()
        );
        assert_eq!(
            TaskState::assertable(TaskState::AbortRequested, TaskEvidence::DecisionSigned),
            TaskState::AbortRequested
        );
        assert_eq!(
            TaskState::assertable(TaskState::Aborted, TaskEvidence::DecisionSigned),
            TaskState::Unknown
        );
    }

    #[test]
    fn assertable_never_strengthens_or_substitutes() {
        for claimed in TaskState::ALL {
            for tier in [
                TaskEvidence::Declared,
                TaskEvidence::DecisionSigned,
                TaskEvidence::ExecutionObserved,
                TaskEvidence::PhysicallyObserved,
            ] {
                let out = TaskState::assertable(claimed, tier);
                assert!(
                    out == claimed || out == TaskState::Unknown,
                    "{claimed:?}/{tier:?}"
                );
            }
        }
    }

    #[test]
    fn a_plan_carries_no_authority_until_committed() {
        let p = plan(1, "cell-3", &[RobotAction::Pick]);
        assert!(!p.is_committed_by(None));
        assert!(p.is_committed_by(Some(&p.digest())));
        assert!(!p.is_committed_by(Some(&plan(2, "cell-3", &[RobotAction::Pick]).digest())));
    }

    #[test]
    fn the_workspace_is_part_of_the_document() {
        assert_ne!(
            plan(1, "cell-3", &[RobotAction::Pick]).digest(),
            plan(1, "cell-4", &[RobotAction::Pick]).digest(),
            "a task authorized in one cell must not commit for another"
        );
    }

    #[test]
    fn the_action_set_is_order_independent_and_content_sensitive() {
        let a = plan(1, "c", &[RobotAction::Pick, RobotAction::Place]);
        let b = plan(1, "c", &[RobotAction::Place, RobotAction::Pick]);
        assert_eq!(a.digest(), b.digest());
        assert_ne!(a.digest(), plan(1, "c", &[RobotAction::Pick]).digest());
    }

    #[test]
    fn authorizing_pick_does_not_authorize_place() {
        let p = plan(1, "c", &[RobotAction::Pick]);
        assert!(p.authorizes(RobotAction::Pick));
        assert!(!p.authorizes(RobotAction::Place));
        assert!(!p.authorizes(RobotAction::ActivateTool));
    }

    #[test]
    fn malformed_plans_are_refused() {
        let id = || aip_system::MissionId::parse("task:x").unwrap();
        let sys = || aip_system::SystemId::parse("robot:y").unwrap();
        let win = TaskWindow {
            from_ms: 1,
            until_ms: 2,
        };
        assert!(TaskPlan::new(id(), 1, sys(), win, "", &[RobotAction::Pick]).is_err());
        assert!(TaskPlan::new(id(), 1, sys(), win, "w", &[]).is_err());
        assert!(TaskPlan::new(
            id(),
            1,
            sys(),
            TaskWindow {
                from_ms: 5,
                until_ms: 5
            },
            "w",
            &[RobotAction::Pick]
        )
        .is_err());
    }

    #[test]
    fn the_window_is_half_open() {
        let p = plan(1, "c", &[RobotAction::Pick]);
        assert!(!p.applies_at(999));
        assert!(p.applies_at(1_000));
        assert!(!p.applies_at(100_000));
    }
}
