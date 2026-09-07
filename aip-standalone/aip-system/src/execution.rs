//! `SystemExecution` — where the levels are bound together, for one run.
//!
//! Every binding in this model is many-to-many over time, which is exactly why
//! it must be stated per execution and not per system:
//!
//! - one platform runs different intelligences at different times (retrofit);
//! - one intelligence runs on different platforms (a fleet);
//! - one intelligence has many concurrent executions (workers);
//! - a mission spans many executions, and an execution serves one mission;
//! - hardware is replaced without the platform changing identity;
//! - the platform is replaced without the system changing identity.
//!
//! A `SystemExecution` says: *this system, running this intelligence, as this
//! execution, on this hardware, in this platform, for this mission.* It is
//! true for a bounded interval and false outside it.
//!
//! # It grants nothing
//!
//! There is no token, scope, key or signature here either. `AuthorityContext`
//! cites the authorization; it is not the authorization, and nothing in this
//! crate reads it to decide anything (D17-4). In particular
//! `parent_execution_id` is lineage data: a child execution inherits *nothing*
//! from its parent by existing, and no code path here transfers a permission
//! along it (S17-5).

use aip_types::canonical::{put_bytes, put_domain, put_str, put_u16, put_u64, put_u8};
use aip_types::ExecutionBinding;
use serde::{Deserialize, Serialize};

use crate::error::SystemError;
use crate::ids::{HardwareId, MissionId, PlatformId, SystemId};

/// Domain tag leading every `SystemExecution` canonical encoding.
///
/// Distinct from the `AutonomousSystem` tag so the two can never be confused
/// by a verifier reading raw bytes, even if their field layouts were to
/// coincide.
pub const SYSTEM_EXECUTION_DOMAIN: &str = "SYNTRIASS/AUTONOMY/EXECUTION/v1";

/// Structure version. Unknown versions are refused, never guessed.
pub const SYSTEM_EXECUTION_VERSION: u16 = 1;

/// A citation of the authorization an execution ran under.
///
/// # A citation, not a grant
///
/// This names where the authority is; it does not carry it. The authority is a
/// signed token chain adjudicated by a decision point, and that chain is what
/// permits anything. Holding a `AuthorityContext` that names a `decision_id`
/// is exactly as powerful as knowing the number — which is to say, not at all.
///
/// It is here so an execution record can be joined to the `ExpectedExecution`
/// it claims, which is what lets a verifier ask whether the claim is true. A
/// claim is not its own confirmation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityContext {
    /// The `ExpectedExecution.decision_id` this run claims. `None` means the
    /// execution claimed no authorization — itself a statement a verifier can
    /// act on, and a more honest one than a fabricated id.
    pub decision_id: Option<[u8; 16]>,
    /// JTI of the root token at the head of the claimed chain, when known.
    /// Context for locating the chain; never a substitute for verifying it.
    pub root_token_jti: Option<[u8; 16]>,
}

impl AuthorityContext {
    /// Cites nothing. The honest default for a record whose authorization is
    /// unknown, and distinguishable from a record that claims one.
    pub fn none() -> Self {
        Self {
            decision_id: None,
            root_token_jti: None,
        }
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        match &self.decision_id {
            Some(d) => {
                put_u8(buf, 1);
                put_bytes(buf, d);
            }
            None => put_u8(buf, 0),
        }
        match &self.root_token_jti {
            Some(j) => {
                put_u8(buf, 1);
                put_bytes(buf, j);
            }
            None => put_u8(buf, 0),
        }
    }
}

/// One execution of one intelligence, on one host, as part of one system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemExecution {
    pub version: u16,
    /// The durable system this execution belongs to.
    pub system_id: SystemId,
    /// AIP-ID of the intelligence that ran. Validated on construction: an
    /// unparseable AIP-ID is refused rather than stored (S17-11).
    agent_id: String,
    /// The AIRI execution instance. Reused verbatim from `aip-airi`; this
    /// model adds no execution identifier of its own.
    pub execution_id: [u8; 16],
    /// The execution that spawned this one.
    ///
    /// **Lineage, not inheritance.** Being someone's child grants nothing.
    /// Nothing in this crate walks this field to transfer a permission, and
    /// there is no permission here to transfer.
    pub parent_execution_id: Option<[u8; 16]>,
    /// The compute host. `None` when unknown — not fabricated.
    pub hardware_id: Option<HardwareId>,
    /// The platform this execution actually ran on.
    ///
    /// Deliberately separate from the system's *registered* platform: an
    /// execution running on a platform other than the registered one is
    /// exactly the situation worth being able to state (D17-2).
    pub platform_id: Option<PlatformId>,
    /// The mission this execution served.
    pub mission_id: Option<MissionId>,
    /// What authorization this execution claims. A citation (see
    /// [`AuthorityContext`]).
    pub authority: AuthorityContext,
    /// The OS-level binding, when one was collected. Reused verbatim from
    /// `aip-types`, including its self-report caveat: a binding an agent
    /// collected about itself is a claim until an independent observer
    /// attests the same facts.
    pub execution_binding: Option<ExecutionBinding>,
    /// Unix ms this record was written. Context; not a validity window.
    pub recorded_at_ms: u64,
}

impl SystemExecution {
    /// Build a record, validating the agent id.
    ///
    /// The AIP-ID is checked here because this is the boundary: after
    /// construction the field is private and every reader can rely on it
    /// being well formed. A malformed identity that reached a canonical
    /// encoding would be a malformed identity inside a signed artifact.
    pub fn new(
        system_id: SystemId,
        agent_id: &str,
        execution_id: [u8; 16],
        recorded_at_ms: u64,
    ) -> Result<Self, SystemError> {
        aip_crypto::validate_aip_id(agent_id).map_err(|_| SystemError::InvalidAgentId)?;
        Ok(Self {
            version: SYSTEM_EXECUTION_VERSION,
            system_id,
            agent_id: agent_id.to_owned(),
            execution_id,
            parent_execution_id: None,
            hardware_id: None,
            platform_id: None,
            mission_id: None,
            authority: AuthorityContext::none(),
            execution_binding: None,
            recorded_at_ms,
        })
    }

    /// The intelligence that ran. Read-only: the field is private so a
    /// caller cannot swap in an unvalidated id after construction.
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub fn with_parent(mut self, parent: [u8; 16]) -> Self {
        self.parent_execution_id = Some(parent);
        self
    }
    pub fn on_hardware(mut self, hardware: HardwareId) -> Self {
        self.hardware_id = Some(hardware);
        self
    }
    pub fn on_platform(mut self, platform: PlatformId) -> Self {
        self.platform_id = Some(platform);
        self
    }
    pub fn for_mission(mut self, mission: MissionId) -> Self {
        self.mission_id = Some(mission);
        self
    }
    pub fn citing(mut self, authority: AuthorityContext) -> Self {
        self.authority = authority;
        self
    }
    pub fn bound_to(mut self, binding: ExecutionBinding) -> Self {
        self.execution_binding = Some(binding);
        self
    }

    /// Refuse a structure whose version this build does not implement.
    ///
    /// Deserialization does not call this — serde will parse a version-2
    /// record into version-1 fields quite happily. A reader must call it
    /// before trusting what it read.
    pub fn check_version(&self) -> Result<(), SystemError> {
        if self.version != SYSTEM_EXECUTION_VERSION {
            return Err(SystemError::UnsupportedVersion {
                found: self.version,
                supported: SYSTEM_EXECUTION_VERSION,
            });
        }
        aip_crypto::validate_aip_id(&self.agent_id).map_err(|_| SystemError::InvalidAgentId)?;
        Ok(())
    }

    /// Domain-tagged, injective canonical bytes.
    ///
    /// Every identity in the record is inside these bytes. That is what makes
    /// a transplant detectable (S17-9): swapping the platform, the hardware,
    /// the mission or the agent changes the encoding, so any signature over it
    /// stops verifying. Nothing here *prevents* a transplant — an unsigned
    /// descriptor cannot — but a transplant cannot be silent.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, SYSTEM_EXECUTION_DOMAIN);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, self.system_id.as_str());
        put_str(&mut buf, &self.agent_id);
        put_bytes(&mut buf, &self.execution_id);
        match &self.parent_execution_id {
            Some(p) => {
                put_u8(&mut buf, 1);
                put_bytes(&mut buf, p);
            }
            None => put_u8(&mut buf, 0),
        }
        // Each optional identity: presence byte then the value. Absent and
        // empty must not encode alike, and the four identity slots must not
        // be able to shift into one another.
        put_opt_id(&mut buf, self.hardware_id.as_ref().map(|h| h.as_str()));
        put_opt_id(&mut buf, self.platform_id.as_ref().map(|p| p.as_str()));
        put_opt_id(&mut buf, self.mission_id.as_ref().map(|m| m.as_str()));
        self.authority.encode(&mut buf);
        match &self.execution_binding {
            Some(b) => {
                put_u8(&mut buf, 1);
                // The binding's own canonical encoding, length-prefixed so it
                // cannot run into the following field.
                put_bytes(&mut buf, &b.canonical_bytes());
            }
            None => put_u8(&mut buf, 0),
        }
        put_u64(&mut buf, self.recorded_at_ms);
        buf
    }
}

fn put_opt_id(buf: &mut Vec<u8>, id: Option<&str>) {
    match id {
        Some(v) => {
            put_u8(buf, 1);
            put_str(buf, v);
        }
        None => put_u8(buf, 0),
    }
}
