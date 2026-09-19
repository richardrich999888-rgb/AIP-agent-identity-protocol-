//! Tenant and workload binding, kept separate from global identity.
//!
//! # Four identities that must not collapse
//!
//! | identity | what it names | who asserts it |
//! |---|---|---|
//! | tenant | the company the work is done for | the operator |
//! | autonomous actor | the agent, by AIP-ID | the identity layer |
//! | workload | the deployed thing — a service, a job, a graph | the operator |
//! | process execution | *this* process instance running *this* binary | an observer measures it |
//!
//! Collapsing any pair of them produces a real failure. Tenant into actor, and
//! one customer's agent can act as another's. Workload into actor, and two
//! deployments of one agent are indistinguishable. Actor into process, and a
//! restarted service inherits the previous run's history. Process into
//! workload, and every replica is the same execution.
//!
//! # Why a token cannot be copied into an identity
//!
//! Tenant, workload and framework are strings. Anything that holds them can
//! send them. So [`WorkloadBinding`] commits to them **together with the
//! execution identity digest** — `ExecutionBinding::identity_bytes`, which
//! covers the agent AIP-ID, the process instance triple and the executable's
//! *contents*.
//!
//! A context lifted from one workload and replayed by another therefore names a
//! process instance that is not the replayer's, and
//! [`WorkloadBinding::covers`] is false. There is no path that accepts the
//! strings alone, because there is no constructor that takes them alone.

use aip_crypto::sha256;
use aip_types::canonical::{put_bytes, put_domain, put_str, put_u16, put_u64};
use aip_types::ExecutionBinding;
use serde::{Deserialize, Serialize};

use crate::error::EnterpriseError;
use crate::{ENTERPRISE_PROFILE_DOMAIN, ENTERPRISE_PROFILE_VERSION};

/// The reserved action-parameter key carrying a workload-binding commitment.
pub const WORKLOAD_BINDING_PARAMETER_KEY: &str = "aip.enterprise.workload_binding.v1";

/// Which of the four identities a name refers to.
///
/// A vocabulary, so that code and reviews can say which one they mean. It
/// grants nothing and is not an identifier type: `aip-system` owns those, and
/// this profile expresses a tenant with a validated string inside a commitment
/// rather than minting a parallel identity system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IdentityKind {
    /// The company or organisational unit the work is done for.
    Tenant,
    /// The agent, by AIP-ID. The identity layer's, not this profile's.
    AutonomousActor,
    /// The deployed thing: a service, a job, a graph revision.
    Workload,
    /// This process instance running this executable content. The only one a
    /// mechanism measures.
    ProcessExecution,
}

impl IdentityKind {
    pub const ALL: [IdentityKind; 4] = [
        Self::Tenant,
        Self::AutonomousActor,
        Self::Workload,
        Self::ProcessExecution,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::Tenant => 0x01,
            Self::AutonomousActor => 0x02,
            Self::Workload => 0x03,
            Self::ProcessExecution => 0x04,
        }
    }

    /// Whether a mechanism measures this identity, or an operator declares it.
    pub fn is_measured(self) -> bool {
        matches!(self, Self::ProcessExecution)
    }

    /// Whether this identity may stand in for another.
    ///
    /// **`false` for every pair, including a kind and itself-as-another-kind.**
    /// The method takes the other kind so a caller asking the question gets a
    /// `false` and a reason rather than reaching for an accessor.
    pub fn may_substitute_for(self, _other: IdentityKind) -> bool {
        false
    }

    pub fn statement(self) -> &'static str {
        match self {
            Self::Tenant => {
                "declared by the operator; names who the work is for, and nothing about who did it"
            }
            Self::AutonomousActor => "an AIP-ID; names the agent, and not the run",
            Self::Workload => "declared by the operator; names the deployment, and not the process",
            Self::ProcessExecution => {
                "measured: a process instance and the executable's contents; the only one an \
                 observer establishes"
            }
        }
    }
}

/// A tenant and workload, bound to a specific execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadBinding {
    pub version: u16,
    tenant: String,
    workload: String,
    system_id: aip_system::SystemId,
    /// Commitment over the framework's name, version and adapter version.
    ///
    /// Committed so a cross-framework transplant changes the digest. **Not a
    /// trust input**: nothing here branches on the framework's name, and
    /// `aip-airi::FrameworkIdentity` says the same for the same reason.
    framework_digest: [u8; 32],
    /// `SHA-256(ExecutionBinding::identity_bytes)` — agent AIP-ID, process
    /// instance triple, executable contents.
    execution_identity_digest: [u8; 32],
    pub bound_at_ms: u64,
}

/// Commitment over a framework identity's public fields.
///
/// Domain-separated so it cannot be confused with any other digest, and
/// computed from the public fields rather than by reaching into `aip-airi`'s
/// private encoder — the profile commits to what the framework said, and does
/// not fork how the framework says it.
pub fn framework_commitment(name: &str, version: &str, adapter_version: &str) -> [u8; 32] {
    let mut buf = Vec::new();
    put_domain(&mut buf, ENTERPRISE_PROFILE_DOMAIN);
    buf.push(0x04); // structure discriminant: a framework commitment
    put_str(&mut buf, name);
    put_str(&mut buf, version);
    put_str(&mut buf, adapter_version);
    sha256(&buf)
}

fn bounded(field: &'static str, v: &str) -> Result<(), EnterpriseError> {
    if v.is_empty() || v.len() > 128 {
        return Err(EnterpriseError::Malformed { reason: field });
    }
    Ok(())
}

impl WorkloadBinding {
    /// Bind a tenant and workload to an execution.
    ///
    /// Takes the `ExecutionBinding` itself rather than a digest, so there is no
    /// constructor a caller can reach with strings alone.
    pub fn new(
        tenant: &str,
        workload: &str,
        system_id: aip_system::SystemId,
        framework_digest: [u8; 32],
        execution: &ExecutionBinding,
        bound_at_ms: u64,
    ) -> Result<Self, EnterpriseError> {
        bounded("tenant must be 1-128 bytes", tenant)?;
        bounded("workload must be 1-128 bytes", workload)?;
        Ok(Self {
            version: ENTERPRISE_PROFILE_VERSION,
            tenant: tenant.to_owned(),
            workload: workload.to_owned(),
            system_id,
            framework_digest,
            execution_identity_digest: sha256(&execution.identity_bytes()),
            bound_at_ms,
        })
    }

    pub fn tenant(&self) -> &str {
        &self.tenant
    }
    pub fn workload(&self) -> &str {
        &self.workload
    }
    pub fn system_id(&self) -> &aip_system::SystemId {
        &self.system_id
    }
    pub fn framework_digest(&self) -> [u8; 32] {
        self.framework_digest
    }
    pub fn execution_identity_digest(&self) -> [u8; 32] {
        self.execution_identity_digest
    }

    /// Whether this binding covers `execution`.
    ///
    /// Compares the execution identity, which covers the agent, the process
    /// instance triple and the executable's contents. Equal pids are never
    /// sufficient, because `identity_bytes` includes the start ticks and the
    /// boot id.
    pub fn covers(&self, execution: &ExecutionBinding) -> bool {
        self.execution_identity_digest == sha256(&execution.identity_bytes())
    }

    /// Refuse a binding offered for an execution it does not cover.
    pub fn admit(&self, execution: &ExecutionBinding) -> Result<(), EnterpriseError> {
        if self.covers(execution) {
            return Ok(());
        }
        Err(EnterpriseError::BindingDoesNotCoverExecution {
            expected: self.execution_identity_digest,
            offered: sha256(&execution.identity_bytes()),
        })
    }

    /// Whether this binding is for the same tenant as another.
    ///
    /// A string comparison, and named as one. It is **not** an authorization
    /// check: two bindings sharing a tenant says nothing about whether either
    /// was permitted.
    pub fn same_tenant(&self, other: &WorkloadBinding) -> bool {
        self.tenant == other.tenant
    }

    pub fn check_version(&self) -> Result<(), EnterpriseError> {
        if self.version != ENTERPRISE_PROFILE_VERSION {
            return Err(EnterpriseError::UnsupportedVersion {
                found: self.version,
                supported: ENTERPRISE_PROFILE_VERSION,
            });
        }
        Ok(())
    }

    /// Domain-tagged, injective canonical bytes over every field.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, ENTERPRISE_PROFILE_DOMAIN);
        // Structure discriminant: 0x02 is a workload binding.
        buf.push(0x02);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, &self.tenant);
        put_str(&mut buf, &self.workload);
        put_str(&mut buf, self.system_id.as_str());
        put_bytes(&mut buf, &self.framework_digest);
        put_bytes(&mut buf, &self.execution_identity_digest);
        put_u64(&mut buf, self.bound_at_ms);
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }

    pub fn authorization_parameter(&self) -> (String, Vec<u8>) {
        (
            WORKLOAD_BINDING_PARAMETER_KEY.to_owned(),
            self.digest().to_vec(),
        )
    }

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
    use aip_types::ProcessInstance;
    use aip_types::EXECUTION_BINDING_VERSION;

    fn execution(agent: &str, pid: u32, ticks: u64, exe: u8) -> ExecutionBinding {
        ExecutionBinding {
            version: EXECUTION_BINDING_VERSION,
            agent_id: agent.to_owned(),
            process: ProcessInstance {
                pid,
                pid_start_time_ticks: ticks,
                boot_id: [0x11; 16],
            },
            exe_content_sha256: [exe; 32],
            exe_path: "/usr/bin/agent".to_owned(),
            bound_at_ms: 1_000,
            container: None,
        }
    }

    fn sys() -> aip_system::SystemId {
        aip_system::SystemId::parse("enterprise:svc-orders").unwrap()
    }

    fn fw() -> [u8; 32] {
        framework_commitment("langgraph", "0.2.1", "vanian-1")
    }

    fn binding(tenant: &str, workload: &str, exec: &ExecutionBinding) -> WorkloadBinding {
        WorkloadBinding::new(tenant, workload, sys(), fw(), exec, 1_000).unwrap()
    }

    #[test]
    fn a_binding_covers_only_the_execution_it_was_made_for() {
        let e = execution("aip:agent-1", 42, 900, 0xAA);
        let b = binding("acme", "orders", &e);
        assert!(b.covers(&e));
        assert!(b.admit(&e).is_ok());

        // Same pid, different start ticks: a different process instance.
        let reused_pid = execution("aip:agent-1", 42, 901, 0xAA);
        assert!(!b.covers(&reused_pid));
        assert!(matches!(
            b.admit(&reused_pid),
            Err(EnterpriseError::BindingDoesNotCoverExecution { .. })
        ));

        // Same process, different binary contents.
        let different_binary = execution("aip:agent-1", 42, 900, 0xBB);
        assert!(!b.covers(&different_binary));

        // Same process, different agent.
        let different_agent = execution("aip:agent-2", 42, 900, 0xAA);
        assert!(!b.covers(&different_agent));
    }

    #[test]
    fn a_copied_tenant_and_workload_do_not_make_a_binding() {
        // The attack: lift the strings, use them from another process.
        let victim = execution("aip:agent-1", 42, 900, 0xAA);
        let attacker = execution("aip:agent-1", 77, 950, 0xAA);
        let b = binding("acme", "orders", &victim);
        // The attacker can name the same tenant and workload...
        let forged = binding("acme", "orders", &attacker);
        assert_eq!(b.tenant(), forged.tenant());
        assert_eq!(b.workload(), forged.workload());
        // ...and the bindings are still different, and neither covers the
        // other's execution.
        assert_ne!(b.digest(), forged.digest());
        assert!(!b.covers(&attacker));
        assert!(!forged.covers(&victim));
    }

    #[test]
    fn the_tenant_the_workload_and_the_framework_are_all_committed() {
        let e = execution("aip:agent-1", 42, 900, 0xAA);
        let base = binding("acme", "orders", &e);
        assert_ne!(base.digest(), binding("globex", "orders", &e).digest());
        assert_ne!(base.digest(), binding("acme", "billing", &e).digest());
        let other_fw = WorkloadBinding::new(
            "acme",
            "orders",
            sys(),
            framework_commitment("autogen", "0.4.0", "vanian-1"),
            &e,
            1_000,
        )
        .unwrap();
        assert_ne!(base.digest(), other_fw.digest());
        let other_sys = WorkloadBinding::new(
            "acme",
            "orders",
            aip_system::SystemId::parse("enterprise:svc-billing").unwrap(),
            fw(),
            &e,
            1_000,
        )
        .unwrap();
        assert_ne!(base.digest(), other_sys.digest());
    }

    #[test]
    fn the_adapter_version_is_part_of_the_framework_commitment() {
        // A changed translation is a changed claim, even from the same
        // framework at the same version.
        assert_ne!(
            framework_commitment("langgraph", "0.2.1", "vanian-1"),
            framework_commitment("langgraph", "0.2.1", "vanian-2")
        );
        assert_ne!(
            framework_commitment("langgraph", "0.2.1", "vanian-1"),
            framework_commitment("langgraph", "0.2.2", "vanian-1")
        );
    }

    #[test]
    fn the_four_identities_never_substitute_for_one_another() {
        for a in IdentityKind::ALL {
            for b in IdentityKind::ALL {
                assert!(!a.may_substitute_for(b), "{a:?} -> {b:?}");
            }
            assert!(!a.statement().is_empty(), "{a:?}");
        }
        let measured: Vec<IdentityKind> = IdentityKind::ALL
            .iter()
            .copied()
            .filter(|k| k.is_measured())
            .collect();
        assert_eq!(
            measured,
            vec![IdentityKind::ProcessExecution],
            "only the process execution is measured; the rest are declared"
        );
    }

    #[test]
    fn same_tenant_is_a_string_comparison_and_not_an_authorization() {
        let e1 = execution("aip:agent-1", 42, 900, 0xAA);
        let e2 = execution("aip:agent-2", 43, 901, 0xBB);
        let a = binding("acme", "orders", &e1);
        let b = binding("acme", "billing", &e2);
        assert!(a.same_tenant(&b));
        // And it buys nothing: neither covers the other's execution.
        assert!(!a.covers(&e2));
        assert!(!b.covers(&e1));
    }

    #[test]
    fn a_commitment_matches_only_itself() {
        let e = execution("aip:agent-1", 42, 900, 0xAA);
        let b = binding("acme", "orders", &e);
        assert!(b.is_committed_by(Some(&b.digest())));
        assert!(!b.is_committed_by(None));
        assert!(!b.is_committed_by(Some(&binding("globex", "orders", &e).digest())));
        assert!(b.check_version().is_ok());
    }

    #[test]
    fn identifiers_are_bounded() {
        let e = execution("aip:agent-1", 42, 900, 0xAA);
        assert!(WorkloadBinding::new("", "w", sys(), fw(), &e, 1).is_err());
        assert!(WorkloadBinding::new("t", "", sys(), fw(), &e, 1).is_err());
        assert!(WorkloadBinding::new(&"x".repeat(129), "w", sys(), fw(), &e, 1).is_err());
        assert!(WorkloadBinding::new("t", &"x".repeat(129), sys(), fw(), &e, 1).is_err());
    }
}
