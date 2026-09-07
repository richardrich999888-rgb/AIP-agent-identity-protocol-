//! End-to-end context propagation across worker, subprocess and container
//! boundaries.
//!
//! # The boundaries are `aip-airi`'s, and a container is a process
//!
//! [`aip_airi::PropagationBoundary`] already names async task, thread, process,
//! subprocess and worker queue. Skill 27 also asks for containers, and this
//! profile deliberately does **not** add a variant for one.
//!
//! A container is a process in namespaces and cgroups. At the boundary the
//! kernel sees, a container crossing *is* a process crossing, and the existing
//! `Process` boundary represents it faithfully. What a container adds is an
//! attribution — "this ran in container X" — and no mechanism in this build
//! measures that: nothing observes a namespace set or a cgroup as an identity,
//! and a namespace inode is reused after it is freed.
//!
//! So [`ContainerAttribution`] is carried, committed, and
//! `is_measured()` is `false`. Adding a `PropagationBoundary::Container` would
//! have changed a signed wire format to imply a boundary the core cannot see.
//!
//! # Why a hop chains to its predecessor
//!
//! A downstream context that does not link to the one above it is a new context
//! wearing an old name. Each hop commits to the previous hop's digest, so
//! lifting a hop out of one chain and pasting it into another changes its
//! digest and breaks the link.
//!
//! The chain root commits to the [`crate::binding::WorkloadBinding`] digest,
//! which itself commits to the execution identity. So a chain cannot be
//! transplanted between workloads, between tenants or between process
//! instances.

use aip_airi::PropagationBoundary;
use aip_crypto::sha256;
use aip_types::canonical::{put_bytes, put_domain, put_str, put_u16, put_u32, put_u64, put_u8};
use serde::{Deserialize, Serialize};

use crate::binding::WorkloadBinding;
use crate::error::EnterpriseError;
use crate::{ENTERPRISE_PROFILE_DOMAIN, ENTERPRISE_PROFILE_VERSION};

/// A container the work ran in, as the deployment declares it.
///
/// Declared, never measured. Committed so a claim about it cannot be revised,
/// and reported as unmeasured so it cannot be read as an observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerAttribution {
    /// The runtime's own id, as the agent read it — typically from
    /// `/proc/self/cgroup` or an environment variable, both of which are
    /// inside the container and written by whoever built it.
    container_id: String,
    /// The image reference the deployment says it ran.
    image_ref: String,
}

impl ContainerAttribution {
    pub fn new(container_id: &str, image_ref: &str) -> Result<Self, EnterpriseError> {
        for (field, v) in [
            ("container id must be 1-128 bytes", container_id),
            ("image reference must be 1-256 bytes", image_ref),
        ] {
            if v.is_empty() || v.len() > 256 {
                return Err(EnterpriseError::Malformed { reason: field });
            }
        }
        if container_id.len() > 128 {
            return Err(EnterpriseError::Malformed {
                reason: "container id must be 1-128 bytes",
            });
        }
        Ok(Self {
            container_id: container_id.to_owned(),
            image_ref: image_ref.to_owned(),
        })
    }

    pub fn container_id(&self) -> &str {
        &self.container_id
    }
    pub fn image_ref(&self) -> &str {
        &self.image_ref
    }

    /// Whether any mechanism measured this attribution.
    ///
    /// **`false`.** The id is read from inside the container by the process
    /// under scrutiny, and a namespace inode is reused after it is freed. What
    /// *is* measured is the process: its instance triple and its executable
    /// contents, which the execution identity already covers.
    pub fn is_measured(&self) -> bool {
        false
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        put_str(buf, &self.container_id);
        put_str(buf, &self.image_ref);
    }
}

/// One hop of an execution context across a boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextHop {
    /// Position in the chain, from 0.
    pub index: u32,
    /// The boundary crossed. `aip-airi`'s vocabulary, consumed.
    pub boundary: PropagationBoundary,
    /// The execution the context was handed to.
    pub to_execution_id: [u8; 16],
    /// The container the downstream side ran in, when the deployment declares
    /// one. Unmeasured either way.
    pub container: Option<ContainerAttribution>,
    /// The digest of the hop before this one, or the chain root's binding
    /// digest for hop 0.
    pub links_to: [u8; 32],
}

impl ContextHop {
    fn encode(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.index);
        put_u8(buf, self.boundary.code());
        put_bytes(buf, &self.to_execution_id);
        match &self.container {
            None => put_u8(buf, 0),
            Some(c) => {
                put_u8(buf, 1);
                c.encode(buf);
            }
        }
        put_bytes(buf, &self.links_to);
    }

    /// Domain-tagged canonical bytes for this hop.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, ENTERPRISE_PROFILE_DOMAIN);
        // Structure discriminant: 0x03 is a context hop.
        put_u8(&mut buf, 0x03);
        self.encode(&mut buf);
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }
}

/// An execution context propagated across one or more boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextChain {
    pub version: u16,
    /// The binding this chain is rooted in. Its digest is what hop 0 links to,
    /// so the chain cannot be transplanted between workloads or tenants.
    root_binding_digest: [u8; 32],
    hops: Vec<ContextHop>,
    /// The interval this context is valid for. Half-open `[from, until)`.
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
}

impl ContextChain {
    /// Start a chain at a workload binding.
    pub fn rooted_at(
        binding: &WorkloadBinding,
        valid_from_ms: u64,
        valid_until_ms: u64,
    ) -> Result<Self, EnterpriseError> {
        if valid_until_ms <= valid_from_ms {
            return Err(EnterpriseError::Malformed {
                reason: "a context validity window must be non-empty and forward in time",
            });
        }
        Ok(Self {
            version: ENTERPRISE_PROFILE_VERSION,
            root_binding_digest: binding.digest(),
            hops: Vec::new(),
            valid_from_ms,
            valid_until_ms,
        })
    }

    pub fn root_binding_digest(&self) -> [u8; 32] {
        self.root_binding_digest
    }
    pub fn hops(&self) -> &[ContextHop] {
        &self.hops
    }
    pub fn len(&self) -> usize {
        self.hops.len()
    }
    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }

    /// The digest the next hop must link to.
    pub fn next_link(&self) -> [u8; 32] {
        self.hops
            .last()
            .map(|h| h.digest())
            .unwrap_or(self.root_binding_digest)
    }

    /// Extend the chain across a boundary.
    ///
    /// The link is computed here rather than supplied, so a caller cannot build
    /// a hop that claims to follow something it does not.
    pub fn extend(
        &mut self,
        boundary: PropagationBoundary,
        to_execution_id: [u8; 16],
        container: Option<ContainerAttribution>,
    ) -> &ContextHop {
        let hop = ContextHop {
            index: self.hops.len() as u32,
            boundary,
            to_execution_id,
            container,
            links_to: self.next_link(),
        };
        self.hops.push(hop);
        self.hops.last().expect("just pushed")
    }

    /// Re-check that every hop links to its predecessor.
    ///
    /// Named `check_links` rather than `verify_*`: verification of evidence is
    /// the core's word and this is a structural self-check on a document.
    ///
    /// The function a receiver calls on a chain that arrived over a wire. A hop
    /// lifted from another chain has a `links_to` that does not match, and a
    /// hop whose contents were edited changes the digest the *next* hop links
    /// to.
    pub fn check_links(&self) -> Result<(), EnterpriseError> {
        let mut expected = self.root_binding_digest;
        for (i, hop) in self.hops.iter().enumerate() {
            if hop.index != i as u32 || hop.links_to != expected {
                return Err(EnterpriseError::ContextChainBroken { at_hop: i as u32 });
            }
            expected = hop.digest();
        }
        Ok(())
    }

    /// Whether the chain is within its validity window at `t_ms`.
    pub fn is_fresh_at(&self, t_ms: u64) -> bool {
        t_ms >= self.valid_from_ms && t_ms < self.valid_until_ms
    }

    /// Admit the chain for use at `t_ms`, against the execution presenting it.
    ///
    /// Three conditions, each of which can only refuse: the links must hold,
    /// the window must contain the moment, and the binding the chain is rooted
    /// in must cover the presenting execution. The third is the one that makes
    /// a copied context useless.
    pub fn admit(
        &self,
        binding: &WorkloadBinding,
        execution: &aip_types::ExecutionBinding,
        t_ms: u64,
    ) -> Result<(), EnterpriseError> {
        self.check_links()?;
        if !self.is_fresh_at(t_ms) {
            return Err(EnterpriseError::ContextStale {
                at_ms: t_ms,
                from_ms: self.valid_from_ms,
                until_ms: self.valid_until_ms,
            });
        }
        if binding.digest() != self.root_binding_digest {
            return Err(EnterpriseError::ContextChainBroken { at_hop: 0 });
        }
        binding.admit(execution)
    }

    /// Whether any container attribution in the chain was measured.
    ///
    /// **`false`.** Carried as a method so a caller looking for measured
    /// container identity finds the answer rather than an accessor.
    pub fn container_identity_measured(&self) -> bool {
        self.hops
            .iter()
            .filter_map(|h| h.container.as_ref())
            .any(|c| c.is_measured())
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

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, ENTERPRISE_PROFILE_DOMAIN);
        // Structure discriminant: 0x05 is a context chain.
        put_u8(&mut buf, 0x05);
        put_u16(&mut buf, self.version);
        put_bytes(&mut buf, &self.root_binding_digest);
        put_u64(&mut buf, self.valid_from_ms);
        put_u64(&mut buf, self.valid_until_ms);
        put_u32(&mut buf, self.hops.len() as u32);
        for h in &self.hops {
            h.encode(&mut buf);
        }
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::framework_commitment;
    use aip_types::{ExecutionBinding, ProcessInstance};

    fn execution(agent: &str, pid: u32, ticks: u64) -> ExecutionBinding {
        ExecutionBinding {
            version: 1,
            agent_id: agent.to_owned(),
            process: ProcessInstance {
                pid,
                pid_start_time_ticks: ticks,
                boot_id: [0x11; 16],
            },
            exe_content_sha256: [0xAA; 32],
            exe_path: "/usr/bin/agent".to_owned(),
            bound_at_ms: 1_000,
        }
    }

    fn binding(tenant: &str, e: &ExecutionBinding) -> WorkloadBinding {
        WorkloadBinding::new(
            tenant,
            "orders",
            aip_system::SystemId::parse("enterprise:svc-orders").unwrap(),
            framework_commitment("langgraph", "0.2.1", "vanian-1"),
            e,
            1_000,
        )
        .unwrap()
    }

    fn chain(b: &WorkloadBinding) -> ContextChain {
        let mut c = ContextChain::rooted_at(b, 1_000, 2_000).unwrap();
        c.extend(PropagationBoundary::WorkerQueue, [0x01; 16], None);
        c.extend(PropagationBoundary::Subprocess, [0x02; 16], None);
        c.extend(
            PropagationBoundary::Process,
            [0x03; 16],
            Some(ContainerAttribution::new("cid-abc", "registry/app:1.2").unwrap()),
        );
        c
    }

    #[test]
    fn a_well_formed_chain_verifies_and_admits() {
        let e = execution("aip:agent-1", 42, 900);
        let b = binding("acme", &e);
        let c = chain(&b);
        assert_eq!(c.len(), 3);
        assert!(c.check_links().is_ok());
        assert!(c.admit(&b, &e, 1_500).is_ok());
    }

    #[test]
    fn a_hop_lifted_from_another_chain_breaks_the_links() {
        let e = execution("aip:agent-1", 42, 900);
        let b = binding("acme", &e);
        let mut c = chain(&b);

        let other_e = execution("aip:agent-2", 77, 950);
        let other_b = binding("globex", &other_e);
        let other_c = chain(&other_b);

        // Paste the other chain's second hop into this one.
        c.hops[1] = other_c.hops()[1].clone();
        assert!(matches!(
            c.check_links(),
            Err(EnterpriseError::ContextChainBroken { at_hop: 1 })
        ));
    }

    #[test]
    fn editing_a_hop_breaks_the_chain_at_the_next_one() {
        let e = execution("aip:agent-1", 42, 900);
        let b = binding("acme", &e);
        let mut c = chain(&b);
        c.hops[0].to_execution_id = [0xFF; 16];
        assert!(matches!(
            c.check_links(),
            Err(EnterpriseError::ContextChainBroken { at_hop: 1 })
        ));
    }

    #[test]
    fn a_chain_cannot_be_presented_by_a_different_execution() {
        let victim = execution("aip:agent-1", 42, 900);
        let b = binding("acme", &victim);
        let c = chain(&b);
        let attacker = execution("aip:agent-1", 77, 950);
        assert!(matches!(
            c.admit(&b, &attacker, 1_500),
            Err(EnterpriseError::BindingDoesNotCoverExecution { .. })
        ));
    }

    #[test]
    fn a_chain_cannot_be_re_rooted_in_another_binding() {
        let e = execution("aip:agent-1", 42, 900);
        let b = binding("acme", &e);
        let c = chain(&b);
        let other = binding("globex", &e);
        assert!(matches!(
            c.admit(&other, &e, 1_500),
            Err(EnterpriseError::ContextChainBroken { at_hop: 0 })
        ));
    }

    #[test]
    fn a_stale_context_is_refused_at_the_boundary() {
        let e = execution("aip:agent-1", 42, 900);
        let b = binding("acme", &e);
        let c = chain(&b);
        assert!(c.is_fresh_at(1_000));
        assert!(c.is_fresh_at(1_999));
        assert!(!c.is_fresh_at(2_000));
        assert!(!c.is_fresh_at(999));
        assert!(matches!(
            c.admit(&b, &e, 2_000),
            Err(EnterpriseError::ContextStale { .. })
        ));
        assert!(matches!(
            c.admit(&b, &e, 999),
            Err(EnterpriseError::ContextStale { .. })
        ));
    }

    #[test]
    fn a_container_attribution_is_carried_and_never_measured() {
        let e = execution("aip:agent-1", 42, 900);
        let b = binding("acme", &e);
        let c = chain(&b);
        let with_container: Vec<&ContextHop> =
            c.hops().iter().filter(|h| h.container.is_some()).collect();
        assert_eq!(with_container.len(), 1);
        assert!(!with_container[0].container.as_ref().unwrap().is_measured());
        assert!(!c.container_identity_measured());
    }

    #[test]
    fn changing_the_container_attribution_changes_the_chain() {
        let e = execution("aip:agent-1", 42, 900);
        let b = binding("acme", &e);
        let a = chain(&b);
        let mut other = ContextChain::rooted_at(&b, 1_000, 2_000).unwrap();
        other.extend(PropagationBoundary::WorkerQueue, [0x01; 16], None);
        other.extend(PropagationBoundary::Subprocess, [0x02; 16], None);
        other.extend(
            PropagationBoundary::Process,
            [0x03; 16],
            Some(ContainerAttribution::new("cid-xyz", "registry/app:1.2").unwrap()),
        );
        assert_ne!(a.digest(), other.digest());
    }

    #[test]
    fn a_substituted_boundary_changes_the_chain() {
        let e = execution("aip:agent-1", 42, 900);
        let b = binding("acme", &e);
        let a = chain(&b);
        let mut other = ContextChain::rooted_at(&b, 1_000, 2_000).unwrap();
        other.extend(PropagationBoundary::Thread, [0x01; 16], None);
        assert_ne!(a.hops()[0].digest(), other.hops()[0].digest());
    }

    #[test]
    fn malformed_windows_and_attributions_are_refused() {
        let e = execution("aip:agent-1", 42, 900);
        let b = binding("acme", &e);
        assert!(ContextChain::rooted_at(&b, 2_000, 2_000).is_err());
        assert!(ContextChain::rooted_at(&b, 2_000, 1_000).is_err());
        assert!(ContainerAttribution::new("", "img").is_err());
        assert!(ContainerAttribution::new("cid", "").is_err());
        assert!(ContainerAttribution::new(&"x".repeat(129), "img").is_err());
        assert!(ContextChain::rooted_at(&b, 1, 2)
            .unwrap()
            .check_version()
            .is_ok());
    }
}
