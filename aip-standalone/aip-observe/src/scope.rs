//! Explicit retention scope carried inside signed observation batches.
//!
//! A scope is an operator selection, never proof of logical agent identity.
//! It deliberately does not grant continuous coverage: current signed health
//! has no subject scope, so a collector must withdraw coverage for a scoped
//! batch even when the retained measurements verify successfully.

use aip_types::canonical::*;
use aip_types::{ContainerIdentity, ProcessInstance};
use serde::{Deserialize, Serialize};

use crate::{KernelLifecycleEvent, ObservationBatch, ObservedProcess};

pub const FILTER_SCOPE_VERSION: u16 = 1;
pub const MAX_FILTER_TARGETS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentFilterTarget {
    /// Customer-selected label, not verified AIP attribution.
    pub agent_label: String,
    #[serde(deserialize_with = "strict_process")]
    pub process: ProcessInstance,
    pub exe_content_sha256: [u8; 32],
    /// When present, all namespace values and an optional cgroup constraint
    /// must match. Missing measurements cannot satisfy a constraint.
    #[serde(default, deserialize_with = "strict_container")]
    pub container: Option<ContainerIdentity>,
}

fn strict_process<'de, D: serde::Deserializer<'de>>(d: D) -> Result<ProcessInstance, D::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct P {
        pid: u32,
        pid_start_time_ticks: u64,
        boot_id: [u8; 16],
    }
    let p = P::deserialize(d)?;
    Ok(ProcessInstance {
        pid: p.pid,
        pid_start_time_ticks: p.pid_start_time_ticks,
        boot_id: p.boot_id,
    })
}

fn strict_container<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<ContainerIdentity>, D::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct C {
        pid_ns_inode: u64,
        mnt_ns_inode: u64,
        net_ns_inode: u64,
        cgroup_id: Option<u64>,
    }
    Ok(Option::<C>::deserialize(d)?.map(|c| ContainerIdentity {
        pid_ns_inode: c.pid_ns_inode,
        mnt_ns_inode: c.mnt_ns_inode,
        net_ns_inode: c.net_ns_inode,
        cgroup_id: c.cgroup_id,
    }))
}

impl AgentFilterTarget {
    pub fn matches(&self, p: &ObservedProcess) -> bool {
        self.process == p.process
            && self.exe_content_sha256 == p.exe_content_sha256
            && self.container.is_none_or(|wanted| {
                p.container.is_some_and(|actual| {
                    wanted.pid_ns_inode == actual.pid_ns_inode
                        && wanted.mnt_ns_inode == actual.mnt_ns_inode
                        && wanted.net_ns_inode == actual.net_ns_inode
                        && wanted
                            .cgroup_id
                            .is_none_or(|id| actual.cgroup_id == Some(id))
                })
            })
    }

    fn valid(&self) -> bool {
        !self.agent_label.is_empty()
            && self.agent_label.len() <= 128
            && self
                .agent_label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:/".contains(&b))
            && self.process.pid > 0
            && self.process.pid_start_time_ticks > 0
            && self.process.boot_id != [0; 16]
            && self.exe_content_sha256 != [0; 32]
            && self.container.is_none_or(|c| {
                c.pid_ns_inode > 0
                    && c.mnt_ns_inode > 0
                    && c.net_ns_inode > 0
                    && c.cgroup_id != Some(0)
            })
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        put_str(buf, &self.agent_label);
        put_u32(buf, self.process.pid);
        put_u64(buf, self.process.pid_start_time_ticks);
        buf.extend_from_slice(&self.process.boot_id);
        buf.extend_from_slice(&self.exe_content_sha256);
        aip_types::put_container(buf, &self.container, true);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentFilterScope {
    pub version: u16,
    pub targets: Vec<AgentFilterTarget>,
}

impl AgentFilterScope {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != FILTER_SCOPE_VERSION {
            return Err("unsupported filter scope version");
        }
        if self.targets.is_empty() || self.targets.len() > MAX_FILTER_TARGETS {
            return Err("filter requires between 1 and 256 exact process targets");
        }
        for (i, target) in self.targets.iter().enumerate() {
            if !target.valid() {
                return Err("invalid filter label, process identity, executable hash, or namespace constraint");
            }
            if self.targets[..i]
                .iter()
                .any(|t| t.process == target.process)
            {
                return Err("duplicate process instance in filter targets");
            }
        }
        Ok(())
    }

    pub fn matches(&self, p: &ObservedProcess) -> bool {
        self.targets.iter().any(|t| t.matches(p))
    }

    /// Retain an event only when its measured process is also the process
    /// named by the event kind. A bound field alone cannot assign a packet,
    /// an unknown event, or another process's payload to an enrolled target.
    pub fn matches_event(&self, event: &KernelLifecycleEvent) -> bool {
        event.bound.as_ref().is_some_and(|process| {
            event.kind.subject_pid() == Some(process.process.pid) && self.matches(process)
        })
    }

    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        put_u16(buf, self.version);
        put_u32(buf, self.targets.len() as u32);
        for t in &self.targets {
            t.encode(buf);
        }
    }
}

/// Signed accounting for records withheld before transport and buffering.
/// Counters are probe reports; no claim about absent activity follows from
/// them. Source loss remains separately visible in `dropped_events`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchFilterReport {
    pub scope: AgentFilterScope,
    pub original_records: u64,
    pub excluded_records: u64,
    pub unassigned_records: u64,
}

impl BatchFilterReport {
    pub fn validate_for(&self, batch: &ObservationBatch) -> bool {
        self.scope.validate().is_ok()
            && (batch.observations.len() as u64)
                .checked_add(batch.kernel_events.len() as u64)
                .and_then(|n| n.checked_add(self.excluded_records))
                .and_then(|n| n.checked_add(self.unassigned_records))
                == Some(self.original_records)
            && batch
                .observations
                .iter()
                .all(|o| self.scope.matches(&o.observed))
            && batch
                .kernel_events
                .iter()
                .all(|e| self.scope.matches_event(e))
    }

    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        self.scope.encode(buf);
        put_u64(buf, self.original_records);
        put_u64(buf, self.excluded_records);
        put_u64(buf, self.unassigned_records);
    }
}
