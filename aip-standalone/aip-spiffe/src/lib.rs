//! Compare **SPIRE's** assertion about a workload's identity against **AIP's**
//! independent measurement of the same process instance.
//!
//! # The two questions, and why they are different
//!
//! SPIRE answers *"which named workload is the process on the other end of this
//! socket?"* and issues an SVID. AIP answers *"what code is actually running in
//! this process instance?"* and binds it. Both consult the kernel; neither asks
//! the agent. The join between them is the executable's SHA-256: SPIRE's `unix`
//! attestor offers it as a `unix:sha256` selector, and AIP measures it as
//! `ObservedProcess::exe_content_sha256`.
//!
//! When SPIRE issues an SVID for an entry selected on a digest, that issuance
//! **is** SPIRE's assertion that it measured that digest. Comparing it against
//! AIP's measurement is therefore two independent parties measuring one thing.
//!
//! # What this does NOT claim
//!
//! Nothing about resisting a hostile host. SPIRE's `unix` attestor reads
//! `/proc/<pid>/exe`, which is the same source AIP measures from, so for that
//! attestor the two **share** the attack surface. Agreement here means the two
//! independently built implementations concur; it does not mean either is
//! immune to a root attacker, and both projects document that limit.
//!
//! # The soundness check that is easy to forget
//!
//! SPIRE names a **pid**. AIP pins a **process instance** (pid + start tick +
//! boot id). A pid can be reused. If the instance AIP measured began *after*
//! SPIRE attested the caller, then AIP is looking at a different, later process
//! that inherited the number, and comparing their digests is meaningless. That
//! case is [`IdentityDivergence::InstanceStartedAfterAttestation`], never
//! `Agrees`.
//!
//! **The reference instant is the fetch, not the SVID's `notBefore`.** This was
//! found by the first live run, which reported a healthy workload as a reused
//! pid: SPIRE's agent **pre-mints** SVIDs for registered entries before any
//! workload asks for one, so `notBefore` records when the certificate was
//! minted and can precede the workload's own start by many seconds. The moment
//! SPIRE actually attested *this caller* is when the workload called the
//! Workload API — `observed_at_ms`. A process that began after that instant
//! cannot be the caller that was attested; one that began before it can.

use aip_observe::{AttestedBatch, BootClockAnchor, ObservedProcess};

pub mod assertion;
pub mod registry;

pub use assertion::{parse_assertion, WorkloadIdentityAssertion};
pub use registry::{parse_digest, parse_entry_show, RegisteredWorkload, Registry};

/// The outcome of comparing the two authorities. Absence of evidence is never
/// agreement: every way of not knowing lands in `NotComparable`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum WorkloadIdentityComparison {
    /// Both authorities named the same code for the same process instance.
    Agrees {
        spiffe_id: String,
        digest_hex: String,
        /// Other selectors the entry also rested on, for the reader's judgement.
        other_selectors: Vec<String>,
    },
    Diverges {
        divergence: IdentityDivergence,
    },
    NotComparable {
        reason: NotComparableReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum IdentityDivergence {
    /// SPIRE issued this identity for a workload required to have one digest;
    /// AIP measured a different one on that process instance.
    DigestMismatch {
        spiffe_id: String,
        spire_required_hex: String,
        aip_measured_hex: String,
    },
    /// The process instance AIP measured started after SPIRE attested the
    /// caller, so it cannot be the process SPIRE attested. A reused pid.
    ///
    /// Compared against the **attestation** instant (when the workload called
    /// the Workload API), not the SVID's `notBefore`: SPIRE pre-mints SVIDs for
    /// registered entries, so `notBefore` can precede the workload's own start.
    InstanceStartedAfterAttestation {
        spiffe_id: String,
        instance_started_ms: i64,
        attested_at_ms: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum NotComparableReason {
    /// SPIRE issued nothing, so there is no identity to check.
    NoSvid,
    /// The SPIFFE ID is not in SPIRE's own registry output.
    UnknownSpiffeId { spiffe_id: String },
    /// The entry rests on no `unix:sha256` selector. The identity did not
    /// depend on the workload's code, so there is nothing for AIP to confirm.
    /// **This is the case that must never be reported as agreement.**
    NoDigestSelector {
        spiffe_id: String,
        other_selectors: Vec<String>,
    },
    /// The entry carries several different digests and can never be satisfied.
    ContradictoryDigestSelectors { spiffe_id: String, count: usize },
    /// AIP recorded no measurement of that pid in the evidence supplied.
    NoAipMeasurement { pid: u32 },
    /// AIP recorded several distinct process instances at that pid; which one
    /// SPIRE attested cannot be determined. Ambiguity, never a verdict.
    AmbiguousProcessInstance { pid: u32, instances: usize },
    /// No clock anchor, so the instance's start cannot be placed in wall time
    /// and the pid-reuse check cannot be made. Refused rather than skipped.
    NoClockAnchor,
    /// The SVID was not valid when it was observed.
    SvidOutsideValidity {
        observed_at_ms: i64,
        not_before_ms: i64,
        not_after_ms: i64,
    },
}

impl WorkloadIdentityComparison {
    pub fn agrees(&self) -> bool {
        matches!(self, WorkloadIdentityComparison::Agrees { .. })
    }
    pub fn diverges(&self) -> bool {
        matches!(self, WorkloadIdentityComparison::Diverges { .. })
    }
}

fn hex32(d: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in d {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Every distinct process instance AIP measured at `pid`, from the bound
/// measurements inside the attested batches.
///
/// Distinct by the full [`aip_types::ProcessInstance`] — pid, start tick and
/// boot id — because a recycled pid is a different instance and collapsing
/// them would hide exactly the case this module exists to catch.
pub fn aip_instances_at_pid(batches: &[AttestedBatch], pid: u32) -> Vec<ObservedProcess> {
    let mut out: Vec<ObservedProcess> = Vec::new();
    for b in batches {
        for e in &b.batch.kernel_events {
            let Some(p) = &e.bound else { continue };
            if p.process.pid != pid {
                continue;
            }
            if !out.iter().any(|q| q.process == p.process) {
                out.push(p.clone());
            }
        }
        for o in &b.batch.observations {
            let p = &o.observed;
            if p.process.pid == pid && !out.iter().any(|q| q.process == p.process) {
                out.push(p.clone());
            }
        }
    }
    out
}

fn anchor_of(batches: &[AttestedBatch]) -> Option<BootClockAnchor> {
    batches.iter().find_map(|b| b.batch.clock_anchor)
}

/// Compare one SPIRE assertion against AIP's evidence.
///
/// Ordering matters: every refusal is checked before any comparison, so a
/// missing precondition can never be skipped past into an `Agrees`.
pub fn compare_workload_identity(
    assertion: &WorkloadIdentityAssertion,
    registry: &Registry,
    batches: &[AttestedBatch],
) -> WorkloadIdentityComparison {
    use NotComparableReason as R;
    let nc = |reason| WorkloadIdentityComparison::NotComparable { reason };

    if assertion.spiffe_id.is_empty() {
        return nc(R::NoSvid);
    }
    // The SVID must have been valid when it was observed, or it attests nothing
    // about that moment.
    if assertion.observed_at_ms < assertion.not_before_ms
        || assertion.observed_at_ms > assertion.not_after_ms
    {
        return nc(R::SvidOutsideValidity {
            observed_at_ms: assertion.observed_at_ms,
            not_before_ms: assertion.not_before_ms,
            not_after_ms: assertion.not_after_ms,
        });
    }

    let Some(entry) = registry.lookup(&assertion.spiffe_id) else {
        return nc(R::UnknownSpiffeId {
            spiffe_id: assertion.spiffe_id.clone(),
        });
    };
    let required = match (entry.required_digest(), entry.distinct_digest_count()) {
        (Some(d), _) => d,
        (None, 0) => {
            return nc(R::NoDigestSelector {
                spiffe_id: assertion.spiffe_id.clone(),
                other_selectors: entry.other_selectors.clone(),
            })
        }
        (None, n) => {
            return nc(R::ContradictoryDigestSelectors {
                spiffe_id: assertion.spiffe_id.clone(),
                count: n,
            })
        }
    };

    let instances = aip_instances_at_pid(batches, assertion.pid);
    match instances.len() {
        0 => return nc(R::NoAipMeasurement { pid: assertion.pid }),
        1 => {}
        n => {
            return nc(R::AmbiguousProcessInstance {
                pid: assertion.pid,
                instances: n,
            })
        }
    }
    let measured = &instances[0];

    let Some(anchor) = anchor_of(batches) else {
        return nc(R::NoClockAnchor);
    };

    // Pid-reuse guard. The instance AIP measured must have existed at the
    // moment SPIRE attested the caller — that is the fetch (`observed_at_ms`),
    // NOT the SVID's `notBefore`, which records pre-minting. See the module
    // docs: anchoring this to `notBefore` reports healthy workloads as reused
    // pids, which the first live run demonstrated.
    let start_ns = anchor.start_ticks_to_ns(measured.process.pid_start_time_ticks);
    let started_ms = aip_corroborate::clock::monotonic_ns_to_wall_ms(&anchor, start_ns);
    // One tick of slack: the start tick has clk_tck granularity, so an instance
    // beginning in the same tick as the attestation must not be called a reuse.
    let slack_ms = (anchor.tick_ns() / 1_000_000).max(1) as i64;
    if started_ms > assertion.observed_at_ms + slack_ms {
        return WorkloadIdentityComparison::Diverges {
            divergence: IdentityDivergence::InstanceStartedAfterAttestation {
                spiffe_id: assertion.spiffe_id.clone(),
                instance_started_ms: started_ms,
                attested_at_ms: assertion.observed_at_ms,
            },
        };
    }

    if measured.exe_content_sha256 == required {
        WorkloadIdentityComparison::Agrees {
            spiffe_id: assertion.spiffe_id.clone(),
            digest_hex: hex32(&required),
            other_selectors: entry.other_selectors.clone(),
        }
    } else {
        WorkloadIdentityComparison::Diverges {
            divergence: IdentityDivergence::DigestMismatch {
                spiffe_id: assertion.spiffe_id.clone(),
                spire_required_hex: hex32(&required),
                aip_measured_hex: hex32(&measured.exe_content_sha256),
            },
        }
    }
}
