//! From a verified attested batch to a correlated `ObservationRecord`.
//!
//! This is the single seam between Tower A (live kernel observation) and
//! Tower B (Skills 17-21), and everything about its shape is defensive.
//!
//! # The one constructor, still the one constructor
//!
//! `ObservationRecord::from_attested` is the only way an observation record
//! comes into existence anywhere in the workspace, and this module does not
//! add a second. What it adds is the check `from_attested` structurally cannot
//! make: **that the observation is about the execution the verifier is asking
//! about.**
//!
//! `from_attested` verifies the batch and checks the correlation's boot id
//! against the boot the observer measured. It does *not* check the correlation
//! `execution_id`, and it cannot — an `ObservedExecution` carries no execution
//! id, because the observer is never told one. The observer measures a process
//! instance; nothing more.
//!
//! So the join has to be made somewhere, and where it is made decides whether
//! the whole model means anything. Made from the agent's self-report, it means
//! nothing: the subject would be nominating its own evidence. Made here, it is
//! this:
//!
//! ```text
//!   the decision point signed an ExpectedExecution
//!   containing an ExecutionBinding                    ← authorization side
//!                       │
//!                       │  ObservedProcess::matches_process_of
//!                       │  (pid, start ticks, boot id, exe content digest)
//!                       ▼
//!   an anchored observer measured a process instance  ← observation side
//! ```
//!
//! Two independently signed statements about the same process instance. The
//! execution id follows from the authorization side, where it was signed;
//! the observation side never has to be trusted to name it.
//!
//! # Exclusion, never downgrade
//!
//! An observation that fails the instance comparison is not weaker evidence
//! about this execution. It is evidence about a different one, and it is
//! dropped. Downgrading instead would let anyone raise the count of "related"
//! observations by supplying unrelated ones — the same reasoning
//! `EffectCorrelation::admits` already applies one layer up.
//!
//! # Order of operations
//!
//! Verify first, then read. Nothing in a batch that has not verified is
//! allowed to influence an *acceptance*; it may only influence a refusal. That
//! is why [`observation_record`] calls `verify_attested_batch` before it
//! indexes anything, even though `from_attested` verifies again — the second
//! verification is `aip-observation`'s invariant and this one is this module's,
//! and neither should depend on the other remembering.

use aip_authorize::{verify_expected_execution, DecisionPointTrustAnchors, ExpectedExecution};
use aip_observation::{ObservationCorrelation, ObservationRecord};
use aip_observe::{verify_attested_batch, AttestedBatch, ObserverTrustAnchors};
use aip_system::SystemId;
use aip_types::ExecutionBinding;

use crate::error::EdgeError;

/// What the verifier is asking about, assembled from things it already trusts.
///
/// Every field arrives from a signed or verifier-held source. None of it comes
/// from the workload, which is why a workload cannot steer the correlation.
#[derive(Debug, Clone)]
pub struct ObservationSubject {
    /// The autonomous system. Declared by the deployment, exactly as the set
    /// of trusted observer keys is.
    pub system_id: SystemId,
    /// The AIRI execution instance. Reused verbatim; this crate mints none.
    pub execution_id: [u8; 16],
    /// The decision the execution claims, when it claims one. `None` is a
    /// statement a verifier can act on and is not "any decision".
    pub decision_id: Option<[u8; 16]>,
    /// The process instance the **decision point** bound its authorization to.
    ///
    /// Taken from a verified `ExpectedExecution` — see
    /// [`subject_from_expectation`], which is the only way to obtain one
    /// without asserting the signature was checked elsewhere.
    pub expected_binding: ExecutionBinding,
    /// The host-boot the verifier believes this execution ran on.
    ///
    /// Checked by `from_attested` against the boot the observer *measured*. A
    /// mismatch yields no record: a verified batch may not be relabelled onto
    /// another host.
    pub boot_id: [u8; 16],
}

/// Build a subject from an expectation this function verifies first.
///
/// The signature check is not a formality. `expected_binding` is the anchor of
/// every correlation below it, so reading it out of an unverified structure
/// would let anyone who can write JSON choose which process instance counts as
/// the authorized one.
pub fn subject_from_expectation(
    expectation: &ExpectedExecution,
    dp_anchors: &DecisionPointTrustAnchors,
    system_id: SystemId,
    execution_id: [u8; 16],
    boot_id: [u8; 16],
) -> Result<ObservationSubject, EdgeError> {
    verify_expected_execution(expectation, dp_anchors)
        .map_err(|_| EdgeError::ExpectationNotTrusted)?;
    Ok(ObservationSubject {
        system_id,
        execution_id,
        decision_id: Some(expectation.decision_id),
        expected_binding: expectation.execution_binding.clone(),
        boot_id,
    })
}

impl ObservationSubject {
    /// The correlation this subject asserts, in `aip-observation`'s own type.
    pub fn correlation(&self) -> ObservationCorrelation {
        ObservationCorrelation {
            system_id: self.system_id.clone(),
            execution_id: self.execution_id,
            boot_id: self.boot_id,
            decision_id: self.decision_id,
        }
    }
}

/// Derive one `ObservationRecord` from the observation at `index`.
///
/// Refuses, in order:
///
/// 1. a batch that does not verify against `anchors` — no record, not a weak
///    one;
/// 2. an index the batch does not carry;
/// 3. an observation of a **different process instance** than the decision
///    point bound;
/// 4. anything `ObservationRecord::from_attested` itself refuses, which
///    includes a correlation naming a host the observer did not measure.
pub fn observation_record(
    batch: &AttestedBatch,
    anchors: &ObserverTrustAnchors,
    index: usize,
    subject: &ObservationSubject,
) -> Result<ObservationRecord, EdgeError> {
    // (1) Nothing below reads an unverified byte to justify an acceptance.
    verify_attested_batch(batch, anchors).map_err(|_| EdgeError::BatchNotTrusted {
        observer_id: batch.observer_id.clone(),
    })?;

    // (2)
    let observed = batch
        .batch
        .observations
        .get(index)
        .ok_or(EdgeError::NoObservationAtIndex {
            index,
            len: batch.batch.observations.len(),
        })?;

    // (3) The join. Full instance tuple plus executable content; an equal pid
    // alone can never satisfy it, which is what makes pid reuse and a
    // same-binary sibling process both fail here rather than downstream.
    if !observed
        .observed
        .matches_process_of(&subject.expected_binding)
    {
        return Err(EdgeError::ProcessInstanceMismatch);
    }

    // (4) The one constructor.
    Ok(ObservationRecord::from_attested(
        batch,
        anchors,
        index,
        subject.correlation(),
    )?)
}

/// Every observation in `batch` that correlates to `subject`, with its index.
///
/// A batch that verifies but describes another execution yields an empty
/// vector — an absence, not an error, and distinguishable by the caller from
/// a batch that failed to verify (which is an `Err`). The two must not be
/// conflated: one is "the observer saw something else", the other is "this is
/// not an observation at all".
pub fn records_for_subject(
    batch: &AttestedBatch,
    anchors: &ObserverTrustAnchors,
    subject: &ObservationSubject,
) -> Result<Vec<(usize, ObservationRecord)>, EdgeError> {
    verify_attested_batch(batch, anchors).map_err(|_| EdgeError::BatchNotTrusted {
        observer_id: batch.observer_id.clone(),
    })?;
    let mut out = Vec::new();
    for index in 0..batch.batch.observations.len() {
        match observation_record(batch, anchors, index, subject) {
            Ok(r) => out.push((index, r)),
            // A non-correlating observation is skipped; a structural refusal
            // is skipped too, because neither produces evidence and the caller
            // asked for the ones that do.
            Err(_) => continue,
        }
    }
    Ok(out)
}
