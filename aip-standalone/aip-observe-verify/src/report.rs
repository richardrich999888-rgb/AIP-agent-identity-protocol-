//! The verifier's findings, as data.
//!
//! Rendering (human text, JSON) and the process exit code are derived from
//! these types in `main.rs`; nothing here formats or exits. Keeping the
//! findings as values rather than printed lines is what lets the core be
//! tested without capturing stdout, and what lets `--json` and the human
//! report be two views of one answer rather than two answers.

use serde::Serialize;

/// One thing that is wrong with an archive. Every variant is a refusal:
/// there is no "warning" that still passes. A verifier that passes with
/// reservations teaches the reader to skip the reservations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind")]
pub enum Finding {
    /// A line did not parse as the record type the file claims to hold.
    Unparseable { line: usize, error: String },
    /// The anchored key did not sign this record.
    SignatureRejected {
        line: usize,
        sequence: u64,
        error: String,
    },
    /// Chain positions are not contiguous: a record is missing, repeated, or
    /// out of order. A gap is indistinguishable from a deletion, so it is
    /// fatal rather than noted.
    SequenceNotContiguous {
        line: usize,
        expected: u64,
        found: u64,
    },
    /// `prev_head` does not equal the recomputed head of the preceding
    /// record. The chain is forked or spliced.
    ChainBroken {
        line: usize,
        sequence: u64,
        expected_prev_head: String,
        found_prev_head: String,
    },
    /// A signed health record states a head at a chain position the batch
    /// archive also covers, and the two disagree. The collector signed two
    /// different answers about one position.
    HealthHeadMismatch {
        sequence: u64,
        health_head: String,
        batch_head: String,
    },
    /// A signed health record names a chain position inside the batch
    /// archive's own range, and no batch at that position is present. The
    /// archive has had a record removed from its middle.
    HealthHeadHasNoBatch { sequence: u64 },
    /// The file held no records at all. An empty archive is not a clean
    /// archive; it is an archive that proves nothing, and asking for a
    /// verdict on it must not yield "pass".
    Empty { what: &'static str },
}

/// Where the first record's predecessor is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ChainStart {
    /// `prev_head` is all zero: this file begins at the observer's epoch, so
    /// the chain is complete from its origin.
    Epoch,
    /// `prev_head` is non-zero: the file is a window onto a longer chain.
    /// Everything in the window is verified and linked, but the verifier has
    /// not seen what came before and says so rather than implying it has.
    MidChain,
}

/// What the verifier found in one batch archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BatchReport {
    pub records: usize,
    pub first_sequence: Option<u64>,
    pub last_sequence: Option<u64>,
    pub start: Option<ChainStart>,
    /// Recomputed head of the last record, hex. This is the value an
    /// institution pins or compares against an independently held anchor.
    pub final_head: Option<String>,
    pub observations: usize,
    pub kernel_events: usize,
}

/// What the verifier found in one health archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HealthReport {
    pub records: usize,
    /// Distinct observer states across the archive, in the order first seen.
    /// A pilot's whole point can be that this list contains more than
    /// `Active`: an observer that never admits to being blind is the failure
    /// mode, not the success one.
    pub states: Vec<String>,
    /// Records that assert coverage of a window.
    pub with_coverage: usize,
    /// Records that assert none. Reported separately and never summed away.
    pub without_coverage: usize,
    /// Health heads checked against a batch at the same chain position.
    pub cross_checked_against_batches: usize,
    /// Records whose signed bytes carry a clock-discipline reading
    /// (protocol 12) in which `STA_UNSYNC` was clear.
    pub clock_synchronised: usize,
    /// Records that carry a reading saying nothing was steering the clock.
    /// Counted separately from the next field: "the collector said its clock
    /// was adrift" and "the collector said nothing" are different facts, and
    /// summing them would lose the one an auditor needs.
    pub clock_unsynchronised: usize,
    /// Records that carry no reading at all.
    pub clock_not_stated: usize,
    /// The largest error bound any record with a reading asserted, in
    /// microseconds. `None` when no record carried a reading. This bounds
    /// how far the timestamps in the covered window may be out, as far as
    /// the collector's own kernel was willing to say.
    pub clock_worst_max_error_us: Option<i64>,
}

/// The whole answer. `ok` is true only if `findings` is empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChainReport {
    pub observer_id: String,
    pub key_version: u32,
    pub public_key: String,
    pub batches: Option<BatchReport>,
    pub health: Option<HealthReport>,
    pub findings: Vec<Finding>,
}

impl ChainReport {
    /// A pass is the absence of findings. Nothing else.
    pub fn ok(&self) -> bool {
        self.findings.is_empty()
    }
}
