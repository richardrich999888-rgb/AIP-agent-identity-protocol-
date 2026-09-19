//! Checking a log against receipts a witness issued.
//!
//! This is the side that runs at review time, possibly years later, by
//! someone who holds the receipts and is shown a log. The question it
//! answers is narrow: **does this log still carry forward everything the
//! witness saw?**
//!
//! It is not a question about content. A log that answers "yes" may still
//! contain nothing useful. What it cannot be is a log with records removed
//! from a stretch the witness had already countersigned.

use aip_nexora::{verify_consistency, CommitmentLog, ConsistencyProof};

use crate::{verify_receipt_chain, WitnessAnchors, WitnessError, WitnessReceipt};

/// The log, as an auditor can interrogate it.
///
/// A port rather than a concrete type, so the audit can run against a live
/// [`CommitmentLog`], a replica, or a stored export without this module
/// knowing which.
pub trait LogView {
    fn log_id(&self) -> [u8; 16];
    fn size(&self) -> u64;
    fn root(&self) -> [u8; 32];
    /// A proof that the current root extends the root at `old_size`.
    /// `None` where the log cannot produce one.
    fn consistency_since(&self, old_size: u64) -> Option<ConsistencyProof>;
}

impl LogView for CommitmentLog {
    fn log_id(&self) -> [u8; 16] {
        CommitmentLog::log_id(self)
    }

    fn size(&self) -> u64 {
        CommitmentLog::size(self)
    }

    fn root(&self) -> [u8; 32] {
        CommitmentLog::root(self)
    }

    fn consistency_since(&self, old_size: u64) -> Option<ConsistencyProof> {
        CommitmentLog::consistency_since(self, old_size).ok()
    }
}

/// What an audit establishes. Three-valued, like every other verdict in
/// this workspace: a thing proven, a thing disproven, and the absence of
/// evidence — which is never quietly converted into either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorStanding {
    /// Every receipt held is carried forward by this log.
    Consistent {
        receipts: usize,
        /// The largest size a witness countersigned. Records below this
        /// index cannot have been removed without detection.
        highest_witnessed_size: u64,
        /// The witness's own clock at that receipt.
        witnessed_at_ms: u64,
    },
    /// The log contradicts a receipt.
    Diverged(Divergence),
    /// Nothing was established. **Not** a pass.
    NotEvaluated(NotEvaluated),
}

impl AnchorStanding {
    /// True only for [`AnchorStanding::Consistent`].
    ///
    /// Written as a method so no caller can reach the "not `Diverged`,
    /// therefore fine" reading that would let [`NotEvaluated`] pass.
    pub fn is_consistent(&self) -> bool {
        matches!(self, Self::Consistent { .. })
    }

    /// A sentence for a reviewer.
    pub fn explain(&self) -> String {
        match self {
            Self::Consistent {
                receipts,
                highest_witnessed_size,
                witnessed_at_ms,
            } => format!(
                "the log carries forward all {receipts} witnessed head(s); the highest \
                 countersigned size is {highest_witnessed_size}, witnessed at {witnessed_at_ms}, \
                 so no record below that index has been removed since"
            ),
            Self::Diverged(d) => d.explain(),
            Self::NotEvaluated(n) => n.explain(),
        }
    }
}

/// How a log contradicts a receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Divergence {
    /// The log is smaller than a size already countersigned. Records were
    /// removed.
    Truncated {
        witnessed_size: u64,
        current_size: u64,
    },
    /// At a size the witness saw, the log now has a different root.
    RootChanged {
        size: u64,
        witnessed_root: [u8; 32],
        current_root: [u8; 32],
    },
    /// The log claims to be at least as large, but its current root does
    /// not extend the witnessed one.
    NotAnExtension {
        witnessed_size: u64,
        current_size: u64,
    },
    /// The log could not produce a consistency proof from a witnessed
    /// size it should be able to prove. Treated as divergence, not as an
    /// unknown: otherwise a log evades the audit by declining to prove.
    ConsistencyUnprovable {
        witnessed_size: u64,
        current_size: u64,
    },
    /// The log is not the log these receipts are about.
    DifferentLog { receipts: [u8; 16], log: [u8; 16] },
}

impl Divergence {
    pub fn explain(&self) -> String {
        match self {
            Self::Truncated {
                witnessed_size,
                current_size,
            } => format!(
                "a witness countersigned this log at size {witnessed_size}; it is now \
                 {current_size}. An append-only log does not shrink, so {} record(s) were \
                 removed after they were witnessed",
                witnessed_size.saturating_sub(*current_size)
            ),
            Self::RootChanged { size, .. } => format!(
                "at size {size} the witness countersigned one root and this log has another: \
                 the history below that point was rewritten"
            ),
            Self::NotAnExtension {
                witnessed_size,
                current_size,
            } => format!(
                "the log at size {current_size} does not extend the root witnessed at \
                 {witnessed_size}: it is a different history, not a longer one"
            ),
            Self::ConsistencyUnprovable {
                witnessed_size,
                current_size,
            } => format!(
                "the log cannot prove that size {current_size} extends the witnessed size \
                 {witnessed_size}. An append-only log can always produce that proof; one that \
                 cannot is treated as divergent"
            ),
            Self::DifferentLog { receipts, log } => format!(
                "these receipts are about log {} and this is log {}",
                hex(receipts),
                hex(log)
            ),
        }
    }
}

/// Why nothing could be established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotEvaluated {
    /// No receipts were held. The most important variant in this file: a
    /// log that was never witnessed is **unanchored**, and an unanchored
    /// log is exactly the situation this crate exists to distinguish from
    /// an anchored one.
    NoReceipts,
    /// The receipts did not verify, or their chain is broken.
    ReceiptsUnusable(WitnessError),
}

impl NotEvaluated {
    pub fn explain(&self) -> String {
        match self {
            Self::NoReceipts => "no witness receipts were supplied, so nothing about this log's \
                 history is established. This is not a clean result: it is the absence of one"
                .to_string(),
            Self::ReceiptsUnusable(e) => format!(
                "the receipts could not be used, so the log is unchecked rather than checked \
                 and clean: {e}"
            ),
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Audit a log against the receipts a witness issued for it.
///
/// `receipts` must be in issue order; [`verify_receipt_chain`] enforces
/// that they form an unbroken chain, so a removed receipt is caught before
/// any comparison happens.
///
/// The comparison itself is done against the **highest** receipt only, and
/// that is sufficient rather than lazy: the receipt chain already proves
/// each receipt extends the one before under a consistency proof the
/// witness verified at the time, so carrying the highest witnessed root
/// forward carries all of them.
pub fn audit(
    log: &dyn LogView,
    receipts: &[WitnessReceipt],
    anchors: &WitnessAnchors,
) -> AnchorStanding {
    if receipts.is_empty() {
        return AnchorStanding::NotEvaluated(NotEvaluated::NoReceipts);
    }
    if let Err(e) = verify_receipt_chain(receipts, anchors) {
        return AnchorStanding::NotEvaluated(NotEvaluated::ReceiptsUnusable(e));
    }

    let highest = receipts
        .iter()
        .max_by_key(|r| r.size)
        .expect("non-empty, checked above");

    if highest.log_id != log.log_id() {
        return AnchorStanding::Diverged(Divergence::DifferentLog {
            receipts: highest.log_id,
            log: log.log_id(),
        });
    }

    let current_size = log.size();
    let current_root = log.root();

    if current_size < highest.size {
        return AnchorStanding::Diverged(Divergence::Truncated {
            witnessed_size: highest.size,
            current_size,
        });
    }
    if current_size == highest.size {
        return if current_root == highest.root {
            consistent(receipts, highest)
        } else {
            AnchorStanding::Diverged(Divergence::RootChanged {
                size: highest.size,
                witnessed_root: highest.root,
                current_root,
            })
        };
    }

    // The log claims to be longer. Make it prove the witnessed root is a
    // prefix of the current one.
    let Some(proof) = log.consistency_since(highest.size) else {
        return AnchorStanding::Diverged(Divergence::ConsistencyUnprovable {
            witnessed_size: highest.size,
            current_size,
        });
    };
    if proof.old_size != highest.size
        || proof.new_size != current_size
        || !verify_consistency(&highest.root, &current_root, &proof)
    {
        return AnchorStanding::Diverged(Divergence::NotAnExtension {
            witnessed_size: highest.size,
            current_size,
        });
    }
    consistent(receipts, highest)
}

fn consistent(receipts: &[WitnessReceipt], highest: &WitnessReceipt) -> AnchorStanding {
    AnchorStanding::Consistent {
        receipts: receipts.len(),
        highest_witnessed_size: highest.size,
        witnessed_at_ms: highest.witnessed_at_ms,
    }
}
