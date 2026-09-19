//! `aip-anchor` — the external witness for NEXORA log heads (R11 of
//! `docs/pilot/RBI_REQUIREMENTS_COVERAGE.md`).
//!
//! # What a commitment log does not, by itself, prevent
//!
//! [`aip_nexora::CommitmentLog`] gives an append-only Merkle tree with
//! inclusion and consistency proofs. Those establish that a record is under
//! a root and that one root extends another. What they cannot establish is
//! that the root a verifier is shown today is the root that existed
//! yesterday. Whoever holds the NEXORA signing key can build a shorter log,
//! sign a head over it, and present it with internally consistent proofs.
//! Every check passes. The removed records are simply gone, and nothing in
//! the artefact says so.
//!
//! [`aip_nexora::MemoryAnchor`] is honest about this: its own documentation
//! says it is "the shape of an anchor, not its independence".
//!
//! # What this crate adds
//!
//! A **witness**: a second party, running on a system the log operator does
//! not control, holding a key the log operator does not have. It receives
//! heads, checks them, and countersigns them into a [`WitnessReceipt`].
//!
//! The property that matters is negative and simple. An operator who
//! rewrites the log can still sign the new head — but cannot produce a
//! witness receipt for it, because that needs the witness's key. Held
//! receipts are therefore evidence the operator cannot revise, and
//! [`audit`] checks a log against them.
//!
//! # Boundaries
//!
//! This module is pure: no clock, no filesystem, no network. Time enters as
//! an argument, storage lives in [`store`], and where the witness runs is an
//! operator's decision that no amount of code can make for them. A witness
//! on the same host, under the same administrator, holding a key in the
//! same file, is a second signature and not a second party — and this crate
//! cannot tell the difference. [`deploy/pilot/ANCHOR_WITNESS.md`] states
//! what the deployment has to do for the signature to mean anything.

pub mod audit;
pub mod store;

pub use audit::{audit, AnchorStanding, Divergence, LogView, NotEvaluated};

use aip_crypto::{sha256, sign_ed25519, verify_ed25519};
use aip_nexora::{
    verify_consistency, verify_signed_head, ConsistencyProof, NexoraTrustAnchors, SignedHead,
};
use aip_types::canonical::{put_bytes, put_domain, put_str, put_u16, put_u32, put_u64};
use aip_types::{AipError, Signature};
use serde::{Deserialize, Serialize};

/// Domain tag for the witness countersignature.
pub const WITNESS_RECEIPT_DOMAIN: &str = "AIP/AnchorWitness/Receipt/v1";
/// Wire version of [`WitnessReceipt`].
pub const WITNESS_RECEIPT_VERSION: u16 = 1;

/// How far ahead of the witness's own clock a head may claim to have been
/// issued and still be witnessed.
///
/// A witness that countersigns a head dated an hour in its own future is
/// lending its credibility to a timestamp it cannot corroborate, and the
/// resulting receipt would read as independent corroboration of that time.
/// Five seconds accommodates ordinary NTP dispersion between two hosts and
/// nothing more; a persistent breach of it is a clock fault worth fixing,
/// not a tolerance worth widening.
pub const DEFAULT_FUTURE_TOLERANCE_MS: u64 = 5_000;

// ─── Errors ───

/// Why a witness refused to countersign, or why a receipt did not verify.
///
/// Every variant is a refusal. There is no variant meaning "witnessed with
/// reservations", because a receipt carrying a reservation would be read as
/// a receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessError {
    /// The head did not verify under the NEXORA anchors the witness holds.
    /// A witness signs nothing it cannot itself check.
    HeadNotVerified(aip_nexora::NexoraError),
    /// The witness key is the NEXORA key. Then the receipt is a second
    /// signature by the same party and proves nothing about rewriting.
    WitnessKeyIsLogKey,
    /// The public key given is not the one the private key derives. The
    /// witness would sign with one and publish the other.
    KeypairMismatch,
    /// The head names a different log than the receipts already held.
    DifferentLog {
        expected: [u8; 16],
        got: [u8; 16],
    },
    /// A head no larger than the last one witnessed. A log that stops
    /// growing is fine; a log that shrinks, or that re-presents a size with
    /// a different root, is the event this crate exists to catch.
    NotAnExtension {
        witnessed: u64,
        offered: u64,
    },
    /// Same size, different root: two logs claiming to be one.
    Fork {
        size: u64,
        witnessed_root: [u8; 32],
        offered_root: [u8; 32],
    },
    /// An extension was offered with no consistency proof. Without one,
    /// "this extends what you witnessed" is an assertion.
    ConsistencyMissing {
        from: u64,
        to: u64,
    },
    /// The consistency proof does not carry the witnessed root to the
    /// offered one.
    ConsistencyInvalid {
        from: u64,
        to: u64,
    },
    /// The head claims an issue time materially ahead of the witness's own
    /// clock. See [`DEFAULT_FUTURE_TOLERANCE_MS`].
    HeadFromTheFuture {
        head_issued_at_ms: u64,
        witness_now_ms: u64,
        tolerance_ms: u64,
    },
    /// The head chain is broken: this head does not name the previously
    /// witnessed head as its predecessor.
    HeadChainBroken,
    UnsupportedVersion(u16),
    EmptyWitnessId,
    /// No anchor for this `(witness_id, key_version)`. Anchors come from the
    /// verifier, never from the receipt.
    UntrustedWitness {
        witness_id: String,
        key_version: u32,
    },
    /// The receipt was altered after signing.
    PayloadHashMismatch,
    SignatureInvalid,
    /// The receipt's own chain does not link to the previous receipt.
    ReceiptChainBroken {
        at_size: u64,
    },
    Crypto(AipError),
}

impl std::fmt::Display for WitnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeadNotVerified(e) => {
                write!(
                    f,
                    "the head did not verify under the witness's NEXORA anchors: {e:?}"
                )
            }
            Self::KeypairMismatch => write!(
                f,
                "the public key given is not the one this private key derives: the witness \
                 would sign with one key and be anchored under another"
            ),
            Self::WitnessKeyIsLogKey => write!(
                f,
                "the witness key is the log's own signing key: a countersignature by the same \
                 party is not a second party"
            ),
            Self::DifferentLog { expected, got } => write!(
                f,
                "this witness holds log {} and was offered a head for log {}",
                hex(expected),
                hex(got)
            ),
            Self::NotAnExtension { witnessed, offered } => write!(
                f,
                "already witnessed size {witnessed}; offered {offered}, which does not extend it"
            ),
            Self::Fork { size, .. } => write!(
                f,
                "two different roots offered at size {size}: one of them is not this log"
            ),
            Self::ConsistencyMissing { from, to } => write!(
                f,
                "no consistency proof from {from} to {to}: that the log extends is a claim \
                 until proven"
            ),
            Self::ConsistencyInvalid { from, to } => {
                write!(f, "the consistency proof from {from} to {to} does not hold")
            }
            Self::HeadFromTheFuture {
                head_issued_at_ms,
                witness_now_ms,
                tolerance_ms,
            } => write!(
                f,
                "the head claims {head_issued_at_ms} but the witness reads {witness_now_ms} \
                 (tolerance {tolerance_ms} ms): a witness cannot corroborate a time it has \
                 not reached"
            ),
            Self::HeadChainBroken => write!(
                f,
                "this head does not name the previously witnessed head as its predecessor"
            ),
            Self::UnsupportedVersion(v) => write!(f, "unsupported receipt version {v}"),
            Self::EmptyWitnessId => write!(f, "a witness must have an identifier"),
            Self::UntrustedWitness {
                witness_id,
                key_version,
            } => write!(
                f,
                "no anchor for witness {witness_id} key version {key_version}: anchors come \
                 from the verifier, never from the receipt"
            ),
            Self::PayloadHashMismatch => write!(f, "the receipt was altered after signing"),
            Self::SignatureInvalid => write!(f, "the receipt signature does not verify"),
            Self::ReceiptChainBroken { at_size } => write!(
                f,
                "the receipt at size {at_size} does not link to the one before it: a receipt \
                 has been removed from the set"
            ),
            Self::Crypto(e) => write!(f, "crypto: {e:?}"),
        }
    }
}

impl std::error::Error for WitnessError {}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ─── The receipt ───

/// One witness's countersignature over one head, chained to its own
/// previous receipt.
///
/// `prev_receipt` makes the receipt set append-only in its own right: a
/// witness that later drops a receipt from the middle leaves a break that
/// [`verify_receipt_chain`] finds, so the witness cannot quietly rewrite
/// its own record either.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessReceipt {
    pub version: u16,
    pub witness_id: String,
    pub key_version: u32,
    /// The log this head belongs to.
    pub log_id: [u8; 16],
    /// Size and root exactly as the head stated them. These are what an
    /// audit compares the current log against.
    pub size: u64,
    pub root: [u8; 32],
    /// Digest of the head that was witnessed, so the receipt names one
    /// specific head and not merely a (size, root) pair.
    pub head_digest: [u8; 32],
    /// What the head claimed about when it was issued.
    pub head_issued_at_ms: u64,
    /// **The witness's own clock**, not the log's. Where the two disagree,
    /// a reader sees the disagreement instead of one overwriting the other.
    pub witnessed_at_ms: u64,
    /// Digest of this witness's previous receipt for this log; zero for the
    /// first.
    pub prev_receipt: [u8; 32],
    pub signature: Signature,
}

impl WitnessReceipt {
    /// The bytes the witness signs. Every field a reader relies on is
    /// inside it.
    pub fn signing_preimage(&self) -> Vec<u8> {
        receipt_preimage(
            self.version,
            &self.witness_id,
            self.key_version,
            &self.log_id,
            self.size,
            &self.root,
            &self.head_digest,
            self.head_issued_at_ms,
            self.witnessed_at_ms,
            &self.prev_receipt,
        )
    }

    /// Identifies this receipt to the next one in the chain.
    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.signing_preimage())
    }

    /// How far the log's clock ran ahead of the witness's, in
    /// milliseconds, or `None` where the witness was not behind.
    ///
    /// Reported rather than judged: a small skew is ordinary, and what
    /// counts as material is a deployment's decision.
    pub fn log_clock_ahead_by_ms(&self) -> Option<u64> {
        self.head_issued_at_ms
            .checked_sub(self.witnessed_at_ms)
            .filter(|d| *d > 0)
    }
}

#[allow(clippy::too_many_arguments)]
fn receipt_preimage(
    version: u16,
    witness_id: &str,
    key_version: u32,
    log_id: &[u8; 16],
    size: u64,
    root: &[u8; 32],
    head_digest: &[u8; 32],
    head_issued_at_ms: u64,
    witnessed_at_ms: u64,
    prev_receipt: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::new();
    put_domain(&mut buf, WITNESS_RECEIPT_DOMAIN);
    put_u16(&mut buf, version);
    put_str(&mut buf, witness_id);
    put_u32(&mut buf, key_version);
    put_bytes(&mut buf, log_id);
    put_u64(&mut buf, size);
    put_bytes(&mut buf, root);
    put_bytes(&mut buf, head_digest);
    put_u64(&mut buf, head_issued_at_ms);
    put_u64(&mut buf, witnessed_at_ms);
    put_bytes(&mut buf, prev_receipt);
    buf
}

// ─── The witness ───

/// The state a witness carries between heads: what it last countersigned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WitnessState {
    pub log_id: Option<[u8; 16]>,
    pub last_size: u64,
    pub last_root: [u8; 32],
    pub last_head_digest: [u8; 32],
    pub last_receipt_digest: [u8; 32],
    pub receipts_issued: u64,
}

/// A second party that countersigns heads.
///
/// Holds a private key and the NEXORA anchors it checks heads against. It
/// never holds the log: a witness that could reconstruct the log could be
/// argued to have produced it.
pub struct Witness {
    witness_id: String,
    key_version: u32,
    private_key: Vec<u8>,
    public_key: Vec<u8>,
    log_anchors: NexoraTrustAnchors,
    future_tolerance_ms: u64,
    state: WitnessState,
}

impl Witness {
    /// Build a witness.
    ///
    /// `log_anchors` are the NEXORA keys this witness will accept heads
    /// from. A witness with no anchors countersigns nothing, which is the
    /// correct behaviour for one that was never told whose log it guards.
    pub fn new(
        witness_id: &str,
        key_version: u32,
        private_key: &[u8],
        public_key: &[u8],
        log_anchors: NexoraTrustAnchors,
    ) -> Result<Self, WitnessError> {
        if witness_id.is_empty() {
            return Err(WitnessError::EmptyWitnessId);
        }
        if private_key.len() != 32 || public_key.len() != 32 {
            return Err(WitnessError::Crypto(AipError::InvalidPublicKey));
        }
        // The two keys must be one keypair. A witness that signs with one
        // key and is anchored under another issues receipts that nobody
        // can verify — and discovers it only when an audit needs them.
        let derived =
            aip_crypto::public_key_from_private(private_key).map_err(WitnessError::Crypto)?;
        if derived != public_key {
            return Err(WitnessError::KeypairMismatch);
        }
        // The check that gives the receipt its meaning. If the witness
        // holds the log's key, a receipt is a second signature by one
        // party and establishes nothing about rewriting.
        for (_, _, log_key) in log_anchors.entries() {
            if log_key == public_key {
                return Err(WitnessError::WitnessKeyIsLogKey);
            }
        }
        Ok(Self {
            witness_id: witness_id.to_string(),
            key_version,
            private_key: private_key.to_vec(),
            public_key: public_key.to_vec(),
            log_anchors,
            future_tolerance_ms: DEFAULT_FUTURE_TOLERANCE_MS,
            state: WitnessState::default(),
        })
    }

    /// Override the future tolerance. Stated explicitly at the call site
    /// rather than buried, because widening it weakens what the receipt's
    /// timestamp is worth.
    pub fn with_future_tolerance_ms(mut self, tolerance_ms: u64) -> Self {
        self.future_tolerance_ms = tolerance_ms;
        self
    }

    /// Resume from persisted state, so a restarted witness does not accept
    /// a rollback it would have refused before the restart.
    pub fn resume(mut self, state: WitnessState) -> Self {
        self.state = state;
        self
    }

    pub fn state(&self) -> &WitnessState {
        &self.state
    }

    pub fn witness_id(&self) -> &str {
        &self.witness_id
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Check a head and countersign it.
    ///
    /// `now_ms` is the **witness's** clock, passed in so this function stays
    /// pure and testable. `consistency` is required for every head after
    /// the first, and is verified here rather than trusted.
    ///
    /// On any refusal the witness's state is unchanged: a refused head
    /// leaves no trace that could be mistaken for acceptance.
    pub fn witness(
        &mut self,
        head: &SignedHead,
        consistency: Option<&ConsistencyProof>,
        now_ms: u64,
    ) -> Result<WitnessReceipt, WitnessError> {
        // 1. The head must verify under anchors the witness holds. A
        //    witness that countersigns an unverified head has added a
        //    signature and no information.
        verify_signed_head(head, &self.log_anchors).map_err(WitnessError::HeadNotVerified)?;

        // 2. One witness guards one log.
        if let Some(expected) = self.state.log_id {
            if expected != head.log_id {
                return Err(WitnessError::DifferentLog {
                    expected,
                    got: head.log_id,
                });
            }
        }

        // 3. The head may not claim a time the witness has not reached.
        if head.issued_at_ms > now_ms.saturating_add(self.future_tolerance_ms) {
            return Err(WitnessError::HeadFromTheFuture {
                head_issued_at_ms: head.issued_at_ms,
                witness_now_ms: now_ms,
                tolerance_ms: self.future_tolerance_ms,
            });
        }

        // 4. Growth, proven. This is the truncation and fork check.
        if self.state.log_id.is_some() {
            if head.size == self.state.last_size {
                return Err(WitnessError::Fork {
                    size: head.size,
                    witnessed_root: self.state.last_root,
                    offered_root: head.root,
                });
            }
            if head.size < self.state.last_size {
                return Err(WitnessError::NotAnExtension {
                    witnessed: self.state.last_size,
                    offered: head.size,
                });
            }
            if head.prev_head != self.state.last_head_digest {
                return Err(WitnessError::HeadChainBroken);
            }
            let Some(proof) = consistency else {
                return Err(WitnessError::ConsistencyMissing {
                    from: self.state.last_size,
                    to: head.size,
                });
            };
            if proof.old_size != self.state.last_size
                || proof.new_size != head.size
                || !verify_consistency(&self.state.last_root, &head.root, proof)
            {
                return Err(WitnessError::ConsistencyInvalid {
                    from: self.state.last_size,
                    to: head.size,
                });
            }
        }

        // 5. Countersign.
        let preimage = receipt_preimage(
            WITNESS_RECEIPT_VERSION,
            &self.witness_id,
            self.key_version,
            &head.log_id,
            head.size,
            &head.root,
            &head.digest(),
            head.issued_at_ms,
            now_ms,
            &self.state.last_receipt_digest,
        );
        let receipt = WitnessReceipt {
            version: WITNESS_RECEIPT_VERSION,
            witness_id: self.witness_id.clone(),
            key_version: self.key_version,
            log_id: head.log_id,
            size: head.size,
            root: head.root,
            head_digest: head.digest(),
            head_issued_at_ms: head.issued_at_ms,
            witnessed_at_ms: now_ms,
            prev_receipt: self.state.last_receipt_digest,
            signature: sign_ed25519(&self.private_key, &self.witness_id, &preimage)
                .map_err(WitnessError::Crypto)?,
        };

        self.state = WitnessState {
            log_id: Some(head.log_id),
            last_size: head.size,
            last_root: head.root,
            last_head_digest: head.digest(),
            last_receipt_digest: receipt.digest(),
            receipts_issued: self.state.receipts_issued.saturating_add(1),
        };
        Ok(receipt)
    }
}

// ─── Verification, by anyone holding receipts ───

/// Anchors a verifier holds for witnesses. Supplied by the verifier; a
/// receipt never names the key it is judged against.
#[derive(Debug, Clone, Default)]
pub struct WitnessAnchors {
    keys: std::collections::BTreeMap<(String, u32), Vec<u8>>,
}

impl WitnessAnchors {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn trust(mut self, witness_id: &str, key_version: u32, public_key: &[u8]) -> Self {
        self.keys
            .insert((witness_id.to_string(), key_version), public_key.to_vec());
        self
    }

    pub fn get(&self, witness_id: &str, key_version: u32) -> Option<&[u8]> {
        self.keys
            .get(&(witness_id.to_string(), key_version))
            .map(|v| v.as_slice())
    }
}

/// Verify one receipt's signature under the verifier's anchors.
pub fn verify_receipt(
    receipt: &WitnessReceipt,
    anchors: &WitnessAnchors,
) -> Result<(), WitnessError> {
    if receipt.version != WITNESS_RECEIPT_VERSION {
        return Err(WitnessError::UnsupportedVersion(receipt.version));
    }
    let Some(key) = anchors.get(&receipt.witness_id, receipt.key_version) else {
        return Err(WitnessError::UntrustedWitness {
            witness_id: receipt.witness_id.clone(),
            key_version: receipt.key_version,
        });
    };
    // The signature envelope must name the same witness as the receipt,
    // or an anchor for one witness would verify another's countersignature.
    if receipt.signature.signer_id != receipt.witness_id {
        return Err(WitnessError::SignatureInvalid);
    }
    // Bind the envelope to the payload. Without this the signature is over
    // its own header and the receipt body is unprotected.
    if receipt.signature.payload_hash != sha256(&receipt.signing_preimage()) {
        return Err(WitnessError::PayloadHashMismatch);
    }
    match verify_ed25519(key, &receipt.signature) {
        Ok(true) => Ok(()),
        Ok(false) => Err(WitnessError::SignatureInvalid),
        Err(e) => Err(WitnessError::Crypto(e)),
    }
}

/// Verify a whole receipt set: every signature, and the chain between them.
///
/// Receipts are taken in the order given; the caller is expected to present
/// them as the witness issued them. A set with a receipt removed breaks the
/// chain, which is the point — otherwise a witness could drop the receipt
/// that contradicts a rewritten log.
pub fn verify_receipt_chain(
    receipts: &[WitnessReceipt],
    anchors: &WitnessAnchors,
) -> Result<(), WitnessError> {
    let mut prev: Option<&WitnessReceipt> = None;
    for r in receipts {
        verify_receipt(r, anchors)?;
        match prev {
            None => {}
            Some(p) => {
                if r.log_id != p.log_id {
                    return Err(WitnessError::DifferentLog {
                        expected: p.log_id,
                        got: r.log_id,
                    });
                }
                if r.prev_receipt != p.digest() {
                    return Err(WitnessError::ReceiptChainBroken { at_size: r.size });
                }
                if r.size <= p.size {
                    return Err(WitnessError::NotAnExtension {
                        witnessed: p.size,
                        offered: r.size,
                    });
                }
            }
        }
        prev = Some(r);
    }
    Ok(())
}
