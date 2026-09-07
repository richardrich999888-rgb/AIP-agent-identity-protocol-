//! Skill 10 Gate 11 — replay semantics.
//!
//! # Offline verification proves what a package supports. It does not grant
//! current authority.
//!
//! That sentence is the whole of this module's purpose. A proof is a
//! deterministic statement about a past execution: the same bytes and the
//! same anchors yield the same verdict today, tomorrow and in a decade.
//! Nothing about that changes when the authority the execution rested on
//! expires — what happened still happened — and nothing about it makes the
//! proof a licence to act now. Evidence and permission are different
//! sentences, and this module keeps them apart.
//!
//! # What is answered here, and by whom
//!
//! | §11 term                      | answered by | how |
//! |-------------------------------|-------------|-----|
//! | valid historical replay       | the verifier | a valid proof *is* this |
//! | proof of a previous execution | the verifier | the same, from the other side |
//! | stale authority               | the verifier | [`AuthorityStanding`], against a present time the *verifier* supplies |
//! | duplicate submission          | the consumer | [`ProofLedger`], below; verification stays pure |
//! | unauthorized reuse            | nobody here  | presenting a proof as permission is the consumer's act |
//!
//! The last row is the honest one. NEXORA cannot detect that somebody
//! waved a valid proof at a system as though it were authorisation; it can
//! only ensure there is nothing in a [`VerifiedProof`](crate::verify::VerifiedProof)
//! that could be read as one, and say so plainly where a reader will meet
//! it.
//!
//! # Why the ledger is not inside the verifier
//!
//! Verification is a pure function of a package and a set of anchors, and
//! several properties rest on that — determinism, offline operation, the
//! absence of hidden state. Duplicate detection is inherently stateful, so
//! it lives here as an explicit act a consumer performs *after* verifying,
//! against a ledger it owns. Being seen twice does not make a past
//! execution untrue; it is a fact about submissions, not about evidence.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::verify::VerifiedProof;

/// Where the authority an execution rested on stands *now*, at a present
/// time the verifier supplied.
///
/// No variant grants anything. The type exists so a consumer can tell "the
/// authority behind this was still live when I looked" from "it expired in
/// 2029" — and so that neither can be mistaken for permission to act.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorityStanding {
    /// The verifier supplied no present time, so staleness was not
    /// assessed. Not an assertion that the authority is live.
    NotAssessed,
    /// The authority's window had not closed at the verifier's present
    /// time. Still not permission: it is an observation about a window.
    ValidNow,
    /// The window closed. The proof remains a true statement about the
    /// past.
    StaleSince { valid_until: u64 },
}

impl AuthorityStanding {
    pub const ALL: [AuthorityStanding; 3] = [
        AuthorityStanding::NotAssessed,
        AuthorityStanding::ValidNow,
        AuthorityStanding::StaleSince { valid_until: 0 },
    ];

    /// Always false. The method exists to be called and to answer no: a
    /// proof is evidence, never permission, and a consumer that reaches
    /// for authority finds this.
    pub fn grants_authority_now(self) -> bool {
        false
    }
}

/// Whether this consumer has seen this proof before.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayStanding {
    /// The first time this ledger has recorded this proof id.
    FirstSeen,
    /// Recorded before. A fact about submissions; the proof is no less
    /// true for having been shown twice.
    DuplicateSubmission { first_seen_count: u64 },
}

/// A consumer's record of the proofs it has accepted.
pub trait ProofLedger {
    fn seen(&self, proof_id: &[u8; 32]) -> Option<u64>;
    fn record(&mut self, proof_id: &[u8; 32]) -> Result<(), String>;
}

/// In-memory: forgotten when the process ends.
#[derive(Debug, Default)]
pub struct MemoryProofLedger {
    seen: HashMap<[u8; 32], u64>,
}

impl ProofLedger for MemoryProofLedger {
    fn seen(&self, proof_id: &[u8; 32]) -> Option<u64> {
        self.seen.get(proof_id).copied()
    }
    fn record(&mut self, proof_id: &[u8; 32]) -> Result<(), String> {
        *self.seen.entry(*proof_id).or_insert(0) += 1;
        Ok(())
    }
}

/// Append-only file of accepted proof ids, one lowercase hex id per line.
#[derive(Debug)]
pub struct FileProofLedger {
    path: PathBuf,
    seen: HashMap<[u8; 32], u64>,
}

impl FileProofLedger {
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut seen: HashMap<[u8; 32], u64> = HashMap::new();
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                for line in text.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let id = parse_hex_id(line).ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("ledger line is not a proof id: {line:?}"),
                        )
                    })?;
                    *seen.entry(id).or_insert(0) += 1;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        Ok(Self { path, seen })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl ProofLedger for FileProofLedger {
    fn seen(&self, proof_id: &[u8; 32]) -> Option<u64> {
        self.seen.get(proof_id).copied()
    }
    fn record(&mut self, proof_id: &[u8; 32]) -> Result<(), String> {
        let mut line: String = proof_id.iter().map(|b| format!("{b:02x}")).collect();
        line.push('\n');
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| e.to_string())?;
        f.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        *self.seen.entry(*proof_id).or_insert(0) += 1;
        Ok(())
    }
}

fn parse_hex_id(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// Record that this consumer accepted this proof, and say whether it had
/// seen it before.
///
/// Deliberately separate from verification, which stays a pure function of
/// a package and a set of anchors. A duplicate is a fact about submissions
/// and never a judgement about the evidence.
pub fn record_submission(
    ledger: &mut impl ProofLedger,
    verified: &VerifiedProof,
) -> Result<ReplayStanding, String> {
    let before = ledger.seen(&verified.proof_id);
    ledger.record(&verified.proof_id)?;
    Ok(match before {
        None => ReplayStanding::FirstSeen,
        Some(n) => ReplayStanding::DuplicateSubmission {
            first_seen_count: n,
        },
    })
}
