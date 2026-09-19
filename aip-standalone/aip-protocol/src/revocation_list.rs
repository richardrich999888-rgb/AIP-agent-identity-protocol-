//! Signed, time-bounded revocation lists for offline verifiers (R7 of
//! `docs/pilot/RBI_REQUIREMENTS_COVERAGE.md`).
//!
//! # The problem this closes
//!
//! Before this module the verifier's revocation input was a bare set of
//! JTIs on [`crate::VerificationContext`]. That set has no provenance, no
//! issue time and no expiry, which produced two distinct failures:
//!
//! 1. **An empty set read as a pass.** A verifier that had never been told
//!    anything about revocation reported `REVOCATION` as PASS — "no token in
//!    the authority chain is revoked" — when what it actually knew was
//!    nothing at all.
//! 2. **A stale set read as a pass.** An auditor verifying a packet in
//!    March against a list exported in January would be told the chain is
//!    unrevoked, which is a statement about January.
//!
//! An offline verifier cannot call anyone to find out. What it can do is
//! insist that whatever it was handed *says when it was true*, and refuse to
//! convert an answer about the past into an answer about now.
//!
//! # The artefact
//!
//! A [`RevocationList`] is signed by the authority that maintains it, and
//! carries:
//!
//! - `issued_at_ms` and `valid_until_ms` — the window inside which the
//!   issuer is willing to stand behind it. Outside that window a verifier
//!   reports [`rules::REVOCATION`](crate::verification_report::rules::REVOCATION)
//!   as NOT EVALUATED, never as a pass.
//! - `sequence` — strictly increasing per issuer. An auditor holding two
//!   lists can tell which is later, and a replayed older list is visible as
//!   such rather than silently authoritative.
//! - The entries themselves, sorted and unique, so one set of revocations
//!   has exactly one encoding and therefore one signature.
//!
//! # What a list does not do
//!
//! It does not prove that the tokens it omits are *live*. Completeness is a
//! claim the issuer makes by signing, bounded by the window; a verifier that
//! trusts the issuer inside the window treats absence as non-revocation, and
//! outside it treats the whole document as expired. There is no third
//! reading in which a stale list is partially believed.

use std::collections::BTreeMap;

use aip_crypto::{sha256, sign_ed25519, verify_ed25519};
use aip_types::canonical::{put_bytes, put_domain, put_str, put_u16, put_u32, put_u64, put_u8};
use aip_types::{AipError, Signature};
use serde::{Deserialize, Serialize};

/// Domain tag leading the canonical encoding. Distinct from every other
/// signed artefact, so a revocation list cannot be presented as one of them.
pub const REVOCATION_LIST_DOMAIN: &str = "AIP/RevocationList/v1";

/// Structure version. A verifier refuses any other value rather than
/// interpreting it: a later version may add fields the signature covers and
/// this parser would not see.
pub const REVOCATION_LIST_VERSION: u16 = 1;

/// Upper bound on the issuer identifier.
pub const MAX_ISSUER_LEN: usize = 256;

/// Upper bound on entries in one list. A bound, so a verifier cannot be made
/// to allocate without limit by a document it has not yet authenticated.
pub const MAX_ENTRIES: usize = 1_000_000;

/// Why a token was revoked. Recorded for the auditor; it changes no outcome,
/// because a revoked token is refused whatever the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationReason {
    /// Key compromise suspected or confirmed.
    KeyCompromise,
    /// The holder's authority ended (role change, offboarding, contract end).
    AuthorityEnded,
    /// Issued in error.
    Erroneous,
    /// Superseded by a later grant.
    Superseded,
    /// Not stated by the issuer.
    Unspecified,
}

impl RevocationReason {
    pub fn code(self) -> u8 {
        match self {
            Self::KeyCompromise => 0x01,
            Self::AuthorityEnded => 0x02,
            Self::Erroneous => 0x03,
            Self::Superseded => 0x04,
            Self::Unspecified => 0xff,
        }
    }
}

/// One revoked token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokedEntry {
    /// The JTI of a root token or a delegation hop.
    pub jti: [u8; 16],
    /// When the issuer says the revocation took effect. Recorded, but not
    /// used to decide: a verifier that holds a fresh list treats every entry
    /// in it as revoked now, regardless of when it became so. Backdating a
    /// revocation cannot un-revoke anything.
    pub revoked_at_ms: u64,
    pub reason: RevocationReason,
}

/// A revocation list as its issuer maintains it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationList {
    pub version: u16,
    /// The authority that maintains this list. A verifier maps
    /// `(issuer_id, key_version)` to an anchor it was provisioned with.
    pub issuer_id: String,
    pub key_version: u32,
    /// Strictly increasing per `(issuer_id, key_version)`. Two lists from
    /// one issuer are ordered by this and never by their timestamps.
    pub sequence: u64,
    pub issued_at_ms: u64,
    /// The instant after which the issuer no longer stands behind this
    /// document. A verifier past it reports NOT EVALUATED.
    pub valid_until_ms: u64,
    /// Sorted by `jti`, with no repeats. Enforced at signing and rechecked
    /// at verification, so one set of revocations has one encoding.
    pub entries: Vec<RevokedEntry>,
}

impl RevocationList {
    /// Domain-tagged, length-prefixed encoding of every field.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(64 + self.entries.len() * 32);
        put_domain(&mut b, REVOCATION_LIST_DOMAIN);
        put_u16(&mut b, self.version);
        put_str(&mut b, &self.issuer_id);
        put_u32(&mut b, self.key_version);
        put_u64(&mut b, self.sequence);
        put_u64(&mut b, self.issued_at_ms);
        put_u64(&mut b, self.valid_until_ms);
        put_u32(&mut b, self.entries.len() as u32);
        for e in &self.entries {
            put_bytes(&mut b, &e.jti);
            put_u64(&mut b, e.revoked_at_ms);
            put_u8(&mut b, e.reason.code());
        }
        b
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.signing_preimage())
    }

    /// Structural checks that need no key.
    fn check_well_formed(&self) -> Result<(), RevocationListError> {
        if self.version != REVOCATION_LIST_VERSION {
            return Err(RevocationListError::UnsupportedVersion(self.version));
        }
        if self.issuer_id.is_empty() {
            return Err(RevocationListError::MissingIssuer);
        }
        if self.issuer_id.len() > MAX_ISSUER_LEN {
            return Err(RevocationListError::IssuerTooLong(self.issuer_id.len()));
        }
        if self.entries.len() > MAX_ENTRIES {
            return Err(RevocationListError::TooManyEntries(self.entries.len()));
        }
        // A window that ends before it starts is not a window; a verifier
        // would have no instant at which the document was ever usable.
        if self.valid_until_ms < self.issued_at_ms {
            return Err(RevocationListError::WindowInverted {
                issued_at_ms: self.issued_at_ms,
                valid_until_ms: self.valid_until_ms,
            });
        }
        for pair in self.entries.windows(2) {
            match pair[0].jti.cmp(&pair[1].jti) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => {
                    return Err(RevocationListError::DuplicateEntry(pair[0].jti))
                }
                std::cmp::Ordering::Greater => {
                    return Err(RevocationListError::EntriesNotSorted(pair[1].jti))
                }
            }
        }
        Ok(())
    }
}

/// A list plus the issuer's signature over its preimage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRevocationList {
    pub list: RevocationList,
    pub attestation: Signature,
}

impl SignedRevocationList {
    /// Build and sign a list. Entries are sorted and checked for duplicates
    /// here, so a caller cannot produce a list whose encoding depends on the
    /// order it happened to collect revocations in.
    pub fn issue(
        issuer_id: &str,
        key_version: u32,
        private_key: &[u8],
        sequence: u64,
        issued_at_ms: u64,
        valid_until_ms: u64,
        mut entries: Vec<RevokedEntry>,
    ) -> Result<Self, RevocationListError> {
        entries.sort_by_key(|e| e.jti);
        let list = RevocationList {
            version: REVOCATION_LIST_VERSION,
            issuer_id: issuer_id.to_string(),
            key_version,
            sequence,
            issued_at_ms,
            valid_until_ms,
            entries,
        };
        list.check_well_formed()?;
        let attestation = sign_ed25519(private_key, issuer_id, &list.signing_preimage())
            .map_err(RevocationListError::Crypto)?;
        Ok(Self { list, attestation })
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

/// The verifier's trust decision: which revocation issuers, under which key
/// versions. Supplied by the verifier, never read from the list.
#[derive(Debug, Clone, Default)]
pub struct RevocationListAnchors {
    keys: BTreeMap<(String, u32), Vec<u8>>,
}

impl RevocationListAnchors {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn trust(mut self, issuer_id: &str, key_version: u32, public_key: &[u8]) -> Self {
        self.keys
            .insert((issuer_id.to_string(), key_version), public_key.to_vec());
        self
    }

    pub fn get(&self, issuer_id: &str, key_version: u32) -> Option<&[u8]> {
        self.keys
            .get(&(issuer_id.to_string(), key_version))
            .map(|k| k.as_slice())
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Why a revocation list could not be used. Every variant is a refusal to
/// treat the document as authoritative; none of them is a finding about the
/// packet being verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationListError {
    UnsupportedVersion(u16),
    MissingIssuer,
    IssuerTooLong(usize),
    TooManyEntries(usize),
    WindowInverted {
        issued_at_ms: u64,
        valid_until_ms: u64,
    },
    DuplicateEntry([u8; 16]),
    EntriesNotSorted([u8; 16]),
    /// The `(issuer_id, key_version)` pair is not anchored. The verifier has
    /// no opinion about issuers it was not provisioned for.
    IssuerNotAnchored {
        issuer_id: String,
        key_version: u32,
    },
    /// `attestation.signer_id` is not the list's `issuer_id`.
    SignerIsNotIssuer,
    PayloadHashMismatch,
    SignatureInvalid,
    /// The verifier's instant is past `valid_until_ms`. **This is the R7
    /// case**: the document was true once and the verifier will not restate
    /// it as true now.
    Expired {
        valid_until_ms: u64,
        verification_time_ms: u64,
    },
    /// The verifier's instant precedes `issued_at_ms`. Either the clock or
    /// the document is wrong, and the verifier cannot tell which.
    NotYetIssued {
        issued_at_ms: u64,
        verification_time_ms: u64,
    },
    Crypto(AipError),
}

impl std::fmt::Display for RevocationListError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Expired {
                valid_until_ms,
                verification_time_ms,
            } => write!(
                f,
                "revocation list expired at {valid_until_ms}; verifying at \
                 {verification_time_ms}"
            ),
            Self::NotYetIssued {
                issued_at_ms,
                verification_time_ms,
            } => write!(
                f,
                "revocation list is dated {issued_at_ms}, after the \
                 verification time {verification_time_ms}"
            ),
            Self::IssuerNotAnchored {
                issuer_id,
                key_version,
            } => write!(
                f,
                "no anchored key for revocation issuer {issuer_id} key version \
                 {key_version}"
            ),
            other => write!(f, "{other:?}"),
        }
    }
}

impl std::error::Error for RevocationListError {}

/// A list that verified under the verifier's anchors and was fresh at the
/// verifier's instant.
///
/// The field is private and there is no constructor: the only way to obtain
/// one is [`verify_revocation_list`], so the verification engine cannot be
/// handed a list nobody checked or one that has expired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRevocationList(RevocationList);

impl VerifiedRevocationList {
    pub fn list(&self) -> &RevocationList {
        &self.0
    }

    /// Whether this list names `jti` as revoked. Binary search: the entries
    /// are sorted, and verification rechecked that they are.
    pub fn contains(&self, jti: &[u8; 16]) -> bool {
        self.0.entries.binary_search_by_key(jti, |e| e.jti).is_ok()
    }

    pub fn entry(&self, jti: &[u8; 16]) -> Option<&RevokedEntry> {
        self.0
            .entries
            .binary_search_by_key(jti, |e| e.jti)
            .ok()
            .map(|i| &self.0.entries[i])
    }

    /// `(issuer, key version, sequence, valid_until)` — what a report cites
    /// so a reader can tell which document the answer came from.
    pub fn citation(&self) -> (&str, u32, u64, u64) {
        (
            &self.0.issuer_id,
            self.0.key_version,
            self.0.sequence,
            self.0.valid_until_ms,
        )
    }
}

/// Verify a revocation list and place it in time.
///
/// `verification_time_ms` is the verifier's own instant, supplied
/// explicitly for the same reason [`crate::VerificationContext::verification_time_ms`]
/// is: an offline verifier checking a historical packet, an air-gapped
/// verifier and a test all need to say what "now" means to them. There is no
/// call to the system clock here.
///
/// Order: structure, then anchor, then signer attribution, then the payload
/// hash, then the signature, then freshness. Freshness is last because a
/// document that does not verify has no window worth discussing.
pub fn verify_revocation_list(
    signed: &SignedRevocationList,
    anchors: &RevocationListAnchors,
    verification_time_ms: u64,
) -> Result<VerifiedRevocationList, RevocationListError> {
    let l = &signed.list;
    l.check_well_formed()?;
    let key = anchors.get(&l.issuer_id, l.key_version).ok_or_else(|| {
        RevocationListError::IssuerNotAnchored {
            issuer_id: l.issuer_id.clone(),
            key_version: l.key_version,
        }
    })?;
    if signed.attestation.signer_id != l.issuer_id {
        return Err(RevocationListError::SignerIsNotIssuer);
    }
    if signed.attestation.payload_hash != l.digest() {
        return Err(RevocationListError::PayloadHashMismatch);
    }
    match verify_ed25519(key, &signed.attestation) {
        Ok(true) => {}
        Ok(false) => return Err(RevocationListError::SignatureInvalid),
        Err(e) => return Err(RevocationListError::Crypto(e)),
    }
    if verification_time_ms < l.issued_at_ms {
        return Err(RevocationListError::NotYetIssued {
            issued_at_ms: l.issued_at_ms,
            verification_time_ms,
        });
    }
    if verification_time_ms > l.valid_until_ms {
        return Err(RevocationListError::Expired {
            valid_until_ms: l.valid_until_ms,
            verification_time_ms,
        });
    }
    Ok(VerifiedRevocationList(l.clone()))
}

/// What the verifier holds about revocation, as the verification engine sees
/// it.
///
/// A supplied-but-unusable list is carried here rather than discarded so the
/// report can say *why* the rule was not evaluated. A caller that dropped the
/// defect on the floor would produce a report indistinguishable from one
/// where no list was ever offered, which is the failure this whole module
/// exists to prevent.
#[derive(Debug, Clone)]
pub enum RevocationEvidence {
    /// A list that verified and is inside its validity window.
    Fresh(Box<VerifiedRevocationList>),
    /// The verifier consulted an authoritative record **of its own** at a
    /// known instant, rather than a document someone handed it.
    ///
    /// This is what an online service has: it reads its own revocation store,
    /// for the caller's tenant, at the moment of the request. That is a
    /// genuine evaluation and must read as one — reporting NOT EVALUATED
    /// there would be as dishonest in the other direction.
    ///
    /// It is deliberately *not* a [`RevocationList`]: nothing here can be
    /// handed to a third party, so a report that rests on it says where the
    /// answer came from and when, and an auditor who needs a portable answer
    /// asks for a signed list instead.
    ///
    /// Membership still comes from
    /// [`crate::VerificationContext::revoked_jtis`], which the verifier
    /// populates from that record.
    Live {
        /// What was consulted, in words a reader of the report can act on.
        source: String,
        /// The instant it was consulted, in Unix ms.
        as_of_ms: u64,
    },
    /// A list was supplied and cannot be used, with the reason.
    Unusable(RevocationListError),
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "aip1RevocationAuthority";
    const T0: u64 = 1_700_000_000_000;

    fn entry(b: u8) -> RevokedEntry {
        RevokedEntry {
            jti: [b; 16],
            revoked_at_ms: T0,
            reason: RevocationReason::AuthorityEnded,
        }
    }

    fn issued(entries: Vec<RevokedEntry>) -> (SignedRevocationList, RevocationListAnchors) {
        let kp = aip_crypto::generate_ed25519_keypair();
        let signed = SignedRevocationList::issue(
            ISSUER,
            1,
            &kp.private_key,
            7,
            T0,
            T0 + 86_400_000,
            entries,
        )
        .unwrap();
        (
            signed,
            RevocationListAnchors::new().trust(ISSUER, 1, &kp.public_key),
        )
    }

    #[test]
    fn entries_are_sorted_at_issue_so_one_set_has_one_encoding() {
        let kp = aip_crypto::generate_ed25519_keypair();
        let a = SignedRevocationList::issue(
            ISSUER,
            1,
            &kp.private_key,
            1,
            T0,
            T0 + 1,
            vec![entry(3), entry(1), entry(2)],
        )
        .unwrap();
        let b = SignedRevocationList::issue(
            ISSUER,
            1,
            &kp.private_key,
            1,
            T0,
            T0 + 1,
            vec![entry(1), entry(2), entry(3)],
        )
        .unwrap();
        assert_eq!(a.list.signing_preimage(), b.list.signing_preimage());
        assert_eq!(a.list.entries[0].jti, [1u8; 16]);
    }

    #[test]
    fn a_duplicate_or_inverted_window_is_refused_at_issue() {
        let kp = aip_crypto::generate_ed25519_keypair();
        assert_eq!(
            SignedRevocationList::issue(
                ISSUER,
                1,
                &kp.private_key,
                1,
                T0,
                T0 + 1,
                vec![entry(4), entry(4)]
            ),
            Err(RevocationListError::DuplicateEntry([4u8; 16]))
        );
        assert_eq!(
            SignedRevocationList::issue(ISSUER, 1, &kp.private_key, 1, T0, T0 - 1, vec![]),
            Err(RevocationListError::WindowInverted {
                issued_at_ms: T0,
                valid_until_ms: T0 - 1
            })
        );
    }

    #[test]
    fn a_fresh_list_answers_membership_and_cites_itself() {
        let (signed, anchors) = issued(vec![entry(9), entry(2)]);
        let v = verify_revocation_list(&signed, &anchors, T0 + 1_000).unwrap();
        assert!(v.contains(&[9u8; 16]));
        assert!(!v.contains(&[8u8; 16]));
        assert_eq!(
            v.entry(&[2u8; 16]).unwrap().reason,
            RevocationReason::AuthorityEnded
        );
        let (issuer, kv, seq, until) = v.citation();
        assert_eq!((issuer, kv, seq, until), (ISSUER, 1, 7, T0 + 86_400_000));
    }

    #[test]
    fn an_expired_or_future_list_is_refused_with_both_instants_named() {
        let (signed, anchors) = issued(vec![entry(1)]);
        assert_eq!(
            verify_revocation_list(&signed, &anchors, T0 + 86_400_001),
            Err(RevocationListError::Expired {
                valid_until_ms: T0 + 86_400_000,
                verification_time_ms: T0 + 86_400_001
            })
        );
        assert_eq!(
            verify_revocation_list(&signed, &anchors, T0 - 1),
            Err(RevocationListError::NotYetIssued {
                issued_at_ms: T0,
                verification_time_ms: T0 - 1
            })
        );
        // The boundaries themselves are inside the window.
        assert!(verify_revocation_list(&signed, &anchors, T0).is_ok());
        assert!(verify_revocation_list(&signed, &anchors, T0 + 86_400_000).is_ok());
    }

    #[test]
    fn an_unanchored_altered_or_impostor_list_establishes_nothing() {
        let (signed, anchors) = issued(vec![entry(1)]);
        assert!(matches!(
            verify_revocation_list(&signed, &RevocationListAnchors::new(), T0),
            Err(RevocationListError::IssuerNotAnchored { .. })
        ));

        // Drop an entry after signing: the hash no longer matches.
        let mut t = signed.clone();
        t.list.entries.clear();
        assert_eq!(
            verify_revocation_list(&t, &anchors, T0),
            Err(RevocationListError::PayloadHashMismatch)
        );

        // Re-sign the emptied list with a key the verifier does not anchor.
        let impostor = aip_crypto::generate_ed25519_keypair();
        let re = SignedRevocationList::issue(
            ISSUER,
            1,
            &impostor.private_key,
            7,
            T0,
            T0 + 86_400_000,
            vec![],
        )
        .unwrap();
        assert_eq!(
            verify_revocation_list(&re, &anchors, T0),
            Err(RevocationListError::SignatureInvalid)
        );

        // A signature naming another signer than the list does.
        let mut s = signed.clone();
        s.attestation.signer_id = "aip1SomeoneElse".into();
        assert_eq!(
            verify_revocation_list(&s, &anchors, T0),
            Err(RevocationListError::SignerIsNotIssuer)
        );

        // A version this build does not implement.
        let mut v = signed.clone();
        v.list.version = REVOCATION_LIST_VERSION + 1;
        assert_eq!(
            verify_revocation_list(&v, &anchors, T0),
            Err(RevocationListError::UnsupportedVersion(
                REVOCATION_LIST_VERSION + 1
            ))
        );
    }

    #[test]
    fn a_reordered_list_is_refused_even_though_it_is_the_same_set() {
        let (signed, anchors) = issued(vec![entry(1), entry(2)]);
        let mut t = signed.clone();
        t.list.entries.reverse();
        // Caught as non-canonical before the signature is ever consulted.
        assert_eq!(
            verify_revocation_list(&t, &anchors, T0),
            Err(RevocationListError::EntriesNotSorted([1u8; 16]))
        );
    }

    #[test]
    fn the_list_round_trips_through_json_and_still_verifies() {
        let (signed, anchors) = issued(vec![entry(5), entry(1)]);
        let json = signed.to_json().unwrap();
        let back = SignedRevocationList::from_json(&json).unwrap();
        assert_eq!(back, signed);
        assert!(verify_revocation_list(&back, &anchors, T0 + 5).is_ok());
    }
}
