//! The capability epoch: the one object the hardware root of trust signs,
//! and the only thing the per-syscall path ever consults.

use aip_crypto::{sha256, sign_ed25519, verify_ed25519};
use aip_types::canonical::*;
use aip_types::{AipError, KeyPair, Signature};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const CAPABILITY_EPOCH_DOMAIN: &str = "SYNTRIASS/GHOST/CAPABILITY_EPOCH/v1";
pub const CAPABILITY_EPOCH_VERSION: u16 = 1;

/// What signed the epoch, and hence what the replay bound rests on.
///
/// Only [`RootOfTrust::SoftwareKey`] has an issuer in this repository
/// ([`SoftwareIssuer`]). The other two are wire vocabulary for issuers that
/// do not exist here yet; an anchor declares which root an issuer holds, and
/// an epoch claiming a stronger root than its anchor declared is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RootOfTrust {
    /// A process-held Ed25519 key with a process-held counter.
    SoftwareKey,
    /// An ATECC608B-held key with its hardware monotonic counter. Not
    /// implemented here.
    Atecc608b,
    /// A TPM 2.0-held key. Not implemented here.
    Tpm2,
}

impl RootOfTrust {
    fn code(&self) -> u8 {
        match self {
            RootOfTrust::SoftwareKey => 0x01,
            RootOfTrust::Atecc608b => 0x02,
            RootOfTrust::Tpm2 => 0x03,
        }
    }
}

/// One permitted egress endpoint. IPv4 only in v1; an epoch with no egress
/// permits none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Egress {
    pub addr_v4: [u8; 4],
    pub port: u16,
}

/// What an issuer is asked to sign. Everything the epoch will carry except
/// the counter and the root, which the issuer supplies because they are the
/// issuer's to supply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochDraft {
    pub epoch_id: [u8; 16],
    pub agent_id: String,
    /// `SHA-256(ExpectedExecution::signing_preimage())` — binds the epoch to
    /// one decision without this crate needing to parse the expectation.
    pub expectation_digest: [u8; 32],
    /// Content hashes of the programs that may be executed.
    pub allowed_programs: Vec<[u8; 32]>,
    pub allowed_egress: Vec<Egress>,
    pub issued_at: u64,
    pub valid_until: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityEpoch {
    pub version: u16,
    pub epoch_id: [u8; 16],
    pub issuer_id: String,
    pub agent_id: String,
    pub expectation_digest: [u8; 32],
    /// Sorted and de-duplicated by the issuer; the verifier checks that it
    /// still is, so two orderings of one set cannot have two digests.
    pub allowed_programs: Vec<[u8; 32]>,
    pub allowed_egress: Vec<Egress>,
    /// Strictly increasing per issuer.
    pub counter: u64,
    pub counter_root: RootOfTrust,
    pub issued_at: u64,
    pub valid_until: u64,
}

impl CapabilityEpoch {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, CAPABILITY_EPOCH_DOMAIN);
        put_u16(&mut buf, self.version);
        buf.extend_from_slice(&self.epoch_id);
        put_str(&mut buf, &self.issuer_id);
        put_str(&mut buf, &self.agent_id);
        buf.extend_from_slice(&self.expectation_digest);
        put_u32(&mut buf, self.allowed_programs.len() as u32);
        for p in &self.allowed_programs {
            buf.extend_from_slice(p);
        }
        put_u32(&mut buf, self.allowed_egress.len() as u32);
        for e in &self.allowed_egress {
            buf.extend_from_slice(&e.addr_v4);
            put_u16(&mut buf, e.port);
        }
        put_u64(&mut buf, self.counter);
        put_u8(&mut buf, self.counter_root.code());
        put_u64(&mut buf, self.issued_at);
        put_u64(&mut buf, self.valid_until);
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }

    pub fn permits_program(&self, content_hash: &[u8; 32]) -> bool {
        self.allowed_programs.binary_search(content_hash).is_ok()
    }

    pub fn permits_egress(&self, egress: &Egress) -> bool {
        self.allowed_egress.binary_search(egress).is_ok()
    }

    fn sets_are_canonical(&self) -> bool {
        self.allowed_programs.windows(2).all(|w| w[0] < w[1])
            && self.allowed_egress.windows(2).all(|w| w[0] < w[1])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCapabilityEpoch {
    pub epoch: CapabilityEpoch,
    pub attestation: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssueError {
    /// The issuer's counter cannot advance; it must not reuse a value.
    CounterExhausted,
    WindowInverted,
    Crypto(AipError),
}

/// Whatever signs epochs. The hardware round trip, if there is one, lives
/// behind this trait and happens once per epoch.
pub trait EpochIssuer {
    fn issuer_id(&self) -> &str;
    fn root_of_trust(&self) -> RootOfTrust;
    fn public_key(&self) -> &[u8];
    fn issue(&mut self, draft: EpochDraft) -> Result<SignedCapabilityEpoch, IssueError>;
}

/// An issuer holding its key and counter in process memory. What it signs
/// is honest about that: `counter_root` is [`RootOfTrust::SoftwareKey`].
pub struct SoftwareIssuer {
    issuer_id: String,
    keypair: KeyPair,
    next_counter: u64,
}

impl SoftwareIssuer {
    pub fn new(issuer_id: &str, keypair: KeyPair, first_counter: u64) -> Self {
        Self {
            issuer_id: issuer_id.to_string(),
            keypair,
            next_counter: first_counter,
        }
    }
}

impl EpochIssuer for SoftwareIssuer {
    fn issuer_id(&self) -> &str {
        &self.issuer_id
    }
    fn root_of_trust(&self) -> RootOfTrust {
        RootOfTrust::SoftwareKey
    }
    fn public_key(&self) -> &[u8] {
        &self.keypair.public_key
    }
    fn issue(&mut self, draft: EpochDraft) -> Result<SignedCapabilityEpoch, IssueError> {
        if draft.valid_until < draft.issued_at {
            return Err(IssueError::WindowInverted);
        }
        let counter = self.next_counter;
        self.next_counter = counter.checked_add(1).ok_or(IssueError::CounterExhausted)?;
        let mut allowed_programs = draft.allowed_programs;
        allowed_programs.sort_unstable();
        allowed_programs.dedup();
        let mut allowed_egress = draft.allowed_egress;
        allowed_egress.sort_unstable();
        allowed_egress.dedup();
        let epoch = CapabilityEpoch {
            version: CAPABILITY_EPOCH_VERSION,
            epoch_id: draft.epoch_id,
            issuer_id: self.issuer_id.clone(),
            agent_id: draft.agent_id,
            expectation_digest: draft.expectation_digest,
            allowed_programs,
            allowed_egress,
            counter,
            counter_root: RootOfTrust::SoftwareKey,
            issued_at: draft.issued_at,
            valid_until: draft.valid_until,
        };
        let attestation = sign_ed25519(
            &self.keypair.private_key,
            &self.issuer_id,
            &epoch.canonical_bytes(),
        )
        .map_err(IssueError::Crypto)?;
        Ok(SignedCapabilityEpoch { epoch, attestation })
    }
}

/// The enforcer's trust decision: which issuers, under which keys, holding
/// which root of trust. The root is part of the anchor because an epoch must
/// not be allowed to upgrade its own provenance.
#[derive(Debug, Clone, Default)]
pub struct EpochAnchors {
    issuers: BTreeMap<String, (Vec<u8>, RootOfTrust)>,
}

impl EpochAnchors {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn trust(mut self, issuer_id: &str, public_key: &[u8], root: RootOfTrust) -> Self {
        self.issuers
            .insert(issuer_id.to_string(), (public_key.to_vec(), root));
        self
    }
    pub fn get(&self, issuer_id: &str) -> Option<(&[u8], RootOfTrust)> {
        self.issuers.get(issuer_id).map(|(k, r)| (k.as_slice(), *r))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochError {
    UnsupportedVersion(u16),
    IssuerNotAnchored(String),
    SignerIsNotIssuer,
    PayloadHashMismatch,
    SignatureInvalid,
    /// The epoch claims a root the anchor did not declare for this issuer.
    RootOfTrustMismatch {
        anchored: RootOfTrust,
        claimed: RootOfTrust,
    },
    WindowInverted,
    /// A permitted set is not sorted and de-duplicated; the encoding would
    /// not be injective over sets.
    SetsNotCanonical,
    Crypto(AipError),
}

/// An epoch that verified against the enforcer's anchors. No constructor;
/// [`verify_epoch`] is the only source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEpoch(CapabilityEpoch);

impl VerifiedEpoch {
    pub fn epoch(&self) -> &CapabilityEpoch {
        &self.0
    }
}

pub fn verify_epoch(
    signed: &SignedCapabilityEpoch,
    anchors: &EpochAnchors,
) -> Result<VerifiedEpoch, EpochError> {
    let e = &signed.epoch;
    if e.version != CAPABILITY_EPOCH_VERSION {
        return Err(EpochError::UnsupportedVersion(e.version));
    }
    let (key, anchored_root) = anchors
        .get(&e.issuer_id)
        .ok_or_else(|| EpochError::IssuerNotAnchored(e.issuer_id.clone()))?;
    if signed.attestation.signer_id != e.issuer_id {
        return Err(EpochError::SignerIsNotIssuer);
    }
    if e.counter_root != anchored_root {
        return Err(EpochError::RootOfTrustMismatch {
            anchored: anchored_root,
            claimed: e.counter_root,
        });
    }
    if e.valid_until < e.issued_at {
        return Err(EpochError::WindowInverted);
    }
    if !e.sets_are_canonical() {
        return Err(EpochError::SetsNotCanonical);
    }
    if signed.attestation.payload_hash != e.digest() {
        return Err(EpochError::PayloadHashMismatch);
    }
    match verify_ed25519(key, &signed.attestation) {
        Ok(true) => Ok(VerifiedEpoch(e.clone())),
        Ok(false) => Err(EpochError::SignatureInvalid),
        Err(err) => Err(EpochError::Crypto(err)),
    }
}
