//! Attestation: the collector signs what the probe reported having seen.
//!
//! # Where the key lives
//!
//! The signing key is held by [`CollectorSigner`], which the architecture
//! places **off the observed host** (OBSERVER_ATTESTATION.md §3, "remote
//! collector"). Nothing on the host side of this crate holds, receives, or
//! can reach a key: [`crate::probe`] has no key field and no signing method,
//! and [`crate::observed::ObservationBatch`] has no signature field. An
//! attacker with root on the observed host can therefore forge observations
//! *offered* to the collector, but cannot forge an attestation of them.
//!
//! # Provenance gating (Stage 6.5)
//!
//! Every observation states its [`SourceMechanism`]. A host-side party could
//! label a fabricated report as kernel-pushed; the collector therefore keeps
//! a **probe registry**: which probe ids an operator has provisioned and
//! which mechanisms each may claim. Under [`ProbePolicy::RegisteredOnly`] a
//! batch from an unregistered probe, or claiming an unregistered mechanism,
//! is refused before anything is signed. The registry lives at the collector,
//! outside the host's reach; the transport that proves a batch really came
//! from the registered probe is a deployment obligation (see report).
//!
//! # What is signed
//!
//! ```text
//! preimage = put_domain("SYNTRIASS/GHOST/OBSERVER_HEAD/v1")
//!          ‖ put_u16(version)
//!          ‖ put_str(observer_id)
//!          ‖ put_u32(key_version)
//!          ‖ put_u64(sequence)
//!          ‖ prev_head                (32 bytes, fixed)
//!          ‖ put_bytes(batch.canonical_bytes())
//!
//! head = SHA-256(preimage)
//! ```
//!
//! `head` is **computed, never carried**: a verifier reconstructs the bytes
//! and re-derives it, so there is no supplied-hash to be trusted.

use std::collections::{HashMap, HashSet};

use aip_crypto::{sha256, verify_ed25519};
use aip_types::canonical::*;
use aip_types::{AipError, Signature};
use serde::{Deserialize, Serialize};

use crate::continuity::{Admission, ContinuityBreak, ContinuityFault, ObserverLedger};
use crate::health::{
    AttestedClock, ContinuityStatus, CoverageWindow, MechanismIntegrity, ObserverState,
    ProbePolicy, SensorHealth, SignedSensorHealth,
};
use crate::observed::{ObservationBatch, SourceMechanism, OBSERVE_PROTOCOL_VERSION};

/// Domain tag leading the attested-batch (chain head) preimage.
pub const OBSERVER_HEAD_DOMAIN: &str = "SYNTRIASS/GHOST/OBSERVER_HEAD/v1";

// ─── Attested batch ───

/// A batch of observations plus the collector's attestation of it.
///
/// The collector attests: *this batch of observations was received from that
/// probe, at this position in my chain*. It does not attest that the
/// observations are true — a host with root can lie to its own probe. It
/// attests that these bytes, in this order, are what it received and recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedBatch {
    pub version: u16,
    pub observer_id: String,
    /// Which of the observer's keys signed this. Verifiers anchor
    /// `(observer_id, key_version)` pairs, so rotation does not invalidate
    /// history and revocation is the removal of one pair.
    pub key_version: u32,
    /// Position in the collector's chain for this observer. Assigned by the
    /// collector; the host cannot choose it.
    pub sequence: u64,
    /// Head of the predecessor batch, `[0u8; 32]` for an epoch start.
    pub prev_head: [u8; 32],
    /// The collector's own clock when it signed this batch. Off-host and
    /// signed, so a verifier can bound *when the collector had this batch*
    /// without trusting anything the host wrote — an event inside the batch
    /// cannot have happened after this moment.
    pub attested_at_ms: u64,
    pub batch: ObservationBatch,
    pub attestation: Signature,
}

impl AttestedBatch {
    /// Exact bytes the attestation covers.
    pub fn signing_preimage(&self) -> Vec<u8> {
        preimage(
            self.version,
            &self.observer_id,
            self.key_version,
            self.sequence,
            &self.prev_head,
            self.attested_at_ms,
            &self.batch,
        )
    }

    /// Chain head, recomputed from the record. Never read from a field.
    pub fn head(&self) -> [u8; 32] {
        sha256(&self.signing_preimage())
    }
}

fn preimage(
    version: u16,
    observer_id: &str,
    key_version: u32,
    sequence: u64,
    prev_head: &[u8; 32],
    attested_at_ms: u64,
    batch: &ObservationBatch,
) -> Vec<u8> {
    let mut buf = Vec::new();
    put_domain(&mut buf, OBSERVER_HEAD_DOMAIN);
    put_u16(&mut buf, version);
    put_str(&mut buf, observer_id);
    put_u32(&mut buf, key_version);
    put_u64(&mut buf, sequence);
    buf.extend_from_slice(prev_head);
    put_u64(&mut buf, attested_at_ms);
    put_bytes(&mut buf, &batch.canonical_bytes());
    buf
}

// ─── Trust anchors and verification ───

/// The verifier's decision about which observer keys it trusts, keyed by
/// `(observer_id, key_version)`.
///
/// Rotation: anchor the new version alongside the old, so historical batches
/// stay verifiable. Revocation: remove the pair.
#[derive(Debug, Clone, Default)]
pub struct ObserverTrustAnchors {
    keys: HashMap<(String, u32), Vec<u8>>,
}

impl ObserverTrustAnchors {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn trust(mut self, observer_id: &str, key_version: u32, public_key: &[u8]) -> Self {
        self.keys
            .insert((observer_id.to_string(), key_version), public_key.to_vec());
        self
    }

    pub fn revoke(&mut self, observer_id: &str, key_version: u32) {
        self.keys.remove(&(observer_id.to_string(), key_version));
    }

    pub fn get(&self, observer_id: &str, key_version: u32) -> Option<&[u8]> {
        self.keys
            .get(&(observer_id.to_string(), key_version))
            .map(|k| k.as_slice())
    }

    /// Every anchor, in a deterministic order, so a written file is stable.
    pub fn entries(&self) -> Vec<(String, u32, Vec<u8>)> {
        let mut v: Vec<(String, u32, Vec<u8>)> = self
            .keys
            .iter()
            .map(|((id, ver), key)| (id.clone(), *ver, key.clone()))
            .collect();
        v.sort();
        v
    }
}

/// Why an attested batch or health record failed verification. Cryptographic
/// failure, trust failure and structural failure stay distinct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    UnsupportedVersion(u16),
    /// No anchor for this `(observer_id, key_version)`. The signature may be
    /// perfectly valid — the verifier does not trust the signer, or the key
    /// version is revoked.
    UntrustedObserverKey {
        observer_id: String,
        key_version: u32,
    },
    /// The anchored observer key is the observed agent's own key. An
    /// observation signed by the observed party is a second self-report, not
    /// independent evidence (I10).
    ObserverKeyIsAgentKey,
    /// `attestation.signer_id` is not `observer_id`.
    SignerMismatch,
    /// The signature does not cover these bytes.
    PayloadHashMismatch,
    SignatureInvalid,
    Crypto(AipError),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for VerifyError {}

pub(crate) fn verify_signature_over(
    payload: &[u8],
    signer_id: &str,
    key_version: u32,
    sig: &Signature,
    anchors: &ObserverTrustAnchors,
) -> Result<(), VerifyError> {
    let key =
        anchors
            .get(signer_id, key_version)
            .ok_or_else(|| VerifyError::UntrustedObserverKey {
                observer_id: signer_id.to_string(),
                key_version,
            })?;
    if sig.signer_id != signer_id {
        return Err(VerifyError::SignerMismatch);
    }
    if sig.payload_hash != sha256(payload) {
        return Err(VerifyError::PayloadHashMismatch);
    }
    match verify_ed25519(key, sig) {
        Ok(true) => Ok(()),
        Ok(false) => Err(VerifyError::SignatureInvalid),
        Err(e) => Err(VerifyError::Crypto(e)),
    }
}

/// Verify an attested batch offline against the verifier's anchors.
///
/// Success means: *the trusted observer signed exactly this batch at this
/// chain position*. It does not mean the observations are true, that the
/// window was continuously covered, or that anything was authorized.
pub fn verify_attested_batch(
    b: &AttestedBatch,
    anchors: &ObserverTrustAnchors,
) -> Result<(), VerifyError> {
    if b.version != OBSERVE_PROTOCOL_VERSION || b.batch.version != OBSERVE_PROTOCOL_VERSION {
        return Err(VerifyError::UnsupportedVersion(b.version));
    }
    verify_signature_over(
        &b.signing_preimage(),
        &b.observer_id,
        b.key_version,
        &b.attestation,
        anchors,
    )
}

/// As [`verify_attested_batch`], additionally refusing an anchor whose key is
/// the observed agent's own public key.
pub fn verify_attested_batch_independent_of_agent(
    b: &AttestedBatch,
    anchors: &ObserverTrustAnchors,
    agent_public_key: &[u8],
) -> Result<(), VerifyError> {
    if let Some(key) = anchors.get(&b.observer_id, b.key_version) {
        if key == agent_public_key {
            return Err(VerifyError::ObserverKeyIsAgentKey);
        }
    }
    verify_attested_batch(b, anchors)
}

/// Verify a signed health record offline.
pub fn verify_signed_health(
    h: &SignedSensorHealth,
    anchors: &ObserverTrustAnchors,
) -> Result<(), VerifyError> {
    if h.health.version != OBSERVE_PROTOCOL_VERSION {
        return Err(VerifyError::UnsupportedVersion(h.health.version));
    }
    verify_signature_over(
        &h.health.canonical_bytes(),
        &h.health.observer_id,
        h.health.key_version,
        &h.attestation,
        anchors,
    )
}

// ─── The attestor ───

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestError {
    Continuity(ContinuityFault),
    /// The observer's integrity failed arithmetically; it may not sign again
    /// under this identity until an operator re-provisions it.
    Quarantined,
    UnsupportedVersion(u16),
    InvalidKeyLength(usize),
    /// The custodian could not sign. Reported rather than retried: a
    /// collector that cannot sign must stop, not produce something weaker.
    Custody(String),
    EmptyObserverId,
    /// A snapshot of another observer was offered for resume. Splicing one
    /// observer's chain position onto another's id is refused.
    ForeignState {
        expected: String,
        got: String,
    },
    /// Under `RegisteredOnly`, a batch arrived from a probe id no operator
    /// provisioned. Refused before signing.
    UnregisteredProbe(String),
    /// A registered probe claimed a mechanism it was not provisioned for —
    /// the shape of "host-side party labels its report as kernel provenance".
    MechanismNotProvisioned {
        probe_id: String,
        mechanism: SourceMechanism,
    },
    /// The batch's own sequence range is impossible (`first > last`).
    MalformedBatch(&'static str),
    Signing(AipError),
}

impl std::fmt::Display for AttestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for AttestError {}

/// The signing seam. Implemented only by a component that holds a key —
/// which, by the architecture, is never on the observed host.
pub trait ObserverAttestor {
    /// Attest a batch received from a probe, stamped with the collector's
    /// current clock.
    fn attest(&mut self, batch: ObservationBatch) -> Result<AttestedBatch, AttestError> {
        self.attest_at(batch, collector_now_ms())
    }
    /// Attest a batch received from a probe at an explicit collector time.
    fn attest_at(
        &mut self,
        batch: ObservationBatch,
        attested_at_ms: u64,
    ) -> Result<AttestedBatch, AttestError>;
    /// Current signed health, with no clock reading. Absence of a recent
    /// health record must reduce coverage at the verifier, never extend it.
    ///
    /// Prefer [`Self::health_with_clock`] in a daemon. This exists for
    /// callers with no clock source and for tests, and records `clock: None`
    /// -- which a verifier reads as "the collector said nothing about its
    /// clock", never as "the clock was fine".
    fn health(&self, emitted_at_ms: u64) -> Result<SignedSensorHealth, AttestError> {
        self.health_with_clock(emitted_at_ms, None)
    }
    /// Current signed health, carrying the collector's clock discipline
    /// inside the attested bytes (protocol 12).
    ///
    /// Reading the clock is IO and therefore the caller's job: this crate
    /// signs what it is given and performs no syscalls of its own on this
    /// path. The daemon reads `aip_observe::clock::clock_discipline()` and
    /// passes the result in.
    fn health_with_clock(
        &self,
        emitted_at_ms: u64,
        clock: Option<AttestedClock>,
    ) -> Result<SignedSensorHealth, AttestError>;
}

/// Why the collector marked the probe stream degraded. Recorded for the
/// operator; the signed health carries the resulting state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeStreamFault {
    /// The probe reported `n` events lost since its previous batch.
    EventsLost { n: u64 },
    /// Within one probe run, the sequence range did not continue from the
    /// previous batch (skipped, repeated, or moved backwards).
    SequenceDiscontinuity { expected_first: u64, got_first: u64 },
}

/// The off-host collector: holds the observer signing key, the continuity
/// ledger and the probe registry, and is the only thing in this crate that
/// can produce a signature.
pub struct CollectorSigner {
    observer_id: String,
    key_version: u32,
    /// The key, held by a custodian rather than as bytes on this struct.
    /// There is no accessor: this type signs and does not surrender
    /// (Phase A). `new` wraps caller-supplied bytes in a development
    /// custodian so existing provisioning keeps working;
    /// `with_custodian` is the production path, where the key is never in
    /// the caller's hands at all.
    custodian: Box<dyn aip_crypto::custody::Custodian>,
    public_key: Vec<u8>,
    ledger: ObserverLedger,
    /// Coverage the collector is willing to vouch for. `None` whenever
    /// continuity is not verified — coverage is never asserted across a gap.
    attested_coverage: Option<CoverageWindow>,
    recovering: bool,
    last_batch_id: Option<[u8; 16]>,
    // Stage 6.5
    probe_policy: ProbePolicy,
    registry: HashMap<String, HashSet<SourceMechanism>>,
    last_probe_run: Option<[u8; 16]>,
    last_probe_seq_last: Option<u64>,
    probe_faults: Vec<ProbeStreamFault>,
    /// Intersection of `active_mechanisms` over the batches that make up the
    /// current coverage epoch. `None` whenever there is no coverage.
    covered_by: Option<Vec<SourceMechanism>>,
    /// The collector's most recent integrity finding **per sampled
    /// mechanism** (the tracepoint-gate check). Keyed by mechanism so a clean
    /// reading for one perf tracepoint can never overwrite a gated reading for
    /// another: a collector that samples `sched`, `sock:inet_sock_set_state`
    /// and `sock:sock_send_length` reports each independently, and the signed
    /// state is the worst across all of them. Empty until the first check; an
    /// empty map is treated as capable, exactly as the previous single-value
    /// `Verified` default was — the coverage predicate, not this signal, is
    /// what protects a non-occurrence claim (a collector that never checks
    /// still cannot manufacture gate-independent coverage). Self-healing: a
    /// mechanism whose slot returns to `Verified` on a later cycle restores
    /// `Active`.
    mechanism_integrity: HashMap<SourceMechanism, MechanismIntegrity>,
}

impl std::fmt::Debug for CollectorSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CollectorSigner")
            .field("observer_id", &self.observer_id)
            .field("key_version", &self.key_version)
            .field("public_key", &self.public_key)
            // Both: the backend, so an operator can see what holds the
            // key, and an explicit marker, so a reader can see that
            // something was withheld rather than that nothing was there.
            .field("custody", &self.custodian.backend())
            .field("private_key", &"<redacted>")
            .field("sequence", &self.ledger.last_sequence())
            .field("continuity", &self.ledger.status())
            .field("attested_coverage", &self.attested_coverage)
            .field("probe_policy", &self.probe_policy)
            .field(
                "registered_probes",
                &self.registry.keys().collect::<Vec<_>>(),
            )
            .field("probe_faults", &self.probe_faults.len())
            .finish()
    }
}

impl CollectorSigner {
    /// Build a signer whose key is held by a custodian, so the private key
    /// never passes through the caller's hands at all.
    ///
    /// This is the production path. With
    /// [`CollectorKey::production`](crate::custody::CollectorKey::production)
    /// the key is generated, wrapped and opened by the custodian, and there
    /// is nothing for a caller to log, serialize or leak.
    pub fn with_custodian(
        observer_id: impl Into<String>,
        key_version: u32,
        custodian: Box<dyn aip_crypto::custody::Custodian>,
    ) -> Result<Self, AttestError> {
        let public_key = custodian.public_key().to_vec();
        if public_key.len() != 32 {
            return Err(AttestError::InvalidKeyLength(public_key.len()));
        }
        // Built through `new` so there is one construction path and one set
        // of invariants. The placeholder key it is handed is replaced by the
        // real custodian before anything is signed.
        let mut s = Self::new(observer_id, key_version, &[0u8; 32], &public_key)?;
        s.custodian = custodian;
        Ok(s)
    }

    pub fn new(
        observer_id: impl Into<String>,
        key_version: u32,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Self, AttestError> {
        let observer_id = observer_id.into();
        if observer_id.is_empty() {
            return Err(AttestError::EmptyObserverId);
        }
        if private_key.len() != 32 {
            return Err(AttestError::InvalidKeyLength(private_key.len()));
        }
        if public_key.len() != 32 {
            return Err(AttestError::InvalidKeyLength(public_key.len()));
        }
        Ok(Self {
            observer_id,
            key_version,
            custodian: Box::new(
                aip_crypto::custody::InMemoryCustodian::new(private_key, public_key)
                    .map_err(|_| AttestError::InvalidKeyLength(private_key.len()))?,
            ),
            public_key: public_key.to_vec(),
            ledger: ObserverLedger::new(),
            attested_coverage: None,
            recovering: false,
            last_batch_id: None,
            probe_policy: ProbePolicy::Open,
            registry: HashMap::new(),
            last_probe_run: None,
            last_probe_seq_last: None,
            probe_faults: Vec::new(),
            covered_by: None,
            mechanism_integrity: HashMap::new(),
        })
    }

    /// Record the result of a mechanism-integrity check for one sampled
    /// `mechanism` (on Linux, an enumeration of the eBPF programs gating that
    /// tracepoint — see [`ProcessTracer::mechanism_integrity`],
    /// [`SockStateTracer::mechanism_integrity`],
    /// [`SockSendTracer::mechanism_integrity`]).
    ///
    /// A non-capable finding for **any** sampled mechanism
    /// ([`MechanismIntegrity::ForeignTracepointGate`] or
    /// [`MechanismIntegrity::Unverifiable`]) makes the next signed health
    /// report [`ObserverState::IntegrityUnknown`]: the observer cannot vouch
    /// that it remained capable of seeing that event class, so absence over
    /// the window carries no information. Keyed per mechanism so a clean
    /// reading for one sensor does not mask a gated reading for another — the
    /// defect a single global slot had. Self-healing: re-reporting the same
    /// mechanism as [`MechanismIntegrity::Verified`] on a later cycle clears
    /// its slot, and `Active` returns once every reported mechanism is capable
    /// again, exactly as a cleared loss count does.
    pub fn note_mechanism_integrity(
        &mut self,
        mechanism: SourceMechanism,
        integrity: MechanismIntegrity,
    ) {
        // End the coverage epoch immediately. Merely hiding it in health()
        // would let a later Verified report resurrect coverage across the
        // blinded window, including if no new batch had arrived yet.
        if !integrity.is_capable() {
            self.attested_coverage = None;
            self.covered_by = None;
        }
        self.mechanism_integrity.insert(mechanism, integrity);
    }

    pub fn observer_id(&self) -> &str {
        &self.observer_id
    }

    pub fn key_version(&self) -> u32 {
        self.key_version
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn ledger(&self) -> &ObserverLedger {
        &self.ledger
    }

    pub fn probe_policy(&self) -> ProbePolicy {
        self.probe_policy
    }

    /// Faults the collector observed in the probe stream so far.
    pub fn probe_faults(&self) -> &[ProbeStreamFault] {
        &self.probe_faults
    }

    /// Switch to `RegisteredOnly` with no probes registered: every batch is
    /// refused until an operator registers something. Explicit and loud.
    pub fn require_registered_probes(&mut self) {
        self.probe_policy = ProbePolicy::RegisteredOnly;
    }

    /// Provision a probe and the mechanisms it may claim. Registering any
    /// probe switches the collector to `RegisteredOnly`. This is operator
    /// configuration held at the collector; the host cannot alter it.
    pub fn register_probe(&mut self, probe_id: &str, mechanisms: &[SourceMechanism]) {
        self.probe_policy = ProbePolicy::RegisteredOnly;
        self.registry
            .insert(probe_id.to_string(), mechanisms.iter().copied().collect());
    }

    /// Record that the probe restarted. Continuity is not re-established by a
    /// restart; the observer enters `Recovering` until a contiguous batch is
    /// admitted.
    pub fn note_probe_restart(&mut self) {
        self.recovering = true;
        self.attested_coverage = None;
        self.covered_by = None;
        self.ledger.note_restart();
    }

    /// Everything the collector must carry across a process restart to
    /// continue its own chain: its id, key version, last sequence and head,
    /// and whether it was quarantined. Persist it after each attestation;
    /// hand it to [`CollectorSigner::resume`] on the way up together with
    /// the archive of health records this collector emitted.
    pub fn snapshot(&self) -> CollectorSnapshot {
        CollectorSnapshot {
            observer_id: self.observer_id.clone(),
            key_version: self.key_version,
            sequence: self.ledger.last_sequence(),
            head: self.ledger.last_head(),
            quarantined: self.ledger.is_quarantined(),
        }
    }

    /// Sign arbitrary bytes as this collector, through its custodian. Used by
    /// the runtime to sign a continuity report at start under wrapped custody,
    /// so the raw key is never needed. The key is never exposed.
    pub(crate) fn sign_bytes(&self, payload: &[u8]) -> Result<Signature, AttestError> {
        self.custodian
            .sign(&self.observer_id, payload)
            .map_err(|e| AttestError::Custody(e.to_string()))
    }

    /// Resume from a snapshot, auditing it against the archive of this
    /// collector's own signed health records (harvested design: PR #3
    /// `ot-sentinel` restart continuity, `6cc439f`).
    ///
    /// - the snapshot must belong to `observer_id` (`ForeignState` otherwise);
    /// - archive records are verified under `public_key` at the snapshot's
    ///   key version and filtered to this observer; forged or foreign
    ///   records are ignored, never counted;
    /// - `Amnesia` and `RolledBack` adopt the archive head so that the
    ///   collector continues one chain rather than starting a second under
    ///   the same key; `Forked` quarantines; `ArchiveTruncated` keeps the
    ///   state;
    /// - a resumed collector is `Recovering` with `Unverified` continuity and
    ///   no coverage until a contiguous batch is admitted — a restart never
    ///   implies continuity, even a clean one.
    pub fn resume(
        snapshot: &CollectorSnapshot,
        observer_id: &str,
        private_key: &[u8],
        public_key: &[u8],
        archive: &[SignedSensorHealth],
    ) -> Result<(Self, Option<ContinuityBreak>), AttestError> {
        // Delegate to the custody-aware path so there is exactly one
        // continuity implementation. An in-memory custodian is the development
        // key holder; a production collector resumes through
        // `resume_with_custodian` with a wrapped-file or hardware custodian.
        let custodian = Box::new(
            aip_crypto::custody::InMemoryCustodian::new(private_key, public_key)
                .map_err(|_| AttestError::InvalidKeyLength(private_key.len()))?,
        );
        Self::resume_with_custodian(snapshot, observer_id, custodian, archive)
    }

    /// Resume a collector whose key is held by a [`Custodian`](aip_crypto::custody::Custodian)
    /// — the production path, where the signing key is wrapped at rest and
    /// never exists as raw bytes in the process's configuration. Identical
    /// continuity semantics to [`resume`](Self::resume); only the key holder
    /// differs.
    pub fn resume_with_custodian(
        snapshot: &CollectorSnapshot,
        observer_id: &str,
        custodian: Box<dyn aip_crypto::custody::Custodian>,
        archive: &[SignedSensorHealth],
    ) -> Result<(Self, Option<ContinuityBreak>), AttestError> {
        if snapshot.observer_id != observer_id {
            return Err(AttestError::ForeignState {
                expected: observer_id.to_string(),
                got: snapshot.observer_id.clone(),
            });
        }
        let public_key = custodian.public_key().to_vec();
        let mut s = Self::with_custodian(observer_id, snapshot.key_version, custodian)?;
        let public_key = public_key.as_slice();
        let brk = verify_continuity(snapshot, archive, public_key);
        let archived = archive_head(snapshot, archive, public_key);
        match &brk {
            None | Some(ContinuityBreak::ArchiveTruncated { .. }) => {
                s.ledger.resume_at(snapshot.sequence, snapshot.head);
            }
            Some(ContinuityBreak::Amnesia { .. }) | Some(ContinuityBreak::RolledBack { .. }) => {
                let (seq, head) =
                    archived.expect("a break against the archive implies an archive head");
                s.ledger.resume_at(Some(seq), Some(head));
            }
            Some(ContinuityBreak::Forked { .. }) => {
                s.ledger.resume_at(snapshot.sequence, snapshot.head);
                s.ledger.quarantine();
            }
        }
        if snapshot.quarantined {
            s.ledger.quarantine();
        }
        if snapshot.sequence.is_some() || archived.is_some() {
            s.recovering = true;
        }
        Ok((s, brk))
    }

    /// What is holding this collector's key. Reported so a deployment can
    /// assert it is not running a development backend in production, and so
    /// an operator can see it without guessing.
    pub fn custody_backend(&self) -> aip_crypto::custody::Backend {
        self.custodian.backend()
    }

    /// Rotate to a new key version. History signed under the old version
    /// stays verifiable while the verifier keeps that anchor.
    pub fn rotate_key(
        &mut self,
        new_version: u32,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<(), AttestError> {
        if private_key.len() != 32 || public_key.len() != 32 {
            return Err(AttestError::InvalidKeyLength(private_key.len()));
        }
        self.key_version = new_version;
        self.custodian = Box::new(
            aip_crypto::custody::InMemoryCustodian::new(private_key, public_key)
                .map_err(|_| AttestError::InvalidKeyLength(private_key.len()))?,
        );
        self.public_key = public_key.to_vec();
        Ok(())
    }

    /// The observer's current state, derived from ledger status, the restart
    /// flag and probe-stream faults. Never optimistic: a recorded loss or
    /// discontinuity degrades the stream for the rest of this ledger epoch,
    /// exactly as a recorded chain gap does.
    pub fn state(&self) -> ObserverState {
        if self.ledger.is_quarantined() {
            return ObserverState::Quarantined;
        }
        // Quarantine (a proven integrity failure) outranks everything. Below
        // it, a foreign tracepoint gate outranks the loss/continuity ladder:
        // it can suppress events with neither a dropped-record count nor a
        // chain break, so an otherwise-clean stream must not mask it. The
        // signed `continuity` field still carries any concurrent gap, so
        // reporting `IntegrityUnknown` here loses nothing a verifier needs.
        if matches!(self.ledger.status(), ContinuityStatus::Broken) {
            return ObserverState::Quarantined;
        }
        // Worst-of across every sampled mechanism: one gated or unverifiable
        // perf tracepoint blinds the observer for that event class, and the
        // signed state must say so even if the other mechanisms are clean.
        if self
            .mechanism_integrity
            .values()
            .any(|integrity| !integrity.is_capable())
        {
            return ObserverState::IntegrityUnknown;
        }
        match self.ledger.status() {
            ContinuityStatus::Broken => ObserverState::Quarantined,
            // A recorded chain gap or probe-stream fault (loss, sequence
            // discontinuity) is reported as Degraded whatever the link
            // status; the signed health carries `continuity` separately, so
            // "degraded AND unverified" loses nothing.
            ContinuityStatus::GapObserved => ObserverState::Degraded,
            _ if !self.probe_faults.is_empty() => ObserverState::Degraded,
            ContinuityStatus::Unverified => {
                if self.recovering {
                    ObserverState::Recovering
                } else {
                    ObserverState::ContinuityUnverified
                }
            }
            ContinuityStatus::Verified => ObserverState::Active,
        }
    }

    fn check_registry(&self, batch: &ObservationBatch) -> Result<(), AttestError> {
        if self.probe_policy == ProbePolicy::Open {
            return Ok(());
        }
        let permitted = self
            .registry
            .get(&batch.probe_id)
            .ok_or_else(|| AttestError::UnregisteredProbe(batch.probe_id.clone()))?;
        for m in batch
            .mechanisms()
            .chain(batch.mechanism_integrity.iter().map(|r| r.mechanism))
        {
            if !permitted.contains(&m) {
                return Err(AttestError::MechanismNotProvisioned {
                    probe_id: batch.probe_id.clone(),
                    mechanism: m,
                });
            }
        }
        Ok(())
    }

    /// Absorb the probe's per-mechanism integrity reports carried in the
    /// batch (`ObservationBatch::mechanism_integrity`). The reports are probe
    /// claims and can only lower the signed state: every non-capable finding
    /// is noted as reported (fail closed), while a `Verified` finding is noted
    /// only for a mechanism the same batch declares active — a probe cannot
    /// clear a slot for a sensor it is not running. This is how the two-host
    /// deployment, where the sensors and the signing key are on different
    /// machines, reaches [`ObserverState::IntegrityUnknown`].
    fn absorb_mechanism_reports(&mut self, batch: &ObservationBatch) {
        for r in &batch.mechanism_integrity {
            if !r.integrity.is_capable() || batch.active_mechanisms.contains(&r.mechanism) {
                self.note_mechanism_integrity(r.mechanism, r.integrity);
            }
        }
    }

    /// Compare the batch's probe-stream fields with what this collector saw
    /// last. A changed run id is a restart; a non-continuing sequence range
    /// or a positive loss count is a fault.
    fn track_probe_stream(&mut self, batch: &ObservationBatch) {
        let restarted = matches!(self.last_probe_run, Some(prev) if prev != batch.probe_run_id);
        if restarted {
            self.note_probe_restart();
            self.last_probe_seq_last = None;
        }
        if let Some(n) = batch.dropped_events {
            if n > 0 {
                self.probe_faults.push(ProbeStreamFault::EventsLost { n });
            }
        }
        if let Some(prev_last) = self.last_probe_seq_last {
            let expected_first = prev_last + 1;
            let has_content = !batch.observations.is_empty() || !batch.kernel_events.is_empty();
            if has_content && batch.probe_seq_first != expected_first {
                self.probe_faults
                    .push(ProbeStreamFault::SequenceDiscontinuity {
                        expected_first,
                        got_first: batch.probe_seq_first,
                    });
            }
        }
        self.last_probe_run = Some(batch.probe_run_id);
        if !batch.observations.is_empty() || !batch.kernel_events.is_empty() {
            self.last_probe_seq_last = Some(batch.probe_seq_last);
        }
    }
}

/// The collector's clock. Off-host by deployment assumption; this is the one
/// place the observer side reads a wall clock, and it is stamped into signed
/// bytes rather than trusted implicitly.
pub(crate) fn collector_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl ObserverAttestor for CollectorSigner {
    fn attest_at(
        &mut self,
        batch: ObservationBatch,
        attested_at_ms: u64,
    ) -> Result<AttestedBatch, AttestError> {
        if batch.version != OBSERVE_PROTOCOL_VERSION {
            return Err(AttestError::UnsupportedVersion(batch.version));
        }
        if self.ledger.is_quarantined() {
            return Err(AttestError::Quarantined);
        }
        if batch.probe_seq_first > batch.probe_seq_last {
            return Err(AttestError::MalformedBatch(
                "probe_seq_first > probe_seq_last",
            ));
        }
        self.check_registry(&batch)?;
        self.absorb_mechanism_reports(&batch);
        let faults_before = self.probe_faults.len();
        self.track_probe_stream(&batch);
        let faulted_now = self.probe_faults.len() > faults_before;

        let sequence = self.ledger.next_sequence();
        let prev_head = self.ledger.expected_prev_head();
        let head = sha256(&preimage(
            OBSERVE_PROTOCOL_VERSION,
            &self.observer_id,
            self.key_version,
            sequence,
            &prev_head,
            attested_at_ms,
            &batch,
        ));

        let admission = self
            .ledger
            .admit(sequence, prev_head, head)
            .map_err(AttestError::Continuity)?;

        // Coverage is only extended across a verified, contiguous link with a
        // clean probe stream, and only up to what the probe claimed. It is
        // never widened by silence, loss, a restart, or unknown integrity.
        let integrity_unknown = self
            .mechanism_integrity
            .values()
            .any(|integrity| !integrity.is_capable());
        match admission {
            _ if integrity_unknown || faulted_now || !self.probe_faults.is_empty() => {
                self.attested_coverage = None;
                self.covered_by = None;
            }
            Admission::Continuous if !self.recovering => {
                self.attested_coverage = Some(match self.attested_coverage {
                    Some(w) => CoverageWindow {
                        from_ms: w.from_ms,
                        to_ms: batch.claimed_to_ms.max(w.to_ms),
                    },
                    None => CoverageWindow {
                        from_ms: batch.claimed_from_ms,
                        to_ms: batch.claimed_to_ms,
                    },
                });
                // Coverage by a mechanism holds only if it was live in every
                // batch of the epoch: intersect, never union.
                self.covered_by = Some(match self.covered_by.take() {
                    Some(prev) => prev
                        .into_iter()
                        .filter(|m| batch.active_mechanisms.contains(m))
                        .collect(),
                    None => batch.active_mechanisms.clone(),
                });
            }
            Admission::Continuous => {
                // First contiguous batch after a restart re-establishes a
                // fresh coverage epoch; it does not back-fill the gap.
                self.recovering = false;
                self.attested_coverage = Some(CoverageWindow {
                    from_ms: batch.claimed_from_ms,
                    to_ms: batch.claimed_to_ms,
                });
                self.covered_by = Some(batch.active_mechanisms.clone());
            }
            Admission::AdmittedWithGap { .. } | Admission::NewEpochUnverified => {
                self.attested_coverage = None;
                self.covered_by = None;
            }
        }

        self.last_batch_id = Some(batch.batch_id);

        let attested = AttestedBatch {
            version: OBSERVE_PROTOCOL_VERSION,
            observer_id: self.observer_id.clone(),
            key_version: self.key_version,
            sequence,
            prev_head,
            attested_at_ms,
            batch,
            attestation: placeholder_signature(&self.observer_id),
        };
        let sig = self
            .custodian
            .sign(&self.observer_id, &attested.signing_preimage())
            .map_err(|e| AttestError::Custody(e.to_string()))?;
        Ok(AttestedBatch {
            attestation: sig,
            ..attested
        })
    }

    fn health_with_clock(
        &self,
        emitted_at_ms: u64,
        clock: Option<AttestedClock>,
    ) -> Result<SignedSensorHealth, AttestError> {
        let state = self.state();
        let health = SensorHealth {
            version: OBSERVE_PROTOCOL_VERSION,
            observer_id: self.observer_id.clone(),
            key_version: self.key_version,
            state,
            continuity: self.ledger.status(),
            probe_policy: self.probe_policy,
            sequence: self.ledger.last_sequence().unwrap_or(0),
            head: self.ledger.last_head().unwrap_or([0u8; 32]),
            last_batch_id: self.last_batch_id,
            // Coverage is only reported when the observer is Active.
            attested_coverage: if state.permits_attested_use() {
                self.attested_coverage
            } else {
                None
            },
            covered_by: if state.permits_attested_use() {
                SourceMechanism::canonical_set(self.covered_by.clone().unwrap_or_default())
            } else {
                Vec::new()
            },
            emitted_at_ms,
            clock,
        };
        let attestation = self
            .custodian
            .sign(&self.observer_id, &health.canonical_bytes())
            .map_err(|e| AttestError::Custody(e.to_string()))?;
        Ok(SignedSensorHealth {
            health,
            attestation,
        })
    }
}

fn placeholder_signature(signer_id: &str) -> Signature {
    Signature {
        algorithm: aip_types::AlgorithmId::Ed25519,
        signer_id: signer_id.to_string(),
        timestamp: 0,
        nonce: [0u8; 16],
        payload_hash: [0u8; 32],
        signature_bytes: vec![],
    }
}

/// The collector's chain position, carried across a restart. Serializable so
/// an operator can persist it; it proves nothing on its own — resume audits
/// it against the archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectorSnapshot {
    pub observer_id: String,
    pub key_version: u32,
    pub sequence: Option<u64>,
    pub head: Option<[u8; 32]>,
    pub quarantined: bool,
}

impl CollectorSnapshot {
    /// No state at all: a first deployment, or a collector that lost its
    /// state.
    pub fn fresh(observer_id: &str, key_version: u32) -> Self {
        Self {
            observer_id: observer_id.to_string(),
            key_version,
            sequence: None,
            head: None,
            quarantined: false,
        }
    }
}

/// The highest-sequence health record in `archive` that is this observer's
/// and verifies under `public_key` at the snapshot's key version.
pub(crate) fn archive_head(
    snapshot: &CollectorSnapshot,
    archive: &[SignedSensorHealth],
    public_key: &[u8],
) -> Option<(u64, [u8; 32])> {
    let anchors =
        ObserverTrustAnchors::new().trust(&snapshot.observer_id, snapshot.key_version, public_key);
    archive
        .iter()
        .filter(|h| h.health.observer_id == snapshot.observer_id)
        .filter(|h| verify_signed_health(h, &anchors).is_ok())
        .filter(|h| h.health.sequence > 0)
        .map(|h| (h.health.sequence, h.health.head))
        .max_by_key(|(s, _)| *s)
}

/// Classify a resumed snapshot against the archive of the collector's own
/// signed health records. `None` when the two agree (or both are empty).
pub fn verify_continuity(
    snapshot: &CollectorSnapshot,
    archive: &[SignedSensorHealth],
    public_key: &[u8],
) -> Option<ContinuityBreak> {
    let archived = archive_head(snapshot, archive, public_key);
    match (snapshot.sequence, snapshot.head, archived) {
        (None, _, None) => None,
        (None, _, Some((archived_sequence, archived_head))) => Some(ContinuityBreak::Amnesia {
            archived_sequence,
            archived_head,
        }),
        (Some(resumed_sequence), _, None) => Some(ContinuityBreak::ArchiveTruncated {
            resumed_sequence,
            archived_sequence: 0,
        }),
        (Some(resumed_sequence), head, Some((archived_sequence, archived_head))) => {
            match resumed_sequence.cmp(&archived_sequence) {
                std::cmp::Ordering::Less => Some(ContinuityBreak::RolledBack {
                    resumed_sequence,
                    archived_sequence,
                }),
                std::cmp::Ordering::Greater => Some(ContinuityBreak::ArchiveTruncated {
                    resumed_sequence,
                    archived_sequence,
                }),
                std::cmp::Ordering::Equal => match head {
                    Some(resumed_head) if resumed_head != archived_head => {
                        Some(ContinuityBreak::Forked {
                            sequence: resumed_sequence,
                            resumed_head,
                            archived_head,
                        })
                    }
                    Some(_) => None,
                    None => Some(ContinuityBreak::Forked {
                        sequence: resumed_sequence,
                        resumed_head: [0u8; 32],
                        archived_head,
                    }),
                },
            }
        }
    }
}

