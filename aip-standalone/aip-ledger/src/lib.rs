//! `aip-ledger` — the per-agent, per-window **access ledger** (R3 of
//! `docs/pilot/RBI_REQUIREMENTS_COVERAGE.md`).
//!
//! The artefact an RBI-supervised entity is asked for at review time, in the
//! shape the FREE-AI inventory, a CERT-In incident report and a fraud-liability
//! dispute all need: *for agent X over window W, every network resource it
//! reached, named as the institution names it, with the reconciler's verdict
//! on each — signed, and verifiable offline by someone who trusts none of the
//! parties involved.*
//!
//! # What a ledger is built from, and only from
//!
//! - **Attested observation batches**, verified under the verifier's observer
//!   anchors before a single byte is read. Socket effects and connect
//!   initiations attributed (by claim) to the agent, inside the window.
//! - **The institution's signed resource registry**, verified under the
//!   institution's anchor. Every endpoint resolves to exactly one named
//!   resource or to `Unregistered` — an answer, never an inference. The
//!   ledger cites the registry revision it resolved against, so a later
//!   registry edit cannot re-label past evidence.
//! - **Signed reconciliation verdicts**, verified under the verifier's
//!   reconciler anchors, cited to the entry they concern through the
//!   observation or kernel event the verdict itself references
//!   (`EvidenceRef::Observation` / `KernelEvent`). Results and strengths are
//!   carried **verbatim**; the ledger restates nothing and raises nothing.
//!   A verdict that references no row this ledger holds is counted, never
//!   dropped.
//!
//! # What a ledger is not
//!
//! It is not a verdict. Its `standing` per entry is a *summary of cited
//! verdicts* (adverse / verified / unproven / none), computed by a fixed rule
//! stated on [`Standing`], and it can never be stronger than the verdicts it
//! cites. An entry with no verdict says `NoVerdict`, which is what an
//! observed connection nobody reconciled is. The ledger holds no key of the
//! observer's or the reconciler's; it is signed by its own signer, a fifth
//! authority, so that its composition is attributable.
//!
//! Time: an observation's time is the host wall clock at measurement
//! (contextual, attacker-controllable under the threat model); a kernel
//! event's time is its kernel stamp placed on the wall clock through the
//! batch's clock anchor, or the collector's attestation time when the batch
//! has no anchor. Both are bounded above by the collector's signed
//! `attested_at_ms`. The ledger records which it used.

use std::collections::BTreeMap;

use aip_crypto::{sha256, sign_ed25519, verify_ed25519};
use aip_observe::{
    tcp_state, verify_attested_batch, AgentAttribution, AttestedBatch, KernelLifecycleKind,
    ObservedEffect, ObserverTrustAnchors, SocketEndpoint, SocketProtocol,
};
use aip_reconcile::{EvidenceRef, ReconcilerTrustAnchors, SignedReconciliation};
use aip_registry::{
    ObservedProtocol, RegistryError, RegistryTrustAnchors, Resolution, ResourceRegistry,
};
use aip_types::canonical::*;
use aip_types::{CoverageWindow, Signature};
use serde::{Deserialize, Serialize};

/// Domain tag leading the canonical encoding of an [`AccessLedger`].
pub const ACCESS_LEDGER_DOMAIN: &str = "GHOST/AccessLedger/v1";
/// Wire version of [`AccessLedger`].
pub const ACCESS_LEDGER_VERSION: u16 = 1;

// ─── Vocabulary ───

/// One remote endpoint as observed: transport protocol and remote address
/// and port. The ledger's row key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EndpointRef {
    /// IANA transport number: [`PROTO_TCP`] or [`PROTO_UDP`].
    pub protocol: u8,
    pub is_v6: bool,
    pub addr: [u8; 16],
    pub port: u16,
}

/// IANA transport protocol numbers, the ledger's protocol vocabulary.
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

impl EndpointRef {
    /// The observer distinguishes families (`Tcp`/`Tcp6`); the ledger keys on
    /// transport and carries the family in `is_v6` from the endpoint itself.
    fn from_socket(protocol: SocketProtocol, remote: &SocketEndpoint) -> Self {
        let transport = match protocol {
            SocketProtocol::Tcp | SocketProtocol::Tcp6 => PROTO_TCP,
            SocketProtocol::Udp | SocketProtocol::Udp6 => PROTO_UDP,
        };
        EndpointRef {
            protocol: transport,
            is_v6: remote.is_v6,
            addr: remote.addr,
            port: remote.port,
        }
    }

    fn observed_protocol(&self) -> ObservedProtocol {
        if self.protocol == PROTO_UDP {
            ObservedProtocol::Udp
        } else {
            ObservedProtocol::Tcp
        }
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        put_u8(buf, self.protocol);
        put_u8(buf, u8::from(self.is_v6));
        buf.extend_from_slice(&self.addr);
        put_u16(buf, self.port);
    }
}

/// How the institution names the endpoint, at the cited registry revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceRef {
    Named {
        id: String,
        /// `Criticality::code()`.
        criticality: u8,
    },
    /// The institution did not name this endpoint. Recorded, never guessed.
    Unregistered,
}

impl ResourceRef {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            ResourceRef::Named { id, criticality } => {
                put_u8(buf, 0x01);
                put_str(buf, id);
                put_u8(buf, *criticality);
            }
            ResourceRef::Unregistered => put_u8(buf, 0x02),
        }
    }
}

/// How a row's time was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeBasis {
    /// Host wall clock at measurement (a probe claim).
    HostWallClock,
    /// Kernel stamp placed on the wall clock through the batch's anchor.
    KernelStampAnchored,
    /// No anchor: the collector's signed attestation time (an upper bound).
    CollectorAttestation,
}

impl TimeBasis {
    fn code(&self) -> u8 {
        match self {
            TimeBasis::HostWallClock => 0x01,
            TimeBasis::KernelStampAnchored => 0x02,
            TimeBasis::CollectorAttestation => 0x03,
        }
    }
}

/// A verified reconciler verdict cited to a row. Result, strength and reason
/// are the reconciler's codes, verbatim.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VerdictCitation {
    pub decision_id: Option<[u8; 16]>,
    pub result: u8,
    pub strength: u8,
    pub reason: u8,
    pub reconciler_id: String,
    pub key_version: u32,
}

impl VerdictCitation {
    fn encode(&self, buf: &mut Vec<u8>) {
        match &self.decision_id {
            Some(d) => {
                put_u8(buf, 1);
                buf.extend_from_slice(d);
            }
            None => put_u8(buf, 0),
        }
        put_u8(buf, self.result);
        put_u8(buf, self.strength);
        put_u8(buf, self.reason);
        put_str(buf, &self.reconciler_id);
        put_u32(buf, self.key_version);
    }
}

/// A fixed summary of a row's cited verdicts. Never stronger than they are.
///
/// Rule: any cited result in {UNATTRIBUTED_EFFECT, PHANTOM_CLAIM,
/// IDENTITY_DIVERGENCE, LINEAGE_VIOLATION} → `Adverse`; else any
/// VERIFIED_EXECUTION → `Verified`; else any citation → `Unproven`; else
/// `NoVerdict`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Standing {
    Verified,
    Adverse,
    Unproven,
    NoVerdict,
}

impl Standing {
    fn code(&self) -> u8 {
        match self {
            Standing::Verified => 0x01,
            Standing::Adverse => 0x02,
            Standing::Unproven => 0x03,
            Standing::NoVerdict => 0x04,
        }
    }

    fn of(citations: &[VerdictCitation]) -> Self {
        const VERIFIED: u8 = 0x01;
        const ADVERSE: [u8; 4] = [0x02, 0x03, 0x04, 0x05];
        if citations.is_empty() {
            return Standing::NoVerdict;
        }
        if citations.iter().any(|c| ADVERSE.contains(&c.result)) {
            return Standing::Adverse;
        }
        if citations.iter().any(|c| c.result == VERIFIED) {
            return Standing::Verified;
        }
        Standing::Unproven
    }
}

/// One row: an endpoint the agent reached, as the institution names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessEntry {
    pub endpoint: EndpointRef,
    pub resource: ResourceRef,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub time_basis: TimeBasis,
    /// Observations and connect initiations folded into this row.
    pub occurrences: u32,
    /// Sorted, deduplicated.
    pub verdicts: Vec<VerdictCitation>,
    pub standing: Standing,
}

impl AccessEntry {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.endpoint.encode(buf);
        self.resource.encode(buf);
        put_u64(buf, self.first_seen_ms);
        put_u64(buf, self.last_seen_ms);
        put_u8(buf, self.time_basis.code());
        put_u32(buf, self.occurrences);
        put_u32(buf, self.verdicts.len() as u32);
        for v in &self.verdicts {
            let mut inner = Vec::new();
            v.encode(&mut inner);
            put_bytes(buf, &inner);
        }
        put_u8(buf, self.standing.code());
    }
}

/// Which attested batch a ledger read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchCitation {
    pub observer_id: String,
    pub key_version: u32,
    pub sequence: u64,
    pub attested_at_ms: u64,
}

impl BatchCitation {
    fn encode(&self, buf: &mut Vec<u8>) {
        put_str(buf, &self.observer_id);
        put_u32(buf, self.key_version);
        put_u64(buf, self.sequence);
        put_u64(buf, self.attested_at_ms);
    }
}

/// The signed ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessLedger {
    pub version: u16,
    pub ledger_signer_id: String,
    pub key_version: u32,
    pub agent_id: String,
    pub window: CoverageWindow,
    pub registry_id: String,
    pub registry_revision: u64,
    /// Every batch read, in the order read.
    pub batches: Vec<BatchCitation>,
    /// Sorted by endpoint.
    pub entries: Vec<AccessEntry>,
    /// Observations and events examined, including those not attributed to
    /// the agent or outside the window. A reader can see how much was looked
    /// at, not only what was kept.
    pub considered: u32,
    /// Verified verdicts offered that named no endpoint this ledger holds.
    /// Recorded so a verdict cannot vanish silently.
    pub unmatched_verdicts: u32,
    pub issued_at_ms: u64,
    pub attestation: Signature,
}

/// Why a ledger could not be built or does not verify. Each is a refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    Registry(RegistryError),
    InvalidWindow,
    BatchInvalid(String),
    VerdictInvalid(String),
    SigningFailed(String),
    UnsupportedVersion(u16),
    UntrustedSigner { signer_id: String, key_version: u32 },
    SignerMismatch,
    PayloadHashMismatch,
    SignatureInvalid,
    EntriesNotCanonical,
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for LedgerError {}

impl From<RegistryError> for LedgerError {
    fn from(e: RegistryError) -> Self {
        LedgerError::Registry(e)
    }
}

// ─── Signer and anchors ───

/// The ledger's own signing authority. Distinct from the observer, the
/// decision point and the reconciler: a ledger's composition is attributable
/// to whoever assembled it, and to no one else.
pub struct LedgerSigner {
    signer_id: String,
    key_version: u32,
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl std::fmt::Debug for LedgerSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LedgerSigner")
            .field("signer_id", &self.signer_id)
            .field("key_version", &self.key_version)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

impl LedgerSigner {
    pub fn new(signer_id: &str, key_version: u32, private_key: &[u8], public_key: &[u8]) -> Self {
        Self {
            signer_id: signer_id.to_owned(),
            key_version,
            private_key: private_key.to_vec(),
            public_key: public_key.to_vec(),
        }
    }

    pub fn signer_id(&self) -> &str {
        &self.signer_id
    }

    pub fn key_version(&self) -> u32 {
        self.key_version
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

/// `(signer_id, key_version)` → public key. The verifier's own.
#[derive(Debug, Clone, Default)]
pub struct LedgerTrustAnchors {
    keys: BTreeMap<(String, u32), Vec<u8>>,
}

impl LedgerTrustAnchors {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn trust(mut self, signer_id: &str, key_version: u32, public_key: &[u8]) -> Self {
        self.keys
            .insert((signer_id.to_owned(), key_version), public_key.to_vec());
        self
    }

    pub fn get(&self, signer_id: &str, key_version: u32) -> Option<&[u8]> {
        self.keys
            .get(&(signer_id.to_owned(), key_version))
            .map(Vec::as_slice)
    }
}

// ─── Builder ───

#[derive(Debug)]
struct RowAcc {
    first_seen_ms: u64,
    last_seen_ms: u64,
    time_basis: TimeBasis,
    occurrences: u32,
    verdicts: Vec<VerdictCitation>,
}

/// Assembles a ledger from verified inputs. Every `observe` and `cite`
/// verifies its input before reading it; an input that does not verify is
/// refused and leaves the builder unchanged.
pub struct AccessLedgerBuilder<'r> {
    agent_id: String,
    window: CoverageWindow,
    registry: &'r ResourceRegistry,
    rows: BTreeMap<EndpointRef, RowAcc>,
    /// `(batch sequence, observation index)` → endpoint, for verdicts that
    /// cite an observation rather than a decision.
    observation_index: BTreeMap<(u64, u32), EndpointRef>,
    kernel_event_index: BTreeMap<(u64, u32), EndpointRef>,
    /// claimed decision id → endpoints observed under that claim, for
    /// verdicts that carry a decision id. The claim is the correlation key
    /// the observer signed as *claimed*; the ledger uses it to place a
    /// verdict, never to assert authority.
    decision_index: BTreeMap<[u8; 16], Vec<EndpointRef>>,
    batches: Vec<BatchCitation>,
    considered: u32,
    unmatched_verdicts: u32,
}

impl<'r> AccessLedgerBuilder<'r> {
    /// Start a ledger for `agent_id` over `window`, resolving against
    /// `registry`, which is verified here under `registry_anchors`.
    pub fn new(
        agent_id: &str,
        window: CoverageWindow,
        registry: &'r ResourceRegistry,
        registry_anchors: &RegistryTrustAnchors,
    ) -> Result<Self, LedgerError> {
        if !window.is_well_formed() {
            return Err(LedgerError::InvalidWindow);
        }
        registry.verify(registry_anchors)?;
        Ok(Self {
            agent_id: agent_id.to_owned(),
            window,
            registry,
            rows: BTreeMap::new(),
            observation_index: BTreeMap::new(),
            kernel_event_index: BTreeMap::new(),
            decision_index: BTreeMap::new(),
            batches: Vec::new(),
            considered: 0,
            unmatched_verdicts: 0,
        })
    }

    fn in_window(&self, t_ms: u64) -> bool {
        self.window.from_ms <= t_ms && t_ms <= self.window.to_ms
    }

    fn claimed_for_agent(&self, attribution: &AgentAttribution) -> bool {
        matches!(attribution, AgentAttribution::Claimed { agent_id, .. } if *agent_id == self.agent_id)
    }

    fn record(&mut self, key: EndpointRef, t_ms: u64, basis: TimeBasis) {
        let row = self.rows.entry(key).or_insert(RowAcc {
            first_seen_ms: t_ms,
            last_seen_ms: t_ms,
            time_basis: basis,
            occurrences: 0,
            verdicts: Vec::new(),
        });
        row.first_seen_ms = row.first_seen_ms.min(t_ms);
        row.last_seen_ms = row.last_seen_ms.max(t_ms);
        // The weaker basis wins the label: a row that mixes anchored and
        // unanchored times is described by its least precise member.
        if basis.code() > row.time_basis.code() {
            row.time_basis = basis;
        }
        row.occurrences += 1;
    }

    /// Read one attested batch. Verified under `anchors` first.
    pub fn observe(
        &mut self,
        batch: &AttestedBatch,
        anchors: &ObserverTrustAnchors,
    ) -> Result<(), LedgerError> {
        verify_attested_batch(batch, anchors)
            .map_err(|e| LedgerError::BatchInvalid(format!("{e:?}")))?;
        self.batches.push(BatchCitation {
            observer_id: batch.observer_id.clone(),
            key_version: batch.key_version,
            sequence: batch.sequence,
            attested_at_ms: batch.attested_at_ms,
        });

        // Socket effects the observer saw owned by a process claimed as ours.
        for (i, o) in batch.batch.observations.iter().enumerate() {
            self.considered += 1;
            let ObservedEffect::SocketObserved {
                protocol, remote, ..
            } = &o.effect
            else {
                continue;
            };
            let key = EndpointRef::from_socket(*protocol, remote);
            self.observation_index
                .insert((batch.sequence, i as u32), key);
            if !self.claimed_for_agent(&o.attribution) {
                continue;
            }
            if let Some(d) = o.claimed_decision_id {
                self.decision_index.entry(d).or_default().push(key);
            }
            // An observation's host clock cannot post-date the collector's
            // signed attestation; clamp so a lying host clock cannot place a
            // row after the batch that carries it.
            let t = o.host_wall_clock_ms.min(batch.attested_at_ms);
            if self.in_window(t) {
                self.record(key, t, TimeBasis::HostWallClock);
            }
        }

        // Connect initiations the kernel pushed, attributed to our agent.
        for (i, ev) in batch.batch.kernel_events.iter().enumerate() {
            self.considered += 1;
            let KernelLifecycleKind::SocketState {
                protocol,
                remote,
                old_state,
                new_state,
                ..
            } = &ev.kind
            else {
                continue;
            };
            if !(*old_state == tcp_state::CLOSE && *new_state == tcp_state::SYN_SENT) {
                continue;
            }
            let key = EndpointRef::from_socket(*protocol, remote);
            self.kernel_event_index
                .insert((batch.sequence, i as u32), key);
            if !self.claimed_for_agent(&ev.attribution) {
                continue;
            }
            if let Some(d) = ev.claimed_decision_id {
                self.decision_index.entry(d).or_default().push(key);
            }
            let (t, basis) = match &batch.batch.clock_anchor {
                Some(a) => {
                    // wall = realtime + (event − monotonic), in ms, saturating.
                    let delta_ns = ev.kernel_timestamp_ns as i128 - a.monotonic_ns as i128;
                    let wall = a.realtime_ms as i128 + delta_ns / 1_000_000;
                    (
                        wall.clamp(0, batch.attested_at_ms as i128) as u64,
                        TimeBasis::KernelStampAnchored,
                    )
                }
                None => (batch.attested_at_ms, TimeBasis::CollectorAttestation),
            };
            if self.in_window(t) {
                self.record(key, t, basis);
            }
        }
        Ok(())
    }

    /// Cite one signed verdict. Verified under `anchors` first. The verdict
    /// is attached to every row whose observation or kernel event it
    /// references, and to every row observed under a claim of the decision
    /// it reconciled. A verdict that names no row this ledger holds is
    /// counted in `unmatched_verdicts`, so it cannot vanish silently.
    pub fn cite(
        &mut self,
        signed: &SignedReconciliation,
        anchors: &ReconcilerTrustAnchors,
    ) -> Result<(), LedgerError> {
        signed
            .verify(anchors)
            .map_err(|e| LedgerError::VerdictInvalid(format!("{e:?}")))?;
        let rec = signed.reconciliation();
        let citation = VerdictCitation {
            decision_id: rec.decision_id.map(|d| *d.as_bytes()),
            result: rec.result.code(),
            strength: rec.strength.code(),
            reason: rec.reason.code(),
            reconciler_id: signed.reconciler_id.clone(),
            key_version: signed.key_version,
        };

        let mut targets: Vec<EndpointRef> = Vec::new();
        if let Some(d) = rec.decision_id {
            if let Some(keys) = self.decision_index.get(d.as_bytes()) {
                targets.extend(keys.iter().copied());
            }
        }
        for r in &rec.evidence {
            match r {
                EvidenceRef::Observation {
                    batch_sequence,
                    index,
                } => {
                    if let Some(k) = self.observation_index.get(&(batch_sequence.0, *index)) {
                        targets.push(*k);
                    }
                }
                EvidenceRef::KernelEvent {
                    batch_sequence,
                    index,
                } => {
                    if let Some(k) = self.kernel_event_index.get(&(batch_sequence.0, *index)) {
                        targets.push(*k);
                    }
                }
                _ => {}
            }
        }
        targets.sort();
        targets.dedup();

        let mut attached = false;
        for key in targets {
            if let Some(row) = self.rows.get_mut(&key) {
                if !row.verdicts.contains(&citation) {
                    row.verdicts.push(citation.clone());
                }
                attached = true;
            }
        }
        if !attached {
            self.unmatched_verdicts += 1;
        }
        Ok(())
    }

    /// Resolve, order, and sign.
    pub fn build_and_sign(
        self,
        signer: &LedgerSigner,
        issued_at_ms: u64,
    ) -> Result<AccessLedger, LedgerError> {
        let (registry_id, registry_revision) = self.registry.citation();
        let mut entries = Vec::with_capacity(self.rows.len());
        for (key, mut acc) in self.rows {
            let resource =
                match self
                    .registry
                    .resolve(key.observed_protocol(), key.is_v6, &key.addr, key.port)
                {
                    Resolution::Resource(e) => ResourceRef::Named {
                        id: e.id.clone(),
                        criticality: e.criticality.code(),
                    },
                    Resolution::Unregistered => ResourceRef::Unregistered,
                };
            acc.verdicts.sort();
            acc.verdicts.dedup();
            let standing = Standing::of(&acc.verdicts);
            entries.push(AccessEntry {
                endpoint: key,
                resource,
                first_seen_ms: acc.first_seen_ms,
                last_seen_ms: acc.last_seen_ms,
                time_basis: acc.time_basis,
                occurrences: acc.occurrences,
                verdicts: acc.verdicts,
                standing,
            });
        }
        let mut ledger = AccessLedger {
            version: ACCESS_LEDGER_VERSION,
            ledger_signer_id: signer.signer_id.clone(),
            key_version: signer.key_version,
            agent_id: self.agent_id,
            window: self.window,
            registry_id: registry_id.to_owned(),
            registry_revision,
            batches: self.batches,
            entries,
            considered: self.considered,
            unmatched_verdicts: self.unmatched_verdicts,
            issued_at_ms,
            attestation: placeholder_signature(&signer.signer_id),
        };
        ledger.attestation = sign_ed25519(
            &signer.private_key,
            &signer.signer_id,
            &ledger.signing_preimage(),
        )
        .map_err(|e| LedgerError::SigningFailed(e.to_string()))?;
        Ok(ledger)
    }
}

// ─── Encoding and verification ───

impl AccessLedger {
    /// The exact bytes hashed into `attestation.payload_hash`. Injective:
    /// every field fixed-width or length-prefixed; each entry and citation
    /// wrapped in its own length prefix.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, ACCESS_LEDGER_DOMAIN);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, &self.ledger_signer_id);
        put_u32(&mut buf, self.key_version);
        put_str(&mut buf, &self.agent_id);
        put_u64(&mut buf, self.window.from_ms);
        put_u64(&mut buf, self.window.to_ms);
        put_str(&mut buf, &self.registry_id);
        put_u64(&mut buf, self.registry_revision);
        put_u32(&mut buf, self.batches.len() as u32);
        for b in &self.batches {
            let mut inner = Vec::new();
            b.encode(&mut inner);
            put_bytes(&mut buf, &inner);
        }
        put_u32(&mut buf, self.entries.len() as u32);
        for e in &self.entries {
            let mut inner = Vec::new();
            e.encode(&mut inner);
            put_bytes(&mut buf, &inner);
        }
        put_u32(&mut buf, self.considered);
        put_u32(&mut buf, self.unmatched_verdicts);
        put_u64(&mut buf, self.issued_at_ms);
        buf
    }

    /// The bytes a commitment log holds: the preimage **plus** the
    /// attestation, so a committed ledger's signer is checkable offline.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = self.signing_preimage();
        put_opt_signature(&mut buf, &Some(self.attestation.clone()));
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }

    /// Verify under the verifier's ledger anchors: version, window shape,
    /// canonical ordering of entries, an anchored `(signer, key_version)`,
    /// a signature naming that signer, the payload hash over this struct's
    /// own preimage, and the Ed25519 signature — in that order.
    pub fn verify(&self, anchors: &LedgerTrustAnchors) -> Result<(), LedgerError> {
        if self.version != ACCESS_LEDGER_VERSION {
            return Err(LedgerError::UnsupportedVersion(self.version));
        }
        if !self.window.is_well_formed() {
            return Err(LedgerError::InvalidWindow);
        }
        if self
            .entries
            .windows(2)
            .any(|w| w[0].endpoint >= w[1].endpoint)
        {
            return Err(LedgerError::EntriesNotCanonical);
        }
        for e in &self.entries {
            if e.verdicts.windows(2).any(|w| w[0] >= w[1])
                || Standing::of(&e.verdicts) != e.standing
            {
                return Err(LedgerError::EntriesNotCanonical);
            }
        }
        let key = anchors
            .get(&self.ledger_signer_id, self.key_version)
            .ok_or_else(|| LedgerError::UntrustedSigner {
                signer_id: self.ledger_signer_id.clone(),
                key_version: self.key_version,
            })?;
        if self.attestation.signer_id != self.ledger_signer_id {
            return Err(LedgerError::SignerMismatch);
        }
        if self.attestation.payload_hash != sha256(&self.signing_preimage()) {
            return Err(LedgerError::PayloadHashMismatch);
        }
        match verify_ed25519(key, &self.attestation) {
            Ok(true) => Ok(()),
            _ => Err(LedgerError::SignatureInvalid),
        }
    }

    /// Rows whose standing is adverse: what an incident report opens with.
    pub fn adverse(&self) -> impl Iterator<Item = &AccessEntry> {
        self.entries
            .iter()
            .filter(|e| e.standing == Standing::Adverse)
    }

    /// Rows the institution never named.
    pub fn unregistered(&self) -> impl Iterator<Item = &AccessEntry> {
        self.entries
            .iter()
            .filter(|e| e.resource == ResourceRef::Unregistered)
    }
}

fn placeholder_signature(signer_id: &str) -> Signature {
    Signature {
        algorithm: aip_types::AlgorithmId::Ed25519,
        signer_id: signer_id.to_owned(),
        timestamp: 0,
        nonce: [0u8; 16],
        payload_hash: [0u8; 32],
        signature_bytes: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cite(result: u8) -> VerdictCitation {
        VerdictCitation {
            decision_id: None,
            result,
            strength: 3,
            reason: 0,
            reconciler_id: "r".into(),
            key_version: 1,
        }
    }

    #[test]
    fn standing_is_a_fixed_summary_never_stronger_than_its_citations() {
        assert_eq!(Standing::of(&[]), Standing::NoVerdict);
        assert_eq!(Standing::of(&[cite(0x01)]), Standing::Verified);
        assert_eq!(Standing::of(&[cite(0x01), cite(0x02)]), Standing::Adverse);
        assert_eq!(Standing::of(&[cite(0x00)]), Standing::Unproven);
        assert_eq!(Standing::of(&[cite(0x06), cite(0x07)]), Standing::Unproven);
        assert_eq!(Standing::of(&[cite(0x03)]), Standing::Adverse);
    }
}
