//! The collector runtime (Gate 8): a [`CollectorSigner`] over a
//! [`CollectorStore`], with a continuity policy that is a policy.
//!
//! # What a restart means
//!
//! Nothing. A resumed runtime is `Recovering` until a contiguous batch is
//! admitted, whatever the policy and whatever the files said. A restart
//! never implies continuity (I9, OBSERVER_ATTESTATION.md §5).
//!
//! # What a break means
//!
//! On start the runtime hands the stored snapshot and the archive of the
//! collector's own signed health records to [`CollectorSigner::resume`],
//! which classifies their disagreement as one of the four
//! [`ContinuityBreak`]s. The runtime then applies the policy:
//!
//! | break            | `Strict` (default)        | `Advisory`                    |
//! |------------------|---------------------------|-------------------------------|
//! | none             | run, `Recovering`         | run, `Recovering`             |
//! | `Amnesia`        | **refuse**                | adopt archive head, run       |
//! | `RolledBack`     | **refuse**                | adopt archive head, run       |
//! | `Forked`         | **refuse** (quarantined)  | run **quarantined**: no batch |
//! | `ArchiveTruncated` | run, `Recovering`       | run, `Recovering`             |
//!
//! Every break — refused or not — is written to the store as a
//! [`SignedContinuityReport`] under the collector's own key before the
//! runtime does anything else, so "the collector was restored from an old
//! state file" is a record a verifier can hold, not a log line. The report
//! is about the observer's own record and names no agent, decision or
//! workload.
//!
//! `Strict` refuses because a collector that forgot, or was rolled back, is
//! a collector whose environment an attacker or an outage has reached; an
//! operator must look before it signs again. `Advisory` continues on the
//! archive head so that one chain is continued rather than a second started
//! under the same key, and says so in the report. A fork is quarantined
//! under both: two heads at one position under one key is an integrity
//! failure of the record itself, and no policy un-proves arithmetic.

use aip_crypto::sign_ed25519;
use aip_types::canonical::*;
use aip_types::Signature;
use serde::{Deserialize, Serialize};

use crate::attest::{
    archive_head, collector_now_ms, verify_signature_over, AttestError, AttestedBatch,
    CollectorSigner, CollectorSnapshot, ObserverAttestor, ObserverTrustAnchors, VerifyError,
};
use crate::continuity::ContinuityBreak;
use crate::health::{AttestedClock, ObserverState, SignedSensorHealth};
use crate::observed::{ObservationBatch, OBSERVE_PROTOCOL_VERSION};
use crate::store::{CollectorStore, StoreError};

/// Domain tag leading the canonical encoding of [`ContinuityReport`].
pub const CONTINUITY_REPORT_DOMAIN: &str = "SYNTRIASS/GHOST/CONTINUITY_REPORT/v1";

/// What the runtime does when its stored state disagrees with its archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ContinuityPolicy {
    /// Refuse to sign after amnesia, rollback or fork until an operator
    /// acts. The default.
    #[default]
    Strict,
    /// Continue on the archive head and report; a fork is still quarantined.
    Advisory,
}

impl ContinuityPolicy {
    fn code(&self) -> u8 {
        match self {
            ContinuityPolicy::Strict => 0x01,
            ContinuityPolicy::Advisory => 0x02,
        }
    }
}

/// How the runtime came up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StartOutcome {
    /// No state and no archive: a first deployment.
    Fresh,
    /// State or archive existed. `continuity_break` is what the audit found;
    /// `None` is a clean resume — still `Recovering`.
    Resumed {
        continuity_break: Option<ContinuityBreak>,
    },
}

/// The result of [`CollectorRuntime::start`].
// A started runtime is large (it carries the signer and its registry) and
// a refusal is small; the value is produced once per process start, so
// boxing would only move the allocation without saving anything.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Started {
    Running(CollectorRuntime, StartOutcome),
    /// `Strict` policy met a break it does not run through. A signed report
    /// of the refusal is in the store.
    Refused(ContinuityBreak),
}

#[derive(Debug)]
pub enum RuntimeError {
    Store(StoreError),
    Attest(AttestError),
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuntimeError::Store(e) => write!(f, "{e}"),
            RuntimeError::Attest(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RuntimeError {}

impl From<StoreError> for RuntimeError {
    fn from(e: StoreError) -> Self {
        RuntimeError::Store(e)
    }
}

impl From<AttestError> for RuntimeError {
    fn from(e: AttestError) -> Self {
        RuntimeError::Attest(e)
    }
}

// ─── The report ───

/// The collector's signed statement that its stored state and its archive
/// disagreed, what it did about it, and when. About the observer's own
/// record only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinuityReport {
    pub version: u16,
    pub observer_id: String,
    pub key_version: u32,
    pub continuity_break: ContinuityBreak,
    /// The sequence in the stored state (`None`: no state file).
    pub resumed_sequence: Option<u64>,
    /// The highest sequence among archive records that verify under the
    /// collector's key (`None`: no such record).
    pub archived_sequence: Option<u64>,
    pub archived_head: Option<[u8; 32]>,
    pub policy: ContinuityPolicy,
    /// `true`: the runtime did not start. `false`: it started on the
    /// position the break implies, `Recovering` or quarantined.
    pub refused: bool,
    pub emitted_at_ms: u64,
}

impl ContinuityReport {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, CONTINUITY_REPORT_DOMAIN);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, &self.observer_id);
        put_u32(&mut buf, self.key_version);
        put_break(&mut buf, &self.continuity_break);
        put_opt_u64(&mut buf, &self.resumed_sequence);
        put_opt_u64(&mut buf, &self.archived_sequence);
        match &self.archived_head {
            Some(h) => {
                put_u8(&mut buf, 1);
                buf.extend_from_slice(h);
            }
            None => put_u8(&mut buf, 0),
        }
        put_u8(&mut buf, self.policy.code());
        put_u8(&mut buf, u8::from(self.refused));
        put_u64(&mut buf, self.emitted_at_ms);
        buf
    }
}

fn put_break(buf: &mut Vec<u8>, b: &ContinuityBreak) {
    match b {
        ContinuityBreak::Amnesia {
            archived_sequence,
            archived_head,
        } => {
            put_u8(buf, 0x01);
            put_u64(buf, *archived_sequence);
            buf.extend_from_slice(archived_head);
        }
        ContinuityBreak::RolledBack {
            resumed_sequence,
            archived_sequence,
        } => {
            put_u8(buf, 0x02);
            put_u64(buf, *resumed_sequence);
            put_u64(buf, *archived_sequence);
        }
        ContinuityBreak::Forked {
            sequence,
            resumed_head,
            archived_head,
        } => {
            put_u8(buf, 0x03);
            put_u64(buf, *sequence);
            buf.extend_from_slice(resumed_head);
            buf.extend_from_slice(archived_head);
        }
        ContinuityBreak::ArchiveTruncated {
            resumed_sequence,
            archived_sequence,
        } => {
            put_u8(buf, 0x04);
            put_u64(buf, *resumed_sequence);
            put_u64(buf, *archived_sequence);
        }
    }
}

/// [`ContinuityReport`] plus the collector's signature over its canonical
/// bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedContinuityReport {
    pub report: ContinuityReport,
    pub signature: Signature,
}

/// Verify a continuity report offline against the verifier's anchors.
pub fn verify_continuity_report(
    r: &SignedContinuityReport,
    anchors: &ObserverTrustAnchors,
) -> Result<(), VerifyError> {
    if !crate::observed::is_verifiable_version(r.report.version) {
        return Err(VerifyError::UnsupportedVersion(r.report.version));
    }
    verify_signature_over(
        &r.report.canonical_bytes(),
        &r.report.observer_id,
        r.report.key_version,
        &r.signature,
        anchors,
    )
}

// ─── The runtime ───

/// A collector that persists: every signature is followed by a snapshot
/// write, every health record by an archive append.
#[derive(Debug)]
pub struct CollectorRuntime {
    signer: CollectorSigner,
    store: CollectorStore,
    policy: ContinuityPolicy,
}

impl CollectorRuntime {
    /// Start over `store`: load the snapshot and archive, audit them, apply
    /// `policy`, record any break, persist the adopted position.
    ///
    /// Errors are not breaks: a corrupt file is [`RuntimeError::Store`], a
    /// snapshot of another observer is [`AttestError::ForeignState`]. Neither
    /// starts a fresh chain.
    pub fn start(
        store: CollectorStore,
        observer_id: &str,
        key_version: u32,
        private_key: &[u8],
        public_key: &[u8],
        policy: ContinuityPolicy,
    ) -> Result<Started, RuntimeError> {
        let loaded = store.load_snapshot()?;
        let archive = store.load_archive()?;
        let fresh = loaded.is_none() && archive.is_empty();
        let resumed_sequence = loaded.as_ref().and_then(|s| s.sequence);
        let snapshot = loaded.unwrap_or_else(|| CollectorSnapshot::fresh(observer_id, key_version));
        let (signer, brk) =
            CollectorSigner::resume(&snapshot, observer_id, private_key, public_key, &archive)?;

        let Some(brk) = brk else {
            let rt = Self {
                signer,
                store,
                policy,
            };
            rt.store.save_snapshot(&rt.signer.snapshot())?;
            let outcome = if fresh {
                StartOutcome::Fresh
            } else {
                StartOutcome::Resumed {
                    continuity_break: None,
                }
            };
            return Ok(Started::Running(rt, outcome));
        };

        let refused = policy == ContinuityPolicy::Strict
            && matches!(
                brk,
                ContinuityBreak::Amnesia { .. }
                    | ContinuityBreak::RolledBack { .. }
                    | ContinuityBreak::Forked { .. }
            );
        let archived = archive_head(&snapshot, &archive, public_key);
        let report = ContinuityReport {
            version: OBSERVE_PROTOCOL_VERSION,
            observer_id: observer_id.to_string(),
            key_version: signer.key_version(),
            continuity_break: brk.clone(),
            resumed_sequence,
            archived_sequence: archived.map(|(s, _)| s),
            archived_head: archived.map(|(_, h)| h),
            policy,
            refused,
            emitted_at_ms: collector_now_ms(),
        };
        let signature = sign_ed25519(private_key, observer_id, &report.canonical_bytes())
            .map_err(AttestError::Signing)?;
        store.append_report(&SignedContinuityReport { report, signature })?;

        if refused {
            return Ok(Started::Refused(brk));
        }
        let rt = Self {
            signer,
            store,
            policy,
        };
        rt.store.save_snapshot(&rt.signer.snapshot())?;
        Ok(Started::Running(
            rt,
            StartOutcome::Resumed {
                continuity_break: Some(brk),
            },
        ))
    }

    /// Start under a [`Custodian`](aip_crypto::custody::Custodian) — the
    /// production path. Identical to [`start`](Self::start) but the signing key
    /// is held wrapped by the custodian and never passes through this call as
    /// raw bytes, so an off-host collector can hold its key at rest without the
    /// runtime ever seeing it. The continuity logic is shared verbatim through
    /// [`CollectorSigner::resume_with_custodian`].
    pub fn start_with_custodian(
        store: CollectorStore,
        observer_id: &str,
        key_version: u32,
        custodian: Box<dyn aip_crypto::custody::Custodian>,
        policy: ContinuityPolicy,
    ) -> Result<Started, RuntimeError> {
        let loaded = store.load_snapshot()?;
        let archive = store.load_archive()?;
        let fresh = loaded.is_none() && archive.is_empty();
        let resumed_sequence = loaded.as_ref().and_then(|s| s.sequence);
        let snapshot = loaded.unwrap_or_else(|| CollectorSnapshot::fresh(observer_id, key_version));
        // Capture the public key before the custodian is moved into the signer;
        // it is needed to locate the archived head for the continuity report.
        let public_key = custodian.public_key().to_vec();
        let (signer, brk) =
            CollectorSigner::resume_with_custodian(&snapshot, observer_id, custodian, &archive)?;

        let Some(brk) = brk else {
            let rt = Self {
                signer,
                store,
                policy,
            };
            rt.store.save_snapshot(&rt.signer.snapshot())?;
            let outcome = if fresh {
                StartOutcome::Fresh
            } else {
                StartOutcome::Resumed {
                    continuity_break: None,
                }
            };
            return Ok(Started::Running(rt, outcome));
        };

        let refused = policy == ContinuityPolicy::Strict
            && matches!(
                brk,
                ContinuityBreak::Amnesia { .. }
                    | ContinuityBreak::RolledBack { .. }
                    | ContinuityBreak::Forked { .. }
            );
        let archived = archive_head(&snapshot, &archive, &public_key);
        let report = ContinuityReport {
            version: OBSERVE_PROTOCOL_VERSION,
            observer_id: observer_id.to_string(),
            key_version: signer.key_version(),
            continuity_break: brk.clone(),
            resumed_sequence,
            archived_sequence: archived.map(|(s, _)| s),
            archived_head: archived.map(|(_, h)| h),
            policy,
            refused,
            emitted_at_ms: collector_now_ms(),
        };
        // Signed through the custodian, so the continuity report is signed
        // without the raw key — the same signature `start` produces with
        // `sign_ed25519`, only the key holder differs.
        let signature = signer.sign_bytes(&report.canonical_bytes())?;
        store.append_report(&SignedContinuityReport { report, signature })?;

        if refused {
            return Ok(Started::Refused(brk));
        }
        let rt = Self {
            signer,
            store,
            policy,
        };
        rt.store.save_snapshot(&rt.signer.snapshot())?;
        Ok(Started::Running(
            rt,
            StartOutcome::Resumed {
                continuity_break: Some(brk),
            },
        ))
    }

    pub fn policy(&self) -> ContinuityPolicy {
        self.policy
    }

    pub fn state(&self) -> ObserverState {
        self.signer.state()
    }

    pub fn signer(&self) -> &CollectorSigner {
        &self.signer
    }

    pub fn signer_mut(&mut self) -> &mut CollectorSigner {
        &mut self.signer
    }

    pub fn store(&self) -> &CollectorStore {
        &self.store
    }

    pub fn snapshot(&self) -> CollectorSnapshot {
        self.signer.snapshot()
    }

    /// Attest at the collector's clock, then persist the new position.
    pub fn attest(&mut self, batch: ObservationBatch) -> Result<AttestedBatch, RuntimeError> {
        self.attest_at(batch, collector_now_ms())
    }

    /// Attest at an explicit collector time, then persist the new position.
    /// A quarantined runtime refuses before touching the store.
    pub fn attest_at(
        &mut self,
        batch: ObservationBatch,
        attested_at_ms: u64,
    ) -> Result<AttestedBatch, RuntimeError> {
        let attested = self.signer.attest_at(batch, attested_at_ms)?;
        self.store.save_snapshot(&self.signer.snapshot())?;
        Ok(attested)
    }

    /// Emit signed health, append it to the archive, persist the position.
    /// Permitted while quarantined: a signed statement of quarantine is
    /// exactly what a verifier needs then.
    pub fn health(&self, emitted_at_ms: u64) -> Result<SignedSensorHealth, RuntimeError> {
        self.health_with_clock(emitted_at_ms, None)
    }

    /// As [`Self::health`], carrying the collector's clock discipline inside
    /// the attested bytes (protocol 12). Reading the clock is IO and stays
    /// with the caller; this signs and persists what it is given.
    pub fn health_with_clock(
        &self,
        emitted_at_ms: u64,
        clock: Option<AttestedClock>,
    ) -> Result<SignedSensorHealth, RuntimeError> {
        let h = self.signer.health_with_clock(emitted_at_ms, clock)?;
        self.store.append_health(&h)?;
        self.store.save_snapshot(&self.signer.snapshot())?;
        Ok(h)
    }
}
