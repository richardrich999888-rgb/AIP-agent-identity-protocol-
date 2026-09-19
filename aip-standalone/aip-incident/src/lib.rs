//! `aip-incident` — the evidence bundle an incident report is built from
//! (R14 of `docs/pilot/RBI_REQUIREMENTS_COVERAGE.md`, matrix row E1).
//!
//! # The six-hour problem
//!
//! CERT-In directs that a reportable incident be reported within six hours
//! of being noticed. Six hours is not much time to assemble evidence by
//! hand, and hand assembly is where two things go wrong: something is
//! missed, and nobody can later tell whether it was missed or never existed.
//!
//! This crate produces one signed bundle for an agent and a window, from
//! documents that are already signed, and **computes what it could not
//! cover** rather than presenting what it has as if it were everything.
//!
//! # The property that makes it useful
//!
//! A bundle states its own gaps. [`CoverageSummary::gaps`] is derived by
//! subtracting the intervals the attested batches actually claim from the
//! window that was asked for. An incident report built on a bundle with a
//! forty-minute hole in it should say so — and the alternative, a bundle
//! that looks complete because the hole is invisible, is how an institution
//! ends up telling a regulator something it cannot support.
//!
//! # What the exporter's signature means
//!
//! Exactly one thing: this set of documents was assembled by this exporter
//! at this time. It does not make any document more true. Every enclosed
//! document keeps its own signature and is verified under its own anchors;
//! the manifest binds the set together so a document cannot be removed from
//! a bundle after the fact without the removal being visible.

use std::collections::BTreeMap;

use aip_crypto::{sha256, sign_ed25519, verify_ed25519};
use aip_observe::AttestedBatch;
use aip_types::canonical::{put_bytes, put_domain, put_str, put_u16, put_u32, put_u64};
use aip_types::{AipError, CoverageWindow, Signature};
use serde::{Deserialize, Serialize};

pub const INCIDENT_BUNDLE_DOMAIN: &str = "GHOST/IncidentBundle/v1";
pub const INCIDENT_BUNDLE_VERSION: u16 = 1;

/// One document in the bundle, by name and digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// Path inside the bundle, e.g. `verdicts/0.json`.
    pub name: String,
    /// SHA-256 of the file's bytes, hex.
    pub sha256: String,
    /// What kind of document it is, so a reader knows which verifier to
    /// point at it.
    pub kind: DocumentKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DocumentKind {
    /// `aip_reconcile::SignedReconciliation`.
    Verdict,
    /// `aip_observe::AttestedBatch`.
    AttestedBatch,
    /// `aip_observe::SignedSensorHealth`.
    SensorHealth,
    /// `aip_ledger::AccessLedger`.
    AccessLedger,
    /// `aip_authorize::ExpectedExecution`.
    Expectation,
}

impl DocumentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verdict => "verdict",
            Self::AttestedBatch => "attested_batch",
            Self::SensorHealth => "sensor_health",
            Self::AccessLedger => "access_ledger",
            Self::Expectation => "expectation",
        }
    }

    fn code(self) -> u8 {
        match self {
            Self::Verdict => 0x01,
            Self::AttestedBatch => 0x02,
            Self::SensorHealth => 0x03,
            Self::AccessLedger => 0x04,
            Self::Expectation => 0x05,
        }
    }
}

/// What the bundle covers, and what it does not.
///
/// Every field here is computed from the enclosed batches. None of it is
/// supplied by the caller, because a caller-supplied coverage claim is the
/// thing an incident report should least be built on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageSummary {
    /// The window the export asked for.
    pub requested_from_ms: u64,
    pub requested_to_ms: u64,
    /// Intervals the enclosed batches claim, merged and sorted.
    pub covered: Vec<(u64, u64)>,
    /// **The load-bearing field.** Sub-intervals of the requested window
    /// that no enclosed batch claims. An empty list means the batches claim
    /// the whole window — not that nothing happened in it.
    pub gaps: Vec<(u64, u64)>,
    /// Total milliseconds of the requested window left uncovered.
    pub uncovered_ms: u64,
    /// How many batches were enclosed.
    pub batches: usize,
    /// Batches whose observer reported a per-mechanism integrity problem.
    /// A covered interval from a blinded sensor is covered in name only.
    pub batches_with_integrity_findings: usize,
    /// Events the kernel dropped, summed across enclosed batches, where the
    /// probe reported a count. `None` where any batch did not report one:
    /// a partial sum would read as a total.
    pub dropped_events: Option<u64>,
}

impl CoverageSummary {
    /// Compute coverage from the batches themselves.
    pub fn compute(window: CoverageWindow, batches: &[&AttestedBatch]) -> Self {
        let mut intervals: Vec<(u64, u64)> = batches
            .iter()
            .map(|b| (b.batch.claimed_from_ms, b.batch.claimed_to_ms))
            // Clip to the requested window: a batch that extends beyond it
            // does not make the window larger.
            .filter_map(|(f, t)| {
                let f = f.max(window.from_ms);
                let t = t.min(window.to_ms);
                (f <= t).then_some((f, t))
            })
            .collect();
        intervals.sort_unstable();

        // Merge touching or overlapping intervals.
        let mut covered: Vec<(u64, u64)> = Vec::new();
        for (f, t) in intervals {
            match covered.last_mut() {
                Some(last) if f <= last.1.saturating_add(1) => last.1 = last.1.max(t),
                _ => covered.push((f, t)),
            }
        }

        // The complement inside the requested window.
        let mut gaps = Vec::new();
        let mut cursor = window.from_ms;
        for (f, t) in &covered {
            if *f > cursor {
                gaps.push((cursor, f - 1));
            }
            cursor = cursor.max(t.saturating_add(1));
        }
        if cursor <= window.to_ms {
            gaps.push((cursor, window.to_ms));
        }
        let uncovered_ms = gaps.iter().map(|(f, t)| t - f + 1).sum();

        let batches_with_integrity_findings = batches
            .iter()
            .filter(|b| {
                b.batch
                    .mechanism_integrity
                    .iter()
                    .any(|r| !r.integrity.is_capable())
            })
            .count();

        // A sum over some batches is not a total. If any batch did not
        // report a count, say nothing rather than report a number that
        // understates the loss.
        let dropped_events = batches
            .iter()
            .map(|b| b.batch.dropped_events)
            .try_fold(0u64, |acc, d| d.map(|n| acc.saturating_add(n)));

        Self {
            requested_from_ms: window.from_ms,
            requested_to_ms: window.to_ms,
            covered,
            gaps,
            uncovered_ms,
            batches: batches.len(),
            batches_with_integrity_findings,
            dropped_events,
        }
    }

    /// Whether the bundle covers the whole window it was asked for.
    ///
    /// False does not mean the bundle is bad; it means the report built on
    /// it must say which minutes are unaccounted for.
    pub fn is_complete(&self) -> bool {
        self.gaps.is_empty()
    }
}

/// The manifest: what is in the bundle, what it covers, and who assembled it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentManifest {
    pub version: u16,
    /// Random identifier for this export.
    pub bundle_id: [u8; 16],
    /// The agent the incident concerns.
    pub agent_id: String,
    /// Who assembled it, and under which key version.
    pub exporter_id: String,
    pub key_version: u32,
    pub exported_at_ms: u64,
    /// Sorted by name, so one set of documents has one encoding.
    pub files: Vec<FileEntry>,
    pub coverage: CoverageSummary,
}

impl IncidentManifest {
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(512);
        put_domain(&mut b, INCIDENT_BUNDLE_DOMAIN);
        put_u16(&mut b, self.version);
        put_bytes(&mut b, &self.bundle_id);
        put_str(&mut b, &self.agent_id);
        put_str(&mut b, &self.exporter_id);
        put_u32(&mut b, self.key_version);
        put_u64(&mut b, self.exported_at_ms);
        put_u32(&mut b, self.files.len() as u32);
        for f in &self.files {
            put_str(&mut b, &f.name);
            put_str(&mut b, &f.sha256);
            b.push(f.kind.code());
        }
        // Coverage is inside the signature: a bundle whose stated gaps could
        // be edited after export would be worse than one with no gaps field.
        let c = &self.coverage;
        put_u64(&mut b, c.requested_from_ms);
        put_u64(&mut b, c.requested_to_ms);
        put_u32(&mut b, c.covered.len() as u32);
        for (f, t) in &c.covered {
            put_u64(&mut b, *f);
            put_u64(&mut b, *t);
        }
        put_u32(&mut b, c.gaps.len() as u32);
        for (f, t) in &c.gaps {
            put_u64(&mut b, *f);
            put_u64(&mut b, *t);
        }
        put_u64(&mut b, c.uncovered_ms);
        put_u32(&mut b, c.batches as u32);
        put_u32(&mut b, c.batches_with_integrity_findings as u32);
        match c.dropped_events {
            None => b.push(0),
            Some(n) => {
                b.push(1);
                put_u64(&mut b, n);
            }
        }
        b
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.signing_preimage())
    }
}

/// A manifest plus the exporter's signature, and the documents themselves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentBundle {
    pub manifest: IncidentManifest,
    pub attestation: Signature,
    /// File name → contents. Verbatim: every document keeps its own
    /// signature and is re-verified under its own anchors.
    pub files: BTreeMap<String, String>,
}

/// The exporter's identity.
pub struct Exporter {
    exporter_id: String,
    key_version: u32,
    private_key: Vec<u8>,
}

impl Exporter {
    pub fn new(exporter_id: &str, key_version: u32, private_key: &[u8]) -> Result<Self, AipError> {
        if private_key.len() != 32 {
            return Err(AipError::InvalidPublicKey);
        }
        if exporter_id.is_empty() {
            return Err(AipError::MissingRequiredField);
        }
        Ok(Self {
            exporter_id: exporter_id.to_string(),
            key_version,
            private_key: private_key.to_vec(),
        })
    }
}

/// Anchors for the exporter, supplied by the verifier.
#[derive(Debug, Clone, Default)]
pub struct ExporterAnchors {
    keys: BTreeMap<(String, u32), Vec<u8>>,
}

impl ExporterAnchors {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn trust(mut self, exporter_id: &str, key_version: u32, public_key: &[u8]) -> Self {
        self.keys
            .insert((exporter_id.to_string(), key_version), public_key.to_vec());
        self
    }

    pub fn get(&self, exporter_id: &str, key_version: u32) -> Option<&[u8]> {
        self.keys
            .get(&(exporter_id.to_string(), key_version))
            .map(|k| k.as_slice())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleError {
    UnsupportedVersion(u16),
    MissingAgent,
    /// A file named in the manifest is absent from the bundle.
    FileMissing(String),
    /// A file is present but its bytes do not hash to what the manifest says.
    FileDigestMismatch(String),
    /// A file is present that the manifest does not name. A bundle with an
    /// undeclared document is a bundle someone added to.
    FileUndeclared(String),
    /// Files are not sorted by name, so this is not the canonical encoding.
    FilesNotCanonical,
    ExporterNotAnchored {
        exporter_id: String,
        key_version: u32,
    },
    SignerIsNotExporter,
    PayloadHashMismatch,
    SignatureInvalid,
    /// The manifest's coverage summary does not match the batches enclosed.
    /// The gaps a bundle states must be the gaps it has.
    CoverageMismatch,
    Crypto(AipError),
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for BundleError {}

/// One document to enclose.
pub struct Document<'a> {
    pub name: String,
    pub kind: DocumentKind,
    pub json: &'a str,
}

/// Assemble and sign a bundle.
///
/// `batches` are the attested batches among `documents`, passed separately
/// because the coverage summary is computed from them rather than from
/// anything the caller states.
pub fn export(
    exporter: &Exporter,
    agent_id: &str,
    window: CoverageWindow,
    bundle_id: [u8; 16],
    exported_at_ms: u64,
    documents: &[Document<'_>],
    batches: &[&AttestedBatch],
) -> Result<IncidentBundle, BundleError> {
    if agent_id.is_empty() {
        return Err(BundleError::MissingAgent);
    }
    let mut files_map: BTreeMap<String, String> = BTreeMap::new();
    let mut entries: Vec<FileEntry> = Vec::with_capacity(documents.len());
    for d in documents {
        if files_map.contains_key(&d.name) {
            return Err(BundleError::FileUndeclared(d.name.clone()));
        }
        entries.push(FileEntry {
            name: d.name.clone(),
            sha256: hex(&sha256(d.json.as_bytes())),
            kind: d.kind,
        });
        files_map.insert(d.name.clone(), d.json.to_string());
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    let manifest = IncidentManifest {
        version: INCIDENT_BUNDLE_VERSION,
        bundle_id,
        agent_id: agent_id.to_string(),
        exporter_id: exporter.exporter_id.clone(),
        key_version: exporter.key_version,
        exported_at_ms,
        files: entries,
        coverage: CoverageSummary::compute(window, batches),
    };
    let attestation = sign_ed25519(
        &exporter.private_key,
        &exporter.exporter_id,
        &manifest.signing_preimage(),
    )
    .map_err(BundleError::Crypto)?;
    Ok(IncidentBundle {
        manifest,
        attestation,
        files: files_map,
    })
}

/// Verify a bundle's own integrity: the manifest's signature, that every
/// declared file is present with the declared digest, and that no undeclared
/// file was added.
///
/// # What this does not do
///
/// It does not verify the enclosed documents. Each carries its own signature
/// and must be checked under its own anchors — the reconciler's for a
/// verdict, the collector's for a batch. A bundle that verifies here is a
/// bundle nobody has edited since export; whether what it contains is true
/// is a separate question with separate keys, and conflating the two is how
/// a bundle's signature comes to be mistaken for an endorsement of its
/// contents.
pub fn verify_bundle(
    bundle: &IncidentBundle,
    anchors: &ExporterAnchors,
) -> Result<(), BundleError> {
    let m = &bundle.manifest;
    if m.version != INCIDENT_BUNDLE_VERSION {
        return Err(BundleError::UnsupportedVersion(m.version));
    }
    if m.agent_id.is_empty() {
        return Err(BundleError::MissingAgent);
    }
    for pair in m.files.windows(2) {
        if pair[0].name >= pair[1].name {
            return Err(BundleError::FilesNotCanonical);
        }
    }
    for f in &m.files {
        let content = bundle
            .files
            .get(&f.name)
            .ok_or_else(|| BundleError::FileMissing(f.name.clone()))?;
        if hex(&sha256(content.as_bytes())) != f.sha256 {
            return Err(BundleError::FileDigestMismatch(f.name.clone()));
        }
    }
    // An extra file is not harmless: a reader who lists the archive sees a
    // document the manifest never vouched for.
    for name in bundle.files.keys() {
        if !m.files.iter().any(|f| &f.name == name) {
            return Err(BundleError::FileUndeclared(name.clone()));
        }
    }

    let key = anchors.get(&m.exporter_id, m.key_version).ok_or_else(|| {
        BundleError::ExporterNotAnchored {
            exporter_id: m.exporter_id.clone(),
            key_version: m.key_version,
        }
    })?;
    if bundle.attestation.signer_id != m.exporter_id {
        return Err(BundleError::SignerIsNotExporter);
    }
    if bundle.attestation.payload_hash != m.digest() {
        return Err(BundleError::PayloadHashMismatch);
    }
    match verify_ed25519(key, &bundle.attestation) {
        Ok(true) => Ok(()),
        Ok(false) => Err(BundleError::SignatureInvalid),
        Err(e) => Err(BundleError::Crypto(e)),
    }
}

/// Recompute the coverage summary from the bundle's own enclosed batches and
/// compare it with what the manifest claims.
///
/// Separate from [`verify_bundle`] because it needs the batches parsed,
/// which needs `aip-observe`'s types. A verifier that has them should run
/// this too: the signature proves the exporter stated these gaps, and this
/// proves the gaps are the ones the evidence actually has.
pub fn verify_coverage(
    bundle: &IncidentBundle,
    batches: &[&AttestedBatch],
) -> Result<(), BundleError> {
    let window = CoverageWindow {
        from_ms: bundle.manifest.coverage.requested_from_ms,
        to_ms: bundle.manifest.coverage.requested_to_ms,
    };
    let recomputed = CoverageSummary::compute(window, batches);
    if recomputed == bundle.manifest.coverage {
        Ok(())
    } else {
        Err(BundleError::CoverageMismatch)
    }
}

fn hex(d: &[u8; 32]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// A human-readable summary for the person writing the report.
///
/// Leads with what is missing, because that is the part a six-hour deadline
/// makes easiest to omit.
pub fn summary_markdown(bundle: &IncidentBundle) -> String {
    let m = &bundle.manifest;
    let c = &m.coverage;
    let mut s = String::new();
    s.push_str("# Incident evidence bundle\n\n");
    s.push_str(&format!("Agent: `{}`\n\n", m.agent_id));
    s.push_str(&format!(
        "Window requested: {} to {} ({} ms)\n\n",
        c.requested_from_ms,
        c.requested_to_ms,
        c.requested_to_ms.saturating_sub(c.requested_from_ms) + 1
    ));

    s.push_str("## Coverage\n\n");
    if c.is_complete() {
        s.push_str(
            "The enclosed batches claim the whole window. This means the \
             observer was recording throughout; it does not mean nothing \
             happened outside what the batches contain.\n\n",
        );
    } else {
        s.push_str(&format!(
            "**{} ms of the window is not covered by any enclosed batch.** \
             Any statement in the report about those intervals is not \
             supported by this bundle.\n\n",
            c.uncovered_ms
        ));
        s.push_str("| Gap from | Gap to |\n|---|---|\n");
        for (f, t) in &c.gaps {
            s.push_str(&format!("| {f} | {t} |\n"));
        }
        s.push('\n');
    }
    if c.batches_with_integrity_findings > 0 {
        s.push_str(&format!(
            "**{} of {} batches carry a sensor integrity finding.** A covered \
             interval from a blinded sensor is covered in name only.\n\n",
            c.batches_with_integrity_findings, c.batches
        ));
    }
    match c.dropped_events {
        Some(0) => s.push_str("No events were reported dropped.\n\n"),
        Some(n) => s.push_str(&format!("{n} events were reported dropped.\n\n")),
        None => s.push_str(
            "At least one batch did not report a dropped-event count, so no \
             total is stated: a partial sum would read as a total.\n\n",
        ),
    }

    s.push_str("## Documents\n\n| File | Kind | SHA-256 |\n|---|---|---|\n");
    for f in &m.files {
        s.push_str(&format!(
            "| {} | {} | {} |\n",
            f.name,
            f.kind.as_str(),
            f.sha256
        ));
    }
    s.push_str(&format!(
        "\nAssembled by `{}` (key version {}) at {}.\n\n\
         The exporter's signature means this set of documents was assembled \
         by that exporter at that time. It does not make any enclosed \
         document more true: each keeps its own signature and must be \
         verified under its own anchors.\n",
        m.exporter_id, m.key_version, m.exported_at_ms
    ));
    s
}
