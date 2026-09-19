//! The CEF event built from a **verified** verdict.
//!
//! # Why verification is not optional here
//!
//! A SIEM is where an institution's analysts form beliefs. If an unsigned
//! or forged verdict can reach it, the SIEM is where a forgery acquires the
//! bank's own provenance: it arrives looking like something the bank's
//! reconciler said. [`CefEvent::from_verdict`] therefore verifies under
//! anchors the caller supplies, and there is no constructor that skips it.
//!
//! # Severity
//!
//! A `Reconciliation` deliberately carries no severity, confidence or
//! score, and a test in `aip-reconcile` enforces that. CEF's header
//! *requires* one, so this crate supplies it and owns it:
//!
//! * It is a **routing hint for the SIEM**, chosen by this exporter. It is
//!   not in any signature and says nothing the verdict says.
//! * It is a total, fixed function of [`ReconciliationResult`] alone —
//!   never of `strength`, never per-event — so two identical results always
//!   route identically. [`severity_for`] is the whole table.
//! * `CANNOT_PROVE` maps to the middle of the range, not the bottom. An
//!   unproven claim is not a clean one, and a SIEM that files it beside
//!   `VERIFIED_EXECUTION` has been told the wrong thing.
//!
//! An analyst deciding anything from the severity rather than from
//! `aipResult` is reading the field this crate invented instead of the one
//! the reconciler signed.

use aip_reconcile::{ReconcilerTrustAnchors, ReconciliationResult, SignedReconciliation};

use crate::escape;

/// CEF format version. The only one this crate emits.
pub const CEF_VERSION: u8 = 0;

/// Why a verdict could not be turned into an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SiemError {
    /// The verdict did not verify under the anchors supplied. Nothing is
    /// emitted: a SIEM must not be where an unverified verdict acquires
    /// the institution's provenance.
    VerdictNotVerified(String),
    /// A device identity field was empty. Every CEF header field is
    /// mandatory and an empty one produces a line the receiver cannot
    /// attribute.
    EmptyDeviceField(&'static str),
    /// A value destined for the line contains a character no identifier
    /// legitimately holds. See [`is_representable`].
    Unrepresentable {
        what: &'static str,
        /// The verdict this was refused for, by digest, so the refusal
        /// names a document an operator can go and look at.
        verdict_digest: String,
    },
}

impl std::fmt::Display for SiemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VerdictNotVerified(e) => write!(
                f,
                "the verdict did not verify under the anchors supplied, so no event is \
                 emitted: {e}"
            ),
            Self::EmptyDeviceField(name) => {
                write!(
                    f,
                    "the CEF header field `{name}` is mandatory and was empty"
                )
            }
            Self::Unrepresentable {
                what,
                verdict_digest,
            } => write!(
                f,
                "`{what}` contains a pipe, a backslash or a control character. No identifier \
                 this system issues does, so this is a fault or an attempt to forge a second \
                 event inside this one, and no line is emitted. Verdict digest: {verdict_digest}"
            ),
        }
    }
}

impl std::error::Error for SiemError {}

/// Who the SIEM will attribute the event to. Supplied by the deployment,
/// because the exporter cannot know what an institution calls its own
/// systems.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub vendor: String,
    pub product: String,
    pub version: String,
}

/// Whether a value can go on a CEF line without the result depending on
/// the receiver's parser.
///
/// Escaping (see [`crate::escape`]) already makes a hostile value safe for
/// a **conformant** CEF parser. This is the second line: a value holding a
/// pipe can still spell a literal `CEF:0|...` inside the record, which a
/// conformant parser reads as text but a stream consumer that re-scans for
/// `CEF:` reads as a second event. An exporter cannot verify what its
/// receiver does, so it refuses to emit a record whose meaning depends on
/// the answer.
///
/// Refusing costs nothing legitimate: no identifier this system issues
/// contains a pipe, a backslash or a control character. A value that does
/// is a fault or an attack, and both are better surfaced than logged.
pub fn is_representable(s: &str) -> bool {
    !s.chars().any(|c| c == '|' || c == '\\' || c.is_control())
}

impl DeviceIdentity {
    pub fn new(vendor: &str, product: &str, version: &str) -> Result<Self, SiemError> {
        if vendor.trim().is_empty() {
            return Err(SiemError::EmptyDeviceField("Device Vendor"));
        }
        if product.trim().is_empty() {
            return Err(SiemError::EmptyDeviceField("Device Product"));
        }
        if version.trim().is_empty() {
            return Err(SiemError::EmptyDeviceField("Device Version"));
        }
        // Operator-supplied configuration. A pipe here is a
        // misconfiguration, caught once at start-up rather than on every
        // line.
        for (what, value) in [
            ("Device Vendor", vendor),
            ("Device Product", product),
            ("Device Version", version),
        ] {
            if !is_representable(value) {
                return Err(SiemError::Unrepresentable {
                    what,
                    verdict_digest: "n/a (device configuration)".to_string(),
                });
            }
        }
        Ok(Self {
            vendor: vendor.to_string(),
            product: product.to_string(),
            version: version.to_string(),
        })
    }
}

/// The exporter's severity table.
///
/// Total by construction — the `match` has no wildcard, so adding a
/// [`ReconciliationResult`] variant is a compile error here rather than a
/// silent default. That is deliberate: a new adverse class defaulting to
/// "informational" is precisely the failure this table exists to prevent.
pub fn severity_for(result: ReconciliationResult) -> u8 {
    match result {
        // Nothing for an analyst to act on.
        ReconciliationResult::VerifiedExecution => 0,
        // The absence of evidence. Middle of the range on purpose: not an
        // adverse finding, and not a clean bill of health either.
        ReconciliationResult::CannotProve => 5,
        // Adverse findings. All high, and none higher than another: this
        // exporter is not entitled to rank one institution's risks.
        ReconciliationResult::UnattributedEffect
        | ReconciliationResult::PhantomClaim
        | ReconciliationResult::IdentityDivergence
        | ReconciliationResult::LineageViolation
        | ReconciliationResult::SensorIntegrityFailure
        | ReconciliationResult::ContinuityFailure => 8,
    }
}

/// One CEF event, assembled and ready to render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CefEvent {
    pub device: DeviceIdentity,
    /// CEF "Signature ID": the stable class of the event.
    pub signature_id: String,
    /// CEF "Name": human-readable, short.
    pub name: String,
    pub severity: u8,
    /// Extension key/value pairs, in a fixed order so two renderings of
    /// one verdict are byte-identical.
    pub extensions: Vec<(&'static str, String)>,
    /// When the reconciliation was computed, as the verdict states it.
    pub verification_time_ms: u64,
}

impl CefEvent {
    /// Build an event from a verdict, **after verifying it**.
    ///
    /// The digest is carried in the event so an analyst reading the line
    /// can ask for the document and check it themselves. Every value that
    /// reaches the line is escaped at render time, not here, so the struct
    /// holds what the verdict says rather than a pre-mangled copy.
    pub fn from_verdict(
        verdict: &SignedReconciliation,
        anchors: &ReconcilerTrustAnchors,
        device: &DeviceIdentity,
    ) -> Result<Self, SiemError> {
        verdict
            .verify(anchors)
            .map_err(|e| SiemError::VerdictNotVerified(format!("{e:?}")))?;

        // The identifier is signed, so a valid verdict can legitimately
        // carry a hostile one. Verification says the reconciler really
        // said this; it does not say the string is safe to concatenate.
        if !is_representable(&verdict.reconciler_id) {
            return Err(SiemError::Unrepresentable {
                what: "reconciler_id",
                verdict_digest: hex(&verdict.digest()),
            });
        }

        let r = &verdict.reconciliation;
        let result = r.result;
        let mut extensions: Vec<(&'static str, String)> = Vec::with_capacity(12);

        // `cs1`/`cs2` carry the two fields an analyst routes on, under
        // their CEF custom-string labels so a receiver that does not know
        // this product still renders something meaningful.
        extensions.push(("cs1", result.as_str().to_string()));
        extensions.push(("cs1Label", "AipResult".to_string()));
        extensions.push(("cs2", format!("{:?}", r.strength)));
        extensions.push(("cs2Label", "AipEvidenceStrength".to_string()));
        extensions.push(("cs3", format!("{:?}", r.reason)));
        extensions.push(("cs3Label", "AipReasonCode".to_string()));
        extensions.push(("cs4", hex(&verdict.digest())));
        extensions.push(("cs4Label", "AipVerdictDigest".to_string()));

        extensions.push(("dvchost", verdict.reconciler_id.clone()));
        extensions.push(("externalId", hex(&verdict.digest())[..16].to_string()));
        extensions.push(("rt", r.verification_time_ms.to_string()));
        if let Some(id) = r.decision_id {
            extensions.push(("cs5", hex(id.as_bytes())));
            extensions.push(("cs5Label", "AipDecisionId".to_string()));
        }
        if r.replay_detected {
            extensions.push(("cs6", "true".to_string()));
            extensions.push(("cs6Label", "AipReplayDetected".to_string()));
        }
        // The one free-text field, and the one that has to make the
        // verdict's limits legible to somebody at 03:00.
        extensions.push(("msg", message_for(result)));

        Ok(Self {
            device: device.clone(),
            signature_id: format!("AIP:{}", result.code()),
            name: result.as_str().replace('_', " ").to_lowercase(),
            severity: severity_for(result),
            extensions,
            verification_time_ms: r.verification_time_ms,
        })
    }

    /// Render the CEF line. No trailing newline: framing belongs to the
    /// transport, and an exporter that adds one produces a blank record
    /// when the transport adds another.
    pub fn to_cef(&self) -> String {
        let mut out = format!(
            "CEF:{}|{}|{}|{}|{}|{}|{}|",
            CEF_VERSION,
            escape::header(&self.device.vendor),
            escape::header(&self.device.product),
            escape::header(&self.device.version),
            escape::header(&self.signature_id),
            escape::header(&self.name),
            self.severity,
        );
        let mut first = true;
        for (k, v) in &self.extensions {
            if !first {
                out.push(' ');
            }
            first = false;
            out.push_str(k);
            out.push('=');
            out.push_str(&escape::extension(v));
        }
        out
    }
}

/// The sentence that goes in `msg`.
///
/// Written for someone deciding whether to act, and deliberately explicit
/// that `CANNOT_PROVE` is the absence of evidence rather than evidence of
/// absence — the misreading that this whole system exists to prevent.
fn message_for(result: ReconciliationResult) -> String {
    match result {
        ReconciliationResult::VerifiedExecution => {
            "Expected and observed execution agree under attested coverage.".into()
        }
        ReconciliationResult::CannotProve => {
            "Evidence is insufficient to classify this execution. This is the absence of \
             evidence, not evidence that nothing happened: do not read it as clean."
                .into()
        }
        ReconciliationResult::UnattributedEffect => {
            "An attested effect occurred for which the decision point attested no \
             expectation exists."
                .into()
        }
        ReconciliationResult::PhantomClaim => {
            "An execution was authorized but no instance of it was observed, under signed \
             kernel coverage of the whole window."
                .into()
        }
        ReconciliationResult::IdentityDivergence => {
            "The instance observed under this decision differs from the instance the \
             decision point authorized."
                .into()
        }
        ReconciliationResult::LineageViolation => {
            "Observed ancestry contradicts the authority chain.".into()
        }
        ReconciliationResult::SensorIntegrityFailure => {
            "Observer signature or chain arithmetic failed: the observation cannot be \
             relied on for this window."
                .into()
        }
        ReconciliationResult::ContinuityFailure => {
            "The observer attests a break in continuity over this window.".into()
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
