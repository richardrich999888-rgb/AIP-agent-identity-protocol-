//! What the sentinel concluded, and how well it can support the conclusion.
//!
//! # Why strength is separate from severity
//!
//! These are the two questions an enforcement decision needs, and conflating
//! them is how automated policing goes wrong. *Severity* asks how bad it
//! would be if true. *Strength* asks how certain we are that it is true. A
//! statistical hunch about a catastrophic action is not a warrant, and a
//! cryptographic proof of a trivial one is not an emergency.
//!
//! [`Strength::Proof`] is reserved for conclusions that follow from
//! arithmetic rather than judgement — a hash chain that branched, a digest
//! that does not recompute, an effect whose parameters match no sealed packet
//! anywhere. These cannot be false positives in the way a rate anomaly can;
//! either the numbers agree or they do not.
//!
//! [`crate::response::ResponsePolicy`] enforces the consequence of that
//! distinction: nothing below `Proof` may ever trigger an automatic
//! quarantine. A ghost hunter that can be talked into revoking a healthy
//! agent by feeding it unusual traffic is itself an attack surface, and the
//! cheapest denial-of-service against a governed fleet would be to make its
//! own watchdog do the damage.

use serde_json::{json, Value};

/// What kind of problem was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingKind {
    /// A consequential effect occurred with no sealed evidence behind it —
    /// the signature of an agent acting outside the governed channel.
    UnattributedEffect,
    /// A consequential effect occurred with no identity presented at all.
    AnonymousEffect,
    /// A DID acted that was never born on this ledger.
    UnregisteredAgent,
    /// One agent's packet chain branched: two records claiming the same
    /// predecessor or the same sequence number. One identity, two runtimes.
    IdentityFork,
    /// A sealed chain no longer recomputes: records were edited or removed.
    LedgerBreak,
    /// The runtime is executing weights the lifecycle chain does not bind.
    ModelDrift,
    /// A pattern of refusals consistent with mapping the authority boundary
    /// rather than with honest mistakes.
    ScopeProbing,
    /// A registered agent stopped reporting while its effects continued.
    LivenessLost,
    /// Timestamps or sequence numbers that cannot both be true.
    TemporalAnomaly,
    /// The ledger claims an action the covering sensor never saw.
    PhantomEvidence,
    /// An action was sealed for a caller whose identity was never proven.
    UnprovenPrincipal,
    /// A sensor's own raw input stream no longer recomputes to a hash it
    /// previously attested — the bytes the sensor is reading changed after
    /// the sentinel sealed an opinion about them. Every conclusion drawn
    /// from that sensor in the affected window is suspect, including
    /// conclusions that favoured the agent under watch.
    SensorTampered,
    /// A sensor with declared coverage has gone silent past its liveness
    /// deadline. Not proof anything happened during the gap — only that the
    /// sentinel's "no ghost" for that window is an absence of attestation,
    /// not a checked absence of ghosts.
    CoverageGap,
    /// Bytes left the trust boundary for a destination the declared egress
    /// policy never approved — the exfiltration and network-pivot signature,
    /// the shape of the July 2026 frontier-lab escapes.
    UnauthorizedEgress,
    /// A process was spawned whose command the declared spawn policy never
    /// approved — an agent reaching for the shell outside its sanctioned set.
    UnauthorizedProcessSpawn,
    /// The sentinel's own chain does not continue from where its archive says
    /// it left off: it restarted into amnesia, resumed from a rolled-back
    /// state, or adopted a head it never sealed. Not a claim about any agent
    /// — a warning that this patrol's conclusions rest on a record that
    /// cannot account for itself, so a clean report from it means less than
    /// a clean report normally would.
    SentinelContinuityBreak,
}

impl FindingKind {
    /// The wire vocabulary.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnattributedEffect => "UNATTRIBUTED_EFFECT",
            Self::AnonymousEffect => "ANONYMOUS_EFFECT",
            Self::UnregisteredAgent => "UNREGISTERED_AGENT",
            Self::IdentityFork => "IDENTITY_FORK",
            Self::LedgerBreak => "LEDGER_BREAK",
            Self::ModelDrift => "MODEL_DRIFT",
            Self::ScopeProbing => "SCOPE_PROBING",
            Self::LivenessLost => "LIVENESS_LOST",
            Self::TemporalAnomaly => "TEMPORAL_ANOMALY",
            Self::PhantomEvidence => "PHANTOM_EVIDENCE",
            Self::UnprovenPrincipal => "UNPROVEN_PRINCIPAL",
            Self::SensorTampered => "SENSOR_TAMPERED",
            Self::CoverageGap => "COVERAGE_GAP",
            Self::UnauthorizedEgress => "UNAUTHORIZED_EGRESS",
            Self::UnauthorizedProcessSpawn => "UNAUTHORIZED_PROCESS_SPAWN",
            Self::SentinelContinuityBreak => "SENTINEL_CONTINUITY_BREAK",
        }
    }
}

/// How well the conclusion is supported. Ordered: `Indicator < Corroborated
/// < Proof`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength {
    /// A heuristic or statistical signal. Worth a human's attention; never
    /// worth an automatic sanction on its own.
    Indicator,
    /// Independent signals agree, or a trusted sensor supports it — but the
    /// conclusion still rests on a judgement somewhere.
    Corroborated,
    /// Follows from arithmetic on data the sentinel holds. A hash that does
    /// not recompute is not an opinion.
    Proof,
}

impl Strength {
    /// The wire vocabulary.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Indicator => "INDICATOR",
            Self::Corroborated => "CORROBORATED",
            Self::Proof => "PROOF",
        }
    }
}

/// How bad it is if true. Ordered: `Low < Medium < High < Critical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Note it.
    Low,
    /// Worth a look.
    Medium,
    /// Something is wrong.
    High,
    /// Containment is the priority.
    Critical,
}

impl Severity {
    /// The wire vocabulary.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

/// A single conclusion, with everything needed to check it independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// What was found.
    pub kind: FindingKind,
    /// How well it is supported.
    pub strength: Strength,
    /// How bad it is if true.
    pub severity: Severity,
    /// The agent it concerns, when one can be named. `None` for effects with
    /// no identity behind them — which is itself the finding.
    pub subject_did: Option<String>,
    /// One line an operator can act on.
    pub summary: String,
    /// Citations: observation ids, packet hashes, anchor ids. A finding that
    /// cannot be re-derived from its citations is not evidence, it is an
    /// assertion, so this is never empty for anything above `Indicator`.
    pub evidence: Vec<String>,
    /// Which detector produced it.
    pub detector: String,
    /// ISO-8601 UTC.
    pub detected_at_utc: String,
}

impl Finding {
    /// A finding with no citations yet.
    pub fn new(
        kind: FindingKind,
        strength: Strength,
        severity: Severity,
        detector: impl Into<String>,
        detected_at_utc: impl Into<String>,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            strength,
            severity,
            subject_did: None,
            summary: summary.into(),
            evidence: Vec::new(),
            detector: detector.into(),
            detected_at_utc: detected_at_utc.into(),
        }
    }

    /// Names the agent this concerns.
    pub fn about(mut self, did: impl Into<String>) -> Self {
        self.subject_did = Some(did.into());
        self
    }

    /// Adds citations.
    pub fn citing(mut self, evidence: impl IntoIterator<Item = String>) -> Self {
        self.evidence.extend(evidence);
        self
    }

    /// Downgrades to at most `ceiling`.
    ///
    /// Used where a conclusion would be arithmetic but rests on a sensor the
    /// operator has not vouched for: the reasoning is sound, the input is not
    /// established, so the claim is capped rather than discarded.
    pub fn capped_at(mut self, ceiling: Strength) -> Self {
        self.strength = self.strength.min(ceiling);
        self
    }

    /// The canonical JSON shape written into the ledger.
    pub fn to_json(&self) -> Value {
        let mut out = json!({
            "kind": self.kind.as_str(),
            "strength": self.strength.as_str(),
            "severity": self.severity.as_str(),
            "summary": self.summary,
            "evidence": self.evidence,
            "detector": self.detector,
            "detectedAtUtc": self.detected_at_utc,
        });
        if let Some(did) = &self.subject_did {
            out["subjectDid"] = json!(did);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strength_and_severity_order_from_weakest_to_strongest() {
        assert!(Strength::Proof > Strength::Corroborated);
        assert!(Strength::Corroborated > Strength::Indicator);
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
    }

    #[test]
    fn capping_lowers_a_claim_but_never_raises_one() {
        let proof = || {
            Finding::new(
                FindingKind::UnattributedEffect,
                Strength::Proof,
                Severity::Critical,
                "d",
                "t",
                "s",
            )
        };
        // An untrusted sensor caps arithmetic down to a lead.
        assert_eq!(
            proof().capped_at(Strength::Corroborated).strength,
            Strength::Corroborated
        );
        // Capping at something higher than the claim leaves it alone: a cap
        // must never be a way to promote a weak finding.
        let weak = Finding::new(
            FindingKind::ScopeProbing,
            Strength::Indicator,
            Severity::Low,
            "d",
            "t",
            "s",
        );
        assert_eq!(
            weak.capped_at(Strength::Proof).strength,
            Strength::Indicator
        );
    }

    #[test]
    fn a_finding_serializes_with_its_citations_intact() {
        let f = Finding::new(
            FindingKind::IdentityFork,
            Strength::Proof,
            Severity::Critical,
            "chain-fork",
            "2026-08-27T00:00:00.000Z",
            "chain branched",
        )
        .about("did:syntriass:agent:AGT-1")
        .citing(["packet:aaaa".to_string(), "packet:bbbb".to_string()]);

        let json = f.to_json();
        assert_eq!(json["kind"], "IDENTITY_FORK");
        assert_eq!(json["strength"], "PROOF");
        assert_eq!(json["subjectDid"], "did:syntriass:agent:AGT-1");
        assert_eq!(json["evidence"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn a_finding_about_nobody_omits_the_subject_rather_than_inventing_one() {
        let f = Finding::new(
            FindingKind::AnonymousEffect,
            Strength::Proof,
            Severity::Critical,
            "reconcile",
            "t",
            "something acted unnamed",
        );
        assert!(f.to_json().get("subjectDid").is_none());
    }
}
