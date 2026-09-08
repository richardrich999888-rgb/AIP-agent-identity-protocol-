//! The spanning threat model (Skill 29).
//!
//! Thirteen threats × seven layers. Each cell says what that layer does about
//! that threat, and where a layer does nothing it says so with a reason.
//!
//! # The vocabulary has no word for "mitigated"
//!
//! The specification requires every threat to map to *prevention, detection,
//! uncertainty, or explicit non-detectability*, and forbids marking a threat
//! mitigated merely because a log or callback exists. Those two clauses
//! together settle the type: [`Disposition`] has four variants and none of
//! them is `Mitigated`. A reviewer cannot write "mitigated — we log it",
//! because the word does not exist and [`Disposition::Detected`] must name
//! the mechanism that detects.
//!
//! Skill 28 removed `Waived` from the conformance vocabulary for the same
//! reason. The way to guarantee a rule is to leave the type no way to express
//! its violation.
//!
//! # Where a layer does nothing
//!
//! `NotDetectable` with a reason, and — where one applies — the
//! non-establishment (`N-1` … `N-11`) that already said so. Filling a cell
//! with `Prevented` because some *other* layer prevents the threat would be
//! the "mitigated because a log exists" failure one level up.

use serde::{Deserialize, Serialize};

/// A threat the model must answer for. The thirteen the specification names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Threat {
    CompromisedAgent,
    CompromisedFramework,
    CompromisedModelRuntime,
    CompromisedTool,
    CompromisedProcess,
    CompromisedHost,
    ForgedTelemetry,
    LostConnectivity,
    PartialObservation,
    SensorDeception,
    ObserverFailure,
    Replay,
    StaleAuthority,
}

/// The layer answering. Seven, as the specification names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Layer {
    Aip,
    Airi,
    Observation,
    Reconciliation,
    Warrant,
    Containment,
    Nexora,
}

/// What a layer does about a threat.
///
/// Four variants, and deliberately **no `Mitigated`** — see the module note.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Disposition {
    /// The attack cannot be expressed. The strongest answer: not refused at
    /// runtime but unrepresentable, so there is no path to test.
    Prevented,
    /// The attack is expressible and the layer catches it. Must name the
    /// mechanism.
    Detected,
    /// The layer cannot settle the question and says so, reducing what the
    /// system will assert rather than guessing.
    Uncertainty,
    /// The layer does nothing about this threat, stated rather than implied.
    NotDetectable,
}

impl Disposition {
    pub fn code(self) -> u8 {
        match self {
            Self::Prevented => 0x01,
            Self::Detected => 0x02,
            Self::Uncertainty => 0x03,
            Self::NotDetectable => 0x04,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prevented => "PREVENTED",
            Self::Detected => "DETECTED",
            Self::Uncertainty => "UNCERTAINTY",
            Self::NotDetectable => "NOT-DETECTABLE",
        }
    }

    /// Whether this disposition is a *positive* answer — the layer acts.
    ///
    /// `Uncertainty` is not a failure: reducing what the system asserts is the
    /// designed response to missing evidence. It is simply not a defence.
    pub fn is_a_defence(self) -> bool {
        matches!(self, Self::Prevented | Self::Detected)
    }
}

impl Threat {
    pub const ALL: [Threat; 13] = [
        Self::CompromisedAgent,
        Self::CompromisedFramework,
        Self::CompromisedModelRuntime,
        Self::CompromisedTool,
        Self::CompromisedProcess,
        Self::CompromisedHost,
        Self::ForgedTelemetry,
        Self::LostConnectivity,
        Self::PartialObservation,
        Self::SensorDeception,
        Self::ObserverFailure,
        Self::Replay,
        Self::StaleAuthority,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Self::CompromisedAgent => "X01",
            Self::CompromisedFramework => "X02",
            Self::CompromisedModelRuntime => "X03",
            Self::CompromisedTool => "X04",
            Self::CompromisedProcess => "X05",
            Self::CompromisedHost => "X06",
            Self::ForgedTelemetry => "X07",
            Self::LostConnectivity => "X08",
            Self::PartialObservation => "X09",
            Self::SensorDeception => "X10",
            Self::ObserverFailure => "X11",
            Self::Replay => "X12",
            Self::StaleAuthority => "X13",
        }
    }

    /// What the attacker controls. Read this before reading a disposition: a
    /// layer's answer is only meaningful against a stated capability.
    pub fn attacker_controls(self) -> &'static str {
        match self {
            Self::CompromisedAgent => "the agent process and everything it says about itself",
            Self::CompromisedFramework => "the orchestration framework and the events it emits",
            Self::CompromisedModelRuntime => {
                "the inference runtime and its reported model identity"
            }
            Self::CompromisedTool => "the tool or API the agent calls and the response it returns",
            Self::CompromisedProcess => "the process image and its self-reported runtime state",
            Self::CompromisedHost => "root on the observed host, including procfs content",
            Self::ForgedTelemetry => "the content of any self-authored telemetry stream",
            Self::LostConnectivity => "the link between the subject and the verifier",
            Self::PartialObservation => "which events reach the collector, by dropping some",
            Self::SensorDeception => "the physical world the sensor reads, or the device layer",
            Self::ObserverFailure => {
                "the collector's availability, and its own record's continuity"
            }
            Self::Replay => "previously valid signed artifacts, resubmitted",
            Self::StaleAuthority => "an authority that was valid and no longer is",
        }
    }

    /// Whether the model treats this as high-impact. The acceptance gate is
    /// about these: each must have an explicit system response or an explicit
    /// `CANNOT_PROVE` boundary.
    ///
    /// All thirteen are. The field exists so that a future addition has to
    /// state its answer rather than inherit one.
    pub fn is_high_impact(self) -> bool {
        true
    }
}

impl Layer {
    pub const ALL: [Layer; 7] = [
        Self::Aip,
        Self::Airi,
        Self::Observation,
        Self::Reconciliation,
        Self::Warrant,
        Self::Containment,
        Self::Nexora,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aip => "AIP",
            Self::Airi => "AIRI",
            Self::Observation => "Observation",
            Self::Reconciliation => "Reconciliation",
            Self::Warrant => "Warrant",
            Self::Containment => "Containment",
            Self::Nexora => "NEXORA",
        }
    }
}

/// One (threat, layer) answer.
///
/// `Serialize` only, for the reason on [`crate::matrix::Cell`]: this is an
/// output, and a threat model readable back out of bytes would be a statement
/// about what the system does that an author could simply write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ThreatCell {
    pub threat: Threat,
    pub threat_id: &'static str,
    pub layer: Layer,
    pub disposition: Disposition,
    /// The mechanism, when the layer acts; the boundary, when it does not.
    /// Never a prose claim and never empty.
    pub mechanism: &'static str,
    /// The non-establishment that already recorded this limit, when one
    /// applies. `N-1` … `N-11` from `AIRI_LIMITATIONS.md`.
    pub non_establishment: &'static str,
}

/// The whole model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ThreatModel {
    pub schema_version: u16,
    pub cells: Vec<ThreatCell>,
}

impl ThreatModel {
    pub fn build() -> Self {
        let mut cells = Vec::with_capacity(Threat::ALL.len() * Layer::ALL.len());
        for t in Threat::ALL {
            for l in Layer::ALL {
                let (disposition, mechanism, non_establishment) = answer(t, l);
                cells.push(ThreatCell {
                    threat: t,
                    threat_id: t.id(),
                    layer: l,
                    disposition,
                    mechanism,
                    non_establishment,
                });
            }
        }
        Self {
            schema_version: crate::CONFORMANCE_SCHEMA_VERSION,
            cells,
        }
    }

    pub fn get(&self, t: Threat, l: Layer) -> Option<&ThreatCell> {
        self.cells.iter().find(|c| c.threat == t && c.layer == l)
    }

    pub fn missing(&self) -> Vec<(Threat, Layer)> {
        let mut out = Vec::new();
        for t in Threat::ALL {
            for l in Layer::ALL {
                if self.get(t, l).is_none() {
                    out.push((t, l));
                }
            }
        }
        out
    }

    /// Threats with no defending layer at all.
    ///
    /// Not necessarily a failure — the acceptance gate accepts an explicit
    /// `CANNOT_PROVE` boundary as a response — but a threat that reaches this
    /// list is one whose only answer is "the system reduces what it asserts",
    /// and a reader should know which ones those are.
    pub fn threats_with_no_defence(&self) -> Vec<Threat> {
        Threat::ALL
            .into_iter()
            .filter(|t| {
                !self
                    .cells
                    .iter()
                    .any(|c| c.threat == *t && c.disposition.is_a_defence())
            })
            .collect()
    }

    /// Threats answered by neither a defence nor a stated uncertainty — the
    /// acceptance gate's failure condition. Must always be empty.
    pub fn threats_with_no_answer(&self) -> Vec<Threat> {
        Threat::ALL
            .into_iter()
            .filter(|t| {
                !self.cells.iter().any(|c| {
                    c.threat == *t
                        && (c.disposition.is_a_defence()
                            || c.disposition == Disposition::Uncertainty)
                })
            })
            .collect()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("threat model is plain data")
    }

    pub fn to_csv(&self) -> String {
        let mut s = String::from(
            "THREAT,THREAT_ID,ATTACKER_CONTROLS,LAYER,DISPOSITION,MECHANISM,NON_ESTABLISHMENT\n",
        );
        for c in &self.cells {
            let row = [
                format!("{:?}", c.threat),
                c.threat_id.to_string(),
                c.threat.attacker_controls().to_string(),
                c.layer.as_str().to_string(),
                c.disposition.as_str().to_string(),
                c.mechanism.to_string(),
                c.non_establishment.to_string(),
            ];
            let cols: Vec<String> = row.iter().map(|f| crate::matrix::csv_field(f)).collect();
            s.push_str(&cols.join(","));
            s.push('\n');
        }
        s
    }
}

/// What one layer does about one threat.
///
/// The rule applied uniformly, so a reader can check a cell rather than trust
/// it: **`Prevented`** means the attack is not expressible against this layer;
/// **`Detected`** means this layer's own code refuses or flags it, and the
/// mechanism names where; **`Uncertainty`** means the layer reduces what it
/// will assert; **`NotDetectable`** means this layer does nothing about this
/// threat, which is stated rather than filled in with another layer's answer.
fn answer(t: Threat, l: Layer) -> (Disposition, &'static str, &'static str) {
    use Disposition::*;
    use Layer::*;
    use Threat::*;

    match (t, l) {
        // ── X01 Compromised agent ─────────────────────────────────────
        (CompromisedAgent, Aip) => (
            Prevented,
            "an AIP-ID is derived from a key and provenance; an agent cannot sign as another identity without that key",
            "",
        ),
        (CompromisedAgent, Airi) => (
            NotDetectable,
            "AIRI is the agent's own account of itself; a compromised agent emits whatever it likes and the events remain well-formed",
            "N-1",
        ),
        (CompromisedAgent, Observation) => (
            Detected,
            "the collector runs off-host under its own key; the agent cannot write the observer's record",
            "",
        ),
        (CompromisedAgent, Reconciliation) => (
            Detected,
            "a claim with no matching observation under kernel-pushed coverage is PhantomClaim; without that coverage it is CANNOT_PROVE",
            "",
        ),
        (CompromisedAgent, Warrant) => (
            NotDetectable,
            "the warrant gate consumes a verdict and detects nothing itself",
            "",
        ),
        (CompromisedAgent, Containment) => (
            NotDetectable,
            "containment acts on a warrant and detects nothing itself",
            "",
        ),
        (CompromisedAgent, Nexora) => (
            Detected,
            "the verifier re-derives the claim from the package's own inputs; a verdict the agent wrote is not derivable",
            "",
        ),

        // ── X02 Compromised framework ─────────────────────────────────
        (CompromisedFramework, Aip) => (
            NotDetectable,
            "AIP knows nothing of frameworks; a framework name is not an identity",
            "",
        ),
        (CompromisedFramework, Airi) => (
            Uncertainty,
            "FrameworkIdentity is data, never a trust input; framework_grants_authority() is non-overridable and returns false, so a compromised framework changes no standing — and AIRI feeds no verdict at all, the reconciler having no dependency on it",
            "N-1, N-11",
        ),
        (CompromisedFramework, Observation) => (
            Detected,
            "the observer watches the process, not the framework; a framework's account does not enter the observed record",
            "",
        ),
        (CompromisedFramework, Reconciliation) => (
            Detected,
            "framework events are claims; corroboration requires an independent observation of the same instance",
            "",
        ),
        (CompromisedFramework, Warrant) => (NotDetectable, "consumes a verdict", ""),
        (CompromisedFramework, Containment) => (NotDetectable, "acts on a warrant", ""),
        (CompromisedFramework, Nexora) => (
            Detected,
            "a relabelled framework event fails verification; the AIRI bundle is re-walked from the package's own bytes",
            "",
        ),

        // ── X03 Compromised model runtime ─────────────────────────────
        (CompromisedModelRuntime, Aip) => (NotDetectable, "AIP does not model inference", ""),
        (CompromisedModelRuntime, Airi) => (
            Uncertainty,
            "model identity is recorded as declared, not as verified; a hosted API returns an unverifiable identifier and a weight digest describes a file, not runtime memory",
            "N-3, N-4",
        ),
        (CompromisedModelRuntime, Observation) => (
            NotDetectable,
            "no implemented mechanism observes accelerator or kernel execution; framework telemetry is still framework telemetry",
            "N-5",
        ),
        (CompromisedModelRuntime, Reconciliation) => (
            Uncertainty,
            "a model invocation is never corroborated by a host observer; the question is refused rather than answered",
            "N-5",
        ),
        (CompromisedModelRuntime, Warrant) => (NotDetectable, "consumes a verdict", ""),
        (CompromisedModelRuntime, Containment) => (NotDetectable, "acts on a warrant", ""),
        (CompromisedModelRuntime, Nexora) => (
            Detected,
            "model provenance is bound to the execution event; a transplanted model event fails verification",
            "",
        ),

        // ── X04 Compromised tool ──────────────────────────────────────
        (CompromisedTool, Aip) => (NotDetectable, "AIP does not model tool endpoints", ""),
        (CompromisedTool, Airi) => (
            Uncertainty,
            "requested invocation, runtime execution and external effect are three separate records; a successful response is none of the other two, and a gateway's own report is not authoritative because its key lifecycle and transport are undefined",
            "N-2, N-9",
        ),
        (CompromisedTool, Observation) => (
            Detected,
            "the local half is observable — a socket is ProcNetTable, a file write is Fanotify — and the observer sees what the host did regardless of what the tool returned",
            "",
        ),
        (CompromisedTool, Reconciliation) => (
            Uncertainty,
            "a successful tool response is not evidence the external effect landed; the remote half stops at CANNOT_PROVE",
            "N-2",
        ),
        (CompromisedTool, Warrant) => (NotDetectable, "consumes a verdict", ""),
        (CompromisedTool, Containment) => (NotDetectable, "acts on a warrant", ""),
        (CompromisedTool, Nexora) => (
            Detected,
            "a tool event transplanted to another agent or execution fails verification",
            "",
        ),

        // ── X05 Compromised process ───────────────────────────────────
        (CompromisedProcess, Aip) => (
            Prevented,
            "execution identity is the process instance plus the executable's content; a different binary is a different identity and cannot be asserted into",
            "",
        ),
        (CompromisedProcess, Airi) => (
            NotDetectable,
            "runtime_binding is self-reported; a compromised process can report its real pid and lie about everything else",
            "N-8",
        ),
        (CompromisedProcess, Observation) => (
            Detected,
            "the collector measures pid, start ticks, boot id and exe content itself rather than accepting them",
            "",
        ),
        (CompromisedProcess, Reconciliation) => (
            Detected,
            "a divergent instance under one decision is IdentityDivergence; PID reuse never matches",
            "",
        ),
        (CompromisedProcess, Warrant) => (NotDetectable, "consumes a verdict", ""),
        (CompromisedProcess, Containment) => (NotDetectable, "acts on a warrant", ""),
        (CompromisedProcess, Nexora) => (
            Detected,
            "the binding is inside the signed expectation; a package whose components are not bound to one another is refused",
            "",
        ),

        // ── X06 Compromised host (root) ───────────────────────────────
        (CompromisedHost, Aip) => (
            Uncertainty,
            "a key on a rooted host is a key the attacker holds; AIP establishes what was signed, not who was in control",
            "",
        ),
        (CompromisedHost, Airi) => (NotDetectable, "every self-report on the host is the attacker's", "N-1"),
        (CompromisedHost, Observation) => (
            Uncertainty,
            "content measured from the observed host is root-forgeable, so every such class is capped at Attested rather than Proven; the collector's own key is off-host",
            "",
        ),
        (CompromisedHost, Reconciliation) => (
            Uncertainty,
            "the Attested ceiling is why no host-content verdict reaches Proven; the limit is declared per ObservationClass, not computed",
            "",
        ),
        (CompromisedHost, Warrant) => (
            Detected,
            "containment requires Proven, which no root-forgeable class reaches; the gate refuses rather than acting on host-controlled content",
            "",
        ),
        (CompromisedHost, Containment) => (
            Prevented,
            "actuation is unreachable from any verdict a rooted host could manufacture; see blocker B-3, which records that it is unreachable from genuine reconciliation too",
            "",
        ),
        (CompromisedHost, Nexora) => (
            Detected,
            "anchors are the verifier's, not the package's; a head signed under an unanchored key is refused",
            "",
        ),

        // ── X07 Forged telemetry ──────────────────────────────────────
        (ForgedTelemetry, Aip) => (
            Prevented,
            "telemetry is not an identity; nothing in AIP consumes it",
            "",
        ),
        (ForgedTelemetry, Airi) => (
            NotDetectable,
            "AIRI records what was reported; forging it produces well-formed self-report, which is what AIRI is",
            "N-1",
        ),
        (ForgedTelemetry, Observation) => (
            Detected,
            "an observation is signed by the collector; edited bytes break the attestation",
            "",
        ),
        (ForgedTelemetry, Reconciliation) => (
            Detected,
            "tampered observer bytes are SensorIntegrityFailure at Proven — an arithmetic statement about the observer's record",
            "",
        ),
        (ForgedTelemetry, Warrant) => (NotDetectable, "consumes a verdict", ""),
        (ForgedTelemetry, Containment) => (NotDetectable, "acts on a warrant", ""),
        (ForgedTelemetry, Nexora) => (
            Detected,
            "every carried component is verified under the verifier's own anchors before any of it is credited",
            "",
        ),

        // ── X08 Lost connectivity ─────────────────────────────────────
        (LostConnectivity, Aip) => (
            NotDetectable,
            "identity and authority are offline artifacts; connectivity changes nothing about them",
            "",
        ),
        (LostConnectivity, Airi) => (
            NotDetectable,
            "AIRI events queue locally; their standing is unchanged by the link",
            "",
        ),
        (LostConnectivity, Observation) => (
            Detected,
            "the collector's sequence and head chain are continuous across a link outage; a gap in the chain is visible whether or not the link was up",
            "",
        ),
        (LostConnectivity, Reconciliation) => (
            Uncertainty,
            "delayed arrival is never non-occurrence; a window with no evidence yet is CANNOT_PROVE, not an absence claim",
            "N-6",
        ),
        (LostConnectivity, Warrant) => (NotDetectable, "consumes a verdict", ""),
        (LostConnectivity, Containment) => (NotDetectable, "acts on a warrant", ""),
        (LostConnectivity, Nexora) => (
            Detected,
            "a proof package verifies offline against anchors the verifier holds; no network is required and none is trusted",
            "",
        ),

        // ── X09 Partial observation ───────────────────────────────────
        (PartialObservation, Aip) => (NotDetectable, "AIP observes nothing", ""),
        (PartialObservation, Airi) => (
            NotDetectable,
            "an agent that reports only some of what it did leaves an intact chain; silence is not visible from AIRI",
            "N-6",
        ),
        (PartialObservation, Observation) => (
            Detected,
            "dropped events are counted and the count is inside the signed batch; a withheld tail batch disagrees with the signed health record's head",
            "N-7",
        ),
        (PartialObservation, Reconciliation) => (
            Uncertainty,
            "an incomplete observation set is CANNOT_PROVE naming the gap; a non-occurrence claim additionally requires kernel-pushed coverage across the whole window",
            "",
        ),
        (PartialObservation, Warrant) => (NotDetectable, "consumes a verdict", ""),
        (PartialObservation, Containment) => (NotDetectable, "acts on a warrant", ""),
        (PartialObservation, Nexora) => (
            Detected,
            "a claim citing evidence the package does not carry is a structural fault and the package is refused",
            "",
        ),

        // ── X10 Sensor deception ──────────────────────────────────────
        (SensorDeception, Aip) => (NotDetectable, "AIP models no sensor", ""),
        (SensorDeception, Airi) => (NotDetectable, "AIRI models no sensor", ""),
        (SensorDeception, Observation) => (
            Uncertainty,
            "a sensor reading is content read from a device and is root-forgeable exactly as procfs is; the physical-effect class is declared and has no implemented mechanism at all",
            "",
        ),
        (SensorDeception, Reconciliation) => (
            Uncertainty,
            "no verdict rests on a physical quantity; the top evidence tier of every embodied profile is unreachable",
            "",
        ),
        (SensorDeception, Warrant) => (NotDetectable, "consumes a verdict", ""),
        (SensorDeception, Containment) => (NotDetectable, "acts on a warrant", ""),
        (SensorDeception, Nexora) => (
            NotDetectable,
            "NEXORA commits to what it was given; a deceived sensor produces a faithfully committed false reading",
            "",
        ),

        // ── X11 Observer failure ──────────────────────────────────────
        (ObserverFailure, Aip) => (NotDetectable, "AIP does not model the observer", ""),
        (ObserverFailure, Airi) => (NotDetectable, "AIRI does not model the observer", ""),
        (ObserverFailure, Observation) => (
            Detected,
            "the collector signs its own state — Degraded, Recovering, ContinuityUnverified, Quarantined, IntegrityUnknown — and a fork at one sequence under one key is arithmetic anyone can recompute",
            "",
        ),
        (ObserverFailure, Reconciliation) => (
            Detected,
            "a quarantined observer yields SensorIntegrityFailure and a broken chain yields ContinuityFailure; both accuse the observer and neither accuses the workload",
            "",
        ),
        (ObserverFailure, Warrant) => (
            Detected,
            "SensorIntegrityFailure is named by the gate and refused as a containment basis; the one verdict strong enough to clear the strength gate is by its nature a verdict about missing observation",
            "",
        ),
        (ObserverFailure, Containment) => (NotDetectable, "acts on a warrant", ""),
        (ObserverFailure, Nexora) => (
            Detected,
            "a continuity report is the collector's own signed statement that its record broke; the verifier carries it and never softens a break into continuity",
            "",
        ),

        // ── X12 Replay ────────────────────────────────────────────────
        (Replay, Aip) => (
            Detected,
            "tokens carry signed issuance and expiry; a replayed token is bounded by its own signature",
            "",
        ),
        (Replay, Airi) => (
            Uncertainty,
            "a replayed framework event is well-formed self-report; AIRI alone cannot distinguish it from the original",
            "N-1",
        ),
        (Replay, Observation) => (
            Detected,
            "a batch at an already-consumed sequence is Replay; a different head at the same sequence is Fork and quarantines permanently",
            "",
        ),
        (Replay, Reconciliation) => (
            Detected,
            "duplicate attested batches are collapsed and the record carries replay_detected",
            "",
        ),
        (Replay, Warrant) => (NotDetectable, "consumes a verdict", ""),
        (Replay, Containment) => (
            Detected,
            "containment consults a replay ledger before acting, so one warrant cannot actuate twice",
            "",
        ),
        (Replay, Nexora) => (
            Detected,
            "a proof id is recorded on first submission; a second submission changes nothing and grants nothing",
            "",
        ),

        // ── X13 Stale authority ───────────────────────────────────────
        (StaleAuthority, Aip) => (
            Prevented,
            "expiry is inside the signature on both ScopedToken and DelegationToken; mutating it invalidates the token rather than extending it",
            "",
        ),
        (StaleAuthority, Airi) => (
            NotDetectable,
            "AIRI carries no authority and cannot assess one",
            "",
        ),
        (StaleAuthority, Observation) => (
            NotDetectable,
            "the observer records what happened, not whether it was permitted",
            "",
        ),
        (StaleAuthority, Reconciliation) => (
            Detected,
            "an expectation outside its window is refused, and action evidence preceding its authorization does not verify the execution",
            "",
        ),
        (StaleAuthority, Warrant) => (NotDetectable, "consumes a verdict", ""),
        (StaleAuthority, Containment) => (NotDetectable, "acts on a warrant", ""),
        (StaleAuthority, Nexora) => (
            Detected,
            "AuthorityStanding is assessed at the verifier's present time and reported as StaleSince; a stale authority is a fact about now and the proof is a statement about then",
            "",
        ),
    }
}
