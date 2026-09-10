//! The external-effect boundary.
//!
//! This is the part of the model that exists because a successful software
//! call is not an effect, and because saying so in a comment has never once
//! stopped anyone.
//!
//! # The three layers, and the boundary between the second and third
//!
//! ```text
//! RequestedEffect   the agent asked for X          SelfReported
//!       │                                          "I intended to"
//!       ▼
//! RuntimeAction     the call returned Y            SelfReported
//!       │                                          "I called it"
//!       ▼  ─────────── the boundary ───────────
//! EffectEvidence    someone else saw Z             IndependentlyObserved
//! ```
//!
//! A 200 response establishes that bytes resembling a success returned to this
//! process. A proxy, a stub, a replayed cassette, a compromised client library,
//! and a service that acknowledged and then failed all produce the identical
//! value. Layer 2 is reporting on layer 3, which is precisely the boundary it
//! cannot see across.
//!
//! # Enforcement, not documentation
//!
//! [`EffectDisposition::Confirmed`] is **unconstructible from a
//! [`RuntimeAction`] alone**. The only constructor that produces it takes an
//! [`EffectEvidence`], and `EffectEvidence` cannot be built from agent-authored
//! material — its constructor requires an observer identity and an attestation
//! reference that the agent does not hold.
//!
//! This is the same pattern `aip-reconcile` uses for `ActionComparison`'s
//! positive variants: put the invariant in the type system, where forgetting
//! it is a compile error rather than a review miss.
//!
//! # Nothing here is a verdict
//!
//! `EffectDisposition` is a structural fact about what evidence exists for one
//! effect. It is an input to the one reconciliation engine, not a result class,
//! not a severity, and not an accusation. This crate produces no verdicts.

use aip_types::canonical::{put_bytes, put_opt_str, put_str, put_u64, put_u8};
use serde::{Deserialize, Serialize};

use crate::error::ExecutionError;

/// What the agent said it wanted to happen outside the process.
///
/// `SelfReported`, always. An intent is a statement about a mind, and the only
/// party with access to it is the party under scrutiny.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestedEffect {
    /// The action class, in the vocabulary the decision point authorizes over,
    /// so this can be compared with `ExpectedExecution.action_kind` without
    /// knowing the tool.
    pub action_kind: String,
    /// Domain-separated commitment to the full parameter set. Built the same
    /// way `aip-airi` builds one — never a bare SHA-256 of a concatenation.
    pub parameter_commitment: [u8; 32],
    /// Where the effect was expected to land: a host, a table, a control
    /// surface. Context for a human and a join key for an observer; not
    /// authorization.
    pub target: Option<String>,
}

/// What the software layer says came back.
///
/// # The type whose whole job is to not be mistaken for an effect
///
/// `transport_status: Some(200)` is the single most misread value in any
/// accountability system. It lives here, at layer 2, and there is no method on
/// this type that produces a confirmation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeAction {
    /// Repeated from the [`RequestedEffect`] so a report cannot be paired with
    /// a different request.
    pub parameter_commitment: [u8; 32],
    /// Transport-level status the client saw — an HTTP code, an exit status, a
    /// bus acknowledgement.
    pub transport_status: Option<u64>,
    /// Commitment to the response bytes.
    pub result_commitment: Option<[u8; 32]>,
    /// The agent's own clock. Context; never trusted to order or place
    /// anything.
    pub reported_at_ms: u64,
}

/// Independent evidence about an effect.
///
/// # Why this cannot be built by an agent
///
/// The constructor requires an observer identity and a reference to an
/// attestation that observer signed. An agent holds neither. That is the
/// enforcement: not a check that could be skipped, but an input that cannot be
/// supplied from inside the process under scrutiny.
///
/// This type does **not** carry an observer key and does not verify anything.
/// Verification belongs to the existing observer trust model
/// (`aip-observe`), and an observation is evidence only under it. Putting a
/// key here would create a second trust anchor for observation, which is
/// exactly what must not happen.
///
/// # It is a reference, not a proof
///
/// Holding an `EffectEvidence` means an observation was *cited*. Whether that
/// observation exists, was signed by an anchored observer, and says what this
/// reference claims are all questions for `aip-observe` to answer against the
/// attested batch. A reference nothing resolves establishes nothing.
///
/// # Deserialization goes through the constructor
///
/// `#[serde(try_from)]` is load-bearing, not tidiness. Without it, serde
/// builds this struct field by field and an attacker with a JSON writer
/// obtains an evidence value the constructor would have refused — the same
/// bypass class that `aip-system`'s identifiers close.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "EffectEvidenceWire")]
pub struct EffectEvidence {
    /// Which observer attested it. A reference for the existing trust model to
    /// resolve — never a grant of trust by being named here.
    observer_id: String,
    /// The attested batch sequence carrying the observation.
    batch_sequence: u64,
    /// Index of the observation within that batch.
    observation_index: u32,
    /// Whether the observation corroborates or contradicts the request. The
    /// observer's finding, recorded; not this crate's judgement.
    corroborates: bool,
}

impl EffectEvidence {
    /// Build a reference to an independent observation.
    ///
    /// Refuses an empty observer id: an anonymous observation is not an
    /// observation, and a reference nothing can resolve is worse than none.
    pub fn new(
        observer_id: &str,
        batch_sequence: u64,
        observation_index: u32,
        corroborates: bool,
    ) -> Result<Self, ExecutionError> {
        if observer_id.is_empty() || observer_id.len() > 128 {
            return Err(ExecutionError::MalformedEvidence {
                reason: "observer id must be 1-128 bytes",
            });
        }
        Ok(Self {
            observer_id: observer_id.to_owned(),
            batch_sequence,
            observation_index,
            corroborates,
        })
    }

    pub fn observer_id(&self) -> &str {
        &self.observer_id
    }
    pub fn batch_sequence(&self) -> u64 {
        self.batch_sequence
    }
    pub fn observation_index(&self) -> u32 {
        self.observation_index
    }
    pub fn corroborates(&self) -> bool {
        self.corroborates
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        put_str(buf, &self.observer_id);
        put_u64(buf, self.batch_sequence);
        put_u64(buf, self.observation_index as u64);
        put_u8(buf, u8::from(self.corroborates));
    }
}

/// The on-the-wire shape of [`EffectEvidence`], used only as a
/// deserialization staging type so every parsed value passes
/// [`EffectEvidence::new`].
///
/// It exists because serde's derived `Deserialize` would otherwise construct
/// the real type field by field, skipping validation entirely.
#[derive(Deserialize)]
struct EffectEvidenceWire {
    observer_id: String,
    batch_sequence: u64,
    observation_index: u32,
    corroborates: bool,
}

impl TryFrom<EffectEvidenceWire> for EffectEvidence {
    type Error = ExecutionError;
    fn try_from(w: EffectEvidenceWire) -> Result<Self, ExecutionError> {
        EffectEvidence::new(
            &w.observer_id,
            w.batch_sequence,
            w.observation_index,
            w.corroborates,
        )
    }
}

/// What may honestly be said about whether an effect occurred.
///
/// Four states, and the separation between the last two is the same separation
/// `CANNOT_PROVE` exists for: "we looked and did not find it" and "we did not
/// look" are different, and summing them turns a blind spot into a clean bill
/// of health.
///
/// **Not a verdict.** See the module documentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EffectDisposition {
    /// Independent evidence corroborates the requested effect.
    ///
    /// Constructible only through [`EffectOutcome::confirmed`], which requires
    /// an [`EffectEvidence`].
    Confirmed(EffectEvidence),
    /// Independent evidence disagrees with the requested effect.
    Contradicted(EffectEvidence),
    /// Independent observation was available and did not establish the effect.
    Unconfirmed,
    /// No independent observation was available. The default, and the honest
    /// answer for a tool call with a 200 and nothing else.
    NotEvaluated,
}

impl EffectDisposition {
    pub fn code(&self) -> u8 {
        match self {
            Self::Confirmed(_) => 0x01,
            Self::Contradicted(_) => 0x02,
            Self::Unconfirmed => 0x03,
            Self::NotEvaluated => 0x04,
        }
    }

    /// Whether this disposition asserts the effect occurred.
    ///
    /// True only for `Confirmed`. `Unconfirmed` and `NotEvaluated` are both
    /// false, and neither is an assertion that it did *not* occur.
    pub fn asserts_occurrence(&self) -> bool {
        matches!(self, Self::Confirmed(_))
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        put_u8(buf, self.code());
        match self {
            Self::Confirmed(e) | Self::Contradicted(e) => {
                put_u8(buf, 1);
                e.encode(buf);
            }
            Self::Unconfirmed | Self::NotEvaluated => put_u8(buf, 0),
        }
    }
}

/// One effect, from request through runtime report to disposition.
///
/// The constructors are the enforcement. There is no `set_disposition`, and no
/// path from a `RuntimeAction` to `Confirmed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectOutcome {
    pub requested: RequestedEffect,
    /// What the software layer reported, when it reported anything. `None`
    /// when the call did not return — which is itself a fact worth recording.
    pub runtime: Option<RuntimeAction>,
    disposition: EffectDisposition,
}

impl EffectOutcome {
    /// An effect that was requested and, so far as anyone independent knows,
    /// neither confirmed nor refuted.
    ///
    /// This is the constructor a tool adapter uses, and it is deliberately the
    /// only one that takes a `RuntimeAction`. A 200 response reaches
    /// `NotEvaluated` and stops there.
    pub fn reported(requested: RequestedEffect, runtime: RuntimeAction) -> Self {
        Self {
            requested,
            runtime: Some(runtime),
            disposition: EffectDisposition::NotEvaluated,
        }
    }

    /// An effect that was requested with nothing reported back.
    pub fn requested_only(requested: RequestedEffect) -> Self {
        Self {
            requested,
            runtime: None,
            disposition: EffectDisposition::NotEvaluated,
        }
    }

    /// Record that an independent observation ran and did not establish the
    /// effect.
    ///
    /// Distinct from leaving it `NotEvaluated`: this says a verifier looked.
    pub fn unconfirmed(mut self) -> Self {
        self.disposition = EffectDisposition::Unconfirmed;
        self
    }

    /// Attach independent evidence.
    ///
    /// The disposition follows the evidence's own finding — `corroborates`
    /// decides between `Confirmed` and `Contradicted`. The caller does not get
    /// to choose, because a caller that could choose would eventually choose
    /// wrong.
    pub fn with_evidence(mut self, evidence: EffectEvidence) -> Self {
        self.disposition = if evidence.corroborates() {
            EffectDisposition::Confirmed(evidence)
        } else {
            EffectDisposition::Contradicted(evidence)
        };
        self
    }

    /// Read-only. There is no setter: the disposition is a consequence of what
    /// was supplied, never an independent choice.
    pub fn disposition(&self) -> &EffectDisposition {
        &self.disposition
    }

    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        put_str(buf, &self.requested.action_kind);
        put_bytes(buf, &self.requested.parameter_commitment);
        put_opt_str(buf, &self.requested.target);
        match &self.runtime {
            Some(r) => {
                put_u8(buf, 1);
                put_bytes(buf, &r.parameter_commitment);
                match r.transport_status {
                    Some(s) => {
                        put_u8(buf, 1);
                        put_u64(buf, s);
                    }
                    None => put_u8(buf, 0),
                }
                match &r.result_commitment {
                    Some(c) => {
                        put_u8(buf, 1);
                        put_bytes(buf, c);
                    }
                    None => put_u8(buf, 0),
                }
                put_u64(buf, r.reported_at_ms);
            }
            None => put_u8(buf, 0),
        }
        self.disposition.encode(buf);
    }
}
