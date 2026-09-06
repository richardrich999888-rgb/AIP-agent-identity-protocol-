//! AIRI — the Vanian Autonomous Intelligence Runtime Interface.
//!
//! # What this crate is
//!
//! A framework-neutral record of what an AI agent's own runtime *says* it
//! did: which model it asked for, which tool it invoked, with which
//! parameters, under which authorization, in which process. One schema
//! covers LangChain, LangGraph, LlamaIndex, AutoGen, CrewAI, OpenAI-style
//! tool calling and bespoke runtimes; adapters are thin translators into
//! these types and are never trust anchors.
//!
//! # What this crate is not
//!
//! **An AIRI event is not evidence that anything happened.** It is evidence
//! that the agent said so. The signing key belongs to the agent, the clock
//! belongs to the agent, and the process that emits the event is the process
//! under scrutiny. Every guarantee here is of the form "this statement was
//! made by this agent about this execution and has not been altered since" —
//! never "this occurred".
//!
//! That distinction is enforced structurally, not by convention:
//!
//! * There is no constructor, field, or enum variant anywhere in this crate
//!   by which an event can describe itself as independently observed.
//! * [`Corroboration::Corroborated`] — the one value that says independent
//!   evidence agreed — carries a [`CorroborationSeal`] whose field is
//!   private and whose only constructor is `pub(crate)`. It can be produced
//!   solely by [`corroborate`], after comparing the claim against attested
//!   observer batches. No adapter, SDK or caller can hand one in.
//! * [`corroborate`] returns a *narrowing* input to the existing reconciler.
//!   It contains no code that writes a `ReconciliationResult` or an
//!   `EvidenceStrength`, so it cannot turn `CANNOT_PROVE` into anything else.
//!
//! # Where AIRI sits
//!
//! ```text
//!   AIP Identity → Authority → Authorization → ExpectedExecution
//!                                                    │
//!                            ┌───────────────────────┴──────────────┐
//!                            │                                      │
//!                     ── AIRI (this crate) ──              ── aip-observe ──
//!                     agent-signed, self-authored          collector-signed,
//!                     model / tool / framework             off-host, keyless
//!                     claims                               probe
//!                            │                                      │
//!                            └───────────────┬──────────────────────┘
//!                                            ▼
//!                                   aip-reconcile (unchanged semantics)
//!                                            ▼
//!                              Warrant → Containment → NEXORA
//! ```
//!
//! The two inputs are deliberately asymmetric. Observer evidence is signed
//! by a key the observed host cannot reach. AIRI evidence is signed by the
//! host itself. Reconciliation is where the asymmetry is exploited: an AIRI
//! claim with no corroborating observation is the interesting case, and it
//! is what makes `PHANTOM_CLAIM` reachable at the *AI action* level rather
//! than only at the socket level.
//!
//! # Privacy
//!
//! Prompts, tool arguments, model outputs and credentials never enter an
//! event. Only domain-separated commitments do — see
//! [`parameter_commitment`]. What is committed is decided by the adapter and
//! stated in `docs/architecture/AIRI_LIMITATIONS.md`; this crate refuses to
//! carry the plaintext.

#![forbid(unsafe_code)]

mod chain;
mod corroborate;
mod error;
mod event;
mod ids;
mod integrate;
mod provenance;

pub use chain::{verify_event_chain, ChainDefect, ChainReport, VerifiedChain};
pub use corroborate::{
    corroborate, Corroboration, CorroborationInputs, CorroborationSeal, NotEvaluatedReason,
    UncorroboratedReason,
};
pub use error::AiriError;
pub use event::{
    parameter_commitment, sign_airi_event, verify_airi_event, AiriEvent, AiriEventKind,
    AiriPayload, AIRI_EVENT_DOMAIN, AIRI_EVENT_VERSION,
};
pub use ids::{ExecutionId, InferenceRequestId, ToolCallId};
pub use integrate::{annotate, claims_decision, verdict_of, AiriAnnotation};
pub use provenance::{
    AgentStart, Completion, ContextPropagation, FrameworkIdentity, ModelProvenance,
    PropagationBoundary, ReportedOutcome, SubprocessReport, ToolInvocation, ToolReport,
    AIRI_PARAM_DOMAIN,
};
