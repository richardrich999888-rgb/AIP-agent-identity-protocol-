//! Corroboration: comparing what the agent said with what the observer saw.
//!
//! # The one job
//!
//! An AIRI claim and an observer batch are asymmetric on purpose. The claim
//! is signed by the agent — the party under scrutiny, which holds its own
//! key and reads its own clock. The batch is signed by a collector the
//! observed host cannot reach. This module is where that asymmetry is spent:
//! it asks whether independent evidence *covering the same window and the
//! same process instance* is consistent with the claim.
//!
//! # What it deliberately cannot do
//!
//! This module contains no code that writes a `ReconciliationResult` or an
//! `EvidenceStrength`. Not as policy — there is no statement here that could.
//! [`Corroboration`] is an input to `aip_reconcile`, and every precondition
//! in that crate's `precondition_holds` is unchanged by this one. In
//! particular:
//!
//! * A `Corroborated` outcome does not make a verdict `VerifiedExecution`.
//!   That still requires the reconciler's own sealed action match, its own
//!   identity match, and its own continuity flag, at `Attested` exactly.
//! * A `Corroborated` outcome can never reach `Proven`. `Proven` is reserved
//!   for facts a third party recomputes from held bytes — signature and
//!   chain arithmetic. Corroboration compares *content*, and content read
//!   from the observed host is root-forgeable.
//! * `NotEvaluated` is the default and the answer whenever the observer did
//!   not cover the claim. Absence of observation is not absence of the act.
//!
//! # The epistemically valuable direction
//!
//! [`Corroboration::Uncorroborated`] — the observer *did* cover the window
//! and the instance, and saw nothing matching — is what this module exists
//! for. It is the AI-stack analogue of a phantom claim: the agent says it
//! called a payments API; the observer, watching that process instance
//! throughout, recorded no socket transition at all. Neither half alone says
//! anything. Together they do.

use aip_authorize::ExpectedExecution;
use aip_observe::{AttestedBatch, CoverageWindow, ObservationAvailability};

use crate::event::{AiriEvent, AiriEventKind, AiriPayload};

/// Proof that [`corroborate`] compared a claim against observer evidence.
///
/// `#[non_exhaustive]` forbids struct-literal construction outside this
/// crate, so a caller cannot hand in a corroboration it did not earn. Same
/// guarantee as `aip_reconcile`'s action-evidence seal: a value meaning
/// "independent evidence agreed" must be unforgeable by the party it
/// exonerates. [`corroborate`] is the only producer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CorroborationSeal {
    /// Sequence numbers of the attested batches that carried the match.
    pub batch_sequences: Vec<u64>,
    /// The window over which the comparison was made.
    pub window: CoverageWindow,
}

impl CorroborationSeal {
    pub(crate) fn new(batch_sequences: Vec<u64>, window: CoverageWindow) -> Self {
        Self {
            batch_sequences,
            window,
        }
    }
}

/// Why a claim covered by observation still failed to corroborate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UncorroboratedReason {
    /// The observer covered the window and the instance and recorded no
    /// observation of the claimed action class. The phantom-claim shape.
    NoMatchingObservation,
    /// Observations exist for the instance, but none of the claimed class.
    ActionClassAbsent { claimed: String },
    /// The claim names a process instance no observation refers to.
    InstanceNotObserved,
}

/// Why a claim was not evaluated at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotEvaluatedReason {
    /// No observer evidence was supplied.
    NoObserverEvidence,
    /// The observer declared itself unavailable over the window.
    ObserverUnavailable,
    /// The claim carries no runtime binding, so there is no instance to
    /// compare against. Self-reported bindings are weak evidence, but their
    /// *absence* removes the join key entirely.
    NoRuntimeBinding,
    /// The event kind makes no claim about anything externally observable.
    /// A model invocation to a hosted API, a context propagation, or a
    /// completion has no host-observable signature of its own.
    NotExternallyObservable { kind: AiriEventKind },
    /// Observer evidence exists but none of it overlaps the claim's window.
    WindowNotCovered,
    /// The claimed action class has no mapping onto anything this build
    /// knows how to observe. Not a finding in either direction.
    ActionClassNotComparable { claimed: String },
}

/// The outcome of comparing one AIRI claim with independent observation.
///
/// `NotEvaluated` is the [`Default`]: absence of evidence yields no finding,
/// matching the reconciler's own default of `CannotProve`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Corroboration {
    /// Not compared. Carries why, so a reader is never left guessing whether
    /// the silence means "clean" or "we did not look".
    NotEvaluated(NotEvaluatedReason),
    /// Independent evidence covering the window and the instance is
    /// consistent with the claim.
    ///
    /// This is **not** a verdict and not a strength. It is one input the
    /// reconciler may use, subject to every precondition it already applies.
    Corroborated(CorroborationSeal),
    /// The observer covered the claim and did not see it.
    Uncorroborated {
        reason: UncorroboratedReason,
        window: CoverageWindow,
    },
    /// The observer saw something the claim contradicts — an instance
    /// mismatch between what the agent reported and what was measured.
    Contradicted { detail: String },
}

impl Default for Corroboration {
    fn default() -> Self {
        Self::NotEvaluated(NotEvaluatedReason::NoObserverEvidence)
    }
}

impl Corroboration {
    /// Did independent evidence agree? False for every other outcome,
    /// including `NotEvaluated` — a caller that treats "we did not look" as
    /// "nothing wrong" gets `false` here.
    pub fn is_corroborated(&self) -> bool {
        matches!(self, Self::Corroborated(_))
    }

    /// Did the observer cover this claim and fail to see it? This is the
    /// finding worth escalating, not `is_corroborated() == false`.
    pub fn is_uncorroborated(&self) -> bool {
        matches!(self, Self::Uncorroborated { .. })
    }
}

/// Everything [`corroborate`] needs. Each field is supplied by the verifier;
/// nothing is read from a clock, a file, or the network.
pub struct CorroborationInputs<'a> {
    /// The claim under examination. The caller must have verified its
    /// signature already — [`corroborate`] re-checks nothing about
    /// authorship, only about agreement.
    pub event: &'a AiriEvent,
    /// Observer batches the verifier holds and has already verified through
    /// `aip_observe::verify_attested_batch`.
    pub batches: &'a [&'a AttestedBatch],
    /// What the observer says about its own coverage of the window.
    pub availability: &'a ObservationAvailability,
    /// The authorization the claim runs under, when the verifier has it.
    pub expectation: Option<&'a ExpectedExecution>,
    /// Slack applied when comparing claimed times with observed windows.
    pub window_tolerance_ms: u64,
}

/// Compare one AIRI claim with the independent evidence the verifier holds.
///
/// # Order
///
/// 1. Is this kind of claim externally observable at all? If not,
///    `NotEvaluated` — and that is the honest answer, not a failure.
/// 2. Is there a runtime binding to join on? If not, `NotEvaluated`.
/// 3. Did the observer declare coverage? If not, `NotEvaluated`.
/// 4. Do any batches overlap the window? If not, `NotEvaluated`.
/// 5. Does any observation refer to the claimed instance? If none does, the
///    claim is `Uncorroborated` — the observer was watching and saw nothing.
/// 6. Does any observation match the claimed action class? If not,
///    `Uncorroborated`; if yes, `Corroborated`.
///
/// A step that cannot be completed stops at `NotEvaluated` rather than
/// falling through to a stronger answer. The failure direction is always
/// toward "we cannot say".
pub fn corroborate(inputs: &CorroborationInputs<'_>) -> Corroboration {
    use Corroboration as C;
    use NotEvaluatedReason as N;

    let ev = inputs.event;

    // 1. Only claims about host-observable acts can be corroborated by a
    //    host observer. A hosted-model inference leaves no local signature
    //    beyond a socket, and the socket belongs to the tool layer.
    if !is_externally_observable(ev.kind()) {
        return C::NotEvaluated(N::NotExternallyObservable { kind: ev.kind() });
    }

    // 2. Without a binding there is no instance to join on.
    let Some(binding) = &ev.runtime_binding else {
        return C::NotEvaluated(N::NoRuntimeBinding);
    };

    // 3. The observer's own statement about coverage.
    let window = match inputs.availability {
        ObservationAvailability::Covered { window } => *window,
        ObservationAvailability::Unavailable { .. } => {
            return C::NotEvaluated(N::ObserverUnavailable)
        }
    };

    if inputs.batches.is_empty() {
        return C::NotEvaluated(N::NoObserverEvidence);
    }

    // 4. Batches must actually overlap the coverage window.
    let overlapping: Vec<&&AttestedBatch> = inputs
        .batches
        .iter()
        .filter(|b| batch_overlaps(b, &window, inputs.window_tolerance_ms))
        .collect();
    if overlapping.is_empty() {
        return C::NotEvaluated(N::WindowNotCovered);
    }

    // 5. Does any observation refer to the instance the agent claims to be?
    let Some(claimed) = claimed_action_class(&ev.payload) else {
        return C::NotEvaluated(N::NotExternallyObservable { kind: ev.kind() });
    };
    // An action class this build cannot map is not comparable. Returning
    // `Uncorroborated` here would manufacture a phantom claim out of a
    // vocabulary gap, which is the worst possible false positive.
    let Some(class) = observable_class_of(&claimed) else {
        return C::NotEvaluated(N::ActionClassNotComparable { claimed });
    };

    let mut instance_seen = false;
    let mut class_matched = false;
    let mut sequences: Vec<u64> = Vec::new();

    for b in &overlapping {
        for obs in &b.batch.observations {
            if obs.observed.process != binding.process {
                continue;
            }
            instance_seen = true;
            if observation_matches(obs, class) {
                class_matched = true;
                sequences.push(b.sequence);
            }
        }
        for ke in &b.batch.kernel_events {
            // A kernel event counts only when the probe bound it to the very
            // instance the agent claims to be. An unbound event names a pid,
            // and a pid is not an instance.
            let Some(bound) = &ke.bound else { continue };
            if bound.process != binding.process {
                continue;
            }
            instance_seen = true;
            if kernel_event_matches(ke, class) {
                class_matched = true;
                sequences.push(b.sequence);
            }
        }
    }

    if !instance_seen {
        return C::Uncorroborated {
            reason: UncorroboratedReason::InstanceNotObserved,
            window,
        };
    }

    if class_matched {
        sequences.sort_unstable();
        sequences.dedup();
        C::Corroborated(CorroborationSeal::new(sequences, window))
    } else {
        C::Uncorroborated {
            reason: UncorroboratedReason::ActionClassAbsent { claimed },
            window,
        }
    }
}

/// Which event kinds describe something a host observer could in principle
/// see. Exhaustively matched so a new kind forces this decision rather than
/// defaulting into "observable" and silently over-claiming.
fn is_externally_observable(kind: AiriEventKind) -> bool {
    use AiriEventKind as K;
    match kind {
        // A tool invocation and a subprocess spawn leave host-visible marks:
        // a socket transition, an exec, a file write.
        K::ToolInvocationRequested | K::ToolExecutionReported | K::SubprocessExecution => true,
        // These are internal to the process. A hosted inference call leaves
        // a socket, but that socket is the *tool* layer's evidence, not the
        // model layer's — attributing it here would double-count.
        K::AgentExecutionStarted
        | K::ModelInvocationRequested
        | K::ModelInvocationObserved
        | K::ExecutionCompleted
        | K::ExecutionFailed
        | K::ExecutionContextPropagated => false,
    }
}

/// The action class a payload claims, in the vocabulary the observer's
/// effects are expressed in.
fn claimed_action_class(payload: &AiriPayload) -> Option<String> {
    match payload {
        AiriPayload::ToolInvocationRequested(t) => Some(t.action_kind.clone()),
        AiriPayload::ToolExecutionReported(t) => Some(t.tool_id.clone()),
        AiriPayload::SubprocessExecution(_) => Some("process.exec".to_string()),
        _ => None,
    }
}

/// The observable classes AIRI can compare against. Deliberately coarse:
/// a finer taxonomy would invite false agreement between a claim and an
/// unrelated observation that happens to sit in the same window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObservableClass {
    Network,
    File,
    ProcessExec,
}

/// Map a claimed action class onto an observable class.
///
/// Returns `None` for anything unrecognised, and `None` means "cannot be
/// compared", never "no match". An unknown tool must not read as agreement
/// *or* as a phantom claim — see [`corroborate`]'s step 6.
fn observable_class_of(claimed: &str) -> Option<ObservableClass> {
    let c = claimed.to_ascii_lowercase();
    if c.starts_with("http") || c.starts_with("net") || c.starts_with("mcp") || c.contains("api") {
        Some(ObservableClass::Network)
    } else if c.starts_with("file") || c.starts_with("fs") {
        Some(ObservableClass::File)
    } else if c == "process.exec" || c.starts_with("shell") || c.starts_with("exec") {
        Some(ObservableClass::ProcessExec)
    } else {
        None
    }
}

/// Does a polled observation evidence the class?
///
/// Only `SocketObserved` says anything about an external act, and it is
/// socket-table polling: it shows a socket existed, not that a connection
/// was made during the window. Weaker than the kernel-event path below and
/// treated as such by the reconciler's own strength rules.
fn observation_matches(obs: &aip_observe::ObservedExecution, class: ObservableClass) -> bool {
    use aip_observe::ObservedEffect as E;
    match (&obs.effect, class) {
        (E::SocketObserved { .. }, ObservableClass::Network) => true,
        // Presence and absence of a process are facts about the observer's
        // sampling, not about any act the agent claimed.
        (E::ProcessPresent | E::ProcessNoLongerPresent, _) => false,
        _ => false,
    }
}

/// Does a kernel-pushed lifecycle event evidence the class?
///
/// This is the stronger path: existence, order and time of these events are
/// kernel-generated rather than polled. It still does not reach `Proven` —
/// binding the event to a process *instance* depends on a pidfd-anchored
/// measurement, and the reconciler, not this function, decides that.
fn kernel_event_matches(ev: &aip_observe::KernelLifecycleEvent, class: ObservableClass) -> bool {
    use aip_observe::KernelLifecycleKind as K;
    matches!(
        (&ev.kind, class),
        (
            K::SocketState { .. } | K::SocketSend { .. } | K::WireSegment { .. },
            ObservableClass::Network
        ) | (K::FileEvent { .. }, ObservableClass::File)
            | (
                K::Exec { .. } | K::ProcessExec { .. } | K::ProcessSpawn { .. } | K::Fork { .. },
                ObservableClass::ProcessExec
            )
    )
}

/// Does a batch's claimed window overlap the coverage window, within slack?
///
/// The batch window is a *probe claim*, so this is a filter that can only
/// exclude, never establish anything on its own.
fn batch_overlaps(b: &AttestedBatch, w: &CoverageWindow, tol: u64) -> bool {
    let from = w.from_ms.saturating_sub(tol);
    let to = w.to_ms.saturating_add(tol);
    b.batch.claimed_to_ms >= from && b.batch.claimed_from_ms <= to
}
