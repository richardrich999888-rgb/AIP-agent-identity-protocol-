//! The payload bodies: what an agent can say about the AI stack it drove.
//!
//! Each type here is a *claim*. The doc comment on each states what a
//! verifier may conclude from it, which in almost every case is "the agent
//! said this", and names the layer below which nothing is observable from
//! inside the process.

use aip_types::canonical::{put_bytes, put_domain, put_opt_str, put_str, put_u64, put_u8};
use serde::{Deserialize, Serialize};

use crate::ids::{InferenceRequestId, ToolCallId};

/// Domain tag for a parameter commitment. Distinct from every other domain
/// so a digest taken elsewhere in the system cannot be presented as one.
pub const AIRI_PARAM_DOMAIN: &str = "SYNTRIASS/AIRI/PARAM_COMMITMENT/v1";

/// Which framework produced the event, and which adapter translated it.
///
/// Recorded so a verifier can tell a LangGraph claim from an AutoGen claim
/// and can refuse an event whose adapter version it does not understand.
/// **Not a trust input**: a popular framework earns no authority here, and
/// nothing in this crate branches on `name` to grant anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameworkIdentity {
    /// e.g. `"langgraph"`, `"autogen"`, `"crewai"`, `"custom"`.
    pub name: String,
    /// The framework's own version string as the adapter observed it.
    pub version: String,
    /// The Vanian adapter's version. Bumped when the translation changes,
    /// so a verifier can reject a mapping it does not know.
    pub adapter_version: String,
}

impl FrameworkIdentity {
    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        put_str(buf, &self.name);
        put_str(buf, &self.version);
        put_str(buf, &self.adapter_version);
    }
}

/// The start of an agent execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStart {
    /// Free-form label for the agent role/graph node. Context only.
    pub agent_role: Option<String>,
    /// The framework's own run/thread id, for human correlation.
    pub framework_run_id: Option<String>,
}

impl AgentStart {
    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        put_opt_str(buf, &self.agent_role);
        put_opt_str(buf, &self.framework_run_id);
    }
}

/// What the agent says about a model invocation.
///
/// # What a verifier may conclude
///
/// That the agent's runtime *asked* for `model_id`. Nothing more. In
/// particular this does **not** establish:
///
/// * that the provider served that model rather than a substitute or a
///   quantised variant — the agent sees only what the API told it;
/// * that any accelerator executed anything. Python → PyTorch/JAX/TF →
///   XLA/native → CUDA is a four-layer chain and this event is authored at
///   the top of it. Framework telemetry reporting a CUDA kernel launch is
///   still framework telemetry;
/// * that `model_digest` describes the weights actually loaded, unless the
///   digest was taken by something outside this process.
///
/// For hosted models `model_digest` is normally `None`, and that absence is
/// the honest answer: there is no digest the agent can compute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelProvenance {
    /// Provider/model identifier as requested, e.g. `"claude-opus-5"`.
    pub model_id: String,
    /// SHA-256 over the weights, when a local runtime can compute one.
    /// `None` for hosted inference — see the type doc.
    pub model_digest: Option<[u8; 32]>,
    /// Execution framework, e.g. `"pytorch"`, `"jax"`, `"tensorflow"`,
    /// `"vllm"`, or `"hosted-api"` when inference is remote.
    pub runtime: String,
    /// That framework's version string, as reported by the framework.
    pub runtime_version: Option<String>,
    /// Provider correlation id for the inference call.
    pub inference_request_id: Option<InferenceRequestId>,
    /// Domain-separated commitment to the prompt/context. The plaintext is
    /// deliberately absent; see the crate-level privacy note.
    pub prompt_commitment: Option<[u8; 32]>,
    /// Domain-separated commitment to the model output.
    pub output_commitment: Option<[u8; 32]>,
    /// Accelerator description when the framework reported one, e.g.
    /// `"cuda:0 NVIDIA H100"`. **Self-reported**: this crate never treats it
    /// as proof that a GPU ran anything.
    pub accelerator: Option<String>,
}

impl ModelProvenance {
    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        put_str(buf, &self.model_id);
        put_opt_digest(buf, &self.model_digest);
        put_str(buf, &self.runtime);
        put_opt_str(buf, &self.runtime_version);
        put_opt_str(
            buf,
            &self.inference_request_id.as_ref().map(|x| x.0.clone()),
        );
        put_opt_digest(buf, &self.prompt_commitment);
        put_opt_digest(buf, &self.output_commitment);
        put_opt_str(buf, &self.accelerator);
    }
}

/// What the agent says it asked a tool to do.
///
/// This is layer 1 of the three the tool boundary must keep apart:
/// **requested invocation**, runtime execution, external effect. A
/// `ToolInvocation` is only ever the first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolInvocation {
    /// Stable tool identifier, e.g. `"mcp:filesystem:write"`,
    /// `"http:POST:payments.internal"`, `"sql:orders:update"`.
    pub tool_id: String,
    /// The action class, mapped by the adapter onto the vocabulary the
    /// decision point authorizes over. Lets a verifier compare a tool call
    /// with an `ExpectedExecution.action_kind` without knowing the tool.
    pub action_kind: String,
    /// Domain-separated commitment to the full parameter set. Built with
    /// [`crate::parameter_commitment`], never a bare SHA-256.
    pub parameter_commitment: [u8; 32],
    /// The model's own tool-call id, for correlation.
    pub tool_call_id: Option<ToolCallId>,
    /// Where the effect is expected to land, when the adapter knows it:
    /// a host, a table, a path. Context for a human; not authorization.
    pub target: Option<String>,
}

impl ToolInvocation {
    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        put_str(buf, &self.tool_id);
        put_str(buf, &self.action_kind);
        put_bytes(buf, &self.parameter_commitment);
        put_opt_str(buf, &self.tool_call_id.as_ref().map(|x| x.0.clone()));
        put_opt_str(buf, &self.target);
    }
}

/// What the agent says came back from a tool.
///
/// # The trap this type exists to label
///
/// A 200 response is not proof that the external effect occurred. It proves
/// that bytes resembling a success came back to this process. A proxy, a
/// stub, a replayed cassette, a compromised client library, or a service
/// that acknowledged and then failed all produce the same value. This type
/// is layer 2 (runtime execution) reporting on layer 3 (external effect),
/// which is exactly the boundary it cannot see across.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolReport {
    pub tool_id: String,
    /// The commitment from the corresponding [`ToolInvocation`], repeated so
    /// a report cannot be paired with a different request.
    pub parameter_commitment: [u8; 32],
    pub outcome: ReportedOutcome,
    /// Commitment to the tool's response.
    pub result_commitment: Option<[u8; 32]>,
    /// Transport-level status the client saw, e.g. an HTTP code.
    pub transport_status: Option<u64>,
}

impl ToolReport {
    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        put_str(buf, &self.tool_id);
        put_bytes(buf, &self.parameter_commitment);
        put_u8(buf, self.outcome.code());
        put_opt_digest(buf, &self.result_commitment);
        match self.transport_status {
            None => put_u8(buf, 0),
            Some(v) => {
                put_u8(buf, 1);
                put_u64(buf, v);
            }
        }
    }
}

/// How the agent's runtime says something ended. A claim, like everything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportedOutcome {
    Success,
    Failure,
    /// The agent declined to proceed — a refusal, a policy stop, a guardrail.
    /// Worth distinguishing: a verifiable non-execution path is evidence of
    /// a kind, where independent observation supports it.
    Denied,
    /// The runtime does not know, e.g. a timeout with no response.
    Indeterminate,
}

impl ReportedOutcome {
    pub fn code(self) -> u8 {
        match self {
            Self::Success => 0x01,
            Self::Failure => 0x02,
            Self::Denied => 0x03,
            Self::Indeterminate => 0x04,
        }
    }
}

/// A subprocess the agent says it spawned.
///
/// The command line is committed, not carried: argument vectors routinely
/// contain credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubprocessReport {
    /// The executable path as the agent passed it. A path, not a measurement
    /// — a same-path different binary is a different program and this field
    /// cannot tell the difference. `aip-observe` can.
    pub program: String,
    /// Commitment to the full argument vector.
    pub argv_commitment: [u8; 32],
    /// The child pid as the parent saw it. Self-reported and reusable; only
    /// an observer's `ProcessInstance` pins an instance.
    pub reported_pid: Option<u64>,
}

impl SubprocessReport {
    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        put_str(buf, &self.program);
        put_bytes(buf, &self.argv_commitment);
        match self.reported_pid {
            None => put_u8(buf, 0),
            Some(v) => {
                put_u8(buf, 1);
                put_u64(buf, v);
            }
        }
    }
}

/// Execution context crossing a boundary: an async task, a thread, a
/// process, a worker queue.
///
/// Emitted on both sides so a verifier can see that a handoff was claimed
/// and, where an observer covered both, whether it happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextPropagation {
    pub boundary: PropagationBoundary,
    /// The execution the context was handed to.
    pub to_execution_id: [u8; 16],
}

impl ContextPropagation {
    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        put_u8(buf, self.boundary.code());
        put_bytes(buf, &self.to_execution_id);
    }
}

/// Which kind of boundary an execution context crossed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PropagationBoundary {
    AsyncTask,
    Thread,
    Process,
    Subprocess,
    WorkerQueue,
}

impl PropagationBoundary {
    pub fn code(self) -> u8 {
        match self {
            Self::AsyncTask => 0x01,
            Self::Thread => 0x02,
            Self::Process => 0x03,
            Self::Subprocess => 0x04,
            Self::WorkerQueue => 0x05,
        }
    }
}

/// How an execution ended, as the agent reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Completion {
    pub outcome: ReportedOutcome,
    /// Short human-readable detail. Committed nowhere; kept short and
    /// non-sensitive by adapter policy.
    pub detail: Option<String>,
}

impl Completion {
    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        put_u8(buf, self.outcome.code());
        put_opt_str(buf, &self.detail);
    }
}

/// Encode an optional 32-byte digest with an explicit presence byte, so
/// `None` and `Some([0u8; 32])` have different preimages.
pub(crate) fn put_opt_digest(buf: &mut Vec<u8>, d: &Option<[u8; 32]>) {
    match d {
        None => put_u8(buf, 0),
        Some(v) => {
            put_u8(buf, 1);
            put_bytes(buf, v);
        }
    }
}

/// Commit to a byte string under AIRI's parameter domain.
///
/// `SHA-256( put_domain(AIRI_PARAM_DOMAIN) ‖ put_bytes(data) )`
///
/// Domain-separated and length-prefixed so that (a) a digest computed
/// anywhere else in the system is not a valid parameter commitment, and
/// (b) the commitment of `a ‖ b` differs from the commitment of `a` and
/// `b` supplied separately.
pub fn commit_bytes(data: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(data.len() + 64);
    put_domain(&mut buf, AIRI_PARAM_DOMAIN);
    put_bytes(&mut buf, data);
    aip_crypto::sha256(&buf)
}
