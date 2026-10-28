//! aip-authorize — Ghost Stage 2: the independent authorization decision point.
//!
//! This crate answers exactly one question, **before** execution:
//!
//! ```text
//! Is this agent, under this authority chain, permitted to perform this
//! action with these parameters from this process instance — and until when?
//! ```
//!
//! A positive answer is a signed [`ExpectedExecution`]. A negative answer is a
//! [`Denial`] carrying a reason. There is no boolean.
//!
//! ## What this crate is not
//!
//! - It is **not** evidence that anything executed. An `ExpectedExecution`
//!   proves only that the designated decision point signed an authorization
//!   expectation.
//! - It is **not** an observer. It never consumes observations and never
//!   states what happened.
//! - It is **not** a reconciler. It does not compare expectation with
//!   evidence or observation, and it emits none of the reconciliation result
//!   classes.
//! - It is **not** an authority model of its own. Chain validity, scope
//!   attenuation and expiry are decided by `aip_core` (`verify_scoped_token`,
//!   `verify_delegation_chain`, `scope_permits`); this crate consumes those
//!   results.
//!
//! ## Trust boundary
//!
//! A [`DecisionPoint`] is constructed by its **operator** with a signing key.
//! No request type in this crate carries key material. An agent that
//! constructs a `DecisionPoint` with its own key and asks it to authorize
//! itself is refused ([`DenialReason::SelfAuthorization`]); a verifier that is
//! handed the agent's key as a decision-point anchor is refused
//! ([`ExpectedVerifyError::DecisionKeyIsAgentKey`]). The remaining guarantee —
//! that the key is actually held in a process the agent cannot read — is a
//! deployment property this crate documents but cannot enforce; see
//! `docs/architecture/DECISION_POINT.md`.

pub mod actions;
pub mod authority;
pub mod coverage;
pub mod decision;
pub mod expected;
pub mod resource;
pub mod spend;

pub use actions::{
    fs_write_action, fs_write_parameters, net_connect_action, net_connect_parameters,
    net_send_action, net_send_parameters, process_exec_action, process_exec_parameters,
    tool_invoke_action, tool_invoke_parameters, FsWriteError, NetConnectError, NetProtocol,
    ToolInvokeError, FS_WRITE_ACTION, MAX_TOOL_ID_LEN, NET_CONNECT_ACTION, NET_SEND_ACTION,
    PARAM_EXE_SHA256, PARAM_PARAMS_COMMITMENT, PARAM_PATH, PARAM_PROTOCOL, PARAM_REMOTE_ADDR,
    PARAM_REMOTE_PORT, PARAM_TOOL_ID, PROCESS_EXEC_ACTION, TOOL_INVOKE_ACTION,
};
pub use authority::{
    verify_authority_reference, AuthorityReferenceError, AuthorityTrustAnchors,
    VerifiedAuthorityReference,
};
pub use coverage::{
    CoverageIssueError, CoverageStatementError, DecisionPointCoverageStatement,
    DECISION_POINT_COVERAGE_DOMAIN, DECISION_POINT_COVERAGE_VERSION,
};
pub use decision::{
    AuthorizationRequest, Decision, DecisionPoint, DecisionPointError, Denial, DenialReason,
};
pub use expected::{
    verify_expected_execution, verify_expected_execution_for_agent, ActionParameters, AuthorityRef,
    DecisionPointTrustAnchors, ExpectedExecution, ExpectedVerifyError, ParameterError,
    TemporalStatus, ACTION_PARAMETERS_DOMAIN, EXPECTED_EXECUTION_DOMAIN,
    EXPECTED_EXECUTION_VERSION,
};
pub use resource::{destination_of, Destination, DestinationError, ResourcePolicy};
pub use spend::{expectation_digest, SpendConfigError, SpendDecision, SpendRecord};
