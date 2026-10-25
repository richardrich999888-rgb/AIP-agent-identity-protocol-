//! C2 models, C3 frameworks, C4 tools, C6 data access, C7 execution
//! environment.

use serde::{Deserialize, Serialize};

/// Where inference runs. Determines which non-establishment applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Hosting {
    /// A provider's API. The served model is unverifiable (N-3).
    Hosted,
    /// Weights on hardware the deployment controls. That those weights were
    /// loaded is still unverifiable (N-4).
    Local,
}

/// C2 — one model the agent uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Model {
    pub provider: String,
    pub model: String,
    #[serde(default)]
    pub version: Option<String>,
    pub hosting: Hosting,
    /// SHA-256 of a weights file, lowercase hex. A statement about a file.
    #[serde(default)]
    pub weight_sha256: Option<String>,
}

/// C3 — one framework or SDK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Framework {
    pub name: String,
    pub version: String,
}

/// How a tool is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolKind {
    Api,
    /// An MCP server. Its `id` is its server name in the client config, which
    /// is what discovery matches on.
    Mcp,
    Plugin,
    Function,
}

/// C4 — one tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub id: String,
    pub kind: ToolKind,
    /// What the tool can do, in the tool's own vocabulary. Descriptive; the
    /// authority to use it is C5.
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
}

/// What kind of resource the agent can reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Database,
    Documents,
    Secret,
    External,
}

/// Direction of access. Ordered by breadth for change detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Read,
    Write,
    ReadWrite,
}

/// C6 — one resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataAccess {
    pub resource: String,
    pub kind: ResourceKind,
    pub access: Access,
}

/// The runtime the agent executes in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeKind {
    Process,
    Container,
    Vm,
    Serverless,
    Other,
}

/// Outbound network posture. `Unknown` is a legitimate declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPosture {
    Restricted,
    Open,
    Unknown,
}

/// The agent's executable, by content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binary {
    /// SHA-256 of the executable's content, lowercase hex.
    pub exe_sha256: String,
    #[serde(default)]
    pub exe_path: Option<String>,
}

/// C7 — the execution environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    pub runtime: RuntimeKind,
    pub network: NetworkPosture,
    #[serde(default)]
    pub binary: Option<Binary>,
}
