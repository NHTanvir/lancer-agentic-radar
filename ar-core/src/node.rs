//! Graph node and edge types: agents, tools, memory stores, RAG sources.

use crate::framework::Framework;
use crate::location::SourceLocation;
use crate::trust::TrustLabel;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Stable, globally-unique identifier for any node in an [`crate::AgentGraph`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NodeId(pub String);

impl NodeId {
    pub fn new(s: impl Into<String>) -> Self {
        NodeId(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for NodeId {
    fn from(s: &str) -> Self {
        NodeId(s.to_string())
    }
}
impl From<String> for NodeId {
    fn from(s: String) -> Self {
        NodeId(s)
    }
}
impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What kind of thing a node represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeKind {
    Agent,
    Tool,
    Memory,
    Rag,
    /// A construct the parser could not statically resolve — always paired
    /// with an `unable-to-statically-resolve` finding.
    Unknown,
}

/// What kind of relationship an edge represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EdgeKind {
    /// Agent is permitted to invoke a tool.
    Calls,
    /// Agent reads from a memory store or RAG source.
    Reads,
    /// Agent writes to a memory store.
    Writes,
    /// Agent hands control to another agent (CrewAI/AutoGen/Agents-SDK handoff).
    Handoff,
    /// Tool result flows back into the agent context.
    Returns,
    /// A trigger (webhook / chat) starts the workflow at this node.
    Triggers,
    /// Generic data-flow edge used for trust propagation between nodes.
    DataFlow,
}

impl EdgeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EdgeKind::Calls => "calls",
            EdgeKind::Reads => "reads",
            EdgeKind::Writes => "writes",
            EdgeKind::Handoff => "handoff",
            EdgeKind::Returns => "returns",
            EdgeKind::Triggers => "triggers",
            EdgeKind::DataFlow => "data-flow",
        }
    }
}

/// A directed edge in the agent graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edge {
    pub from: NodeId,
    pub to: NodeId,
    pub kind: EdgeKind,
    /// Trust label of the data travelling along this edge (filled in by the
    /// propagation pass; `Unknown` until then).
    #[serde(default)]
    pub trust: TrustLabel,
    /// Optional human label (e.g. the conditional-edge predicate name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl Edge {
    pub fn new(from: impl Into<NodeId>, to: impl Into<NodeId>, kind: EdgeKind) -> Self {
        Edge {
            from: from.into(),
            to: to.into(),
            kind,
            trust: TrustLabel::Unknown,
            label: None,
        }
    }
    pub fn with_trust(mut self, t: TrustLabel) -> Self {
        self.trust = t;
        self
    }
    pub fn with_label(mut self, l: impl Into<String>) -> Self {
        self.label = Some(l.into());
        self
    }
}

/// An LLM-backed agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentNode {
    pub id: NodeId,
    pub name: String,
    /// Extracted system prompt (final concatenated form), if found.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<String>,
    /// SHA-256 of `system_prompt` for cross-scan diffing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_prompt_sha256: Option<String>,
    /// Model identifier (e.g. `gpt-4o`, `claude-3-5-sonnet`), if declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub framework: Framework,
    pub location: SourceLocation,
    /// Whether this agent can receive untrusted user input directly.
    #[serde(default)]
    pub accepts_user_input: bool,
}

impl AgentNode {
    pub fn new(id: impl Into<NodeId>, name: impl Into<String>, framework: Framework) -> Self {
        AgentNode {
            id: id.into(),
            name: name.into(),
            system_prompt: None,
            system_prompt_sha256: None,
            model: None,
            framework,
            location: SourceLocation::default(),
            accepts_user_input: false,
        }
    }

    /// Set the system prompt and (re)compute its SHA-256 fingerprint.
    pub fn set_system_prompt(&mut self, prompt: impl Into<String>) {
        let p = prompt.into();
        self.system_prompt_sha256 = Some(sha256_hex(p.as_bytes()));
        self.system_prompt = Some(p);
    }
}

/// Side effects a tool may perform — the basis of excessive-authority and
/// trust-boundary reasoning. Inferred by the parsers; overridable via decorator
/// metadata (`@tool(effects=[...])`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ToolEffects {
    pub reads_fs: bool,
    pub writes_fs: bool,
    pub shell_exec: bool,
    pub net_egress: bool,
    pub db_write: bool,
    pub payment: bool,
    pub email: bool,
    /// Code-eval / dynamic-execution (eval/exec/Function ctor).
    pub code_eval: bool,
}

impl ToolEffects {
    /// True if the tool can perform a privileged / dangerous operation.
    pub fn is_privileged(self) -> bool {
        self.shell_exec
            || self.writes_fs
            || self.net_egress
            || self.db_write
            || self.payment
            || self.email
            || self.code_eval
    }

    /// Whether any effect at all has been inferred.
    pub fn is_known(self) -> bool {
        self.reads_fs
            || self.writes_fs
            || self.shell_exec
            || self.net_egress
            || self.db_write
            || self.payment
            || self.email
            || self.code_eval
    }

    /// Short badges for graph labels: `SHELL`, `NET`, `FS-W`, `DB-W`, `$`, etc.
    pub fn badges(self) -> Vec<&'static str> {
        let mut b = Vec::new();
        if self.shell_exec {
            b.push("SHELL");
        }
        if self.code_eval {
            b.push("EVAL");
        }
        if self.net_egress {
            b.push("NET");
        }
        if self.writes_fs {
            b.push("FS-W");
        }
        if self.reads_fs {
            b.push("FS-R");
        }
        if self.db_write {
            b.push("DB-W");
        }
        if self.email {
            b.push("MAIL");
        }
        if self.payment {
            b.push("$");
        }
        b
    }
}

/// Where a tool's definition came from — affects trust of its description.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "ref")]
pub enum ToolSource {
    /// Defined inline in the scanned codebase.
    Native,
    /// Advertised by an MCP server (carries the server name/URL).
    Mcp(String),
    /// A framework builtin (e.g. `WebSearchTool`, `computer_20250124`).
    Builtin(String),
    /// Imported from a third-party package (carries the import path).
    Imported(String),
    /// Could not determine the source.
    Unknown,
}

impl Default for ToolSource {
    fn default() -> Self {
        ToolSource::Unknown
    }
}

/// A tool an agent is permitted to call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolNode {
    pub id: NodeId,
    pub name: String,
    /// Declared signature / argument schema description, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Tool description text (the MCP / function-calling `description`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub effects: ToolEffects,
    pub source: ToolSource,
    pub location: SourceLocation,
    /// Whether the tool declares an input schema / arg validation.
    #[serde(default)]
    pub has_input_schema: bool,
    /// Whether the parser could resolve the tool's effects at all.
    #[serde(default)]
    pub effects_resolved: bool,
}

impl ToolNode {
    pub fn new(id: impl Into<NodeId>, name: impl Into<String>) -> Self {
        ToolNode {
            id: id.into(),
            name: name.into(),
            signature: None,
            description: None,
            effects: ToolEffects::default(),
            source: ToolSource::default(),
            location: SourceLocation::default(),
            has_input_schema: false,
            effects_resolved: false,
        }
    }
}

/// A persistent memory store (vector DB, chat-history buffer, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryStore {
    pub id: NodeId,
    pub name: String,
    /// Backend kind, e.g. `ConversationBufferMemory`, `RedisChatMessageHistory`,
    /// `mem0`, `Pinecone`, `Qdrant`.
    pub kind: String,
    pub location: SourceLocation,
    /// Whether the store is shared across sessions/runs.
    #[serde(default)]
    pub cross_session: bool,
    /// Whether tenant isolation (metadata filter) is applied on reads.
    #[serde(default)]
    pub tenant_isolated: bool,
    /// Whether an eviction/TTL policy is configured.
    #[serde(default)]
    pub has_eviction_policy: bool,
}

impl MemoryStore {
    pub fn new(id: impl Into<NodeId>, name: impl Into<String>, kind: impl Into<String>) -> Self {
        MemoryStore {
            id: id.into(),
            name: name.into(),
            kind: kind.into(),
            location: SourceLocation::default(),
            cross_session: false,
            tenant_isolated: false,
            has_eviction_policy: false,
        }
    }
}

/// A retrieval-augmented-generation source feeding an agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RAGSource {
    pub id: NodeId,
    pub name: String,
    /// Retriever / vector-store kind (Chroma/FAISS/Pinecone/Weaviate/file_search).
    pub kind: String,
    /// Document source URI/path used to classify trust (`./docs`, `https://…`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document_source: Option<String>,
    pub location: SourceLocation,
    /// Trust of the underlying documents (heuristic; overridable via config).
    #[serde(default)]
    pub trust: TrustLabel,
    /// Whether the store is writable by untrusted input at runtime.
    #[serde(default)]
    pub user_writable: bool,
    /// Whether retrieved chunks carry source attribution.
    #[serde(default)]
    pub has_source_attribution: bool,
}

impl RAGSource {
    pub fn new(id: impl Into<NodeId>, name: impl Into<String>, kind: impl Into<String>) -> Self {
        RAGSource {
            id: id.into(),
            name: name.into(),
            kind: kind.into(),
            document_source: None,
            location: SourceLocation::default(),
            trust: TrustLabel::Unknown,
            user_writable: false,
            has_source_attribution: false,
        }
    }
}

/// SHA-256 hex digest helper (used for system-prompt fingerprints).
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}
