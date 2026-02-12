//! # ar-core
//!
//! Shared types for **lancer-agentic-radar** — the security scanner for agentic
//! AI workflows. This crate is GUI- and IO-agnostic: it defines the
//! [`AgentGraph`] that parsers produce, the [`Finding`] that detectors emit, the
//! [`TrustLabel`] machinery, the compliance mappings every finding carries, and
//! the [`Config`] / option bundles the rest of the workspace programs against.
//!
//! Dependency direction: every other crate (`ar-parsers`, `ar-detectors`,
//! `ar-runtime`, `ar-hardening`, `ar-report`, and the binary) depends on this
//! one and nothing depends back on them — so the public surface here is the
//! contract that keeps the whole tree coherent.

pub mod compliance;
pub mod config;
pub mod error;
pub mod finding;
pub mod framework;
pub mod graph;
pub mod location;
pub mod node;
pub mod report;
pub mod severity;
pub mod trust;

// ---- Flat re-exports: downstream crates use `ar_core::Foo`. ----------------

pub use compliance::{
    AivssVector, ComplianceMode, ComplianceTags, EuAiActArticle, OwaspAgentic2026, OwaspLlm2025,
};
pub use config::{
    Config, DetectorConfig, HardenOptions, McpTransport, ParseOptions, ReportFormat, TestCategory,
    TestOptions, TrustConfig,
};
pub use error::{CoreError, Result};
pub use finding::{Confidence, DetectorCategory, Finding};
pub use framework::Framework;
pub use graph::AgentGraph;
pub use location::SourceLocation;
pub use node::{
    sha256_hex, AgentNode, Edge, EdgeKind, MemoryStore, NodeId, NodeKind, RAGSource, ToolEffects,
    ToolNode, ToolSource,
};
pub use report::{ComplianceSummary, GraphStats, Report, ScanMeta};
pub use severity::Severity;
pub use trust::TrustLabel;

/// The crate version string, surfaced in report metadata + `--version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
