//! Configuration: report formats, trust sources, detector suppression, and the
//! option bundles passed to parsers / detectors / the dynamic runtime.

use crate::compliance::ComplianceMode;
use crate::finding::Confidence;
use crate::framework::Framework;
use crate::severity::Severity;
use crate::trust::TrustLabel;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::str::FromStr;

/// Output report format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    Json,
    Sarif,
    Markdown,
    Html,
}

impl ReportFormat {
    pub const ALL: [ReportFormat; 4] = [
        ReportFormat::Json,
        ReportFormat::Sarif,
        ReportFormat::Markdown,
        ReportFormat::Html,
    ];

    pub fn id(self) -> &'static str {
        match self {
            ReportFormat::Json => "json",
            ReportFormat::Sarif => "sarif",
            ReportFormat::Markdown => "md",
            ReportFormat::Html => "html",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            ReportFormat::Json => "json",
            ReportFormat::Sarif => "sarif",
            ReportFormat::Markdown => "md",
            ReportFormat::Html => "html",
        }
    }

    pub fn content_type(self) -> &'static str {
        match self {
            ReportFormat::Json => "application/json",
            ReportFormat::Sarif => "application/sarif+json",
            ReportFormat::Markdown => "text/markdown",
            ReportFormat::Html => "text/html",
        }
    }
}

impl FromStr for ReportFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(ReportFormat::Json),
            "sarif" => Ok(ReportFormat::Sarif),
            "md" | "markdown" => Ok(ReportFormat::Markdown),
            "html" => Ok(ReportFormat::Html),
            other => Err(format!("unknown report format: {other}")),
        }
    }
}

/// Trust classification for RAG/document sources. Prefix-matched against the
/// declared document source URI.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustConfig {
    /// Source prefixes considered trusted (`./docs/`, `s3://internal-bucket/`).
    #[serde(default)]
    pub trusted_sources: Vec<String>,
    /// Source prefixes considered untrusted (`https://`, `s3://user-uploads/`).
    #[serde(default)]
    pub untrusted_sources: Vec<String>,
}

impl Default for TrustConfig {
    fn default() -> Self {
        TrustConfig {
            trusted_sources: vec![
                "./".into(),
                "../".into(),
                "file://".into(),
                "s3://internal".into(),
            ],
            untrusted_sources: vec![
                "http://".into(),
                "https://".into(),
                "s3://user-uploads".into(),
                "db.user_files".into(),
                "wikipedia".into(),
                "arxiv".into(),
            ],
        }
    }
}

impl TrustConfig {
    /// Classify a document source URI/path into a trust label.
    pub fn classify(&self, source: &str) -> TrustLabel {
        let s = source.trim();
        // Explicit untrusted wins over trusted to stay conservative.
        if self.untrusted_sources.iter().any(|p| s.starts_with(p) || s.contains(p)) {
            return TrustLabel::Untrusted;
        }
        if self.trusted_sources.iter().any(|p| s.starts_with(p)) {
            return TrustLabel::Trusted;
        }
        TrustLabel::Unknown
    }
}

/// Detector enable/suppress configuration (`ar.toml [detectors]`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DetectorConfig {
    /// Detector ids (or category ids) to exclude entirely.
    #[serde(default)]
    pub exclude: Vec<String>,
    /// If non-empty, only these detector ids/categories run.
    #[serde(default)]
    pub only: Vec<String>,
}

impl DetectorConfig {
    /// Whether a detector id (and its category id) is enabled.
    pub fn enabled(&self, detector_id: &str, category_id: &str) -> bool {
        if self
            .exclude
            .iter()
            .any(|e| e == detector_id || e == category_id)
        {
            return false;
        }
        if !self.only.is_empty() {
            return self
                .only
                .iter()
                .any(|o| o == detector_id || o == category_id);
        }
        true
    }
}

/// Top-level configuration (merged from `ar.toml` / `--config` and CLI flags).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub trust: TrustConfig,
    #[serde(default)]
    pub detectors: DetectorConfig,
    /// Severities that cause a non-zero exit code (`--fail-on`).
    #[serde(default)]
    pub fail_on: Vec<Severity>,
    /// Active compliance report sections (`--compliance-mode`).
    #[serde(default)]
    pub compliance_modes: Vec<ComplianceMode>,
    /// Drop findings below this confidence from the report (default: keep all).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_confidence: Option<Confidence>,
}

impl Config {
    /// True if any finding severity in `severities` should trip `--fail-on`.
    pub fn should_fail(&self, severities: impl IntoIterator<Item = Severity>) -> bool {
        if self.fail_on.is_empty() {
            return false;
        }
        severities
            .into_iter()
            .any(|s| self.fail_on.contains(&s))
    }
}

/// Options controlling a static scan / parse.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParseOptions {
    /// Force a specific framework (skip auto-detection).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework: Option<Framework>,
    /// Only parse MCP manifests (`--mcp-only`).
    #[serde(default)]
    pub mcp_only: bool,
    /// Follow tool lists across module boundaries.
    #[serde(default = "default_true")]
    pub follow_imports: bool,
    /// Trust classification config (shared with [`Config::trust`]).
    #[serde(default)]
    pub trust: TrustConfig,
}

fn default_true() -> bool {
    true
}

impl Default for ParseOptions {
    fn default() -> Self {
        ParseOptions {
            framework: None,
            mcp_only: false,
            follow_imports: true,
            trust: TrustConfig::default(),
        }
    }
}

/// Dynamic vulnerability-test categories — matches upstream `agentic-radar
/// test` taxonomy (OWASP LLM Top 10 v2025 / Agentic 2026 aligned).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TestCategory {
    PromptInjection,
    PiiLeakage,
    HarmfulContent,
    FakeNews,
}

impl TestCategory {
    pub const ALL: [TestCategory; 4] = [
        TestCategory::PromptInjection,
        TestCategory::PiiLeakage,
        TestCategory::HarmfulContent,
        TestCategory::FakeNews,
    ];

    pub fn id(self) -> &'static str {
        match self {
            TestCategory::PromptInjection => "prompt-injection",
            TestCategory::PiiLeakage => "pii-leakage",
            TestCategory::HarmfulContent => "harmful-content",
            TestCategory::FakeNews => "fake-news",
        }
    }
}

impl FromStr for TestCategory {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "prompt-injection" | "pi" => Ok(TestCategory::PromptInjection),
            "pii-leakage" | "pii" => Ok(TestCategory::PiiLeakage),
            "harmful-content" | "harmful" => Ok(TestCategory::HarmfulContent),
            "fake-news" | "fakenews" => Ok(TestCategory::FakeNews),
            other => Err(format!("unknown test category: {other}")),
        }
    }
}

/// MCP transport for the dynamic probe.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "transport", content = "endpoint")]
pub enum McpTransport {
    /// Spawn a server subprocess and pipe JSON-RPC over stdio.
    Stdio(String),
    /// Long-lived Server-Sent-Events connection.
    Sse(String),
    /// Stateful WebSocket connection.
    WebSocket(String),
}

/// Options controlling a dynamic test run (`test` subcommand / `--dynamic`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TestOptions {
    /// Agent HTTP endpoint URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Bearer/auth token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    /// MCP server endpoint, if probing MCP directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpTransport>,
    /// Test categories to run (empty = all).
    #[serde(default)]
    pub categories: Vec<TestCategory>,
    /// Max attack prompts per category.
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    /// Optional OTEL trace collector endpoint to consume tool-call telemetry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub otel_endpoint: Option<String>,
    /// Request timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_max_attempts() -> u32 {
    8
}
fn default_timeout() -> u64 {
    30
}

impl Default for TestOptions {
    fn default() -> Self {
        TestOptions {
            endpoint: None,
            auth: None,
            mcp: None,
            categories: Vec::new(),
            max_attempts: default_max_attempts(),
            otel_endpoint: None,
            timeout_secs: default_timeout(),
        }
    }
}

/// Options controlling prompt hardening (`--harden-prompts`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HardenOptions {
    /// LLM model id used to rewrite prompts.
    pub model: String,
    /// API base URL (OpenAI-compatible).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_base: Option<String>,
    /// Run fully offline using the deterministic rule-based rewriter (no API
    /// key required). Defaults to true so hardening always produces output.
    #[serde(default = "default_true")]
    pub offline: bool,
}

impl Default for HardenOptions {
    fn default() -> Self {
        HardenOptions {
            model: "claude-opus-4-8".into(),
            api_base: None,
            offline: true,
        }
    }
}
