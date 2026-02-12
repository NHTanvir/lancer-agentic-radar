//! Findings emitted by detectors.

use crate::compliance::ComplianceTags;
use crate::location::SourceLocation;
use crate::node::NodeId;
use crate::severity::Severity;
use serde::{Deserialize, Serialize};
use std::fmt;

/// The top-level detector categories (one per plan §"Detector catalog").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DetectorCategory {
    PromptInjection,
    ToolPoisoning,
    RagPoisoning,
    MemoryPoisoning,
    TrustBoundary,
    ExcessiveAuthority,
    MissingInputValidation,
    MissingOutputFilter,
    SecretLeakage,
    JailbreakPathway,
    IndirectInjection,
    RecursionBomb,
    InfiniteLoop,
    ResourceExhaustion,
    OwaspAgentic2026,
    N8nWorkflowRisks,
    HandoffAbuse,
    PromptHardeningNeeded,
    /// Parser could not resolve a construct; auditor attention needed.
    Resolution,
}

impl DetectorCategory {
    pub const ALL: [DetectorCategory; 19] = [
        DetectorCategory::PromptInjection,
        DetectorCategory::ToolPoisoning,
        DetectorCategory::RagPoisoning,
        DetectorCategory::MemoryPoisoning,
        DetectorCategory::TrustBoundary,
        DetectorCategory::ExcessiveAuthority,
        DetectorCategory::MissingInputValidation,
        DetectorCategory::MissingOutputFilter,
        DetectorCategory::SecretLeakage,
        DetectorCategory::JailbreakPathway,
        DetectorCategory::IndirectInjection,
        DetectorCategory::RecursionBomb,
        DetectorCategory::InfiniteLoop,
        DetectorCategory::ResourceExhaustion,
        DetectorCategory::OwaspAgentic2026,
        DetectorCategory::N8nWorkflowRisks,
        DetectorCategory::HandoffAbuse,
        DetectorCategory::PromptHardeningNeeded,
        DetectorCategory::Resolution,
    ];

    pub fn id(self) -> &'static str {
        match self {
            DetectorCategory::PromptInjection => "prompt-injection",
            DetectorCategory::ToolPoisoning => "tool-poisoning",
            DetectorCategory::RagPoisoning => "rag-poisoning",
            DetectorCategory::MemoryPoisoning => "memory-poisoning",
            DetectorCategory::TrustBoundary => "trust-boundary",
            DetectorCategory::ExcessiveAuthority => "excessive-authority",
            DetectorCategory::MissingInputValidation => "missing-input-validation",
            DetectorCategory::MissingOutputFilter => "missing-output-filter",
            DetectorCategory::SecretLeakage => "secret-leakage",
            DetectorCategory::JailbreakPathway => "jailbreak-pathway",
            DetectorCategory::IndirectInjection => "indirect-injection",
            DetectorCategory::RecursionBomb => "recursion-bomb",
            DetectorCategory::InfiniteLoop => "infinite-loop",
            DetectorCategory::ResourceExhaustion => "resource-exhaustion",
            DetectorCategory::OwaspAgentic2026 => "owasp-agentic-2026",
            DetectorCategory::N8nWorkflowRisks => "n8n-workflow-risks",
            DetectorCategory::HandoffAbuse => "handoff-abuse",
            DetectorCategory::PromptHardeningNeeded => "prompt-hardening-needed",
            DetectorCategory::Resolution => "resolution",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            DetectorCategory::PromptInjection => "Prompt Injection",
            DetectorCategory::ToolPoisoning => "Tool Poisoning",
            DetectorCategory::RagPoisoning => "RAG Poisoning",
            DetectorCategory::MemoryPoisoning => "Memory Poisoning",
            DetectorCategory::TrustBoundary => "Trust-Boundary Violation",
            DetectorCategory::ExcessiveAuthority => "Excessive Tool Authority",
            DetectorCategory::MissingInputValidation => "Missing Input Validation",
            DetectorCategory::MissingOutputFilter => "Missing Output Filtering",
            DetectorCategory::SecretLeakage => "Secret Leakage",
            DetectorCategory::JailbreakPathway => "Jailbreak Pathway",
            DetectorCategory::IndirectInjection => "Indirect Injection",
            DetectorCategory::RecursionBomb => "Recursion Bomb",
            DetectorCategory::InfiniteLoop => "Infinite Loop",
            DetectorCategory::ResourceExhaustion => "Resource Exhaustion",
            DetectorCategory::OwaspAgentic2026 => "OWASP Agentic 2026 Mapping",
            DetectorCategory::N8nWorkflowRisks => "n8n Workflow Risks",
            DetectorCategory::HandoffAbuse => "Handoff Abuse",
            DetectorCategory::PromptHardeningNeeded => "Prompt Hardening Needed",
            DetectorCategory::Resolution => "Resolution / Audit Needed",
        }
    }
}

impl fmt::Display for DetectorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// Confidence in a finding — adjustable by the (optional) LLM triage pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Default for Confidence {
    fn default() -> Self {
        Confidence::Medium
    }
}

/// A single security finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Sub-check id, e.g. `tb-tool-output-to-next-tool-input`.
    pub detector_id: String,
    pub category: DetectorCategory,
    pub severity: Severity,
    #[serde(default)]
    pub confidence: Confidence,
    pub title: String,
    pub description: String,
    /// Agent this finding is attached to, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<NodeId>,
    /// Tool this finding is attached to, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<NodeId>,
    /// Free-form evidence (matched source text, edge description, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    /// Plain-English remediation guidance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix_suggestion: Option<String>,
    /// A candidate auto-mitigation patch / hardened rewrite (if generated).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation_patch: Option<String>,
    #[serde(default)]
    pub location: SourceLocation,
    #[serde(default)]
    pub compliance: ComplianceTags,
    /// Set true when a `# ar-ignore` hint or config exclusion suppresses it.
    #[serde(default)]
    pub suppressed: bool,
    /// True once a `--dynamic` probe confirmed exploitability.
    #[serde(default)]
    pub dynamically_confirmed: bool,
}

impl Finding {
    pub fn new(
        detector_id: impl Into<String>,
        category: DetectorCategory,
        severity: Severity,
        title: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Finding {
            detector_id: detector_id.into(),
            category,
            severity,
            confidence: Confidence::default(),
            title: title.into(),
            description: description.into(),
            agent: None,
            tool: None,
            evidence: None,
            fix_suggestion: None,
            remediation_patch: None,
            location: SourceLocation::default(),
            compliance: ComplianceTags::default(),
            suppressed: false,
            dynamically_confirmed: false,
        }
    }

    pub fn with_agent(mut self, id: impl Into<NodeId>) -> Self {
        self.agent = Some(id.into());
        self
    }
    pub fn with_tool(mut self, id: impl Into<NodeId>) -> Self {
        self.tool = Some(id.into());
        self
    }
    pub fn with_evidence(mut self, e: impl Into<String>) -> Self {
        self.evidence = Some(e.into());
        self
    }
    pub fn with_fix(mut self, f: impl Into<String>) -> Self {
        self.fix_suggestion = Some(f.into());
        self
    }
    pub fn with_location(mut self, l: SourceLocation) -> Self {
        self.location = l;
        self
    }
    pub fn with_compliance(mut self, c: ComplianceTags) -> Self {
        self.compliance = c;
        self
    }
    pub fn with_confidence(mut self, c: Confidence) -> Self {
        self.confidence = c;
        self
    }

    /// Stable per-finding fingerprint (detector + location + title) for SARIF
    /// partial fingerprints and baseline diffing.
    pub fn fingerprint(&self) -> String {
        crate::node::sha256_hex(
            format!(
                "{}|{}|{}|{}",
                self.detector_id,
                self.location.display_path(),
                self.title,
                self.agent.as_ref().map(|a| a.0.as_str()).unwrap_or("")
            )
            .as_bytes(),
        )
    }
}
