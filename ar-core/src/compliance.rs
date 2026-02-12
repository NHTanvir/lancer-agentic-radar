//! Compliance & standards mappings carried by every finding.
//!
//! Each detector tags its findings against the external standards the report
//! cross-references: OWASP Top 10 for Agentic Applications 2026, OWASP LLM Top
//! 10 v2025, OWASP AIVSS, NIST AI RMF (AI 600-1), the EU AI Act, CSA AICM and
//! MITRE ATLAS.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// OWASP Top 10 for Agentic Applications (2026).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OwaspAgentic2026 {
    GoalHijacking,
    ToolMisuse,
    IdentityAbuse,
    MemoryPoisoning,
    CascadingFailure,
    RogueAgent,
    UnauthorizedHandoff,
    UnsafeAutonomyEscalation,
    DataExfiltrationViaAgent,
    TraceabilityGap,
}

impl OwaspAgentic2026 {
    pub const ALL: [OwaspAgentic2026; 10] = [
        OwaspAgentic2026::GoalHijacking,
        OwaspAgentic2026::ToolMisuse,
        OwaspAgentic2026::IdentityAbuse,
        OwaspAgentic2026::MemoryPoisoning,
        OwaspAgentic2026::CascadingFailure,
        OwaspAgentic2026::RogueAgent,
        OwaspAgentic2026::UnauthorizedHandoff,
        OwaspAgentic2026::UnsafeAutonomyEscalation,
        OwaspAgentic2026::DataExfiltrationViaAgent,
        OwaspAgentic2026::TraceabilityGap,
    ];

    /// Stable short code, `AAT-01` .. `AAT-10`.
    pub fn code(self) -> &'static str {
        match self {
            OwaspAgentic2026::GoalHijacking => "AAT-01",
            OwaspAgentic2026::ToolMisuse => "AAT-02",
            OwaspAgentic2026::IdentityAbuse => "AAT-03",
            OwaspAgentic2026::MemoryPoisoning => "AAT-04",
            OwaspAgentic2026::CascadingFailure => "AAT-05",
            OwaspAgentic2026::RogueAgent => "AAT-06",
            OwaspAgentic2026::UnauthorizedHandoff => "AAT-07",
            OwaspAgentic2026::UnsafeAutonomyEscalation => "AAT-08",
            OwaspAgentic2026::DataExfiltrationViaAgent => "AAT-09",
            OwaspAgentic2026::TraceabilityGap => "AAT-10",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            OwaspAgentic2026::GoalHijacking => "Goal Hijacking",
            OwaspAgentic2026::ToolMisuse => "Tool Misuse",
            OwaspAgentic2026::IdentityAbuse => "Identity & Privilege Abuse",
            OwaspAgentic2026::MemoryPoisoning => "Memory Poisoning",
            OwaspAgentic2026::CascadingFailure => "Cascading Failures",
            OwaspAgentic2026::RogueAgent => "Rogue Agents",
            OwaspAgentic2026::UnauthorizedHandoff => "Unauthorized Handoff",
            OwaspAgentic2026::UnsafeAutonomyEscalation => "Unsafe Autonomy Escalation",
            OwaspAgentic2026::DataExfiltrationViaAgent => "Data Exfiltration via Agent",
            OwaspAgentic2026::TraceabilityGap => "Traceability & Observability Gap",
        }
    }
}

impl fmt::Display for OwaspAgentic2026 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.code(), self.title())
    }
}

/// OWASP Top 10 for LLM Applications (2025).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OwaspLlm2025 {
    PromptInjection,
    SensitiveInformationDisclosure,
    SupplyChain,
    DataAndModelPoisoning,
    ImproperOutputHandling,
    ExcessiveAgency,
    SystemPromptLeakage,
    VectorAndEmbeddingWeaknesses,
    Misinformation,
    UnboundedConsumption,
}

impl OwaspLlm2025 {
    pub const ALL: [OwaspLlm2025; 10] = [
        OwaspLlm2025::PromptInjection,
        OwaspLlm2025::SensitiveInformationDisclosure,
        OwaspLlm2025::SupplyChain,
        OwaspLlm2025::DataAndModelPoisoning,
        OwaspLlm2025::ImproperOutputHandling,
        OwaspLlm2025::ExcessiveAgency,
        OwaspLlm2025::SystemPromptLeakage,
        OwaspLlm2025::VectorAndEmbeddingWeaknesses,
        OwaspLlm2025::Misinformation,
        OwaspLlm2025::UnboundedConsumption,
    ];

    /// Code `LLM01:2025` .. `LLM10:2025`.
    pub fn code(self) -> &'static str {
        match self {
            OwaspLlm2025::PromptInjection => "LLM01:2025",
            OwaspLlm2025::SensitiveInformationDisclosure => "LLM02:2025",
            OwaspLlm2025::SupplyChain => "LLM03:2025",
            OwaspLlm2025::DataAndModelPoisoning => "LLM04:2025",
            OwaspLlm2025::ImproperOutputHandling => "LLM05:2025",
            OwaspLlm2025::ExcessiveAgency => "LLM06:2025",
            OwaspLlm2025::SystemPromptLeakage => "LLM07:2025",
            OwaspLlm2025::VectorAndEmbeddingWeaknesses => "LLM08:2025",
            OwaspLlm2025::Misinformation => "LLM09:2025",
            OwaspLlm2025::UnboundedConsumption => "LLM10:2025",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            OwaspLlm2025::PromptInjection => "Prompt Injection",
            OwaspLlm2025::SensitiveInformationDisclosure => "Sensitive Information Disclosure",
            OwaspLlm2025::SupplyChain => "Supply Chain",
            OwaspLlm2025::DataAndModelPoisoning => "Data and Model Poisoning",
            OwaspLlm2025::ImproperOutputHandling => "Improper Output Handling",
            OwaspLlm2025::ExcessiveAgency => "Excessive Agency",
            OwaspLlm2025::SystemPromptLeakage => "System Prompt Leakage",
            OwaspLlm2025::VectorAndEmbeddingWeaknesses => "Vector and Embedding Weaknesses",
            OwaspLlm2025::Misinformation => "Misinformation",
            OwaspLlm2025::UnboundedConsumption => "Unbounded Consumption",
        }
    }
}

impl fmt::Display for OwaspLlm2025 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.code(), self.title())
    }
}

/// EU AI Act articles referenced by the compliance reporter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EuAiActArticle {
    /// Art. 9 — risk-management system.
    Article9RiskManagement,
    /// Art. 10 — data and data governance.
    Article10DataGovernance,
    /// Art. 13 — transparency & provision of information to deployers.
    Article13Transparency,
    /// Art. 14 — human oversight.
    Article14HumanOversight,
    /// Art. 15 — accuracy, robustness and cybersecurity.
    Article15Robustness,
}

impl EuAiActArticle {
    pub fn code(self) -> &'static str {
        match self {
            EuAiActArticle::Article9RiskManagement => "EU-AI-Act Art.9",
            EuAiActArticle::Article10DataGovernance => "EU-AI-Act Art.10",
            EuAiActArticle::Article13Transparency => "EU-AI-Act Art.13",
            EuAiActArticle::Article14HumanOversight => "EU-AI-Act Art.14",
            EuAiActArticle::Article15Robustness => "EU-AI-Act Art.15",
        }
    }
    pub fn title(self) -> &'static str {
        match self {
            EuAiActArticle::Article9RiskManagement => "Risk management system",
            EuAiActArticle::Article10DataGovernance => "Data and data governance",
            EuAiActArticle::Article13Transparency => "Transparency & information to deployers",
            EuAiActArticle::Article14HumanOversight => "Human oversight",
            EuAiActArticle::Article15Robustness => "Accuracy, robustness & cybersecurity",
        }
    }
}

impl fmt::Display for EuAiActArticle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.code(), self.title())
    }
}

/// A simplified AIVSS (AI Vulnerability Scoring System) vector + score.
///
/// We model the AIVSS 1.0 agentic metric group as a compact vector string so
/// findings interoperate with other AIVSS-aware tooling. The numeric `score`
/// is a 0.0–10.0 roll-up aligned with the finding severity when not computed
/// from metrics directly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AivssVector {
    /// Autonomy of the affected agent: `N`one / `S`upervised / `F`ull.
    pub autonomy: char,
    /// Tool access: `N`one / `L`imited / `B`road.
    pub tool_access: char,
    /// Impact: `L`ow / `M`edium / `H`igh / `C`ritical.
    pub impact: char,
    /// Exploitability: `T`heoretical / `P`lausible / `D`emonstrated.
    pub exploitability: char,
    pub score: f32,
}

impl AivssVector {
    pub fn vector_string(&self) -> String {
        format!(
            "AIVSS:1.0/AU:{}/TA:{}/IM:{}/EX:{}/SC:{:.1}",
            self.autonomy, self.tool_access, self.impact, self.exploitability, self.score
        )
    }
}

impl fmt::Display for AivssVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.vector_string())
    }
}

/// The set of standards a [`ComplianceTags`] can map onto. Drives the
/// `--compliance-mode` flag and which report sections are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComplianceMode {
    #[serde(rename = "owasp-agentic-top10-2026")]
    OwaspAgenticTop10_2026,
    #[serde(rename = "owasp-llm-top10-2025")]
    OwaspLlmTop10_2025,
    #[serde(rename = "owasp-aivss")]
    OwaspAivss,
    #[serde(rename = "eu-ai-act")]
    EuAiAct,
    #[serde(rename = "nist-ai-rmf")]
    NistAiRmf,
    #[serde(rename = "csa-aicm")]
    CsaAicm,
    #[serde(rename = "mitre-atlas")]
    MitreAtlas,
}

impl ComplianceMode {
    pub const ALL: [ComplianceMode; 7] = [
        ComplianceMode::OwaspAgenticTop10_2026,
        ComplianceMode::OwaspLlmTop10_2025,
        ComplianceMode::OwaspAivss,
        ComplianceMode::EuAiAct,
        ComplianceMode::NistAiRmf,
        ComplianceMode::CsaAicm,
        ComplianceMode::MitreAtlas,
    ];

    pub fn id(self) -> &'static str {
        match self {
            ComplianceMode::OwaspAgenticTop10_2026 => "owasp-agentic-top10-2026",
            ComplianceMode::OwaspLlmTop10_2025 => "owasp-llm-top10-2025",
            ComplianceMode::OwaspAivss => "owasp-aivss",
            ComplianceMode::EuAiAct => "eu-ai-act",
            ComplianceMode::NistAiRmf => "nist-ai-rmf",
            ComplianceMode::CsaAicm => "csa-aicm",
            ComplianceMode::MitreAtlas => "mitre-atlas",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            ComplianceMode::OwaspAgenticTop10_2026 => "OWASP Top 10 for Agentic Applications 2026",
            ComplianceMode::OwaspLlmTop10_2025 => "OWASP Top 10 for LLM Applications 2025",
            ComplianceMode::OwaspAivss => "OWASP AIVSS",
            ComplianceMode::EuAiAct => "EU AI Act",
            ComplianceMode::NistAiRmf => "NIST AI RMF (AI 600-1)",
            ComplianceMode::CsaAicm => "CSA AI Controls Matrix",
            ComplianceMode::MitreAtlas => "MITRE ATLAS",
        }
    }
}

impl fmt::Display for ComplianceMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

impl FromStr for ComplianceMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let n = s.trim().to_ascii_lowercase();
        let m = match n.as_str() {
            "owasp-agentic-top10-2026" | "owasp-agentic-2026" | "owasp-agentic" => {
                ComplianceMode::OwaspAgenticTop10_2026
            }
            "owasp-llm-top10-2025" | "owasp-llm-2025" | "owasp-llm" => {
                ComplianceMode::OwaspLlmTop10_2025
            }
            "owasp-aivss" | "aivss" => ComplianceMode::OwaspAivss,
            "eu-ai-act" | "euaiact" => ComplianceMode::EuAiAct,
            "nist-ai-rmf" | "nist" => ComplianceMode::NistAiRmf,
            "csa-aicm" | "aicm" => ComplianceMode::CsaAicm,
            "mitre-atlas" | "atlas" => ComplianceMode::MitreAtlas,
            other => return Err(format!("unknown compliance mode: {other}")),
        };
        Ok(m)
    }
}

/// All the standards mappings attached to a single finding.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ComplianceTags {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owasp_agentic_2026: Vec<OwaspAgentic2026>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owasp_llm_2025: Vec<OwaspLlm2025>,
    /// NIST AI RMF subcategory codes (e.g. `MEASURE 2.7`, `MANAGE 4.1`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nist_ai_rmf: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub eu_ai_act: Vec<EuAiActArticle>,
    /// CSA AICM control ids (e.g. `AICM-AIS-03`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub csa_aicm: Vec<String>,
    /// MITRE ATLAS technique ids (e.g. `AML.T0051`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mitre_atlas: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aivss: Option<AivssVector>,
    /// Optional CVSS 3.1 vector string for cross-tool interop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss: Option<String>,
}

impl ComplianceTags {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_agentic(mut self, c: OwaspAgentic2026) -> Self {
        self.owasp_agentic_2026.push(c);
        self
    }
    pub fn with_llm(mut self, c: OwaspLlm2025) -> Self {
        self.owasp_llm_2025.push(c);
        self
    }
    pub fn with_eu(mut self, a: EuAiActArticle) -> Self {
        self.eu_ai_act.push(a);
        self
    }
    pub fn with_nist(mut self, s: impl Into<String>) -> Self {
        self.nist_ai_rmf.push(s.into());
        self
    }
    pub fn with_aicm(mut self, s: impl Into<String>) -> Self {
        self.csa_aicm.push(s.into());
        self
    }
    pub fn with_atlas(mut self, s: impl Into<String>) -> Self {
        self.mitre_atlas.push(s.into());
        self
    }
    pub fn with_aivss(mut self, v: AivssVector) -> Self {
        self.aivss = Some(v);
        self
    }

    /// Whether this finding has any mapping for the given mode (used to filter
    /// report sections when `--compliance-mode` is set).
    pub fn covers(&self, mode: ComplianceMode) -> bool {
        match mode {
            ComplianceMode::OwaspAgenticTop10_2026 => !self.owasp_agentic_2026.is_empty(),
            ComplianceMode::OwaspLlmTop10_2025 => !self.owasp_llm_2025.is_empty(),
            ComplianceMode::OwaspAivss => self.aivss.is_some(),
            ComplianceMode::EuAiAct => !self.eu_ai_act.is_empty(),
            ComplianceMode::NistAiRmf => !self.nist_ai_rmf.is_empty(),
            ComplianceMode::CsaAicm => !self.csa_aicm.is_empty(),
            ComplianceMode::MitreAtlas => !self.mitre_atlas.is_empty(),
        }
    }
}
