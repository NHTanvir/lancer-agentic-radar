//! The aggregate scan result the reporters render.

use crate::compliance::OwaspAgentic2026;
use crate::config::ComplianceMode;
use crate::finding::{DetectorCategory, Finding};
use crate::framework::Framework;
use crate::graph::AgentGraph;
use crate::severity::Severity;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Metadata about a scan run.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ScanMeta {
    pub tool_version: String,
    pub scanned_path: PathBuf,
    /// Framework forced via `--framework`, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework: Option<Framework>,
    /// Frameworks auto-detected during the scan.
    #[serde(default)]
    pub frameworks_detected: Vec<Framework>,
    /// ISO-8601 timestamp (filled by the caller; ar-core stays clock-free).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(default)]
    pub dynamic: bool,
    #[serde(default)]
    pub hardened: bool,
    #[serde(default)]
    pub compliance_modes: Vec<ComplianceMode>,
}

/// Counts derived from the graph for the report header.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct GraphStats {
    pub agents: usize,
    pub tools: usize,
    pub memory_stores: usize,
    pub rag_sources: usize,
    pub edges: usize,
    pub unknown_nodes: usize,
}

impl GraphStats {
    pub fn of(graph: &AgentGraph) -> Self {
        GraphStats {
            agents: graph.agents.len(),
            tools: graph.tools.len(),
            memory_stores: graph.memory.len(),
            rag_sources: graph.rag.len(),
            edges: graph.edges.len(),
            unknown_nodes: graph.unknowns.len(),
        }
    }
}

/// Roll-up of findings against the compliance standards.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ComplianceSummary {
    /// Count of findings touching each OWASP Agentic 2026 category (drives the
    /// coverage pie chart). Keyed by category code.
    pub owasp_agentic_2026: BTreeMap<String, usize>,
    pub owasp_llm_2025: BTreeMap<String, usize>,
    pub eu_ai_act: BTreeMap<String, usize>,
    pub nist_ai_rmf: BTreeMap<String, usize>,
    pub csa_aicm: BTreeMap<String, usize>,
    pub mitre_atlas: BTreeMap<String, usize>,
}

impl ComplianceSummary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut s = ComplianceSummary::default();
        for f in findings {
            for c in &f.compliance.owasp_agentic_2026 {
                *s.owasp_agentic_2026.entry(c.code().to_string()).or_default() += 1;
            }
            for c in &f.compliance.owasp_llm_2025 {
                *s.owasp_llm_2025.entry(c.code().to_string()).or_default() += 1;
            }
            for a in &f.compliance.eu_ai_act {
                *s.eu_ai_act.entry(a.code().to_string()).or_default() += 1;
            }
            for n in &f.compliance.nist_ai_rmf {
                *s.nist_ai_rmf.entry(n.clone()).or_default() += 1;
            }
            for c in &f.compliance.csa_aicm {
                *s.csa_aicm.entry(c.clone()).or_default() += 1;
            }
            for m in &f.compliance.mitre_atlas {
                *s.mitre_atlas.entry(m.clone()).or_default() += 1;
            }
        }
        // Ensure every OWASP Agentic category is represented (0 if untouched)
        // so the pie chart shows full coverage.
        for c in OwaspAgentic2026::ALL {
            s.owasp_agentic_2026
                .entry(c.code().to_string())
                .or_insert(0);
        }
        s
    }
}

/// The complete result of a scan, fed to every reporter.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub meta: ScanMeta,
    pub graph: AgentGraph,
    pub findings: Vec<Finding>,
    pub stats: GraphStats,
    pub compliance_summary: ComplianceSummary,
}

impl Report {
    /// Build a report, computing graph stats + compliance summary. Findings are
    /// sorted by descending severity then detector id for stable output.
    pub fn new(meta: ScanMeta, graph: AgentGraph, mut findings: Vec<Finding>) -> Self {
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.detector_id.cmp(&b.detector_id))
                .then_with(|| a.title.cmp(&b.title))
        });
        let stats = GraphStats::of(&graph);
        let compliance_summary = ComplianceSummary::from_findings(&findings);
        Report {
            meta,
            graph,
            findings,
            stats,
            compliance_summary,
        }
    }

    /// Findings that are not suppressed.
    pub fn active_findings(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| !f.suppressed)
    }

    /// Count of active findings per severity.
    pub fn severity_counts(&self) -> BTreeMap<Severity, usize> {
        let mut m = BTreeMap::new();
        for f in self.active_findings() {
            *m.entry(f.severity).or_default() += 1;
        }
        m
    }

    /// Count of active findings per detector category.
    pub fn category_counts(&self) -> BTreeMap<String, usize> {
        let mut m = BTreeMap::new();
        for f in self.active_findings() {
            *m.entry(f.category.id().to_string()).or_default() += 1;
        }
        m
    }

    /// The set of severities present among active findings (for `--fail-on`).
    pub fn present_severities(&self) -> Vec<Severity> {
        let mut v: Vec<Severity> = self.active_findings().map(|f| f.severity).collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// All categories used by category for grouping in reports.
    pub fn findings_by_category(&self) -> BTreeMap<DetectorCategory, Vec<&Finding>> {
        let mut m: BTreeMap<DetectorCategory, Vec<&Finding>> = BTreeMap::new();
        for f in self.active_findings() {
            m.entry(f.category).or_default().push(f);
        }
        m
    }
}
