//! # ar-report
//!
//! Report emitters for **lancer-agentic-radar**. Given the aggregate
//! [`ar_core::Report`] produced by a scan, this crate renders it in any of the
//! supported output formats and provides the graph visualizations and
//! runtime-governance policy exports:
//!
//! * [`json`] — machine-readable JSON (the full report).
//! * [`sarif`] — hand-rolled SARIF 2.1.0 for GitHub code scanning.
//! * [`markdown`] — auditor-friendly Markdown with an embedded Mermaid diagram.
//! * [`html`] — a standalone dark-mode HTML page.
//! * [`graphviz`] — Mermaid `flowchart TB` + DOT/Graphviz of the tool topology.
//! * [`governance`] — Microsoft Agent Governance Toolkit / Cisco DefenseClaw /
//!   Meta LlamaFirewall policy exports.
//!
//! The crate depends only on [`ar_core`] and `serde_json`; it performs no I/O
//! beyond the [`write_report`] convenience.

pub mod json;
pub mod sarif;
pub mod markdown;
pub mod html;
pub mod graphviz; // mermaid + dot
pub mod governance; // MS AGT / DefenseClaw / LlamaFirewall

use ar_core::{AgentGraph, Report, ReportFormat};
use std::io::Write;
use std::path::Path;

/// Render the report in the requested format.
pub fn render(report: &Report, format: ReportFormat) -> String {
    match format {
        ReportFormat::Json => json::render(report),
        ReportFormat::Sarif => sarif::render(report),
        ReportFormat::Markdown => markdown::render(report),
        ReportFormat::Html => html::render(report),
    }
}

/// Mermaid `flowchart TB` of the tool topology (edge colors by trust, node
/// effect badges, system-prompt sha label).
pub fn mermaid(graph: &AgentGraph) -> String {
    graphviz::mermaid(graph)
}

/// DOT/Graphviz equivalent.
pub fn dot(graph: &AgentGraph) -> String {
    graphviz::dot(graph)
}

/// Microsoft Agent Governance Toolkit policy export (JSON string).
pub fn export_ms_agt(report: &Report) -> String {
    governance::ms_agt(report)
}

/// Cisco DefenseClaw secure-agent-framework export (JSON string).
pub fn export_defenseclaw(report: &Report) -> String {
    governance::defenseclaw(report)
}

/// Meta LlamaFirewall inline-filter config export (JSON string).
pub fn export_llamafirewall(report: &Report) -> String {
    governance::llamafirewall(report)
}

/// Render the report in `format` and write it to `path`.
pub fn write_report(
    report: &Report,
    format: ReportFormat,
    path: impl AsRef<Path>,
) -> std::io::Result<()> {
    let rendered = render(report, format);
    let mut file = std::fs::File::create(path)?;
    file.write_all(rendered.as_bytes())?;
    file.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ar_core::{
        AgentNode, ComplianceTags, DetectorCategory, Edge, EdgeKind, Finding, Framework,
        MemoryStore, OwaspAgentic2026, OwaspLlm2025, RAGSource, ScanMeta, Severity, ToolNode,
        TrustLabel,
    };

    /// Build a tiny but representative report: one agent, one privileged tool,
    /// a memory store, a RAG source, an unknown node and a couple of findings.
    fn sample_report() -> Report {
        let mut graph = AgentGraph::new();

        let mut agent = AgentNode::new("agent:planner", "Planner", Framework::OpenAIAgentsSdk);
        agent.model = Some("gpt-4o".to_string());
        agent.set_system_prompt("You are a helpful planning agent.");
        agent.accepts_user_input = true;
        let agent_id = graph.add_agent(agent);

        let mut tool = ToolNode::new("tool:shell", "run_shell");
        tool.effects.shell_exec = true;
        tool.effects.net_egress = true;
        let tool_id = graph.add_tool(tool);

        let mem_id = graph.add_memory(MemoryStore::new(
            "mem:buffer",
            "history",
            "ConversationBufferMemory",
        ));
        let rag_id = graph.add_rag(RAGSource::new("rag:docs", "internal-docs", "Chroma"));
        let unk_id = graph.add_unknown("unk:dynamic", "dynamic tool list");

        graph.add_edge(
            Edge::new(agent_id.clone(), tool_id.clone(), EdgeKind::Calls)
                .with_trust(TrustLabel::Untrusted),
        );
        graph.add_edge(
            Edge::new(agent_id.clone(), rag_id.clone(), EdgeKind::Reads)
                .with_trust(TrustLabel::Trusted)
                .with_label("retrieve"),
        );
        graph.add_edge(
            Edge::new(agent_id.clone(), mem_id, EdgeKind::Writes).with_trust(TrustLabel::Mixed),
        );
        graph.add_edge(Edge::new(unk_id, agent_id.clone(), EdgeKind::DataFlow));

        let findings = vec![
            Finding::new(
                "tb-untrusted-to-shell",
                DetectorCategory::TrustBoundary,
                Severity::Critical,
                "Untrusted input reaches shell-exec tool",
                "User-controlled data flows into a tool that executes shell commands.",
            )
            .with_agent(agent_id.clone())
            .with_tool(tool_id.clone())
            .with_evidence("agent.tools = [run_shell]  # subprocess.run(cmd, shell=True)")
            .with_fix("Add an allow-list and input validation before the shell tool.")
            .with_compliance(
                ComplianceTags::new()
                    .with_agentic(OwaspAgentic2026::ToolMisuse)
                    .with_llm(OwaspLlm2025::ExcessiveAgency)
                    .with_nist("MANAGE 4.1")
                    .with_atlas("AML.T0051"),
            ),
            Finding::new(
                "pi-no-role-separator",
                DetectorCategory::PromptInjection,
                Severity::Medium,
                "System prompt lacks role separation",
                "The system prompt does not separate trusted instructions from user content.",
            )
            .with_agent(agent_id)
            .with_compliance(ComplianceTags::new().with_llm(OwaspLlm2025::PromptInjection)),
        ];

        let meta = ScanMeta {
            tool_version: "0.1.0".to_string(),
            scanned_path: "examples/app".into(),
            framework: Some(Framework::OpenAIAgentsSdk),
            frameworks_detected: vec![Framework::OpenAIAgentsSdk],
            timestamp: Some("2026-05-31T00:00:00Z".to_string()),
            dynamic: false,
            hardened: false,
            compliance_modes: Vec::new(),
        };

        Report::new(meta, graph, findings)
    }

    #[test]
    fn json_render_is_valid_json() {
        let report = sample_report();
        let s = json::render(&report);
        assert!(!s.is_empty());
        let parsed: serde_json::Value =
            serde_json::from_str(&s).expect("json output must parse");
        assert!(parsed.get("findings").is_some());
        // round-trips back into a Report.
        let _back: Report = serde_json::from_str(&s).expect("json must round-trip");
    }

    #[test]
    fn sarif_has_version_and_rules() {
        let report = sample_report();
        let s = sarif::render(&report);
        assert!(!s.is_empty());
        assert!(s.contains("2.1.0"));
        assert!(s.contains("lancer-agentic-radar"));
        let v: serde_json::Value = serde_json::from_str(&s).expect("sarif must be valid json");
        assert_eq!(v["version"], "2.1.0");
        let rules = &v["runs"][0]["tool"]["driver"]["rules"];
        assert!(rules.as_array().map(|r| !r.is_empty()).unwrap_or(false));
        let results = &v["runs"][0]["results"];
        assert!(results.as_array().map(|r| r.len() == 2).unwrap_or(false));
        assert!(s.contains("partialFingerprints"));
    }

    #[test]
    fn markdown_has_sections_and_mermaid() {
        let report = sample_report();
        let s = markdown::render(&report);
        assert!(!s.is_empty());
        assert!(s.contains("# lancer-agentic-radar"));
        assert!(s.contains("Table of Contents"));
        assert!(s.contains("Severity Summary"));
        assert!(s.contains("```mermaid"));
        assert!(s.contains("flowchart"));
        assert!(s.contains("OWASP Agentic 2026 coverage"));
        assert!(s.contains("AAT-02"));
    }

    #[test]
    fn html_is_self_contained() {
        let report = sample_report();
        let s = html::render(&report);
        assert!(!s.is_empty());
        assert!(s.contains("<html"));
        assert!(s.contains("</html>"));
        assert!(s.contains("<style>"));
        assert!(s.contains("<details>"));
        assert!(s.contains("class=\"mermaid\""));
        assert!(s.contains("mermaid.min.js"));
    }

    #[test]
    fn mermaid_marker_present() {
        let report = sample_report();
        let m = mermaid(&report.graph);
        assert!(m.contains("flowchart TB"));
        // privileged tool gets the shell/net badges.
        assert!(m.contains("SHELL"));
        assert!(m.contains("linkStyle"));
        // system-prompt short sha label.
        assert!(m.contains("sp#"));
    }

    #[test]
    fn dot_is_digraph() {
        let report = sample_report();
        let d = dot(&report.graph);
        assert!(d.contains("digraph"));
        assert!(d.contains("->"));
        assert!(d.contains("shape=cylinder"));
        assert!(d.contains("shape=parallelogram"));
    }

    #[test]
    fn governance_exports_are_json() {
        let report = sample_report();

        let agt = export_ms_agt(&report);
        let v: serde_json::Value = serde_json::from_str(&agt).expect("agt json");
        assert_eq!(v["policy_set"], "lancer-agentic-radar");
        // Only the Critical finding is enforceable -> exactly one rule.
        assert_eq!(v["rules"].as_array().map(|a| a.len()), Some(1));
        assert_eq!(v["rules"][0]["action"], "deny");

        let dc = export_defenseclaw(&report);
        let v: serde_json::Value = serde_json::from_str(&dc).expect("dc json");
        assert_eq!(v["framework"], "defenseclaw");
        assert_eq!(v["controls"][0]["control_type"], "tool-policy");

        let lf = export_llamafirewall(&report);
        let v: serde_json::Value = serde_json::from_str(&lf).expect("lf json");
        assert_eq!(v["engine"], "llamafirewall");
        // Both findings produce filters (distinct categories).
        assert_eq!(v["filters"].as_array().map(|a| a.len()), Some(2));
    }

    #[test]
    fn render_dispatch_covers_all_formats() {
        let report = sample_report();
        for fmt in ReportFormat::ALL {
            let s = render(&report, fmt);
            assert!(!s.is_empty(), "format {:?} rendered empty", fmt);
        }
    }
}
